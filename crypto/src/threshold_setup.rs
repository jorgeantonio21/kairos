use std::{fs, path::Path};

use blst::min_sig::PublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    bls::constants::BLS_PUBLIC_KEY_BYTES,
    consensus_bls::{BlsPublicKey, PeerId},
    error::{ThresholdSetupError, ThresholdSetupResult},
    scalar::Scalar,
};

/// Serialized setup artifact for threshold signing bootstrap.
///
/// This is intended for boot-time loading and validation, not hot-path message handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSetupArtifact {
    pub validator_set_id: String,
    pub peer_id: PeerId,
    pub participant_index: u64,
    pub n: usize,
    pub f: usize,
    pub validators: Vec<ValidatorParticipant>,
    pub domains: ThresholdDomains,
    pub keysets: ThresholdKeysets,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorParticipant {
    pub peer_id: PeerId,
    pub participant_index: u64,
    pub m_share_public_key: String,
    pub l_share_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdDomains {
    pub m_not: String,
    pub nullify: String,
    pub l_not: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdKeysets {
    pub m_nullify: ThresholdKeyset,
    pub l_notarization: ThresholdKeyset,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdKeyset {
    pub threshold: usize,
    pub group_public_key: String,
    pub secret_share: String,
}

/// Decoded setup material for runtime integration.
#[derive(Debug, Clone)]
pub struct DecodedThresholdSetup {
    pub artifact: ThresholdSetupArtifact,
    pub m_nullify_group_public_key: BlsPublicKey,
    pub l_notarization_group_public_key: BlsPublicKey,
    pub m_nullify_secret_share: Scalar,
    pub l_notarization_secret_share: Scalar,
    pub participant_index_by_peer_id: std::collections::HashMap<PeerId, u64>,
    pub m_share_public_key_by_peer_id: std::collections::HashMap<PeerId, BlsPublicKey>,
    pub l_share_public_key_by_peer_id: std::collections::HashMap<PeerId, BlsPublicKey>,
}

impl ThresholdSetupArtifact {
    /// Loads a setup artifact from a JSON file.
    pub fn load_from_path(path: impl AsRef<Path>) -> ThresholdSetupResult<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).map_err(|source| ThresholdSetupError::ArtifactRead {
            path: path.to_path_buf(),
            source,
        })?;

        serde_json::from_str(&raw).map_err(|source| ThresholdSetupError::ArtifactParse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Validates artifact structural and configuration constraints.
    pub fn validate_for_node(
        &self,
        local_peer_id: PeerId,
        expected_n: usize,
        expected_f: usize,
        expected_validator_set_id: Option<&str>,
    ) -> ThresholdSetupResult<()> {
        if self.peer_id != local_peer_id {
            return Err(ThresholdSetupError::PeerIdMismatch {
                artifact: self.peer_id,
                local: local_peer_id,
            });
        }
        if self.n != expected_n || self.f != expected_f {
            return Err(ThresholdSetupError::ThresholdParamsMismatch {
                artifact_n: self.n,
                artifact_f: self.f,
                expected_n,
                expected_f,
            });
        }
        if self.participant_index == 0 || self.participant_index as usize > self.n {
            return Err(ThresholdSetupError::ParticipantIndexOutOfRange {
                participant_index: self.participant_index,
                n: self.n,
            });
        }
        if self.validators.len() != self.n {
            return Err(ThresholdSetupError::InvalidCommitmentSetSize {
                actual: self.validators.len(),
                expected: self.n,
            });
        }
        let mut seen_peer_ids = std::collections::HashSet::new();
        let mut seen_indices = std::collections::HashSet::new();
        for validator in &self.validators {
            if !seen_peer_ids.insert(validator.peer_id) {
                return Err(ThresholdSetupError::DuplicatePeerIdInParticipants {
                    peer_id: validator.peer_id,
                });
            }
            if !seen_indices.insert(validator.participant_index) {
                return Err(ThresholdSetupError::DuplicateParticipantIndex {
                    participant_index: validator.participant_index,
                });
            }
            if validator.participant_index == 0 || validator.participant_index as usize > self.n {
                return Err(ThresholdSetupError::ParticipantIndexOutOfRange {
                    participant_index: validator.participant_index,
                    n: self.n,
                });
            }
            decode_group_public_key(
                "validator.m_share_public_key",
                &validator.m_share_public_key,
            )?;
            decode_group_public_key(
                "validator.l_share_public_key",
                &validator.l_share_public_key,
            )?;
        }
        let local_present = self.validators.iter().any(|validator| {
            validator.peer_id == local_peer_id
                && validator.participant_index == self.participant_index
        });
        if !local_present {
            return Err(ThresholdSetupError::PeerIdMismatch {
                artifact: self.peer_id,
                local: local_peer_id,
            });
        }
        if let Some(expected) = expected_validator_set_id
            && self.validator_set_id != expected
        {
            return Err(ThresholdSetupError::ValidatorSetMismatch {
                artifact: self.validator_set_id.clone(),
                expected: expected.to_string(),
            });
        }

        let m_threshold_expected = 2 * self.f + 1;
        let l_threshold_expected = self.n - self.f;
        if self.keysets.m_nullify.threshold != m_threshold_expected {
            return Err(ThresholdSetupError::InvalidMNullifyThreshold {
                actual: self.keysets.m_nullify.threshold,
                expected: m_threshold_expected,
            });
        }
        if self.keysets.l_notarization.threshold != l_threshold_expected {
            return Err(ThresholdSetupError::InvalidLNotarizationThreshold {
                actual: self.keysets.l_notarization.threshold,
                expected: l_threshold_expected,
            });
        }

        validate_domain_tags(&self.domains)?;
        decode_group_public_key(
            "m_nullify.group_public_key",
            &self.keysets.m_nullify.group_public_key,
        )?;
        decode_group_public_key(
            "l_notarization.group_public_key",
            &self.keysets.l_notarization.group_public_key,
        )?;
        decode_secret_share(
            "m_nullify.secret_share",
            &self.keysets.m_nullify.secret_share,
        )?;
        decode_secret_share(
            "l_notarization.secret_share",
            &self.keysets.l_notarization.secret_share,
        )?;
        Ok(())
    }

    /// Validates and decodes key material for runtime use.
    pub fn decode(self) -> ThresholdSetupResult<DecodedThresholdSetup> {
        let m_nullify_group_public_key = decode_group_public_key(
            "m_nullify.group_public_key",
            &self.keysets.m_nullify.group_public_key,
        )?;
        let l_notarization_group_public_key = decode_group_public_key(
            "l_notarization.group_public_key",
            &self.keysets.l_notarization.group_public_key,
        )?;
        let m_nullify_secret_share = decode_secret_share(
            "m_nullify.secret_share",
            &self.keysets.m_nullify.secret_share,
        )?;
        let l_notarization_secret_share = decode_secret_share(
            "l_notarization.secret_share",
            &self.keysets.l_notarization.secret_share,
        )?;
        let mut participant_index_by_peer_id = std::collections::HashMap::new();
        let mut m_share_public_key_by_peer_id = std::collections::HashMap::new();
        let mut l_share_public_key_by_peer_id = std::collections::HashMap::new();
        for validator in &self.validators {
            participant_index_by_peer_id.insert(validator.peer_id, validator.participant_index);
            m_share_public_key_by_peer_id.insert(
                validator.peer_id,
                decode_group_public_key(
                    "validator.m_share_public_key",
                    &validator.m_share_public_key,
                )?,
            );
            l_share_public_key_by_peer_id.insert(
                validator.peer_id,
                decode_group_public_key(
                    "validator.l_share_public_key",
                    &validator.l_share_public_key,
                )?,
            );
        }

        Ok(DecodedThresholdSetup {
            artifact: self,
            m_nullify_group_public_key,
            l_notarization_group_public_key,
            m_nullify_secret_share,
            l_notarization_secret_share,
            participant_index_by_peer_id,
            m_share_public_key_by_peer_id,
            l_share_public_key_by_peer_id,
        })
    }
}

fn validate_domain_tags(domains: &ThresholdDomains) -> ThresholdSetupResult<()> {
    let tags = [
        domains.m_not.trim(),
        domains.nullify.trim(),
        domains.l_not.trim(),
    ];
    if tags.iter().any(|tag| tag.is_empty()) {
        return Err(ThresholdSetupError::EmptyDomainTags);
    }
    if tags[0] == tags[1] || tags[0] == tags[2] || tags[1] == tags[2] {
        return Err(ThresholdSetupError::DuplicateDomainTags);
    }
    Ok(())
}

fn decode_group_public_key(
    field: &'static str,
    encoded: &str,
) -> ThresholdSetupResult<BlsPublicKey> {
    let decoded = hex::decode(encoded)
        .map_err(|source| ThresholdSetupError::InvalidGroupPublicKeyEncoding { field, source })?;
    let actual = decoded.len();
    if actual != BLS_PUBLIC_KEY_BYTES {
        return Err(ThresholdSetupError::InvalidGroupPublicKeyLength {
            field,
            expected: BLS_PUBLIC_KEY_BYTES,
            actual,
        });
    }

    let key = PublicKey::from_bytes(&decoded).map_err(|error_code| {
        ThresholdSetupError::InvalidGroupPublicKeyBytes { field, error_code }
    })?;
    Ok(BlsPublicKey(key.to_bytes()))
}

fn decode_secret_share(field: &'static str, encoded: &str) -> ThresholdSetupResult<Scalar> {
    let decoded = hex::decode(encoded)
        .map_err(|source| ThresholdSetupError::InvalidSecretShareEncoding { field, source })?;
    let actual = decoded.len();
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ThresholdSetupError::InvalidSecretShareLength { field, actual })?;
    Ok(Scalar::from_bytes_le(bytes))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::consensus_bls::BlsSecretKey;
    use rand::{SeedableRng, rngs::StdRng};

    fn valid_artifact() -> ThresholdSetupArtifact {
        let mut rng = StdRng::seed_from_u64(101);
        let sk_a = BlsSecretKey::generate(&mut rng);
        let sk_b = BlsSecretKey::generate(&mut rng);
        let pk_a = sk_a.public_key();
        let pk_b = sk_b.public_key();

        ThresholdSetupArtifact {
            validator_set_id: "vs-1".to_string(),
            peer_id: pk_a.to_peer_id(),
            participant_index: 1,
            n: 6,
            f: 1,
            validators: vec![
                ValidatorParticipant {
                    peer_id: pk_a.to_peer_id(),
                    participant_index: 1,
                    m_share_public_key: hex::encode(pk_a.0),
                    l_share_public_key: hex::encode(pk_b.0),
                },
                ValidatorParticipant {
                    peer_id: pk_b.to_peer_id(),
                    participant_index: 2,
                    m_share_public_key: hex::encode(pk_b.0),
                    l_share_public_key: hex::encode(pk_a.0),
                },
                ValidatorParticipant {
                    peer_id: 3,
                    participant_index: 3,
                    m_share_public_key: hex::encode(pk_a.0),
                    l_share_public_key: hex::encode(pk_a.0),
                },
                ValidatorParticipant {
                    peer_id: 4,
                    participant_index: 4,
                    m_share_public_key: hex::encode(pk_a.0),
                    l_share_public_key: hex::encode(pk_a.0),
                },
                ValidatorParticipant {
                    peer_id: 5,
                    participant_index: 5,
                    m_share_public_key: hex::encode(pk_a.0),
                    l_share_public_key: hex::encode(pk_a.0),
                },
                ValidatorParticipant {
                    peer_id: 6,
                    participant_index: 6,
                    m_share_public_key: hex::encode(pk_a.0),
                    l_share_public_key: hex::encode(pk_a.0),
                },
            ],
            domains: ThresholdDomains {
                m_not: "minimmit/m_not/v1".to_string(),
                nullify: "minimmit/nullify/v1".to_string(),
                l_not: "minimmit/l_not/v1".to_string(),
            },
            keysets: ThresholdKeysets {
                m_nullify: ThresholdKeyset {
                    threshold: 3,
                    group_public_key: hex::encode(pk_a.0),
                    secret_share: hex::encode(sk_a.0),
                },
                l_notarization: ThresholdKeyset {
                    threshold: 5,
                    group_public_key: hex::encode(pk_b.0),
                    secret_share: hex::encode(sk_b.0),
                },
            },
        }
    }

    #[test]
    fn validate_for_node_accepts_valid_artifact() {
        let artifact = valid_artifact();
        artifact
            .validate_for_node(artifact.peer_id, artifact.n, artifact.f, Some("vs-1"))
            .expect("valid artifact");
    }

    #[test]
    fn validate_for_node_rejects_wrong_peer() {
        let artifact = valid_artifact();
        let err = artifact
            .validate_for_node(artifact.peer_id + 1, artifact.n, artifact.f, None)
            .expect_err("must fail");
        assert!(err.to_string().contains("peer_id mismatch"));
    }

    #[test]
    fn validate_for_node_rejects_threshold_mismatch() {
        let mut artifact = valid_artifact();
        artifact.keysets.m_nullify.threshold = 4;
        let err = artifact
            .validate_for_node(artifact.peer_id, artifact.n, artifact.f, None)
            .expect_err("must fail");
        assert!(err.to_string().contains("m_nullify threshold"));
    }

    #[test]
    fn validate_for_node_rejects_duplicate_domains() {
        let mut artifact = valid_artifact();
        artifact.domains.nullify = artifact.domains.m_not.clone();
        let err = artifact
            .validate_for_node(artifact.peer_id, artifact.n, artifact.f, None)
            .expect_err("must fail");
        assert!(err.to_string().contains("must be unique"));
    }

    #[test]
    fn decode_rejects_bad_share_length() {
        let mut artifact = valid_artifact();
        artifact.keysets.m_nullify.secret_share = "abcd".to_string();
        let err = artifact.decode().expect_err("must fail");
        assert!(err.to_string().contains("exactly 32 bytes"));
    }

    #[test]
    fn load_from_path_roundtrip() {
        let artifact = valid_artifact();
        let raw = serde_json::to_string_pretty(&artifact).expect("serialize");
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("threshold-setup-{stamp}.json"));
        fs::write(&path, raw).expect("write");

        let loaded = ThresholdSetupArtifact::load_from_path(&path).expect("load");
        fs::remove_file(&path).expect("cleanup");
        assert_eq!(loaded.peer_id, artifact.peer_id);
        assert_eq!(loaded.n, artifact.n);
        assert_eq!(loaded.f, artifact.f);
    }

    #[test]
    fn load_from_path_rejects_malformed_json() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("threshold-setup-bad-{stamp}.json"));
        fs::write(&path, "{not valid json").expect("write");
        let result = ThresholdSetupArtifact::load_from_path(&path);
        fs::remove_file(&path).expect("cleanup");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("failed to parse threshold setup artifact JSON")
        );
    }

    #[test]
    fn load_from_path_rejects_partial_artifact() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("threshold-setup-partial-{stamp}.json"));
        fs::write(
            &path,
            r#"{"validator_set_id":"vs","peer_id":1,"participant_index":1}"#,
        )
        .expect("write");
        let result = ThresholdSetupArtifact::load_from_path(&path);
        fs::remove_file(&path).expect("cleanup");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("failed to parse threshold setup artifact JSON")
        );
    }

    #[test]
    fn validate_for_node_rejects_invalid_group_key_encoding() {
        let mut artifact = valid_artifact();
        artifact.keysets.m_nullify.group_public_key = "zzzz".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("group public key")
        );
    }

    #[test]
    fn validate_for_node_rejects_validator_set_mismatch() {
        let artifact = valid_artifact();
        let result =
            artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, Some("other-vs"));
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("validator_set_id mismatch")
        );
    }

    #[test]
    fn validate_for_node_rejects_duplicate_peer_id_in_validators() {
        let mut artifact = valid_artifact();
        artifact.validators[2].peer_id = artifact.validators[0].peer_id;
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
        assert!(result.expect_err("error").to_string().contains("duplicate peer_id"));
    }

    #[test]
    fn validate_for_node_rejects_duplicate_participant_index_in_validators() {
        let mut artifact = valid_artifact();
        artifact.validators[2].participant_index = artifact.validators[0].participant_index;
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
        assert!(result.expect_err("error").to_string().contains("duplicate participant_index"));
    }

    #[test]
    fn validate_for_node_rejects_validator_participant_index_out_of_range() {
        let mut artifact = valid_artifact();
        artifact.validators[0].participant_index = 99;
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
        assert!(result.expect_err("error").to_string().contains("participant_index"));
    }

    #[test]
    fn validate_for_node_rejects_invalid_validator_m_share_public_key() {
        let mut artifact = valid_artifact();
        artifact.validators[0].m_share_public_key = "invalid".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_invalid_validator_l_share_public_key() {
        let mut artifact = valid_artifact();
        artifact.validators[0].l_share_public_key = "invalid".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_invalid_m_group_public_key() {
        let mut artifact = valid_artifact();
        artifact.keysets.m_nullify.group_public_key = "invalid".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
        assert!(result.expect_err("error").to_string().contains("group public key"));
    }

    #[test]
    fn validate_for_node_rejects_invalid_l_group_public_key() {
        let mut artifact = valid_artifact();
        artifact.keysets.l_notarization.group_public_key = "invalid".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_invalid_m_secret_share() {
        let mut artifact = valid_artifact();
        artifact.keysets.m_nullify.secret_share = "invalid".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_invalid_l_secret_share() {
        let mut artifact = valid_artifact();
        artifact.keysets.l_notarization.secret_share = "invalid".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_empty_m_domain() {
        let mut artifact = valid_artifact();
        artifact.domains.m_not = "   ".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
        assert!(result.expect_err("error").to_string().contains("empty"));
    }

    #[test]
    fn validate_for_node_rejects_empty_nullify_domain() {
        let mut artifact = valid_artifact();
        artifact.domains.nullify = "   ".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_empty_l_domain() {
        let mut artifact = valid_artifact();
        artifact.domains.l_not = "   ".to_string();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_duplicate_m_and_nullify_domain() {
        let mut artifact = valid_artifact();
        artifact.domains.nullify = artifact.domains.m_not.clone();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_duplicate_m_and_l_domain() {
        let mut artifact = valid_artifact();
        artifact.domains.l_not = artifact.domains.m_not.clone();
        let result = artifact.validate_for_node(artifact.peer_id, artifact.n, artifact.f, None);
        assert!(result.is_err());
    }

    #[test]
    fn validate_for_node_rejects_invalid_l_threshold() {
        let mut artifact = valid_artifact();
        artifact.keysets.l_notarization.threshold = 3;
        let err = artifact
            .validate_for_node(artifact.peer_id, artifact.n, artifact.f, None)
            .expect_err("must fail");
        assert!(err.to_string().contains("l_notarization threshold"));
    }

    #[test]
    fn decode_rejects_invalid_group_key_length() {
        let mut artifact = valid_artifact();
        artifact.keysets.m_nullify.group_public_key = "aabbcc".to_string();
        let err = artifact.decode().expect_err("must fail");
        assert!(err.to_string().contains("must be exactly"));
    }

    #[test]
    fn decode_rejects_invalid_group_key_bytes() {
        let mut artifact = valid_artifact();
        artifact.keysets.m_nullify.group_public_key = "00000000000000000000000000000000000000000000000000000000000000ff".to_string();
        let err = artifact.decode().expect_err("must fail");
        assert!(err.to_string().contains("bytes"));
    }

    #[test]
    fn decode_rejects_invalid_secret_share_encoding() {
        let mut artifact = valid_artifact();
        artifact.keysets.m_nullify.secret_share = "not hex".to_string();
        let err = artifact.decode().expect_err("must fail");
        assert!(err.to_string().contains("hex"));
    }

    #[test]
    fn decode_roundtrip() {
        let artifact = valid_artifact();
        let decoded = artifact.decode().expect("decode");
        assert_eq!(decoded.artifact.n, 6);
        assert_eq!(decoded.artifact.f, 1);
    }

    #[test]
    fn decoded_setup_has_correct_mappings() {
        let artifact = valid_artifact();
        let decoded = artifact.decode().expect("decode");
        assert_eq!(decoded.participant_index_by_peer_id.len(), 6);
        assert_eq!(decoded.m_share_public_key_by_peer_id.len(), 6);
        assert_eq!(decoded.l_share_public_key_by_peer_id.len(), 6);
    }
}
