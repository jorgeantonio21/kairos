//! Consensus BLS types for threshold signing in Minimmit.
//!
//! This module provides wrapper types around BLS12-381 keys and signatures,
//! with support for threshold signing operations required by the consensus protocol.
//!
//! ## Threshold Signing in Minimmit
//!
//! Minimmit uses two threshold signature schemes:
//! - **M-notarization**: threshold `2f + 1` (view progression)
//! - **L-notarization**: threshold `n - f` (block finalization)
//!
//! Both require combining partial signatures from multiple validators using
//! Lagrange interpolation.

use std::str::FromStr;

use anyhow::{Result, anyhow};
use blst::min_sig::PublicKey;
use rand::{CryptoRng, RngCore};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bls::constants::{
    BLS_PUBLIC_KEY_BYTES, BLS_SECRET_KEY_BYTES, BLS_SIGNATURE_BYTES, PEER_ID_BYTES,
};
use crate::bls::ops::{
    combine_public_keys_with_lagrange, combine_signatures_with_lagrange, generate_secret_key_bytes,
    public_key_from_secret_key_bytes, sign_with_scalar, sign_with_secret_key_bytes,
    verify_signature_bytes,
};
use crate::scalar::Scalar;
use crate::threshold_math::lagrange_coefficients_for_indices;
use crate::threshold_setup::DecodedThresholdSetup;

/// Validator identifier derived from BLS public key.
///
/// Derived as the first 8 bytes of the BLAKE3 hash of the compressed public key.
/// This provides a deterministic, uniformly distributed identifier.
pub type PeerId = u64;

/// BLS12-381 public key in compressed G2 format (96 bytes).
///
/// Wrapper around raw bytes with verification and threshold interpolation methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Archive, Deserialize, Serialize)]
pub struct BlsPublicKey(pub [u8; BLS_PUBLIC_KEY_BYTES]);

/// BLS12-381 signature in compressed G1 format (48 bytes).
///
/// Standard BLS signature that can be aggregated and threshold-combined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Archive, Deserialize, Serialize)]
pub struct BlsSignature(pub [u8; BLS_SIGNATURE_BYTES]);

/// Threshold partial signature created by a single validator share.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Archive, Deserialize, Serialize)]
pub struct ThresholdPartialSignature(pub BlsSignature);

/// Threshold proof created by combining partial signatures at quorum.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Archive, Deserialize, Serialize)]
pub struct ThresholdProof(pub BlsSignature);

/// BLS12-381 secret key (32 bytes).
///
/// Note: This is a full secret key, not a threshold share.
/// For threshold signing, use the `threshold` module.
#[derive(Clone, Debug, PartialEq, Eq, Archive, Deserialize, Serialize)]
pub struct BlsSecretKey(pub [u8; BLS_SECRET_KEY_BYTES]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThresholdDomain {
    MNotarization,
    Nullification,
    LNotarization,
}

#[derive(Clone, Debug)]
pub struct ThresholdSignerContext {
    participant_index: u64,
    n: usize,
    m_threshold: usize,
    l_threshold: usize,
    m_not_domain: Vec<u8>,
    nullify_domain: Vec<u8>,
    l_not_domain: Vec<u8>,
    m_group_public_key: BlsPublicKey,
    l_group_public_key: BlsPublicKey,
    m_secret_share: Scalar,
    l_secret_share: Scalar,
}

impl BlsSecretKey {
    /// Generate a new random BLS secret key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(generate_secret_key_bytes(rng))
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> BlsPublicKey {
        let pk_bytes =
            public_key_from_secret_key_bytes(&self.0).expect("Invalid BLS secret key bytes");
        BlsPublicKey(pk_bytes)
    }

    /// Sign a message with this secret key.
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let sig_bytes =
            sign_with_secret_key_bytes(&self.0, message).expect("Invalid BLS secret key bytes");
        BlsSignature(sig_bytes)
    }
}

impl ThresholdSignerContext {
    pub fn from_decoded_setup(setup: DecodedThresholdSetup) -> Result<Self> {
        let participant_index = setup.artifact.participant_index;
        let n = setup.artifact.n;
        if participant_index == 0 || participant_index as usize > n {
            return Err(anyhow!(
                "invalid participant index {} for n={}",
                participant_index,
                n
            ));
        }

        Ok(Self {
            participant_index,
            n,
            m_threshold: setup.artifact.keysets.m_nullify.threshold,
            l_threshold: setup.artifact.keysets.l_notarization.threshold,
            m_not_domain: setup.artifact.domains.m_not.into_bytes(),
            nullify_domain: setup.artifact.domains.nullify.into_bytes(),
            l_not_domain: setup.artifact.domains.l_not.into_bytes(),
            m_group_public_key: setup.m_nullify_group_public_key,
            l_group_public_key: setup.l_notarization_group_public_key,
            m_secret_share: setup.m_nullify_secret_share,
            l_secret_share: setup.l_notarization_secret_share,
        })
    }

    pub fn participant_index(&self) -> u64 {
        self.participant_index
    }

    pub fn threshold_for(&self, domain: ThresholdDomain) -> usize {
        match domain {
            ThresholdDomain::MNotarization | ThresholdDomain::Nullification => self.m_threshold,
            ThresholdDomain::LNotarization => self.l_threshold,
        }
    }

    pub fn partial_sign(
        &self,
        domain: ThresholdDomain,
        payload: &[u8],
    ) -> Result<ThresholdPartialSignature> {
        let message = self.domain_separated_message(domain, payload);
        let secret_share = match domain {
            ThresholdDomain::MNotarization | ThresholdDomain::Nullification => &self.m_secret_share,
            ThresholdDomain::LNotarization => &self.l_secret_share,
        };
        let signature = sign_with_scalar(secret_share, &message)?;
        Ok(ThresholdPartialSignature(BlsSignature(signature)))
    }

    pub fn verify_threshold_proof(
        &self,
        domain: ThresholdDomain,
        payload: &[u8],
        signature: &ThresholdProof,
    ) -> bool {
        let message = self.domain_separated_message(domain, payload);
        let group_public_key = match domain {
            ThresholdDomain::MNotarization | ThresholdDomain::Nullification => {
                self.m_group_public_key
            }
            ThresholdDomain::LNotarization => self.l_group_public_key,
        };
        group_public_key.verify(&message, &signature.0)
    }

    pub fn combine_partials(
        &self,
        domain: ThresholdDomain,
        partials: &[(u64, ThresholdPartialSignature)],
    ) -> Result<ThresholdProof> {
        if partials.len() < self.threshold_for(domain) {
            return Err(anyhow!(
                "not enough partials for {:?}: got {}, need at least {}",
                domain,
                partials.len(),
                self.threshold_for(domain)
            ));
        }
        for (index, _) in partials {
            if *index == 0 || *index as usize > self.n {
                return Err(anyhow!(
                    "participant index {} is out of range [1, {}]",
                    index,
                    self.n
                ));
            }
        }
        ThresholdProof::combine_partials(partials)
    }

    pub fn domain_separated_message(&self, domain: ThresholdDomain, payload: &[u8]) -> Vec<u8> {
        let domain_bytes = match domain {
            ThresholdDomain::MNotarization => &self.m_not_domain,
            ThresholdDomain::Nullification => &self.nullify_domain,
            ThresholdDomain::LNotarization => &self.l_not_domain,
        };
        let mut message = Vec::with_capacity(domain_bytes.len() + payload.len());
        message.extend_from_slice(domain_bytes);
        message.extend_from_slice(payload);
        message
    }
}

impl BlsPublicKey {
    /// Verify a signature over a message.
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> bool {
        verify_signature_bytes(&self.0, message, &signature.0).is_ok()
    }

    /// Verify a threshold signature by interpolating the group public key.
    ///
    /// Combines the given public keys using Lagrange coefficients derived from
    /// DKG participant indices, then verifies the signature against the interpolated key.
    ///
    /// The indices are DKG-assigned (1..n), not hash-derived PeerIds.
    pub fn verify_threshold(
        public_keys: &[BlsPublicKey],
        indices: &[u64],
        message: &[u8],
        signature: &BlsSignature,
    ) -> bool {
        match Self::interpolate_threshold_public_key(public_keys, indices) {
            Ok(pk) => pk.verify(message, signature),
            Err(_) => false,
        }
    }

    /// Interpolate a threshold group public key from participant public keys.
    ///
    /// Given `t` public keys `PK_i` and their corresponding indices `x_i`,
    /// computes the group public key:
    /// ```math
    /// PK = \sum_{i=1}^{t} \lambda_i \cdot PK_i
    /// ```
    /// where `λ_i` are Lagrange coefficients computed from the indices (not PeerIds).
    ///
    /// Using indices instead of hash-derived PeerIds ensures deterministic behavior
    /// and prevents vanity/selection bias attacks.
    pub fn interpolate_threshold_public_key(
        public_keys: &[BlsPublicKey],
        indices: &[u64],
    ) -> Result<BlsPublicKey> {
        if public_keys.is_empty() {
            return Err(anyhow!("Cannot interpolate public key from empty set"));
        }
        if public_keys.len() != indices.len() {
            return Err(anyhow!(
                "Mismatched public key and index counts: {} != {}",
                public_keys.len(),
                indices.len()
            ));
        }

        let lambdas = lagrange_coefficients_for_indices(indices)?;
        let public_key_bytes: Vec<[u8; BLS_PUBLIC_KEY_BYTES]> =
            public_keys.iter().map(|pk| pk.0).collect();
        let out = combine_public_keys_with_lagrange(&public_key_bytes, &lambdas)?;

        Ok(BlsPublicKey(out))
    }

    /// Derive a PeerId from this public key.
    ///
    /// Uses BLAKE3 hash of the compressed public key, taking first 8 bytes
    /// as a little-endian u64.
    pub fn to_peer_id(&self) -> PeerId {
        let hash = blake3::hash(&self.0);
        let bytes: [u8; PEER_ID_BYTES] = hash.as_bytes()[..PEER_ID_BYTES]
            .try_into()
            .expect("Slice length must match PEER_ID_BYTES");
        u64::from_le_bytes(bytes)
    }

    /// Serialize in compressed BLS format.
    pub fn serialize_compressed<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }

    /// Deserialize from compressed BLS format.
    pub fn deserialize_compressed<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut bytes = [0u8; BLS_PUBLIC_KEY_BYTES];
        reader.read_exact(&mut bytes)?;
        PublicKey::from_bytes(&bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid compressed BLS public key",
            )
        })?;
        Ok(Self(bytes))
    }
}

impl FromStr for BlsPublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        let pk = PublicKey::from_bytes(&bytes)
            .map_err(|e| anyhow!("Invalid BLS public key bytes: {:?}", e))?;
        Ok(Self(pk.to_bytes()))
    }
}

impl BlsSignature {
    /// Combine threshold partial signatures using Lagrange interpolation.
    ///
    /// Given partial signatures `σ_i` from participants with indices `x_i`:
    /// ```math
    /// \sigma = \sum_{i=1}^{t} \lambda_i \cdot \sigma_i
    /// ```
    /// The resulting signature can be verified against the interpolated group public key.
    ///
    /// The indices are DKG-assigned (1..n), not hash-derived PeerIds.
    /// Using indices ensures deterministic behavior and prevents vanity attacks.
    pub fn combine_partials(partials: &[(u64, BlsSignature)]) -> Result<BlsSignature> {
        if partials.is_empty() {
            return Err(anyhow!("Cannot combine empty partial signature set"));
        }

        let indices: Vec<u64> = partials.iter().map(|(idx, _)| *idx).collect();
        let lambdas = lagrange_coefficients_for_indices(&indices)?;
        let signature_bytes: Vec<[u8; BLS_SIGNATURE_BYTES]> =
            partials.iter().map(|(_, sig)| sig.0).collect();
        let out = combine_signatures_with_lagrange(&signature_bytes, &lambdas)?;

        Ok(BlsSignature(out))
    }

    /// Serialize in compressed BLS format.
    pub fn serialize_compressed<W: std::io::Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.0)
    }
}

impl ThresholdPartialSignature {
    pub fn verify(&self, public_key: &BlsPublicKey, message: &[u8]) -> bool {
        public_key.verify(message, &self.0)
    }

    pub fn serialize_compressed<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.serialize_compressed(writer)
    }
}

impl ThresholdProof {
    /// Combine threshold partial signatures using Lagrange interpolation.
    pub fn combine_partials(partials: &[(u64, ThresholdPartialSignature)]) -> Result<Self> {
        if partials.is_empty() {
            return Err(anyhow!("Cannot combine empty partial signature set"));
        }
        let raw_partials = partials
            .iter()
            .map(|(idx, sig)| (*idx, sig.0))
            .collect::<Vec<_>>();
        Ok(Self(BlsSignature::combine_partials(&raw_partials)?))
    }

    pub fn verify_with_public_keys(
        &self,
        public_keys: &[BlsPublicKey],
        indices: &[u64],
        message: &[u8],
    ) -> bool {
        BlsPublicKey::verify_threshold(public_keys, indices, message, &self.0)
    }

    pub fn serialize_compressed<W: std::io::Write>(&self, writer: W) -> std::io::Result<()> {
        self.0.serialize_compressed(writer)
    }
}

impl From<BlsSignature> for ThresholdPartialSignature {
    fn from(value: BlsSignature) -> Self {
        Self(value)
    }
}

impl From<BlsSignature> for ThresholdProof {
    fn from(value: BlsSignature) -> Self {
        Self(value)
    }
}

impl From<ThresholdPartialSignature> for BlsSignature {
    fn from(value: ThresholdPartialSignature) -> Self {
        value.0
    }
}

impl From<ThresholdProof> for BlsSignature {
    fn from(value: ThresholdProof) -> Self {
        value.0
    }
}

impl Default for BlsSignature {
    fn default() -> Self {
        Self([0u8; BLS_SIGNATURE_BYTES])
    }
}

/// Pre-computed threshold signature with all required verification data.
///
/// Stores the aggregated signature along with the public keys and indices
/// needed to verify it. Indices are DKG-assigned (1..n), not hash-derived PeerIds.
#[derive(Clone, Debug, Archive, Deserialize, Serialize)]
pub struct AggregatedSignature<const N: usize> {
    /// The combined threshold signature.
    pub aggregated_signature: BlsSignature,
    /// Public keys of all N participants.
    pub public_keys: [BlsPublicKey; N],
    /// DKG indices corresponding to each public key (1..n).
    pub indices: [u64; N],
}

impl<const N: usize> AggregatedSignature<N> {
    /// Create a new aggregated signature from individual signatures.
    ///
    /// Verifies each input signature before combining.
    /// Indices are DKG-assigned (1..n), not hash-derived PeerIds.
    pub fn new(
        public_keys: [BlsPublicKey; N],
        indices: [u64; N],
        message: &[u8],
        signatures: &[BlsSignature],
    ) -> Option<Self> {
        if signatures.len() != N || N == 0 {
            return None;
        }

        for idx in 0..N {
            if !public_keys[idx].verify(message, &signatures[idx]) {
                return None;
            }
        }

        let partials: Vec<(u64, BlsSignature)> = indices
            .iter()
            .copied()
            .zip(signatures.iter().copied())
            .collect();
        let aggregated_signature = BlsSignature::combine_partials(&partials).ok()?;

        Some(Self {
            aggregated_signature,
            public_keys,
            indices,
        })
    }

    /// Create from pre-combined signature without verification.
    pub fn new_from_aggregated_signature(
        public_keys: [BlsPublicKey; N],
        indices: [u64; N],
        aggregated_signature: BlsSignature,
    ) -> Self {
        Self {
            public_keys,
            indices,
            aggregated_signature,
        }
    }

    /// Verify the aggregated signature against a message.
    pub fn verify(&self, message: &[u8]) -> bool {
        BlsPublicKey::verify_threshold(
            &self.public_keys,
            &self.indices,
            message,
            &self.aggregated_signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::{ThresholdBLS, ThresholdBLS as Scheme};
    use rand::{SeedableRng, rngs::StdRng, thread_rng};

    const TEST_THRESHOLD: usize = 3;
    const TEST_TOTAL_PARTICIPANTS: usize = 5;
    const FIRST_SELECTED_INDEX: usize = 0;
    const SECOND_SELECTED_INDEX: usize = 2;
    const THIRD_SELECTED_INDEX: usize = 4;

    #[test]
    fn threshold_combine_and_verify_roundtrip() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(TEST_THRESHOLD, TEST_TOTAL_PARTICIPANTS);
        let (_, key_shares) = scheme.trusted_setup(&mut rng).expect("setup");

        let message = b"threshold message";
        let selected = [
            &key_shares[FIRST_SELECTED_INDEX],
            &key_shares[SECOND_SELECTED_INDEX],
            &key_shares[THIRD_SELECTED_INDEX],
        ];

        // Use DKG indices (1-based from the scheme) for threshold signing
        let indices: Vec<u64> = vec![1, 3, 5]; // Corresponds to selected shares
        let partials: Vec<(u64, BlsSignature)> = selected
            .iter()
            .zip(indices.iter())
            .map(|(share, &idx)| {
                let ps = Scheme::partial_sign(share, message).expect("partial sign");
                (idx, BlsSignature(ps.signature.to_bytes()))
            })
            .collect();

        let public_keys: Vec<BlsPublicKey> = selected
            .iter()
            .map(|share| BlsPublicKey(share.public_key.to_bytes()))
            .collect();

        let combined = BlsSignature::combine_partials(&partials).expect("combine");

        assert!(BlsPublicKey::verify_threshold(
            &public_keys,
            &indices,
            message,
            &combined
        ));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let message = b"single-signer";
        let signature = sk.sign(message);
        assert!(pk.verify(message, &signature));
    }

    #[test]
    fn combine_partials_rejects_empty() {
        let result = BlsSignature::combine_partials(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn combine_partials_rejects_duplicate_indices() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(TEST_THRESHOLD, TEST_TOTAL_PARTICIPANTS);
        let (_, key_shares) = scheme.trusted_setup(&mut rng).expect("setup");
        let message = b"duplicate-index";

        let ps0 = Scheme::partial_sign(&key_shares[FIRST_SELECTED_INDEX], message).expect("sign 0");
        let ps1 =
            Scheme::partial_sign(&key_shares[SECOND_SELECTED_INDEX], message).expect("sign 1");
        // Use same index twice (both using index 1)
        let partials = vec![
            (1u64, BlsSignature(ps0.signature.to_bytes())),
            (1u64, BlsSignature(ps1.signature.to_bytes())),
        ];

        let result = BlsSignature::combine_partials(&partials);
        assert!(result.is_err());
    }

    #[test]
    fn verify_threshold_rejects_wrong_message() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(TEST_THRESHOLD, TEST_TOTAL_PARTICIPANTS);
        let (_, key_shares) = scheme.trusted_setup(&mut rng).expect("setup");

        let signed_message = b"threshold message";
        let wrong_message = b"wrong message";
        let selected = [
            &key_shares[FIRST_SELECTED_INDEX],
            &key_shares[SECOND_SELECTED_INDEX],
            &key_shares[THIRD_SELECTED_INDEX],
        ];

        let indices: Vec<u64> = vec![1, 3, 5];
        let partials: Vec<(u64, BlsSignature)> = selected
            .iter()
            .zip(indices.iter())
            .map(|(share, &idx)| {
                let ps = Scheme::partial_sign(share, signed_message).expect("partial sign");
                (idx, BlsSignature(ps.signature.to_bytes()))
            })
            .collect();
        let combined = BlsSignature::combine_partials(&partials).expect("combine");
        let public_keys: Vec<BlsPublicKey> = selected
            .iter()
            .map(|share| BlsPublicKey(share.public_key.to_bytes()))
            .collect();

        assert!(!BlsPublicKey::verify_threshold(
            &public_keys,
            &indices,
            wrong_message,
            &combined
        ));
    }

    #[test]
    fn verify_threshold_rejects_mismatched_lengths() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"mismatch");
        // Use indices instead of PeerIds
        let result = BlsPublicKey::verify_threshold(&[pk], &[1, 999], b"mismatch", &sig);
        assert!(!result);
    }

    #[test]
    fn deserialize_compressed_rejects_invalid_bytes() {
        let bytes = [0u8; BLS_PUBLIC_KEY_BYTES];
        let result = BlsPublicKey::deserialize_compressed(bytes.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn bls_public_key_to_peer_id() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let peer_id = pk.to_peer_id();
        assert!(peer_id != 0);
    }

    #[test]
    fn bls_public_key_serialize_roundtrip() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let mut buffer = Vec::new();
        pk.serialize_compressed(&mut buffer).expect("serialize");
        let restored =
            BlsPublicKey::deserialize_compressed(buffer.as_slice()).expect("deserialize");
        assert_eq!(pk, restored);
    }

    #[test]
    fn bls_signature_serialize_roundtrip() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let sig = sk.sign(b"test message");
        let mut buffer = Vec::new();
        sig.serialize_compressed(&mut buffer).expect("serialize");
        assert_eq!(buffer.len(), BLS_SIGNATURE_BYTES);
    }

    #[test]
    fn threshold_signer_context_from_decoded_setup_rejects_zero_index() {
        let artifact = valid_artifact_with_index(0);
        let result = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn threshold_signer_context_from_decoded_setup_rejects_index_out_of_range() {
        let mut artifact = valid_artifact_with_index(99);
        artifact.n = 6;
        let result = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn threshold_signer_context_threshold_for_m_notarization() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        assert_eq!(ctx.threshold_for(ThresholdDomain::MNotarization), 3);
    }

    #[test]
    fn threshold_signer_context_threshold_for_l_notarization() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        assert_eq!(ctx.threshold_for(ThresholdDomain::LNotarization), 5);
    }

    #[test]
    fn threshold_signer_context_threshold_for_nullification() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        assert_eq!(ctx.threshold_for(ThresholdDomain::Nullification), 3);
    }

    #[test]
    fn threshold_signer_context_partial_sign_m_notarization() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial = ctx
            .partial_sign(ThresholdDomain::MNotarization, b"test")
            .expect("sign");
        assert!(!ctx.verify_threshold_proof(
            ThresholdDomain::MNotarization,
            b"test",
            &ThresholdProof(partial.0)
        ));
    }

    #[test]
    fn threshold_signer_context_partial_sign_l_notarization() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial = ctx
            .partial_sign(ThresholdDomain::LNotarization, b"test")
            .expect("sign");
        assert!(!ctx.verify_threshold_proof(
            ThresholdDomain::LNotarization,
            b"test",
            &ThresholdProof(partial.0)
        ));
    }

    #[test]
    fn threshold_signer_context_partial_sign_nullification() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial = ctx
            .partial_sign(ThresholdDomain::Nullification, b"test")
            .expect("sign");
        assert!(!ctx.verify_threshold_proof(
            ThresholdDomain::Nullification,
            b"test",
            &ThresholdProof(partial.0)
        ));
    }

    #[test]
    fn threshold_signer_context_combine_partials_rejects_insufficient() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial = ctx
            .partial_sign(ThresholdDomain::MNotarization, b"test")
            .expect("sign");
        let result = ctx.combine_partials(ThresholdDomain::MNotarization, &[(1, partial)]);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_signer_context_combine_partials_rejects_zero_index() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial = ctx
            .partial_sign(ThresholdDomain::MNotarization, b"test")
            .expect("sign");
        let result = ctx.combine_partials(ThresholdDomain::MNotarization, &[(0, partial)]);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_signer_context_combine_partials_rejects_out_of_range_index() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial = ctx
            .partial_sign(ThresholdDomain::MNotarization, b"test")
            .expect("sign");
        let result = ctx.combine_partials(ThresholdDomain::MNotarization, &[(99, partial)]);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_signer_context_combine_partials_success() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial1 = ctx
            .partial_sign(ThresholdDomain::MNotarization, b"test")
            .expect("sign1");
        let partial2 = ctx
            .partial_sign(ThresholdDomain::MNotarization, b"test")
            .expect("sign2");
        let result = ctx.combine_partials(
            ThresholdDomain::MNotarization,
            &[(1, partial1), (2, partial2)],
        );
        assert!(result.is_err());
    }

    #[test]
    fn threshold_signer_context_domain_separated_message() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let msg = ctx.domain_separated_message(ThresholdDomain::MNotarization, b"payload");
        assert!(!msg.is_empty());
    }

    #[test]
    fn threshold_signer_context_participant_index() {
        let artifact = valid_artifact_with_index(3);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        assert_eq!(ctx.participant_index(), 3);
    }

    #[test]
    fn threshold_signer_context_verify_threshold_proof_wrong_payload() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial = ctx
            .partial_sign(ThresholdDomain::MNotarization, b"test")
            .expect("sign");
        assert!(!ctx.verify_threshold_proof(
            ThresholdDomain::MNotarization,
            b"wrong-payload",
            &ThresholdProof(partial.0)
        ));
    }

    #[test]
    fn threshold_signer_context_combine_partials_below_threshold() {
        let artifact = valid_artifact_with_index(1);
        let ctx = ThresholdSignerContext::from_decoded_setup(artifact.decode().unwrap()).unwrap();
        let partial = ctx
            .partial_sign(ThresholdDomain::MNotarization, b"test")
            .expect("sign");
        let result = ctx.combine_partials(ThresholdDomain::MNotarization, &[(1, partial)]);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_partial_signature_verify() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"test");
        let partial = ThresholdPartialSignature(sig);
        assert!(partial.verify(&pk, b"test"));
        assert!(!partial.verify(&pk, b"wrong"));
    }

    #[test]
    fn threshold_partial_signature_serialize_roundtrip() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let sig = sk.sign(b"test");
        let partial = ThresholdPartialSignature(sig);
        let mut buffer = Vec::new();
        partial
            .serialize_compressed(&mut buffer)
            .expect("serialize");
        assert_eq!(buffer.len(), BLS_SIGNATURE_BYTES);
    }

    #[test]
    fn threshold_proof_combine_partials_rejects_empty() {
        let result = ThresholdProof::combine_partials(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_proof_verify_with_public_keys() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(TEST_THRESHOLD, TEST_TOTAL_PARTICIPANTS);
        let (_, key_shares) = scheme.trusted_setup(&mut rng).expect("setup");
        let message = b"threshold message";
        let selected = [
            &key_shares[FIRST_SELECTED_INDEX],
            &key_shares[SECOND_SELECTED_INDEX],
            &key_shares[THIRD_SELECTED_INDEX],
        ];
        let indices: Vec<u64> = vec![1, 3, 5];
        let partials: Vec<(u64, BlsSignature)> = selected
            .iter()
            .zip(indices.iter())
            .map(|(share, &idx)| {
                let ps = Scheme::partial_sign(share, message).expect("partial sign");
                (idx, BlsSignature(ps.signature.to_bytes()))
            })
            .collect();
        let combined = BlsSignature::combine_partials(&partials).expect("combine");
        let proof = ThresholdProof(combined);
        let public_keys: Vec<BlsPublicKey> = selected
            .iter()
            .map(|share| BlsPublicKey(share.public_key.to_bytes()))
            .collect();
        assert!(proof.verify_with_public_keys(&public_keys, &indices, message));
    }

    #[test]
    fn threshold_proof_serialize_roundtrip() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let sig = sk.sign(b"test");
        let proof = ThresholdProof(sig);
        let mut buffer = Vec::new();
        proof.serialize_compressed(&mut buffer).expect("serialize");
        assert_eq!(buffer.len(), BLS_SIGNATURE_BYTES);
    }

    #[test]
    fn aggregated_signature_new_rejects_mismatched_lengths() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"test");
        let result = AggregatedSignature::<2>::new([pk, pk], [1, 2], b"test", &[sig]);
        assert!(result.is_none());
    }

    #[test]
    fn aggregated_signature_new_rejects_zero_n() {
        let result = AggregatedSignature::<0>::new([], [], b"test", &[]);
        assert!(result.is_none());
    }

    #[test]
    fn aggregated_signature_new_rejects_invalid_signature() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let wrong_sig = BlsSecretKey::generate(&mut rng).sign(b"other");
        let result = AggregatedSignature::<1>::new([pk], [1], b"test", &[wrong_sig]);
        assert!(result.is_none());
    }

    #[test]
    fn aggregated_signature_new_from_aggregated_signature() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"test");
        let agg = AggregatedSignature::<1>::new_from_aggregated_signature([pk], [1], sig);
        assert!(agg.verify(b"test"));
    }

    #[test]
    fn aggregated_signature_verify() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(TEST_THRESHOLD, TEST_TOTAL_PARTICIPANTS);
        let (_, key_shares) = scheme.trusted_setup(&mut rng).expect("setup");
        let message = b"test message";
        let selected = [
            &key_shares[FIRST_SELECTED_INDEX],
            &key_shares[SECOND_SELECTED_INDEX],
            &key_shares[THIRD_SELECTED_INDEX],
        ];
        let indices: Vec<u64> = vec![1, 3, 5];
        let partials: Vec<(u64, BlsSignature)> = selected
            .iter()
            .zip(indices.iter())
            .map(|(share, &idx)| {
                let ps = Scheme::partial_sign(share, message).expect("partial sign");
                (idx, BlsSignature(ps.signature.to_bytes()))
            })
            .collect();
        let combined = BlsSignature::combine_partials(&partials).expect("combine");
        let public_keys: [BlsPublicKey; 3] = selected
            .iter()
            .map(|share| BlsPublicKey(share.public_key.to_bytes()))
            .collect::<Vec<_>>()
            .try_into()
            .expect("selected set should map to exactly three public keys");
        let indices_arr: [u64; 3] = [1, 3, 5];
        let agg =
            AggregatedSignature::new_from_aggregated_signature(public_keys, indices_arr, combined);
        assert!(agg.verify(message));
    }

    #[test]
    fn bls_public_key_interpolate_rejects_empty() {
        let result = BlsPublicKey::interpolate_threshold_public_key(&[], &[]);
        assert!(result.is_err());
    }

    #[test]
    fn bls_public_key_interpolate_rejects_mismatched_lengths() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let result = BlsPublicKey::interpolate_threshold_public_key(&[pk], &[1, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn bls_public_key_interpolate_success() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let result = BlsPublicKey::interpolate_threshold_public_key(&[pk], &[1]);
        assert!(result.is_ok());
    }

    #[test]
    fn bls_public_key_from_str_valid() {
        let mut rng = thread_rng();
        let sk = BlsSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let hex_str = hex::encode(pk.0);
        let parsed: BlsPublicKey = hex_str.parse().expect("parse");
        assert_eq!(pk, parsed);
    }

    #[test]
    fn bls_public_key_from_str_invalid_hex() {
        let result: Result<BlsPublicKey, _> = "not valid hex".parse();
        assert!(result.is_err());
    }

    #[test]
    fn bls_public_key_from_str_invalid_bytes() {
        let result: Result<BlsPublicKey, _> = "aabbccdd".parse();
        assert!(result.is_err());
    }

    fn valid_artifact_with_index(index: u64) -> crate::threshold_setup::ThresholdSetupArtifact {
        use crate::threshold_setup::{
            ThresholdDomains, ThresholdKeyset, ThresholdKeysets, ValidatorParticipant,
        };

        let mut rng = StdRng::seed_from_u64(101);
        let sk_a = BlsSecretKey::generate(&mut rng);
        let pk_a = sk_a.public_key();
        let sk_b = BlsSecretKey::generate(&mut rng);
        let pk_b = sk_b.public_key();

        let validators: Vec<ValidatorParticipant> = (1..=6)
            .map(|i| ValidatorParticipant {
                peer_id: i as u64,
                participant_index: i as u64,
                m_share_public_key: hex::encode(pk_a.0),
                l_share_public_key: hex::encode(pk_b.0),
            })
            .collect();

        crate::threshold_setup::ThresholdSetupArtifact {
            validator_set_id: "vs-1".to_string(),
            peer_id: 1,
            participant_index: index,
            n: 6,
            f: 1,
            validators,
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
}
