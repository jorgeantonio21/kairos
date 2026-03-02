use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow};
use consensus::state::peer::PeerSet;
use crypto::bls::ops::public_key_from_scalar;
use crypto::consensus_bls::{BlsPublicKey, PeerId, ThresholdSignerContext};
use crypto::dkg::run_in_memory_dual_dkg;
use crypto::threshold_setup::{
    ThresholdDomains, ThresholdKeyset, ThresholdKeysets, ThresholdSetupArtifact,
    ValidatorParticipant,
};
use p2p::identity::ValidatorIdentity;

pub struct ThresholdTestMaterial {
    pub peer_set: PeerSet,
    pub signer_by_peer_id: HashMap<PeerId, ThresholdSignerContext>,
}

const DOMAIN_M_NOT: &str = "consensus/m-not/v1";
const DOMAIN_NULLIFY: &str = "consensus/nullify/v1";
const DOMAIN_L_NOT: &str = "consensus/l-not/v1";

pub fn build_threshold_test_material(
    identities: &[ValidatorIdentity],
    n: usize,
    f: usize,
    validator_set_id: &str,
) -> Result<ThresholdTestMaterial> {
    if identities.len() != n {
        return Err(anyhow!(
            "identities length {} does not match n {}",
            identities.len(),
            n
        ));
    }
    if validator_set_id.trim().is_empty() {
        return Err(anyhow!("validator_set_id must be non-empty"));
    }

    let mut entries = identities
        .iter()
        .map(|identity| (identity.peer_id(), *identity.bls_public_key()))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(peer_id, _)| *peer_id);

    let unique_count = entries
        .iter()
        .map(|(peer_id, _)| *peer_id)
        .collect::<HashSet<_>>()
        .len();
    if unique_count != entries.len() {
        return Err(anyhow!(
            "duplicate peer_id detected while building threshold material"
        ));
    }

    let mut rng = rand::thread_rng();
    let dual_dkg = run_in_memory_dual_dkg(n, f, &mut rng).context("run in-memory dual DKG")?;

    let m_secret_by_index: HashMap<u64, crypto::scalar::Scalar> = dual_dkg
        .m_nullify
        .participant_shares
        .iter()
        .map(|share| (share.participant_index, share.secret_share.clone()))
        .collect();
    let l_secret_by_index: HashMap<u64, crypto::scalar::Scalar> = dual_dkg
        .l_notarization
        .participant_shares
        .iter()
        .map(|share| (share.participant_index, share.secret_share.clone()))
        .collect();

    let mut validators = Vec::with_capacity(n);
    let mut peers = Vec::with_capacity(n);
    let mut indices = Vec::with_capacity(n);
    let mut m_share_public_key_by_peer_id = HashMap::with_capacity(n);
    let mut l_share_public_key_by_peer_id = HashMap::with_capacity(n);

    for (position, (peer_id, public_key)) in entries.iter().enumerate() {
        let participant_index = (position + 1) as u64;
        let m_secret = m_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow!("missing M secret share for index {}", participant_index))?;
        let l_secret = l_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow!("missing L secret share for index {}", participant_index))?;

        let m_share_public_key = BlsPublicKey(public_key_from_scalar(m_secret)?);
        let l_share_public_key = BlsPublicKey(public_key_from_scalar(l_secret)?);

        validators.push(ValidatorParticipant {
            peer_id: *peer_id,
            participant_index,
            m_share_public_key: hex::encode(m_share_public_key.0),
            l_share_public_key: hex::encode(l_share_public_key.0),
        });
        peers.push(*public_key);
        indices.push(participant_index);
        m_share_public_key_by_peer_id.insert(*peer_id, m_share_public_key);
        l_share_public_key_by_peer_id.insert(*peer_id, l_share_public_key);
    }

    let peer_set = PeerSet::with_threshold_material(
        peers,
        indices,
        m_share_public_key_by_peer_id,
        l_share_public_key_by_peer_id,
        DOMAIN_M_NOT.as_bytes().to_vec(),
        DOMAIN_NULLIFY.as_bytes().to_vec(),
        DOMAIN_L_NOT.as_bytes().to_vec(),
    )?;

    let mut signer_by_peer_id = HashMap::with_capacity(n);
    for (position, (peer_id, _)) in entries.iter().enumerate() {
        let participant_index = (position + 1) as u64;
        let m_secret = m_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow!("missing M secret share for index {}", participant_index))?;
        let l_secret = l_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow!("missing L secret share for index {}", participant_index))?;

        let artifact = ThresholdSetupArtifact {
            validator_set_id: validator_set_id.to_string(),
            peer_id: *peer_id,
            participant_index,
            n,
            f,
            validators: validators.clone(),
            domains: ThresholdDomains {
                m_not: DOMAIN_M_NOT.to_string(),
                nullify: DOMAIN_NULLIFY.to_string(),
                l_not: DOMAIN_L_NOT.to_string(),
            },
            keysets: ThresholdKeysets {
                m_nullify: ThresholdKeyset {
                    threshold: 2 * f + 1,
                    group_public_key: hex::encode(dual_dkg.m_nullify.group_public_key.0),
                    secret_share: hex::encode(m_secret.to_bytes_le()),
                },
                l_notarization: ThresholdKeyset {
                    threshold: n - f,
                    group_public_key: hex::encode(dual_dkg.l_notarization.group_public_key.0),
                    secret_share: hex::encode(l_secret.to_bytes_le()),
                },
            },
        };

        artifact.validate_for_node(*peer_id, n, f, Some(validator_set_id))?;
        let decoded = artifact.decode()?;
        let signer = ThresholdSignerContext::from_decoded_setup(decoded)?;
        signer_by_peer_id.insert(*peer_id, signer);
    }

    Ok(ThresholdTestMaterial {
        peer_set,
        signer_by_peer_id,
    })
}
