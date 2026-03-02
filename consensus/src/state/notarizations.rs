use std::hash::{Hash, Hasher};

use rkyv::{Archive, Deserialize, Serialize};

use crate::state::peer::PeerSet;
use crypto::consensus_bls::{BlsPublicKey, PeerId, ThresholdPartialSignature, ThresholdProof};

/// [`Vote`] represents a vote for a given block.
///
/// A vote corresponds to an authenticated block, from a given peer.
#[derive(Archive, Deserialize, Serialize, Clone, Debug)]
pub struct Vote {
    /// The view number for which the vote is being cast
    pub view: u64,
    /// The hash of the block that is being voted for
    pub block_hash: [u8; blake3::OUT_LEN],
    /// The signature of block by the peer that is voting
    /// for the current block in the M-notarization threshold domain.
    pub signature: ThresholdPartialSignature,
    /// The signature of block by the peer in the L-notarization threshold domain.
    pub l_signature: ThresholdPartialSignature,
    /// The public key of the peer that is
    /// voting for the current block
    pub peer_id: PeerId,
    /// The leader's ID of the view
    pub leader_id: PeerId,
}

impl Vote {
    pub fn new(
        view: u64,
        block_hash: [u8; blake3::OUT_LEN],
        signature: impl Into<ThresholdPartialSignature>,
        peer_id: PeerId,
        leader_id: PeerId,
    ) -> Self {
        let signature = signature.into();
        Self::new_with_threshold_signatures(
            view, block_hash, signature, signature, peer_id, leader_id,
        )
    }

    pub fn new_with_threshold_signatures(
        view: u64,
        block_hash: [u8; blake3::OUT_LEN],
        m_signature: impl Into<ThresholdPartialSignature>,
        l_signature: impl Into<ThresholdPartialSignature>,
        peer_id: PeerId,
        leader_id: PeerId,
    ) -> Self {
        let m_signature = m_signature.into();
        let l_signature = l_signature.into();
        Self {
            view,
            block_hash,
            signature: m_signature,
            l_signature,
            peer_id,
            leader_id,
        }
    }

    /// Verifies if the block has been successfully signed by its author
    /// Note: this does not verify that the [`PeerId`] matches the public key
    /// of the peer that signed the block. This should be verified by the caller, beforehand.
    pub fn verify_m_signature(&self, peer_public_key: &BlsPublicKey, message: &[u8]) -> bool {
        self.signature.verify(peer_public_key, message)
    }

    /// Verifies the L-threshold partial signature.
    pub fn verify_l_signature(&self, peer_public_key: &BlsPublicKey, message: &[u8]) -> bool {
        self.l_signature.verify(peer_public_key, message)
    }

    pub fn verify(&self, peer_public_key: &BlsPublicKey) -> bool {
        self.signature.verify(peer_public_key, &self.block_hash)
    }
}

impl Hash for Vote {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.view.hash(state);
        self.block_hash.hash(state);
        self.peer_id.hash(state);
    }
}

impl PartialEq for Vote {
    fn eq(&self, other: &Self) -> bool {
        self.view == other.view
            && self.block_hash == other.block_hash
            && self.peer_id == other.peer_id
    }
}

impl Eq for Vote {}

/// [`MNotarization`] represents a (2f + 1)-signature quorum for a given block (also
/// referred to as a M-notarization). An M-notarization is required to progress to the next view,
/// but not to finalize a block. Moreover, a block for view `v` can receive a M-notarization,
/// but not being finalized for that view (which happens if the consensus cannot finalize it
/// within the given view timeout period).
///
/// The type parameters `N` and `F` correspond to the total number of peers and the number of
/// faulty peers, respectively. The type parameter `M_SIZE` corresponds to the size of the
/// aggregated signature.
#[derive(Archive, Deserialize, Serialize, Clone, Debug)]
pub struct MNotarization<const N: usize, const F: usize, const M_SIZE: usize> {
    /// The view number for which the M-notarization is being cast
    pub view: u64,
    /// The hash of the block that has been notarized
    pub block_hash: [u8; blake3::OUT_LEN],
    /// The aggregated signature of the block by the peers that have notarized it
    pub aggregated_signature: ThresholdProof,
    /// The leader's ID of the view
    pub leader_id: PeerId,
}

impl<const N: usize, const F: usize, const M_SIZE: usize> MNotarization<N, F, M_SIZE> {
    pub fn new(
        view: u64,
        block_hash: [u8; blake3::OUT_LEN],
        aggregated_signature: impl Into<ThresholdProof>,
        leader_id: PeerId,
    ) -> Self {
        let aggregated_signature = aggregated_signature.into();
        Self {
            view,
            block_hash,
            aggregated_signature,
            leader_id,
        }
    }

    /// Verifies the underlying M-notarization aggregated block signature
    pub fn verify(&self, peer_set: &PeerSet) -> bool {
        let message = if let Some(domain) = peer_set.m_not_domain.as_ref() {
            let mut message = Vec::with_capacity(domain.len() + self.block_hash.len());
            message.extend_from_slice(domain);
            message.extend_from_slice(&self.block_hash);
            message
        } else {
            self.block_hash.to_vec()
        };
        match peer_set.m_group_public_key.as_ref() {
            Some(group_public_key) => group_public_key.verify(&message, &self.aggregated_signature.0),
            None => false,
        }
    }
}

impl<const N: usize, const F: usize, const M_SIZE: usize> Hash for MNotarization<N, F, M_SIZE> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.view.hash(state);
        self.block_hash.hash(state);
    }
}

impl<const N: usize, const F: usize, const M_SIZE: usize> PartialEq
    for MNotarization<N, F, M_SIZE>
{
    fn eq(&self, other: &Self) -> bool {
        self.view == other.view && self.block_hash == other.block_hash
    }
}

impl<const N: usize, const F: usize, const M_SIZE: usize> Eq for MNotarization<N, F, M_SIZE> {}

/// [`LNotarization`] represents a (n - f)-signature quorum for a given block (also
/// referred to as an L-notarization). An L-notarization is the finality proof for a block,
/// meaning the block is committed and can never be reverted.
///
/// Light clients can use the L-notarization to verify that a block was correctly finalized
/// by checking the compact threshold proof against the L-domain group public key.
///
/// The type parameters `N` and `F` correspond to the total number of peers and the number of
/// faulty peers, respectively.
#[derive(Archive, Deserialize, Serialize, Clone, Debug)]
pub struct LNotarization<const N: usize, const F: usize> {
    /// The view number when the block was finalized
    pub view: u64,
    /// The hash of the finalized block
    pub block_hash: [u8; blake3::OUT_LEN],
    /// Compact threshold signature for the finalized block in the L domain.
    pub aggregated_signature: ThresholdProof,
    /// The block height for easier lookup
    pub height: u64,
}

impl<const N: usize, const F: usize> LNotarization<N, F> {
    pub fn new(
        view: u64,
        block_hash: [u8; blake3::OUT_LEN],
        aggregated_signature: impl Into<ThresholdProof>,
        height: u64,
    ) -> Self {
        let aggregated_signature = aggregated_signature.into();
        Self {
            view,
            block_hash,
            aggregated_signature,
            height,
        }
    }

    /// Verifies the L-notarization aggregated BLS signature against the validator set.
    ///
    /// Returns `true` if the compact L-threshold proof verifies under the L group public key.
    pub fn verify(&self, peer_set: &PeerSet) -> bool {
        let message = if let Some(domain) = peer_set.l_not_domain.as_ref() {
            let mut message = Vec::with_capacity(domain.len() + self.block_hash.len());
            message.extend_from_slice(domain);
            message.extend_from_slice(&self.block_hash);
            message
        } else {
            self.block_hash.to_vec()
        };
        match peer_set.l_group_public_key.as_ref() {
            Some(group_public_key) => group_public_key.verify(&message, &self.aggregated_signature.0),
            None => false,
        }
    }
}

impl<const N: usize, const F: usize> Hash for LNotarization<N, F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.view.hash(state);
        self.block_hash.hash(state);
        self.height.hash(state);
    }
}

impl<const N: usize, const F: usize> PartialEq for LNotarization<N, F> {
    fn eq(&self, other: &Self) -> bool {
        self.view == other.view
            && self.block_hash == other.block_hash
            && self.height == other.height
    }
}

impl<const N: usize, const F: usize> Eq for LNotarization<N, F> {}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crypto::consensus_bls::{BlsSecretKey, ThresholdProof};
    use rand::thread_rng;

    use super::{LNotarization, MNotarization};
    use crate::state::peer::PeerSet;
    use crate::storage::conversions::serialize_for_db;

    fn threshold_peer_set_with_domains(
        keypairs: &[(u64, BlsSecretKey)],
        m_domain: &[u8],
        nullify_domain: &[u8],
        l_domain: &[u8],
    ) -> PeerSet {
        let peers = keypairs
            .iter()
            .map(|(_, secret_key)| secret_key.public_key())
            .collect::<Vec<_>>();
        let indices = keypairs.iter().map(|(index, _)| *index).collect::<Vec<_>>();
        let mut m_map = HashMap::new();
        let mut l_map = HashMap::new();
        for (index, secret_key) in keypairs {
            let peer_id = secret_key.public_key().to_peer_id();
            let _ = index;
            m_map.insert(peer_id, secret_key.public_key());
            l_map.insert(peer_id, secret_key.public_key());
        }
        PeerSet::with_threshold_material(
            peers,
            indices,
            m_map,
            l_map,
            m_domain.to_vec(),
            nullify_domain.to_vec(),
            l_domain.to_vec(),
        )
        .expect("build threshold peer set")
    }

    #[test]
    fn m_notarization_verify_fails_with_domain_mismatch() {
        let mut rng = thread_rng();
        let keypairs = [
            (1u64, BlsSecretKey::generate(&mut rng)),
            (2u64, BlsSecretKey::generate(&mut rng)),
            (3u64, BlsSecretKey::generate(&mut rng)),
        ];
        let m_domain = b"m-not-domain";
        let l_domain = b"l-not-domain";
        let _peer_set =
            threshold_peer_set_with_domains(&keypairs, m_domain, b"nullify-domain", l_domain);

        let block_hash = [7u8; blake3::OUT_LEN];
        let mut message = Vec::with_capacity(m_domain.len() + block_hash.len());
        message.extend_from_slice(m_domain);
        message.extend_from_slice(&block_hash);

        let partials = keypairs
            .iter()
            .map(|(index, secret_key)| (*index, secret_key.sign(&message).into()))
            .collect::<Vec<_>>();
        let aggregated_signature = ThresholdProof::combine_partials(&partials).expect("combine");
        let peer_ids = keypairs
            .iter()
            .map(|(_, secret_key)| secret_key.public_key().to_peer_id())
            .collect::<Vec<_>>();

        let notarization =
            MNotarization::<3, 1, 3>::new(10, block_hash, aggregated_signature, peer_ids[0]);
        let wrong_domain_peer_set =
            threshold_peer_set_with_domains(&keypairs, b"wrong-domain", b"nullify-domain", l_domain);
        assert!(!notarization.verify(&wrong_domain_peer_set));
    }

    #[test]
    fn l_notarization_verify_fails_with_wrong_domain_signature() {
        let mut rng = thread_rng();
        let keypairs = [
            (1u64, BlsSecretKey::generate(&mut rng)),
            (2u64, BlsSecretKey::generate(&mut rng)),
            (3u64, BlsSecretKey::generate(&mut rng)),
        ];
        let m_domain = b"m-not-domain";
        let l_domain = b"l-not-domain";
        let peer_set =
            threshold_peer_set_with_domains(&keypairs, m_domain, b"nullify-domain", l_domain);

        let block_hash = [9u8; blake3::OUT_LEN];
        // Intentionally sign with M domain while verifying as L domain.
        let mut wrong_message = Vec::with_capacity(m_domain.len() + block_hash.len());
        wrong_message.extend_from_slice(m_domain);
        wrong_message.extend_from_slice(&block_hash);

        let partials = keypairs
            .iter()
            .map(|(index, secret_key)| (*index, secret_key.sign(&wrong_message).into()))
            .collect::<Vec<_>>();
        let aggregated_signature = ThresholdProof::combine_partials(&partials).expect("combine");
        let notarization = LNotarization::<3, 1>::new(
            11,
            block_hash,
            aggregated_signature,
            11,
        );
        assert!(!notarization.verify(&peer_set));
    }

    #[test]
    fn l_notarization_serialized_size_is_constant_across_validator_sizes() {
        let mut rng = thread_rng();
        let keypairs = [
            (1u64, BlsSecretKey::generate(&mut rng)),
            (2u64, BlsSecretKey::generate(&mut rng)),
            (3u64, BlsSecretKey::generate(&mut rng)),
        ];
        let l_domain = b"l-not-domain";
        let block_hash = [3u8; blake3::OUT_LEN];
        let mut message = Vec::with_capacity(l_domain.len() + block_hash.len());
        message.extend_from_slice(l_domain);
        message.extend_from_slice(&block_hash);

        let partials = keypairs
            .iter()
            .map(|(index, secret_key)| (*index, secret_key.sign(&message).into()))
            .collect::<Vec<_>>();
        let aggregated_signature = ThresholdProof::combine_partials(&partials).expect("combine");

        let l_small = LNotarization::<6, 1>::new(7, block_hash, aggregated_signature, 42);
        let l_large = LNotarization::<50, 9>::new(7, block_hash, aggregated_signature, 42);

        let small_bytes = serialize_for_db(&l_small).expect("serialize small");
        let large_bytes = serialize_for_db(&l_large).expect("serialize large");

        assert_eq!(
            small_bytes.len(),
            large_bytes.len(),
            "compact L notarization size must not scale with validator-set size"
        );
    }
}
