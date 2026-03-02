use std::collections::HashMap;

use anyhow::Result;
use rkyv::{Archive, Deserialize, Serialize};

use crypto::consensus_bls::{BlsPublicKey, PeerId};

/// [`Peer`] represents a peer in the consensus protocol.
///
/// It is identified by its public key.
#[derive(Clone, Debug, Archive, Deserialize, Serialize)]
pub struct Peer {
    /// The peer's ID
    pub peer_id: PeerId,
    /// The peer's public key
    pub public_key: BlsPublicKey,
    /// Whether the peer is the current leader
    pub is_current_leader: bool,
}

impl Peer {
    pub fn new(public_key: BlsPublicKey, is_current_leader: bool) -> Self {
        Self {
            peer_id: public_key.to_peer_id(),
            public_key,
            is_current_leader,
        }
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.peer_id == other.peer_id
    }
}

impl Eq for Peer {}

/// [`PeerSet`] represents a set of peers in the consensus protocol.
///
/// It contains the peers' IDs and public keys, plus DKG indices for threshold operations.
///
/// ## Security Note
///
/// The `indices` field contains DKG-assigned participant indices (1..n), which should be
/// used for threshold signing and leader selection. This prevents vanity/selection bias
/// attacks that are possible when using hash-derived PeerIds.
#[derive(Clone, Debug)]
pub struct PeerSet {
    /// The map of peer IDs to public keys (for P2P and general use)
    pub id_to_public_key: HashMap<PeerId, BlsPublicKey>,
    /// Sorted vector of peer IDs (for P2P networking)
    pub sorted_peer_ids: Vec<PeerId>,
    /// Map from peer ID to participant index (1..=n) used for threshold interpolation.
    pub id_to_index: HashMap<PeerId, u64>,
    /// DKG indices [1, 2, ..., n] for threshold signing and leader selection.
    /// These are deterministic and cannot be biased by key mining.
    pub indices: Vec<u64>,
    /// Public verification keys for M-notarization/nullification threshold shares.
    pub id_to_m_share_public_key: HashMap<PeerId, BlsPublicKey>,
    /// Public verification keys for L-notarization threshold shares.
    pub id_to_l_share_public_key: HashMap<PeerId, BlsPublicKey>,
    /// Group public key for M-notarization/nullification threshold proofs.
    pub m_group_public_key: Option<BlsPublicKey>,
    /// Group public key for L-notarization threshold proofs.
    pub l_group_public_key: Option<BlsPublicKey>,
    /// Domain separator for M-notarization signatures.
    pub m_not_domain: Option<Vec<u8>>,
    /// Domain separator for nullification signatures.
    pub nullify_domain: Option<Vec<u8>>,
    /// Domain separator for L-notarization signatures.
    pub l_not_domain: Option<Vec<u8>>,
}

impl PeerSet {
    /// Creates a new peer set from a vector of public keys.
    ///
    /// The vector of public keys is expected to be sorted by peer ID.
    ///
    /// The sorting of the peer IDs is done in order to make sure that the order of the
    /// peers in the vector is the same as the order of the peer IDs in the sorted vector.
    /// This is useful for the round-robin leader selection strategy, where the leader is
    /// selected by the index of the replica in the vector of replicas.
    ///
    /// The `indices` field is automatically populated as [1, 2, ..., n] for deterministic
    /// threshold operations.
    ///
    /// # Panics
    ///
    /// Panics if the input vector of public keys contains either:
    /// - Duplicate public keys
    /// - Distinct public keys with the same peer ID
    pub fn new(peers: Vec<BlsPublicKey>) -> Self {
        let n = peers.len();
        if n == 0 {
            return Self {
                id_to_m_share_public_key: HashMap::new(),
                id_to_l_share_public_key: HashMap::new(),
                id_to_public_key: HashMap::new(),
                sorted_peer_ids: Vec::new(),
                id_to_index: HashMap::new(),
                indices: Vec::new(),
                m_group_public_key: None,
                l_group_public_key: None,
                m_not_domain: Some(Vec::new()),
                nullify_domain: Some(Vec::new()),
                l_not_domain: Some(Vec::new()),
            };
        }
        let original_len = peers.len();
        let mut id_to_public_key = HashMap::with_capacity(peers.len());
        let mut sorted_peer_ids = Vec::with_capacity(peers.len());
        for peer in peers {
            let peer_id = peer.to_peer_id();
            id_to_public_key.insert(peer_id, peer);
            sorted_peer_ids.push(peer_id);
        }
        sorted_peer_ids.sort();
        sorted_peer_ids.dedup();
        // Make sure there were no duplicates in the input.
        assert_eq!(sorted_peer_ids.len(), original_len);

        // DKG indices are always [1, 2, ..., n] - deterministic, no mining possible
        let indices: Vec<u64> = (1u64..=n as u64).collect();
        let id_to_index = sorted_peer_ids
            .iter()
            .copied()
            .zip(indices.iter().copied())
            .collect();

        let ordered_public_keys = sorted_peer_ids
            .iter()
            .map(|peer_id| {
                *id_to_public_key
                    .get(peer_id)
                    .expect("peer id must exist in id_to_public_key")
            })
            .collect::<Vec<_>>();
        let m_group_public_key =
            BlsPublicKey::interpolate_threshold_public_key(&ordered_public_keys, &indices)
                .expect("peer set interpolation must succeed for unique non-zero indices");
        let l_group_public_key =
            BlsPublicKey::interpolate_threshold_public_key(&ordered_public_keys, &indices)
                .expect("peer set interpolation must succeed for unique non-zero indices");

        Self {
            id_to_m_share_public_key: id_to_public_key.clone(),
            id_to_l_share_public_key: id_to_public_key.clone(),
            id_to_public_key,
            sorted_peer_ids,
            id_to_index,
            indices,
            m_group_public_key: Some(m_group_public_key),
            l_group_public_key: Some(l_group_public_key),
            m_not_domain: Some(Vec::new()),
            nullify_domain: Some(Vec::new()),
            l_not_domain: Some(Vec::new()),
        }
    }

    /// Creates a new peer set with explicit indices.
    ///
    /// Use this when the DKG indices are not simply [1..n], such as when
    /// participants join with specific assigned indices.
    pub fn with_indices(peers: Vec<BlsPublicKey>, indices: Vec<u64>) -> Self {
        let original_len = peers.len();
        assert_eq!(indices.len(), original_len);
        if original_len == 0 {
            return Self {
                id_to_m_share_public_key: HashMap::new(),
                id_to_l_share_public_key: HashMap::new(),
                id_to_public_key: HashMap::new(),
                sorted_peer_ids: Vec::new(),
                id_to_index: HashMap::new(),
                indices: Vec::new(),
                m_group_public_key: None,
                l_group_public_key: None,
                m_not_domain: Some(Vec::new()),
                nullify_domain: Some(Vec::new()),
                l_not_domain: Some(Vec::new()),
            };
        }

        let mut entries = peers
            .into_iter()
            .zip(indices.iter().copied())
            .map(|(public_key, index)| (public_key.to_peer_id(), public_key, index))
            .collect::<Vec<_>>();

        // Ensure there are no duplicate peer IDs.
        let mut sorted_peer_ids = entries
            .iter()
            .map(|(peer_id, _, _)| *peer_id)
            .collect::<Vec<_>>();
        sorted_peer_ids.sort();
        sorted_peer_ids.dedup();
        assert_eq!(sorted_peer_ids.len(), original_len);

        // Ensure participant indices are unique and non-zero.
        let mut unique_indices = entries
            .iter()
            .map(|(_, _, index)| *index)
            .collect::<Vec<_>>();
        unique_indices.sort_unstable();
        unique_indices.dedup();
        assert_eq!(unique_indices.len(), original_len);
        assert!(unique_indices.iter().all(|index| *index > 0));

        let id_to_public_key = entries
            .iter()
            .map(|(peer_id, public_key, _)| (*peer_id, *public_key))
            .collect::<HashMap<_, _>>();
        let id_to_index = entries
            .iter()
            .map(|(peer_id, _, index)| (*peer_id, *index))
            .collect::<HashMap<_, _>>();

        // In threshold mode, leadership order must follow participant indices.
        entries.sort_by_key(|(peer_id, _, index)| (*index, *peer_id));
        let sorted_peer_ids = entries
            .iter()
            .map(|(peer_id, _, _)| *peer_id)
            .collect::<Vec<_>>();

        let interpolation_indices = entries
            .iter()
            .map(|(_, _, index)| *index)
            .collect::<Vec<_>>();
        let ordered_public_keys = entries
            .iter()
            .map(|(_, public_key, _)| *public_key)
            .collect::<Vec<_>>();
        let m_group_public_key = BlsPublicKey::interpolate_threshold_public_key(
            &ordered_public_keys,
            &interpolation_indices,
        )
        .expect("peer set interpolation must succeed for unique non-zero indices");
        let l_group_public_key = BlsPublicKey::interpolate_threshold_public_key(
            &ordered_public_keys,
            &interpolation_indices,
        )
        .expect("peer set interpolation must succeed for unique non-zero indices");

        Self {
            id_to_m_share_public_key: id_to_public_key.clone(),
            id_to_l_share_public_key: id_to_public_key.clone(),
            id_to_public_key,
            sorted_peer_ids,
            id_to_index,
            indices,
            m_group_public_key: Some(m_group_public_key),
            l_group_public_key: Some(l_group_public_key),
            m_not_domain: Some(Vec::new()),
            nullify_domain: Some(Vec::new()),
            l_not_domain: Some(Vec::new()),
        }
    }

    /// Creates a peer set with explicit DKG indices, threshold verification keys, and domains.
    pub fn with_threshold_material(
        peers: Vec<BlsPublicKey>,
        indices: Vec<u64>,
        id_to_m_share_public_key: HashMap<PeerId, BlsPublicKey>,
        id_to_l_share_public_key: HashMap<PeerId, BlsPublicKey>,
        m_not_domain: Vec<u8>,
        nullify_domain: Vec<u8>,
        l_not_domain: Vec<u8>,
    ) -> Result<Self> {
        let mut peer_set = Self::with_indices(peers, indices);
        if peer_set.id_to_public_key.len() != id_to_m_share_public_key.len()
            || peer_set.id_to_public_key.len() != id_to_l_share_public_key.len()
        {
            return Err(anyhow::anyhow!(
                "threshold verification key maps must match validator set cardinality"
            ));
        }
        for peer_id in &peer_set.sorted_peer_ids {
            if !id_to_m_share_public_key.contains_key(peer_id) {
                return Err(anyhow::anyhow!(
                    "missing m-share verification key for peer_id {}",
                    peer_id
                ));
            }
            if !id_to_l_share_public_key.contains_key(peer_id) {
                return Err(anyhow::anyhow!(
                    "missing l-share verification key for peer_id {}",
                    peer_id
                ));
            }
        }
        peer_set.id_to_m_share_public_key = id_to_m_share_public_key;
        peer_set.id_to_l_share_public_key = id_to_l_share_public_key;
        let ordered_peer_ids = peer_set
            .id_to_index
            .iter()
            .map(|(peer_id, index)| (*index, *peer_id))
            .collect::<Vec<_>>();
        let mut ordered_peer_ids = ordered_peer_ids;
        ordered_peer_ids.sort_unstable_by_key(|(index, _)| *index);

        let m_public_keys = ordered_peer_ids
            .iter()
            .map(|(_, peer_id)| {
                peer_set
                    .id_to_m_share_public_key
                    .get(peer_id)
                    .copied()
                    .ok_or_else(|| {
                        anyhow::anyhow!("missing m-share verification key for peer_id {}", peer_id)
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let l_public_keys = ordered_peer_ids
            .iter()
            .map(|(_, peer_id)| {
                peer_set
                    .id_to_l_share_public_key
                    .get(peer_id)
                    .copied()
                    .ok_or_else(|| {
                        anyhow::anyhow!("missing l-share verification key for peer_id {}", peer_id)
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let interpolation_indices = ordered_peer_ids
            .iter()
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        peer_set.m_group_public_key = Some(BlsPublicKey::interpolate_threshold_public_key(
            &m_public_keys,
            &interpolation_indices,
        )?);
        peer_set.l_group_public_key = Some(BlsPublicKey::interpolate_threshold_public_key(
            &l_public_keys,
            &interpolation_indices,
        )?);
        peer_set.m_not_domain = Some(m_not_domain);
        peer_set.nullify_domain = Some(nullify_domain);
        peer_set.l_not_domain = Some(l_not_domain);
        Ok(peer_set)
    }

    /// Gets a public key from a peer ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the peer ID is not found in the peer set.
    pub fn get_public_key(&self, peer_id: &PeerId) -> Result<&BlsPublicKey> {
        if let Some(public_key) = self.id_to_public_key.get(peer_id) {
            Ok(public_key)
        } else {
            Err(anyhow::anyhow!("Peer ID {peer_id} not found in peer set"))
        }
    }

    /// Checks if a peer ID is in the peer set.
    pub fn contains(&self, peer_id: &PeerId) -> bool {
        self.id_to_public_key.contains_key(peer_id)
    }

    pub fn get_index(&self, peer_id: &PeerId) -> Result<u64> {
        self.id_to_index
            .get(peer_id)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Peer ID {peer_id} index not found in peer set"))
    }

    pub fn get_m_share_public_key(&self, peer_id: &PeerId) -> Result<&BlsPublicKey> {
        self.id_to_m_share_public_key
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("M-share public key for peer_id {peer_id} not found"))
    }

    pub fn get_l_share_public_key(&self, peer_id: &PeerId) -> Result<&BlsPublicKey> {
        self.id_to_l_share_public_key
            .get(peer_id)
            .ok_or_else(|| anyhow::anyhow!("L-share public key for peer_id {peer_id} not found"))
    }
}

// ... existing code ...

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::consensus_bls::BlsSecretKey;
    use rand::thread_rng;

    #[test]
    fn test_peer_new() {
        let mut rng = thread_rng();
        let secret_key = BlsSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        let expected_peer_id = public_key.to_peer_id();

        let peer = Peer::new(public_key, true);

        assert_eq!(peer.peer_id, expected_peer_id);
        assert_eq!(peer.public_key, public_key);
        assert!(peer.is_current_leader);
    }

    #[test]
    fn test_peer_equality() {
        let mut rng = thread_rng();
        let secret_key1 = BlsSecretKey::generate(&mut rng);
        let public_key1 = secret_key1.public_key();

        let secret_key2 = BlsSecretKey::generate(&mut rng);
        let public_key2 = secret_key2.public_key();

        // Same public key should create equal peers
        let peer1 = Peer::new(public_key1, true);
        let peer2 = Peer::new(public_key1, false);
        assert_eq!(peer1, peer2);

        // Different public keys should create unequal peers
        let peer3 = Peer::new(public_key2, true);
        assert_ne!(peer1, peer3);
    }

    #[test]
    fn test_peer_set_new_empty() {
        let peer_set = PeerSet::new(vec![]);
        assert!(peer_set.id_to_public_key.is_empty());
        assert!(peer_set.sorted_peer_ids.is_empty());
    }

    #[test]
    fn test_peer_set_new_single_peer() {
        let mut rng = thread_rng();
        let secret_key = BlsSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        let expected_peer_id = public_key.to_peer_id();

        let peer_set = PeerSet::new(vec![public_key]);

        assert_eq!(peer_set.id_to_public_key.len(), 1);
        assert_eq!(peer_set.sorted_peer_ids.len(), 1);
        assert_eq!(peer_set.sorted_peer_ids[0], expected_peer_id);
        assert_eq!(peer_set.id_to_public_key[&expected_peer_id], public_key);
    }

    #[test]
    fn test_peer_set_new_multiple_peers() {
        let mut rng = thread_rng();
        let mut public_keys = vec![];
        let mut expected_peer_ids = vec![];

        // Generate multiple distinct public keys
        for _ in 0..5 {
            let secret_key = BlsSecretKey::generate(&mut rng);
            let public_key = secret_key.public_key();
            let peer_id = public_key.to_peer_id();
            public_keys.push(public_key);
            expected_peer_ids.push(peer_id);
        }

        let peer_set = PeerSet::new(public_keys.clone());

        assert_eq!(peer_set.id_to_public_key.len(), 5);
        assert_eq!(peer_set.sorted_peer_ids.len(), 5);

        // Check that sorted_peer_ids is actually sorted
        let mut sorted_expected = expected_peer_ids.clone();
        sorted_expected.sort();
        assert_eq!(peer_set.sorted_peer_ids, sorted_expected);

        // Check that all peer IDs are correctly mapped
        for (i, peer_id) in expected_peer_ids.iter().enumerate() {
            assert_eq!(peer_set.id_to_public_key[peer_id], public_keys[i]);
        }
    }

    #[test]
    #[should_panic]
    fn test_peer_set_new_duplicate_public_keys() {
        let mut rng = thread_rng();
        let secret_key = BlsSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();

        // Try to create PeerSet with duplicate public keys
        let _peer_set = PeerSet::new(vec![public_key, public_key]);
    }

    #[test]
    fn test_peer_set_get_public_key_existing() {
        let mut rng = thread_rng();
        let secret_key = BlsSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();
        let peer_id = public_key.to_peer_id();

        let peer_set = PeerSet::new(vec![public_key]);

        let result = peer_set.get_public_key(&peer_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &public_key);
    }

    #[test]
    fn test_peer_set_get_public_key_non_existing() {
        let mut rng = thread_rng();
        let secret_key = BlsSecretKey::generate(&mut rng);
        let public_key = secret_key.public_key();

        let peer_set = PeerSet::new(vec![public_key]);

        // Use a peer ID that doesn't exist
        let non_existing_peer_id = 999999999999;
        let result = peer_set.get_public_key(&non_existing_peer_id);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not found in peer set")
        );
    }

    #[test]
    fn test_peer_set_get_public_key_multiple_peers() {
        let mut rng = thread_rng();
        let mut public_keys = vec![];
        let mut peer_ids = vec![];

        // Generate multiple distinct public keys
        for _ in 0..3 {
            let secret_key = BlsSecretKey::generate(&mut rng);
            let public_key = secret_key.public_key();
            let peer_id = public_key.to_peer_id();
            public_keys.push(public_key);
            peer_ids.push(peer_id);
        }

        let peer_set = PeerSet::new(public_keys.clone());

        // Test getting each public key by its peer ID
        for (i, peer_id) in peer_ids.iter().enumerate() {
            let result = peer_set.get_public_key(peer_id);
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), &public_keys[i]);
        }
    }
}
