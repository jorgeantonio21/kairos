use crate::{crypto::consensus_bls::PeerId, state::leader::Leader};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// [`LeaderManager`] trait for managing leader selection.
///
/// One essential aspect of any derived implementation is the ability to
/// select the leader for a given view, in a fully deterministic and reproducible way.
/// This is crucial for the safety of the consensus protocol, and to make sure
/// that replicas are always able to agree on the leader for a view, given its past
/// state.
pub trait LeaderManager: Send {
    /// Selects the leader for a given view.
    fn leader_for_view(&self, view: u64) -> Result<Leader>;
}

/// [`RoundRobinLeaderManager`] implements the round-robin leader selection strategy.
///
/// This strategy selects the leader for a given view by using a round-robin approach
/// based on DKG indices. Using indices instead of hash-derived PeerIds prevents
/// vanity/selection bias attacks where a node could mine for favorable positions.
///
/// The leader is selected by: `view % n` to get an index, then mapping that to a PeerId.
pub(crate) struct RoundRobinLeaderManager {
    /// The number of replicas in the consensus protocol.
    n: usize,

    /// PeerIds for P2P communication (sorted).
    pub replicas: Vec<PeerId>,

    /// DKG participant indices aligned with `replicas`.
    indices: Vec<u64>,
}

impl RoundRobinLeaderManager {
    /// Creates a new round-robin leader manager.
    ///
    /// # Arguments
    /// * `n` - The total number of replicas in the consensus protocol
    /// * `replicas` - A **sorted** vector of replica peer IDs (for P2P)
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - The `replicas` vector is not sorted in ascending order
    /// - The length of `replicas` does not match `n`
    #[cfg(test)]
    pub fn new(n: usize, replicas: Vec<PeerId>) -> Self {
        let indices = (1u64..=n as u64).collect::<Vec<_>>();
        Self::new_with_indices(n, replicas, indices)
    }

    /// Creates a round-robin leader manager using explicit participant indices aligned with
    /// `replicas`.
    pub fn new_with_indices(n: usize, replicas: Vec<PeerId>, indices: Vec<u64>) -> Self {
        assert_eq!(
            replicas.len(),
            n,
            "Replicas count mismatch: expected {}, got {}",
            n,
            replicas.len()
        );
        assert_eq!(
            indices.len(),
            n,
            "Indices count mismatch: expected {}, got {}",
            n,
            indices.len()
        );

        // Verify that the replicas are sorted (for deterministic P2P)
        for i in 1..replicas.len() {
            assert!(
                replicas[i - 1] < replicas[i],
                "Replicas must be sorted in ascending order. \
                Found {} >= {} at indices {} and {}. \
                Use PeerSet::sorted_peer_ids to ensure proper ordering.",
                replicas[i - 1],
                replicas[i],
                i - 1,
                i
            );
        }

        Self {
            n,
            replicas,
            indices,
        }
    }
}

impl LeaderManager for RoundRobinLeaderManager {
    fn leader_for_view(&self, view: u64) -> Result<Leader> {
        // Use DKG index for selection - deterministic, cannot be biased
        let leader_index = (view as usize) % self.n;
        let leader_idx = self.indices[leader_index];
        let leader_peer_id = self.replicas[leader_index];
        Ok(Leader::new(leader_peer_id, leader_idx, view))
    }
}

/// [`LeaderSelectionStrategy`] represents the strategy used to select the leader for a given view.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaderSelectionStrategy {
    /// [`RoundRobin`] selects the leader for a given view by using a round-robin approach.
    /// The leader is selected by the index of the replica in the (deterministic) list of replicas.
    RoundRobin,

    /// [`Random`] selects the leader for a given view by using a random approach.
    /// The leader is selected by a random number generator.
    Random,

    /// [`ProofOfStake`] selects the leader for a given view by using a proof-of-stake approach.
    /// The leader is selected by the proof-of-stake mechanism.
    ProofOfStake,
}
