use rkyv::{Archive, Deserialize, Serialize};

use crypto::consensus_bls::PeerId;

/// [`Leader`] represents a leader in the consensus protocol, for a given view.
///
/// A leader is responsible for proposing a block for a given view. The leader
/// is selected using round-robin based on DKG indices.
#[derive(Archive, Deserialize, Serialize)]
pub struct Leader {
    /// The leader's PeerId (for P2P communication)
    pub peer_id: PeerId,
    /// The DKG index of the leader (1..n), used for threshold operations
    pub index: u64,
    /// The view number
    pub view: u64,
}

impl Leader {
    pub fn new(peer_id: PeerId, index: u64, view: u64) -> Self {
        Self {
            peer_id,
            index,
            view,
        }
    }

    /// Returns the leader's PeerId (for P2P)
    #[inline]
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the leader's DKG index (for threshold operations)
    #[inline]
    pub fn index(&self) -> u64 {
        self.index
    }

    /// Returns the view number
    #[inline]
    pub fn view(&self) -> u64 {
        self.view
    }

    /// Returns whether the leader is the current leader
    #[inline]
    pub fn is_leader_for_view(&self, view: u64) -> bool {
        self.view == view
    }
}
