mod server;

pub use server::run_server;

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

const RING_SIZE: usize = 256;

/// Returns current epoch in milliseconds.
pub fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Per-view state slot in the ring buffer.
///
/// Indexed by `view % RING_SIZE`. All fields are atomics for lock-free
/// writes from the consensus thread and reads from the axum SSE handler.
pub struct ViewSlot {
    pub view: AtomicU64,
    pub leader: AtomicU64,
    pub vote_count: AtomicU64,
    pub nullify_count: AtomicU64,
    pub m_notarized_at: AtomicU64,
    pub l_notarized_at: AtomicU64,
    pub nullified_at: AtomicU64,
    pub started_at: AtomicU64,
    pub block_hash_lo: AtomicU64,
    pub block_hash_hi: AtomicU64,
    pub tx_count: AtomicU64,
}

impl ViewSlot {
    fn new() -> Self {
        Self {
            view: AtomicU64::new(0),
            leader: AtomicU64::new(0),
            vote_count: AtomicU64::new(0),
            nullify_count: AtomicU64::new(0),
            m_notarized_at: AtomicU64::new(0),
            l_notarized_at: AtomicU64::new(0),
            nullified_at: AtomicU64::new(0),
            started_at: AtomicU64::new(0),
            block_hash_lo: AtomicU64::new(0),
            block_hash_hi: AtomicU64::new(0),
            tx_count: AtomicU64::new(0),
        }
    }
}

/// Shared metrics between the consensus thread (writer) and the axum server (reader).
///
/// All fields are atomics. The consensus thread performs `Relaxed` stores (~1ns each).
/// The SSE handler performs `Relaxed` loads every 100ms to diff and push events.
pub struct DashboardMetrics {
    pub current_view: AtomicU64,
    pub finalized_view: AtomicU64,
    pub total_m_notarizations: AtomicU64,
    pub total_l_notarizations: AtomicU64,
    pub total_nullifications: AtomicU64,
    pub total_cascade_nullifications: AtomicU64,
    pub node_n: AtomicU64,
    pub node_f: AtomicU64,
    pub views: Box<[ViewSlot]>,
}

impl DashboardMetrics {
    pub fn new() -> Self {
        let mut views = Vec::with_capacity(RING_SIZE);
        for _ in 0..RING_SIZE {
            views.push(ViewSlot::new());
        }
        Self {
            current_view: AtomicU64::new(0),
            finalized_view: AtomicU64::new(0),
            total_m_notarizations: AtomicU64::new(0),
            total_l_notarizations: AtomicU64::new(0),
            total_nullifications: AtomicU64::new(0),
            total_cascade_nullifications: AtomicU64::new(0),
            node_n: AtomicU64::new(0),
            node_f: AtomicU64::new(0),
            views: views.into_boxed_slice(),
        }
    }

    /// Returns the slot for a given view number.
    pub fn slot(&self, view: u64) -> &ViewSlot {
        &self.views[(view as usize) % RING_SIZE]
    }

    /// Resets a slot and initializes it for a new view.
    pub fn init_view(&self, view: u64, leader: u64) {
        let slot = self.slot(view);
        slot.view.store(view, Relaxed);
        slot.leader.store(leader, Relaxed);
        slot.started_at.store(epoch_ms(), Relaxed);
        slot.vote_count.store(0, Relaxed);
        slot.nullify_count.store(0, Relaxed);
        slot.m_notarized_at.store(0, Relaxed);
        slot.l_notarized_at.store(0, Relaxed);
        slot.nullified_at.store(0, Relaxed);
        slot.tx_count.store(0, Relaxed);
        slot.block_hash_lo.store(0, Relaxed);
        slot.block_hash_hi.store(0, Relaxed);
        self.current_view.store(view, Relaxed);
    }
}

impl Default for DashboardMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of a single view slot (plain data, no atomics).
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
pub struct ViewSlotSnapshot {
    pub view: u64,
    pub leader: u64,
    pub vote_count: u64,
    pub nullify_count: u64,
    pub m_notarized_at: u64,
    pub l_notarized_at: u64,
    pub nullified_at: u64,
    pub started_at: u64,
    pub block_hash_lo: u64,
    pub block_hash_hi: u64,
    pub tx_count: u64,
}

impl ViewSlotSnapshot {
    fn from_slot(slot: &ViewSlot) -> Self {
        Self {
            view: slot.view.load(Relaxed),
            leader: slot.leader.load(Relaxed),
            vote_count: slot.vote_count.load(Relaxed),
            nullify_count: slot.nullify_count.load(Relaxed),
            m_notarized_at: slot.m_notarized_at.load(Relaxed),
            l_notarized_at: slot.l_notarized_at.load(Relaxed),
            nullified_at: slot.nullified_at.load(Relaxed),
            started_at: slot.started_at.load(Relaxed),
            block_hash_lo: slot.block_hash_lo.load(Relaxed),
            block_hash_hi: slot.block_hash_hi.load(Relaxed),
            tx_count: slot.tx_count.load(Relaxed),
        }
    }

    /// Format block hash as hex string from lo/hi parts.
    pub fn block_hash_hex(&self) -> String {
        if self.block_hash_lo == 0 && self.block_hash_hi == 0 {
            return String::new();
        }
        format!("{:016x}{:016x}", self.block_hash_hi, self.block_hash_lo)
    }
}

/// Full snapshot of all dashboard state.
#[derive(Clone, Default, Serialize)]
pub struct DashboardSnapshot {
    pub current_view: u64,
    pub finalized_view: u64,
    pub total_m_notarizations: u64,
    pub total_l_notarizations: u64,
    pub total_nullifications: u64,
    pub total_cascade_nullifications: u64,
    pub node_n: u64,
    pub node_f: u64,
    pub views: Vec<ViewSlotSnapshot>,
}

impl DashboardSnapshot {
    pub fn from_metrics(metrics: &DashboardMetrics) -> Self {
        let views: Vec<ViewSlotSnapshot> = metrics
            .views
            .iter()
            .map(ViewSlotSnapshot::from_slot)
            .collect();
        Self {
            current_view: metrics.current_view.load(Relaxed),
            finalized_view: metrics.finalized_view.load(Relaxed),
            total_m_notarizations: metrics.total_m_notarizations.load(Relaxed),
            total_l_notarizations: metrics.total_l_notarizations.load(Relaxed),
            total_nullifications: metrics.total_nullifications.load(Relaxed),
            total_cascade_nullifications: metrics.total_cascade_nullifications.load(Relaxed),
            node_n: metrics.node_n.load(Relaxed),
            node_f: metrics.node_f.load(Relaxed),
            views,
        }
    }

    /// Produce SSE events for any fields that changed since `prev`.
    pub fn diff(&self, prev: &Self) -> Vec<SseEvent> {
        let mut events = Vec::new();

        if self.current_view != prev.current_view {
            events.push(SseEvent::CurrentViewChanged {
                view: self.current_view,
            });
        }
        if self.finalized_view != prev.finalized_view {
            events.push(SseEvent::FinalizedViewChanged {
                view: self.finalized_view,
            });
        }
        if self.total_m_notarizations != prev.total_m_notarizations {
            events.push(SseEvent::TotalsChanged {
                m_notarizations: self.total_m_notarizations,
                l_notarizations: self.total_l_notarizations,
                nullifications: self.total_nullifications,
                cascade_nullifications: self.total_cascade_nullifications,
            });
        }

        // Diff per-view slots
        for (i, cur) in self.views.iter().enumerate() {
            if cur.view == 0 {
                continue;
            }
            let prv = &prev.views[i];
            if cur == prv {
                continue;
            }

            if cur.view != prv.view {
                events.push(SseEvent::ViewStarted {
                    view: cur.view,
                    leader: cur.leader,
                    timestamp: cur.started_at,
                });
            }
            if cur.vote_count != prv.vote_count {
                events.push(SseEvent::VoteCountChanged {
                    view: cur.view,
                    count: cur.vote_count,
                });
            }
            if cur.nullify_count != prv.nullify_count {
                events.push(SseEvent::NullifyCountChanged {
                    view: cur.view,
                    count: cur.nullify_count,
                });
            }
            if cur.m_notarized_at != prv.m_notarized_at && cur.m_notarized_at != 0 {
                events.push(SseEvent::MNotarization {
                    view: cur.view,
                    timestamp: cur.m_notarized_at,
                    block_hash: cur.block_hash_hex(),
                    vote_count: cur.vote_count,
                });
            }
            if cur.l_notarized_at != prv.l_notarized_at && cur.l_notarized_at != 0 {
                events.push(SseEvent::LNotarization {
                    view: cur.view,
                    timestamp: cur.l_notarized_at,
                    block_hash: cur.block_hash_hex(),
                    vote_count: cur.vote_count,
                });
            }
            if cur.nullified_at != prv.nullified_at && cur.nullified_at != 0 {
                events.push(SseEvent::Nullification {
                    view: cur.view,
                    timestamp: cur.nullified_at,
                    nullify_count: cur.nullify_count,
                });
            }
            if cur.block_hash_lo != prv.block_hash_lo || cur.block_hash_hi != prv.block_hash_hi {
                events.push(SseEvent::BlockProposed {
                    view: cur.view,
                    block_hash: cur.block_hash_hex(),
                    tx_count: cur.tx_count,
                });
            }
        }

        events
    }
}

/// SSE event types pushed to connected clients.
#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SseEvent {
    CurrentViewChanged {
        view: u64,
    },
    FinalizedViewChanged {
        view: u64,
    },
    TotalsChanged {
        m_notarizations: u64,
        l_notarizations: u64,
        nullifications: u64,
        cascade_nullifications: u64,
    },
    ViewStarted {
        view: u64,
        leader: u64,
        timestamp: u64,
    },
    VoteCountChanged {
        view: u64,
        count: u64,
    },
    NullifyCountChanged {
        view: u64,
        count: u64,
    },
    MNotarization {
        view: u64,
        timestamp: u64,
        block_hash: String,
        vote_count: u64,
    },
    LNotarization {
        view: u64,
        timestamp: u64,
        block_hash: String,
        vote_count: u64,
    },
    Nullification {
        view: u64,
        timestamp: u64,
        nullify_count: u64,
    },
    BlockProposed {
        view: u64,
        block_hash: String,
        tx_count: u64,
    },
}
