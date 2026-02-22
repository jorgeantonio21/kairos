//! Consensus metrics for Prometheus monitoring.
//!
//! Non-generic struct holding pre-registered metric handles from the `metrics` crate.
//! After first access, all metric operations (counter increment, gauge set, histogram record)
//! resolve to cached function pointers with <5ns overhead per call.
//!
//! # Usage
//!
//! ```ignore
//! let m = ConsensusMetrics::new();
//! m.current_view.set(42.0);
//! m.blocks_finalized_total.increment(1);
//! m.finalization_latency_seconds.record(0.123);
//! ```
//!
//! Works without an installed recorder (no-op fallback), so tests need no setup.

use metrics::{
    Counter, Gauge, Histogram, counter, describe_counter, describe_gauge, describe_histogram,
    gauge, histogram,
};

/// All consensus-related metric handles.
///
/// Constructed once at startup, then passed by reference into the consensus engine,
/// state machine, and view manager. Non-generic to avoid polluting `<N, F, M_SIZE>` signatures.
pub struct ConsensusMetrics {
    // -- View Progression --
    pub current_view: Gauge,
    pub finalized_view: Gauge,
    pub views_since_finalization: Gauge,
    pub non_finalized_views: Gauge,

    // -- Finalization --
    pub blocks_finalized_total: Counter,
    pub finalization_latency_seconds: Histogram,

    // -- Notarizations --
    pub m_notarizations_total: Counter,
    pub l_notarizations_total: Counter,

    // -- Nullification --
    pub nullifications_total: Counter,
    pub cascade_nullifications_total: Counter,
    pub nullify_messages_sent_total: Counter,
    pub view_timeouts_total: Counter,

    // -- Voting --
    pub votes_sent_total: Counter,
    pub votes_received_valid: Counter,
    pub votes_received_duplicate: Counter,
    pub votes_received_invalid: Counter,

    // -- Block Proposals --
    pub proposals_total: Counter,
    pub proposals_empty_total: Counter,
    pub proposal_build_duration_seconds: Histogram,

    // -- Block Validation --
    pub block_validation_duration_seconds: Histogram,
    pub blocks_validated_success: Counter,
    pub blocks_validated_failure: Counter,

    // -- Messages --
    pub messages_block_proposal: Counter,
    pub messages_vote: Counter,
    pub messages_nullify: Counter,
    pub messages_m_notarization: Counter,
    pub messages_nullification: Counter,
    pub messages_block_recovery: Counter,
    pub message_processing_duration_seconds: Histogram,

    // -- Mempool --
    pub mempool_pending_count: Gauge,
    pub mempool_queued_count: Gauge,
    pub transactions_received_total: Counter,
    pub transactions_invalid_signature_total: Counter,

    // -- Ring Buffers --
    pub ring_buffer_consensus_msgs: Gauge,
    pub ring_buffer_broadcast: Gauge,
    pub ring_buffer_proposal_req: Gauge,
    pub ring_buffer_proposal_resp: Gauge,
    pub ring_buffer_finalized: Gauge,

    // -- Tick --
    pub tick_duration_seconds: Histogram,
}

impl ConsensusMetrics {
    /// Create a new set of metric handles.
    ///
    /// Safe to call without an installed recorder (all operations become no-ops).
    pub fn new() -> Self {
        Self {
            // View Progression
            current_view: gauge!("consensus.current_view"),
            finalized_view: gauge!("consensus.finalized_view"),
            views_since_finalization: gauge!("consensus.views_since_finalization"),
            non_finalized_views: gauge!("consensus.non_finalized_views"),

            // Finalization
            blocks_finalized_total: counter!("consensus.blocks_finalized_total"),
            finalization_latency_seconds: histogram!("consensus.finalization_latency_seconds"),

            // Notarizations
            m_notarizations_total: counter!("consensus.m_notarizations_total"),
            l_notarizations_total: counter!("consensus.l_notarizations_total"),

            // Nullification
            nullifications_total: counter!("consensus.nullifications_total"),
            cascade_nullifications_total: counter!("consensus.cascade_nullifications_total"),
            nullify_messages_sent_total: counter!("consensus.nullify_messages_sent_total"),
            view_timeouts_total: counter!("consensus.view_timeouts_total"),

            // Voting
            votes_sent_total: counter!("consensus.votes_sent_total"),
            votes_received_valid: counter!("consensus.votes_received_total", "result" => "valid"),
            votes_received_duplicate: counter!("consensus.votes_received_total", "result" => "duplicate"),
            votes_received_invalid: counter!("consensus.votes_received_total", "result" => "invalid"),

            // Block Proposals
            proposals_total: counter!("consensus.proposals_total"),
            proposals_empty_total: counter!("consensus.proposals_empty_total"),
            proposal_build_duration_seconds: histogram!(
                "consensus.proposal_build_duration_seconds"
            ),

            // Block Validation
            block_validation_duration_seconds: histogram!(
                "consensus.block_validation_duration_seconds"
            ),
            blocks_validated_success: counter!("consensus.blocks_validated_total", "result" => "success"),
            blocks_validated_failure: counter!("consensus.blocks_validated_total", "result" => "failure"),

            // Messages (by type label)
            messages_block_proposal: counter!("consensus.messages_processed_total", "type" => "block_proposal"),
            messages_vote: counter!("consensus.messages_processed_total", "type" => "vote"),
            messages_nullify: counter!("consensus.messages_processed_total", "type" => "nullify"),
            messages_m_notarization: counter!("consensus.messages_processed_total", "type" => "m_notarization"),
            messages_nullification: counter!("consensus.messages_processed_total", "type" => "nullification"),
            messages_block_recovery: counter!("consensus.messages_processed_total", "type" => "block_recovery"),
            message_processing_duration_seconds: histogram!(
                "consensus.message_processing_duration_seconds"
            ),

            // Mempool
            mempool_pending_count: gauge!("consensus.mempool_pending_count"),
            mempool_queued_count: gauge!("consensus.mempool_queued_count"),
            transactions_received_total: counter!("consensus.transactions_received_total"),
            transactions_invalid_signature_total: counter!(
                "consensus.transactions_invalid_signature_total"
            ),

            // Ring Buffers
            ring_buffer_consensus_msgs: gauge!("consensus.ring_buffer_utilization", "channel" => "consensus_msgs"),
            ring_buffer_broadcast: gauge!("consensus.ring_buffer_utilization", "channel" => "broadcast"),
            ring_buffer_proposal_req: gauge!("consensus.ring_buffer_utilization", "channel" => "proposal_req"),
            ring_buffer_proposal_resp: gauge!("consensus.ring_buffer_utilization", "channel" => "proposal_resp"),
            ring_buffer_finalized: gauge!("consensus.ring_buffer_utilization", "channel" => "finalized"),

            // Tick
            tick_duration_seconds: histogram!("consensus.tick_duration_seconds"),
        }
    }

    /// Register Prometheus HELP text for all metrics.
    ///
    /// Call once after installing the Prometheus recorder so that `/metrics` output
    /// includes human-readable descriptions.
    pub fn describe() {
        // View Progression
        describe_gauge!("consensus.current_view", "Current active consensus view");
        describe_gauge!(
            "consensus.finalized_view",
            "Last L-notarized (finalized) view"
        );
        describe_gauge!(
            "consensus.views_since_finalization",
            "Gap between current and finalized view"
        );
        describe_gauge!(
            "consensus.non_finalized_views",
            "Number of non-finalized view contexts"
        );

        // Finalization
        describe_counter!(
            "consensus.blocks_finalized_total",
            "Total blocks finalized via L-notarization"
        );
        describe_histogram!(
            "consensus.finalization_latency_seconds",
            "Time from block proposal to L-notarization"
        );

        // Notarizations
        describe_counter!(
            "consensus.m_notarizations_total",
            "Total M-notarizations (2f+1 votes)"
        );
        describe_counter!(
            "consensus.l_notarizations_total",
            "Total L-notarizations (n-f votes)"
        );

        // Nullification
        describe_counter!(
            "consensus.nullifications_total",
            "Total aggregated nullifications broadcast"
        );
        describe_counter!(
            "consensus.cascade_nullifications_total",
            "Total cascade nullification events"
        );
        describe_counter!(
            "consensus.nullify_messages_sent_total",
            "Total individual nullify messages sent"
        );
        describe_counter!(
            "consensus.view_timeouts_total",
            "Total view timeout nullifications"
        );

        // Voting
        describe_counter!(
            "consensus.votes_sent_total",
            "Total votes cast by this replica"
        );
        describe_counter!(
            "consensus.votes_received_total",
            "Total votes received by result"
        );

        // Block Proposals
        describe_counter!(
            "consensus.proposals_total",
            "Total block proposals built as leader"
        );
        describe_counter!(
            "consensus.proposals_empty_total",
            "Total empty block proposals"
        );
        describe_histogram!(
            "consensus.proposal_build_duration_seconds",
            "Time to build a block proposal"
        );

        // Block Validation
        describe_histogram!(
            "consensus.block_validation_duration_seconds",
            "Time to validate a block"
        );
        describe_counter!(
            "consensus.blocks_validated_total",
            "Total blocks validated by result"
        );

        // Messages
        describe_counter!(
            "consensus.messages_processed_total",
            "Total consensus messages processed by type"
        );
        describe_histogram!(
            "consensus.message_processing_duration_seconds",
            "Per-message processing latency"
        );

        // Mempool
        describe_gauge!(
            "consensus.mempool_pending_count",
            "Number of transactions in pending pool"
        );
        describe_gauge!(
            "consensus.mempool_queued_count",
            "Number of transactions in queued pool"
        );
        describe_counter!(
            "consensus.transactions_received_total",
            "Total transactions ingested"
        );
        describe_counter!(
            "consensus.transactions_invalid_signature_total",
            "Total transactions rejected for invalid signature"
        );

        // Ring Buffers
        describe_gauge!(
            "consensus.ring_buffer_utilization",
            "Ring buffer utilization ratio per channel"
        );

        // Tick
        describe_histogram!(
            "consensus.tick_duration_seconds",
            "Time spent in tick() processing"
        );
    }
}

impl Default for ConsensusMetrics {
    fn default() -> Self {
        Self::new()
    }
}
