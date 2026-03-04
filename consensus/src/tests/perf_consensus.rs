//! Consensus Performance Integration Tests
//!
//! These tests emit machine-readable metrics for CI regression gating.

use super::{e2e_consensus::create_test_logger, network_simulator::LocalNetwork, test_helpers::*};
use crate::{
    consensus_manager::consensus_engine::ConsensusEngine, metrics::ConsensusMetrics,
    state::transaction::Transaction,
};
use std::{
    collections::{HashMap, HashSet},
    env,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn percentile_ms(sorted_values_ms: &[u64], percentile: f64) -> u64 {
    if sorted_values_ms.is_empty() {
        return 0;
    }
    let rank = ((percentile / 100.0) * ((sorted_values_ms.len() - 1) as f64)).round() as usize;
    sorted_values_ms[rank]
}

#[test]
#[ignore] // Run with: cargo test --package consensus --lib test_perf_consensus_steady_state -- --ignored --nocapture
fn test_perf_consensus_steady_state() {
    let logger = create_test_logger();

    let total_duration_secs = env_usize("PERF_TEST_DURATION_SECS", 30) as u64;
    let warmup_secs = env_usize("PERF_TEST_WARMUP_SECS", 10) as u64;
    let tx_interval_ms = env_usize("PERF_TEST_TX_INTERVAL_MS", 100) as u64;
    let tx_batch_size = env_usize("PERF_TEST_TX_BATCH_SIZE", 1);

    assert!(
        total_duration_secs > warmup_secs,
        "duration must be greater than warmup"
    );

    let total_duration = Duration::from_secs(total_duration_secs);
    let warmup_duration = Duration::from_secs(warmup_secs);
    let tx_interval = Duration::from_millis(tx_interval_ms);

    let fixture_tx_budget =
        (total_duration_secs * 1000 / tx_interval_ms) as usize * tx_batch_size + 500;
    let (mut all_transactions, genesis_accounts) =
        create_funded_test_transactions(fixture_tx_budget);
    let fixture = TestFixture::with_genesis_accounts(genesis_accounts);

    let mut network = LocalNetwork::<N, F, M_SIZE>::new();
    let mut replica_setups = Vec::with_capacity(N);
    let mut peer_id_to_secret_key = HashMap::new();

    for kp in &fixture.keypairs {
        peer_id_to_secret_key.insert(kp.public_key.to_peer_id(), kp.secret_key.clone());
    }

    for (i, &peer_id) in fixture.peer_set.sorted_peer_ids.iter().enumerate() {
        let secret_key = peer_id_to_secret_key
            .get(&peer_id)
            .expect("secret key not found")
            .clone();
        let replica_logger = logger.new(slog::o!("replica" => i, "peer_id" => peer_id));
        replica_setups.push(ReplicaSetup::new(peer_id, secret_key, replica_logger));
    }

    let mut engines = Vec::with_capacity(N);
    let mut grpc_tx_queues = Vec::with_capacity(N);
    let mut mempool_services = Vec::with_capacity(N);
    let mut stores = Vec::with_capacity(N);

    for (i, setup) in replica_setups.into_iter().enumerate() {
        let replica_id = setup.replica_id;
        stores.push(setup.storage.clone());
        network.register_replica(replica_id, setup.message_producer, setup.broadcast_consumer);

        let replica_logger = logger.new(slog::o!("replica" => i, "peer_id" => replica_id));
        let engine = ConsensusEngine::<N, F, M_SIZE>::new(
            fixture.config.clone(),
            replica_id,
            setup.secret_key,
            setup.message_consumer,
            setup.broadcast_notify,
            setup.broadcast_producer,
            setup.proposal_req_producer,
            setup.proposal_resp_consumer,
            setup.finalized_producer,
            setup.persistence_writer,
            DEFAULT_TICK_INTERVAL,
            Arc::new(ConsensusMetrics::new()),
            None,
            replica_logger,
        )
        .expect("failed to create consensus engine");

        engines.push(engine);
        grpc_tx_queues.push(setup.grpc_tx_queue);
        mempool_services.push(setup.mempool_service);
    }

    network.start();
    assert!(network.is_running(), "network should be running");

    let mut tx_index = 0usize;
    let mut last_polled_blocks = 0usize;
    let mut seen_finalized_hashes = HashSet::new();
    let mut submitted_at: HashMap<[u8; 32], Instant> = HashMap::new();
    let mut measured_submitted = 0usize;
    let mut measured_finalized = 0usize;
    let mut finalize_latencies_ms = Vec::new();
    let mut measurement_start: Option<Instant> = None;
    let mut start_view_at_measurement = 0u64;

    let start = Instant::now();
    while start.elapsed() < total_duration && !all_transactions.is_empty() {
        let now = Instant::now();
        let in_measurement = now.duration_since(start) >= warmup_duration;
        if in_measurement && measurement_start.is_none() {
            measurement_start = Some(now);
            let blocks = stores[0]
                .get_all_finalized_blocks()
                .expect("failed to read finalized blocks");
            start_view_at_measurement = blocks.last().map(|b| b.view()).unwrap_or(0);
            last_polled_blocks = blocks.len();
        }

        let batch = tx_batch_size.min(all_transactions.len());
        for _ in 0..batch {
            if let Some(tx) = all_transactions.pop() {
                let tx_hash = tx.tx_hash;
                let replica_idx = tx_index % N;
                tx_index += 1;

                if grpc_tx_queues[replica_idx].push(tx).is_ok() && in_measurement {
                    measured_submitted += 1;
                    submitted_at.insert(tx_hash, now);
                }
            }
        }

        let blocks = stores[0]
            .get_all_finalized_blocks()
            .expect("failed to read finalized blocks");
        if blocks.len() > last_polled_blocks {
            for block in blocks.iter().skip(last_polled_blocks) {
                for tx in &block.transactions {
                    if seen_finalized_hashes.insert(tx.tx_hash)
                        && let Some(submitted_instant) = submitted_at.get(&tx.tx_hash)
                    {
                        measured_finalized += 1;
                        let latency = Instant::now()
                            .saturating_duration_since(*submitted_instant)
                            .as_millis() as u64;
                        finalize_latencies_ms.push(latency);
                    }
                }
            }
            last_polled_blocks = blocks.len();
        }

        thread::sleep(tx_interval);
    }

    // Graceful shutdown
    for engine in &engines {
        engine.shutdown();
    }
    network.shutdown();
    for mut service in mempool_services {
        service.shutdown();
    }
    for engine in engines {
        engine
            .shutdown_and_wait(Duration::from_secs(10))
            .expect("engine shutdown failed");
    }

    let measurement_start = measurement_start.expect("measurement window did not start");
    let measurement_duration_secs = measurement_start.elapsed().as_secs_f64();
    assert!(
        measurement_duration_secs > 0.0,
        "measurement duration must be > 0"
    );

    let blocks = stores[0]
        .get_all_finalized_blocks()
        .expect("failed to read finalized blocks");
    let end_view = blocks
        .last()
        .map(|b| b.view())
        .unwrap_or(start_view_at_measurement);
    let view_delta = end_view.saturating_sub(start_view_at_measurement);
    let views_per_sec = view_delta as f64 / measurement_duration_secs;

    finalize_latencies_ms.sort_unstable();
    let p50 = percentile_ms(&finalize_latencies_ms, 50.0);
    let p95 = percentile_ms(&finalize_latencies_ms, 95.0);
    let p99 = percentile_ms(&finalize_latencies_ms, 99.0);

    let submitted_tps = measured_submitted as f64 / measurement_duration_secs;
    let finalized_tps = measured_finalized as f64 / measurement_duration_secs;
    let inclusion_rate = if measured_submitted > 0 {
        measured_finalized as f64 / measured_submitted as f64
    } else {
        0.0
    };

    assert!(view_delta > 0, "no finalized view progress");
    assert!(measured_submitted > 0, "no measured transactions submitted");
    assert!(measured_finalized > 0, "no measured transactions finalized");

    println!(
        "PERF_METRICS scenario=steady_state views_per_sec={:.4} latency_p50_ms={} latency_p95_ms={} latency_p99_ms={} submitted_tps={:.4} finalized_tps={:.4} inclusion_rate={:.4} measurement_duration_secs={:.2} view_delta={} submitted_txs={} finalized_txs={}",
        views_per_sec,
        p50,
        p95,
        p99,
        submitted_tps,
        finalized_tps,
        inclusion_rate,
        measurement_duration_secs,
        view_delta,
        measured_submitted,
        measured_finalized
    );
}
