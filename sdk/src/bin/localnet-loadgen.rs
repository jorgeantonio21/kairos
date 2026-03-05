use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use kairos_sdk::{Address, KairosClient, TxBuilder, Wallet};

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * ((sorted.len() - 1) as f64)).round() as usize;
    sorted[rank]
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let duration_secs = env_u64("LOADGEN_DURATION_SECS", 60);
    let workers = env_usize("LOADGEN_WORKERS", 12);
    let timeout_secs = env_u64("LOADGEN_TX_TIMEOUT_SECS", 20);
    let endpoints = std::env::var("LOADGEN_ENDPOINTS")
        .unwrap_or_else(|_| {
            "http://127.0.0.1:50051,http://127.0.0.1:50052,http://127.0.0.1:50053,http://127.0.0.1:50054,http://127.0.0.1:50055,http://127.0.0.1:50056".to_string()
        })
        .split(',')
        .map(|s| s.trim().to_string())
        .collect::<Vec<_>>();

    if endpoints.is_empty() {
        anyhow::bail!("LOADGEN_ENDPOINTS is empty");
    }

    let submitted = Arc::new(AtomicU64::new(0));
    let finalized = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let latencies_ms = Arc::new(Mutex::new(Vec::<u64>::new()));

    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let mut handles = Vec::with_capacity(workers);

    for worker_idx in 0..workers {
        let endpoint = endpoints[worker_idx % endpoints.len()].clone();
        let submitted = Arc::clone(&submitted);
        let finalized = Arc::clone(&finalized);
        let rejected = Arc::clone(&rejected);
        let latencies_ms = Arc::clone(&latencies_ms);

        let handle = tokio::spawn(async move {
            let client = match KairosClient::connect(&endpoint).await {
                Ok(c) => c,
                Err(_) => return,
            };

            let wallet = Wallet::generate();
            let recipient = Address::from_bytes([worker_idx as u8; 32]);
            let mut nonce = 0_u64;

            while Instant::now() < deadline {
                let tx = match TxBuilder::mint(recipient, 1).sign(&wallet, nonce) {
                    Ok(tx) => tx,
                    Err(_) => {
                        rejected.fetch_add(1, Ordering::Relaxed);
                        nonce = nonce.saturating_add(1);
                        continue;
                    }
                };

                submitted.fetch_add(1, Ordering::Relaxed);
                let started = Instant::now();
                let res = client
                    .submit_and_wait(tx, Duration::from_secs(timeout_secs))
                    .await;

                match res {
                    Ok(_) => {
                        finalized.fetch_add(1, Ordering::Relaxed);
                        let latency_ms = started.elapsed().as_millis() as u64;
                        if let Ok(mut guard) = latencies_ms.lock() {
                            guard.push(latency_ms);
                        }
                    }
                    Err(_) => {
                        rejected.fetch_add(1, Ordering::Relaxed);
                    }
                }

                nonce = nonce.saturating_add(1);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    let elapsed_secs = duration_secs as f64;
    let submitted_total = submitted.load(Ordering::Relaxed);
    let finalized_total = finalized.load(Ordering::Relaxed);
    let rejected_total = rejected.load(Ordering::Relaxed);

    let mut latencies = latencies_ms.lock().map(|g| g.clone()).unwrap_or_default();
    latencies.sort_unstable();

    let p50 = percentile(&latencies, 50.0);
    let p95 = percentile(&latencies, 95.0);
    let p99 = percentile(&latencies, 99.0);

    let submitted_tps = submitted_total as f64 / elapsed_secs;
    let finalized_tps = finalized_total as f64 / elapsed_secs;
    let inclusion_rate = if submitted_total > 0 {
        finalized_total as f64 / submitted_total as f64
    } else {
        0.0
    };

    println!(
        "LOADGEN_METRICS submitted_tps={:.4} finalized_tps={:.4} inclusion_rate={:.4} latency_p50_ms={} latency_p95_ms={} latency_p99_ms={} submitted={} finalized={} rejected={} duration_secs={}",
        submitted_tps,
        finalized_tps,
        inclusion_rate,
        p50,
        p95,
        p99,
        submitted_total,
        finalized_total,
        rejected_total,
        duration_secs
    );

    Ok(())
}
