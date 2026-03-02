//! Kairos Validator Node Binary
//!
//! This binary runs a validator node for the Kairos consensus network.
//!
//! # Usage
//!
//! Run a node with a configuration file:
//! ```bash
//! cargo run --package node -- run --config node/config/node0.toml
//! ```
//!
//! Regenerate local network configs (if needed):
//! ```bash
//! cargo run --package node -- generate-configs
//! ```

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use slog::{Drain, Logger, o};

use ark_serialize::CanonicalSerialize;
use commonware_runtime::Runner;
use commonware_runtime::tokio::Runner as TokioRunner;
use consensus::crypto::consensus_bls::BlsSecretKey;
use consensus::metrics::ConsensusMetrics;
use crypto::bls::ops::public_key_from_scalar;
use crypto::dkg::run_in_memory_dual_dkg;
use crypto::threshold_setup::{
    ThresholdDomains, ThresholdKeyset, ThresholdKeysets, ThresholdSetupArtifact,
    ValidatorParticipant,
};
use metrics_exporter_prometheus::PrometheusHandle;
use node::ValidatorNode;
use node::config::LogFormat;
use p2p::ValidatorIdentity;
use rand::SeedableRng;

/// Network size constants
const N: usize = 6;
const F: usize = 1;
const M_SIZE: usize = 3;

/// Base ports for local network
const BASE_P2P_PORT: u16 = 9000;
const BASE_GRPC_PORT: u16 = 50051;
const PORT_GAP: u16 = 100;

/// Fixed seed for deterministic key generation
const LOCAL_NETWORK_SEED: u64 = 42;
const LOCAL_THRESHOLD_ARTIFACT_SEED: u64 = 4242;

#[derive(Parser, Debug)]
#[command(name = "kairos-node")]
#[command(about = "Kairos validator node for the Minimmit consensus protocol")]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info", global = true)]
    log_level: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a validator node
    Run {
        /// Path to the configuration file
        #[arg(short, long)]
        config: PathBuf,

        /// Override the node index (defaults to rpc.peer_id from config)
        #[arg(long)]
        node_index: Option<usize>,
    },

    /// Regenerate local network config files
    GenerateConfigs {
        /// Output directory
        #[arg(short, long, default_value = "node/config")]
        output_dir: PathBuf,
    },
    /// Generate threshold setup artifacts for deterministic local validators.
    GenerateThresholdArtifacts {
        /// Output directory for per-validator artifact JSON files.
        #[arg(short, long, default_value = "node/config/threshold")]
        output_dir: PathBuf,
        /// Validator set id encoded in artifacts.
        #[arg(long, default_value = "kairos-local-vs-1")]
        validator_set_id: String,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Run { config, node_index } => {
            // Load config first to get logging settings
            let node_config = node::NodeConfig::from_path(&config)
                .with_context(|| format!("Failed to load config from {}", config.display()))?;

            let logger = create_logger(&args.log_level, &node_config.logging);

            // Install Prometheus exporter if enabled
            let prometheus_handle = if node_config.metrics.enabled {
                let metrics_addr = node_config.metrics.listen_address;
                let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
                let handle = builder
                    .install_recorder()
                    .context("Failed to install Prometheus metrics exporter")?;
                ConsensusMetrics::describe();
                spawn_metrics_http_server(metrics_addr, handle.clone(), logger.clone())
                    .context("Failed to start Prometheus metrics HTTP server")?;
                slog::info!(
                    logger,
                    "Prometheus metrics exporter started";
                    "listen_address" => %metrics_addr,
                );
                Some(handle)
            } else {
                None
            };

            let shutdown = Arc::new(AtomicBool::new(false));
            ctrlc_handler(Arc::clone(&shutdown));
            run_node_with_config(
                config,
                node_config,
                node_index,
                prometheus_handle,
                logger,
                shutdown,
            )
        }
        Command::GenerateConfigs { output_dir } => {
            let logger = create_logger(&args.log_level, &node::config::LoggingConfig::default());
            generate_configs(&output_dir, logger)
        }
        Command::GenerateThresholdArtifacts {
            output_dir,
            validator_set_id,
        } => {
            let logger = create_logger(&args.log_level, &node::config::LoggingConfig::default());
            generate_threshold_artifacts(&output_dir, &validator_set_id, logger)
        }
    }
}

/// Run a validator node from a pre-loaded configuration.
fn run_node_with_config(
    config_path: PathBuf,
    config: node::NodeConfig,
    node_index_override: Option<usize>,
    prometheus_handle: Option<PrometheusHandle>,
    logger: Logger,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    slog::info!(logger, "Loading configuration"; "path" => %config_path.display());

    let node_index = node_index_override.unwrap_or(config.rpc.peer_id as usize);

    slog::info!(
        logger,
        "Configuration loaded";
        "node_index" => node_index,
        "p2p_addr" => %config.p2p.listen_addr,
        "grpc_addr" => %config.rpc.listen_addr,
    );

    // Generate deterministic identity
    let identities = generate_deterministic_identities(N);
    let identity = identities
        .into_iter()
        .nth(node_index)
        .context("Node index out of range")?;

    slog::info!(logger, "Starting validator"; "peer_id" => identity.peer_id());

    // Create parent directory of the storage path (storage.path is a file, not a directory)
    if let Some(parent) = std::path::Path::new(&config.storage.path).parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create storage directory: {}", parent.display()))?;
    }

    let node = ValidatorNode::<N, F, M_SIZE>::from_config(
        config,
        identity,
        prometheus_handle,
        logger.clone(),
    )?;

    slog::info!(logger, "Node spawned, waiting for P2P bootstrap...");

    let executor = TokioRunner::default();
    executor.start(|_ctx| async move {
        node.wait_ready().await;
        slog::info!(logger, "Node is ready and participating in consensus");

        while !shutdown.load(Ordering::Relaxed) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        slog::info!(logger, "Shutting down...");
        if let Err(e) = node.shutdown(Duration::from_secs(10)) {
            slog::error!(logger, "Shutdown error"; "error" => %e);
        }
    });

    Ok(())
}

/// Generate local network configuration files.
fn generate_configs(output_dir: &std::path::Path, logger: Logger) -> Result<()> {
    slog::info!(logger, "Generating configs"; "output_dir" => %output_dir.display());

    fs::create_dir_all(output_dir)?;

    let identities = generate_deterministic_identities(N);

    // Collect peer info
    let peers: Vec<PeerInfo> = identities
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let mut bls_buf = Vec::new();
            id.bls_public_key()
                .0
                .serialize_compressed(&mut bls_buf)
                .unwrap();

            PeerInfo {
                index: i,
                bls_pubkey: hex::encode(&bls_buf),
                ed25519_pubkey: hex::encode(id.ed25519_public_key().as_ref()),
                peer_id: id.peer_id(),
                p2p_port: BASE_P2P_PORT + (i as u16 * PORT_GAP),
                grpc_port: BASE_GRPC_PORT + i as u16,
            }
        })
        .collect();

    // Generate genesis accounts
    let genesis_accounts = generate_genesis_accounts();

    // Generate each node's config
    for i in 0..N {
        let content = build_config(i, &peers, &genesis_accounts);
        let path = output_dir.join(format!("node{}.toml", i));
        fs::write(&path, &content)?;
        slog::info!(logger, "Generated"; "file" => %path.display());
    }

    // Generate run script
    let script = build_run_script(output_dir);
    let script_path = output_dir.join("run-local-network.sh");
    fs::write(&script_path, &script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))?;
    }

    println!("\nGenerated {} config files in {}", N, output_dir.display());
    println!("\nTo run the local network:");
    println!("  {}", script_path.display());
    println!("\nOr run individual nodes:");
    for i in 0..N {
        println!(
            "  cargo run -p node -- run -c {}/node{}.toml",
            output_dir.display(),
            i
        );
    }

    Ok(())
}

struct PeerInfo {
    index: usize,
    bls_pubkey: String,
    ed25519_pubkey: String,
    peer_id: u64,
    p2p_port: u16,
    grpc_port: u16,
}

/// Generate deterministic genesis account keys for testing.
fn generate_genesis_accounts() -> Vec<(String, u64)> {
    // Use a different seed for genesis accounts
    let mut rng = rand::rngs::StdRng::seed_from_u64(1337);

    vec![
        {
            let key = ed25519_dalek::SigningKey::generate(&mut rng);
            let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
            (pubkey_hex, 1_000_000_000)
        },
        {
            let key = ed25519_dalek::SigningKey::generate(&mut rng);
            let pubkey_hex = hex::encode(key.verifying_key().as_bytes());
            (pubkey_hex, 500_000_000)
        },
    ]
}

fn build_config(node_idx: usize, peers: &[PeerInfo], genesis_accounts: &[(String, u64)]) -> String {
    let node = &peers[node_idx];

    let consensus_peers = peers
        .iter()
        .map(|p| format!("    \"{}\",", p.bls_pubkey))
        .collect::<Vec<_>>()
        .join("\n");

    let p2p_validators = peers
        .iter()
        .filter(|p| p.index != node_idx)
        .map(|p| format!(
            "[[p2p.validators]]\ned25519_public_key = \"{}\"\nbls_peer_id = \"{}\"\naddress = \"127.0.0.1:{}\"\n",
            p.ed25519_pubkey, p.peer_id, p.p2p_port
        ))
        .collect::<Vec<_>>()
        .join("\n");

    let genesis_accounts_toml = genesis_accounts
        .iter()
        .map(|(pubkey, balance)| {
            format!(
                "[[consensus.genesis_accounts]]\npublic_key = \"{}\"\nbalance = {}",
                pubkey, balance
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    format!(
        r#"# Kairos Local Network - Node {node_idx}
# Generated with seed {seed}. Do not edit peer keys manually.

[consensus]
n = {n}
f = {f}
view_timeout = {{ secs = 5, nanos = 0 }}
leader_manager = "round_robin"
network = "local"
peers = [
{consensus_peers}
]

{genesis_accounts_toml}

[storage]
path = "./data/node{node_idx}.redb"

[p2p]
listen_addr = "127.0.0.1:{p2p_port}"
external_addr = "127.0.0.1:{p2p_port}"
total_number_peers = {n}
maximum_number_faulty_peers = {f}
bootstrap_timeout_ms = 30000
ping_interval_ms = 200
cluster_id = "kairos-local"

{p2p_validators}
[rpc]
listen_addr = "127.0.0.1:{grpc_port}"
max_concurrent_streams = 100
request_timeout_secs = 30
peer_id = {node_idx}
network = "local"
total_validators = {n}
f = {f}

[identity]

[threshold_setup]
mode = "disabled"
# artifact_path = "/path/to/threshold_setup.json"
# validator_set_id = "vs-2026-01"
# expected_m_nullify_group_public_key = "<hex>"
# expected_l_notarization_group_public_key = "<hex>"
#
# [threshold_setup.bootstrap]
# endpoint = "http://127.0.0.1:7001"
# participant_index = {node_idx_plus_one}
# finalize_if_last = false
# max_attempts = 60
# backoff_ms = 1000
"#,
        node_idx = node_idx,
        node_idx_plus_one = node_idx + 1,
        seed = LOCAL_NETWORK_SEED,
        n = N,
        f = F,
        consensus_peers = consensus_peers,
        p2p_port = node.p2p_port,
        p2p_validators = p2p_validators,
        grpc_port = node.grpc_port,
    )
}

fn build_run_script(config_dir: &std::path::Path) -> String {
    format!(
        r#"#!/bin/bash
# Kairos Local Network Runner
set -e

LOG_DIR="${{TMPDIR:-/tmp}}/kairos-local"
mkdir -p "$LOG_DIR"

echo "Building..."
cargo build --package node --release

echo "Starting 6 validators..."
for i in $(seq 0 5); do
    ./target/release/node run --config {config_dir}/node$i.toml > "$LOG_DIR/node$i.log" 2>&1 &
    echo "  Node $i started (PID: $!)"
done

echo ""
echo "All nodes started. Logs in $LOG_DIR"
echo "Press Ctrl+C to stop."

trap "pkill -f 'node run --config'" EXIT
wait
"#,
        config_dir = config_dir.display()
    )
}

fn generate_threshold_artifacts(
    output_dir: &std::path::Path,
    validator_set_id: &str,
    logger: Logger,
) -> Result<()> {
    slog::info!(
        logger,
        "Generating threshold artifacts";
        "output_dir" => %output_dir.display(),
        "validator_set_id" => validator_set_id,
    );

    fs::create_dir_all(output_dir)?;

    let identities = generate_deterministic_identities(N);
    let mut rng = rand::rngs::StdRng::seed_from_u64(LOCAL_THRESHOLD_ARTIFACT_SEED);
    let dual_dkg =
        run_in_memory_dual_dkg(N, F, &mut rng).context("failed to generate dual DKG material")?;

    let m_secret_by_index = dual_dkg
        .m_nullify
        .participant_shares
        .iter()
        .map(|share| (share.participant_index, share.secret_share.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    let l_secret_by_index = dual_dkg
        .l_notarization
        .participant_shares
        .iter()
        .map(|share| (share.participant_index, share.secret_share.clone()))
        .collect::<std::collections::HashMap<_, _>>();

    let validators = identities
        .iter()
        .enumerate()
        .map(|(idx, identity)| {
            let participant_index = (idx + 1) as u64;
            let m_secret = m_secret_by_index.get(&participant_index).ok_or_else(|| {
                anyhow::anyhow!("missing M secret share for index {}", participant_index)
            })?;
            let l_secret = l_secret_by_index.get(&participant_index).ok_or_else(|| {
                anyhow::anyhow!("missing L secret share for index {}", participant_index)
            })?;

            Ok(ValidatorParticipant {
                peer_id: identity.peer_id(),
                participant_index,
                m_share_public_key: hex::encode(public_key_from_scalar(m_secret)?),
                l_share_public_key: hex::encode(public_key_from_scalar(l_secret)?),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    for idx in 0..N {
        let participant_index = (idx + 1) as u64;
        let m_secret = m_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow::anyhow!("missing M secret share for index {}", participant_index))?;
        let l_secret = l_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow::anyhow!("missing L secret share for index {}", participant_index))?;

        let artifact = ThresholdSetupArtifact {
            validator_set_id: validator_set_id.to_string(),
            participant_index,
            peer_id: identities[idx].peer_id(),
            n: N,
            f: F,
            validators: validators.clone(),
            domains: ThresholdDomains {
                m_not: "minimmit/m_not/v1".to_string(),
                nullify: "minimmit/nullify/v1".to_string(),
                l_not: "minimmit/l_not/v1".to_string(),
            },
            keysets: ThresholdKeysets {
                m_nullify: ThresholdKeyset {
                    threshold: 2 * F + 1,
                    group_public_key: hex::encode(dual_dkg.m_nullify.group_public_key.0),
                    secret_share: hex::encode(m_secret.to_bytes_le()),
                },
                l_notarization: ThresholdKeyset {
                    threshold: N - F,
                    group_public_key: hex::encode(dual_dkg.l_notarization.group_public_key.0),
                    secret_share: hex::encode(l_secret.to_bytes_le()),
                },
            },
        };

        let path = output_dir.join(format!("validator-{}.threshold_setup.json", idx));
        fs::write(&path, serde_json::to_string_pretty(&artifact)?)?;
        slog::info!(logger, "Generated threshold artifact"; "file" => %path.display());
    }

    println!(
        "M_NULLIFY_GROUP_PUBLIC_KEY={}",
        hex::encode(dual_dkg.m_nullify.group_public_key.0)
    );
    println!(
        "L_NOTARIZATION_GROUP_PUBLIC_KEY={}",
        hex::encode(dual_dkg.l_notarization.group_public_key.0)
    );
    println!("Artifacts generated in {}", output_dir.display());

    Ok(())
}

fn generate_deterministic_identities(count: usize) -> Vec<ValidatorIdentity> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(LOCAL_NETWORK_SEED);
    (0..count)
        .map(|_| ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut rng)))
        .collect()
}

fn create_logger(cli_level: &str, logging_config: &node::config::LoggingConfig) -> Logger {
    use slog::Level;

    // CLI flag overrides config file
    let level_str = if cli_level != "info" {
        cli_level
    } else {
        &logging_config.level
    };

    let level = match level_str.to_lowercase().as_str() {
        "trace" => Level::Trace,
        "debug" => Level::Debug,
        "info" => Level::Info,
        "warn" => Level::Warning,
        "error" => Level::Error,
        _ => Level::Info,
    };

    match logging_config.format {
        LogFormat::Json => {
            let drain = slog_json::Json::default(std::io::stdout()).fuse();
            let drain = slog::LevelFilter::new(drain, level).fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!("version" => env!("CARGO_PKG_VERSION")))
        }
        LogFormat::Terminal => {
            let decorator = slog_term::TermDecorator::new().build();
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog::LevelFilter::new(drain, level).fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            Logger::root(drain, o!("version" => env!("CARGO_PKG_VERSION")))
        }
    }
}

fn ctrlc_handler(shutdown: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            tokio::signal::ctrl_c().await.ok();
            shutdown.store(true, Ordering::SeqCst);
        });
    });
}

fn spawn_metrics_http_server(
    listen_addr: SocketAddr,
    handle: PrometheusHandle,
    logger: Logger,
) -> Result<()> {
    let listener = std::net::TcpListener::bind(listen_addr)
        .with_context(|| format!("Failed to bind metrics listener at {listen_addr}"))?;

    std::thread::Builder::new()
        .name("prometheus-http".to_string())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };

                let body = handle.render();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );

                if let Err(e) = stream.write_all(response.as_bytes()) {
                    slog::debug!(logger, "Failed to write metrics response"; "error" => %e);
                }
            }
        })
        .context("Failed to spawn metrics HTTP thread")?;

    Ok(())
}
