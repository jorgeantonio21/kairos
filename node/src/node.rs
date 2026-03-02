//! ValidatorNode - High-level orchestrator for all node services.
//!
//! This module provides a unified interface for spawning and managing all
//! the services that make up a validator node:
//!
//! - Storage (ConsensusStore)
//! - Block Validation Service
//! - Mempool Service
//! - Consensus Engine
//! - P2P Service
//! - gRPC Server
//!
//! ## Runtime Architecture
//!
//! This node uses **two separate tokio runtimes**:
//!
//! 1. **P2P Runtime** (`commonware_runtime::tokio::Runner`)
//!    - Manages the P2P networking layer via commonware-p2p
//!    - Runs in a dedicated OS thread spawned by `spawn_p2p()`
//!    - The commonware `Runner::start()` pattern consumes the runner and blocks until completion,
//!      so it cannot be shared with other services
//!
//! 2. **gRPC Runtime** (standard `tokio::runtime::Runtime`)
//!    - Manages the tonic gRPC server for external API
//!    - Runs in a dedicated OS thread for isolation
//!
//! ### Why Separate Runtimes?
//!
//! The separate runtimes provide:
//! - **Workload isolation**: gRPC (bursty external requests) vs P2P (steady gossip)
//! - **No contention**: Services communicate via lock-free `ArrayQueue` and `Notify`
//! - **Independent shutdown**: Each runtime shuts down cleanly without blocking the other
//! - **Simplicity**: No complex lifetime management across runtime boundaries
//!
//! The cost is minimal: one extra OS thread and ~MB of tokio runtime overhead.
//!
//! ## Spawn Order
//!
//! Services are spawned in dependency order:
//!
//! ```text
//! 1. Storage         ─── Opens DB, creates ConsensusStore
//!        ↓
//! 2. Validation      ─── Creates PendingStateWriter/Reader  
//!        ↓
//! 3. Mempool         ─── Needs PendingStateReader
//!        ↓
//! 4. P2P             ─── Creates broadcast channels
//!        ↓
//! 5. Consensus       ─── Needs P2P's broadcast_notify
//!        ↓
//! 6. gRPC            ─── Needs tx queues, P2P handle
//! ```
//!
//! ## Shutdown Order
//!
//! Shutdown is dependency-aware: services that depend on others must finish first.
//!
//! ```text
//! 1. Stop gRPC       ─── No new user transactions
//! 2. Signal P2P      ─── Stop accepting network messages  
//! 3. Signal Consensus─── Stop after current view
//! 4. Wait Consensus  ─── May still request proposals from mempool
//! 5. Shutdown Mempool─── Now safe (consensus is done)
//! 6. Wait P2P        ─── Finish pending broadcasts
//! ```
//!
//! Key insight: **Consensus depends on Mempool** for proposal building,
//! so Mempool must stay alive until Consensus finishes.

use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam::queue::ArrayQueue;
use crypto::consensus_bls::{BlsPublicKey, ThresholdSignerContext};
use crypto::threshold_setup::ThresholdSetupArtifact;
use rtrb::RingBuffer;
use slog::{Logger, o};

use tokio::sync::Notify;

use commonware_runtime::tokio::Runner as TokioRunner;
use consensus::consensus::ConsensusMessage;
use consensus::consensus_manager::config::ConsensusConfig;
use consensus::consensus_manager::consensus_engine::ConsensusEngine;
use consensus::mempool::MempoolService;
use consensus::metrics::ConsensusMetrics;
use consensus::state::peer::PeerSet;
use consensus::state::transaction::Transaction;
use consensus::storage::store::ConsensusStore;
use consensus::validation::PendingStateWriter;
use grpc_client::config::RpcConfig;
use grpc_client::server::{RpcContext, RpcServer};
use metrics_exporter_prometheus::PrometheusHandle;
use p2p::ValidatorIdentity;
use p2p::config::P2PConfig;
use p2p::service::{P2PHandle, spawn as spawn_p2p};
use visualizer::DashboardMetrics;

use crate::bootstrap_client::{BootstrapClient, BootstrapOrchestrationConfig};
use crate::config::{NodeConfig, ThresholdBootstrapConfig, ThresholdMode};

/// Default buffer size for ring buffers and queues.
const BUFFER_SIZE: usize = 10_000;

/// Default tick interval for consensus state machine.
const DEFAULT_TICK_INTERVAL: Duration = Duration::from_millis(10);

/// High-level orchestrator for all node services.
///
/// `ValidatorNode` owns all the services and handles that make up a validator.
/// It provides a single entry point for spawning and shutting down the node.
///
/// # Example
///
/// ```ignore
/// // Load config from file
/// let config = NodeConfig::from_path("config.toml")?;
/// let identity = ValidatorIdentity::generate();
/// let logger = create_logger();
///
/// // Spawn all services
/// let node = ValidatorNode::<6, 1, 3>::from_config(config, identity, logger)?;
///
/// // Wait for P2P bootstrap
/// node.wait_ready().await;
///
/// // Node is now running and participating in consensus...
///
/// // Graceful shutdown
/// node.shutdown(Duration::from_secs(10))?;
/// ```
pub struct ValidatorNode<const N: usize, const F: usize, const M_SIZE: usize> {
    /// P2P service handle for network operations.
    p2p_handle: P2PHandle,

    /// Consensus engine running the BFT protocol.
    consensus_engine: ConsensusEngine<N, F, M_SIZE>,

    /// Mempool service managing pending transactions.
    mempool_service: MempoolService,

    /// Persistent storage for blocks and state.
    storage: Arc<ConsensusStore>,

    /// Global shutdown flag shared across services.
    shutdown: Arc<AtomicBool>,

    /// gRPC server address.
    grpc_addr: SocketAddr,

    /// gRPC server shutdown signal.
    grpc_shutdown: Arc<Notify>,

    /// Node logger.
    logger: Logger,
}

impl<const N: usize, const F: usize, const M_SIZE: usize> ValidatorNode<N, F, M_SIZE> {
    fn build_peer_set_from_threshold_setup(
        consensus_config: &ConsensusConfig,
        decoded: &crypto::threshold_setup::DecodedThresholdSetup,
    ) -> Result<PeerSet> {
        let parsed_peers = consensus_config
            .peers
            .iter()
            .map(|peer| {
                BlsPublicKey::from_str(peer).with_context(|| {
                    format!("Failed to parse BLS public key from consensus config peer: {peer}")
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let peer_ids_from_config = parsed_peers
            .iter()
            .map(BlsPublicKey::to_peer_id)
            .collect::<std::collections::HashSet<_>>();
        let peer_ids_from_artifact = decoded
            .participant_index_by_peer_id
            .keys()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        if peer_ids_from_config != peer_ids_from_artifact {
            return Err(anyhow::anyhow!(
                "threshold setup validator participants do not match consensus peers"
            ));
        }

        let mut indexed = parsed_peers
            .into_iter()
            .map(|public_key| {
                let peer_id = public_key.to_peer_id();
                let index = decoded
                    .participant_index_by_peer_id
                    .get(&peer_id)
                    .copied()
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing participant index in threshold setup for peer_id {}",
                            peer_id
                        )
                    })?;
                Ok((peer_id, index, public_key))
            })
            .collect::<Result<Vec<_>>>()?;
        indexed.sort_by_key(|(_, index, _)| *index);
        let indices = indexed
            .iter()
            .map(|(_, index, _)| *index)
            .collect::<Vec<_>>();
        let peers = indexed
            .into_iter()
            .map(|(_, _, public_key)| public_key)
            .collect::<Vec<_>>();
        PeerSet::with_threshold_material(
            peers,
            indices,
            decoded.m_share_public_key_by_peer_id.clone(),
            decoded.l_share_public_key_by_peer_id.clone(),
            decoded.artifact.domains.m_not.as_bytes().to_vec(),
            decoded.artifact.domains.nullify.as_bytes().to_vec(),
            decoded.artifact.domains.l_not.as_bytes().to_vec(),
        )
    }

    /// Spawns all node services from configuration.
    ///
    /// ## Spawn Order
    ///
    /// Services are spawned in dependency order:
    /// 1. Storage - Opens database
    /// 2. PendingState - Creates state readers/writers
    /// 3. Mempool - Transaction pool (needs pending state)
    /// 4. P2P - Network layer (creates tx broadcast queues)
    /// 5. gRPC - External API (needs P2P queues)
    /// 6. Consensus - BFT protocol (needs mempool channels + P2P notify)
    ///
    /// After spawning, call `wait_ready()` to wait for P2P bootstrap.
    ///
    /// # Arguments
    ///
    /// * `consensus_config` - Consensus protocol configuration
    /// * `p2p_config` - P2P networking configuration
    /// * `rpc_config` - gRPC server configuration
    /// * `identity` - Validator identity (BLS + Ed25519 keys)
    /// * `storage_path` - Path to the database directory
    /// * `logger` - Logger instance
    ///
    /// # Returns
    ///
    /// A `ValidatorNode` with all services spawned. Call `wait_ready()` before use.
    ///
    /// # Errors
    ///
    /// Returns an error if any service fails to start.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn<P: AsRef<Path>>(
        consensus_config: ConsensusConfig,
        p2p_config: P2PConfig,
        rpc_config: RpcConfig,
        visualizer_config: crate::config::VisualizerConfig,
        identity: ValidatorIdentity,
        threshold_signer: Option<ThresholdSignerContext>,
        peers_override: Option<PeerSet>,
        storage_path: P,
        prometheus_handle: Option<PrometheusHandle>,
        logger: Logger,
    ) -> Result<Self> {
        let peer_id = identity.peer_id();
        let grpc_addr = rpc_config.listen_addr;

        slog::info!(
            logger,
            "Spawning ValidatorNode";
            "peer_id" => %peer_id,
            "storage_path" => %storage_path.as_ref().display(),
            "grpc_addr" => %grpc_addr,
        );

        // 1. Open Storage
        let storage = Arc::new(
            ConsensusStore::open(storage_path.as_ref())
                .context("Failed to open consensus store")?,
        );
        slog::debug!(logger, "Storage opened");

        // 2. Create PendingState
        let (persistence_writer, pending_state_reader) =
            PendingStateWriter::new(Arc::clone(&storage), 0);
        let grpc_pending_state_reader = pending_state_reader.clone();
        slog::debug!(logger, "PendingState created");

        // 3. Create shared shutdown flag
        let shutdown = Arc::new(AtomicBool::new(false));

        // 4. Create transaction queues
        // gRPC → Mempool: ArrayQueue (MPMC)
        let grpc_tx_queue = Arc::new(ArrayQueue::<Transaction>::new(BUFFER_SIZE));

        // P2P → Mempool: rtrb (SPSC)
        let (p2p_to_mempool_producer, p2p_to_mempool_consumer) =
            RingBuffer::<Transaction>::new(BUFFER_SIZE);

        // 5. Spawn Mempool Service
        let (mempool_service, mempool_channels) = MempoolService::spawn(
            Arc::clone(&grpc_tx_queue),
            p2p_to_mempool_consumer,
            pending_state_reader,
            Arc::clone(&shutdown),
            logger.new(o!("component" => "mempool")),
        );
        slog::debug!(logger, "Mempool service spawned");

        // 6. Create consensus message channels
        let (consensus_msg_producer, consensus_msg_consumer) =
            RingBuffer::<ConsensusMessage<N, F, M_SIZE>>::new(BUFFER_SIZE);
        let (broadcast_producer, broadcast_consumer) =
            RingBuffer::<ConsensusMessage<N, F, M_SIZE>>::new(BUFFER_SIZE);

        // 7. Clone BLS key before moving identity
        let bls_secret_key = identity.bls_secret_key().clone();

        // 8. Spawn P2P Service (creates tx broadcast queues)
        // Validators pass storage to handle BlockRequest from RPC nodes
        let p2p_handle = spawn_p2p::<TokioRunner, N, F, M_SIZE>(
            TokioRunner::default(),
            p2p_config,
            identity,
            consensus_msg_producer,
            p2p_to_mempool_producer,
            broadcast_consumer,
            Some(Arc::clone(&storage)),
            logger.new(o!("component" => "p2p")),
        );
        slog::debug!(logger, "P2P service spawned");

        // Get P2P's broadcast notify to share with consensus
        let broadcast_notify = Arc::clone(&p2p_handle.broadcast_notify);
        let p2p_ready = Arc::clone(&p2p_handle.is_ready);

        // 9. Create RPC Context and spawn gRPC server
        let rpc_context = RpcContext::new(
            Arc::clone(&storage),
            grpc_pending_state_reader,
            Some(mempool_channels.stats_reader.clone()), // mempool_stats
            None,                                        // peer_stats (TODO)
            None,                                        // block_events (TODO)
            None,                                        // consensus_events (TODO)
            None,                                        // tx_events (TODO)
            Arc::clone(&p2p_handle.tx_broadcast_queue),
            Arc::clone(&p2p_handle.tx_broadcast_notify),
            Arc::clone(&grpc_tx_queue),
            Arc::clone(&p2p_ready),
            prometheus_handle,
            logger.new(o!("component" => "grpc")),
        );

        // Create shutdown signal for gRPC server
        let grpc_shutdown = Arc::new(Notify::new());
        let grpc_shutdown_signal = Arc::clone(&grpc_shutdown);

        // Spawn gRPC server in a separate thread with its own Tokio runtime.
        // See module docs for why we use a separate runtime instead of sharing
        // the commonware runtime with P2P.
        let grpc_logger = logger.new(o!("component" => "grpc-server"));
        std::thread::Builder::new()
            .name("grpc-server".into())
            .spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("create tokio runtime for grpc");
                rt.block_on(async move {
                    let server = RpcServer::new(rpc_config, rpc_context);
                    let shutdown_future = async move {
                        grpc_shutdown_signal.notified().await;
                    };
                    if let Err(e) = server.serve_with_shutdown(shutdown_future).await {
                        slog::error!(grpc_logger, "gRPC server error"; "error" => %e);
                    }
                });
            })
            .context("Failed to spawn gRPC server thread")?;
        slog::debug!(logger, "gRPC server spawned"; "addr" => %grpc_addr);

        // 10. Create consensus metrics
        let metrics = Arc::new(ConsensusMetrics::new());

        // 10b. Create dashboard and spawn visualizer server (if enabled)
        let dashboard = if visualizer_config.enabled {
            let db = Arc::new(DashboardMetrics::new());
            db.node_n.store(
                consensus_config.n as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            db.node_f.store(
                consensus_config.f as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            let db_clone = Arc::clone(&db);
            let viz_addr = visualizer_config.listen_address;
            let viz_logger = logger.new(o!("component" => "visualizer"));
            std::thread::Builder::new()
                .name("visualizer".into())
                .spawn(move || {
                    let rt = tokio::runtime::Runtime::new()
                        .expect("create tokio runtime for visualizer");
                    rt.block_on(async move {
                        if let Err(e) = visualizer::run_server(db_clone, viz_addr).await {
                            slog::error!(viz_logger, "Visualizer server error"; "error" => %e);
                        }
                    });
                })
                .context("Failed to spawn visualizer server thread")?;
            slog::info!(logger, "Visualizer server spawned"; "addr" => %viz_addr);
            Some(db)
        } else {
            None
        };

        // 11. Spawn Consensus Engine
        let consensus_engine = ConsensusEngine::<N, F, M_SIZE>::new_with_peers(
            consensus_config,
            peer_id,
            bls_secret_key,
            threshold_signer,
            peers_override,
            consensus_msg_consumer,
            broadcast_notify,
            broadcast_producer,
            mempool_channels.proposal_req_producer,
            mempool_channels.proposal_resp_consumer,
            mempool_channels.finalized_producer,
            persistence_writer,
            DEFAULT_TICK_INTERVAL,
            metrics,
            dashboard,
            logger.new(o!("component" => "consensus")),
        )
        .context("Failed to create consensus engine")?;
        slog::debug!(logger, "Consensus engine spawned");

        slog::info!(
            logger,
            "ValidatorNode spawned - call wait_ready() to complete bootstrap";
            "grpc_addr" => %grpc_addr,
        );

        Ok(Self {
            p2p_handle,
            consensus_engine,
            mempool_service,
            storage,
            shutdown,
            grpc_addr,
            grpc_shutdown,
            logger,
        })
    }

    fn maybe_run_bootstrap_and_write_artifact(
        config: &mut NodeConfig,
        identity: &ValidatorIdentity,
    ) -> Result<()> {
        if config.threshold_setup.mode != ThresholdMode::Enabled {
            return Ok(());
        }

        let artifact_path = config
            .threshold_setup
            .artifact_path
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "threshold_setup.artifact_path is required when threshold_setup.mode=enabled"
                )
            })?;
        if artifact_path.exists() {
            return Ok(());
        }

        let validator_set_id = config
            .threshold_setup
            .validator_set_id
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "threshold_setup.validator_set_id is required when threshold_setup.mode=enabled"
                )
            })?
            .clone();
        let bootstrap = config
            .threshold_setup
            .bootstrap
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "threshold_setup.bootstrap is required when artifact is missing and threshold_setup.mode=enabled"
                )
            })?;
        let orchestration = Self::bootstrap_orchestration(
            bootstrap,
            validator_set_id,
            config.consensus.n,
            config.consensus.f,
        )?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build bootstrap tokio runtime")?;
        let provisioned = runtime.block_on(async {
            let client = BootstrapClient::connect(&orchestration.endpoint).await?;
            client.provision_artifact(identity, &orchestration).await
        })?;

        Self::write_artifact_atomically(artifact_path, &provisioned.artifact_json)?;

        Self::apply_or_verify_expected_group_key(
            &mut config.threshold_setup.expected_m_nullify_group_public_key,
            &provisioned.expected_m_nullify_group_public_key,
            "m-nullify",
        )?;
        Self::apply_or_verify_expected_group_key(
            &mut config
                .threshold_setup
                .expected_l_notarization_group_public_key,
            &provisioned.expected_l_notarization_group_public_key,
            "l-notarization",
        )?;

        Ok(())
    }

    fn bootstrap_orchestration(
        bootstrap: &ThresholdBootstrapConfig,
        validator_set_id: String,
        total_participants: usize,
        max_faulty: usize,
    ) -> Result<BootstrapOrchestrationConfig> {
        if bootstrap.endpoint.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "threshold_setup.bootstrap.endpoint must be non-empty"
            ));
        }
        if bootstrap.participant_index == 0 {
            return Err(anyhow::anyhow!(
                "threshold_setup.bootstrap.participant_index must be non-zero"
            ));
        }
        if bootstrap.participant_index as usize > total_participants {
            return Err(anyhow::anyhow!(
                "threshold_setup.bootstrap.participant_index {} exceeds consensus n={}",
                bootstrap.participant_index,
                total_participants
            ));
        }
        if bootstrap.max_attempts == 0 {
            return Err(anyhow::anyhow!(
                "threshold_setup.bootstrap.max_attempts must be greater than zero"
            ));
        }
        if bootstrap.backoff_ms == 0 {
            return Err(anyhow::anyhow!(
                "threshold_setup.bootstrap.backoff_ms must be greater than zero"
            ));
        }

        Ok(BootstrapOrchestrationConfig {
            endpoint: bootstrap.endpoint.clone(),
            validator_set_id,
            participant_index: bootstrap.participant_index,
            total_participants,
            max_faulty,
            finalize_if_last: bootstrap.finalize_if_last,
            max_attempts: bootstrap.max_attempts,
            backoff: Duration::from_millis(bootstrap.backoff_ms),
        })
    }

    fn write_artifact_atomically(path: &Path, artifact_json: &str) -> Result<()> {
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "threshold_setup.artifact_path '{}' has no parent directory",
                path.display()
            )
        })?;
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create threshold setup artifact parent directory '{}'",
                parent.display()
            )
        })?;

        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, artifact_json).with_context(|| {
            format!(
                "failed to write threshold setup artifact temp file '{}'",
                tmp.display()
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).with_context(
                || {
                    format!(
                        "failed to set owner-only permissions on threshold setup artifact temp file '{}'",
                        tmp.display()
                    )
                },
            )?;
        }

        std::fs::rename(&tmp, path).with_context(|| {
            format!(
                "failed to move threshold setup artifact from '{}' to '{}'",
                tmp.display(),
                path.display()
            )
        })?;

        Ok(())
    }

    fn apply_or_verify_expected_group_key(
        expected: &mut Option<String>,
        fetched: &str,
        label: &str,
    ) -> Result<()> {
        if fetched.is_empty() {
            return Err(anyhow::anyhow!(
                "bootstrap returned empty expected {} group public key",
                label
            ));
        }
        match expected {
            Some(existing) if existing != fetched => Err(anyhow::anyhow!(
                "bootstrap expected {} group public key mismatch: config value differs from bootstrap result",
                label
            )),
            Some(_) => Ok(()),
            None => {
                *expected = Some(fetched.to_string());
                Ok(())
            }
        }
    }

    fn validate_threshold_setup(config: &NodeConfig, identity: &ValidatorIdentity) -> Result<()> {
        if config.threshold_setup.mode != ThresholdMode::Enabled {
            return Ok(());
        }

        let artifact_path = config
            .threshold_setup
            .artifact_path
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "threshold_setup.artifact_path is required when threshold_setup.mode=enabled"
                )
            })?;

        let metadata = std::fs::metadata(artifact_path).with_context(|| {
            format!(
                "Cannot read metadata for threshold setup artifact '{}'",
                artifact_path.display()
            )
        })?;
        if !metadata.is_file() {
            return Err(anyhow::anyhow!(
                "threshold_setup.artifact_path '{}' is not a regular file",
                artifact_path.display()
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(anyhow::anyhow!(
                    "threshold setup artifact '{}' has overly permissive permissions {:o}; require owner-only access",
                    artifact_path.display(),
                    mode
                ));
            }
        }

        let artifact =
            ThresholdSetupArtifact::load_from_path(artifact_path).with_context(|| {
                format!(
                    "Failed to load threshold setup artifact from '{}'",
                    artifact_path.display()
                )
            })?;
        artifact
            .validate_for_node(
                identity.peer_id(),
                config.consensus.n,
                config.consensus.f,
                config.threshold_setup.validator_set_id.as_deref(),
            )
            .context("Threshold setup artifact validation failed")?;

        let expected_m = config
            .threshold_setup
            .expected_m_nullify_group_public_key
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "threshold_setup.expected_m_nullify_group_public_key is required when threshold_setup.mode=enabled"
                )
            })?;
        let expected_l = config
            .threshold_setup
            .expected_l_notarization_group_public_key
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "threshold_setup.expected_l_notarization_group_public_key is required when threshold_setup.mode=enabled"
                )
            })?;

        let expected_m = BlsPublicKey::from_str(expected_m)
            .context("Invalid expected m-nullify group public key in node config")?;
        let expected_l = BlsPublicKey::from_str(expected_l)
            .context("Invalid expected l-notarization group public key in node config")?;
        let artifact_m = BlsPublicKey::from_str(&artifact.keysets.m_nullify.group_public_key)
            .context("Invalid m-nullify group public key in threshold artifact")?;
        let artifact_l = BlsPublicKey::from_str(&artifact.keysets.l_notarization.group_public_key)
            .context("Invalid l-notarization group public key in threshold artifact")?;

        if expected_m != artifact_m {
            return Err(anyhow::anyhow!(
                "Threshold setup mismatch: expected m-nullify group public key differs from artifact"
            ));
        }
        if expected_l != artifact_l {
            return Err(anyhow::anyhow!(
                "Threshold setup mismatch: expected l-notarization group public key differs from artifact"
            ));
        }

        Ok(())
    }

    /// Spawns a validator node from a unified `NodeConfig`.
    ///
    /// This is the recommended way to create a `ValidatorNode`.
    /// The config can be loaded from TOML/YAML files or environment variables.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = NodeConfig::from_path("config.toml")?;
    /// let identity = ValidatorIdentity::generate();
    /// let logger = create_logger();
    ///
    /// let node = ValidatorNode::<6, 1, 3>::from_config(config, identity, logger)?;
    /// node.wait_ready().await;
    /// ```
    ///
    /// # Arguments
    ///
    /// * `config` - Complete node configuration
    /// * `identity` - Validator identity (BLS + Ed25519 keys)
    /// * `logger` - Logger instance
    ///
    /// # Returns
    ///
    /// A `ValidatorNode` with all services spawned. Call `wait_ready()` before use.
    ///
    /// # Errors
    ///
    /// Returns an error if any service fails to start.
    pub fn from_config(
        mut config: NodeConfig,
        identity: ValidatorIdentity,
        prometheus_handle: Option<PrometheusHandle>,
        logger: Logger,
    ) -> Result<Self> {
        #[cfg(not(test))]
        if config.threshold_setup.mode != ThresholdMode::Enabled {
            return Err(anyhow::anyhow!(
                "threshold_setup.mode=enabled is required for production validator startup"
            ));
        }

        Self::maybe_run_bootstrap_and_write_artifact(&mut config, &identity)?;
        Self::validate_threshold_setup(&config, &identity)?;

        let threshold_signer = if config.threshold_setup.mode == ThresholdMode::Enabled {
            let artifact_path = config.threshold_setup.artifact_path.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "threshold_setup.artifact_path is required when threshold_setup.mode=enabled"
                )
            })?;
            let artifact = ThresholdSetupArtifact::load_from_path(artifact_path)?;
            let decoded = artifact.decode()?;
            Some(ThresholdSignerContext::from_decoded_setup(decoded)?)
        } else {
            None
        };
        let peers_override = if config.threshold_setup.mode == ThresholdMode::Enabled {
            let artifact_path = config.threshold_setup.artifact_path.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "threshold_setup.artifact_path is required when threshold_setup.mode=enabled"
                )
            })?;
            let artifact = ThresholdSetupArtifact::load_from_path(artifact_path)?;
            let decoded = artifact.decode()?;
            Some(Self::build_peer_set_from_threshold_setup(
                &config.consensus,
                &decoded,
            )?)
        } else {
            None
        };

        Self::spawn(
            config.consensus,
            config.p2p,
            config.rpc,
            config.visualizer,
            identity,
            threshold_signer,
            peers_override,
            &config.storage.path,
            prometheus_handle,
            logger,
        )
    }

    /// Wait for the node to be fully ready (P2P bootstrap complete).
    ///
    /// This should be called after `spawn()` to ensure the P2P network
    /// is connected before the node starts participating in consensus.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let node = ValidatorNode::spawn(...)?;
    /// node.wait_ready().await;  // Wait for P2P bootstrap
    /// // Node is now ready for consensus
    /// ```
    pub async fn wait_ready(&self) {
        slog::info!(self.logger, "Waiting for P2P bootstrap...");
        self.p2p_handle.wait_ready().await;
        slog::info!(self.logger, "P2P bootstrap complete - node is ready");
    }

    /// Returns the P2P handle for network operations.
    pub fn p2p_handle(&self) -> &P2PHandle {
        &self.p2p_handle
    }

    /// Returns the gRPC server address.
    pub fn grpc_addr(&self) -> SocketAddr {
        self.grpc_addr
    }

    /// Returns the storage handle.
    pub fn storage(&self) -> Arc<ConsensusStore> {
        Arc::clone(&self.storage)
    }

    /// Checks if the node is healthy (all services running).
    pub fn is_healthy(&self) -> bool {
        !self.shutdown.load(Ordering::Acquire)
            && self.consensus_engine.is_running()
            && self.mempool_service.is_running()
            && self.p2p_handle.is_ready()
    }

    /// Performs hierarchical shutdown of all services.
    ///
    /// ## Shutdown Order (dependency-aware)
    ///
    /// ```text
    /// 1. Stop gRPC       ─── No new user transactions
    /// 2. Signal P2P      ─── Stop accepting network messages
    /// 3. Signal Consensus─── Stop after current view
    /// 4. Wait Consensus  ─── May still request proposals from mempool
    /// 5. Shutdown Mempool─── Now safe (consensus is done)
    /// 6. Wait P2P        ─── Finish pending broadcasts
    /// ```
    ///
    /// Key insight: **Consensus depends on Mempool** for proposal building,
    /// so Mempool must stay alive until Consensus finishes.
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for consensus shutdown
    ///
    /// # Returns
    ///
    /// Ok(()) if all services shut down cleanly, Err otherwise.
    pub fn shutdown(mut self, timeout: Duration) -> Result<()> {
        slog::info!(self.logger, "Beginning hierarchical shutdown");

        // Step 1: Set global shutdown flag (stops accepting new work)
        self.shutdown.store(true, Ordering::Release);

        // Step 2: Stop gRPC server (no new user transactions)
        self.grpc_shutdown.notify_one();
        slog::debug!(self.logger, "gRPC server shutdown signaled");

        // Step 3: Signal P2P to stop (no new network messages)
        self.p2p_handle.shutdown();
        slog::debug!(self.logger, "P2P service signaled");

        // Step 4: Signal consensus engine to stop
        // Consensus may still request proposals from mempool during wind-down
        self.consensus_engine.shutdown();
        slog::debug!(self.logger, "Consensus engine signaled");

        // Step 5: Wait for consensus engine to finish
        // Mempool is still running to serve any final proposal requests
        self.consensus_engine
            .shutdown_and_wait(timeout)
            .context("Consensus engine shutdown failed")?;
        slog::debug!(self.logger, "Consensus engine shutdown complete");

        // Step 6: Shutdown mempool (now safe - consensus is done)
        self.mempool_service.shutdown();
        slog::debug!(self.logger, "Mempool service shutdown complete");

        // Step 7: Wait for P2P thread to finish pending broadcasts
        let _ = self.p2p_handle.join();
        slog::debug!(self.logger, "P2P service shutdown complete");

        slog::info!(self.logger, "ValidatorNode shutdown complete");
        Ok(())
    }
}

/// Builder for ValidatorNode with fluent configuration.
pub struct ValidatorNodeBuilder<const N: usize, const F: usize, const M_SIZE: usize> {
    consensus_config: Option<ConsensusConfig>,
    p2p_config: Option<P2PConfig>,
    rpc_config: Option<RpcConfig>,
    visualizer_config: crate::config::VisualizerConfig,
    identity: Option<ValidatorIdentity>,
    storage_path: Option<String>,
    prometheus_handle: Option<PrometheusHandle>,
    logger: Option<Logger>,
}

impl<const N: usize, const F: usize, const M_SIZE: usize> Default
    for ValidatorNodeBuilder<N, F, M_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const F: usize, const M_SIZE: usize> ValidatorNodeBuilder<N, F, M_SIZE> {
    /// Creates a new builder with no configuration.
    pub fn new() -> Self {
        Self {
            consensus_config: None,
            p2p_config: None,
            rpc_config: None,
            visualizer_config: crate::config::VisualizerConfig::default(),
            identity: None,
            storage_path: None,
            prometheus_handle: None,
            logger: None,
        }
    }

    /// Sets the consensus configuration.
    pub fn with_consensus_config(mut self, config: ConsensusConfig) -> Self {
        self.consensus_config = Some(config);
        self
    }

    /// Sets the P2P configuration.
    pub fn with_p2p_config(mut self, config: P2PConfig) -> Self {
        self.p2p_config = Some(config);
        self
    }

    /// Sets the gRPC server configuration.
    pub fn with_rpc_config(mut self, config: RpcConfig) -> Self {
        self.rpc_config = Some(config);
        self
    }

    /// Sets the visualizer configuration.
    pub fn with_visualizer_config(mut self, config: crate::config::VisualizerConfig) -> Self {
        self.visualizer_config = config;
        self
    }

    /// Sets the validator identity.
    pub fn with_identity(mut self, identity: ValidatorIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Sets the storage path.
    pub fn with_storage_path(mut self, path: impl Into<String>) -> Self {
        self.storage_path = Some(path.into());
        self
    }

    /// Sets the Prometheus metrics handle.
    pub fn with_prometheus_handle(mut self, handle: PrometheusHandle) -> Self {
        self.prometheus_handle = Some(handle);
        self
    }

    /// Sets the logger.
    pub fn with_logger(mut self, logger: Logger) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Builds and spawns the ValidatorNode.
    ///
    /// # Errors
    ///
    /// Returns an error if any required field is missing or if spawning fails.
    pub fn build(self) -> Result<ValidatorNode<N, F, M_SIZE>> {
        let consensus_config = self
            .consensus_config
            .ok_or_else(|| anyhow::anyhow!("consensus_config is required"))?;
        let p2p_config = self
            .p2p_config
            .ok_or_else(|| anyhow::anyhow!("p2p_config is required"))?;
        let rpc_config = self
            .rpc_config
            .ok_or_else(|| anyhow::anyhow!("rpc_config is required"))?;
        let identity = self
            .identity
            .ok_or_else(|| anyhow::anyhow!("identity is required"))?;
        let storage_path = self
            .storage_path
            .ok_or_else(|| anyhow::anyhow!("storage_path is required"))?;
        let logger = self
            .logger
            .unwrap_or_else(|| slog::Logger::root(slog::Discard, o!()));

        ValidatorNode::spawn(
            consensus_config,
            p2p_config,
            rpc_config,
            self.visualizer_config,
            identity,
            None,
            None,
            &storage_path,
            self.prometheus_handle,
            logger,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::{SocketAddr, TcpListener},
        path::PathBuf,
        sync::mpsc,
        thread,
        time::Duration,
    };

    use bootstrap_rpc::proto::{
        Commitment, RegisterParticipantRequest, Share, SubmitCommitmentsRequest,
        SubmitSharesRequest, bootstrap_service_client::BootstrapServiceClient,
        bootstrap_service_server::BootstrapServiceServer,
    };
    use bootstrap_rpc::service::BootstrapServiceImpl;
    use consensus::{
        consensus_manager::{
            config::{ConsensusConfig, GenesisAccount, Network},
            leader_manager::LeaderSelectionStrategy,
        },
        crypto::consensus_bls::BlsSecretKey,
        storage::config::StorageConfig,
    };
    use crypto::dkg::create_dealer_contribution;
    use crypto::threshold_setup::{
        ThresholdDomains, ThresholdKeyset, ThresholdKeysets, ThresholdSetupArtifact,
        ValidatorParticipant,
    };
    use grpc_client::config::RpcConfig;
    use p2p::{ValidatorIdentity, config::P2PConfig};
    use rand::{SeedableRng, rngs::StdRng};
    use tempfile::NamedTempFile;
    use tonic::transport::Server;

    use super::ValidatorNode;
    use crate::config::{
        NodeConfig, ThresholdBootstrapConfig, ThresholdMode, ThresholdSetupConfig,
    };

    fn test_node_config(
        identity: &ValidatorIdentity,
        artifact_path: Option<PathBuf>,
    ) -> NodeConfig {
        let peer_public_key = hex::encode(identity.bls_public_key().0);
        NodeConfig {
            consensus: ConsensusConfig::new(
                6,
                1,
                std::time::Duration::from_secs(5),
                LeaderSelectionStrategy::RoundRobin,
                Network::Local,
                vec![peer_public_key],
                vec![GenesisAccount {
                    public_key: "abcd".to_string(),
                    balance: 1,
                }],
            ),
            storage: StorageConfig::new("/tmp".to_string()),
            p2p: P2PConfig::default(),
            rpc: RpcConfig::default(),
            identity: crate::config::IdentityConfig::default(),
            metrics: crate::config::MetricsConfig::default(),
            logging: crate::config::LoggingConfig::default(),
            visualizer: crate::config::VisualizerConfig::default(),
            threshold_setup: ThresholdSetupConfig {
                mode: ThresholdMode::Enabled,
                artifact_path,
                validator_set_id: Some("vs-test".to_string()),
                expected_m_nullify_group_public_key: None,
                expected_l_notarization_group_public_key: None,
                bootstrap: None,
            },
        }
    }

    fn write_artifact(identity: &ValidatorIdentity) -> (NamedTempFile, ThresholdSetupArtifact) {
        let mut rng = StdRng::seed_from_u64(9090);
        let m_sk = BlsSecretKey::generate(&mut rng);
        let l_sk = BlsSecretKey::generate(&mut rng);
        let artifact = ThresholdSetupArtifact {
            validator_set_id: "vs-test".to_string(),
            peer_id: identity.peer_id(),
            participant_index: 1,
            n: 6,
            f: 1,
            validators: vec![
                ValidatorParticipant {
                    peer_id: identity.peer_id(),
                    participant_index: 1,
                    m_share_public_key: hex::encode(m_sk.public_key().0),
                    l_share_public_key: hex::encode(l_sk.public_key().0),
                },
                ValidatorParticipant {
                    peer_id: 2,
                    participant_index: 2,
                    m_share_public_key: hex::encode(m_sk.public_key().0),
                    l_share_public_key: hex::encode(l_sk.public_key().0),
                },
                ValidatorParticipant {
                    peer_id: 3,
                    participant_index: 3,
                    m_share_public_key: hex::encode(m_sk.public_key().0),
                    l_share_public_key: hex::encode(l_sk.public_key().0),
                },
                ValidatorParticipant {
                    peer_id: 4,
                    participant_index: 4,
                    m_share_public_key: hex::encode(m_sk.public_key().0),
                    l_share_public_key: hex::encode(l_sk.public_key().0),
                },
                ValidatorParticipant {
                    peer_id: 5,
                    participant_index: 5,
                    m_share_public_key: hex::encode(m_sk.public_key().0),
                    l_share_public_key: hex::encode(l_sk.public_key().0),
                },
                ValidatorParticipant {
                    peer_id: 6,
                    participant_index: 6,
                    m_share_public_key: hex::encode(m_sk.public_key().0),
                    l_share_public_key: hex::encode(l_sk.public_key().0),
                },
            ],
            domains: ThresholdDomains {
                m_not: "minimmit/m_not/v1".to_string(),
                nullify: "minimmit/nullify/v1".to_string(),
                l_not: "minimmit/l_not/v1".to_string(),
            },
            keysets: ThresholdKeysets {
                m_nullify: ThresholdKeyset {
                    threshold: 3,
                    group_public_key: hex::encode(m_sk.public_key().0),
                    secret_share: hex::encode(m_sk.0),
                },
                l_notarization: ThresholdKeyset {
                    threshold: 5,
                    group_public_key: hex::encode(l_sk.public_key().0),
                    secret_share: hex::encode(l_sk.0),
                },
            },
        };

        let file = NamedTempFile::new().expect("temp artifact file");
        let raw = serde_json::to_string_pretty(&artifact).expect("serialize artifact");
        fs::write(file.path(), raw).expect("write artifact");
        (file, artifact)
    }

    fn free_local_addr() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);
        addr
    }

    async fn register_participant(
        client: &mut BootstrapServiceClient<tonic::transport::Channel>,
        validator_set_id: &str,
        peer_id: u64,
        participant_index: u64,
    ) {
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            client.register_participant(RegisterParticipantRequest {
                validator_set_id: validator_set_id.to_string(),
                peer_id,
                participant_index,
            }),
        )
        .await
        .expect("register timeout")
        .expect("register rpc")
        .into_inner();
        assert!(response.accepted, "{}", response.message);
    }

    async fn submit_dealer_material(
        client: &mut BootstrapServiceClient<tonic::transport::Channel>,
        validator_set_id: &str,
        participant_index: u64,
        n: usize,
        f: usize,
    ) {
        let mut rng = StdRng::seed_from_u64(1_000 + participant_index);
        let m_threshold = 2 * f + 1;
        let l_threshold = n - f;
        let (m_bundle, m_shares) =
            create_dealer_contribution(m_threshold, n, participant_index, &mut rng)
                .expect("m contribution");
        let (l_bundle, l_shares) =
            create_dealer_contribution(l_threshold, n, participant_index, &mut rng)
                .expect("l contribution");

        let commitments = vec![
            Commitment {
                dealer_index: participant_index,
                keyset: "m_nullify".to_string(),
                commitment_public_keys: m_bundle
                    .commitments
                    .iter()
                    .map(|pk| hex::encode(pk.0))
                    .collect(),
            },
            Commitment {
                dealer_index: participant_index,
                keyset: "l_notarization".to_string(),
                commitment_public_keys: l_bundle
                    .commitments
                    .iter()
                    .map(|pk| hex::encode(pk.0))
                    .collect(),
            },
        ];
        let shares = m_shares
            .into_iter()
            .map(|share| Share {
                dealer_index: share.dealer_index,
                recipient_index: share.recipient_index,
                keyset: "m_nullify".to_string(),
                share_hex: hex::encode(share.value.to_bytes_le()),
            })
            .chain(l_shares.into_iter().map(|share| Share {
                dealer_index: share.dealer_index,
                recipient_index: share.recipient_index,
                keyset: "l_notarization".to_string(),
                share_hex: hex::encode(share.value.to_bytes_le()),
            }))
            .collect::<Vec<_>>();

        let commit_resp = tokio::time::timeout(
            Duration::from_secs(2),
            client.submit_commitments(SubmitCommitmentsRequest {
                validator_set_id: validator_set_id.to_string(),
                commitments,
            }),
        )
        .await
        .expect("commit timeout")
        .expect("commit rpc")
        .into_inner();
        assert!(commit_resp.accepted, "{}", commit_resp.message);

        let share_resp = tokio::time::timeout(
            Duration::from_secs(2),
            client.submit_shares(SubmitSharesRequest {
                validator_set_id: validator_set_id.to_string(),
                shares,
            }),
        )
        .await
        .expect("share timeout")
        .expect("shares rpc")
        .into_inner();
        assert!(share_resp.accepted, "{}", share_resp.message);
    }

    #[test]
    fn threshold_setup_validation_accepts_valid_config() {
        let identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(1)));
        let (artifact_file, artifact) = write_artifact(&identity);
        let mut config = test_node_config(&identity, Some(artifact_file.path().to_path_buf()));
        config.threshold_setup.expected_m_nullify_group_public_key =
            Some(artifact.keysets.m_nullify.group_public_key.clone());
        config
            .threshold_setup
            .expected_l_notarization_group_public_key =
            Some(artifact.keysets.l_notarization.group_public_key.clone());

        let result = ValidatorNode::<6, 1, 3>::validate_threshold_setup(&config, &identity);
        assert!(result.is_ok(), "validation failed: {:?}", result.err());
    }

    #[test]
    fn threshold_setup_validation_rejects_group_key_mismatch() {
        let identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(2)));
        let (artifact_file, artifact) = write_artifact(&identity);
        let mut config = test_node_config(&identity, Some(artifact_file.path().to_path_buf()));
        config.threshold_setup.expected_m_nullify_group_public_key =
            Some(artifact.keysets.l_notarization.group_public_key.clone());
        config
            .threshold_setup
            .expected_l_notarization_group_public_key =
            Some(artifact.keysets.l_notarization.group_public_key.clone());

        let result = ValidatorNode::<6, 1, 3>::validate_threshold_setup(&config, &identity);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("m-nullify group public key")
        );
    }

    #[test]
    fn threshold_setup_validation_is_noop_when_disabled() {
        let identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(3)));
        let mut config = test_node_config(&identity, None);
        config.threshold_setup.mode = ThresholdMode::Disabled;

        let result = ValidatorNode::<6, 1, 3>::validate_threshold_setup(&config, &identity);
        assert!(result.is_ok());
    }

    #[test]
    fn threshold_setup_validation_rejects_missing_artifact() {
        let identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(4)));
        let missing = std::env::temp_dir().join("missing-threshold-setup-artifact.json");
        let mut config = test_node_config(&identity, Some(missing));
        config.threshold_setup.expected_m_nullify_group_public_key = Some("deadbeef".to_string());
        config
            .threshold_setup
            .expected_l_notarization_group_public_key = Some("deadbeef".to_string());

        let result = ValidatorNode::<6, 1, 3>::validate_threshold_setup(&config, &identity);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("Cannot read metadata")
        );
    }

    #[test]
    fn threshold_setup_validation_rejects_wrong_peer_id() {
        let identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(5)));
        let (artifact_file, mut artifact) = write_artifact(&identity);
        artifact.peer_id = artifact.peer_id.saturating_add(1);
        let raw = serde_json::to_string_pretty(&artifact).expect("serialize");
        fs::write(artifact_file.path(), raw).expect("write");

        let mut config = test_node_config(&identity, Some(artifact_file.path().to_path_buf()));
        config.threshold_setup.expected_m_nullify_group_public_key =
            Some(artifact.keysets.m_nullify.group_public_key.clone());
        config
            .threshold_setup
            .expected_l_notarization_group_public_key =
            Some(artifact.keysets.l_notarization.group_public_key.clone());

        let result = ValidatorNode::<6, 1, 3>::validate_threshold_setup(&config, &identity);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_setup_validation_rejects_threshold_mismatch() {
        let identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(6)));
        let (artifact_file, mut artifact) = write_artifact(&identity);
        artifact.keysets.m_nullify.threshold = 4;
        let raw = serde_json::to_string_pretty(&artifact).expect("serialize");
        fs::write(artifact_file.path(), raw).expect("write");

        let mut config = test_node_config(&identity, Some(artifact_file.path().to_path_buf()));
        config.threshold_setup.expected_m_nullify_group_public_key =
            Some(artifact.keysets.m_nullify.group_public_key.clone());
        config
            .threshold_setup
            .expected_l_notarization_group_public_key =
            Some(artifact.keysets.l_notarization.group_public_key.clone());

        let result = ValidatorNode::<6, 1, 3>::validate_threshold_setup(&config, &identity);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_setup_validation_rejects_invalid_expected_group_key() {
        let identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(7)));
        let (artifact_file, artifact) = write_artifact(&identity);
        let mut config = test_node_config(&identity, Some(artifact_file.path().to_path_buf()));
        config.threshold_setup.expected_m_nullify_group_public_key = Some("not-hex".to_string());
        config
            .threshold_setup
            .expected_l_notarization_group_public_key =
            Some(artifact.keysets.l_notarization.group_public_key.clone());

        let result = ValidatorNode::<6, 1, 3>::validate_threshold_setup(&config, &identity);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("Invalid expected m-nullify group public key")
        );
    }

    #[test]
    fn bootstrap_orchestration_rejects_invalid_participant_index() {
        let bootstrap = ThresholdBootstrapConfig {
            endpoint: "http://127.0.0.1:7001".to_string(),
            participant_index: 0,
            finalize_if_last: false,
            max_attempts: 10,
            backoff_ms: 100,
        };

        let result = ValidatorNode::<6, 1, 3>::bootstrap_orchestration(
            &bootstrap,
            "vs-test".to_string(),
            6,
            1,
        );
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("participant_index must be non-zero")
        );
    }

    #[test]
    fn bootstrap_path_requires_bootstrap_config_when_artifact_missing() {
        let identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(8)));
        let missing = std::env::temp_dir().join("missing-threshold-setup-bootstrap-artifact.json");
        let mut config = test_node_config(&identity, Some(missing));
        config.threshold_setup.bootstrap = None;

        let result = ValidatorNode::<6, 1, 3>::maybe_run_bootstrap_and_write_artifact(
            &mut config,
            &identity,
        );
        assert!(result.is_err());
        assert!(
            result
                .expect_err("error")
                .to_string()
                .contains("threshold_setup.bootstrap is required")
        );
    }

    #[test]
    #[ignore = "requires local TCP binding and loopback networking"]
    fn bootstrap_path_provisions_artifact_end_to_end() {
        let addr = free_local_addr();
        let endpoint = format!("http://{}", addr);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = mpsc::channel();

        let server_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("server runtime");
            runtime.block_on(async move {
                let service = BootstrapServiceImpl::default();
                let _ = ready_tx.send(());
                Server::builder()
                    .add_service(BootstrapServiceServer::new(service))
                    .serve_with_shutdown(addr, async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("bootstrap server");
            });
        });
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("ready");

        let n = 6usize;
        let f = 1usize;
        let validator_set_id = "vs-bootstrap-e2e";
        let identities = (1..=n as u64)
            .map(|seed| {
                ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(
                    seed,
                )))
            })
            .collect::<Vec<_>>();
        let local_identity =
            ValidatorIdentity::from_bls_key(BlsSecretKey::generate(&mut StdRng::seed_from_u64(1)));

        let client_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("client runtime");
        let mut client = client_rt
            .block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(2),
                    BootstrapServiceClient::connect(endpoint.clone()),
                )
                .await
            })
            .expect("connect timeout")
            .expect("connect");

        client_rt.block_on(async {
            for (i, identity) in identities.iter().enumerate() {
                register_participant(
                    &mut client,
                    validator_set_id,
                    identity.peer_id(),
                    (i + 1) as u64,
                )
                .await;
            }
            for participant_index in 2..=n as u64 {
                submit_dealer_material(&mut client, validator_set_id, participant_index, n, f)
                    .await;
            }
        });

        let artifact_file = std::env::temp_dir().join(format!(
            "threshold-bootstrap-e2e-{}.json",
            local_identity.peer_id()
        ));
        if artifact_file.exists() {
            fs::remove_file(&artifact_file).expect("cleanup existing");
        }

        let mut config = test_node_config(&local_identity, Some(artifact_file.clone()));
        config.threshold_setup.validator_set_id = Some(validator_set_id.to_string());
        config.threshold_setup.expected_m_nullify_group_public_key = None;
        config
            .threshold_setup
            .expected_l_notarization_group_public_key = None;
        config.threshold_setup.bootstrap = Some(ThresholdBootstrapConfig {
            endpoint: endpoint.clone(),
            participant_index: 1,
            finalize_if_last: true,
            max_attempts: 5,
            backoff_ms: 50,
        });

        ValidatorNode::<6, 1, 3>::maybe_run_bootstrap_and_write_artifact(
            &mut config,
            &local_identity,
        )
        .expect("bootstrap provision");

        assert!(artifact_file.exists());
        let artifact =
            ThresholdSetupArtifact::load_from_path(&artifact_file).expect("load artifact");
        artifact
            .validate_for_node(local_identity.peer_id(), n, f, Some(validator_set_id))
            .expect("validate artifact");

        assert_eq!(
            config
                .threshold_setup
                .expected_m_nullify_group_public_key
                .as_deref(),
            Some(artifact.keysets.m_nullify.group_public_key.as_str())
        );
        assert_eq!(
            config
                .threshold_setup
                .expected_l_notarization_group_public_key
                .as_deref(),
            Some(artifact.keysets.l_notarization.group_public_key.as_str())
        );

        // Drop client-side gRPC resources before graceful server shutdown.
        // `serve_with_shutdown` waits for active connections to drain.
        drop(client);
        drop(client_rt);

        fs::remove_file(&artifact_file).expect("remove artifact");
        let _ = shutdown_tx.send(());
        server_thread.join().expect("server join");
    }
}
