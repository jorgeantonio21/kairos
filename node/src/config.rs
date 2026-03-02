//! Node configuration types.
//!
//! Combines all service configurations into a unified `NodeConfig` that can be
//! loaded from TOML/YAML files or environment variables.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::Result;
use figment::{
    Figment,
    providers::{Env, Format, Toml, Yaml},
};
use serde::{Deserialize, Serialize};

use consensus::consensus_manager::config::ConsensusConfig;
use consensus::storage::config::StorageConfig;
use grpc_client::config::RpcConfig;
use p2p::config::P2PConfig;

/// Validator identity configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Path to the BLS secret key file (hex-encoded).
    /// If not provided, a new key will be generated.
    pub bls_secret_key_path: Option<String>,

    /// Path to the Ed25519 secret key file for P2P identity.
    /// If not provided, a new key will be generated.
    pub ed25519_secret_key_path: Option<String>,
}

/// Complete node configuration combining all service configs.
///
/// # Example TOML
///
/// ```toml
/// [consensus]
/// n = 4
/// f = 1
/// view_timeout = { secs = 5, nanos = 0 }
/// leader_manager = "RoundRobin"
/// network = "local"
/// peers = ["peer1_pubkey", "peer2_pubkey", ...]
///
/// [storage]
/// path = "/var/lib/kairos/data"
///
/// [p2p]
/// listen_addr = "0.0.0.0:9000"
/// external_addr = "1.2.3.4:9000"
///
/// [rpc]
/// listen_addr = "0.0.0.0:50051"
///
/// [identity]
/// bls_secret_key_path = "/etc/kairos/bls.key"
/// ed25519_secret_key_path = "/etc/kairos/ed25519.key"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Consensus protocol configuration.
    pub consensus: ConsensusConfig,

    /// Persistent storage configuration.
    pub storage: StorageConfig,

    /// P2P networking configuration.
    pub p2p: P2PConfig,

    /// gRPC server configuration.
    pub rpc: RpcConfig,

    /// Validator identity configuration.
    #[serde(default)]
    pub identity: IdentityConfig,

    /// Metrics (Prometheus) configuration.
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Consensus visualizer configuration.
    #[serde(default)]
    pub visualizer: VisualizerConfig,

    /// Threshold setup bootstrap configuration.
    #[serde(default)]
    pub threshold_setup: ThresholdSetupConfig,
}

/// Prometheus metrics exporter configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable the Prometheus HTTP endpoint.
    pub enabled: bool,
    /// Socket address for the `/metrics` endpoint.
    pub listen_address: SocketAddr,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: "127.0.0.1:9090".parse().unwrap(),
        }
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable terminal output (slog-term).
    #[default]
    Terminal,
    /// Structured JSON output (slog-json).
    Json,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Output format.
    pub format: LogFormat,
    /// Minimum log level (error, warn, info, debug).
    pub level: String,
    /// Optional file path for log output.
    pub file: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Terminal,
            level: "info".to_string(),
            file: None,
        }
    }
}

/// Consensus visualizer embedded web UI configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisualizerConfig {
    /// Enable the visualizer HTTP server.
    pub enabled: bool,
    /// Socket address for the visualizer (serves dashboard + SSE).
    pub listen_address: SocketAddr,
}

impl Default for VisualizerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: "127.0.0.1:8080".parse().unwrap(),
        }
    }
}

/// Threshold setup mode.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ThresholdMode {
    #[default]
    Disabled,
    Enabled,
}

/// Boot-time threshold setup validation configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThresholdSetupConfig {
    /// Whether threshold setup loading/validation is enabled.
    #[serde(default)]
    pub mode: ThresholdMode,
    /// Path to setup artifact JSON.
    #[serde(default)]
    pub artifact_path: Option<PathBuf>,
    /// Optional expected validator set identifier.
    #[serde(default)]
    pub validator_set_id: Option<String>,
    /// Expected group public key for the m/nullify keyset (hex-encoded compressed key).
    #[serde(default)]
    pub expected_m_nullify_group_public_key: Option<String>,
    /// Expected group public key for the l-notarization keyset (hex-encoded compressed key).
    #[serde(default)]
    pub expected_l_notarization_group_public_key: Option<String>,
    /// Optional bootstrap-RPC ceremony configuration used when artifact is absent at startup.
    #[serde(default)]
    pub bootstrap: Option<ThresholdBootstrapConfig>,
}

/// Threshold setup bootstrap RPC configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdBootstrapConfig {
    /// gRPC endpoint for bootstrap service (for example `http://127.0.0.1:7001`).
    pub endpoint: String,
    /// Local validator participant index for DKG (must match registration plan).
    pub participant_index: u64,
    /// If true, this node attempts to finalize the ceremony after submissions.
    pub finalize_if_last: bool,
    /// Maximum attempts for fetch/finalize polling loop.
    pub max_attempts: u32,
    /// Backoff between attempts in milliseconds.
    pub backoff_ms: u64,
}

impl Default for ThresholdBootstrapConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:7001".to_string(),
            participant_index: 0,
            finalize_if_last: false,
            max_attempts: 60,
            backoff_ms: 1000,
        }
    }
}

impl NodeConfig {
    /// Load configuration from a file path.
    ///
    /// Supports TOML (.toml) and YAML (.yaml, .yml) formats.
    /// Environment variables can override file values using the `NODE_` prefix.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = NodeConfig::from_path("config.toml")?;
    /// ```
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        let mut figment = Figment::new();

        // Detect file format based on extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            figment = match ext {
                "toml" => figment.merge(Toml::file(path)),
                "yaml" | "yml" => figment.merge(Yaml::file(path)),
                _ => {
                    return Err(anyhow::anyhow!(
                        "Unsupported config file format: {}. Use .toml, .yaml, or .yml",
                        ext
                    ));
                }
            };
        }

        // Allow environment variable overrides with NODE_ prefix
        figment = figment.merge(Env::prefixed("NODE_").split("__"));

        let config: NodeConfig = figment.extract()?;
        Ok(config)
    }

    /// Load configuration from environment variables only.
    ///
    /// Uses the `NODE_` prefix for all variables.
    /// Nested fields use double underscore: `NODE_CONSENSUS__N=4`
    pub fn from_env() -> Result<Self> {
        let figment = Figment::new().merge(Env::prefixed("NODE_").split("__"));

        let config: NodeConfig = figment.extract()?;
        Ok(config)
    }
}
