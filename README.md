<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/kairos-logo-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/kairos-logo-light.svg">
    <img src="assets/kairos-logo-light.svg" alt="Kairos Logo" width="400" />
  </picture>
</p>

# Kairos

A minimalist, low-latency blockchain protocol. EVM-compatible. USDC-native settlement.

## Overview

Kairos is a high-performance Layer 1 blockchain built for speed. Powered by the **Minimmit** consensus protocol, Kairos achieves 2-round finality with approximately 17% lower latency than state-of-the-art BFT protocols — making it ideal for real-time payments, DeFi, and any application where every millisecond matters.

### Key Properties

- ⚡ **Fastest finality** — Minimmit consensus achieves 2-round commit with optimistic responsiveness
- 🔗 **EVM-compatible** — Full Ethereum Virtual Machine compatibility for seamless smart contract deployment
- 💵 **USDC-native** — First-class USDC support as the native settlement asset
- 🔒 **Byzantine fault tolerant** — Secure under `n ≥ 5f + 1` with cryptographic finality guarantees
- 🧱 **Minimalist design** — Lean codebase, no bloat, purpose-built for low-latency consensus

### Why Kairos

Existing blockchains trade latency for generality. Multi-second finality times are unacceptable for real-time payments, high-frequency trading, and interactive financial applications. Kairos is designed from the ground up to minimize time-to-finality through two key innovations:

1. **Minimmit Consensus**: A Byzantine-fault-tolerant State Machine Replication (SMR) protocol that decouples view progression from transaction finality. While requiring `n-f` votes for finalization (L-notarizations), the protocol allows view progression with only `2f+1` votes (M-notarizations). This minimizes overhead on the consensus hot path, achieving ~17% lower latency than Alpenglow and Simplex in globally distributed networks.

2. **State Channels**: For high-frequency payment flows and DeFi interactions, Kairos supports state channels that allow participants to transact off-chain with on-chain settlement guarantees. This enables thousands of USDC transfers per second without requiring each transaction to pass through consensus.

Together, these innovations deliver a blockchain where sub-second finality is the norm — not the exception.

**Research Paper**: [Minimmit: Minimizing Latency of Optimistic BFT SMR](https://arxiv.org/pdf/2508.10862)

## Protocol Summary

### Byzantine Fault Tolerance

Minimmit operates under the assumption that on a total of `n` validators, at most `f` may exhibit Byzantine (arbitrary) faults, where:

```
n >= 5f + 1
```

This is the minimum resilience required for 2-round finality in partially synchronous settings. For example:
- `f = 1` requires `n >= 6` validators
- `f = 2` requires `n >= 11` validators

### Dual Notarization System

The protocol uses two distinct vote thresholds for different purposes:

| Notarization | Threshold | Purpose |
|--------------|-----------|---------|
| **M-Notarization** | `2f + 1` votes | View progression (move to next view) |
| **L-Notarization** | `n - f` votes | Transaction finality (block committed) |

This separation is the source of Minimmit's latency advantage: validators can progress to the next view as soon as they observe `2f + 1` votes, without waiting for the full `n - f` required for finality.

### Protocol Flow

```
┌─────────────┐
│   Leader    │
│  (View v)   │
└──────┬──────┘
       │
       │ 1. Propose Block B
       │    (view, transactions, parent_hash)
       │
       ▼
┌──────────────────────────────────────┐
│      P2P Layer Broadcast             │
└──────┬────────────┬────────────┬─────┘
       │            │            │
       ▼            ▼            ▼
   ┌───────┐    ┌───────┐    ┌───────┐
   │Node 1 │    │Node 2 │    │Node n │
   └───┬───┘    └───┬───┘    └───┬───┘
       │            │            │
       │ 2. Validate Block B     │
       │    (signatures, state)  │
       │            │            │
       ▼            ▼            ▼
   ┌────────────────────────────────┐
   │   Consensus Layer (each node)  │
   │   - Check validity conditions  │
   │   - Vote if valid              │
   └────────┬───────────────────────┘
            │
            │ 3. Broadcast Vote(B, v)
            │
            ▼
   ┌────────────────────────────────┐
   │    Vote Collection             │
   │                                │
   │  2f+1 votes --> M-Notarization │  <-- View Progression
   │  (move to view v+1)            │
   │                                │
   │  n-f votes --> L-Notarization  │  <-- Finalization
   │  (finalize block B)            │
   └────────────────────────────────┘
```

### Nullification (Handling Faulty Leaders)

When a view stalls (leader is faulty or network issues prevent timely delivery), validators send nullify messages:

1. Timer expires without receiving a valid block proposal
2. Validator broadcasts `Nullify(view)` message
3. When `2f + 1` nullify messages are collected, validators progress to next view
4. This ensures liveness: even with Byzantine leaders, honest validators eventually reach a view with an honest leader

### Safety Guarantees

Validators vote for a block only if:
1. An M-notarization exists for the parent block
2. Nullifications exist for all intermediate views (between parent and current)
3. The block passes validation (signatures, state transitions)

This ensures no two inconsistent blocks can both receive L-notarizations, maintaining the consistency property.

## Architecture

The implementation consists of four primary architectural layers:

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL ENVIRONMENT                         │
│  Users/Txns              Other Peers              Other Peers        │
└─────────┬────────────────────┬────────────────────────┬──────────────┘
          │                    │                        │
┌─────────▼────────────────────▼────────────────────────▼──────────────┐
│                    P2P COMMUNICATION LAYER                            │
│  - Message Broadcasting (Blocks, Votes, Nullifications)               │
│  - Peer Discovery and Connection Management                           │
│  - BLS Signature Verification                                         │
│  - Message Authentication and Deduplication                           │
└──────────────────────┬────────────────────┬──────────────────────────┘
                       │                    │
            ┌──────────▼────────┐  ┌────────▼──────────┐
┌───────────▼──────────┐  ┌─────▼──▼─────────┐  ┌──────▼────────────┐
│  BLOCK VALIDATION    │  │  CORE CONSENSUS   │  │  PERSISTENT       │
│  LAYER               │<-│  LAYER            │<-│  STORAGE LAYER    │
│                      │  │  (Minimmit)       │  │                   │
│  - Block Structure   │  │  - View Mgmt      │  │  - Finalized      │
│  - Signatures        │  │  - Voting Logic   │  │    Blocks         │
│  - State Validation  │  │  - M/L-Notarize   │  │  - Votes          │
│                      │  │  - Nullification  │  │  - Notarizations  │
│  Parallel Ed25519    │  │  - Finalization   │  │                   │
│  batch verification  │  │                   │  │  RocksDB          │
└──────────────────────┘  └───────────────────┘  └───────────────────┘
```

### Thread Model

The node runs on 3 OS threads plus 1 async runtime:

| Thread | Responsibilities |
|--------|-----------------|
| **P2P** (Tokio) | Network I/O, BLS signature verification, message routing |
| **Mempool** | Transaction validation, storage, block proposal building |
| **Consensus** | Block validation, voting, finalization, state management |

### Inter-Thread Communication

All threads communicate via lock-free SPSC ring buffers (`rtrb`):

```
┌─────────────┐                       ┌───────────────────┐     ┌─────────────┐
│    P2P      │                       │     MEMPOOL       │     │  CONSENSUS  │
│   Thread    │                       │     Thread        │     │   Thread    │
└─────────────┘                       └───────────────────┘     └─────────────┘
      │                                       │                       │
      │ consensus_msgs (BlockProposal+Votes)  │                       │
      ├──────────────────────────────────────────────────────────────>│
      │                                       │                       │
      │ transactions                          │                       │
      ├──────────────────────────────────────>│                       │
      │                                       │                       │
      │                                       │ proposal_request      │
      │                                       │<──────────────────────┤
      │                                       │                       │
      │                                       │ proposal_response     │
      │                                       ├──────────────────────>│
      │                                       │                       │
      │                                       │ finalized_notif       │
      │                                       │<──────────────────────┤
      │                                       │                       │
      │<──────────────────────────────────────────────────────────────┤
      │                     broadcast                                 │
```

## Project Structure

```
core/
├── consensus/          # Core consensus implementation
│   ├── src/
│   │   ├── consensus_manager/   # Minimmit state machine
│   │   │   ├── consensus_engine.rs
│   │   │   ├── state_machine.rs
│   │   │   ├── view_manager.rs
│   │   │   └── view_chain.rs
│   │   ├── crypto/              # BLS signatures, aggregation
│   │   ├── mempool/             # Transaction pool service
│   │   ├── state/               # Blocks, transactions, accounts
│   │   ├── storage/             # RocksDB persistence
│   │   └── validation/          # Block and transaction validation
│   └── benches/                 # Performance benchmarks
├── crypto/             # Threshold cryptography
├── grpc-client/        # External gRPC API
│   ├── proto/          # Protocol buffer definitions
│   └── src/
│       ├── server.rs   # gRPC server
│       └── services/   # Service implementations
├── node/               # High-level node orchestration
│   └── src/
│       ├── config.rs   # Unified configuration
│       └── node.rs     # ValidatorNode struct
├── p2p/                # Peer-to-peer networking
│   └── src/
│       ├── network.rs  # Iroh-based networking
│       └── protocols/  # Consensus, gossip, sync protocols
├── visualizer/         # Embedded web UI for consensus visualization
│   └── src/
│       ├── lib.rs             # DashboardMetrics, ViewSlot, diff logic
│       ├── server.rs          # axum SSE + REST + static serving
│       └── static/            # HTML/JS/CSS (embedded at compile time)
├── tests/              # Integration and E2E tests
│   └── src/
│       ├── e2e_consensus/
│       └── gossip/
└── docs/               # Additional documentation
```

## Getting Started

### Using Nix (Recommended)

[Nix](https://nixos.org/) provides a reproducible development environment with all
dependencies pre-configured. This is the fastest way to get started.

**Install Nix** (if you don't have it):

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

**Enter the dev shell:**

```bash
nix develop
```

This gives you Rust 1.90.0, protobuf compiler, OpenSSL, cargo-deny, git-cliff,
taplo, and all other required tools — on both **macOS** and **Linux**.

**Automatic activation with direnv** (optional):

```bash
# Install direnv: https://direnv.net/
direnv allow
# Now every `cd` into the repo auto-activates the environment
```

**Build & test:**

```bash
cargo build --release
cargo test
cargo bench
```

**Build a reproducible release binary via Nix:**

```bash
nix build
./result/bin/node --help
```

**Build a minimal Docker image via Nix** (~50MB):

```bash
nix build .#dockerImage
docker load < result
docker run --rm kairos-node:latest --help
```

### Manual Setup (Without Nix)

<details>
<summary>Click to expand manual setup instructions</summary>

**Prerequisites:**
- Rust 1.90.0 (`rustup install 1.90.0`)
- `protobuf-compiler` / `protobuf`
- `pkg-config`, `libssl-dev` / `openssl`
- `libclang-dev` / `llvm`
- Linux only: `uuid-dev`, `libbsd-dev`

```bash
git clone https://github.com/jorgeantonio21/kairos.git
cd core

cargo build --release
cargo test
cargo bench
```

</details>

### Running a Node

```rust
use node::{NodeConfig, ValidatorNode};
use p2p::ValidatorIdentity;

// Load configuration from file
let config = NodeConfig::from_path("config.toml")?;

// Generate or load validator identity
let identity = ValidatorIdentity::generate();

// Create logger
let logger = create_logger();

// Spawn all services
let node = ValidatorNode::<6, 1, 3>::from_config(config, identity, logger)?;

// Wait for P2P bootstrap (connect to other validators)
node.wait_ready().await;

// Node is now participating in consensus...

// Graceful shutdown
node.shutdown(Duration::from_secs(10))?;
```

## Configuration

Configuration can be provided via TOML, YAML, or environment variables. See [`config.example.toml`](config.example.toml) for a complete reference with all available options.

### Quick Start Configuration

Copy the example configuration and modify for your environment:

```bash
cp config.example.toml config.toml
# Edit config.toml with your settings
```

### Minimal Configuration

```toml
[consensus]
n = 6                                    # Total validators (must be >= 5f + 1)
f = 1                                    # Max Byzantine faults
view_timeout = { secs = 5, nanos = 0 }   # Block proposal timeout
leader_manager = "RoundRobin"
network = "local"
peers = []                               # BLS public keys of all validators
genesis_accounts = []

[storage]
path = "/var/lib/kairos/data"

[p2p]
listen_addr = "0.0.0.0:9000"
external_addr = "1.2.3.4:9000"           # Your public IP
total_number_peers = 6
maximum_number_faulty_peers = 1
validators = []                          # Bootstrap peer info

[rpc]
listen_addr = "0.0.0.0:50051"
peer_id = 0                              # This validator's index
network = "local"
total_validators = 6
f = 1

[identity]
bls_secret_key_path = "/etc/kairos/keys/bls.key"
ed25519_secret_key_path = "/etc/kairos/keys/ed25519.key"
```

### Environment Variables

Configuration can be overridden via environment variables with the `NODE_` prefix. Nested fields use double underscore:

```bash
NODE_CONSENSUS__N=6
NODE_CONSENSUS__F=1
NODE_CONSENSUS__VIEW_TIMEOUT__SECS=10
NODE_STORAGE__PATH=/data/kairos
NODE_P2P__LISTEN_ADDR=0.0.0.0:9000
NODE_RPC__LISTEN_ADDR=0.0.0.0:8080
```

## Cryptography

### BLS Signatures

The protocol uses BLS12-381 signatures for:
- Block proposals (leader signature)
- Votes (validator signatures)
- Nullification messages

BLS signatures enable efficient aggregation: `n` individual signatures can be combined into a single constant-size threshold signature.

### Threshold Signatures

Two threshold schemes are used:
- `2f + 1` threshold for M-notarizations and nullifications
- `n - f` threshold for L-notarizations (finality)

### Transaction Signatures

Individual transactions use Ed25519 signatures with parallel batch verification for performance.

## Performance

### Block Validation Benchmarks

Measured on Apple M2 (8 cores):

| Transactions | Sequential | Parallel Batch | Speedup |
|--------------|------------|----------------|---------|
| 100          | 2.8ms      | 0.8ms          | 3.5x    |
| 500          | 14ms       | 2.1ms          | 6.7x    |
| 1000         | 28ms       | 3.2ms          | 8.75x   |
| 5000         | 140ms      | 14ms           | 10x     |

### Latency Characteristics

- **Optimistic responsiveness**: Transaction latency is proportional to actual network delay, not predetermined timeouts
- **2-round finality**: Blocks finalize in 2 network rounds under normal conditions
- **Adaptive view changes**: Views progress as soon as `2f + 1` votes are collected

## Storage

The persistent storage layer uses RocksDB with the following schema:

| Table | Key | Value |
|-------|-----|-------|
| Blocks | `block_hash` | Block data (view, txs, parent, sigs) |
| Votes | `(view, block_hash, peer_id)` | BLS signature |
| Nullifications | `(view, peer_id)` | BLS signature |
| Notarizations | `(view, block_hash)` | Type (M/L), threshold sig, bitmap |
| Accounts | `address` | Balance, nonce, state |

## Mempool

The mempool implements a two-pool design:

- **Pending**: Transactions ready for execution (continuous nonces)
- **Queued**: Transactions waiting for earlier nonces

Features:
- Fee-based priority ordering
- Replace-by-Fee (RBF) support
- Configurable size limits with eviction

## gRPC API

The node exposes a gRPC API for external interaction:

| Service | Methods |
|---------|---------|
| `AccountService` | `GetAccount`, `GetBalance`, `GetNonce` |
| `BlockService` | `GetBlock`, `GetBlockByHeight`, `GetLatestBlock` |
| `TransactionService` | `SubmitTransaction`, `GetTransaction` |
| `NodeService` | `GetStatus`, `GetPeers`, `GetHealth` |
| `SubscriptionService` | `SubscribeBlocks`, `SubscribeTransactions` |

## Consensus Visualizer

The consensus visualizer is an embedded web dashboard that provides real-time visibility into the Minimmit consensus protocol. It shows view progression, vote accumulation, M/L-notarizations, and nullifications as they happen. The dashboard is served directly from the node binary — no external dependencies, no build step, no npm.

### How It Works

The visualizer uses a lock-free shared data structure (`Arc<DashboardMetrics>`) between the consensus thread and an embedded axum HTTP server. The consensus thread writes atomic stores (~1ns each) on every state change. Connected browser clients receive updates via Server-Sent Events (SSE), where the server diffs snapshots every 100ms and pushes only the changes.

```
Consensus thread              axum HTTP server             Browser
     │                             │                          │
     │  Relaxed atomic stores      │                          │
     ▼                             │                          │
  ┌────────────────────────────────┐                          │
  │   Arc<DashboardMetrics>        │  Relaxed atomic loads    │
  │   256-slot ring buffer         │──────────────────────>   │
  │   (view % 256)                 │  SSE diff every 100ms    │
  └────────────────────────────────┘                          │
                                                              │
                                   GET /api/events ──> EventSource
                                   GET /api/state  ──> JSON snapshot
                                   GET /api/health ──> health check
                                   GET /           ──> dashboard HTML
```

Zero allocation and zero blocking on the consensus hot path. The dashboard is entirely optional — when disabled (the default), there is no overhead.

### Enabling the Visualizer

#### Option 1: Configuration file

Add a `[visualizer]` section to your node's TOML config:

```toml
[visualizer]
enabled = true
listen_address = "127.0.0.1:8080"
```

#### Option 2: Environment variables

```bash
NODE_VISUALIZER__ENABLED=true
NODE_VISUALIZER__LISTEN_ADDRESS=127.0.0.1:8080
```

Then start the node normally and open the dashboard in a browser:

```bash
cargo run -p node -- --config config.toml
# Dashboard available at http://127.0.0.1:8080
```

### Dashboard Tabs

The dashboard has five tabs:

**Overview** — High-level consensus state at a glance. Shows the current view number, finalized view number, and a horizontal strip of the last ~30 views as colored boxes. Each box represents a view:
- Green: L-notarized (finalized)
- Blue: M-notarized (view progressed but not yet finalized)
- Red: Nullified (view failed)
- Orange: Cascade nullified
- Gray: In progress

**Consensus Timeline** — Per-view detail with progress bars. Each row shows a view's vote progress (`vote_count / n`) with threshold markers at `2f+1` (M-notarization) and `n-f` (L-notarization), plus a nullify progress bar with its `2f+1` threshold. Status badges show the lifecycle: Proposed → Voting → M-Notarized → L-Notarized | Nullified.

**Blocks** — Table of block proposals: view number, leader, block hash (truncated), transaction count, status, and timestamp.

**Notarizations** — Three sections showing M-notarizations (blue), L-notarizations (green), and nullifications (red) with their respective metadata.

**Logs** — Real-time event stream. Every SSE event is rendered as a color-coded log entry. Auto-scrolls by default with a pause toggle.

### REST & SSE API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/` | Dashboard HTML page |
| GET | `/static/app.js` | Dashboard JavaScript |
| GET | `/static/style.css` | Dashboard stylesheet |
| GET | `/api/events` | SSE stream (diff-based, 100ms interval) |
| GET | `/api/state` | Full JSON snapshot of all active view slots |
| GET | `/api/health` | Current view, finalized view, node N/F |

The SSE stream emits JSON events with a `kind` field:

```json
{"kind":"current_view_changed","view":42}
{"kind":"view_started","view":42,"leader":3,"timestamp":1740000000000}
{"kind":"vote_count_changed","view":42,"count":4}
{"kind":"m_notarization","view":42,"timestamp":1740000000050,"block_hash":"a1b2c3...","vote_count":3}
{"kind":"l_notarization","view":42,"timestamp":1740000000100,"block_hash":"a1b2c3...","vote_count":5}
{"kind":"nullification","view":42,"timestamp":1740000000200,"nullify_count":3}
{"kind":"block_proposed","view":42,"block_hash":"a1b2c3...","tx_count":10}
```

You can consume the SSE stream programmatically with `curl`:

```bash
curl -N http://127.0.0.1:8080/api/events
```

Or fetch a one-time snapshot:

```bash
curl -s http://127.0.0.1:8080/api/state | jq .
```

### Running a Local 6-Node Network with Visualizers

Each validator in a local network can run its own visualizer on a different port. This lets you observe consensus from every node's perspective simultaneously.

#### Using per-node config files

The local config files live in `node/config/`. To enable the visualizer on each node, add a `[visualizer]` section to each `node/config/nodeN.toml`. Each node must use a unique port:

| Node | Config file | Visualizer address | Dashboard URL |
|------|-------------|--------------------|---------------|
| node0 | `node/config/node0.toml` | `127.0.0.1:8080` | http://127.0.0.1:8080 |
| node1 | `node/config/node1.toml` | `127.0.0.1:8081` | http://127.0.0.1:8081 |
| node2 | `node/config/node2.toml` | `127.0.0.1:8082` | http://127.0.0.1:8082 |
| node3 | `node/config/node3.toml` | `127.0.0.1:8083` | http://127.0.0.1:8083 |
| node4 | `node/config/node4.toml` | `127.0.0.1:8084` | http://127.0.0.1:8084 |
| node5 | `node/config/node5.toml` | `127.0.0.1:8085` | http://127.0.0.1:8085 |

Add the following to each config file (adjusting the port per node):

```toml
# node/config/node0.toml
[visualizer]
enabled = true
listen_address = "127.0.0.1:8080"
```

```toml
# node/config/node1.toml
[visualizer]
enabled = true
listen_address = "127.0.0.1:8081"
```

And so on for nodes 2–5.

Then start each node in a separate terminal:

```bash
# Terminal 1
cargo run -p node -- --config node/config/node0.toml

# Terminal 2
cargo run -p node -- --config node/config/node1.toml

# Terminal 3
cargo run -p node -- --config node/config/node2.toml

# Terminal 4
cargo run -p node -- --config node/config/node3.toml

# Terminal 5
cargo run -p node -- --config node/config/node4.toml

# Terminal 6
cargo run -p node -- --config node/config/node5.toml
```

Open all six dashboards side-by-side:

```bash
open http://127.0.0.1:8080 http://127.0.0.1:8081 http://127.0.0.1:8082 \
     http://127.0.0.1:8083 http://127.0.0.1:8084 http://127.0.0.1:8085
```

#### Using environment variables (no config file edits)

If you don't want to edit the TOML files, override via environment variables. Each node needs its own unique `LISTEN_ADDRESS`:

```bash
# Terminal 1
NODE_VISUALIZER__ENABLED=true NODE_VISUALIZER__LISTEN_ADDRESS=127.0.0.1:8080 \
  cargo run -p node -- --config node/config/node0.toml

# Terminal 2
NODE_VISUALIZER__ENABLED=true NODE_VISUALIZER__LISTEN_ADDRESS=127.0.0.1:8081 \
  cargo run -p node -- --config node/config/node1.toml

# ... and so on for nodes 2-5 with ports 8082-8085
```

#### Docker Compose localnet

Use the prebuilt 6-node localnet profile in `deployments/localnet/localnet.override.yml`.
It already includes:

- static validator container IPs (`172.30.0.10` .. `172.30.0.15`) for stable P2P addressing
- visualizer enablement and host ports (`8080` .. `8085`)
- per-node metrics ports (`9090`, `9092` .. `9096`)

Start localnet:

```bash
./deployments/localnet/generate-keys.sh --clean
docker build -f deployments/Dockerfile -t kairos-node:latest .
docker compose \
  -f deployments/localnet/docker-compose.yml \
  -f deployments/localnet/localnet.override.yml \
  up -d
```

Open node visualizers:

```bash
open http://127.0.0.1:8080  # validator-0
open http://127.0.0.1:8081  # validator-1
open http://127.0.0.1:8082  # validator-2
open http://127.0.0.1:8083  # validator-3
open http://127.0.0.1:8084  # validator-4
open http://127.0.0.1:8085  # validator-5
```

Open observability:

```bash
open http://127.0.0.1:3000  # Grafana
open http://127.0.0.1:9091  # Prometheus
```

### What to Look For

When observing a healthy network across multiple dashboards:

- **Vote progress bars** fill to the `2f+1` marker (M-notarization) quickly, then continue filling toward `n-f` (L-notarization).
- **View strip** shows a sequence of green boxes (L-notarized views) with the occasional blue (M-notarized but not yet finalized) at the head.
- **Finalized view** increases steadily, staying within a few views of the current view.
- **All nodes agree** on the same finalized view number and show the same block hashes for finalized views.

Potential issues to diagnose:

- **Red boxes (nullifications)**: A view timed out or the leader was faulty. Occasional reds are normal; clusters of reds indicate network issues or a Byzantine leader.
- **Orange boxes (cascade nullifications)**: A past view was nullified after nodes had already progressed. Check the Logs tab for the cascade trigger view.
- **Vote progress stuck below `2f+1`**: A node may be partitioned from the network or a peer is not voting.
- **Finalized view divergence between nodes**: Nodes are seeing different L-notarizations. This should not happen in a correctly operating network and warrants investigation.

## Testing

```bash
# Unit tests
cargo test

# Integration tests
cargo test --package tests

# E2E consensus tests
cargo test --package tests e2e_consensus

# Gossip protocol tests  
cargo test --package tests gossip

# Run with logging
RUST_LOG=debug cargo test
```

## Security Considerations

- All peer connections use authenticated encryption
- Messages include timestamps and sequence numbers to prevent replay attacks
- Rate limiting protects against denial-of-service attempts
- Peer connections are diversified to resist eclipse attacks

## Contributing

Contributions are welcome. Please ensure:

1. All tests pass (`cargo test`)
2. No clippy warnings (`cargo clippy -- -D warnings`)
3. Code is formatted (`cargo fmt`)
4. TOML files are formatted (`taplo fmt`)
5. Documentation is updated for public APIs

> **Tip:** Use `nix develop` to get all the tools above in one command.

## Deployment

The `deployments/` directory contains a production-ready Docker Compose stack
for local development and testing. See [deployments/README.md](deployments/README.md)
for full documentation.

- **Single node:** `docker compose -f deployments/docker-compose.yml up`
- **6-validator localnet:** `docker compose -f deployments/localnet/docker-compose.yml -f deployments/localnet/localnet.override.yml up -d`
- **Docker images:**
  - **Linux/CI:** `nix build .#dockerImage && docker load < result` (minimal ~50MB image)
  - **macOS:** `docker build -f deployments/Dockerfile -t kairos-node:latest .`
- **Releases:** tagged versions are pushed to GHCR (`ghcr.io/jorgeantonio21/kairos/node`)

### Deployment Roadmap

| Phase | Status |
|-------|--------|
| Local single-node (Docker Compose) | ✅ |
| Multi-node localnet (6 validators) | ✅ |
| Observability (Prometheus + Loki + Grafana) | ✅ |
| Alerting rules (Prometheus) | ✅ |
| Nix-built Docker images (GHCR) | ✅ |
| Consensus Visualizer (embedded web UI) | ✅ |
| Terraform (AWS/GCP cloud deployment) | 🔜 Planned |
| Kubernetes (Helm charts) | 🔜 Planned |

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## References

- [Minimmit: Minimizing Latency of Optimistic BFT SMR](https://arxiv.org/pdf/2508.10862)
- [BLS12-381 Curve](https://hackmd.io/@benjaminion/bls12-381)
- [Commonware Runtime](https://github.com/commonwarexyz/monorepo)
