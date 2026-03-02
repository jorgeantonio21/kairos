//! Test Helpers and Utilities
//!
//! This module provides common utilities, fixtures, and helper functions for integration tests.

use crate::{
    consensus::ConsensusMessage,
    consensus_manager::{
        config::{ConsensusConfig, GenesisAccount},
        leader_manager::LeaderSelectionStrategy,
    },
    crypto::{
        consensus_bls::{BlsPublicKey, BlsSecretKey, PeerId, ThresholdSignerContext},
        transaction_crypto::{TxPublicKey, TxSecretKey},
    },
    mempool::{FinalizedNotification, MempoolService, ProposalRequest, ProposalResponse},
    state::{address::Address, peer::PeerSet, transaction::Transaction},
    storage::store::ConsensusStore,
    validation::PendingStateWriter,
};

use std::{
    collections::HashMap,
    sync::{Arc, atomic::AtomicBool},
};
use tokio::sync::Notify;

use anyhow::{Context, Result, anyhow};
use crypto::bls::ops::public_key_from_scalar;
use crypto::dkg::run_in_memory_dual_dkg;
use crypto::threshold_setup::{
    ThresholdDomains, ThresholdKeyset, ThresholdKeysets, ThresholdSetupArtifact,
    ValidatorParticipant,
};
use rtrb::{Consumer, Producer, RingBuffer};
use std::time::Duration;
use tempfile::TempDir;

/// Test configuration constants
pub const N: usize = 6;
pub const F: usize = 1;
pub const M_SIZE: usize = 3;
pub const BUFFER_SIZE: usize = 10_000;

/// Default view timeout for tests
pub const DEFAULT_VIEW_TIMEOUT: Duration = Duration::from_secs(5);

/// Default tick interval for consensus engines
pub const DEFAULT_TICK_INTERVAL: Duration = Duration::from_millis(10);
pub const TEST_VALIDATOR_SET_ID: &str = "consensus-e2e-threshold-tests";
pub const DOMAIN_M_NOT: &str = "consensus/m-not/v1";
pub const DOMAIN_NULLIFY: &str = "consensus/nullify/v1";
pub const DOMAIN_L_NOT: &str = "consensus/l-not/v1";

/// Keypair for a replica
#[derive(Clone)]
pub struct KeyPair {
    pub secret_key: BlsSecretKey,
    pub public_key: BlsPublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let sk = BlsSecretKey::generate(&mut rand::thread_rng());
        let pk = sk.public_key();
        Self {
            secret_key: sk,
            public_key: pk,
        }
    }
}

fn gen_tx_keypair() -> (TxSecretKey, TxPublicKey) {
    let sk = TxSecretKey::generate(&mut rand::rngs::OsRng);
    let pk = sk.public_key();
    (sk, pk)
}

/// Complete setup for a single replica with synchronous block validation
pub struct ReplicaSetup<const N: usize, const F: usize, const M_SIZE: usize> {
    /// The replica's peer ID
    pub replica_id: PeerId,

    /// The replica's secret key
    pub secret_key: BlsSecretKey,

    /// Consumer for incoming consensus messages (from network)
    pub message_consumer: Consumer<ConsensusMessage<N, F, M_SIZE>>,

    /// Producer for incoming consensus messages (network writes here)
    pub message_producer: Producer<ConsensusMessage<N, F, M_SIZE>>,

    /// Consumer for outgoing consensus messages (network reads from here)
    pub broadcast_consumer: Consumer<ConsensusMessage<N, F, M_SIZE>>,

    /// Producer for outgoing consensus messages (consensus engine writes here)
    pub broadcast_producer: Producer<ConsensusMessage<N, F, M_SIZE>>,

    /// Notify for signaling when new messages are available to broadcast
    pub broadcast_notify: Arc<Notify>,

    /// Mempool service handle
    pub mempool_service: MempoolService,

    /// Producer for requesting block proposals
    pub proposal_req_producer: Producer<ProposalRequest>,

    // Consumer for receiving block proposals
    pub proposal_resp_consumer: Consumer<ProposalResponse>,

    /// Producer for notifying mempool of finalized blocks (Consensus → Mempool)
    pub finalized_producer: Producer<FinalizedNotification>,

    /// Lock-free queue for submitting gRPC transactions to mempool (gRPC → Mempool)
    /// Uses ArrayQueue (MPMC) since multiple gRPC handlers may push concurrently.
    pub grpc_tx_queue: Arc<crossbeam::queue::ArrayQueue<Transaction>>,

    /// Producer for submitting P2P-gossipped transactions to mempool (P2P → Mempool)
    /// Uses rtrb (SPSC) since a single P2P thread pushes to a single mempool thread.
    #[allow(dead_code)]
    pub p2p_tx_producer: Producer<Transaction>,

    /// Persistence writer for consensus state
    pub persistence_writer: PendingStateWriter,

    /// Persistent storage for this replica
    pub storage: Arc<ConsensusStore>,

    /// Shutdown flag (shared with mempool service)
    #[allow(unused)]
    pub shutdown: Arc<AtomicBool>,

    /// Temporary directory for storage (must be kept alive)
    _temp_dir: TempDir,
}

impl<const N: usize, const F: usize, const M_SIZE: usize> ReplicaSetup<N, F, M_SIZE> {
    /// Creates a new replica setup with MempoolService
    ///
    /// Block validation is now done synchronously in ViewProgressManager,
    /// so no separate BlockValidationService is needed.
    ///
    /// ## Transaction Queue Architecture
    ///
    /// - `grpc_tx_queue`: ArrayQueue (MPMC) for gRPC handlers to push transactions
    /// - `p2p_tx_producer`/`p2p_tx_consumer`: rtrb (SPSC) for P2P thread to push gossipped
    ///   transactions
    ///
    /// The MempoolService polls from BOTH sources in its main loop.
    pub fn new(replica_id: PeerId, secret_key: BlsSecretKey, logger: slog::Logger) -> Self {
        // Create ring buffers for consensus messages
        let (message_producer, message_consumer) = RingBuffer::new(BUFFER_SIZE);
        let (broadcast_producer, broadcast_consumer) = RingBuffer::new(BUFFER_SIZE);

        // Create broadcast notify for signaling new messages to broadcast
        let broadcast_notify = Arc::new(Notify::new());

        // Create temporary directory and storage
        let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("consensus.redb");
        let storage = Arc::new(ConsensusStore::open(&db_path).expect("Failed to open storage"));

        // Create shutdown flag (shared across all services)
        let shutdown = Arc::new(AtomicBool::new(false));

        // Create PendingStateWriter directly (no separate validation service needed)
        let (persistence_writer, pending_state_reader) =
            PendingStateWriter::new(Arc::clone(&storage), 0);

        // Create gRPC transaction queue (ArrayQueue for MPMC - multiple gRPC handlers)
        let grpc_tx_queue = Arc::new(crossbeam::queue::ArrayQueue::new(BUFFER_SIZE));

        // Create P2P transaction channel (rtrb for SPSC - single P2P thread to single mempool
        // thread)
        let (p2p_tx_producer, p2p_tx_consumer) = RingBuffer::<Transaction>::new(BUFFER_SIZE);

        // Spawn MempoolService with both transaction sources:
        // - grpc_tx_queue: ArrayQueue for gRPC-submitted transactions
        // - p2p_tx_consumer: rtrb Consumer for P2P-gossipped transactions
        let (mempool_service, mempool_channels) = MempoolService::spawn(
            Arc::clone(&grpc_tx_queue),
            p2p_tx_consumer,
            pending_state_reader,
            Arc::clone(&shutdown),
            logger,
        );

        Self {
            replica_id,
            secret_key,
            storage,
            message_consumer,
            message_producer,
            broadcast_consumer,
            broadcast_producer,
            broadcast_notify,
            mempool_service,
            proposal_req_producer: mempool_channels.proposal_req_producer,
            proposal_resp_consumer: mempool_channels.proposal_resp_consumer,
            finalized_producer: mempool_channels.finalized_producer,
            grpc_tx_queue,
            p2p_tx_producer,
            persistence_writer,
            shutdown,
            _temp_dir: temp_dir,
        }
    }
}

/// Test fixture containing all components needed for an end-to-end test
pub struct TestFixture {
    /// Generated keypairs for all replicas
    pub keypairs: Vec<KeyPair>,

    /// The peer set containing all replica peer IDs
    pub peer_set: PeerSet,
    /// Per-peer threshold signer contexts used for consensus hot-path signatures.
    pub threshold_signer_by_peer_id: HashMap<PeerId, ThresholdSignerContext>,

    /// Base consensus configuration
    pub config: ConsensusConfig,
}

impl TestFixture {
    /// Creates a new test fixture with generated keypairs and configuration
    ///
    /// # Arguments
    /// * `n` - Number of replicas
    /// * `f` - Number of Byzantine faults tolerated
    /// * `view_timeout` - Timeout for view changes
    ///
    /// # Returns
    /// A complete test fixture ready for use
    pub fn new(n: usize, f: usize, view_timeout: Duration) -> Self {
        let mut keypairs = Vec::new();

        // Generate keypairs for all replicas
        for _ in 0..n {
            let keypair = KeyPair::generate();
            keypairs.push(keypair);
        }

        let (peer_set, threshold_signer_by_peer_id) =
            build_threshold_material_from_keypairs(&keypairs, n, f, TEST_VALIDATOR_SET_ID)
                .expect("threshold test material generation must succeed");

        // Create config strings (hex-encoded public keys)
        let mut peer_strs = Vec::with_capacity(peer_set.sorted_peer_ids.len());
        for peer_id in &peer_set.sorted_peer_ids {
            let pk = peer_set.id_to_public_key.get(peer_id).unwrap();
            let mut buf = Vec::new();
            pk.serialize_compressed(&mut buf).unwrap();
            peer_strs.push(hex::encode(buf));
        }

        let config = ConsensusConfig {
            n,
            f,
            view_timeout,
            leader_manager: LeaderSelectionStrategy::RoundRobin,
            network: crate::consensus_manager::config::Network::Local,
            peers: peer_strs,
            genesis_accounts: vec![],
        };

        Self {
            keypairs,
            peer_set,
            threshold_signer_by_peer_id,
            config,
        }
    }

    /// Creates a test fixture with funded genesis accounts
    pub fn with_genesis_accounts(genesis_accounts: Vec<GenesisAccount>) -> Self {
        let mut fixture = Self::default();
        fixture.config.genesis_accounts = genesis_accounts;
        fixture
    }

    /// Creates a default test fixture with standard parameters (N=6, F=1)
    pub fn default() -> Self {
        Self::new(N, F, DEFAULT_VIEW_TIMEOUT)
    }
}

fn build_threshold_material_from_keypairs(
    keypairs: &[KeyPair],
    n: usize,
    f: usize,
    validator_set_id: &str,
) -> Result<(PeerSet, HashMap<PeerId, ThresholdSignerContext>)> {
    if keypairs.len() != n {
        return Err(anyhow!(
            "keypair length {} does not match n {}",
            keypairs.len(),
            n
        ));
    }
    if validator_set_id.trim().is_empty() {
        return Err(anyhow!("validator_set_id must be non-empty"));
    }

    let mut entries = keypairs
        .iter()
        .map(|keypair| (keypair.public_key.to_peer_id(), keypair.public_key))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(peer_id, _)| *peer_id);

    let mut rng = rand::thread_rng();
    let dual_dkg = run_in_memory_dual_dkg(n, f, &mut rng).context("run in-memory dual DKG")?;

    let m_secret_by_index = dual_dkg
        .m_nullify
        .participant_shares
        .iter()
        .map(|share| (share.participant_index, share.secret_share.clone()))
        .collect::<HashMap<_, _>>();
    let l_secret_by_index = dual_dkg
        .l_notarization
        .participant_shares
        .iter()
        .map(|share| (share.participant_index, share.secret_share.clone()))
        .collect::<HashMap<_, _>>();

    let mut validators = Vec::with_capacity(n);
    let mut peers = Vec::with_capacity(n);
    let mut indices = Vec::with_capacity(n);
    let mut id_to_m_share_public_key = HashMap::with_capacity(n);
    let mut id_to_l_share_public_key = HashMap::with_capacity(n);

    for (position, (peer_id, public_key)) in entries.iter().enumerate() {
        let participant_index = (position + 1) as u64;
        let m_secret = m_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow!("missing M secret share for index {}", participant_index))?;
        let l_secret = l_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow!("missing L secret share for index {}", participant_index))?;

        let m_share_public_key = BlsPublicKey(public_key_from_scalar(m_secret)?);
        let l_share_public_key = BlsPublicKey(public_key_from_scalar(l_secret)?);
        validators.push(ValidatorParticipant {
            peer_id: *peer_id,
            participant_index,
            m_share_public_key: hex::encode(m_share_public_key.0),
            l_share_public_key: hex::encode(l_share_public_key.0),
        });
        peers.push(*public_key);
        indices.push(participant_index);
        id_to_m_share_public_key.insert(*peer_id, m_share_public_key);
        id_to_l_share_public_key.insert(*peer_id, l_share_public_key);
    }

    let mut peer_set = PeerSet::with_threshold_material(
        peers,
        indices,
        id_to_m_share_public_key,
        id_to_l_share_public_key,
        DOMAIN_M_NOT.as_bytes().to_vec(),
        DOMAIN_NULLIFY.as_bytes().to_vec(),
        DOMAIN_L_NOT.as_bytes().to_vec(),
    )?;
    peer_set.m_group_public_key = Some(dual_dkg.m_nullify.group_public_key);
    peer_set.l_group_public_key = Some(dual_dkg.l_notarization.group_public_key);

    let mut signer_by_peer_id = HashMap::with_capacity(n);
    for (position, (peer_id, _)) in entries.iter().enumerate() {
        let participant_index = (position + 1) as u64;
        let m_secret = m_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow!("missing M secret share for index {}", participant_index))?;
        let l_secret = l_secret_by_index
            .get(&participant_index)
            .ok_or_else(|| anyhow!("missing L secret share for index {}", participant_index))?;

        let artifact = ThresholdSetupArtifact {
            validator_set_id: validator_set_id.to_string(),
            peer_id: *peer_id,
            participant_index,
            n,
            f,
            validators: validators.clone(),
            domains: ThresholdDomains {
                m_not: DOMAIN_M_NOT.to_string(),
                nullify: DOMAIN_NULLIFY.to_string(),
                l_not: DOMAIN_L_NOT.to_string(),
            },
            keysets: ThresholdKeysets {
                m_nullify: ThresholdKeyset {
                    threshold: 2 * f + 1,
                    group_public_key: hex::encode(dual_dkg.m_nullify.group_public_key.0),
                    secret_share: hex::encode(m_secret.to_bytes_le()),
                },
                l_notarization: ThresholdKeyset {
                    threshold: n - f,
                    group_public_key: hex::encode(dual_dkg.l_notarization.group_public_key.0),
                    secret_share: hex::encode(l_secret.to_bytes_le()),
                },
            },
        };
        artifact
            .validate_for_node(*peer_id, n, f, Some(validator_set_id))
            .context("threshold setup artifact validation for test node")?;
        let signer = ThresholdSignerContext::from_decoded_setup(artifact.decode()?)?;
        signer_by_peer_id.insert(*peer_id, signer);
    }

    Ok((peer_set, signer_by_peer_id))
}

/// Creates a test transaction with the given parameters and proper signature
///
/// # Arguments
/// * `secret_key` - The secret key to sign the transaction with
/// * `public_key` - The sender's public key
/// * `nonce` - The transaction nonce
/// * `_payload` - Unused (kept for API compatibility)
pub fn create_test_transaction(
    secret_key: &TxSecretKey,
    public_key: &TxPublicKey,
    nonce: u64,
    _payload: Vec<u8>,
) -> Transaction {
    Transaction::new_transfer(
        Address::from_public_key(public_key),
        Address::from_bytes([2u8; 32]),
        100,
        nonce,
        10,
        secret_key,
    )
}

/// Creates funded test transactions along with their keypairs
/// Returns (transactions, genesis_accounts) where genesis_accounts can be used
/// to fund the senders in the genesis block
pub fn create_funded_test_transactions(count: usize) -> (Vec<Transaction>, Vec<GenesisAccount>) {
    let mut transactions = Vec::new();
    let mut genesis_accounts = Vec::new();

    for _i in 0..count {
        let (sk, pk) = gen_tx_keypair();

        // Create genesis account entry for this sender
        genesis_accounts.push(GenesisAccount {
            public_key: hex::encode(pk.to_bytes()),
            balance: 10_000,
        });

        // Create the transaction
        transactions.push(create_test_transaction(&sk, &pk, 0, vec![]));
    }

    (transactions, genesis_accounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::consensus_bls::{ThresholdDomain, ThresholdProof};

    #[test]
    fn threshold_fixture_material_sanity_combines_and_verifies() {
        let fixture = TestFixture::default();
        let payload = [7u8; blake3::OUT_LEN];

        let mut partials = Vec::new();
        for peer_id in fixture.peer_set.sorted_peer_ids.iter().take(2 * F + 1) {
            let signer = fixture
                .threshold_signer_by_peer_id
                .get(peer_id)
                .expect("missing signer");
            let partial = signer
                .partial_sign(ThresholdDomain::MNotarization, &payload)
                .expect("sign");
            let index = fixture.peer_set.get_index(peer_id).expect("index");
            partials.push((index, partial));
        }

        let proof = ThresholdProof::combine_partials(&partials).expect("combine");
        let mut message = DOMAIN_M_NOT.as_bytes().to_vec();
        message.extend_from_slice(&payload);
        let group_key = fixture
            .peer_set
            .m_group_public_key
            .expect("missing m group key");
        assert!(group_key.verify(&message, &proof.0));
    }
}
