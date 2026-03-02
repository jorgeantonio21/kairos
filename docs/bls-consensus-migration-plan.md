# BLS Consensus Migration Plan (ark -> blst via `crypto/`)

## Objective

Migrate consensus BLS cryptography from `consensus/src/crypto/aggregated.rs` (ark-based)
to `crypto/` (blst-based), while preserving protocol behavior and enabling:

1. Section 6.4 true threshold signatures for quorum proofs.
2. Section 6.5 compressed nullifications over threshold proofs for faster recovery after asynchrony.

## Scope and Non-Goals

### In Scope

- Replace consensus BLS primitive dependency path to `crypto/`.
- Remove consensus-local BLS implementation from `consensus/src/crypto/aggregated.rs`.
- Implement validator-set threshold key setup for consensus quorum signing.
- Keep transaction signatures (`transaction_crypto.rs`) unchanged unless explicitly requested.
- Add production tests for correctness invariants and migration safety.
- Add benchmark harnesses for pre/post migration performance tracking.

### Out of Scope (for this migration)

- Validator membership protocol redesign.
- Mempool dissemination redesign.
- Erasure coding parameter changes.

## Current State Snapshot (as of February 28, 2026)

- Consensus BLS primitives now come from `crypto::consensus_bls` (blst-backed).
- `consensus/src/crypto/aggregated.rs` is currently a re-export shim to `crypto::consensus_bls`.
- Consensus notarization/nullification construction now uses threshold combination
  (Lagrange interpolation over signer IDs), not additive signature aggregation.
- Notarization/nullification proof construction keeps deterministic signer ordering
  (sorted by `peer_id`) for reproducible proof bytes across replicas.
- Consensus verification paths (`MNotarization`, `LNotarization`, `Nullification`) use
  threshold verification semantics and fail closed.
- Runtime consensus paths in `view_context` and `consensus_engine` now avoid panic-prone
  `unwrap`/`expect` on network/config-driven data and return contextual errors instead.
- `crypto/` now has shared modules to avoid duplicated crypto logic:
  - `src/bls/constants.rs`
  - `src/bls/ops.rs`
  - `src/threshold_math.rs`
- Setup-oriented threshold flow remains in `crypto/src/threshold.rs` with supporting
  math in `scalar.rs` and `polynomial.rs`.
- Phase 1A DKG core is now available in `crypto/src/dkg.rs`:
  - Joint-Feldman dealer contribution generation
  - share verification against polynomial commitments
  - in-memory ceremony runners for single and dual keysets (`2f+1` and `n-f`)
  - adversarial/tamper and threshold-signing unit tests
- `crypto` setup and DKG boundaries now expose typed error enums (`ThresholdSetupError`,
  `DkgError`) instead of generic `anyhow` errors.
- `bootstrap-rpc` finalize now uses submitted commitments/shares to reconstruct both keysets,
  verify all dealer shares, derive group keys, and issue per-validator artifacts.
- Benchmark harness exists under `tests/benches/bls_impl_compare.rs` and has been
  updated to threshold-style combine/verify APIs.

## Threshold Setup Model (Required)

To implement paper Sections 6.4 and 6.5 faithfully, consensus must use threshold key material
for the initial validator set.

### Setup Strategy Decision

- [x] DKG ceremony selected as the setup strategy for threshold key generation.
- [ ] Trusted dealer setup (explicitly not selected for production path).

### Setup Artifacts

- [x] Threshold public key(s) for quorum proof verification.
- [x] Per-validator private share(s), securely provisioned.
- [x] Explicit domain separation for:
  - [x] M-notarization (`2f + 1`)
  - [x] Nullification (`2f + 1`)
  - [x] L-notarization (`n - f`) if separate threshold domain is used

### Operational Constraints

- [ ] Setup must run at genesis / initial validator activation.
- [ ] Reconfiguration path (validator set changes) must be explicitly documented, even if deferred.
- [ ] Secret shares must never be persisted in plaintext.

## Target Architecture

### Dependency Direction

- `consensus` depends on `crypto` for consensus BLS.
- `consensus/src/crypto/aggregated.rs` removed after full migration.
- `consensus/src/crypto/mod.rs` keeps only non-BLS modules (e.g., tx crypto), or is restructured.

### API Ownership

- `crypto/` owns:
  - key and signature types for consensus BLS,
  - sign/verify,
  - aggregate and aggregate-verify,
  - threshold aggregation helpers (where needed),
  - serialization formats for network/storage stability.

### Proof Types

- `MNotarization`, `LNotarization`, `Nullification` remain protocol objects in consensus state.
- Their cryptographic fields are backed by `crypto` crate types.
- Explicit signer set validation and threshold checks are mandatory.

## Migration Phases

## Phase 0: Baseline and Guardrails

### Deliverables

- [ ] Freeze baseline benchmark numbers (as-is ark vs blst report in repo docs). (pending doc/report finalization)
- [ ] Add migration feature flag only if needed for safe incremental rollout.
- [x] Add explicit acceptance tests before refactor (to avoid behavior drift).

### Exit Criteria

- [x] We can detect regressions in vote/m-notarization/l-notarization/nullification flow before crypto changes.

## Phase 1: Threshold Setup Bootstrap

### Deliverables

- [x] Finalize setup strategy (trusted dealer vs DKG) and document trust assumptions. (DKG selected)
- [x] Implement setup artifact format and secure loading path for validator nodes. (`crypto::threshold_setup`)
- [ ] Add startup validation:
  - [x] share is present and parseable for local validator
  - [x] threshold public key matches network config
  - [x] domain tags are valid and non-empty
- [x] Add failure behavior:
  - [x] node refuses consensus start on invalid/missing setup artifacts
  - [x] actionable error messages for operators

### Detailed Implementation Plan (Phase 1)

1. Config and artifact model
- [x] Add `node.threshold_setup.artifact_path` (required when threshold mode is enabled).
- [x] Add `node.threshold_setup.mode` with explicit values:
  - [x] `disabled` (current behavior)
  - [x] `enabled` (requires setup artifact + startup validation)
- [ ] Define artifact schema in `crypto/` for setup/runtime consumption:
  - [x] `validator_id` (`PeerId`)
  - [x] `epoch` / `validator_set_id`
  - [x] `group_public_key` (compressed)
  - [x] local `secret_share` (encoded, non-plaintext at rest requirement documented)
  - [x] threshold parameters (`n`, `f`, `m_threshold=2f+1`, `l_threshold=n-f`)
  - [x] domain tags (`m_not`, `nullify`, optional `l_not`)
- [x] Add deterministic serialization/deserialization for artifact format.

2. `crypto/` setup/runtime APIs
- [x] Add setup loader API in `crypto`:
  - [x] parse artifact
  - [x] structural validation (`n`, `f`, thresholds, domain tags)
  - [x] key material decoding/validation
- [ ] Add runtime signer/verifier context type in `crypto`:
  - [x] owns local share + group key + domain tags
  - [x] exposes typed methods for partial sign per domain
  - [x] exposes typed threshold verify helpers
- [ ] Add explicit error enum for setup failures (parse, mismatch, missing fields, invalid thresholds).

3. Consensus startup integration
- [x] Wire artifact loading into node startup before consensus engine creation.
- [ ] On startup, verify:
  - [x] local validator has exactly one share for current validator set
  - [x] local `PeerId` matches configured replica identity
  - [x] artifact `n` and `f` match consensus compile/runtime parameters
  - [x] artifact group key matches network config expectation
  - [x] all required domain tags exist and are non-empty
- [x] Refuse to start consensus when validation fails; return actionable operator error.

4. Runtime usage boundaries
- [x] Ensure consensus manager receives signer context from `crypto` (not raw secret key only).
- [x] Restrict threshold-signing code paths to runtime context (no ad-hoc key parsing in hot path).
- [ ] Keep all artifact parsing out of per-message handlers (startup only).

5. Security and operational constraints
- [ ] Document required filesystem permissions for setup artifact.
- [ ] Add explicit guardrail: artifact must not be world-readable.
- [ ] Ensure logs never print secret share bytes.
- [ ] Add key rotation/reconfiguration note (deferred implementation) with hard failure on set mismatch.

6. Tests for Phase 1
- [x] Unit tests (`crypto`):
  - [x] artifact parse success
  - [x] malformed/partial artifact rejection
  - [x] threshold parameter mismatch rejection
  - [x] empty/duplicate domain tag rejection
- [ ] Integration tests (`consensus`/`node`):
  - [x] startup succeeds with valid artifact
  - [x] startup fails with missing artifact
  - [x] startup fails with wrong `PeerId`
  - [x] startup fails with group key mismatch
  - [x] startup fails with threshold mismatch
- [x] Regression test: when `threshold_mode=disabled`, current non-setup behavior remains unchanged.

7. Rollout sequence
- [x] Phase 1A: introduce DKG core primitives in `crypto` (no runtime wiring yet).
- [x] Phase 1A.1: introduce schema + loader behind `threshold_mode=enabled` without enabling by default.
- [ ] Phase 1B: wire startup validation and failure behavior.
- [ ] Phase 1C: switch local/dev configs to enabled mode for end-to-end verification.
- [ ] Phase 1D: remove temporary compatibility hooks once all environments use setup artifacts.

### Phase 1B Scope and Status

1. Startup validation hardening
- [x] Add explicit network expectation for group public keys (both keysets) in node config:
  - [x] expected `m_nullify` group public key
  - [x] expected `l_notarization` group public key
- [x] Enforce startup mismatch failure between artifact group keys and configured expected keys.
- [ ] Enforce validator-set ID policy:
  - [x] when `validator_set_id` expectation is configured, mismatch is fatal
  - [ ] when omitted, log warning and continue (temporary compatibility)
- [ ] Add artifact file guardrails:
  - [x] fail if artifact path is missing or not readable
  - [x] fail if file permissions are too permissive (non-owner-readable/writable policy, platform-aware, unix)

2. Error model and operator UX
- [x] Introduce typed setup validation errors in `crypto` (replace generic `anyhow` for setup API boundary).
- [x] Preserve actionable operator messages at node startup with root-cause context.

3. Test completion for Phase 1 bootstrap
- [x] `crypto` tests:
  - [x] malformed/partial artifact rejection coverage
  - [x] group key decode mismatch scenarios
- [x] `node` startup validation tests (implemented in node test module):
  - [x] startup succeeds with valid enabled setup
  - [x] startup fails with missing artifact
  - [x] startup fails with wrong `PeerId`
  - [x] startup fails with group key mismatch
  - [x] startup fails with threshold mismatch
  - [x] startup succeeds unchanged when `threshold_mode=disabled`

4. Documentation and config examples
- [ ] Add threshold setup example block to node config docs:
  - [ ] `mode`, `artifact_path`, `validator_set_id`
  - [ ] expected group key fields for both keysets
- [ ] Document artifact operational requirements (storage path, permissions, secret handling).

5. Dedicated bootstrap service scaffolding
- [x] Add new `bootstrap-rpc` workspace crate for ceremony coordination.
- [x] Add proto + tonic service skeleton (`RegisterParticipant`, `SubmitCommitments`,
  `SubmitShares`, `FinalizeCeremony`, `FetchArtifact`).
- [x] Wire network-driven DKG execution in finalize path using submitted commitments/shares.
- [x] Finalize path verifies all shares against dealer commitments before artifact issuance.
- [x] Integrate node startup bootstrap client flow:
  - [x] register participant
  - [x] submit local dealer commitments/shares for both keysets
  - [x] optional finalize attempt + artifact polling fetch
  - [x] atomic artifact write before startup validation
  - [x] populate expected group keys from bootstrap fetch when absent in config

### Phase 1B Exit Criteria

- [ ] Node startup performs complete threshold setup validation (identity, thresholds, domains, expected group keys, validator set id, file policy).
- [ ] Integration tests cover startup success/failure matrix.
- [ ] Disabled mode path remains behaviorally unchanged.

### Exit Criteria

- [ ] A validator node can boot with threshold share material and expose readiness for consensus signing.

## Phase 2: Introduce Consensus BLS API in `crypto/`

### Deliverables

- [x] Add `crypto::consensus_bls` module with stable public API.
- [ ] Include types:
  - [x] `SecretKey`
  - [x] `PublicKey`
  - [x] `Signature`
  - [x] `PeerId`
  - [ ] `ThresholdPartialSignature`
  - [ ] `ThresholdProof`
- [ ] Include operations:
  - [x] partial sign (threshold share)
  - [x] verify
  - [x] combine partial signatures to threshold proof
  - [x] verify threshold proof
  - [x] deterministic encode/decode for network/storage
- [ ] Add unit tests for:
  - [x] sign/verify correctness
  - [x] wrong message rejection
  - [x] wrong signer-set rejection
  - [x] duplicate signer rejection
  - [x] deterministic serialization roundtrip

### Exit Criteria

- [x] Consensus can import this module without using ark BLS types.

## Phase 3: Migrate Consensus State Types

### Files

- `consensus/src/state/notarizations.rs`
- `consensus/src/state/nullify.rs`
- related storage conversions and tests

### Deliverables

- [x] Replace ark-backed BLS types with `crypto::consensus_bls` types.
- [ ] Keep fields and protocol semantics unchanged where possible.
- [ ] Validate signer threshold constraints:
  - [x] M proof requires `2f + 1`
  - [x] L proof requires `n - f`
  - [x] Nullification requires `2f + 1`
- [x] Validate signer uniqueness before proof acceptance.
- [ ] Ensure peer ID to pubkey mapping checks are explicit and non-panicking. (mostly done in runtime paths; continue cleanup outside critical handlers)

### Exit Criteria

- [x] State object serialization/deserialization still passes roundtrip tests.
- [x] No ark BLS import remains in these state files.

## Phase 4: Migrate Manager and Runtime Paths

### Files

- `consensus/src/consensus_manager/utils.rs`
- `consensus/src/consensus_manager/view_context.rs`
- `consensus/src/consensus_manager/view_manager.rs`
- `consensus/src/consensus_manager/state_machine.rs`

### Deliverables

- [x] Replace aggregation/verification calls with `crypto` API.
- [ ] Remove any assumptions that can panic on missing peer keys. (runtime handlers hardened; continue full-file cleanup)
- [x] Enforce deterministic signer ordering when forming proofs.
- [x] Ensure duplicate/zero signer IDs are rejected before broadcast/storage.
- [x] Preserve existing view progression semantics.

### Exit Criteria

- [x] Consensus integration tests pass for normal and adversarial flows.
- [x] No behavior regression in M/L/nullification processing.

## Section 6.4 Completion Checklist

This checklist is the acceptance gate for claiming Minimmit Section 6.4 is fully implemented.

### A. Runtime Enforcement (No Legacy Path)

- [x] Remove production full-signature fallback from consensus hot path handlers.
  - Test-only compatibility fallback remains under `#[cfg(test)]`.
- [x] Require threshold setup artifacts for validator startup in production mode.
- [x] Fail startup if threshold domains, share verification keys, thresholds, or group keys are missing.
- [x] Ensure disabled/compatibility mode is explicitly non-production and documented.
  - `ValidatorNode::from_config` now rejects `threshold_setup.mode != enabled` in non-test builds.

### B. Dual-Threshold Semantics

- [x] Maintain two independent keysets:
  - [x] `2f + 1` threshold for `M-notarization` and `nullification`.
  - [x] `n - f` threshold for `L-notarization`.
- [x] Ensure each vote carries two partial signatures (M-domain and L-domain).
- [x] Verify both partial signatures before vote acceptance/storage.
- [x] Ensure quorum proof builders reject mismatched threshold/keyset usage.

### C. Quorum Proof Wire/Storage Rules

- [x] Use constant-size threshold proofs for M-notarization and nullification propagation.
- [x] Keep direct `n - f` vote collection as the finalization trigger (or explicitly implement and validate L-proof forwarding if adopted).
- [x] Keep deterministic ordering for signer metadata in proof construction and persistence.
- [x] Ensure serialized proof data is stable across nodes and restarts.

### D. Indexing and Membership Safety

- [x] Use participant indices (`1..=n`) for interpolation/combination everywhere (never `PeerId` as interpolation coordinate).
- [x] Enforce signer index uniqueness and valid range before proof combine/verify.
- [x] Enforce signer membership in current validator set before acceptance.
- [x] Confirm leader selection and protocol identity mapping remain consistent with configured validator-set indexing.
  - `PeerSet::with_indices` now orders leader-selection peer list by participant index.

### E. Bootstrap / DKG Operational Completion

- [x] Complete network-driven bootstrap ceremony flow for validators:
  - [x] register participant
  - [x] submit commitments
  - [x] submit shares
  - [x] finalize ceremony
  - [x] fetch artifact
- [x] Persist artifact atomically and bind to `validator_set_id`.
- [x] Validate artifact against expected group keys and threshold parameters on startup.
- [ ] Define and test validator set rotation/reconfiguration behavior.

### F. Test and Adversarial Coverage

- [ ] Add adversarial tests for:
  - [ ] wrong domain
  - [ ] wrong signer index mapping
  - [ ] duplicate signer indices
  - [ ] mixed keyset/domain signatures
  - [ ] insufficient threshold cardinality
- [ ] Add threshold-enabled end-to-end consensus tests covering normal and faulty leader flows.
- [ ] Add fail-closed tests for malformed network/storage inputs.
- [ ] Ensure existing consensus scenarios pass unchanged (except intentional threshold-specific assertions).

### G. Exit Criteria for Section 6.4

- [x] Consensus hot path is explicitly threshold-signature based for M, nullification, and L voting semantics.
- [x] All production validator nodes can boot and run with validated threshold artifacts.
- [x] No legacy aggregate-signature shim remains on consensus critical path.
- [ ] Benchmark and correctness suites pass with threshold mode enabled. (correctness/lint green; benchmark publication pending)

## Phase 5: Implement Section 6.5 Compressed Nullifications

### Deliverables

- [ ] Add new message type:
  - [ ] `CompressedNullificationRange { start_view, end_view, proof }`
- [ ] Add validation rules:
  - [ ] view range monotonic and bounded
  - [ ] proof domain separation binds to `(start_view, end_view)`
  - [ ] signer threshold semantics and membership checks
- [ ] Add state-machine handling:
  - [ ] prefer compressed range during recovery
  - [ ] fallback to per-view nullifications for compatibility
- [ ] Add tests:
  - [ ] honest compressed range recovery
  - [ ] malformed range rejection
  - [ ] invalid proof rejection
  - [ ] replay protection semantics

### Exit Criteria

- [ ] Recovery from long asynchrony no longer requires per-view nullification flooding.

## Phase 6: Cleanup and Removal

### Deliverables

- [ ] Remove `consensus/src/crypto/aggregated.rs`. (currently re-export shim)
- [x] Remove ark BLS deps from `consensus/Cargo.toml`.
- [ ] Update docs and architecture references.
- [ ] Ensure no dead code paths remain.

### Exit Criteria

- [ ] Consensus BLS path is exclusively sourced from `crypto/`. (functionally yes, shim still present)

## Correctness Requirements (Must Hold)

- [ ] One vote per `(view, peer_id)`.
- [x] M/L/nullification thresholds are checked before acceptance.
- [x] Signer IDs are unique and members of validator set.
- [ ] Hash/domain for signed messages is deterministic and stable.
- [ ] No panics from malformed network inputs. (core runtime handlers hardened; continue wider audit)
- [x] Threshold proof verification fails closed on malformed share/proof inputs.

## Performance Requirements

- [ ] Pre/post benchmark table for:
  - [ ] partial sign
  - [ ] verify
  - [ ] threshold proof combine
  - [ ] threshold proof verify
  - [ ] M/L/nullification pipeline latency
- [ ] No material throughput regression in normal-case consensus runs.
- [ ] Improved recovery behavior in asynchronous nullification-heavy scenarios after compressed ranges.

## Testing Matrix

### Unit

- [x] Crypto primitives and serialization.
- [x] Proof builder/validator edge cases.

### Integration

- [ ] M progression with missing block recovery.
- [ ] L finalization with delayed votes.
- [ ] Nullification cascade and range compression flows.

### Property

- [ ] Threshold proof verification equivalence to accepted quorum share sets.
- [ ] Deterministic proof construction under unordered input sets.

### Regression

- [ ] Existing e2e consensus scenarios pass without behavior regressions. (pending full e2e pass)

## Risks and Mitigations

### Risk: Semantic mismatch between existing aggregate flow and threshold expectations

Mitigation:
- Make threshold setup and threshold proof path mandatory from early phases.
- Gate rollout behind strict compatibility tests before removing old path.

### Risk: Serialization incompatibility

Mitigation:
- Add explicit compatibility tests for stored notarization/nullification formats.
- Introduce versioned encoding only if breaking change is unavoidable.

### Risk: View progression regressions under adversarial traffic

Mitigation:
- Add targeted tests for equivocation, delayed messages, and range nullification paths.

## Work Breakdown and Tracking

## Branch

- Active branch: `feat/ja/bls-aggregation-consensus`

## Progress Checklist

- [x] Branch created and checked out.
- [ ] Phase 0 complete
- [ ] Phase 1 complete
- [x] Phase 2 complete
- [ ] Phase 3 complete
- [ ] Phase 4 complete
- [ ] Phase 5 complete
- [ ] Phase 6 complete

## Session Log

Use this section to append progress updates.

- 2026-02-28:
  - Created migration plan document.
  - Baseline as-is benchmarks and initial BLST hardening already present in working tree.
  - Implemented `crypto::consensus_bls` as consensus-facing API.
  - Migrated consensus aggregation/verification paths to threshold semantics
    (Lagrange interpolation + signer IDs).
  - Removed ark BLS deps from consensus crypto path and deleted consensus conversions module.
  - Added shared crypto internals to reduce duplication:
    `bls/constants.rs`, `bls/ops.rs`, `threshold_math.rs`.
  - Refactored adapters to use shared internals; removed duplicated sign/verify/combine glue.
  - Added crate README for `crypto` documenting runtime/setup scope and module boundaries.
  - Expanded `crypto` unit tests across ops, adapters, threshold math, scalar, polynomial.
  - Verified:
    - `cargo test -p crypto` (passing)
    - `cargo check -p crypto -p consensus -p grpc-client -p rpc -p tests --all-targets` (passing)
    - `cargo clippy --all-targets --all-features -- -D warnings` (passing)
- 2026-03-01:
  - Added bootstrap artifact validator participant map (`peer_id -> participant_index`) and
    per-keyset threshold share verification keys for all validators.
  - Wired node startup to build consensus `PeerSet` from threshold setup artifact, including:
    explicit participant indices, share verification keys, and domain tags.
  - Wired round-robin leader manager to consume explicit participant indices.
  - Removed legacy threshold signing shim from consensus hot-path and switched to
    domain-separated threshold partial signing for M, nullify, and L domains.
  - Extended vote structure to carry dual threshold partial signatures (M + L) and switched
    L-notarization aggregation to use L-domain partial signatures.
  - Updated consensus verification paths to use threshold share verification keys and domain
    separation for M-notarization, nullification, and L-notarization.
  - Added reusable threshold test-material generator in `tests/src/threshold_support.rs`
    (in-memory dual DKG, participant index mapping, artifact-backed signer contexts).
  - Wired `tests/src/e2e_consensus/scenarios.rs` happy-path fixture to support threshold mode
    via `ConsensusEngine::new_with_peers(...)` and added ignored
    `test_multi_node_happy_path_threshold_mode`.
  - Wired `tests/src/gossip/helpers.rs` to optionally construct consensus nodes with threshold
    signer context + threshold-aware peer set while preserving legacy default behavior.
  - Verified:
    - `cargo test -p tests --no-run` (passing)
    - `cargo test -p tests` (passing; ignored integration tests compiled)
    - `cargo clippy -p tests --all-targets --all-features -- -D warnings` (passing)
