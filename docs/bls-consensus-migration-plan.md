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

- Consensus currently uses ark-based BLS in:
  - `consensus/src/crypto/aggregated.rs`
  - `consensus/src/state/notarizations.rs`
  - `consensus/src/state/nullify.rs`
- Quorum proofs currently store:
  - aggregated signature + signer IDs (not threshold key shares).
- `crypto/` now has hardened blst threshold paths and tests.
- Benchmark harness exists for as-is comparison under `tests/benches/bls_impl_compare.rs`.

## Threshold Setup Model (Required)

To implement paper Sections 6.4 and 6.5 faithfully, consensus must use threshold key material
for the initial validator set.

### Decision Required

- [ ] Choose one setup strategy:
  - [ ] Trusted dealer setup (faster to ship, higher trust assumption)
  - [ ] DKG ceremony (preferred long-term, stronger trust model)

### Setup Artifacts

- [ ] Threshold public key(s) for quorum proof verification.
- [ ] Per-validator private share(s), securely provisioned.
- [ ] Explicit domain separation for:
  - [ ] M-notarization (`2f + 1`)
  - [ ] Nullification (`2f + 1`)
  - [ ] L-notarization (`n - f`) if separate threshold domain is used

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

- [ ] Freeze baseline benchmark numbers (as-is ark vs blst report in repo docs).
- [ ] Add migration feature flag only if needed for safe incremental rollout.
- [ ] Add explicit acceptance tests before refactor (to avoid behavior drift).

### Exit Criteria

- [ ] We can detect regressions in vote/m-notarization/l-notarization/nullification flow before crypto changes.

## Phase 1: Threshold Setup Bootstrap

### Deliverables

- [ ] Finalize setup strategy (trusted dealer vs DKG) and document trust assumptions.
- [ ] Implement setup artifact format and secure loading path for validator nodes.
- [ ] Add startup validation:
  - [ ] share is present and parseable for local validator
  - [ ] threshold public key matches network config
  - [ ] domain tags are valid and non-empty
- [ ] Add failure behavior:
  - [ ] node refuses consensus start on invalid/missing setup artifacts
  - [ ] actionable error messages for operators

### Exit Criteria

- [ ] A validator node can boot with threshold share material and expose readiness for consensus signing.

## Phase 2: Introduce Consensus BLS API in `crypto/`

### Deliverables

- [ ] Add `crypto::consensus_bls` module with stable public API.
- [ ] Include types:
  - [ ] `SecretKey`
  - [ ] `PublicKey`
  - [ ] `Signature`
  - [ ] `PeerId`
  - [ ] `ThresholdPartialSignature`
  - [ ] `ThresholdProof`
- [ ] Include operations:
  - [ ] partial sign (threshold share)
  - [ ] verify
  - [ ] combine partial signatures to threshold proof
  - [ ] verify threshold proof
  - [ ] deterministic encode/decode for network/storage
- [ ] Add unit tests for:
  - [ ] sign/verify correctness
  - [ ] wrong message rejection
  - [ ] wrong signer-set rejection
  - [ ] duplicate signer rejection
  - [ ] deterministic serialization roundtrip

### Exit Criteria

- [ ] Consensus can import this module without using ark BLS types.

## Phase 3: Migrate Consensus State Types

### Files

- `consensus/src/state/notarizations.rs`
- `consensus/src/state/nullify.rs`
- related storage conversions and tests

### Deliverables

- [ ] Replace ark-backed BLS types with `crypto::consensus_bls` types.
- [ ] Keep fields and protocol semantics unchanged where possible.
- [ ] Validate signer threshold constraints:
  - [ ] M proof requires `2f + 1`
  - [ ] L proof requires `n - f`
  - [ ] Nullification requires `2f + 1`
- [ ] Validate signer uniqueness before proof acceptance.
- [ ] Ensure peer ID to pubkey mapping checks are explicit and non-panicking.

### Exit Criteria

- [ ] State object serialization/deserialization still passes roundtrip tests.
- [ ] No ark BLS import remains in these state files.

## Phase 4: Migrate Manager and Runtime Paths

### Files

- `consensus/src/consensus_manager/utils.rs`
- `consensus/src/consensus_manager/view_context.rs`
- `consensus/src/consensus_manager/view_manager.rs`
- `consensus/src/consensus_manager/state_machine.rs`

### Deliverables

- [ ] Replace aggregation/verification calls with `crypto` API.
- [ ] Remove any assumptions that can panic on missing peer keys.
- [ ] Enforce deterministic signer ordering when forming proofs.
- [ ] Ensure duplicate/zero signer IDs are rejected before broadcast/storage.
- [ ] Preserve existing view progression semantics.

### Exit Criteria

- [ ] Consensus integration tests pass for normal and adversarial flows.
- [ ] No behavior regression in M/L/nullification processing.

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

- [ ] Remove `consensus/src/crypto/aggregated.rs`.
- [ ] Remove ark BLS deps from `consensus/Cargo.toml`.
- [ ] Update docs and architecture references.
- [ ] Ensure no dead code paths remain.

### Exit Criteria

- [ ] Consensus BLS path is exclusively sourced from `crypto/`.

## Correctness Requirements (Must Hold)

- [ ] One vote per `(view, peer_id)`.
- [ ] M/L/nullification thresholds are checked before acceptance.
- [ ] Signer IDs are unique and members of validator set.
- [ ] Hash/domain for signed messages is deterministic and stable.
- [ ] No panics from malformed network inputs.
- [ ] Threshold proof verification fails closed on malformed share/proof inputs.

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

- [ ] Crypto primitives and serialization.
- [ ] Proof builder/validator edge cases.

### Integration

- [ ] M progression with missing block recovery.
- [ ] L finalization with delayed votes.
- [ ] Nullification cascade and range compression flows.

### Property

- [ ] Threshold proof verification equivalence to accepted quorum share sets.
- [ ] Deterministic proof construction under unordered input sets.

### Regression

- [ ] Existing e2e consensus scenarios pass without behavior regressions.

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
- [ ] Phase 2 complete
- [ ] Phase 3 complete
- [ ] Phase 4 complete
- [ ] Phase 5 complete
- [ ] Phase 6 complete

## Session Log

Use this section to append progress updates.

- 2026-02-28:
  - Created migration plan document.
  - Baseline as-is benchmarks and initial BLST hardening already present in working tree.
