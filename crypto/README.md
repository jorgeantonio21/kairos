# crypto

`crypto` provides BLS12-381 primitives used by consensus runtime and validator setup.

## Scope

This crate has two explicit scopes:

1. Runtime consensus crypto API
- Deterministic wire-friendly key/signature types
- Single-sign and threshold-proof verification
- Threshold combination by signer/share IDs (Lagrange interpolation)

2. Setup-time threshold crypto
- Shamir secret sharing
- Trusted setup utilities to produce key shares
- Partial signing and threshold reconstruction helpers

## Module Map

- `src/consensus_bls.rs`
  - Consensus-facing types and API (`BlsSecretKey`, `BlsPublicKey`, `BlsSignature`, `AggregatedSignature`)
  - Uses shared internals for signing/verification/interpolation

- `src/bls/constants.rs`
  - Shared constants (DST, key/signature sizes, scalar bit size, peer-id constants)

- `src/bls/ops.rs`
  - Shared low-level BLS operations
  - Source of truth for sign/verify/key-derive and weighted combination

- `src/threshold_math.rs`
  - Shared Lagrange interpolation and signer/share ID validation

- `src/scalar.rs`
  - Scalar field wrapper and arithmetic for Fr

- `src/polynomial.rs`
  - Polynomial utilities used by Shamir sharing

- `src/threshold.rs`
  - Setup-oriented threshold workflow (`ThresholdBLS`, `ShamirSharing`, `KeyShare`, `PartialSignature`)

## Boundary Rules

- `src/bls/ops.rs` owns reusable cryptographic operations.
- `src/threshold_math.rs` owns interpolation/ID validation.
- Adapter modules (`consensus_bls`, `threshold`) should orchestrate and convert types, not duplicate crypto logic.

## Semantics

- Threshold combination uses Lagrange coefficients derived from signer/share IDs.
- Signer/share IDs must be unique and non-zero.
- Verification is fail-closed on malformed inputs.
- Runtime types remain stable byte wrappers for storage/network compatibility.

## What This Crate Does Not Cover

- DKG ceremony/orchestration
- Validator reconfiguration protocol
- Consensus protocol logic itself

## Testing

Run all unit tests for this crate:

```bash
cargo test -p crypto
```

Run full workspace compile checks for dependents:

```bash
cargo check -p crypto -p consensus -p grpc-client -p rpc -p tests --all-targets
```

Coverage (if toolchain has `llvm-tools-preview` installed):

```bash
cargo llvm-cov -p crypto --lib --summary-only
```

## Coverage Status (current session)

- Unit tests pass for all modules in `crypto`.
- We attempted to run `cargo llvm-cov`, but this environment failed installing `llvm-tools-preview`, so we do **not** have a measured line/branch coverage percentage yet.
