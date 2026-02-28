//! Shared constants for BLS12-381 threshold signing in this crate.
//!
//! Scope:
//! - Runtime consensus verification/signing (`consensus_bls`)
//! - Setup-time threshold key workflows (`threshold`)
//! - Internal low-level BLST point operations (`bls::ops`)

/// Domain separation tag used for all BLS signatures in this repository.
///
/// This must remain stable across all nodes in a network. Changing it breaks
/// compatibility with existing signatures.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Compressed byte length of a BLS12-381 G2 public key.
pub const BLS_PUBLIC_KEY_BYTES: usize = 96;

/// Compressed byte length of a BLS12-381 G1 signature.
pub const BLS_SIGNATURE_BYTES: usize = 48;

/// Byte length of a serialized BLS secret key scalar.
pub const BLS_SECRET_KEY_BYTES: usize = 32;

/// Bit length used for scalar multiplication in BLST operations.
///
/// For BLS12-381 Fr this is 255 bits.
pub const SCALAR_BITS: usize = 255;

/// Number of bytes used to derive `PeerId` from a BLAKE3 hash prefix.
pub const PEER_ID_BYTES: usize = 8;

/// Sentinel invalid peer identifier for threshold signer sets.
pub const INVALID_PEER_ID: u64 = 0;
