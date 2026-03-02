//! Shared constants for BLS12-381 threshold signing in this crate.
//!
//! ## Mathematical Background
//!
//! ### BLS12-381 Curve
//! BLS12-381 is a pairing-friendly elliptic curve with:
//! - Base field modulus `p`: A 381-bit prime
//! - Scalar field `Fr`: 255-bit prime (order of the subgroups)
//! - Security level: ~128 bits
//!
//! The curve has two groups of prime order `r`:
//! - **G1**: Points on the curve `E(Fp)` -- smaller, faster
//! - **G2**: Points on the twist `E'(Fp²)` -- larger, but needed for aggregation
//!
//! ### Signature Scheme
//! BLS signatures use the **Boneh-Lynn-Shacham (BLS)** short signature scheme:
//! ```math
//! \sigma = sk \cdot H(m)
//! ```
//! where `sk` is the secret key, `H` is a hash-to-curve function, and `m` is the message.
//!
//! Verification checks the pairing equality:
//! ```math
//! e(\sigma, g_2) = e(H(m), pk)
//! ```
//!
//! ### Threshold Signatures
//! In threshold BLS, the secret key is split into `n` shares such that:
//! - Any `t` shares can produce a valid partial signature
//! - Fewer than `t` shares reveal nothing about the secret
//!
//! Partial signatures are combined using **Lagrange coefficients**:
//! ```math
//! \sigma = \sum_{i \in S} \lambda_i \cdot \sigma_i, \quad \lambda_i = \prod_{j \in S, j \neq i} \frac{x_j}{x_j - x_i}
//! ```
//! where `S` is the set of `t` signers.

/// Domain separation tag used for all BLS signatures in this repository.
///
/// This must remain stable across all nodes in a network. Changing it breaks
/// compatibility with existing signatures.
///
/// ## DST Format Breakdown
///
/// The DST string follows the [IETF BLS signature draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/):
///
/// | Component | Value | Meaning |
/// |-----------|-------|---------|
/// | Curve | BLS12-381 | The underlying elliptic curve |
/// | Encoding | XMD | expand_message_xmd (deterministic) |
/// | Hash | SHA-256 | Hash function for XMD |
/// | Hash-to-curve | SSWU | Shallue-van de Woestijne-Urbano |
/// | Mode | RO | Random oracle (hash-to-field) |
/// | Group | G1 | Signatures in G1 (smaller, faster) |
/// | Trailer | NUL | No trailer byte |
///
/// ## Why G1 for Signatures?
///
/// - Signatures are 48 bytes (G1) vs 96 bytes (G2) -- **2x smaller**
/// - G1 operations are faster due to smaller field arithmetic
/// - Public keys still use G2 (96 bytes) for compatibility with aggregation
///
/// ## Security Note
///
/// The trailing underscore marks this as a draft version. When upgrading to
/// a final RFC, the DST will change, requiring a hard fork.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

/// Compressed byte length of a BLS12-381 G2 public key.
///
/// ## Mathematical Explanation
///
/// A BLS12-381 G2 point has coordinates `(x, y)` in `Fp²` (field of size `p²`).
/// Each element of `Fp²` requires 2 × 381 bits = 762 bits = 96 bytes (with 6 padding bits).
///
/// The **compressed format** stores only the x-coordinate plus one bit for y-sign:
/// - 381 bits for x (48 bytes)
/// - 1 bit for y parity (embedded in the 384th bit position)
/// - 6 unused bits for alignment
///
/// Total: **48 bytes** for one Fp² element, but convention stores the full encoding.
///
/// ## Why G2 for Public Keys?
///
/// - G2 points are required for the **check pairing** `e(P, Q)` where `P ∈ G1`, `Q ∈ G2`
/// - BLS aggregation uses G2 public keys in the verification equation
/// - Standard practice: sign in G1 (smaller), verify with G2 public keys
pub const BLS_PUBLIC_KEY_BYTES: usize = 96;

/// Compressed byte length of a BLS12-381 G1 signature.
///
/// ## Mathematical Explanation
///
/// A BLS12-381 G1 point has coordinates `(x, y)` in `Fp` (prime field).
/// - x: 381 bits → 48 bytes
/// - y: 381 bits → 48 bytes
/// - Compression: Store x (48 bytes) + 1 bit for y parity = **48 bytes**
///
/// ## Compression Details
///
/// The compressed representation uses the fact that for a valid point:
/// ```math
/// y = \pm\sqrt{x^3 + 4}
/// ```
///
/// Only the x-coordinate and the sign of y are needed to reconstruct y.
/// This halves the storage from 96 bytes (uncompressed) to 48 bytes.
pub const BLS_SIGNATURE_BYTES: usize = 48;

/// Byte length of a serialized BLS secret key scalar.
///
/// ## Mathematical Explanation
///
/// The secret key is a random scalar in the BLS12-381 scalar field `Fr`.
/// The order of `Fr` is:
///
/// ```math
/// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
/// ```
///
/// This is a 255-bit prime (slightly less than 256 bits).
///
/// A scalar is stored as 32 bytes (256 bits) with:
/// - 32 bytes = 256 bits > 255-bit max value
/// - The top bit is always 0 (ensured by the generation algorithm)
pub const BLS_SECRET_KEY_BYTES: usize = 32;

/// Bit length used for scalar multiplication in BLST operations.
///
/// For BLS12-381 Fr this is 255 bits.
///
/// ## Mathematical Explanation
///
/// The scalar field `Fr` has order `r` (the prime above), which requires 255 bits to represent.
/// Using 255-bit arithmetic (instead of 256-bit) provides:
///
/// - **Efficiency**: Slightly faster modular arithmetic
/// - **Security**: No timing leaks from the unused bit
/// - **Correctness**: Values are always reduced modulo `r`
///
/// This is specific to BLS12-381. Other curves (e.g., BN254) have different bit lengths.
pub const SCALAR_BITS: usize = 255;

/// Number of bytes used to derive `PeerId` from a BLAKE3 hash prefix.
///
/// ## Design Rationale
///
/// 8 bytes (64 bits) provides:
/// - **2^64 possible peer IDs**: Sufficient for any realistic network
/// - **Low collision probability**: ~1 in 2^32 for 100k nodes (birthday bound)
/// - **Compact storage**: 8 bytes vs 32 bytes for full hash
///
/// ## Derivation Process
///
/// ```ignore
/// use blake3::hash;
/// let full_hash = hash(public_key_bytes);
/// let peer_id = u64::from_le_bytes(full_hash.as_bytes()[0..8]);
/// ```
///
/// The first 8 bytes of the BLAKE3 hash form the peer identifier.
pub const PEER_ID_BYTES: usize = 8;

/// Sentinel invalid peer identifier for threshold signer sets.
///
/// ## Purpose
///
/// Used as a placeholder or "null" value in data structures where:
/// - A peer ID is required but no peer is assigned
/// - Initialization state before real peer IDs are set
///
/// The value `0` is chosen because:
/// - It's outside the valid participant range `[1, n]`
/// - It provides a clear "not set" semantic
/// - It maps naturally to Rust's `Option::None` pattern
///
/// ## Usage Example
///
/// ```ignore
/// let mut peer_ids = vec![INVALID_PEER_ID; n];
/// // Fill in real peer IDs...
/// assert!(peer_ids.contains(&INVALID_PEER_ID)); // If not all filled
/// ```
pub const INVALID_PEER_ID: u64 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bls_public_key_bytes_length() {
        assert_eq!(BLS_PUBLIC_KEY_BYTES, 96);
    }

    #[test]
    fn bls_signature_bytes_length() {
        assert_eq!(BLS_SIGNATURE_BYTES, 48);
    }

    #[test]
    fn bls_secret_key_bytes_length() {
        assert_eq!(BLS_SECRET_KEY_BYTES, 32);
    }

    #[test]
    fn scalar_bits_is_255() {
        assert_eq!(SCALAR_BITS, 255);
    }

    #[test]
    fn peer_id_bytes_is_8() {
        assert_eq!(PEER_ID_BYTES, 8);
    }

    #[test]
    fn invalid_peer_id_is_zero() {
        assert_eq!(INVALID_PEER_ID, 0);
    }
}
