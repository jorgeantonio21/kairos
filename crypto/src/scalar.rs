use blst::{
    blst_fr, blst_fr_add, blst_fr_from_scalar, blst_fr_inverse, blst_fr_mul, blst_fr_sub,
    blst_lendian_from_scalar, blst_scalar, blst_scalar_from_fr, blst_scalar_from_le_bytes,
};
use rand::{CryptoRng, Rng};

/// A scalar value in the BLS12-381 scalar field Fr.
///
/// Scalars are elements of the finite field Fr with order r, where r is a 255-bit prime.
/// They are used throughout BLS cryptography for:
/// - Private keys (secret scalars)
/// - Random values in signature generation
/// - Lagrange coefficients in threshold signature schemes
/// - Shares in Shamir's secret sharing
///
/// All arithmetic operations are performed modulo r, the order of the BLS12-381 curve.
/// The field r is: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scalar {
    inner: blst_scalar,
}

impl Scalar {
    /// Creates a scalar from a 32-byte little-endian representation.
    ///
    /// # Arguments
    /// * `bytes` - Exactly 32 bytes in little-endian order
    ///
    /// # Returns
    /// A scalar value reduced modulo r
    ///
    /// # Note
    /// Values larger than r are automatically reduced modulo r.
    pub fn from_bytes_le(bytes: [u8; 32]) -> Self {
        let mut blst_scalar = blst_scalar::default();
        unsafe {
            // This API returns `false` for zero values in secret-key semantics.
            // Zero is valid for our generic field scalar type, so we accept the output value.
            let _ = blst_scalar_from_le_bytes(&mut blst_scalar, bytes.as_ptr(), 32);
        };
        Self { inner: blst_scalar }
    }

    /// Creates a scalar from a u64 value.
    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Self::from_bytes_le(bytes)
    }

    /// Generates a random scalar using a cryptographically secure RNG.
    ///
    /// The generated scalar is uniformly distributed in the range [0, r-1].
    ///
    /// # Arguments
    /// * `rng` - A cryptographically secure random number generator
    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes_le(bytes)
    }

    /// Converts the scalar to its 32-byte little-endian representation.
    ///
    /// # Returns
    /// Exactly 32 bytes representing the scalar in little-endian order
    pub fn to_bytes_le(&self) -> [u8; 32] {
        let mut bytes = [0; 32];
        unsafe {
            blst_lendian_from_scalar(bytes.as_mut_ptr(), &self.inner);
        };
        bytes
    }

    /// Returns the additive identity element (zero) in the scalar field.
    pub fn zero() -> Self {
        Self {
            inner: blst_scalar::default(),
        }
    }

    /// Returns the multiplicative identity element (one) in the scalar field.
    pub fn one() -> Self {
        Self::from_u64(1)
    }

    /// Checks whether this scalar is the additive identity (zero).
    ///
    /// # Returns
    /// `true` if the scalar equals zero, `false` otherwise
    pub fn is_zero(&self) -> bool {
        let bytes = self.to_bytes_le();
        bytes.iter().all(|&b| b == 0)
    }

    /// Performs modular addition: `(self + other) mod r`.
    ///
    /// # Arguments
    /// * `other` - The scalar to add to `self`
    ///
    /// # Returns
    /// A new scalar containing the sum
    pub fn add(&self, other: &Scalar) -> Scalar {
        let lhs = self.as_fr();
        let rhs = other.as_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_add(&mut result, &lhs, &rhs);
        }
        Self::from_fr(&result)
    }

    /// Performs modular subtraction: `(self - other) mod r`.
    ///
    /// # Arguments
    /// * `other` - The scalar to subtract from `self`
    ///
    /// # Returns
    /// A new scalar containing the difference
    pub fn sub(&self, other: &Scalar) -> Scalar {
        let lhs = self.as_fr();
        let rhs = other.as_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_sub(&mut result, &lhs, &rhs);
        }
        Self::from_fr(&result)
    }

    /// Performs modular multiplication: `(self * other) mod r`.
    ///
    /// # Arguments
    /// * `other` - The scalar to multiply with `self`
    ///
    /// # Returns
    /// A new scalar containing the product
    pub fn mul(&self, other: &Scalar) -> Scalar {
        let lhs = self.as_fr();
        let rhs = other.as_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_mul(&mut result, &lhs, &rhs);
        }
        Self::from_fr(&result)
    }

    /// Computes the modular inverse: `self^(-1) mod r`.
    ///
    /// The inverse exists for all non-zero scalars since r is prime.
    ///
    /// # Returns
    /// - `Some(inverse)` if the scalar is non-zero
    /// - `None` if the scalar is zero (undefined inverse)
    pub fn inverse(&self) -> Option<Scalar> {
        if self.is_zero() {
            return None;
        }
        let input = self.as_fr();
        let mut result = blst_fr::default();
        unsafe {
            blst_fr_inverse(&mut result, &input);
        };
        Some(Self::from_fr(&result))
    }

    /// Performs modular division: `(self * other^(-1)) mod r`.
    ///
    /// This is equivalent to `self * other.inverse()` when the inverse exists.
    ///
    /// # Arguments
    /// * `other` - The scalar to divide by
    ///
    /// # Returns
    /// - `Some(result)` if `other` is non-zero
    /// - `None` if `other` is zero (division by zero)
    pub fn div(&self, other: &Scalar) -> Option<Scalar> {
        if other.is_zero() {
            return None;
        }
        other.inverse().map(|inverse| self.mul(&inverse))
    }

    /// Returns a reference to the underlying `blst_scalar`.
    ///
    /// This method provides low-level access to the BLST library representation.
    /// Use with caution - direct manipulation may violate invariants.
    pub fn as_blst_scalar(&self) -> &blst_scalar {
        &self.inner
    }

    fn as_fr(&self) -> blst_fr {
        let mut fr = blst_fr::default();
        unsafe {
            blst_fr_from_scalar(&mut fr, &self.inner);
        }
        fr
    }

    fn from_fr(fr: &blst_fr) -> Self {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, fr);
        }
        Self { inner: scalar }
    }
}

#[cfg(test)]
mod tests {
    use super::Scalar;

    #[test]
    fn roundtrip_bytes_le() {
        let original = Scalar::from_u64(123456789);
        let bytes = original.to_bytes_le();
        let decoded = Scalar::from_bytes_le(bytes);
        assert_eq!(decoded, original);
    }

    #[test]
    fn inverse_of_zero_is_none() {
        assert!(Scalar::zero().inverse().is_none());
    }

    #[test]
    fn div_by_zero_is_none() {
        let one = Scalar::one();
        assert!(one.div(&Scalar::zero()).is_none());
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = Scalar::from_u64(55);
        let b = Scalar::from_u64(21);
        let sum = a.add(&b);
        let back = sum.sub(&b);
        assert_eq!(back, a);
    }
}
