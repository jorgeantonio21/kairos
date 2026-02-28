use anyhow::Result;
use blst::min_sig::{PublicKey, Signature};
use rand::{CryptoRng, Rng};

use crate::bls::constants::BLS_SIGNATURE_BYTES;
use crate::bls::ops::{
    combine_signatures_with_lagrange,
    public_key_from_scalar,
    sign_with_scalar,
    verify_signature_bytes,
};
use crate::threshold_math::{lagrange_coefficients_for_peer_ids, lagrange_coefficient_at_zero};
use crate::{polynomial::Polynomial, scalar::Scalar};

/// Share of a secret in Shamir's secret sharing scheme.
/// Each share consists of an x-coordinate (index) and y-coordinate (secret share).
#[derive(Clone, Debug)]
pub struct Share {
    /// The x-coordinate (participant index from 1 to n)
    pub x: Scalar,
    /// The y-coordinate (secret share value)
    pub y: Scalar,
}

/// Shamir's secret sharing scheme for threshold cryptography.
/// Allows splitting a secret into n shares where any t shares can reconstruct the secret.
pub struct ShamirSharing {
    /// Minimum shares needed to reconstruct the secret
    threshold: usize,
    /// Total number of shares to generate
    total_shares: usize,
}

impl ShamirSharing {
    /// Create a new Shamir sharing scheme.
    ///
    /// # Arguments
    /// * `threshold` - Minimum shares needed for reconstruction (t)
    /// * `total_shares` - Total shares to generate (n)
    ///
    /// # Panics
    /// Panics if threshold > total_shares or threshold == 0
    pub fn new(threshold: usize, total_shares: usize) -> Self {
        debug_assert!(threshold > 0 && threshold <= total_shares);
        Self {
            threshold,
            total_shares,
        }
    }

    /// Split a secret into shares using Shamir's scheme.
    /// Creates a random polynomial of degree t-1 with the secret as constant term,
    /// then evaluates at points 1, 2, ..., n to generate shares.
    ///
    /// # Arguments
    /// * `secret` - The secret to split
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// Vector of n shares, any t of which can reconstruct the secret
    pub fn split<R: Rng + CryptoRng>(&self, secret: Scalar, rng: &mut R) -> Vec<Share> {
        // Create polynomial with secret as constant term
        let poly = Polynomial::random(self.threshold - 1, secret, rng);

        // Evaluate at points 1, 2, 3, ..., n
        let mut shares = Vec::with_capacity(self.total_shares);
        for i in 1..=self.total_shares {
            let x = Scalar::from_u64(i as u64);
            let y = poly.evaluate(&x);
            shares.push(Share { x, y });
        }

        shares
    }

    /// Reconstruct secret from threshold shares using Lagrange interpolation.
    /// Combines shares with formula: secret = ∑ y_i × λ_i
    ///
    /// # Arguments
    /// * `shares` - At least t shares to reconstruct from
    ///
    /// # Panics
    /// Panics if fewer than threshold shares provided
    pub fn reconstruct(&self, shares: &[Share]) -> Result<Scalar> {
        debug_assert!(
            shares.len() >= self.threshold,
            "Not enough shares to reconstruct"
        );

        let shares_to_use = &shares[..self.threshold];
        let xs: Vec<Scalar> = shares_to_use.iter().map(|share| share.x.clone()).collect();
        let mut secret = Scalar::zero();

        for (i, share) in shares_to_use.iter().enumerate() {
            let lambda = lagrange_coefficient_at_zero(&xs, i)?;
            let term = share.y.mul(&lambda);
            secret = secret.add(&term);
        }

        Ok(secret)
    }
}

/// Key share for a participant in threshold BLS signature scheme.
/// Contains the participant's secret scalar and corresponding public key.
#[derive(Clone)]
pub struct KeyShare {
    /// Participant identifier
    pub id: u64,
    /// Secret scalar share
    pub secret_scalar: Scalar,
    /// Public key corresponding to secret_scalar
    pub public_key: PublicKey,
}

/// Partial signature from a single participant.
/// Contains the participant ID and their signature share.
#[derive(Clone)]
pub struct PartialSignature {
    /// Participant identifier
    pub id: u64,
    /// Signature share
    pub signature: Signature,
}

/// BLS threshold signature scheme using Shamir's secret sharing.
/// Enables distributed signing where t-out-of-n participants can create a valid signature.
pub struct ThresholdBLS {
    threshold: usize,
    total_participants: usize,
    shamir: ShamirSharing,
}

impl ThresholdBLS {
    /// Create a new threshold BLS scheme.
    ///
    /// # Arguments
    /// * `threshold` - Minimum participants needed for valid signature (t)
    /// * `total_participants` - Total number of participants (n)
    pub fn new(threshold: usize, total_participants: usize) -> Self {
        Self {
            threshold,
            total_participants,
            shamir: ShamirSharing::new(threshold, total_participants),
        }
    }

    /// Convert a scalar (private key) to its corresponding BLS public key.
    ///
    /// Computes PK = scalar × G₂, where G₂ is the generator point of the G₂ group.
    /// This is the standard BLS key derivation: public key is private key times generator.
    ///
    /// # Arguments
    /// * `scalar` - The private key scalar
    ///
    /// # Returns
    /// The corresponding BLS public key, or error if key derivation fails
    ///
    /// # Security
    /// This operation is computationally expensive but secure.
    /// The resulting public key can be safely shared.
    fn scalar_to_public_key(scalar: &Scalar) -> Result<PublicKey> {
        let pk_bytes = public_key_from_scalar(scalar)?;
        PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create public key: {:?}", e))
    }

    /// Generate master keypair and distribute key shares.
    /// Creates a random master secret, derives public key, then splits secret into shares.
    ///
    /// # Arguments
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// Tuple of (master_public_key, key_shares)
    pub fn trusted_setup<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(PublicKey, Vec<KeyShare>)> {
        let master_scalar = Scalar::random(rng);
        let master_pk = Self::scalar_to_public_key(&master_scalar)
            .map_err(|e| anyhow::anyhow!("Failed to create master public key: {:?}", e))?;

        // Create shares using Shamir's Secret Sharing
        let shares = self.shamir.split(master_scalar, rng);

        // Convert shares to KeyShare objects
        let mut key_shares = Vec::with_capacity(self.total_participants);
        for (idx, share) in shares.iter().enumerate() {
            let share_pk = Self::scalar_to_public_key(&share.y)
                .map_err(|e| anyhow::anyhow!("Failed to create share public key: {:?}", e))?;

            key_shares.push(KeyShare {
                id: (idx + 1) as u64,
                secret_scalar: share.y.clone(),
                public_key: share_pk,
            });
        }

        Ok((master_pk, key_shares))
    }

    /// Create a partial signature for a message using a key share.
    ///
    /// # Arguments
    /// * `key_share` - Participant's key share
    /// * `message` - Message to sign
    ///
    /// # Returns
    /// Partial signature that can be combined with others
    pub fn partial_sign(key_share: &KeyShare, message: &[u8]) -> Result<PartialSignature> {
        let sig_bytes = sign_with_scalar(&key_share.secret_scalar, message)?;
        let signature = Signature::from_bytes(&sig_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create signature: {:?}", e))?;
        Ok(PartialSignature {
            id: key_share.id,
            signature,
        })
    }

    /// Aggregate partial signatures into a complete signature.
    /// Uses Lagrange interpolation in the exponent to combine signatures correctly.
    ///
    /// # Arguments
    /// * `partial_signatures` - Exactly t partial signatures to aggregate
    ///
    /// # Returns
    /// Complete BLS signature
    pub fn aggregate(&self, partial_signatures: &[PartialSignature]) -> Result<Signature> {
        if partial_signatures.len() != self.threshold {
            return Err(anyhow::anyhow!(
                "Invalid partial signature count: got {}, expected exactly {}",
                partial_signatures.len(),
                self.threshold
            ));
        }

        let participant_ids: Vec<u64> = partial_signatures.iter().map(|partial| partial.id).collect();
        let lambdas = lagrange_coefficients_for_peer_ids(&participant_ids)?;
        let signatures: Vec<[u8; BLS_SIGNATURE_BYTES]> = partial_signatures
            .iter()
            .map(|partial| partial.signature.to_bytes())
            .collect();
        let final_signature_bytes = combine_signatures_with_lagrange(&signatures, &lambdas)?;
        let final_signature = Signature::from_bytes(&final_signature_bytes).map_err(|e| {
            anyhow::anyhow!(
                "Failed to construct final signature from combined bytes: {:?}",
                e
            )
        })?;

        Ok(final_signature)
    }

    /// Verify a signature against a public key and message.
    ///
    /// # Arguments
    /// * `public_key` - BLS public key
    /// * `message` - Signed message
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// Ok(()) if signature is valid, Error otherwise
    pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<()> {
        let pk_bytes = public_key.to_bytes();
        let sig_bytes = signature.to_bytes();
        verify_signature_bytes(&pk_bytes, message, &sig_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_scalar_arithmetic() {
        let a = Scalar::from_u64(5);
        let b = Scalar::from_u64(3);

        let sum = a.add(&b); // 5 + 3 = 8
        let diff = a.sub(&b); // 5 - 3 = 2
        let prod = a.mul(&b); // 5 * 3 = 15

        println!("Scalar arithmetic test passed");
        assert!(!sum.is_zero());
        assert!(!diff.is_zero());
        assert!(!prod.is_zero());
    }

    #[test]
    fn test_scalar_inverse() {
        let a = Scalar::from_u64(5);
        let a_inv = a.inverse().expect("Should have inverse");

        let product = a.mul(&a_inv);
        let one = Scalar::one();

        assert_eq!(product, one);
    }

    #[test]
    fn test_polynomial_evaluation() {
        // P(x) = 1 + 2x + 3x^2
        let coeffs = vec![
            Scalar::from_u64(1),
            Scalar::from_u64(2),
            Scalar::from_u64(3),
        ];

        let poly = Polynomial::new(coeffs);
        let x = Scalar::from_u64(5);
        let result = poly.evaluate(&x);

        // P(5) = 1 + 2*5 + 3*25 = 1 + 10 + 75 = 86
        println!("Polynomial evaluation test passed");
        assert!(!result.is_zero());
        assert_eq!(result, Scalar::from_u64(86));
    }

    #[test]
    fn test_shamir_secret_sharing() {
        let mut rng = thread_rng();
        let shamir = ShamirSharing::new(3, 5);

        let secret = Scalar::from_u64(42);
        let shares = shamir.split(secret.clone(), &mut rng);

        assert_eq!(shares.len(), 5);

        // Reconstruct from first 3 shares
        let reconstructed = shamir
            .reconstruct(&shares[..3])
            .expect("Reconstruction failed");

        println!("Shamir's Secret Sharing test passed");
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_threshold_signature() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(3, 5);

        let (master_pk, key_shares) = scheme
            .trusted_setup(&mut rng)
            .expect("Key generation failed");

        let message = b"Test message";
        let partial_sigs: Vec<_> = key_shares
            .iter()
            .take(3)
            .map(|share| {
                ThresholdBLS::partial_sign(share, message).expect("Partial signing failed")
            })
            .collect();

        let signature = scheme.aggregate(&partial_sigs).expect("Aggregation failed");

        ThresholdBLS::verify(&master_pk, message, &signature).expect("Verification failed");

        println!("✓ Threshold signature test passed!");
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(3, 5);
        let (master_pk, key_shares) = scheme
            .trusted_setup(&mut rng)
            .expect("Key generation failed");

        let signed_message = b"Signed message";
        let wrong_message = b"Wrong message";
        let partial_sigs: Vec<_> = key_shares
            .iter()
            .take(3)
            .map(|share| {
                ThresholdBLS::partial_sign(share, signed_message).expect("Partial signing failed")
            })
            .collect();
        let signature = scheme.aggregate(&partial_sigs).expect("Aggregation failed");

        let result = ThresholdBLS::verify(&master_pk, wrong_message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_rejects_zero_participant_id() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(3, 5);
        let (_, key_shares) = scheme
            .trusted_setup(&mut rng)
            .expect("Key generation failed");

        let message = b"Test message";
        let mut partial_sigs: Vec<_> = key_shares
            .iter()
            .take(3)
            .map(|share| {
                ThresholdBLS::partial_sign(share, message).expect("Partial signing failed")
            })
            .collect();

        partial_sigs[0].id = 0;
        let result = scheme.aggregate(&partial_sigs);
        assert!(result.is_err());
    }

    #[test]
    fn test_shamir_reconstruct_rejects_duplicate_x_coordinates() {
        let shamir = ShamirSharing::new(2, 3);
        let duplicate = Scalar::from_u64(9);
        let shares = vec![
            Share {
                x: duplicate.clone(),
                y: Scalar::from_u64(5),
            },
            Share {
                x: duplicate,
                y: Scalar::from_u64(7),
            },
        ];

        let result = shamir.reconstruct(&shares);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_rejects_duplicate_participant_ids() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(3, 5);

        let (_, key_shares) = scheme
            .trusted_setup(&mut rng)
            .expect("Key generation failed");

        let message = b"Test message";
        let mut partial_sigs: Vec<_> = key_shares
            .iter()
            .take(3)
            .map(|share| {
                ThresholdBLS::partial_sign(share, message).expect("Partial signing failed")
            })
            .collect();

        partial_sigs[1].id = partial_sigs[0].id;

        let result = scheme.aggregate(&partial_sigs);
        assert!(result.is_err());
    }

    #[test]
    fn test_aggregate_requires_exact_threshold_signatures() {
        let mut rng = thread_rng();
        let scheme = ThresholdBLS::new(3, 5);

        let (_, key_shares) = scheme
            .trusted_setup(&mut rng)
            .expect("Key generation failed");

        let message = b"Test message";
        let partial_sigs: Vec<_> = key_shares
            .iter()
            .take(4)
            .map(|share| {
                ThresholdBLS::partial_sign(share, message).expect("Partial signing failed")
            })
            .collect();

        let result = scheme.aggregate(&partial_sigs);
        assert!(result.is_err());
    }
}
