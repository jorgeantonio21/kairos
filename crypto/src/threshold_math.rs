use std::collections::HashSet;

use anyhow::{Result, anyhow};

use crate::bls::constants::INVALID_PEER_ID;
use crate::scalar::Scalar;

/// Validates that the given indices are unique and non-zero.
///
/// In threshold signing, indices must be:
/// - Non-zero (0 is reserved as INVALID_PEER_ID)
/// - Unique (no duplicates in the signing set)
///
/// These are DKG-assigned participant indices (1..n), not hash-derived PeerIds.
pub fn validate_unique_nonzero_indices(indices: &[u64]) -> Result<()> {
    let mut seen = HashSet::with_capacity(indices.len());
    for idx in indices {
        if *idx == INVALID_PEER_ID {
            return Err(anyhow!(
                "Index {} is invalid in threshold signatures (reserved)",
                INVALID_PEER_ID
            ));
        }
        if !seen.insert(*idx) {
            return Err(anyhow!(
                "Duplicate index in threshold signature set: {}",
                idx
            ));
        }
    }
    Ok(())
}

/// Computes the Lagrange coefficient λ_i at x=0 for a specific index.
///
/// Given points (x_0, x_1, ..., x_{t-1}) where x_j is the index of participant j,
/// computes λ_i = ∏_{j≠i} x_j / (x_j - x_i)
///
/// This is used for threshold signature combination:
/// σ = Σ λ_i · σ_i
pub fn lagrange_coefficient_at_zero(xs: &[Scalar], i: usize) -> Result<Scalar> {
    let mut numerator = Scalar::one();
    let mut denominator = Scalar::one();

    for (j, x_j) in xs.iter().enumerate() {
        if i == j {
            continue;
        }
        numerator = numerator.mul(x_j);
        let diff = x_j.sub(&xs[i]);
        denominator = denominator.mul(&diff);
    }

    numerator
        .div(&denominator)
        .ok_or_else(|| anyhow!("Invalid interpolation set: duplicate x coordinates"))
}

/// Computes all Lagrange coefficients at x=0 for a set of indices.
///
/// Returns a vector λ where λ[i] is the coefficient for the i-th index.
pub fn lagrange_coefficients_at_zero(xs: &[Scalar]) -> Result<Vec<Scalar>> {
    (0..xs.len())
        .map(|i| lagrange_coefficient_at_zero(xs, i))
        .collect()
}

/// Computes Lagrange coefficients for threshold signature combination.
///
/// The indices are DKG-assigned participant indices (1..n), not hash-derived PeerIds.
/// This ensures deterministic behavior regardless of public key values.
///
/// # Arguments
/// * `indices` - Sorted list of participant indices [1, 2, ..., n]
///
/// # Returns
/// Vector of coefficients λ where λ[i] corresponds to indices[i].
pub fn lagrange_coefficients_for_indices(indices: &[u64]) -> Result<Vec<Scalar>> {
    validate_unique_nonzero_indices(indices)?;
    let xs: Vec<Scalar> = indices.iter().map(|id| Scalar::from_u64(*id)).collect();
    lagrange_coefficients_at_zero(&xs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_zero_index() {
        let result = validate_unique_nonzero_indices(&[0, 1, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_duplicate_index() {
        let result = validate_unique_nonzero_indices(&[1, 2, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_accepts_unique_nonzero_indices() {
        let result = validate_unique_nonzero_indices(&[1, 2, 3, 4, 5]);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_accepts_single_index() {
        let result = validate_unique_nonzero_indices(&[42]);
        assert!(result.is_ok());
    }

    #[test]
    fn lagrange_coefficients_count_matches_input() {
        let coeffs = lagrange_coefficients_for_indices(&[1, 2, 4]).expect("coeffs");
        assert_eq!(coeffs.len(), 3);
    }

    #[test]
    fn lagrange_coefficients_single_point_is_one() {
        let coeffs = lagrange_coefficients_for_indices(&[7]).expect("coeffs");
        assert_eq!(coeffs.len(), 1);
        assert_eq!(coeffs[0], Scalar::one());
    }

    #[test]
    fn lagrange_coefficients_sum_to_one() {
        let indices = &[1u64, 2, 3, 4, 5];
        let coeffs = lagrange_coefficients_for_indices(indices).expect("coeffs");
        let sum: Scalar = coeffs.iter().fold(Scalar::zero(), |acc, c| acc.add(c));
        assert_eq!(sum, Scalar::one());
    }

    #[test]
    fn lagrange_coefficient_at_zero_handles_two_points() {
        let xs = vec![Scalar::from_u64(1), Scalar::from_u64(2)];
        let lambda_0 = lagrange_coefficient_at_zero(&xs, 0).expect("lambda");
        let lambda_1 = lagrange_coefficient_at_zero(&xs, 1).expect("lambda");
        assert_eq!(lambda_0.add(&lambda_1), Scalar::one());
    }

    #[test]
    fn lagrange_coefficient_at_zero_rejects_duplicate_x() {
        let xs = vec![Scalar::from_u64(1), Scalar::from_u64(1)];
        let result = lagrange_coefficient_at_zero(&xs, 0);
        assert!(result.is_err());
    }

    #[test]
    fn lagrange_coefficients_at_zero_empty_input() {
        let xs: Vec<Scalar> = vec![];
        let result = lagrange_coefficients_at_zero(&xs);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
