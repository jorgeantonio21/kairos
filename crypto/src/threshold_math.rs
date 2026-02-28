use std::collections::HashSet;

use anyhow::{Result, anyhow};

use crate::bls::constants::INVALID_PEER_ID;
use crate::scalar::Scalar;

pub fn validate_unique_nonzero_peer_ids(peer_ids: &[u64]) -> Result<()> {
    let mut seen = HashSet::with_capacity(peer_ids.len());
    for peer_id in peer_ids {
        if *peer_id == INVALID_PEER_ID {
            return Err(anyhow!("Peer ID {INVALID_PEER_ID} is invalid in threshold signatures"));
        }
        if !seen.insert(*peer_id) {
            return Err(anyhow!("Duplicate peer ID in threshold signature set: {peer_id}"));
        }
    }
    Ok(())
}

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

pub fn lagrange_coefficients_at_zero(xs: &[Scalar]) -> Result<Vec<Scalar>> {
    (0..xs.len())
        .map(|i| lagrange_coefficient_at_zero(xs, i))
        .collect()
}

pub fn lagrange_coefficients_for_peer_ids(peer_ids: &[u64]) -> Result<Vec<Scalar>> {
    validate_unique_nonzero_peer_ids(peer_ids)?;
    let xs: Vec<Scalar> = peer_ids.iter().map(|id| Scalar::from_u64(*id)).collect();
    lagrange_coefficients_at_zero(&xs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_zero_peer_id() {
        let result = validate_unique_nonzero_peer_ids(&[0, 1, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_duplicate_peer_id() {
        let result = validate_unique_nonzero_peer_ids(&[1, 2, 2]);
        assert!(result.is_err());
    }

    #[test]
    fn lagrange_coefficients_count_matches_input() {
        let coeffs = lagrange_coefficients_for_peer_ids(&[1, 2, 4]).expect("coeffs");
        assert_eq!(coeffs.len(), 3);
    }

    #[test]
    fn lagrange_coefficients_single_point_is_one() {
        let coeffs = lagrange_coefficients_for_peer_ids(&[7]).expect("coeffs");
        assert_eq!(coeffs.len(), 1);
        assert_eq!(coeffs[0], Scalar::one());
    }
}
