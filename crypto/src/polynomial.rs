use rand::{CryptoRng, Rng};

use crate::scalar::Scalar;

/// Polynomial over scalar field Fr
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Create polynomial with given coefficients
    /// The element at index 0 is the constant term
    pub fn new(coefficients: Vec<Scalar>) -> Self {
        Polynomial { coefficients }
    }

    /// Generate random polynomial of given degree with specified constant term
    pub fn random<R: Rng + CryptoRng>(degree: usize, constant_term: Scalar, rng: &mut R) -> Self {
        let mut coefficients = vec![constant_term];
        for _ in 0..degree {
            coefficients.push(Scalar::random(rng));
        }
        Polynomial::new(coefficients)
    }

    /// Evaluate polynomial at point x using Horner's method
    /// P(x) = a_0 + a_1*x + a_2*x^2 + ... + a_n*x^n
    pub fn evaluate(&self, x: &Scalar) -> Scalar {
        if self.coefficients.is_empty() {
            return Scalar::zero();
        }

        // Horner's method: work backwards from highest degree
        let mut result = self.coefficients.last().unwrap().clone();

        for coeff in self.coefficients.iter().rev().skip(1) {
            result = result.mul(x).add(coeff);
        }

        result
    }

    /// Get the constant term (secret)
    pub fn constant_term(&self) -> &Scalar {
        &self.coefficients[0]
    }

    /// Get a coefficient by index (`0` is constant term).
    pub fn coefficient(&self, index: usize) -> Option<&Scalar> {
        self.coefficients.get(index)
    }

    /// Get polynomial degree
    pub fn degree(&self) -> usize {
        self.coefficients.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::Polynomial;
    use crate::scalar::Scalar;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn degree_and_constant_term() {
        let poly = Polynomial::new(vec![
            Scalar::from_u64(7),
            Scalar::from_u64(2),
            Scalar::from_u64(1),
        ]);
        assert_eq!(*poly.constant_term(), Scalar::from_u64(7));
        assert_eq!(poly.degree(), 2);
    }

    #[test]
    fn evaluate_empty_polynomial_returns_zero() {
        let poly = Polynomial::new(vec![]);
        let value = poly.evaluate(&Scalar::from_u64(10));
        assert_eq!(value, Scalar::zero());
    }

    #[test]
    fn random_polynomial_has_requested_degree() {
        let mut rng = StdRng::seed_from_u64(42);
        let poly = Polynomial::random(4, Scalar::from_u64(9), &mut rng);
        assert_eq!(poly.degree(), 4);
        assert_eq!(*poly.constant_term(), Scalar::from_u64(9));
    }

    #[test]
    fn evaluate_at_zero_returns_constant_term() {
        let poly = Polynomial::new(vec![
            Scalar::from_u64(42),
            Scalar::from_u64(3),
            Scalar::from_u64(5),
        ]);
        let value = poly.evaluate(&Scalar::zero());
        assert_eq!(value, Scalar::from_u64(42));
    }

    #[test]
    fn evaluate_linear_polynomial() {
        let poly = Polynomial::new(vec![Scalar::from_u64(2), Scalar::from_u64(3)]);
        let value = poly.evaluate(&Scalar::from_u64(4));
        assert_eq!(value, Scalar::from_u64(14));
    }

    #[test]
    fn coefficient_out_of_bounds_returns_none() {
        let poly = Polynomial::new(vec![Scalar::from_u64(1), Scalar::from_u64(2)]);
        assert!(poly.coefficient(5).is_none());
        assert!(poly.coefficient(0).is_some());
    }

    #[test]
    fn degree_of_empty_polynomial_is_zero() {
        let poly = Polynomial::new(vec![]);
        assert_eq!(poly.degree(), 0);
    }

    #[test]
    fn degree_of_constant_polynomial_is_zero() {
        let poly = Polynomial::new(vec![Scalar::from_u64(5)]);
        assert_eq!(poly.degree(), 0);
    }
}
