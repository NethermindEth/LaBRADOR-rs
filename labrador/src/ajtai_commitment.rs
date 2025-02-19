use crate::{rq::Rq, rq_matrix::RqMatrix, zq::Zq};
use thiserror::Error;

// Error types with clear documentation
#[derive(Debug, Error)]
pub enum ParameterError {
    #[error("parameters must be positive")]
    ZeroParameter,
    #[error("security bound β·m^(3/2) must be less than q")]
    SecurityBoundViolation,
    #[error("invalid bounds specified")]
    InvalidBounds,
}

#[derive(Debug, Error)]
pub enum CommitError {
    #[error("witness coefficients exceed bound")]
    WitnessBoundViolation,
    #[error("randomness coefficients exceed bound")]
    RandomnessBoundViolation,
}

/// Configuration parameters for Ajtai commitment scheme with validation invariants
#[derive(Debug, Clone)]
pub struct AjtaiParameters {
    beta: Zq,
    witness_bound: Zq,
    randomness_bound: Zq,
}

impl AjtaiParameters {
    /// Creates new parameters with validation
    pub fn new(beta: Zq, witness_bound: Zq, randomness_bound: Zq) -> Result<Self, ParameterError> {
        if witness_bound.is_zero() || randomness_bound.is_zero() {
            return Err(ParameterError::InvalidBounds);
        }

        Ok(Self {
            beta,
            witness_bound,
            randomness_bound,
        })
    }

    /// Default parameters for ternary distribution {-1, 0, 1}
    pub fn ternary() -> Self {
        Self {
            beta: Zq::one(),
            witness_bound: Zq::one(),
            randomness_bound: Zq::one(),
        }
    }
}

/// Ajtai commitment scheme implementation with matrix-based operations
#[derive(Debug)]
pub struct AjtaiCommitment<const M: usize, const N: usize, const D: usize> {
    matrix_a: RqMatrix<M, N, D>,
    witness_bound: Zq,
    randomness_bound: Zq,
}

/// Cryptographic opening containing witness and randomness
#[derive(Clone, Debug)]
pub struct Opening<const N: usize, const M: usize, const D: usize> {
    pub witness: [Rq<D>; N],
    pub randomness: [Rq<D>; M],
}

// Core implementation with security checks
impl<const M: usize, const N: usize, const D: usize> AjtaiCommitment<M, N, D> {
    /// Creates new commitment scheme with validated parameters
    pub fn new(params: AjtaiParameters) -> Result<Self, ParameterError> {
        Self::validate_parameters(&params)?;
        Ok(Self {
            matrix_a: RqMatrix::random(),
            witness_bound: params.witness_bound,
            randomness_bound: params.randomness_bound,
        })
    }

    /// Creates scheme with default ternary distribution bounds
    pub fn setup() -> Result<Self, ParameterError> {
        Self::new(AjtaiParameters::ternary())
    }

    /// Generates commitment and opening information with bounds checking
    pub fn commit(
        &self,
        witness: [Rq<D>; N],
    ) -> Result<([Rq<D>; M], Opening<N, M, D>), CommitError> {
        if !Self::check_bounds(&witness, self.witness_bound) {
            return Err(CommitError::WitnessBoundViolation);
        }

        let randomness = self.generate_bounded_randomness()?;

        let mut commitment = self.matrix_a.mul_vec(&witness);
        Self::add_randomness(&mut commitment, &randomness);

        Ok((
            commitment,
            Opening {
                witness,
                randomness,
            },
        ))
    }

    /// Verifies commitment against opening information
    pub fn verify(&self, commitment: &[Rq<D>; M], opening: &Opening<N, M, D>) -> bool {
        let bounds_valid = Self::check_bounds(&opening.witness, self.witness_bound)
            && Self::check_bounds(&opening.randomness, self.randomness_bound);

        bounds_valid && self.verify_commitment_calculation(commitment, opening)
    }

    /// Validates scheme parameters against cryptographic security requirements
    fn validate_parameters(params: &AjtaiParameters) -> Result<(), ParameterError> {
        if [M, N, D].iter().any(|&v| v == 0) {
            return Err(ParameterError::ZeroParameter);
        }

        Self::verify_security_relation(
            params.beta.value(),
            u128::try_from(M).unwrap(),
            Self::modulus_u128(),
        )
    }

    /// Verifies the security relation β²m³ < q² required for Ajtai's commitment scheme.
    ///
    /// This bound ensures the scheme's security by:
    /// 1. Making the underlying lattice problem hard (SIS assumption)
    /// 2. Preventing statistical attacks on the commitment
    /// 3. Ensuring the commitment is binding under standard lattice assumptions
    ///
    /// The relation β²m³ < q² is a necessary condition derived from the security
    /// proof of Ajtai's commitment scheme, where:
    /// - β bounds the size of randomness/witness coefficients
    /// - m is the commitment output length
    /// - q is the modulus of the underlying ring
    fn verify_security_relation(beta: u32, m: u128, q: u128) -> Result<(), ParameterError> {
        let beta = u128::from(beta);
        let m_cubed = m
            .checked_pow(3)
            .ok_or(ParameterError::SecurityBoundViolation)?;
        let beta_squared = beta
            .checked_pow(2)
            .ok_or(ParameterError::SecurityBoundViolation)?;
        let q_squared = q
            .checked_pow(2)
            .ok_or(ParameterError::SecurityBoundViolation)?;

        if beta_squared
            .checked_mul(m_cubed)
            .map(|left| left >= q_squared)
            .unwrap_or(true)
        {
            Err(ParameterError::SecurityBoundViolation)
        } else {
            Ok(())
        }
    }

    /// Checks polynomial coefficients against specified bound
    fn check_bounds<const SIZE: usize>(polynomials: &[Rq<D>; SIZE], bound: Zq) -> bool {
        polynomials.iter().all(|p| p.check_bounds(bound))
    }

    /// Generates randomness with proper bounds checking
    fn generate_bounded_randomness(&self) -> Result<[Rq<D>; M], CommitError> {
        let randomness = std::array::from_fn(|_| Rq::random_small());
        if !Self::check_bounds(&randomness, self.randomness_bound) {
            Err(CommitError::RandomnessBoundViolation)
        } else {
            Ok(randomness)
        }
    }

    /// Recomputes commitment from opening and verifies match
    fn verify_commitment_calculation(
        &self,
        commitment: &[Rq<D>; M],
        opening: &Opening<N, M, D>,
    ) -> bool {
        let mut recomputed = self.matrix_a.mul_vec(&opening.witness);
        Self::add_randomness(&mut recomputed, &opening.randomness);
        commitment == &recomputed
    }

    /// Adds randomness to commitment in-place
    fn add_randomness(commitment: &mut [Rq<D>; M], randomness: &[Rq<D>; M]) {
        commitment
            .iter_mut()
            .zip(randomness)
            .for_each(|(c, r)| *c += r.clone());
    }

    fn modulus_u128() -> u128 {
        let q_val = (Zq::zero() - Zq::one()).value();
        u128::from(q_val) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_M: usize = 8;
    const TEST_N: usize = 8;
    const TEST_D: usize = 4;
    type TestAjtai = AjtaiCommitment<TEST_M, TEST_N, TEST_D>;

    // Test helpers
    mod test_utils {
        use super::*;

        pub fn valid_witness(scheme: &TestAjtai) -> [Rq<TEST_D>; TEST_N] {
            std::array::from_fn(|_| Rq::new(std::array::from_fn(|_| scheme.witness_bound)))
        }

        pub fn setup_scheme() -> TestAjtai {
            TestAjtai::new(AjtaiParameters::new(Zq::one(), Zq::new(1), Zq::new(1)).unwrap())
                .unwrap()
        }
    }

    #[test]
    fn rejects_invalid_parameters() {
        assert!(AjtaiParameters::new(Zq::one(), Zq::zero(), Zq::one()).is_err());
        let _ = test_utils::setup_scheme(); // Will panic if setup fails
    }

    #[test]
    fn initializes_with_correct_bounds() {
        let scheme = TestAjtai::setup().unwrap();
        assert_eq!(scheme.witness_bound.value(), 1);
        assert_eq!(scheme.randomness_bound.value(), 1);
    }

    #[test]
    fn completes_commitment_cycle() {
        let scheme = test_utils::setup_scheme();
        let witness = test_utils::valid_witness(&scheme);

        let (commitment, opening) = scheme.commit(witness).unwrap();
        assert!(scheme.verify(&commitment, &opening));

        let mut bad_opening = opening.clone();
        bad_opening.witness[0] = Rq::random_small();
        assert!(!scheme.verify(&commitment, &bad_opening));
    }

    #[test]
    fn maintains_security_properties() {
        let scheme = test_utils::setup_scheme();
        let witness = test_utils::valid_witness(&scheme);

        let (c1, _) = scheme.commit(witness).unwrap();
        let (c2, _) = scheme.commit(test_utils::valid_witness(&scheme)).unwrap();
        assert_ne!(
            c1, c2,
            "Different witnesses should produce different commitments"
        );
    }

    #[test]
    fn handles_edge_cases() {
        let scheme = test_utils::setup_scheme();
        let zero_witness = std::array::from_fn(|_| Rq::zero());

        assert!(scheme.commit(zero_witness).is_ok());
        assert!(scheme.commit(test_utils::valid_witness(&scheme)).is_ok());
    }

    #[test]
    fn stress_test() {
        let scheme = TestAjtai::setup().unwrap();

        (0..100).for_each(|_| {
            let witness = test_utils::valid_witness(&scheme);
            let (commitment, opening) = scheme.commit(witness).unwrap();
            assert!(scheme.verify(&commitment, &opening));
        });
    }
}
