use crate::sumcheck::{Env, Var};
use ark_ff::Field;

pub use test_field::Fm;

/// Should check sumcheck where the sum is zero
#[derive(Clone, Debug)]
pub struct ZeroSumcheck<V>(pub V);
/// Should check that the polynomial evaluates to 0 over the domain
pub struct ZeroCheck<V>(pub V);

/// To be implemented on evals that can provide the necessary polynomial
/// for zero check
pub trait ZeroCheckAvailable: Sized {
    /// Provides the index to eq(x,b), for some random b, multiplying
    /// a polynomial f by it and checking the sum is 0 is equivalent
    /// to checking that f is the zero polynomial
    fn zerocheck_eq() -> Self;
    fn zero_check<F, V, C, E>(env: &E, zero_check: ZeroCheck<V>) -> ZeroSumcheck<V>
    where
        F: Field,
        V: Var<F>,
        E: Env<F, V, Self, C>,
    {
        let idx = Self::zerocheck_eq();
        let eq = env.get(idx);
        ZeroSumcheck(zero_check.0 * eq)
    }
}

/// To be implemented on evals that can provide a zero polynomial,
/// useful when needing an identity.
pub trait ZeroAvailable: Sized {
    /// Provides the index to the zero polynomial, which evaluates
    /// to zero at any point
    fn zero() -> Self;
}

mod test_field {
    #![allow(non_local_definitions)]
    use ark_ff::{Fp64, MontBackend, MontConfig};

    #[derive(MontConfig)]
    #[modulus = "4294967291"]
    #[generator = "3"]
    pub struct M32Config;

    /// Small field based on the prime 2^31-1. Intended for testing
    /// as it is too small to be secure in most applications.
    pub type Fm = Fp64<MontBackend<M32Config, 1>>;
}
