//! New sumcheck implementation based on the new Reduction.

pub mod evals;
pub mod folding;
pub mod oracles;
mod prove;
mod reduction;
mod relation;

use crate::barycentric_eval::BarycentricWeights;
use ark_ff::Field;
pub use oracles::OracleQueryInstance;
pub use prove::ProverKey;
pub use reduction::{SumcheckError, SumcheckReduction, SumcheckVerifierKey};
pub use relation::{SumcheckInstance, SumcheckRelation};
use std::ops::Mul;

#[derive(Clone, Debug)]
/// A message of the sumcheck protocol, represented as
/// the evaluations of polynomial over the domain 0..d.
pub struct SumcheckMessage<F>(Vec<F>);

impl<F: Field> SumcheckMessage<F> {
    pub fn zero(degree: usize) -> Self {
        Self(vec![F::ZERO; degree + 1])
    }

    pub(crate) fn new_degree_n(eval_at_0: F, eval_at_1: F, degree: usize) -> Self {
        assert!(degree >= 1, "degree should be >= 1");
        // e0, e1
        // P(x) = (e1 - e0)x + e0
        // TODO: it may be possible to exploit this structure further
        let mut message = Vec::with_capacity(degree + 1);
        let diff = eval_at_1 - eval_at_0;
        let mut last = F::zero();
        //as x is 0..d multiplication is unnecessary
        for _ in 0..=degree {
            message.push(last + eval_at_0);
            last += diff;
        }
        Self(message)
    }

    /// Adds an extra evaluation to handle a bigger degree.
    pub(crate) fn extend(self, weights: &BarycentricWeights<F>) -> Self {
        assert_eq!(self.0.len(), weights.domain_size());
        // The message length equals the weights length, so the next point is the constant
        // out-of-domain point that weights.extend(...) has already been precomputed for
        let message_extra_eval = weights.extend(&self.0);
        let evals = self.0.into_iter().chain([message_extra_eval]);
        Self(evals.collect())
    }
}

impl<F: Field> Mul for SumcheckMessage<F> {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        for ab in self.0.iter_mut().zip(rhs.0.iter()) {
            let (a, b): (&mut F, &F) = ab;
            *a *= b;
        }
        self
    }
}

pub(crate) mod degree {
    use std::ops::{Add, AddAssign, Mul, MulAssign, Sub};

    use crate::{
        sumcheck::Var,
        sumcheck2::evals::{Evals, Mles},
        sumcheck2::oracles::{EvalLocation, Oracle, SumcheckFunction},
    };
    use ark_ff::Field;

    #[derive(Clone, Copy, Debug)]
    struct Degree(usize);

    impl Add for Degree {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            Degree(self.0.max(rhs.0))
        }
    }

    impl Add<&Self> for Degree {
        type Output = Self;

        fn add(self, rhs: &Self) -> Self::Output {
            Degree(self.0.max(rhs.0))
        }
    }

    impl Sub<Self> for Degree {
        type Output = Self;

        fn sub(self, rhs: Self) -> Self::Output {
            Degree(self.0.max(rhs.0))
        }
    }

    impl Sub<&Self> for Degree {
        type Output = Self;

        fn sub(self, rhs: &Self) -> Self::Output {
            Degree(self.0.max(rhs.0))
        }
    }

    impl Mul for Degree {
        type Output = Self;

        fn mul(self, rhs: Self) -> Self::Output {
            #[allow(clippy::suspicious_arithmetic_impl)]
            Degree(self.0 + rhs.0)
        }
    }

    impl Mul<&Self> for Degree {
        type Output = Self;

        fn mul(self, rhs: &Self) -> Self::Output {
            #[allow(clippy::suspicious_arithmetic_impl)]
            Degree(self.0 + rhs.0)
        }
    }

    impl<F: Field> Add<F> for Degree {
        type Output = Self;

        fn add(self, _rhs: F) -> Self::Output {
            self
        }
    }

    impl<F: Field> Sub<F> for Degree {
        type Output = Self;

        fn sub(self, _rhs: F) -> Self::Output {
            self
        }
    }

    impl<F: Field> Mul<F> for Degree {
        type Output = Self;

        fn mul(self, _rhs: F) -> Self::Output {
            self
        }
    }

    impl AddAssign<&Self> for Degree {
        fn add_assign(&mut self, rhs: &Self) {
            *self = *self + rhs;
        }
    }

    impl<F: Field> MulAssign<F> for Degree {
        fn mul_assign(&mut self, _rhs: F) {}
    }

    impl<F: Field> Var<F> for Degree {}

    pub fn sumcheck_degree<F: Field, O: Oracle<F>>(oracle: &O) -> usize {
        let natures: Mles<O::Function, O::Nature> = oracle.natures();

        let intitial_degrees = <O::Function as Evals>::map_evals(&natures, |nature: &O::Nature| {
            let location: EvalLocation = (*nature).into();
            //NOTE: This may not always be true in sumcheck, and it ceirtainly is not
            // in sumfold.
            // This function is only to be used by sumcheck, for now it will be assumed
            // that instance evals are always 0, and the rest always 1. But at some
            // point it may be better to use some trait for the natures instead of just
            // Into<EvalLocation>.
            match location {
                EvalLocation::Structure => Degree(1),
                EvalLocation::Instance => Degree(0),
                EvalLocation::Witness => Degree(1),
            }
        });

        let degree: Degree = oracle.function().function(&intitial_degrees);
        degree.0
    }
}
