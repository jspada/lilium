use crate::sumcheck::Var;
use crate::sumcheck2::evals::Evals;
use ark_ff::Field;
use std::fmt::Debug;

/// The definition of a multivariate polynomial as some function
/// of multilinear polynomials.
pub trait SumcheckFunction<F: Field>: Evals {
    type Natures: Copy + Debug;

    fn natures() -> Self::Mles<Self::Natures>;

    fn function<V: Var<F> + Debug>(&self, evals: &Self::Mles<V>) -> V;
}
