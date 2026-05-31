use crate::{polynomials::Evals, sumcheck::Var};
use ark_ff::Field;
use std::fmt::Debug;

/// The definition of a multivariate polynomial as some function
/// of multilinear polynomials.
pub trait SumcheckFunction<F: Field>: Debug + Clone + 'static {
    type Mles<V: Debug>: Evals<V> + Debug;
    type Natures: Copy + Debug;

    fn natures() -> Self::Mles<Self::Natures>;

    fn map_evals<A, B, M>(evals: &Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Debug,
        B: Debug,
        M: Fn(&A) -> B;

    fn combine<A, B, C, M>(a: &Self::Mles<A>, b: &Self::Mles<B>, f: M) -> Self::Mles<C>
    where
        A: Debug,
        B: Debug,
        C: Debug,
        M: Fn(&A, &B) -> C;

    fn apply<A, M>(a: &mut Self::Mles<A>, f: M)
    where
        A: Debug,
        M: Fn(&mut A);

    fn combine_mut_conditional<A, B, M>(
        a: &mut Self::Mles<A>,
        b: &Self::Mles<B>,
        c: Self::Mles<bool>,
        f: M,
    ) where
        A: Debug,
        B: Debug,
        M: Fn(&mut A, &B, bool);

    fn combine3<A, B, C, M>(a: [&Self::Mles<A>; 2], b: &Self::Mles<B>, f: M) -> Self::Mles<C>
    where
        A: Debug,
        B: Debug,
        C: Debug,
        M: Fn(&A, &A, &B) -> C;

    fn function<V: Var<F> + Debug>(&self, evals: &Self::Mles<V>) -> V;
}
