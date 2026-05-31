use crate::{polynomials::Evals, sumcheck::Var, sumcheck2::oracles::composite::Either};
use ark_ff::Field;
use std::{fmt::Debug, marker::PhantomData};

/// The definition of a multivariate polynomial as some function
/// of multilinear polynomials.
pub trait SumcheckFunction<F: Field>: Debug + Clone + 'static {
    type Mles<V>: Evals<V> + Debug;
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
        M: Fn(&mut A, &B, bool);

    fn combine3<A, B, C, M>(a: [&Self::Mles<A>; 2], b: &Self::Mles<B>, f: M) -> Self::Mles<C>
    where
        A: Debug,
        B: Debug,
        M: Fn(&A, &A, &B) -> C;

    fn function<V: Var<F>>(&self, evals: &Self::Mles<V>) -> V;
}

#[derive(Clone, Copy, Debug)]
pub struct EitherLeft<F: Field, SF: SumcheckFunction<F>>(SF, PhantomData<F>);

impl<F, SF, L, R> SumcheckFunction<F> for EitherLeft<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F, Natures = Either<L, R>>,
    L: Copy + Debug,
    R: Copy + Debug,
{
    type Mles<V> = SF::Mles<V>;

    type Natures = Option<L>;

    fn natures() -> Self::Mles<Self::Natures> {
        let natures = SF::natures();
        SF::map_evals(&natures, |nature| match nature {
            Either::Left(x) => Some(*x),
            Either::Right(_) => None,
        })
    }

    fn map_evals<A, B, M>(evals: &Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Debug,
        B: Debug,
        M: Fn(&A) -> B,
    {
        SF::map_evals(evals, f)
    }

    fn combine<A, B, C, M>(a: &Self::Mles<A>, b: &Self::Mles<B>, f: M) -> Self::Mles<C>
    where
        A: Debug,
        B: Debug,
        M: Fn(&A, &B) -> C,
    {
        SF::combine(a, b, f)
    }

    fn apply<A, M>(a: &mut Self::Mles<A>, f: M)
    where
        A: Debug,
        M: Fn(&mut A),
    {
        SF::apply(a, f);
    }

    fn combine_mut_conditional<A, B, M>(
        a: &mut Self::Mles<A>,
        b: &Self::Mles<B>,
        c: Self::Mles<bool>,
        f: M,
    ) where
        A: Debug,
        M: Fn(&mut A, &B, bool),
    {
        SF::combine_mut_conditional(a, b, c, f);
    }

    fn combine3<A, B, C, M>(a: [&Self::Mles<A>; 2], b: &Self::Mles<B>, f: M) -> Self::Mles<C>
    where
        A: Debug,
        B: Debug,
        M: Fn(&A, &A, &B) -> C,
    {
        SF::combine3(a, b, f)
    }

    fn function<V: crate::sumcheck::Var<F>>(&self, evals: &Self::Mles<V>) -> V {
        self.0.function(evals)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EitherRight<F: Field, SF: SumcheckFunction<F>>(SF, PhantomData<F>);

impl<F, SF, L, R> SumcheckFunction<F> for EitherRight<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F, Natures = Either<L, R>>,
    L: Copy + Debug,
    R: Copy + Debug,
{
    type Mles<V> = SF::Mles<V>;

    type Natures = Option<R>;

    fn natures() -> Self::Mles<Self::Natures> {
        let natures = SF::natures();
        SF::map_evals(&natures, |nature| match nature {
            Either::Left(_) => None,
            Either::Right(x) => Some(*x),
        })
    }

    fn map_evals<A, B, M>(evals: &Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Debug,
        B: Debug,
        M: Fn(&A) -> B,
    {
        SF::map_evals(evals, f)
    }

    fn combine<A, B, C, M>(a: &Self::Mles<A>, b: &Self::Mles<B>, f: M) -> Self::Mles<C>
    where
        A: Debug,
        B: Debug,
        M: Fn(&A, &B) -> C,
    {
        SF::combine(a, b, f)
    }

    fn apply<A, M>(a: &mut Self::Mles<A>, f: M)
    where
        A: Debug,
        M: Fn(&mut A),
    {
        SF::apply(a, f);
    }

    fn combine_mut_conditional<A, B, M>(
        a: &mut Self::Mles<A>,
        b: &Self::Mles<B>,
        c: Self::Mles<bool>,
        f: M,
    ) where
        A: Debug,
        M: Fn(&mut A, &B, bool),
    {
        SF::combine_mut_conditional(a, b, c, f);
    }

    fn combine3<A, B, C, M>(a: [&Self::Mles<A>; 2], b: &Self::Mles<B>, f: M) -> Self::Mles<C>
    where
        A: Debug,
        B: Debug,
        M: Fn(&A, &A, &B) -> C,
    {
        SF::combine3(a, b, f)
    }

    fn function<V: crate::sumcheck::Var<F>>(&self, evals: &Self::Mles<V>) -> V {
        self.0.function(evals)
    }
}
