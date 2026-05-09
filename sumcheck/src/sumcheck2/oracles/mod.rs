use crate::{
    polynomials::{Evals, MultiPoint},
    sumcheck::Var,
};
use ark_ff::Field;
use std::fmt::Debug;
use transcript::reduction2::{Message, Relation};

pub trait SumcheckFunction<F: Field> {
    type Mles<V>: Evals<V>;

    #[allow(dead_code)]
    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B;

    fn function<V: Var<F>>(&self, evals: &Self::Mles<V>) -> V;
}

#[derive(Clone, Debug)]
pub struct OracleQueryInstance<F: Field, O> {
    pub oracle_instance: O,
    pub point: MultiPoint<F>,
    pub eval: F,
}

pub trait Oracle<F: Field>: 'static + Clone + Debug
where
    <Self::Instance as Message<F>>::Error: Clone,
{
    type Evals<V>: Evals<V>;
    type Function: SumcheckFunction<F, Mles<F> = Self::Evals<F>>;
    type Instance: Message<F> + Clone;
    type QueryRelation: Relation<Instance = OracleQueryInstance<F, Self::Instance>>;
    // many of these things would be better in the key than in the oracle.
    fn mle(&self) -> &[Self::Evals<F>];
    fn function(&self) -> Self::Function;
    fn vars(&self) -> usize;
    fn oracle_params(&self) -> <Self::Instance as Message<F>>::Params;
}
