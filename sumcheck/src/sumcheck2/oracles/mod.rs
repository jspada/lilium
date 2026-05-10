use crate::{
    polynomials::{Evals, MultiPoint},
    sumcheck::Var,
};
use ark_ff::Field;
use std::{fmt::Debug, marker::PhantomData};
use transcript::reduction2::{Message, Relation};

pub mod small;

pub trait SumcheckFunction<F: Field>: Debug + Clone + 'static {
    type Mles<V>: Evals<V> + Debug;

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

#[derive(Clone, Copy, Debug)]
/// Unexpedted number of variables
pub struct UnexpectedVars;

impl<F: Field> Message<F> for MultiPoint<F> {
    type Params = usize;

    type Error = UnexpectedVars;

    fn len(params: &Self::Params) -> usize {
        *params
    }

    fn to_field_elements(&self, expected_len: usize) -> Result<Vec<F>, Self::Error> {
        if self.vars() == expected_len {
            Ok(self.clone().inner())
        } else {
            Err(UnexpectedVars)
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum QueryInstanceError<F: Field, O: Message<F>> {
    Point(UnexpectedVars),
    Oracle(O::Error),
}

impl<F, O> Message<F> for OracleQueryInstance<F, O>
where
    F: Field,
    O: Message<F>,
{
    type Params = (O::Params, usize);

    type Error = QueryInstanceError<F, O>;

    fn len(params: &Self::Params) -> usize {
        O::len(&params.0) + MultiPoint::<F>::len(&params.1) + 1
    }

    fn to_field_elements(&self, expected_len: usize) -> Result<Vec<F>, Self::Error> {
        // Here we have to either assume the oracle instance or the point to be
        // correct.
        // It is a limitation of how the Message trait works with compound types.
        // In this case the point is assume to be correct, but both oracle and
        // point could be wrong in a way that adds up to the correct length.
        // It isn't a soundness bug, but I can make debugging harder.
        let expected = expected_len - self.point.vars() - 1;
        let mut elems = self
            .oracle_instance
            .to_field_elements(expected)
            .map_err(QueryInstanceError::Oracle)?;
        elems.extend(self.point.clone().inner());
        elems.push(self.eval);
        Ok(elems)
    }
}

pub struct QueryRelation<F, O>(PhantomData<(F, O)>);

impl<F: Field, O: Oracle<F>> Relation for QueryRelation<F, O> {
    type Structure = O;

    type Instance = OracleQueryInstance<F, O::Instance>;

    type Witness = O::Witness;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let OracleQueryInstance {
            oracle_instance,
            point,
            eval,
        } = instance;
        assert_eq!(point.vars(), structure.vars());
        let evals = structure.eval(point, oracle_instance, witness);
        let f = structure.function();
        *eval == f.function(&evals)
    }
}

pub trait Oracle<F: Field>: 'static + Clone + Debug
where
    <Self::Instance as Message<F>>::Error: Clone,
{
    type Evals<V>: Evals<V>;
    type Function: SumcheckFunction<F, Mles<F> = Self::Evals<F>>;
    type Instance: Message<F> + Clone;
    type Witness;

    // many of these things would be better in the key than in the oracle.
    fn mle(&self) -> &[Self::Evals<F>];
    fn function(&self) -> &Self::Function;
    fn vars(&self) -> usize;
    fn oracle_params(&self) -> <Self::Instance as Message<F>>::Params;
    fn eval(
        &self,
        point: &MultiPoint<F>,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::Evals<F>;
}
