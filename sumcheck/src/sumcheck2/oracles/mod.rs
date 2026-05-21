use crate::polynomials::{Evals, MultiPoint};
use ark_ff::Field;
use std::{fmt::Debug, marker::PhantomData, rc::Rc};
use transcript::reduction2::{Message, Relation};

pub mod composite;
mod function;
pub mod small;

pub use function::{EitherLeft, EitherRight, SumcheckFunction};

#[derive(Clone, Debug)]
/// An instance in the QueryRelation, made up of an instance of
/// the oracle, an evaluation point, and an evaluation.
pub struct OracleQueryInstance<F: Field, O> {
    pub oracle_instance: O,
    pub point: MultiPoint<F>,
    pub eval: F,
}

#[derive(Clone, Copy, Debug)]
/// Unexpected number of variables
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

/// The oracle query relation.
/// To be in the relation means that evaluating the given oracle
/// on the given point, results in the given evaluation.
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

#[derive(Clone, Copy, Debug)]
/// The location where the given multilinear polynomial is.
/// It may be part of the structure, it may be part of the witness,
/// or it may be part of the instance.
/// The instance tends to be for degree 0 polynomials, like challenges.
pub enum EvalLocation {
    Structure,
    Instance,
    Witness,
}

pub trait Oracle<F: Field>: 'static + Clone + Debug
where
    <Self::Instance as Message<F>>::Error: Clone,
{
    type Evals<V>: Evals<V> + From<Mles<F, Self, V>> + Into<Mles<F, Self, V>>;
    type Function: SumcheckFunction<F, Mles<F> = Self::Evals<F>>;
    type Instance: Message<F> + Clone;
    type Witness;

    /// Each multilinear polynomial that goes into creating the multivariate
    /// polynomial used in sumcheck has some nature.
    /// Some may be part of the structure, some multilinear, some constant,
    /// some may have a small representation, others may be under a commitment.
    /// Each oracle may have its own supported natures, the only thing they all
    /// need to do is let sumcheck the location of each.
    type Nature: Into<EvalLocation> + Copy + Debug;

    // many of these things would be better in the key than in the oracle.
    fn instance_evals(instance: &Self::Instance) -> Self::Evals<F>;
    fn structure(&self) -> Rc<Vec<Self::Evals<F>>>;
    fn function(&self) -> &Self::Function;
    fn vars(&self) -> usize;
    fn oracle_params(&self) -> <Self::Instance as Message<F>>::Params;
    fn eval(
        &self,
        point: &MultiPoint<F>,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::Evals<F>;
    fn witness_from_evals(evals: &[Self::Evals<F>]) -> Self::Witness;
    fn natures(&self) -> Self::Evals<Self::Nature>;
}

pub type Mles<F, O, V> = <<O as Oracle<F>>::Function as SumcheckFunction<F>>::Mles<V>;
