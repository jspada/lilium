use crate::{
    polynomials::MultiPoint,
    sumcheck2::oracles::{
        composite::{CompositeOracleInstance, Either},
        EvalLocation, SumcheckFunction,
    },
};
use ark_ff::Field;
use std::{fmt::Debug, marker::PhantomData};
use transcript::reduction2::{Message, Relation};

#[derive(Clone, Debug)]
pub struct PartialQueryInstance<F: Field, O> {
    evals: Vec<F>,
    oracle_instance: O,
    point: MultiPoint<F>,
}

impl<F: Field, O> PartialQueryInstance<F, O> {
    pub fn new(evals: Vec<F>, oracle_instance: O, point: &MultiPoint<F>) -> Self {
        Self {
            evals,
            oracle_instance,
            point: point.clone(),
        }
    }

    pub fn evals(&self) -> &[F] {
        &self.evals
    }

    pub fn oracle_instance(&self) -> &O {
        &self.oracle_instance
    }

    pub fn point(&self) -> &MultiPoint<F> {
        &self.point
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OracleParams {
    pub vars: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum OracleEval<F> {
    Computed(F),
    ProverProvided,
    None,
}

pub trait PartialOracle<F, SF>: 'static + Clone + Debug
where
    F: Field,
    SF: SumcheckFunction<F>,
    <Self::Instance as Message<F>>::Error: Clone,
{
    type Instance: Message<F, Params = OracleParams> + Clone;
    type VerifierKey: From<Self> + Clone;

    type Nature: Into<EvalLocation> + Copy + Debug;

    type QueryRelation: Relation<
        Structure = Self,
        Instance = PartialQueryInstance<F, Self::Instance>,
        Witness = Vec<SF::Mles<F>>,
    >;

    fn instance_evals(instance: &Self::Instance) -> SF::Mles<F>;
    fn evals(
        key: &Self::VerifierKey,
        instance: &Self::Instance,
        point: &MultiPoint<F>,
    ) -> SF::Mles<OracleEval<F>>;
    fn prover_provided(nature: &Self::Nature) -> bool;
}

impl<F, SF, P1, P2> PartialQueryInstance<F, CompositeOracleInstance<F, SF, P1, P2>>
where
    F: Field,
    SF: SumcheckFunction<F>,
    P1: PartialOracle<F, SF>,
    P2: PartialOracle<F, SF>,
{
    pub fn split(
        self,
        evals1: usize,
        evals2: usize,
    ) -> (
        PartialQueryInstance<F, P1::Instance>,
        PartialQueryInstance<F, P2::Instance>,
    ) {
        let Self {
            evals,
            oracle_instance,
            point,
        } = self;
        assert_eq!(evals.len(), evals1 + evals2);
        let (evals1, evals2) = evals.split_at(evals1);
        let CompositeOracleInstance {
            oracle1_instance,
            oracle2_instance,
        } = oracle_instance;

        let instance1 = PartialQueryInstance {
            evals: evals1.to_vec(),
            oracle_instance: oracle1_instance,
            point: point.clone(),
        };
        let instance2 = PartialQueryInstance {
            evals: evals2.to_vec(),
            oracle_instance: oracle2_instance,
            point,
        };
        (instance1, instance2)
    }
}

pub struct PartialQueryRelation<F, SF, P1, P2>(PhantomData<(F, SF, P1, P2)>);

impl<F, SF, P1, P2> Relation for PartialQueryRelation<F, SF, P1, P2>
where
    F: Field,
    SF: SumcheckFunction<F, Natures = Either<P1::Nature, P2::Nature>>,
    P1: PartialOracle<F, SF>,
    P2: PartialOracle<F, SF>,
{
    type Structure = (P1, P2);

    type Instance = (
        PartialQueryInstance<F, P1::Instance>,
        PartialQueryInstance<F, P2::Instance>,
    );

    type Witness = Vec<SF::Mles<F>>;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let check1 = P1::QueryRelation::check(&structure.0, &instance.0, witness);
        let check2 = P2::QueryRelation::check(&structure.1, &instance.1, witness);
        check1 && check2
    }
}
