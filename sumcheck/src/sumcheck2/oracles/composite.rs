use crate::{
    polynomials::{Evals, EvalsExt, MultiPoint},
    sumcheck2::{
        oracles::{EvalLocation, Oracle, QueryRelation, SumcheckFunction},
        OracleQueryInstance,
    },
};
use ark_ff::Field;
use core::panic;
use sponge::sponge::Duplex;
use std::{fmt::Debug, marker::PhantomData, rc::Rc};
use transcript::reduction2::{
    GuardedProof, InherentParams, Message, ProverOutput, Reduction, Relation, Transcript,
    TranscriptBuilder, VerifierTranscript,
};

#[derive(Clone, Copy, Debug)]
pub enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<A, B> From<Either<A, B>> for EvalLocation
where
    A: Into<EvalLocation>,
    B: Into<EvalLocation>,
{
    fn from(value: Either<A, B>) -> Self {
        match value {
            Either::Left(a) => a.into(),
            Either::Right(b) => b.into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OracleParams {
    pub vars: usize,
}

pub struct PartialQueryInstance<F, O> {
    evals: Vec<F>,
    oracle_instance: O,
}

impl<F, O> PartialQueryInstance<F, O> {
    pub fn new(evals: Vec<F>, oracle_instance: O) -> Self {
        Self {
            evals,
            oracle_instance,
        }
    }

    pub fn evals(&self) -> &[F] {
        &self.evals
    }

    pub fn oracle_instance(&self) -> &O {
        &self.oracle_instance
    }
}

pub trait PartialOracle<F, SF>: 'static + Clone + Debug
where
    F: Field,
    SF: SumcheckFunction<F>,
    <Self::Instance as Message<F>>::Error: Clone,
{
    type Instance: Message<F, Params = OracleParams> + InherentParams<F> + Clone;
    // type Witness;

    type Nature: Into<EvalLocation> + Copy + Debug;

    type QueryRelation: Relation<
        Structure = Self,
        Instance = PartialQueryInstance<F, Self::Instance>,
        Witness = Vec<SF::Mles<F>>,
    >;

    fn instance_evals(instance: &Self::Instance) -> SF::Mles<F>;
    fn oracle_params(&self) -> <Self::Instance as Message<F>>::Params;
    fn evals(instance: &Self::Instance, point: &MultiPoint<F>) -> SF::Mles<OracleEval<F>>;
}

pub enum OracleEval<F> {
    Computed(F),
    ProverProvided,
    None,
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

#[derive(Clone, Debug)]
pub struct CompositeOracle<F, SF, P1, P2>
where
    F: Field,
    SF: SumcheckFunction<F>,
    P1: PartialOracle<F, SF>,
    P2: PartialOracle<F, SF>,
{
    f: SF,
    mles: Rc<Vec<SF::Mles<F>>>,
    vars: usize,
    partial_oracle_1: P1,
    partial_oracle_2: P2,
}

pub struct CompositeQueryRelation<F, SF, P1, P2>(PhantomData<(F, SF, P1, P2)>);

#[derive(Clone, Copy, Debug)]
pub struct CompositeOracleInstance<F, SF, P1, P2>
where
    F: Field,
    SF: SumcheckFunction<F>,
    P1: PartialOracle<F, SF>,
    P2: PartialOracle<F, SF>,
{
    oracle1_instance: P1::Instance,
    oracle2_instance: P2::Instance,
}

#[derive(Clone, Copy, Debug)]
pub enum CompositeError<F, P1: Message<F>, P2: Message<F>> {
    Oracle1(P1::Error),
    Oracle2(P2::Error),
    UnexpectedLenght,
}

impl<F, SF, P1, P2> Message<F> for CompositeOracleInstance<F, SF, P1, P2>
where
    F: Field,
    SF: SumcheckFunction<F>,
    P1: PartialOracle<F, SF>,
    P2: PartialOracle<F, SF>,
{
    type Params = OracleParams;

    type Error = CompositeError<F, P1::Instance, P2::Instance>;

    fn len(params: &Self::Params) -> usize {
        P1::Instance::len(params) + P2::Instance::len(params)
    }

    fn to_field_elements(&self, expected_len: usize) -> Result<Vec<F>, Self::Error> {
        use CompositeError::*;
        let oracle1_len = P1::Instance::len(&self.oracle1_instance.params());
        let oracle2_len = P2::Instance::len(&self.oracle2_instance.params());

        let mut elems = self
            .oracle1_instance
            .to_field_elements(oracle1_len)
            .map_err(Oracle1)?;

        elems.extend(
            self.oracle2_instance
                .to_field_elements(expected_len)
                .map_err(Oracle2)?,
        );

        if expected_len != oracle1_len + oracle2_len {
            Err(UnexpectedLenght)
        } else {
            Ok(elems)
        }
    }
}

impl<F, SF, P1, P2> Oracle<F> for CompositeOracle<F, SF, P1, P2>
where
    F: Field,
    SF: SumcheckFunction<F, Natures = Either<P1::Nature, P2::Nature>>,
    P1: PartialOracle<F, SF>,
    P2: PartialOracle<F, SF>,
{
    type Evals<V> = SF::Mles<V>;

    type Function = SF;

    type Instance = CompositeOracleInstance<F, SF, P1, P2>;

    type Witness = Vec<SF::Mles<F>>;

    type Nature = Either<P1::Nature, P2::Nature>;

    fn instance_evals(instance: &Self::Instance) -> Self::Evals<F> {
        let natures = SF::natures().flatten_vec();
        let evals_oracle1 = P1::instance_evals(&instance.oracle1_instance).flatten_vec();
        assert_eq!(natures.len(), evals_oracle1.len());
        let evals_oracle2 = P2::instance_evals(&instance.oracle2_instance).flatten_vec();
        assert_eq!(natures.len(), evals_oracle2.len());

        let mut evals = vec![];

        for ((o1, o2), nature) in evals_oracle1.into_iter().zip(evals_oracle2).zip(natures) {
            let eval = match nature {
                Either::Left(_) => o1,
                Either::Right(_) => o2,
            };
            evals.push(eval);
        }

        SF::Mles::unflatten_vec(evals)
    }

    fn structure(&self) -> Rc<Vec<Self::Evals<F>>> {
        Rc::clone(&self.mles)
    }

    fn function(&self) -> &Self::Function {
        &self.f
    }

    fn vars(&self) -> usize {
        self.vars
    }

    fn oracle_params(&self) -> <Self::Instance as Message<F>>::Params {
        OracleParams { vars: self.vars }
    }

    fn eval(
        &self,
        point: &MultiPoint<F>,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> Self::Evals<F> {
        let natures = SF::natures();
        let instance_evals = Self::instance_evals(instance);
        // TODO: Evaluate only what's needed of each.
        let witness_evals = EvalsExt::eval(witness, point.clone());
        let structure_evals = EvalsExt::eval(&self.mles, point.clone());

        let locations = SF::map_evals(&natures, |nature| match nature {
            Either::Left(n) => (*n).into(),
            Either::Right(n) => (*n).into(),
        });

        let evals = SF::combine(&instance_evals, &locations, |eval, location| {
            if let EvalLocation::Instance = location {
                *eval
            } else {
                F::ZERO
            }
        });

        let evals = SF::combine3(
            [&evals, &witness_evals],
            &locations,
            |eval, witness, location| match location {
                EvalLocation::Structure | EvalLocation::Instance => *eval,
                EvalLocation::Witness => *witness,
            },
        );

        SF::combine3(
            [&evals, &structure_evals],
            &locations,
            |eval, witness, location| match location {
                EvalLocation::Witness | EvalLocation::Instance => *eval,
                EvalLocation::Structure => *witness,
            },
        )
    }

    fn witness_from_evals(evals: &[Self::Evals<F>]) -> Self::Witness {
        evals.to_vec()
    }

    fn natures(&self) -> Self::Evals<Self::Nature> {
        SF::natures()
    }
}

pub struct CompositeReductionKey<F: Field, SF: SumcheckFunction<F>> {
    // Number of evals provided to the oracle be the prover
    // and to be verified through some reduction.
    oracle1_evals: usize,
    oracle2_evals: usize,
    f: SF,
    _field: PhantomData<F>,
}

#[derive(Clone, Debug)]
/// All evaluations provided by the prover to the 2 oracles.
pub struct ProverEvals<F>(Vec<F>);

impl<F: Field> Message<F> for ProverEvals<F> {
    type Params = usize;

    type Error = ();

    fn len(params: &Self::Params) -> usize {
        *params
    }

    fn to_field_elements(&self, expected_len: usize) -> Result<Vec<F>, Self::Error> {
        if self.0.len() == expected_len {
            Ok(self.0.clone())
        } else {
            Err(())
        }
    }
}

impl<F, SF, P1, P2> Reduction<F, QueryRelation<F, Self>, PartialQueryRelation<F, SF, P1, P2>>
    for CompositeOracle<F, SF, P1, P2>
where
    F: Field,
    SF: SumcheckFunction<F, Natures = Either<P1::Nature, P2::Nature>>,
    P1: PartialOracle<F, SF>,
    P2: PartialOracle<F, SF>,
    <QueryRelation<F, Self> as Relation>::Instance: Message<F, Params = (OracleParams, usize)>,
{
    type ProverKey = ();

    type VerifierKey = CompositeReductionKey<F, SF>;

    type Proof = ProverEvals<F>;

    type Error = ();

    fn transcript_pattern(
        key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        builder.round::<F, ProverEvals<F>, 0>(key.oracle1_evals + key.oracle2_evals)
    }

    fn verifier_key(structure_1: &Self, structure_2: &(P1, P2)) -> Self::VerifierKey {
        todo!()
    }

    fn instance_params(key: &Self::VerifierKey) -> (OracleParams, usize) {
        todo!()
    }

    fn key_pair(
        structure_1: &Self,
        structure_2: &(P1, P2),
    ) -> (Self::VerifierKey, Self::ProverKey) {
        todo!()
    }

    fn prove<S: Duplex<F>>(
        key: &Self::ProverKey,
        instance: OracleQueryInstance<F, CompositeOracleInstance<F, SF, P1, P2>>,
        witness: Vec<SF::Mles<F>>,
        transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<PartialQueryRelation<F, SF, P1, P2>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: OracleQueryInstance<F, CompositeOracleInstance<F, SF, P1, P2>>,
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<<PartialQueryRelation<F, SF, P1, P2> as Relation>::Instance, Self::Error> {
        let OracleQueryInstance {
            oracle_instance,
            point,
            eval: expected_eval,
        } = instance;

        let (prover_evals, []) = transcript.receive_message(|proof| proof.clone(), &proof)?;
        let ProverEvals(prover_evals) = prover_evals;

        assert_eq!(prover_evals.len(), key.oracle1_evals + key.oracle2_evals);

        let instance1 = prover_evals[0..key.oracle1_evals].to_vec();
        let instance2 = prover_evals[key.oracle1_evals..].to_vec();

        let mut prover_evals = prover_evals.into_iter();

        let evals1 = P1::evals(&oracle_instance.oracle1_instance, &point);
        let evals1 = evals1.flatten_vec().into_iter().map(|eval| match eval {
            OracleEval::Computed(e) => Some(e),
            // This Some(x.unwrap()) is desired in this case.
            OracleEval::ProverProvided => Some(prover_evals.next().unwrap()),
            OracleEval::None => None,
        });
        let evals1 = SF::Mles::unflatten_vec(evals1.collect());
        assert_eq!(prover_evals.len(), key.oracle2_evals);

        let evals2 = P2::evals(&oracle_instance.oracle2_instance, &point);
        let evals2 = evals2.flatten_vec().into_iter().map(|eval| match eval {
            OracleEval::Computed(e) => Some(e),
            OracleEval::ProverProvided => Some(prover_evals.next().unwrap()),
            OracleEval::None => None,
        });
        let evals2 = SF::Mles::unflatten_vec(evals2.collect());

        let natures = SF::natures();
        let evals = SF::combine3([&evals1, &evals2], &natures, |eval1, eval2, nature| {
            match (eval1, eval2, nature) {
                // (None, None, Either::Left(_)) => todo!(),
                // (None, None, Either::Right(_)) => todo!(),
                // (None, Some(_), Either::Left(_)) => todo!(),
                (None, Some(e), Either::Right(_)) => *e,
                (Some(e), None, Either::Left(_)) => *e,
                // (Some(_), None, Either::Right(_)) => todo!(),
                // (Some(_), Some(_), Either::Left(_)) => todo!(),
                // (Some(_), Some(_), Either::Right(_)) => todo!(),
                _ => panic!("Incorrect oracle answered query, or correct oracle fail to answer"),
            }
        });
        assert_eq!(prover_evals.len(), 0);

        let eval = key.f.function(&evals);

        if eval == expected_eval {
            let instance1 = PartialQueryInstance::new(instance1, oracle_instance.oracle1_instance);
            let instance2 = PartialQueryInstance::new(instance2, oracle_instance.oracle2_instance);
            Ok((instance1, instance2))
        } else {
            todo!()
        }
    }
}
