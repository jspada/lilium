use crate::{
    polynomials::MultiPoint,
    sumcheck2::{
        oracles::{Oracle, QueryRelation, SumcheckFunction},
        OracleQueryInstance,
    },
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use transcript::reduction2::{
    Argument, GuardedProof, Message, ProverOutput, Reduction, Relation, Transcript,
    TranscriptBuilder, VerifierTranscript,
};

#[derive(Clone, Debug)]
/// An oracle over MLEs which have a small representation and
/// can be cheaply evluated over a point by the verifier.
pub struct SmallEvalOracle<F: Field, SF: SumcheckFunction<F>> {
    f: SF,
    evals_over_domain: Vec<SF::Mles<F>>,
    evals: SF::Mles<fn(&MultiPoint<F>) -> F>,
    vars: usize,
}

impl<F: Field, SF: SumcheckFunction<F>> SmallEvalOracle<F, SF> {
    pub fn new(
        f: SF,
        evals_over_domain: Option<Vec<SF::Mles<F>>>,
        evals: SF::Mles<fn(&MultiPoint<F>) -> F>,
        vars: usize,
    ) -> Self {
        let evals_over_domain = match evals_over_domain {
            Some(evals) => {
                assert_eq!(evals.len().ilog2() as usize, vars);
                evals
            }
            None => {
                // TODO: eval over domain
                todo!()
            }
        };
        Self {
            f,
            evals_over_domain,
            evals,
            vars,
        }
    }
}

impl<F: Field, SF: SumcheckFunction<F>> Oracle<F> for SmallEvalOracle<F, SF> {
    type Evals<V> = SF::Mles<V>;

    type Function = SF;

    type Instance = ();

    type Witness = ();

    fn mle(&self) -> &[Self::Evals<F>] {
        &self.evals_over_domain
    }

    fn function(&self) -> &Self::Function {
        &self.f
    }

    fn vars(&self) -> usize {
        self.vars
    }

    fn oracle_params(&self) -> <Self::Instance as Message<F>>::Params {}

    fn eval(&self, point: &MultiPoint<F>, _instance: &(), _witness: &()) -> Self::Evals<F> {
        SF::map_evals(&self.evals, |f| f(point))
    }

    fn witness_from_evals(_evals: &[Self::Evals<F>]) -> Self::Witness {}

    fn instance_evals(_instance: &()) -> Self::Evals<F> {
        Default::default()
    }
}

/// An argument for the QuertRelation over the small oracle.
pub struct SmallOracleArgument;

type Rel<F, SF> = QueryRelation<F, SmallEvalOracle<F, SF>>;

impl<F, SF> Reduction<F, Rel<F, SF>, ()> for SmallOracleArgument
where
    F: Field,
    SF: SumcheckFunction<F>,
    <Rel<F, SF> as Relation>::Instance: Message<F, Params = ((), usize)>,
{
    type ProverKey = SmallEvalOracle<F, SF>;

    type VerifierKey = SmallEvalOracle<F, SF>;

    type Proof = ();

    type Error = ();

    fn transcript_pattern(
        _key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        // It is essentially a non-interactive protocol.
        builder
    }

    fn verifier_key(structure_1: &SmallEvalOracle<F, SF>, _structure_2: &()) -> Self::VerifierKey {
        structure_1.clone()
    }

    fn instance_params(
        key: &Self::VerifierKey,
    ) -> <<Rel<F, SF> as Relation>::Instance as Message<F>>::Params
    where
        <Rel<F, SF> as Relation>::Instance: Message<F>,
    {
        let vars = key.vars;
        ((), vars)
    }

    fn key_pair(
        structure_1: &<Rel<F, SF> as Relation>::Structure,
        _structure_2: &<() as Relation>::Structure,
    ) -> (Self::VerifierKey, Self::ProverKey) {
        (structure_1.clone(), structure_1.clone())
    }

    fn prove<S: Duplex<F>>(
        _key: &Self::ProverKey,
        _instance: <Rel<F, SF> as Relation>::Instance,
        _witness: <Rel<F, SF> as Relation>::Witness,
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<(), Self::Proof> {
        ProverOutput {
            instance: (),
            witness: (),
            proof: (),
        }
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: OracleQueryInstance<F, ()>,
        _proof: GuardedProof<Self::Proof>,
        _transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<(), Self::Error> {
        match QueryRelation::check(key, &instance, &()) {
            true => Ok(()),
            false => Err(()),
        }
    }
}

impl<F, SF> Argument<F, Rel<F, SF>> for SmallOracleArgument
where
    F: Field,
    SF: SumcheckFunction<F>,
    <Rel<F, SF> as Relation>::Instance: Message<F, Params = ((), usize)>,
{
}
