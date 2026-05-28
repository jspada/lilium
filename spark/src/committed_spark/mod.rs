use crate::{
    challenges::SparkChallenges, evals::SparkEval, spark::SparkEvalCheck, structure::SparkStructure,
};
use ark_ff::Field;
use commit::{
    batching::{structured::StructuredBatchEval, BatchEval, BatchingError},
    committed_structure::CommittedStructure,
    CommmitmentScheme, OpenInstance,
};
use sponge::sponge::Duplex;
use std::rc::Rc;
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::{Sum, SumcheckFunction, SumcheckVerifier},
    SumcheckError,
};
use transcript::{
    messages::SingleElement, params::ParamResolver, protocols::Reduction, Message, MessageGuard,
    TranscriptGuard,
};

mod prove;

pub use prove::ProverOutput;

//TODO: add prover for the reduction

#[derive(Clone, Debug)]
pub struct CommittedSpark<F: Field, C: CommmitmentScheme<F>, const D: usize> {
    committed_structure: CommittedStructure<F, SparkEvalCheck<D>, C>,
    structure: Rc<SparkStructure<F, D>>,
    sumcheck_verifier: SumcheckVerifier<F, SparkEvalCheck<D>>,
}

pub struct CommittedSparkInstance<F: Field, const D: usize> {
    pub point: [MultiPoint<F>; D],
    pub eval: F,
}

impl<F: Field, const D: usize> CommittedSparkInstance<F, D> {
    pub fn new(point: [MultiPoint<F>; D], eval: F) -> Self {
        Self { point, eval }
    }
}

impl<F: Field, const D: usize> Message<F> for CommittedSparkInstance<F, D> {
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        8 * D + 1
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = Vec::with_capacity(8 * D + 1);
        elems.extend(self.point.iter().cloned().flat_map(MultiPoint::inner));
        elems.resize(8 * D, F::zero());
        elems.push(self.eval);
        elems
    }
}

type StructureEvals<F, const D: usize> = ([[F; 2]; D], [F; 2]);
type InstanceEvals<F, const D: usize> = [[F; 3]; D];

#[derive(Debug, Clone)]
pub struct CommittedSparkProof<F: Field, C: CommmitmentScheme<F>, const D: usize> {
    eq_lookup_commitments: [C::Commitment; D],
    fraction_lookup_commitments: [[C::Commitment; 2]; D],
    sumcheck_proof: sumcheck::sumcheck::Proof<F, SparkEvalCheck<D>>,
    structure_evals: StructureEvals<F, D>,
    instance_evals: InstanceEvals<F, D>,
}

#[derive(Debug, Clone)]
pub enum Error<F: Field, C: CommmitmentScheme<F>> {
    Transcript(transcript::Error),
    Sumcheck(SumcheckError),
    Batching(BatchingError<F, C>),
    /// Final eval check at r failed
    EvalCheck,
}

impl<F: Field, C: CommmitmentScheme<F>> From<transcript::Error> for Error<F, C> {
    fn from(value: transcript::Error) -> Self {
        Self::Transcript(value)
    }
}

impl<F: Field, C: CommmitmentScheme<F>> From<SumcheckError> for Error<F, C> {
    fn from(value: SumcheckError) -> Self {
        Self::Sumcheck(value)
    }
}

impl<F: Field, C: CommmitmentScheme<F>> From<BatchingError<F, C>> for Error<F, C> {
    fn from(value: BatchingError<F, C>) -> Self {
        Self::Batching(value)
    }
}

impl<F, C, const D: usize> Reduction<F> for CommittedSpark<F, C, D>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = CommittedSparkInstance<F, D>;

    type B = OpenInstance<F, C::Commitment>;

    type Key = Self;

    type Proof = CommittedSparkProof<F, C, D>;

    type Error = Error<F, C>;

    fn transcript_pattern(
        key: &Self,
        builder: transcript::TranscriptBuilder,
    ) -> transcript::TranscriptBuilder {
        builder
            .round::<F, CommittedSparkInstance<F, D>, 0>()
            // eq_lookups commitments
            .round::<F, [C::Commitment; D], 2>()
            //other lookup commitments
            .point()
            .round::<F, [[C::Commitment; 2]; D], 1>()
            .add_reduction_pattern::<F, SumcheckVerifier<F, SparkEvalCheck<D>>>(
                &key.sumcheck_verifier,
            )
            .round::<F, InstanceEvals<SingleElement<F>, D>, 0>()
            .round::<F, StructureEvals<SingleElement<F>, D>, 0>()
            .add_reduction_pattern::<F, CommittedStructure<F, SparkEvalCheck<D>, C>>(
                &key.committed_structure,
            )
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: transcript::MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let vars = key.committed_structure.vars();
        let (instance, []) = transcript.unwrap_guard(instance)?;

        let (eq_lookup_commitments, [c1, c2]) =
            transcript.receive_message(|proof| proof.eq_lookup_commitments.clone())?;

        let zero_check_point = MultiPoint::new(transcript.point()?);

        let (fraction_lookup_commitments, [c3]) =
            transcript.receive_message(|proof| proof.fraction_lookup_commitments.clone())?;

        let challenges = SparkChallenges::new(c1, c3, c2);

        let CommittedSparkInstance { point, eval } = instance;
        assert_eq!(point[0].vars(), vars);
        let sumcheck_instance = MessageGuard::new(Sum(eval));

        let sumcheck_proof =
            transcript.receive_message_delayed(|proof| proof.sumcheck_proof.clone());

        let reduced = SumcheckVerifier::verify_reduction(
            &key.sumcheck_verifier,
            sumcheck_instance,
            transcript.new_guard(sumcheck_proof),
        )?;

        let r = MultiPoint::new(reduced.vars);
        let zero_eq_eval = zero_check_point.eval_as_eq(&r);
        let eq_evals = point.map(|x| x.eval_as_eq(&r));
        let small_evals = SparkEval::<F, D>::small_evals(zero_eq_eval, eq_evals);
        let instance = {
            let commitments: Vec<C::Commitment> = eq_lookup_commitments
                .into_iter()
                .zip(fraction_lookup_commitments)
                .flat_map(|(eq, [f1, f2])| [f1, f2, eq])
                .collect();
            let (instance_evals, []) = transcript
                .receive_message(|proof| proof.instance_evals.map(|x| x.map(SingleElement)))?;
            let (structure_evals, []) = transcript.receive_message(|proof| {
                let shared = proof.structure_evals.1.map(SingleElement);
                let per_dimension = proof.structure_evals.0.map(|x| x.map(SingleElement));
                (per_dimension, shared)
            })?;
            let commitments_and_evals: Vec<(C::Commitment, F)> = commitments
                .into_iter()
                .zip(instance_evals.into_iter().flatten().map(|x| x.0))
                .collect();
            let dynamic_batch = BatchEval::new(r, commitments_and_evals);
            let structure_evals: Vec<F> = structure_evals
                .0
                .into_iter()
                .flatten()
                .chain(structure_evals.1)
                .map(|x| x.0)
                .collect();
            let instance = StructuredBatchEval::new(dynamic_batch, structure_evals);
            MessageGuard::new(instance)
        };
        let (open_instance, evals) = CommittedStructure::verify_reduction(
            &key.committed_structure,
            instance,
            transcript.new_guard(()),
        )?;

        let evals = evals.combine(&small_evals, |committed, small| committed.xor(small));
        // shouldn't fail as lengths should be checked at this point
        let evals: SparkEval<F, D> =
            <SparkEvalCheck<D> as SumcheckFunction<F>>::map_evals(evals, Option::unwrap);

        let checks = key
            .sumcheck_verifier
            .check_evals_at_r(evals, reduced.eval, &challenges);
        if checks {
            Ok(open_instance)
        } else {
            Err(Error::EvalCheck)
        }
    }
}

impl<F: Field, C: CommmitmentScheme<F>, const D: usize> CommittedSpark<F, C, D> {
    pub fn new(structure: Rc<SparkStructure<F, D>>, scheme: &C) -> Self {
        assert!(structure.val.len().is_power_of_two());
        let vars = structure.val.len().ilog2() as usize;

        let dummy_point = MultiPoint::new(vec![F::zero(); vars]);
        let points = [(); D].map(|_| dummy_point.clone());
        let challenges = SparkChallenges::default();
        let zero_check_point = dummy_point;

        let mles = SparkEval::<F, D>::evals(&structure, points, challenges, zero_check_point);

        let committed_structure = CommittedStructure::new(Rc::new(mles), scheme);
        let sumcheck_verifier: SumcheckVerifier<F, SparkEvalCheck<D>> = SumcheckVerifier::new(vars);

        Self {
            committed_structure,
            structure,
            sumcheck_verifier,
        }
    }
}
