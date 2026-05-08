use crate::instances::{
    lcs::LcsSumcheck,
    linearized::{
        sumcheck_argument::{LinearizedMles, LinearizedSumcheck, SingleChall},
        LinearizedInstance,
    },
    matrix_eval::BatchMatrixEvalInstance,
};
use ark_ff::Field;
use commit::{
    batching::{structured::StructuredBatchEval, BatchEval},
    committed_structure::CommittedStructure,
    CommmitmentScheme, OpenInstance,
};
use std::marker::PhantomData;
use sumcheck::{
    polynomials::MultiPoint,
    sumcheck::{Sum, SumcheckVerifier},
};
use transcript::{
    instances::PolyEvalCheck, messages::SingleElement, protocols::Reduction, MessageGuard,
};

pub(crate) struct LinearizedInstanceReduction<F, CS, const IO: usize, const S: usize>(
    PhantomData<(F, CS)>,
);

#[derive(Debug, Clone)]
pub struct LinearizedProof<F: Field, const IO: usize> {
    pub(crate) sumcheck_proof: sumcheck::sumcheck::Proof<F, LinearizedSumcheck<IO>>,
    pub(crate) w_eval: SingleElement<F>,
    pub(crate) matrix_evals: [SingleElement<F>; IO],
}

type Sumcheck<F, const IO: usize> = SumcheckVerifier<F, LinearizedSumcheck<IO>>;

impl<F, CS, const IO: usize, const S: usize> Reduction<F>
    for LinearizedInstanceReduction<F, CS, IO, S>
where
    F: Field,
    CS: CommmitmentScheme<F> + 'static,
{
    type A = LinearizedInstance<F, CS, IO, S>;

    type B = (
        BatchMatrixEvalInstance<F, IO>,
        [OpenInstance<F, CS::Commitment>; 2],
    );

    type Key = super::Key<F, CS, IO, S>;

    type Proof = LinearizedProof<F, IO>;

    type Error = crate::Error<F, CS>;

    fn transcript_pattern(
        key: &Self::Key,
        builder: transcript::TranscriptBuilder,
    ) -> transcript::TranscriptBuilder {
        //TODO: create once and store in key.
        let sumcheck_verifier = SumcheckVerifier::new(key.domain_vars);
        builder
            .round::<F, Self::A, 1>()
            .add_reduction_patter::<F, Sumcheck<F, IO>>(&sumcheck_verifier)
            .add_reduction_patter::<F, CommittedStructure<F, LcsSumcheck<F, IO, S>, CS>>(
                &key.selector_commitments,
            )
            .round::<F, SingleElement<F>, 0>()
            .round::<F, [SingleElement<F>; IO], 0>()
    }

    fn verify_reduction<D: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: transcript::MessageGuard<Self::A>,
        mut transcript: transcript::TranscriptGuard<F, D, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, [chall]) = transcript.unwrap_guard(instance)?;
        let LinearizedInstance {
            witness_commit,
            witness_eval,
            rx,
            products,
            selector_evals,
            constants,
        } = instance;

        let n_vars = key.domain_vars;

        let sum = products[1..]
            .iter()
            .fold(products[0], |acc, m| acc * chall + m);
        let sum = MessageGuard::new(Sum(sum));

        // Verifying sumcheck reduction to point evaluation check.
        let sumcheck_verifier = SumcheckVerifier::new(n_vars);
        let proof = transcript.receive_message_delayed(|proof| proof.sumcheck_proof.clone());
        let reduced = Sumcheck::<F, IO>::verify_reduction(
            &sumcheck_verifier,
            sum,
            transcript.new_guard(proof),
        )?;

        // Proving evaluations of selectors at rx.
        let dynamic_batch =
            BatchEval::new(rx.clone(), vec![(witness_commit.clone(), witness_eval)]);
        let mut structured_evals = selector_evals.to_vec();
        structured_evals.push(constants);
        let committed_open_instance: StructuredBatchEval<F, CS> =
            StructuredBatchEval::new(dynamic_batch, structured_evals);
        let instance = MessageGuard::new(committed_open_instance);

        let (open_instance_rx, evals) =
            CommittedStructure::<F, LcsSumcheck<F, IO, S>, CS>::verify_reduction(
                &key.selector_commitments,
                instance,
                transcript.new_guard(()),
            )
            .map_err(crate::Error::Batching)?;

        for (i, eval) in evals.gate_selectors().iter().enumerate() {
            debug_assert_eq!(eval.unwrap(), selector_evals[i]);
        }

        let PolyEvalCheck { vars, eval } = reduced;
        // this eval will have to be verified with the commitment
        let (SingleElement(w_eval), []) = transcript.receive_message(|proof| proof.w_eval).unwrap();
        let ry = MultiPoint::new(vars.clone());
        let open_instance_ry = OpenInstance::new(witness_commit, ry.clone(), w_eval);

        // Get claimed unverfied evals of each matrix in (rx, open_point), to
        // be checked later as one of the instances produced in this reduction.
        let (matrix_evals, []) = transcript.receive_message(|proof| proof.matrix_evals)?;
        let matrix_evals = matrix_evals.map(|x| x.0);
        // Evals M(rx,ry)
        let matrices = matrix_evals;
        let r_eval = rx.eval_as_eq(&ry);
        let evals_at_r = LinearizedMles::new(matrices, r_eval, w_eval);

        let chall = SingleChall(chall);
        let checks = sumcheck_verifier.check_evals_at_r(evals_at_r, eval, &chall);
        if !checks {
            return Err(crate::Error::EvalCheck);
        }

        // rx was given by the instance, and the second dimension results from sumcheck.
        let point = [rx, ry];

        Ok((
            BatchMatrixEvalInstance {
                matrix_evals,
                point,
            },
            [open_instance_rx, open_instance_ry],
        ))
    }
}
