use crate::{
    batching::{
        multipoint::{MultipointBatching, MultipointChall, MultipointEvals},
        BatchingError,
    },
    CommmitmentScheme, OpenInstance,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use sumcheck::{
    polynomials::MultiPoint,
    sumcheck::{Proof, Sum, SumcheckVerifier},
};
use transcript::{
    instances::PolyEvalCheck, messages::SingleElement, protocols::Reduction, MessageGuard,
    TranscriptBuilder, TranscriptGuard,
};

#[derive(Clone, Debug)]
pub struct BatchingProof<F: Field, C, const N: usize> {
    sumcheck_proof: Proof<F, MultipointBatching<C, N>>,
    evals: [F; N],
}

impl<F: Field, C, const N: usize> BatchingProof<F, C, N> {
    pub(crate) fn new(sumcheck_proof: Proof<F, MultipointBatching<C, N>>, evals: [F; N]) -> Self {
        Self {
            sumcheck_proof,
            evals,
        }
    }
}

impl<F, C, const N: usize> Reduction<F> for MultipointBatching<C, N>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = [OpenInstance<F, C::Commitment>; N];

    type B = OpenInstance<F, C::Commitment>;

    type Key = SumcheckVerifier<F, MultipointBatching<C, N>>;

    type Proof = BatchingProof<F, C, N>;

    type Error = BatchingError<F, C>;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        builder
            .round::<F, Self::A, 1>()
            .add_reduction_pattern::<F, Self::Key>(key)
            .round::<F, [SingleElement<F>; N], 1>()
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, [chall]) = transcript.unwrap_guard(instance)?;

        let sum = instance
            .iter()
            .fold(F::zero(), |acc, open| acc * chall + open.eval);

        let sum = MessageGuard::new(Sum(sum));

        let sumcheck_proof =
            transcript.receive_message_delayed(|proof| proof.sumcheck_proof.clone());

        let reduced =
            SumcheckVerifier::verify_reduction(key, sum, transcript.new_guard(sumcheck_proof))?;
        let PolyEvalCheck { eval, vars } = reduced;
        let r = MultiPoint::new(vars);
        let eq_evals = instance.each_ref().map(|open| open.point.eval_as_eq(&r));

        let (poly_evals, [combination_challenge]) =
            transcript.receive_message(|proof| proof.evals.map(SingleElement))?;
        let poly_evals = poly_evals.map(|x| x.0);

        let mut evals = eq_evals.map(|eq| MultipointEvals {
            eq,
            poly: F::zero(),
        });

        for (i, eval) in evals.iter_mut().enumerate() {
            eval.poly = poly_evals[i];
        }

        let challs = MultipointChall(chall);
        let checks = key.check_evals_at_r_symbolic(evals, eval, &challs);

        assert!(checks);
        if !checks {
            return Err(BatchingError::EvalCheck);
        }

        let chall = combination_challenge;

        let mut evals_and_commits = poly_evals
            .into_iter()
            .zip(instance)
            .map(|(eval, open)| (eval, open.commit));
        let first = evals_and_commits.next().unwrap();
        let (eval, commit) = evals_and_commits.fold(first, |acc, e| {
            let eval = acc.0 * chall + e.0;
            let commit = acc.1 * chall + e.1;
            (eval, commit)
        });

        Ok(OpenInstance::new(commit, r, eval))
    }
}
