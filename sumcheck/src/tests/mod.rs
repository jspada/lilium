use crate::{
    polynomials::{EvalsExt, MultiPoint},
    sumcheck::{DegreeParam, Sum, SumcheckFunction, SumcheckProver, SumcheckVerifier},
};
use ark_ff::Field;
use sponge::{permutation::UnsafePermutation, sponge::Sponge};
use transcript::{
    instances::PolyEvalCheck, params::ParamResolver, protocols::Reduction, MessageGuard,
    Transcript, TranscriptBuilder, TranscriptDescriptor, TranscriptGuard,
};

#[cfg(test)]
mod mul_square;
#[cfg(test)]
mod sum_of_products;
#[cfg(test)]
mod zero_check;

pub type TestSponge<F> = Sponge<F, UnsafePermutation<F, 3>, 2, 1, 3>;

pub fn sumcheck_transcript<F, SF>(
    key: &SumcheckVerifier<F, SF>,
    vars: usize,
) -> TranscriptDescriptor<F, TestSponge<F>>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    let degree = crate::sumcheck::sumcheck_degree::<F, SF>();
    let resolver = ParamResolver::new().set::<DegreeParam>(degree);
    let transcript_builder = TranscriptBuilder::new(vars, resolver);
    SumcheckVerifier::<F, SF>::transcript_pattern(key, transcript_builder).finish()
}

/// Creates a prove with the mle and tries to verify it.
/// Returns evals and point to double check if desired.
pub fn prove_and_verify<F, SF>(
    mle: Vec<SF::Mles<F>>,
    sum: F,
    challs: SF::Challs,
) -> (SF::Mles<F>, MultiPoint<F>)
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    let vars = mle.len().ilog2() as usize;

    let verifier = SumcheckVerifier::<F, SF>::new(vars);

    let transcript_desc = sumcheck_transcript::<F, SF>(&verifier, vars);

    let prover = SumcheckProver::<F, SF>::new(vars);
    let mut transcript: Transcript<F, TestSponge<F>> = transcript_desc.instantiate();
    let proof = prover
        .prove(&mut transcript, mle.clone(), &challs)
        .unwrap()
        .proof;
    transcript.finish().unwrap();

    let instance = MessageGuard::new(Sum(sum));
    let mut transcript = transcript_desc.instantiate();
    let check = {
        let transcript = TranscriptGuard::new(&mut transcript, proof);
        SumcheckVerifier::verify_reduction(&verifier, instance, transcript).unwrap()
    };
    transcript.finish().unwrap();

    let PolyEvalCheck { vars, eval } = check;
    let r = MultiPoint::new(vars);

    let evals = EvalsExt::eval(&mle, r.clone());
    assert!(verifier.check_evals_at_r(evals.clone(), eval, &challs));
    (evals, r)
}
