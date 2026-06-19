//! ZeroCheck example and test, 2 instances are created, folded and the
//! folded instance is proved and verified.

use crate::{
    folding::{prover::SumFoldProverOutput, zerofold::ZeroFold, SumFold, SumFoldInstance},
    polynomials::{simple_eval::SimpleEval, MultiPoint},
    sumcheck::{
        CommitType, Env, EvalKind, NoChallIdx, NoChallenges, ProverOutput, Sum, SumcheckFunction,
        SumcheckProver, SumcheckVerifier, Var,
    },
    zerocheck::{CompactPowers, ZeroCheckIdx, ZeroCheckMles},
};
use ark_ff::Field;
use sponge::sponge::UnsafeSponge;
use std::fmt::Debug;
use transcript::{
    instances::PolyEvalCheck, params::ParamResolver, protocols::Reduction, MessageGuard,
    TranscriptBuilder, TranscriptGuard,
};

// Folding zerocheck currently requires defining 2 functions, one
// for sumcheck and the other for sumfold.

/// To be proved with sumcheck.
struct ZeroCheckWrapped;

type Evals<V> = ZeroCheckMles<V, SimpleEval<V, 3>>;

/// The kind could be anything, it isn't relevant for this test.
const fn kinds() -> Evals<EvalKind> {
    let inner = SimpleEval::new([EvalKind::Committed(CommitType::Instance); 3]);
    ZeroCheckMles::new(EvalKind::Virtual, inner)
}

impl<F: Field> SumcheckFunction<F> for ZeroCheckWrapped {
    type Idx = ZeroCheckIdx<usize>;

    type Mles<V: Copy + Debug> = Evals<V>;

    type Challs = NoChallenges<F>;

    type ChallIdx = NoChallIdx;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        evals.map(&f, |inner| inner.map(&f))
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(env: E) -> V {
        let a = env.get(ZeroCheckIdx::Inner(0));
        let b = env.get(ZeroCheckIdx::Inner(1));
        let c = env.get(ZeroCheckIdx::Inner(2));
        let z = env.get(ZeroCheckIdx::ZeroCheckChallenge);
        z * (a * b - c)
    }

    fn symbolic_function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        &self,
        env: E,
    ) -> Option<V> {
        let a = env.get(ZeroCheckIdx::Inner(0));
        let b = env.get(ZeroCheckIdx::Inner(1));
        let c = env.get(ZeroCheckIdx::Inner(2));
        let z = env.get(ZeroCheckIdx::ZeroCheckChallenge);
        Some(z * (a * b - c))
    }
}

// To be fold by sumfold.
struct ZeroCheckInner;

impl<F: Field> SumcheckFunction<F> for ZeroCheckInner {
    type Idx = usize;

    type Mles<V: Copy + Debug> = SimpleEval<V, 3>;

    type Challs = NoChallenges<F>;

    type ChallIdx = NoChallIdx;

    const KINDS: Self::Mles<EvalKind> = SimpleEval::new([EvalKind::Virtual; 3]);

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B,
    {
        evals.map(f)
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(env: E) -> V {
        let a = env.get(0);
        let b = env.get(1);
        let c = env.get(2);
        a * b - c
    }

    fn symbolic_function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        &self,
        env: E,
    ) -> Option<V> {
        let a = env.get(0);
        let b = env.get(1);
        let c = env.get(2);
        Some(a * b - c)
    }
}

const VARS: usize = 5;

#[derive(Clone)]
struct InstanceWitness<F: Field> {
    witness: Vec<Evals<F>>,
    powers: CompactPowers<F>,
}

fn sample_instance_witness<F: Field>(elems: Vec<F>) -> InstanceWitness<F> {
    assert!(elems.len() > (1 << VARS) * 2);
    let mut evals = vec![];
    let mut elems = elems.into_iter();
    let chall = elems.next().unwrap();
    let compact_powers = CompactPowers::new(chall, VARS) * F::from(3u8);
    let mut powers = compact_powers.clone().eval_over_domain().into_iter();
    for _ in 0..(1 << VARS) {
        let a = elems.next().unwrap();
        let b = elems.next().unwrap();
        let c = a * b;
        let inner = SimpleEval::new([a, b, c]);
        let z = powers.next().unwrap();
        evals.push(Evals::new(z, inner));
    }
    InstanceWitness {
        witness: evals,
        powers: compact_powers,
    }
}

fn check_pair<F: Field>(pair: InstanceWitness<F>, sum: F) {
    let InstanceWitness { witness, powers } = pair;
    prove_and_verify(powers, witness, sum);
}

fn test<F: Field>(random_elements: Vec<F>) {
    let mut elements = random_elements.into_iter();

    let pair1 = sample_instance_witness::<F>(elements.by_ref().take((1 << VARS) * 2 + 1).collect());
    let pair2 = sample_instance_witness::<F>(elements.by_ref().take((1 << VARS) * 2 + 1).collect());

    check_pair(pair1.clone(), F::zero());
    check_pair(pair2.clone(), F::zero());

    let zerofold: ZeroFold<F, ZeroCheckInner> = ZeroFold::new(ZeroCheckInner, VARS);

    let (witness, sum, folder) = {
        let transcript_desc = TranscriptBuilder::new(VARS, ParamResolver::new())
            .add_reduction_pattern::<F, SumFold<F, _>>(zerofold.sumfold_key())
            .finish::<F, UnsafeSponge<F>>();

        let instance = SumFoldInstance::new([F::zero(), F::zero()]);
        let sums = Some(instance);
        let w1 = pair1.witness.iter().map(|e| *e.inner()).collect();
        let w2 = pair2.witness.iter().map(|e| *e.inner()).collect::<Vec<_>>();

        let powers = [pair1.powers.clone(), pair2.powers.clone()];
        let mut transcript = transcript_desc.instantiate();
        let SumFoldProverOutput {
            instance,
            folded_witness,
            proof,
            folder,
            sum,
        } = zerofold.fold_zerocheck(
            w1,
            w2.as_slice(),
            sums,
            powers,
            NoChallenges::default(),
            &mut transcript,
        );
        transcript.finish_unchecked();

        let mut transcript = transcript_desc.instantiate();
        let transcript_guard = TranscriptGuard::new(&mut transcript, proof);
        let instance = MessageGuard::new(instance);

        //TODO: compare folder from prover and verifier.
        let (instance, _) =
            SumFold::verify_reduction(zerofold.sumfold_key(), instance, transcript_guard).unwrap();
        assert_eq!(sum, instance.0);
        transcript.finish_unchecked();
        (folded_witness, instance, folder)
    };

    let powers = folder.fold_powers(pair1.powers, pair2.powers);
    let folded_powers = powers.eval_over_domain().into_iter();
    let witness = witness
        .into_iter()
        .zip(folded_powers)
        .map(|(e, p)| ZeroCheckMles::new(p, e))
        .collect();

    let pair = InstanceWitness { witness, powers };

    check_pair(pair, sum.0);
}

#[test]
fn fold_zerocheck() {
    use ark_ff::UniformRand;
    use ark_vesta::Fr;
    use rand::{rngs::StdRng, SeedableRng};
    use std::iter::repeat;

    let mut rng = StdRng::seed_from_u64(0);
    let elems = repeat(()).map(|_| Fr::rand(&mut rng));
    let elems = elems.take((1 << VARS) * 4 + 2).collect();
    test(elems);
}

pub fn prove_and_verify<F: Field>(powers: CompactPowers<F>, mle: Vec<Evals<F>>, sum: F) {
    let prover = SumcheckProver::<F, ZeroCheckWrapped>::new_symbolic(VARS, &ZeroCheckWrapped);
    let verifier = SumcheckVerifier::<F, ZeroCheckWrapped>::new_symbolic(ZeroCheckWrapped, VARS);

    let transcript_desc = TranscriptBuilder::new(VARS, ParamResolver::new())
        .add_reduction_pattern::<F, SumcheckVerifier<F, ZeroCheckWrapped>>(&verifier)
        .finish::<F, UnsafeSponge<F>>();

    let reduced = {
        let mut transcript = transcript_desc.instantiate();
        let reduced = prover
            .prove_zerocheck(
                powers.clone(),
                &mut transcript,
                mle,
                &NoChallenges::default(),
            )
            .unwrap();
        transcript.finish().unwrap();
        reduced
    };
    let ProverOutput { proof, evals, .. } = reduced;

    let mut transcript = transcript_desc.instantiate();
    let instance = MessageGuard::new(Sum(sum));

    let reduced = SumcheckVerifier::verify_reduction(&verifier, instance, transcript.guard(proof));
    transcript.finish_unchecked();
    let PolyEvalCheck { vars, eval } = reduced.unwrap();
    let point = MultiPoint::new(vars);

    let inner = *evals.inner();
    let powers_eval = powers.point_eval(&point);
    let evals = ZeroCheckMles::new(powers_eval, inner);

    let checks = verifier.check_evals_at_r(evals, eval, &NoChallenges::default());
    assert!(checks);
}

// Test that prove_zerocheck (the prover the FLCS reduction relies on) folds down
// to the correct evaluation by comparison with an algorithmically independent evaluation
// using EvalsExt::eval at the challenge point the prover produced.
// Note that the prove_and_verify above only feeds the provers own evals.inner()
// back into check_evals_at_r.
#[test]
fn zerocheck_eval_matches_mle() {
    use crate::polynomials::EvalsExt;
    use ark_ff::UniformRand;
    use ark_vesta::Fr;
    use rand::{rngs::StdRng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(7);
    let mut elem = || Fr::rand(&mut rng);

    // Build a random inner MLE (a, b, c per hypercube point) and the zerocheck wrapped MLE.
    let powers = CompactPowers::new(elem(), VARS);
    let mut inner_mles: Vec<SimpleEval<Fr, 3>> = Vec::with_capacity(1 << VARS);
    let mut witness: Vec<Evals<Fr>> = Vec::with_capacity(1 << VARS);
    for z in powers.eval_over_domain() {
        // We are only testing eval plumbing, not the zero property, so a * b != c here
        let inner = SimpleEval::new([elem(), elem(), elem()]);
        inner_mles.push(inner);
        witness.push(Evals::new(z, inner));
    }

    // Run the zerocheck prover to get its evaluation of inner MLE at the challenge point (actual result)
    let prover = SumcheckProver::<Fr, ZeroCheckWrapped>::new_symbolic(VARS, &ZeroCheckWrapped);
    let verifier = SumcheckVerifier::<Fr, ZeroCheckWrapped>::new_symbolic(ZeroCheckWrapped, VARS);
    let mut transcript = TranscriptBuilder::new(VARS, ParamResolver::new())
        .add_reduction_pattern::<Fr, SumcheckVerifier<Fr, ZeroCheckWrapped>>(&verifier)
        .finish::<Fr, UnsafeSponge<Fr>>()
        .instantiate();
    let actual_output = prover
        .prove_zerocheck(powers, &mut transcript, witness, &NoChallenges::default())
        .unwrap();
    transcript.finish().unwrap();

    // Independent evaluations of the inner MLE at the same challenge point (expected result)
    let expected_eval1 = EvalsExt::eval(&inner_mles[..], actual_output.point.clone());

    assert_eq!(
        actual_output.evals.inner().inner(),
        expected_eval1.inner(),
        "The prove_zerocheck inner eval disagrees with independent MLE eval at the challenge point"
    );

    // Also check consistency of MLE evaluators
    let expected_eval2 = EvalsExt::eval_slow(inner_mles, actual_output.point);

    assert_eq!(
        expected_eval1.inner(),
        expected_eval2.inner(),
        "EvalsExt::eval and EvalsExt::eval_slow disagree at the challenge point (MLE evaluators are inconsistent)"
    );
}
