use crate::{
    folding::prover::SumFoldProverOutput,
    polynomials::simple_eval::SimpleEval,
    sumcheck::{Env, EvalKind, NoChallIdx, NoChallenges, SumcheckVerifier, Var},
};
use rand::{rngs::StdRng, SeedableRng};
use sponge::sponge::UnsafeSponge;
use transcript::{protocols::Reduction, MessageGuard, TranscriptBuilder};

use super::*;

const VARS: usize = 4;

fn fold_and_prove<F: Field, SF>(sums: [F; 2], witnesses: [Vec<SF::Mles<F>>; 2], f: SF)
where
    SF: SumcheckFunction<F, Challs = NoChallenges<F>> + Copy,
{
    let [w1, w2] = witnesses;

    // checking sumcheck individually
    {
        check_sumcheck::<F, SF>(sums[0], w1.clone(), f);
        check_sumcheck::<F, SF>(sums[1], w2.clone(), f);
    }

    let sumfold_key = SumFold::<F, _>::new(&f);

    let transcript_desc = TranscriptBuilder::new(VARS, ParamResolver::new())
        .add_reduction_pattern::<F, SumFold<F, _>>(&sumfold_key)
        .finish::<F, UnsafeSponge<F>>();

    let (w3, instance) = {
        let mut transcript = transcript_desc.instantiate();
        let instance = SumFoldInstance::new([sums[0], sums[1]]);
        let SumFoldProverOutput {
            instance,
            folded_witness,
            proof,
            ..
        } = sumfold_key.fold(
            w1,
            &w2,
            Some(instance),
            &mut transcript,
            NoChallenges::default(),
        );
        transcript.finish_unchecked();

        let mut transcript = transcript_desc.instantiate();
        let instance = MessageGuard::new(instance);
        let reduced =
            SumFold::verify_reduction(&sumfold_key, instance, transcript.guard(proof)).unwrap();
        transcript.finish_unchecked();
        (folded_witness, reduced.0)
    };
    check_sumcheck::<F, SF>(instance.0, w3, f);
}

#[cfg(test)]
fn check_sumcheck<F, SF>(sum: F, witness: Vec<SF::Mles<F>>, f: SF)
where
    F: Field,
    SF: SumcheckFunction<F, Challs = NoChallenges<F>> + Copy,
{
    let vars = VARS;
    let prover = SumcheckProver::<F, SF>::new(vars);
    let verifier = SumcheckVerifier::new_symbolic(f, vars);
    let builder = TranscriptBuilder::new(vars, ParamResolver::new());
    let transcript_desc = SumcheckVerifier::<F, SF>::transcript_pattern(&verifier, builder)
        .finish::<F, UnsafeSponge<F>>();

    let out = {
        let mut transcript = transcript_desc.instantiate();
        let out = prover
            .prove(&mut transcript, witness, &NoChallenges::default())
            .unwrap();
        transcript.finish_unchecked();
        out
    };

    let reduced = {
        let mut transcript = transcript_desc.instantiate();
        let instance = MessageGuard::new(Sum(sum));

        let reduced =
            SumcheckVerifier::verify_reduction(&verifier, instance, transcript.guard(out.proof))
                .unwrap();
        transcript.finish_unchecked();
        reduced
    };
    let checks = verifier.check_evals_at_r(out.evals, reduced.eval, &NoChallenges::default());
    assert!(checks);
}

/// A fake zero check with rows like a * b - c = 0.
#[derive(Clone, Copy)]
struct Product;

const fn kinds() -> SimpleEval<EvalKind, 3> {
    SimpleEval::new([EvalKind::Virtual; 3])
}

impl<F: Field> SumcheckFunction<F> for Product {
    type Idx = usize;

    type Mles<V: Copy + std::fmt::Debug> = SimpleEval<V, 3>;

    type Challs = NoChallenges<F>;

    type ChallIdx = NoChallIdx;

    const KINDS: Self::Mles<EvalKind> = kinds();

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + std::fmt::Debug,
        B: Copy + std::fmt::Debug,
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

#[test]
fn sumfold_product() {
    use ark_ff::{UniformRand, Zero};
    use ark_vesta::Fr;

    let vars = VARS;
    let mut rng = StdRng::seed_from_u64(0);

    let mut w: Vec<SimpleEval<Fr, 3>> = vec![];
    for _ in 0..(1 << (vars + 1)) {
        let a: Fr = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let c = a * b;
        let eval = SimpleEval::new([a, b, c]);
        w.push(eval);
    }
    let mut w = w.into_iter();
    let w1 = w.by_ref().take(1 << vars).collect::<Vec<_>>();
    let w2 = w.by_ref().take(1 << vars).collect::<Vec<_>>();

    fold_and_prove::<Fr, Product>([Fr::zero(); 2], [w1, w2], Product);
}

#[derive(Clone, Copy)]
struct InnerProduct;

impl<F: Field> SumcheckFunction<F> for InnerProduct {
    type Idx = usize;

    type Mles<V: Copy + std::fmt::Debug> = SimpleEval<V, 2>;

    type Challs = NoChallenges<F>;

    type ChallIdx = NoChallIdx;

    const KINDS: Self::Mles<EvalKind> = SimpleEval::new([EvalKind::Virtual; 2]);

    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + std::fmt::Debug,
        B: Copy + std::fmt::Debug,
        M: Fn(A) -> B,
    {
        evals.map(f)
    }

    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(env: E) -> V {
        let a = env.get(0);
        let b = env.get(1);
        a * b
    }

    fn symbolic_function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        &self,
        env: E,
    ) -> Option<V> {
        let a = env.get(0);
        let b = env.get(1);
        Some(a * b)
    }
}

#[test]
fn sumfold_inner_product() {
    use ark_ff::{UniformRand, Zero};
    use ark_vesta::Fr;

    let vars = VARS;
    let mut rng = StdRng::seed_from_u64(0);

    let mut w = vec![];
    for _ in 0..(1 << (vars + 1)) {
        let a: Fr = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        w.push([a, b]);
    }
    let mut w = w.into_iter();
    let w1 = w.by_ref().take(1 << vars).collect::<Vec<_>>();
    let s1 = w1
        .iter()
        .fold(Fr::zero(), |acc, eval| acc + eval[0] * eval[1]);
    let w2 = w.by_ref().take(1 << vars).collect::<Vec<_>>();
    let s2 = w2
        .iter()
        .fold(Fr::zero(), |acc, eval| acc + eval[0] * eval[1]);

    let w1: Vec<SimpleEval<Fr, 2>> = w1.into_iter().map(SimpleEval::new).collect();
    let w2: Vec<SimpleEval<Fr, 2>> = w2.into_iter().map(SimpleEval::new).collect();

    fold_and_prove::<Fr, InnerProduct>([s1, s2], [w1, w2], InnerProduct);
}
