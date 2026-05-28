use crate::instances::{
    flcs::{
        key::FlcsReductionKey,
        sumcheck_reduction::{ConstraintCombinationChallenge, LcsMles, LcsSumcheck},
        FoldableLcsInstance,
    },
    linearized::LinearizedInstance,
};
use ark_ff::Field;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use sumcheck::{
    polynomials::{Evals, MultiPoint},
    sumcheck::{Sum, SumcheckFunction, SumcheckVerifier},
    zerocheck::ZeroCheckMles,
};
use transcript::{
    instances::PolyEvalCheck, messages::SingleElement, protocols::Reduction, MessageGuard,
    TranscriptGuard,
};

/// Proof for the LCS -> Linearized reduction.
#[derive(Debug, Clone)]
pub struct FlcsReductionProof<F: Field, const IO: usize, const S: usize> {
    sumcheck: sumcheck::sumcheck::Proof<F, LcsSumcheck<F, IO, S>>,
    selector_evals: [F; S],
    witness_eval: F,
    products: [F; IO],
    constants_eval: F,
}

impl<F: Field, const IO: usize, const S: usize> FlcsReductionProof<F, IO, S> {
    pub(crate) fn new(
        sumcheck: sumcheck::sumcheck::Proof<F, LcsSumcheck<F, IO, S>>,
        selector_evals: [F; S],
        witness_eval: F,
        products: [F; IO],
        constants_eval: F,
    ) -> Self {
        Self {
            sumcheck,
            selector_evals,
            witness_eval,
            products,
            constants_eval,
        }
    }
}

pub struct FlcsReduction<C, const I: usize, const IO: usize, const S: usize>(PhantomData<C>);

impl<F, C, const I: usize, const IO: usize, const S: usize> Reduction<F>
    for FlcsReduction<C, I, IO, S>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = FoldableLcsInstance<F, C, I>;

    type B = LinearizedInstance<F, C, IO, S>;

    type Key = FlcsReductionKey<F, IO, S>;

    type Proof = FlcsReductionProof<F, IO, S>;

    type Error = crate::Error<F, C>;

    fn transcript_pattern(
        key: &Self::Key,
        builder: transcript::TranscriptBuilder,
    ) -> transcript::TranscriptBuilder {
        let sumcheck_verifier = &key.sumcheck_verifier;
        builder
            .round::<F, Self::A, 1>()
            .add_reduction_pattern::<F, SumcheckVerifier<F, LcsSumcheck<F, IO, S>>>(
                sumcheck_verifier,
            )
            // selectors, w, constants, products
            .round::<F, [SingleElement<F>; S], 0>()
            .round::<F, SingleElement<F>, 0>()
            .round::<F, SingleElement<F>, 0>()
            .round::<F, [SingleElement<F>; IO], 0>()
    }

    fn verify_reduction<D: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, D, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        // Unwrap isntance, get challenge for sumcheck.
        let (lcs_instance, [sumcheck_chall]) = transcript.unwrap_guard(instance)?;
        let FoldableLcsInstance {
            witness_commit,
            public_inputs,
            zerocheck_powers,
            sum,
        } = lcs_instance;

        let sumcheck_verifier = &key.sumcheck_verifier;
        let sumcheck_instance = MessageGuard::new(Sum(sum));

        // Receive sumcheck proof.
        let proof = transcript.receive_message_delayed(|p| p.sumcheck.clone());
        // Verifying sumcheck proof, reducing instance to point eval check.
        let check: PolyEvalCheck<F> = SumcheckVerifier::verify_reduction(
            sumcheck_verifier,
            sumcheck_instance,
            transcript.new_guard(proof),
        )?;

        // Point where to evaluate the sumcheck polynomial.
        let check_point = MultiPoint::new(check.vars.clone());

        // Assembling different types of evals into a single one.
        let evals: ZeroCheckMles<F, LcsMles<F, IO, S>> = {
            let small_evals_inner: LcsMles<Option<F>, IO, S> =
                LcsMles::<Option<F>, IO, S>::small_evals(
                    check_point.clone(),
                    public_inputs.to_vec(),
                );
            let zerocheck_eval = Some(zerocheck_powers.point_eval(&check_point));
            let small_evals = ZeroCheckMles::new(zerocheck_eval, small_evals_inner);

            // Committed evals provided by prover and verification deferred
            // to the linearized instance.
            let (selector_evals, []) =
                transcript.receive_message(|proof| proof.selector_evals.map(SingleElement))?;
            let (w_eval, []) =
                transcript.receive_message(|proof| SingleElement(proof.witness_eval))?;
            let (constants_eval, []) =
                transcript.receive_message(|proof| SingleElement(proof.constants_eval))?;
            let committed_evals_inner = LcsMles::from_committed_evals(
                w_eval.0,
                selector_evals.map(SingleElement::inner),
                constants_eval.0,
            );
            let committed_evals = ZeroCheckMles::new(None, committed_evals_inner);

            let evals = committed_evals.combine(&small_evals, Option::xor);

            // Matrix evals are just received from the prover, a linearized instance
            // is create to verify them later.
            let (products, []) = transcript.receive_message(|proof| {
                let products = proof.products;
                products.map(SingleElement)
            })?;

            let products: [F; IO] = products.map(SingleElement::inner);

            let products_inner = LcsMles::new_only_products(products);
            let products = ZeroCheckMles::new(None, products_inner);
            let evals = products.combine(&evals, Option::xor);
            LcsSumcheck::<F, IO, S>::map_evals(evals, Option::unwrap)
        };

        // Instance to be verified for the matrix evals.
        let linearized_instance: LinearizedInstance<F, C, IO, S> = {
            let products: [F; IO] = *evals.inner().products();
            let rx = check_point;
            let selector_evals = *evals.inner().gate_selectors();
            let witness_eval = *evals.inner().w();
            let constants = *evals.inner().constants();
            LinearizedInstance {
                witness_commit,
                witness_eval,
                rx,
                products,
                selector_evals,
                constants,
            }
        };

        let evals: ZeroCheckMles<F, LcsMles<F, IO, S>> = evals;
        let challs = ConstraintCombinationChallenge::from(sumcheck_chall);

        // Check evaluation on the point.
        let checks = sumcheck_verifier.check_evals_at_r_symbolic(evals, check.eval, &challs);
        if !checks {
            return Err(crate::Error::EvalCheck);
        }

        Ok(linearized_instance)
    }
}
