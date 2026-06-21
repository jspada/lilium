use crate::{
    barycentric_eval::BarycentricWeights,
    folding::utils::FieldFolder,
    sumcheck2::{
        evals::Mles,
        folding::Foldable,
        oracles::Oracle,
        zerocheck::{ZeroSumcheck, ZeroSumcheckInstance},
        SumcheckError, SumcheckMessage,
    },
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::reduction2::{
    FoldingRelation, GuardedProof, ProverOutput, Reduction, Relation, Transcript,
    TranscriptBuilder, VerifierTranscript,
};

/// Folding scheme for zerocheck.
pub struct ZeroFold<F, O>(PhantomData<(F, O)>);

#[derive(Clone, Debug)]
pub struct ZeroFoldKey<F: Field, O: Oracle<F>> {
    // Weights for degree d.
    // weights: BarycentricWeights<F>,
    // Weights for degree d + 1.
    extended_weights: BarycentricWeights<F>,
    degree: usize,
    // f: O::Function,
    _o: PhantomData<O>,
}

impl<F, O> Reduction<F, FoldingRelation<ZeroSumcheck<F, O>>, ZeroSumcheck<F, O>> for ZeroFold<F, O>
where
    F: Field,
    O: Oracle<F>,
    O::Instance: Foldable<F>,
{
    type ProverKey = ZeroFoldKey<F, O>;

    type VerifierKey = ZeroFoldKey<F, O>;

    type Proof = SumcheckMessage<F>;

    type Error = SumcheckError;

    fn transcript_pattern(
        _key: &Self::VerifierKey,
        _builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        todo!()
    }

    fn verifier_key(_structure_1: &O, _structure_2: &O) -> Self::VerifierKey {
        todo!()
    }

    fn key_pair(_structure_1: &O, _structure_2: &O) -> (Self::VerifierKey, Self::ProverKey) {
        todo!()
    }

    fn prove<S: Duplex<F>>(
        _key: &Self::ProverKey,
        _instance: [ZeroSumcheckInstance<F, O>; 2],
        _witness: [Vec<Mles<O::Function, F>>; 2],
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<ZeroSumcheck<F, O>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: [ZeroSumcheckInstance<F, O>; 2],
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<<ZeroSumcheck<F, O> as Relation>::Instance, Self::Error> {
        let Ok((_, [beta])) = transcript.receive_message(|_| (), &GuardedProof::empty(), &());
        // eq(x,beta) = x * beta + (1-x) * (1-beta)
        // eq(0,beta) = 1 - beta
        // eq(1,beta) = beta
        let sum = (F::one() - beta) * instance[0].sum + beta * instance[1].sum;

        // A single sumcheck round, we get message from prover, generate challenge
        // r, check message agrees with original sum.
        // And then the work is reduced to a new sumcheck instance over the same polynomial
        // with 1 variable fixed with r.
        let (msg, [r]) = transcript
            .receive_message(Clone::clone, &proof, &(key.degree + 1))
            .map_err(SumcheckError::Degree)?;
        let msg = msg.to_message();

        if sum != msg.eval_at_0() + msg.eval_at_1() {
            return Err(SumcheckError::RoundSum);
        }

        let eqr = r * beta + (F::one() - r) * (F::one() - beta);

        // This would be the sum of eq(beta,r) * f(r,...)
        let new_sum = msg.eval_at_x(r, &key.extended_weights);
        // Thus, removing eq(beta,r) leaves just the sum of f(r,...)
        let sum = new_sum / eqr;
        let (oracle_instance, zerocheck_powers) = {
            let folder = FieldFolder::new(r);
            let [a, b] = instance;
            let oracle = Foldable::fold(&folder, a.oracle_instance, b.oracle_instance);
            let powers = folder.fold_powers(a.zerocheck_powers, b.zerocheck_powers);
            (oracle, powers)
        };

        Ok(ZeroSumcheckInstance {
            sum,
            zerocheck_powers,
            oracle_instance,
        })
    }
}
