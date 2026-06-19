use crate::{
    sumcheck2::{
        evals::Mles,
        oracles::Oracle,
        zerocheck::{ZeroSumcheck, ZeroSumcheckInstance, Zerocheck},
    },
    zerocheck::CompactPowers,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::reduction2::{
    GuardedProof, NoError, ProverOutput, Reduction, Relation, Transcript, TranscriptBuilder,
    VerifierTranscript,
};

pub struct ZerocheckReduction<F, O>(PhantomData<(F, O)>);

impl<F, O> Reduction<F, Zerocheck<F, O>, ZeroSumcheck<F, O>> for ZerocheckReduction<F, O>
where
    F: Field,
    O: Oracle<F>,
{
    type ProverKey = usize;

    type VerifierKey = usize;

    type Proof = ();

    type Error = NoError;

    fn transcript_pattern(_: &Self::VerifierKey, builder: TranscriptBuilder) -> TranscriptBuilder {
        builder.round::<F, (), 1>(&())
    }

    fn verifier_key(oracle: &O, _: &O) -> Self::VerifierKey {
        oracle.vars()
    }

    fn key_pair(oracle: &O, _: &O) -> (Self::VerifierKey, Self::ProverKey) {
        let vars = oracle.vars();
        (vars, vars)
    }

    fn prove<S: Duplex<F>>(
        key: &usize,
        instance: O::Instance,
        witness: Vec<Mles<O::Function, F>>,
        transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<ZeroSumcheck<F, O>, Self::Proof> {
        let vars = *key;
        let [chall] = transcript.send_message(&(), &());
        let zerocheck_powers = CompactPowers::new(chall, vars);

        let instance = ZeroSumcheckInstance {
            zerocheck_powers,
            oracle_instance: instance,
        };

        ProverOutput {
            instance,
            witness,
            proof: (),
        }
    }

    fn verify<S: Duplex<F>>(
        key: &usize,
        instance: <Zerocheck<F, O> as Relation>::Instance,
        proof: GuardedProof<()>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<<ZeroSumcheck<F, O> as Relation>::Instance, Self::Error> {
        let vars = *key;

        let Ok(((), [chall])) = transcript.receive_message(|_| (), &proof, &());

        let zerocheck_powers = CompactPowers::new(chall, vars);

        Ok(ZeroSumcheckInstance {
            zerocheck_powers,
            oracle_instance: instance,
        })
    }
}
