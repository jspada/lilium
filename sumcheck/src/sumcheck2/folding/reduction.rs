use crate::sumcheck2::{evals::Mles, oracles::Oracle, SumcheckInstance, SumcheckRelation};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::reduction2::{
    FoldingRelation, GuardedProof, ProverOutput, Reduction, Transcript, TranscriptBuilder,
    VerifierTranscript,
};

pub struct SumFold<F, O>(PhantomData<(F, O)>);

impl<F, O> Reduction<F, FoldingRelation<SumcheckRelation<F, O>>, SumcheckRelation<F, O>>
    for SumFold<F, O>
where
    F: Field,
    O: Oracle<F>,
{
    type ProverKey = ();

    type VerifierKey = ();

    type Proof = ();

    type Error = ();

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
        _instance: [SumcheckInstance<F, O>; 2],
        _witness: [Vec<Mles<O::Function, F>>; 2],
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<SumcheckRelation<F, O>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        _key: &Self::VerifierKey,
        _instance: [SumcheckInstance<F, O>; 2],
        _proof: GuardedProof<Self::Proof>,
        _transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<SumcheckInstance<F, O>, Self::Error> {
        todo!()
    }
}
