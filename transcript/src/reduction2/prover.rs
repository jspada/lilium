use crate::reduction2::{
    Message, ProverOutput, Reduction, Relation, TranscriptBuilder, TranscriptDescriptor,
};
use ark_ff::Field;
use sponge::sponge::Duplex;

/// A prover for relation R.
pub struct Prover<F, S, R1, R2, R>
where
    F: Field,
    R1: Relation,
    R1::Instance: Message<F>,
    R2: Relation,
    S: Duplex<F>,
    R: Reduction<F, R1, R2>,
{
    key: R::ProverKey,
    transcript_descriptor: TranscriptDescriptor<F, S>,
}

impl<F, S, R1, R2, R> Prover<F, S, R1, R2, R>
where
    F: Field,
    R1: Relation,
    R1::Instance: Message<F>,
    R2: Relation,
    S: Duplex<F>,
    R: Reduction<F, R1, R2>,
{
    /// Creates prover from the structures of both relations.
    pub fn new(structure_1: &R1::Structure, structure_2: &R2::Structure) -> Self {
        let (verifier_key, key) = R::key_pair(structure_1, structure_2);

        let builder = TranscriptBuilder::new();
        let builder = R::transcript_pattern(&verifier_key, builder);

        let transcript_descriptor = builder.finish();

        Self {
            key,
            transcript_descriptor,
        }
    }

    /// Prove an instance-witness pair.
    pub fn prove(
        &self,
        instance: R1::Instance,
        witness: R1::Witness,
    ) -> ProverOutput<R2, R::Proof> {
        let mut transcript = self.transcript_descriptor.instanciate();
        let out = R::prove(&self.key, instance, witness, &mut transcript);
        transcript.finish();
        out
    }
}
