use crate::reduction2::{
    transcript::VerifierTranscript, transcript_builder::TranscriptDescriptor, GuardedProof,
    Message, Reduction, Relation, TranscriptBuilder,
};

use ark_ff::Field;
use sponge::sponge::Duplex;

/// A verifier for relation R.
pub struct Verifier<F, S, R1, R2, R>
where
    F: Field,
    R1: Relation,
    R1::Instance: Message<F>,
    R2: Relation,
    S: Duplex<F>,
    R: Reduction<F, R1, R2>,
{
    key: R::VerifierKey,
    transcript_descriptor: TranscriptDescriptor<F, S>,
}

impl<F, S, R1, R2, R> Verifier<F, S, R1, R2, R>
where
    F: Field,
    R1: Relation,
    R1::Instance: Message<F>,
    R2: Relation,
    S: Duplex<F>,
    R: Reduction<F, R1, R2>,
{
    /// Creates verifier from the structures of both relations.
    pub fn new(structure_1: &R1::Structure, structure_2: &R2::Structure) -> Self {
        let key = R::verifier_key(structure_1, structure_2);

        let builder = TranscriptBuilder::new();
        let builder = R::transcript_pattern(&key, builder);

        let transcript_descriptor = builder.finish();

        Verifier {
            key,
            transcript_descriptor,
        }
    }

    /// Verify that the instance is in R1 by the provided proof.
    pub fn verify(
        &self,
        instance: R1::Instance,
        proof: R::Proof,
    ) -> Result<R2::Instance, R::Error> {
        let transcript = self.transcript_descriptor.instanciate();
        let mut transcript = VerifierTranscript::<F, S>::new(transcript);

        let instance = transcript.wrap(instance);
        let proof = GuardedProof::new(proof);

        let reduced = R::verify(&self.key, instance, proof, &mut transcript);

        // This shouldn't be possible through the public API.
        if let Err(err) = transcript.finish() {
            panic!("Transcript error: {:?}", err);
        }

        reduced
    }
}
