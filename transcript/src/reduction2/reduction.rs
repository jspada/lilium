use super::Relation;
use crate::reduction2::{
    Guard, GuardedProof, Message, Transcript, TranscriptBuilder, VerifierTranscript,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::fmt::Debug;

pub struct ProverOutput<R: Relation, P> {
    pub instance: R::Instance,
    pub witness: R::Witness,
    pub proof: P,
}

/// A reduction from relation R1 to R2.
pub trait Reduction<F: Field, R1: Relation, R2: Relation>
where
    R1::Instance: Message<F>,
{
    type ProverKey;
    type VerifierKey;
    type Proof: Clone;
    type Error: Clone + Debug;

    /// Defines the shape of the interactive protocol, any interactions which
    /// deviate from it will result in panics in the prover and errors in the
    /// verifier.
    fn transcript_pattern(key: &Self::VerifierKey, builder: TranscriptBuilder)
        -> TranscriptBuilder;

    fn verifier_key(structure_1: &R1::Structure, structure_2: &R2::Structure) -> Self::VerifierKey;

    fn key_pair(
        structure_1: &R1::Structure,
        structure_2: &R2::Structure,
    ) -> (Self::VerifierKey, Self::ProverKey);

    fn prove<S: Duplex<F>>(
        key: &Self::ProverKey,
        instance: R1::Instance,
        witness: R1::Witness,
        transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<R2, Self::Proof>;

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: Guard<R1::Instance>,
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<R2::Instance, Self::Error>;
}

/// An argument is just a reduction where the target relation is unit.
pub trait Argument<F: Field, R: Relation>: Reduction<F, R, ()>
where
    R::Instance: Message<F>,
{
}
