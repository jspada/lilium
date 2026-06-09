use crate::spark3::{SparkInstance, StaticSparkRelation, StaticSparkStructure};
use ark_ff::Field;
use commit::commit2::{CommitmentScheme, OpenInstance, OpeningRelation};
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::reduction2::{
    GuardedProof, ProverOutput, Reduction, Transcript, TranscriptBuilder, VerifierTranscript,
};

pub struct SparkReduction<F: Field, C: CommitmentScheme<F>, const N: usize>(PhantomData<(F, C)>);

type Rel1<F, const N: usize> = StaticSparkRelation<F, N>;
type Rel2<F, C> = OpeningRelation<F, C>;

impl<F, C, const N: usize> Reduction<F, Rel1<F, N>, Rel2<F, C>> for SparkReduction<F, C, N>
where
    F: Field,
    C: CommitmentScheme<F>,
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

    fn verifier_key(
        _structure_1: &StaticSparkStructure<F, N>,
        _structure_2: &C,
    ) -> Self::VerifierKey {
        todo!()
    }

    fn key_pair(
        _structure_1: &StaticSparkStructure<F, N>,
        _structure_2: &C,
    ) -> (Self::VerifierKey, Self::ProverKey) {
        todo!()
    }

    fn prove<S: Duplex<F>>(
        _key: &Self::ProverKey,
        _instance: SparkInstance<F>,
        _witness: (),
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<OpeningRelation<F, C>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        _key: &Self::VerifierKey,
        _instance: SparkInstance<F>,
        _proof: GuardedProof<Self::Proof>,
        _transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<OpenInstance<F, C>, Self::Error> {
        todo!()
    }
}
