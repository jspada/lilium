use super::*;

pub struct ZerocheckReduction<F, O>(PhantomData<(F, O)>);

impl<F, O> Reduction<F, Zerocheck<F, O>, QueryRelation<F, O>> for ZerocheckReduction<F, O>
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
        _instance: O::Instance,
        _witness: <Zerocheck<F, O> as Relation>::Witness,
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<QueryRelation<F, O>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        _key: &Self::VerifierKey,
        _instance: O::Instance,
        _proof: GuardedProof<Self::Proof>,
        _transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<OracleQueryInstance<F, O::Instance>, Self::Error> {
        todo!()
    }
}
