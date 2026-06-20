use crate::{
    sumcheck2::{
        evals::Mles,
        oracles::{Oracle, QueryRelation},
        prove,
        reduction::SumcheckVerifierKey,
        zerocheck::{ZeroSumcheck, ZeroSumcheckInstance, Zerocheck},
        SumcheckError, SumcheckInstance, SumcheckMessage, SumcheckReduction,
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

#[derive(Clone, Copy, Debug)]
pub struct ZerocheckSumcheckReduction<F, O>(PhantomData<(F, O)>);

impl<F: Field, O: Oracle<F>> Reduction<F, ZeroSumcheck<F, O>, QueryRelation<F, O>>
    for ZerocheckSumcheckReduction<F, O>
{
    type ProverKey = prove::ProverKey<F, O>;

    type VerifierKey = SumcheckVerifierKey<F>;

    type Proof = Vec<SumcheckMessage<F>>;

    type Error = SumcheckError;

    fn transcript_pattern(
        key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        SumcheckReduction::<F, O>::transcript_pattern(key, builder)
    }

    fn verifier_key(structure_1: &O, structure_2: &O) -> Self::VerifierKey {
        SumcheckReduction::verifier_key(structure_1, structure_2)
    }

    fn key_pair(structure_1: &O, structure_2: &O) -> (Self::VerifierKey, Self::ProverKey) {
        SumcheckReduction::key_pair(structure_1, structure_2)
    }

    fn prove<S: Duplex<F>>(
        _key: &Self::ProverKey,
        _instance: ZeroSumcheckInstance<F, O>,
        _witness: Vec<Mles<O::Function, F>>,
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<QueryRelation<F, O>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: ZeroSumcheckInstance<F, O>,
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<<QueryRelation<F, O> as Relation>::Instance, Self::Error> {
        let ZeroSumcheckInstance {
            zerocheck_powers,
            oracle_instance,
        } = instance;
        let instance = SumcheckInstance::new(F::ZERO, oracle_instance);
        let mut reduced = SumcheckReduction::<F, O>::verify(key, instance, proof, transcript)?;
        let powers_eval = zerocheck_powers.point_eval(&reduced.point);

        // As the check will be f(r) * z(r) = eval
        // We can take it off here and have the same output as normal sumcheck.
        // Checking instead f(r) = eval / z(r)
        reduced.eval /= powers_eval;
        Ok(reduced)
    }
}
