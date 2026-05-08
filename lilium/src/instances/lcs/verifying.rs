use crate::{
    flcs::{FlcsReduction, FlcsReductionProof},
    instances::{
        lcs::{
            key::LcsProvingKey,
            zerocheck_reduction::{ZerocheckReduction, ZerocheckReductionKey},
            LcsInstance, LcsProver,
        },
        linearized::proving::{LinearizedInstanceReduction, LinearizedProof},
    },
    proving::matrix_eval2::{MatrixEvalProof, MatrixEvalProtocol},
};
use ark_ff::Field;
use commit::{
    batching::multipoint::{BatchingProof, MultipointBatching},
    CommmitmentScheme,
};
use transcript::{
    protocols::{Protocol, Reduction},
    MessageGuard, TranscriptBuilder, TranscriptGuard,
};

pub struct LcsProof<F: Field, C: CommmitmentScheme<F>, const IO: usize, const S: usize> {
    reduction_proof: FlcsReductionProof<F, IO, S>,
    linearized_proof: LinearizedProof<F, IO>,
    matrix_eval_proof: MatrixEvalProof<F, C, IO>,
    batching_proof: BatchingProof<F, C, 3>,
    open_proof: C::Proof,
}

impl<F: Field, C: CommmitmentScheme<F>, const IO: usize, const S: usize> LcsProof<F, C, IO, S> {
    pub(crate) fn new(
        reduction_proof: FlcsReductionProof<F, IO, S>,
        linearized_proof: LinearizedProof<F, IO>,
        matrix_eval_proof: MatrixEvalProof<F, C, IO>,
        batching_proof: BatchingProof<F, C, 3>,
        open_proof: C::Proof,
    ) -> Self {
        Self {
            reduction_proof,
            linearized_proof,
            matrix_eval_proof,
            batching_proof,
            open_proof,
        }
    }
}

impl<F, C, const I: usize, const IO: usize, const S: usize> Protocol<F> for LcsProver<C, I, IO, S>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type Key = LcsProvingKey<F, C, IO, S>;

    type Instance = LcsInstance<F, C, I>;

    type Proof = LcsProof<F, C, IO, S>;

    type Error = ();

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        let vars = key.flcs_reduction_key.domain_vars;
        let zerocheck_key = ZerocheckReductionKey::new(vars);
        builder
            .add_reduction_patter::<F, ZerocheckReduction<C, I>>(&zerocheck_key)
            .add_reduction_patter::<F, FlcsReduction<C, I, IO, S>>(&key.flcs_reduction_key)
            .add_reduction_patter::<F, LinearizedInstanceReduction<F, C, IO, S>>(
                &key.linearized_reduction_key,
            )
            .add_reduction_patter::<F, MatrixEvalProtocol<F, C, IO>>(&key.matrix_eval_key)
            .add_reduction_patter::<F, MultipointBatching<C, 3>>(&key.batching)
            .add_protocol_patter::<F, C>(&key.pcs)
    }

    fn prove(_instance: Self::Instance) -> Self::Proof {
        todo!()
    }

    fn verify<D: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::Instance>,
        mut transcript: TranscriptGuard<F, D, Self::Proof>,
    ) -> Result<(), Self::Error> {
        let instance = {
            let vars = key.flcs_reduction_key.domain_vars;
            let zerocheck_key = ZerocheckReductionKey::new(vars);
            let instance = ZerocheckReduction::verify_reduction(
                &zerocheck_key,
                instance,
                transcript.new_guard(()),
            );
            //TODO:handle
            MessageGuard::new(instance.unwrap())
        };
        let flcs_reduction_proof =
            transcript.receive_message_delayed(|proof| proof.reduction_proof.clone());
        //TODO:handle
        let reduced = FlcsReduction::verify_reduction(
            &key.flcs_reduction_key,
            instance,
            transcript.new_guard(flcs_reduction_proof),
        )
        .unwrap();
        let linearized_instance = reduced;

        let linearized_instance = MessageGuard::new(linearized_instance);
        let linearized_proof =
            transcript.receive_message_delayed(|proof| proof.linearized_proof.clone());
        let proof = linearized_proof;
        //TODO: handle
        let reduced = LinearizedInstanceReduction::verify_reduction(
            &key.linearized_reduction_key,
            linearized_instance,
            transcript.new_guard(proof),
        )
        .unwrap();
        let (matrix_eval_instance, open_instances) = reduced;

        let matrix_eval_instance = MessageGuard::new(matrix_eval_instance);
        let proof = transcript.receive_message_delayed(|proof| proof.matrix_eval_proof.clone());
        //TODO: handle
        let open_instance3 = MatrixEvalProtocol::verify_reduction(
            &key.matrix_eval_key,
            matrix_eval_instance,
            transcript.new_guard(proof),
        )
        .unwrap();

        let scheme = &key.pcs;

        let [open_instance1, open_instance2] = open_instances;
        let instance = [open_instance1, open_instance2, open_instance3];
        let instance = MessageGuard::new(instance);
        let proof = transcript.receive_message_delayed(|proof| proof.batching_proof.clone());
        //TODO: handle
        let open_instance = MultipointBatching::verify_reduction(
            &key.batching,
            instance,
            transcript.new_guard(proof),
        )
        .unwrap();

        let proof = transcript.receive_message_delayed(|proof| proof.open_proof.clone());
        let instance = MessageGuard::new(open_instance);
        //TODO: handle
        C::verify(scheme, instance, transcript.new_guard(proof)).unwrap();

        Ok(())
    }
}
