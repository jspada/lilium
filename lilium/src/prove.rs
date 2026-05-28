use crate::{
    circuit_key::CircuitKey,
    instances::lcs::{verifying::LcsProof, LcsInstance},
};
use ark_ff::Field;
use ccs::{
    circuit::{Circuit, Prove},
    witness::Witness,
};
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;

// TODO: make a proof type that is generic over a given circuit.

impl<F, T, C, CS, const I: usize, const IO: usize, const S: usize> CircuitKey<F, T, C, CS, I, IO, S>
where
    F: Field,
    T: Duplex<F>,
    CS: CommmitmentScheme<F> + 'static,
{
    /// Creates witness from inputs, commits to it, creates instance and proves it.
    /// Returns (instance, proof, private_output)
    pub fn prove_from_inputs<const IN: usize, const OUT: usize, const PRIV_OUT: usize>(
        &self,
        inputs: [F; IN],
    ) -> (
        LcsInstance<F, CS, I>,
        LcsProof<F, CS, IO, S>,
        C::PrivateOutput,
    )
    where
        C: Circuit<F, IN, OUT, PRIV_OUT>,
    {
        let (instance, witness, output) = self.commit_witness(inputs);

        let proof = self.prove(instance.clone(), witness);
        (instance, proof, output)
    }

    /// Generates witness from inputs, commits to it, and returns an instance-witness
    /// pair which can be proved or folded.
    /// Returns (instance, witness, private_output)
    pub fn commit_witness<const IN: usize, const OUT: usize, const PRIV_OUT: usize>(
        &self,
        inputs: [F; IN],
    ) -> (LcsInstance<F, CS, I>, Witness<F>, C::PrivateOutput)
    where
        C: Circuit<F, IN, OUT, PRIV_OUT>,
    {
        assert_eq!(I, IN + OUT);
        let (mut witness, output) = <C as Prove<_, IN, OUT, PRIV_OUT, IO>>::witness(inputs, true);
        witness.pad_to_power();
        let witness_commit = self.committment_scheme.commit_mle(&witness.0);

        let mut inputs = [F::zero(); I];
        assert!(witness.0.len() >= I);
        inputs.copy_from_slice(&witness.0[0..I]);

        let instance: LcsInstance<F, CS, I> = LcsInstance::new(witness_commit, inputs);

        (instance, witness, output)
    }

    /// Proves (instance, witness) pair.
    pub fn prove(
        &self,
        instance: LcsInstance<F, CS, I>,
        witness: Witness<F>,
    ) -> LcsProof<F, CS, IO, S> {
        let mut transcript = self.transcript.instantiate();
        let proof = self.lcs_key.prove(instance, witness.0, &mut transcript);
        transcript.finish().unwrap();
        proof
    }
}
