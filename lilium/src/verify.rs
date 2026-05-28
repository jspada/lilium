use crate::{
    circuit_key::CircuitKey,
    instances::lcs::{verifying::LcsProof, LcsInstance, LcsProver},
};
use ark_ff::Field;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use transcript::{protocols::Protocol, MessageGuard, TranscriptGuard};

impl<F, T, C, CS, const I: usize, const IO: usize, const S: usize> CircuitKey<F, T, C, CS, I, IO, S>
where
    F: Field,
    T: Duplex<F>,
    CS: CommmitmentScheme<F> + 'static,
{
    //TODO: output result instead.
    pub fn verify(&self, instance: LcsInstance<F, CS, I>, proof: LcsProof<F, CS, IO, S>) -> bool {
        let mut transcript = self.transcript.instantiate();
        let result = {
            let transcript = TranscriptGuard::new(&mut transcript, proof);
            let instance = MessageGuard::new(instance);
            LcsProver::verify(&self.lcs_key, instance, transcript)
        };
        transcript.finish().unwrap();
        match result {
            Ok(()) => true,
            Err(_) => false,
        }
    }
}
