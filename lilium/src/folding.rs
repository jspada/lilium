use crate::{
    circuit_key::CircuitKey,
    flcs::{folding::LcsFolding, FoldableLcsInstance},
    instances::lcs::{zerocheck_reduction::ZerocheckReductionKey, LcsInstance},
};
use ark_ff::Field;
use ccs::witness::Witness;
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use sumcheck::folding::SumFoldProof;
use transcript::{protocols::Reduction, MessageGuard};

/// A pair of instances, which allows for any combination of `FoldableLcsInstance`
/// and `LcsInstance`.
/// Do not create this directly, use instead `(A,B).into()` or `InstancePair::from((A,B))`
/// which is implemented for the 4 cases.
pub enum InstancePair<F, C, const I: usize>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    Flcs(FoldableLcsInstance<F, C, I>, FoldableLcsInstance<F, C, I>),
    Mixed(FoldableLcsInstance<F, C, I>, LcsInstance<F, C, I>),
    Lcs(LcsInstance<F, C, I>, LcsInstance<F, C, I>),
}

impl<F, C, const I: usize> From<(FoldableLcsInstance<F, C, I>, FoldableLcsInstance<F, C, I>)>
    for InstancePair<F, C, I>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn from((a, b): (FoldableLcsInstance<F, C, I>, FoldableLcsInstance<F, C, I>)) -> Self {
        InstancePair::Flcs(a, b)
    }
}

impl<F, C, const I: usize> From<(FoldableLcsInstance<F, C, I>, LcsInstance<F, C, I>)>
    for InstancePair<F, C, I>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn from((a, b): (FoldableLcsInstance<F, C, I>, LcsInstance<F, C, I>)) -> Self {
        InstancePair::Mixed(a, b)
    }
}

impl<F, C, const I: usize> From<(LcsInstance<F, C, I>, FoldableLcsInstance<F, C, I>)>
    for InstancePair<F, C, I>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn from((a, b): (LcsInstance<F, C, I>, FoldableLcsInstance<F, C, I>)) -> Self {
        InstancePair::Mixed(b, a)
    }
}

impl<F, C, const I: usize> From<(LcsInstance<F, C, I>, LcsInstance<F, C, I>)>
    for InstancePair<F, C, I>
where
    F: Field,
    C: CommmitmentScheme<F>,
{
    fn from((a, b): (LcsInstance<F, C, I>, LcsInstance<F, C, I>)) -> Self {
        InstancePair::Lcs(a, b)
    }
}

impl<F, T, C, CS, const I: usize, const IO: usize, const S: usize> CircuitKey<F, T, C, CS, I, IO, S>
where
    F: Field,
    T: Duplex<F>,
    CS: CommmitmentScheme<F> + 'static,
{
    /// Folds 2 instance-witness pairs into a single instance-witness pair.
    /// Returns (instance, witness, proof).
    /// Each instance may be a `FoldableLcsInstance` or an `LcsInstance`.
    pub fn fold(
        &self,
        instances: impl Into<InstancePair<F, CS, I>>,
        witnesses: [Witness<F>; 2],
    ) -> (FoldableLcsInstance<F, CS, I>, Vec<F>, SumFoldProof<F>) {
        let instance_pair = instances.into();
        //TODO:store key
        let zerocheck_reduction_key =
            ZerocheckReductionKey::new(self.lcs_key.flcs_reduction_key.domain_vars);
        let (a, b) = match instance_pair {
            InstancePair::Flcs(a, b) => (a, b),
            InstancePair::Mixed(a, b) => {
                let mut transcript = self.zerocheck_transcript.instantiate();
                let b = zerocheck_reduction_key.reduce(b, &mut transcript);
                transcript.finish_unchecked();
                (a, b)
            }
            InstancePair::Lcs(a, b) => {
                let [a, b] = [a, b].map(|instance| {
                    let mut transcript = self.zerocheck_transcript.instantiate();
                    let instance = zerocheck_reduction_key.reduce(instance, &mut transcript);
                    transcript.finish_unchecked();
                    instance
                });
                (a, b)
            }
        };
        let instances = [a, b];
        let mut transcript = self.folding_transcript.instantiate();
        let folded =
            self.folding_key
                .fold::<CS, _, I>(instances, witnesses.map(|w| w.0), &mut transcript);
        transcript.finish_unchecked();
        folded
    }

    /// Verifier side of `Self::fold`, takes 2 instances and a proof and returns a
    /// a folded instance.
    pub fn fold_instances(
        &self,
        instances: impl Into<InstancePair<F, CS, I>>,
        proof: SumFoldProof<F>,
    ) -> FoldableLcsInstance<F, CS, I> {
        let zerocheck_reduction_key =
            ZerocheckReductionKey::new(self.lcs_key.flcs_reduction_key.domain_vars);
        let (a, b) = match instances.into() {
            InstancePair::Flcs(a, b) => (a, b),
            InstancePair::Mixed(a, b) => {
                let mut transcript = self.zerocheck_transcript.instantiate();
                let b = zerocheck_reduction_key.reduce(b, &mut transcript);
                transcript.finish_unchecked();
                (a, b)
            }
            InstancePair::Lcs(a, b) => {
                let [a, b] = [a, b].map(|instance| {
                    let mut transcript = self.zerocheck_transcript.instantiate();
                    let instance = zerocheck_reduction_key.reduce(instance, &mut transcript);
                    transcript.finish_unchecked();
                    instance
                });
                (a, b)
            }
        };
        let mut transcript = self.folding_transcript.instantiate();
        let instance = MessageGuard::new([a, b]);
        let instance = LcsFolding::<F, CS, IO, I, S>::verify_reduction(
            &self.folding_key,
            instance,
            transcript.guard(proof),
        )
        .unwrap();
        transcript.finish_unchecked();
        instance
    }
}
