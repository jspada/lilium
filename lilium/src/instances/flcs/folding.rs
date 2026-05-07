use crate::{
    flcs::{
        sumcheck_reduction::{ConstraintCombinationChallenge, LcsMles, LcsSumcheck, LcsSumfold},
        FoldableLcsInstance,
    },
    Error,
};
use ark_ff::Field;
use ccs::{structure::Exp, witness::LinearCombinations};
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use std::{iter::repeat, marker::PhantomData, rc::Rc};
use sumcheck::{
    folding::{SumFold, SumFoldInstance, SumFoldProof, SumFoldProverOutput, ZeroFold},
    zerocheck::ZeroCheckMles,
};
use transcript::{
    protocols::Reduction, MessageGuard, Transcript, TranscriptBuilder, TranscriptGuard,
};

pub struct LcsFolding<F, C, const IO: usize, const I: usize, const S: usize> {
    _phantom: PhantomData<(F, C)>,
}

pub struct LcsFoldingKey<F: Field, const IO: usize, const S: usize> {
    // vars: usize,
    zerofold: ZeroFold<F, LcsSumfold<F, IO, S>>,
    structure: Rc<Vec<ZeroCheckMles<F, LcsMles<F, IO, S>>>>,
    linear_combinations: Rc<LinearCombinations<IO>>,
}

impl<F, C, const IO: usize, const I: usize, const S: usize> Reduction<F>
    for LcsFolding<F, C, IO, I, S>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = [FoldableLcsInstance<F, C, I>; 2];

    type B = FoldableLcsInstance<F, C, I>;

    type Key = LcsFoldingKey<F, IO, S>;

    type Proof = SumFoldProof<F>;

    type Error = Error<F, C>;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        builder
            .round::<F, Self::A, 0>()
            .add_reduction_patter::<F, SumFold<F, _>>(key.zerofold.sumfold_key())
    }

    fn verify_reduction<D: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, D, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instances, []): ([FoldableLcsInstance<F, C, I>; 2], _) =
            transcript.unwrap_guard(instance)?;

        let sums = instances.each_ref().map(|instance| instance.sum);
        let sumfold_instance = MessageGuard::new(SumFoldInstance::new(sums));
        let (sum, folder) =
            SumFold::verify_reduction(key.zerofold.sumfold_key(), sumfold_instance, transcript)?;
        let [a, b] = instances;
        let folded_instance = a.fold(b, folder, sum.0);
        Ok(folded_instance)
    }
}

impl<F: Field, const IO: usize, const S: usize> LcsFoldingKey<F, IO, S> {
    pub fn new(
        gates: Vec<Vec<Exp<usize>>>,
        vars: usize,
        structure: Rc<Vec<ZeroCheckMles<F, LcsMles<F, IO, S>>>>,
        linear_combinations: Rc<LinearCombinations<IO>>,
    ) -> Self {
        let function = LcsSumcheck::<F, IO, S>::new(gates, false);
        let zerofold = ZeroFold::new(LcsSumfold::from(function), vars);
        Self {
            zerofold,
            structure,
            linear_combinations,
        }
    }

    pub fn fold<C, D, const I: usize>(
        &self,
        instances: [FoldableLcsInstance<F, C, I>; 2],
        witnesses: [Vec<F>; 2],
        transcript: &mut Transcript<F, D>,
    ) -> (FoldableLcsInstance<F, C, I>, Vec<F>, SumFoldProof<F>)
    where
        C: CommmitmentScheme<F> + 'static,
        D: Duplex<F>,
    {
        let [] = transcript.send_message(&instances).unwrap();
        let (w1, w2) = {
            let [w1, w2] = witnesses.each_ref();
            let structure = &self.structure;
            let combinations = &self.linear_combinations;
            let w1 = fill_mles(structure, combinations, &instances[0].public_inputs, w1);
            let w2 = fill_mles(structure, combinations, &instances[1].public_inputs, w2);
            (w1, w2)
        };
        let sums = SumFoldInstance::new(instances.each_ref().map(|instance| instance.sum));
        let powers = instances
            .each_ref()
            .map(|instance| instance.zerocheck_powers.clone());
        // dummy value as it won't be used in folding.
        let challenges = ConstraintCombinationChallenge::from(F::zero());
        let SumFoldProverOutput {
            instance: _,
            folded_witness: _,
            proof,
            folder,
            sum,
        } = self
            .zerofold
            .fold_zerocheck(w1, &w2, sums.into(), powers, challenges, transcript);

        let [inst1, inst2] = instances;
        let instance = inst1.fold(inst2, folder, sum);

        let [mut w1, w2] = witnesses;
        folder.fold_vector(&mut w1, &w2);
        let witness = w1;

        (instance, witness, proof)
    }
}

fn fill_mles<F, const IO: usize, const S: usize>(
    structure: &[ZeroCheckMles<F, LcsMles<F, IO, S>>],
    linear_combinations: &LinearCombinations<IO>,
    inputs: &[F],
    witness: &[F],
) -> Vec<LcsMles<F, IO, S>>
where
    F: Field,
{
    let mut mles: Vec<_> = structure.iter().map(|e| *e.inner()).collect();
    let combinations = linear_combinations.compute(witness);
    let combinations = combinations.chain(repeat([F::zero(); IO])).take(mles.len());

    for (i, combination) in combinations.enumerate() {
        let products: [F; IO] = combination;
        let inputs = inputs.get(i).cloned();
        let w = witness[i];
        mles[i].set_instance_witness_evals(products, w, inputs);
    }
    mles
}
