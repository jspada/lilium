use crate::sumcheck2::{
    evals::{Evals, Mles},
    oracles::{EvalLocation, Oracle, SumcheckFunction},
    relation::merge,
};
use ark_ff::Field;
use std::marker::PhantomData;
use transcript::reduction2::Relation;

/// The sumcheck relation over a given oracle.
pub struct Zerocheck<F, O>(PhantomData<(F, O)>);

impl<F: Field, O: Oracle<F>> Relation for Zerocheck<F, O> {
    type Structure = O;

    type Instance = O::Instance;

    type Witness = Vec<Mles<O::Function, F>>;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let locations: Mles<O::Function, O::Nature> = structure.natures();
        let locations: Mles<O::Function, EvalLocation> =
            <O::Function as Evals>::map_evals(&locations, |n: &O::Nature| (*n).into());

        let mle = structure.structure();
        // Creating such a thing shouldn't be allowed, thus it will
        // panic instead of returning false.
        assert_eq!(mle.len(), witness.len());

        let instance_evals = O::instance_evals(instance);
        let f = structure.function();

        for (structure, witness) in mle.iter().zip(witness) {
            let evals = merge::<F, O>(structure, &instance_evals, witness, &locations);
            let eval: F = f.function(&evals);
            if !eval.is_zero() {
                return false;
            }
        }

        true
    }
}
