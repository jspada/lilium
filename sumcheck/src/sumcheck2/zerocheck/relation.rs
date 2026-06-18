use crate::sumcheck2::{evals::Mles, oracles::Oracle, relation::oracle_evals};
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
        oracle_evals(structure, instance, witness)
            .iter()
            .all(F::is_zero)
    }
}
