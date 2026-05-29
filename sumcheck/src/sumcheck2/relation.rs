use crate::sumcheck2::oracles::{EvalLocation, Mles, Oracle, SumcheckFunction};
use ark_ff::Field;
use std::marker::PhantomData;
use transcript::reduction2::{Message, Relation};

fn merge<F: Field, O: Oracle<F>>(
    structure: &O::Evals<F>,
    instance: &O::Evals<F>,
    witness: &O::Evals<F>,
    locations: &O::Evals<EvalLocation>,
) -> O::Evals<F> {
    use EvalLocation::*;

    let locations: Mles<F, O, EvalLocation> = locations.clone().into();

    let evals: O::Evals<F> = <O::Function as SumcheckFunction<F>>::combine3(
        [structure, instance],
        &locations,
        |s: &F, i, l: &EvalLocation| match l {
            Structure => *s,
            Instance => *i,
            Witness => F::ZERO,
        },
    );

    <O::Function as SumcheckFunction<F>>::combine3(
        [&evals, witness],
        &locations,
        |e: &F, w, l: &EvalLocation| match l {
            Structure | Instance => *e,
            Witness => *w,
        },
    )
}

#[derive(Clone, Copy, Debug)]
/// An instance in the sumcheck relation, consting of the
/// claimed sum of the evaluations of the oracle over the
/// domain. And the instance of the oracle.
pub struct SumcheckInstance<F: Field, O: Oracle<F>> {
    /// The claimed sum.
    pub(crate) sum: F,
    pub(crate) oracle_instance: O::Instance,
}

impl<F: Field, O: Oracle<F>> Message<F> for SumcheckInstance<F, O> {
    type Params = <O::Instance as Message<F>>::Params;

    type Error = <O::Instance as Message<F>>::Error;

    fn len(params: &Self::Params) -> usize {
        1 + O::Instance::len(params)
    }

    fn to_field_elements(&self, params: &Self::Params) -> Result<Vec<F>, Self::Error> {
        let mut elems = self.oracle_instance.to_field_elements(params)?;
        elems.insert(0, self.sum);
        Ok(elems)
    }
}

/// The sumcheck relation over a given oracle.
pub struct SumcheckRelation<F, O>(PhantomData<(F, O)>);

impl<F: Field, O: Oracle<F>> Relation for SumcheckRelation<F, O> {
    type Structure = O;

    type Instance = SumcheckInstance<F, O>;

    type Witness = Vec<O::Evals<F>>;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let locations: Mles<F, O, O::Nature> = structure.natures().into();
        let locations: Mles<F, O, EvalLocation> =
            <O::Function as SumcheckFunction<F>>::map_evals(&locations, |n: &O::Nature| {
                (*n).into()
            });
        let locations: O::Evals<EvalLocation> = From::from(locations);

        let mle = structure.structure();
        // Creating such a thing shouldn't be allowed, thus it will
        // panic instead of returning false.
        assert_eq!(mle.len(), witness.len());

        let instance_evals = O::instance_evals(&instance.oracle_instance);
        let f = structure.function();
        let mut sum = F::ZERO;
        for (structure, witness) in mle.iter().zip(witness) {
            let evals = merge::<F, O>(structure, &instance_evals, witness, &locations);
            let eval: F = f.function(&evals);
            sum += eval;
        }

        sum == instance.sum
    }
}
