use crate::{
    polynomials::MultiPoint,
    sumcheck2::{
        degree,
        oracles::{EvalLocation, Mles, Oracle, SumcheckFunction},
        SumcheckMessage,
    },
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::rc::Rc;
use transcript::reduction2::Transcript;

pub struct ProverKey<F: Field, O: Oracle<F>> {
    degree: usize,
    vars: usize,
    structure_evals: Rc<Vec<O::Evals<F>>>,
    f: O::Function,
    structure_filter: Mles<F, O, bool>,
    instance_filter: Mles<F, O, bool>,
}

impl<F: Field, O: Oracle<F>> ProverKey<F, O> {
    pub(crate) fn new(oracle: &O) -> Self {
        let vars = oracle.vars();
        let degree = degree::sumcheck_degree(oracle);

        let structure_evals = oracle.structure();

        let f = oracle.function().clone();

        let natures = oracle.natures();
        let natures = natures.into();

        let structure_filter =
            <O::Function as SumcheckFunction<F>>::map_evals(&natures, |nature: &O::Nature| {
                let location: EvalLocation = (*nature).into();
                matches!(location, EvalLocation::Structure)
            });

        let instance_filter =
            <O::Function as SumcheckFunction<F>>::map_evals(&natures, |nature: &O::Nature| {
                let location: EvalLocation = (*nature).into();
                matches!(location, EvalLocation::Instance)
            });

        Self {
            degree,
            vars,
            structure_evals,
            f,
            structure_filter,
            instance_filter,
        }
    }

    /// Merges evals from the structure, instance and witness.
    fn merge_evals(
        &self,
        witness: &mut O::Evals<F>,
        structure: &O::Evals<F>,
        instance: &O::Evals<F>,
    ) {
        <O::Function as SumcheckFunction<F>>::combine_mut_conditional(
            witness,
            structure,
            self.structure_filter.clone(),
            |w: &mut F, s: &F, is_structure| {
                if is_structure {
                    *w = *s;
                }
            },
        );

        <O::Function as SumcheckFunction<F>>::combine_mut_conditional(
            witness,
            instance,
            self.instance_filter.clone(),
            |w: &mut F, i: &F, is_instance| {
                if is_instance {
                    *w = *i;
                }
            },
        );
    }

    pub(crate) fn prove<S: Duplex<F>>(
        &self,
        witness: Vec<O::Evals<F>>,
        transcript: &mut Transcript<F, S>,
        instance_evals: O::Evals<F>,
    ) -> (Vec<SumcheckMessage<F>>, MultiPoint<F>, F) {
        let mut witness = self.prepare_witness(witness, instance_evals);
        let mut vars = vec![];
        let mut messages = vec![];

        for _ in 0..self.vars {
            let message = self.message(&witness);
            let [r] = transcript.send_message(&message, &self.degree);

            self.bind_variable(&mut witness, r);
            vars.push(r);
            messages.push(message);
        }

        assert_eq!(witness.len(), 1);

        let eval: F = self.f.function(&witness[0]);

        vars.reverse();
        let point = MultiPoint::new(vars);

        (messages, point, eval)
    }

    /// Adds witness and structure evals to the witness.
    fn prepare_witness(
        &self,
        mut witness: Vec<O::Evals<F>>,
        instance_evals: O::Evals<F>,
    ) -> Vec<O::Evals<F>> {
        for (witness, structure) in witness.iter_mut().zip(self.structure_evals.as_ref()) {
            self.merge_evals(witness, structure, &instance_evals);
        }
        witness
    }

    /// Computes the round's sumcheck message.
    fn message(&self, mles: &[O::Evals<F>]) -> SumcheckMessage<F> {
        assert!(mles.len().is_power_of_two());

        let degree = self.degree;

        // All evals start as a bunch of degree 1 polynomials.
        // A degree 1 polynomial can be cheaply evluated over an arbitrary
        // domain with FFTs or anything.
        // If the domain is 0..=d then it is just an addition per evaluation.
        // Given eval at 0 e0 and eval at 1 e1, the polynomial looks like this:
        // e0 + e1x - e0x
        // or alternatively:
        // e0 + x(e1 - e0)
        // And the evaluations:
        // f(0) = e0
        // f(1) = e0 + (e1 - e0) = f(0) + (e1 - e0)
        // f(2) = e0 + (e1 - e0) + (e1 - e0) = f(1) + (e1 - e0)
        // f(3) = f(2) + (e1 - e0)
        //
        // As you can see, to compute f(x), we only need 2 elements,
        // e1 - e0 and the f(x-1).
        let (left, right) = mles.split_at(mles.len() / 2);

        let mut message = vec![F::zero(); degree + 1];
        for (left, right) in left.iter().zip(right) {
            // The last evaluations, and what is needed to compute the next.
            let mut e = <O::Function as SumcheckFunction<F>>::combine::<F, F, _, _>(
                left,
                right,
                |e0, e1| {
                    let coeff = *e1 - e0;
                    let last_eval = e0;
                    (*last_eval, coeff)
                },
            );

            for m in message.iter_mut() {
                let evals = <O::Function as SumcheckFunction<F>>::map_evals(&e, |(eval, _)| *eval);
                let eval: F = self.f.function(&evals);

                *m += eval;
                <O::Function as SumcheckFunction<F>>::apply(&mut e, |(last, coeff)| {
                    *last += coeff;
                });
            }
        }

        SumcheckMessage(message)
    }

    fn bind_variable(&self, mles: &mut Vec<O::Evals<F>>, var: F) {
        assert!(mles.len().is_power_of_two());
        let len = mles.len();
        let (left, right) = mles.split_at_mut(len / 2);

        for (left, right) in left.iter_mut().zip(right) {
            *left = <O::Function as SumcheckFunction<F>>::combine::<F, F, F, _>(
                left,
                right,
                |e0, e1| *e0 + var * (*e1 - e0),
            );
        }

        mles.truncate(len / 2);
    }
}
