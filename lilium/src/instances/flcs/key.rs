use crate::instances::flcs::sumcheck_reduction::{LcsMles, LcsSumcheck};
use crate::instances::lcs::sumcheck_argument;
use ark_ff::Field;
use ccs::structure::Exp;
use ccs::witness::LinearCombinations;
use std::rc::Rc;
use sumcheck::{
    sumcheck::{SumcheckProver, SumcheckVerifier},
    zerocheck::ZeroCheckMles,
};

pub struct FlcsReductionKey<F, const IO: usize, const S: usize>
where
    F: Field,
{
    pub domain_vars: usize,
    pub sumcheck_verifier: SumcheckVerifier<F, LcsSumcheck<F, IO, S>>,
    pub sumcheck_prover: SumcheckProver<F, LcsSumcheck<F, IO, S>>,
    pub structure: Rc<Vec<ZeroCheckMles<F, LcsMles<F, IO, S>>>>,
    pub linear_combinations: Rc<LinearCombinations<IO>>,
}

impl<F, const IO: usize, const S: usize> FlcsReductionKey<F, IO, S>
where
    F: Field,
{
    pub fn new(
        structure: Rc<Vec<sumcheck_argument::LcsMles<F, IO, S>>>,
        linear_combinations: Rc<LinearCombinations<IO>>,
        gates: Vec<Vec<Exp<usize>>>,
    ) -> Self {
        let domain_vars = structure.len().next_power_of_two().ilog2() as usize;
        let multi_constraint = gates.iter().any(|constraints| constraints.len() > 1);
        let sumcheck_function = LcsSumcheck::new(gates, multi_constraint);
        let structure = structure
            .iter()
            .map(|inner| {
                let (input_selector, gate_selectors) = inner.selectors();
                let constants = inner.constants();
                let inner = LcsMles::new_structure(input_selector, gate_selectors, constants);
                ZeroCheckMles::new(F::zero(), inner)
            })
            .collect();
        let structure = Rc::new(structure);

        let sumcheck_prover = SumcheckProver::new_symbolic(domain_vars, &sumcheck_function);
        let sumcheck_verifier = SumcheckVerifier::new_symbolic(sumcheck_function, domain_vars);
        Self {
            domain_vars,
            sumcheck_verifier,
            sumcheck_prover,
            structure,
            linear_combinations,
        }
    }
}
