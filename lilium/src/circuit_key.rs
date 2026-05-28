use ark_ff::Field;
use ccs::{
    circuit::{BuildStructure, Circuit},
    structure::{CcsStructure, Exp, Matrix},
};
use commit::CommmitmentScheme;
use sponge::sponge::Duplex;
use std::{marker::PhantomData, rc::Rc};
use transcript::{params::ParamResolver, TranscriptBuilder, TranscriptDescriptor};

use crate::{
    flcs::folding::{LcsFolding, LcsFoldingKey},
    instances::lcs::{
        key::LcsProvingKey,
        sumcheck_argument::LcsMles,
        zerocheck_reduction::{ZerocheckReduction, ZerocheckReductionKey},
        LcsProver,
    },
};

/// key to create and verify proofs for a given circuit
pub struct CircuitKey<
    F: Field,
    D: Duplex<F>,
    C,
    CS: CommmitmentScheme<F>,
    const I: usize,
    const IO: usize = 0,
    const S: usize = 0,
> {
    _circuit: PhantomData<C>,
    pub(crate) transcript: TranscriptDescriptor<F, D>,
    pub(crate) committment_scheme: Rc<CS>,
    pub(crate) lcs_key: LcsProvingKey<F, CS, IO, S>,
    pub(crate) folding_key: LcsFoldingKey<F, IO, S>,
    pub(crate) folding_transcript: TranscriptDescriptor<F, D>,
    /// For the zerocheck reduction used in certain cases of folding.
    pub(crate) zerocheck_transcript: TranscriptDescriptor<F, D>,
}

impl<F, T, C, CS, const I: usize, const IO: usize, const S: usize> CircuitKey<F, T, C, CS, I, IO, S>
where
    F: Field,
    T: Duplex<F>,
    CS: CommmitmentScheme<F>,
{
    pub fn new<const IN: usize, const OUT: usize, const PRIV_OUT: usize>() -> Self
    where
        C: Circuit<F, IN, OUT, PRIV_OUT>,
        CS: 'static,
    {
        let ccs_structure: CcsStructure<F, IO, S> = C::structure();
        let vars = ccs_structure.vars();
        let spark_structure = ccs_structure.io_matrices.clone().map(|matrix: Matrix| {
            let mut evals: Vec<_> = matrix
                .iter()
                .map(|index| {
                    let (i, j) = index;
                    ([i, j], F::one())
                })
                .collect();
            evals.resize(1 << vars, ([0, 0], F::zero()));
            evals
        });
        let committment_scheme = Rc::new(CS::new(vars));

        let structure = Rc::new(structure(ccs_structure.clone()));
        let gates: Vec<Vec<Exp<usize>>> = ccs_structure
            .gates
            .iter()
            .map(|gate| Vec::from(gate.clone()))
            .collect();
        let matrices = ccs_structure.io_matrices.clone().map(Rc::new);
        let lcs_key = LcsProvingKey::new(
            Rc::clone(&committment_scheme),
            structure,
            matrices,
            spark_structure,
            gates.clone(),
        );

        let folding_key = LcsFoldingKey::new(
            gates,
            vars,
            Rc::clone(&lcs_key.flcs_reduction_key.structure),
            Rc::clone(&lcs_key.flcs_reduction_key.linear_combinations),
        );
        let transcript_builder = TranscriptBuilder::new(vars, ParamResolver::new());
        let folding_transcript = transcript_builder
            .add_reduction_pattern::<F, LcsFolding<F, CS, IO, I, S>>(&folding_key)
            .finish();

        let transcript_builder = TranscriptBuilder::new(vars, ParamResolver::new());
        let transcript = transcript_builder
            .add_protocol_pattern::<F, LcsProver<CS, I, IO, S>>(&lcs_key)
            .finish();
        let transcript_builder = TranscriptBuilder::new(vars, ParamResolver::new());
        let zerocheck_transcript = transcript_builder
            .add_reduction_pattern::<F, ZerocheckReduction<CS, I>>(&ZerocheckReductionKey::new(
                vars,
            ))
            .finish();

        Self {
            _circuit: PhantomData,
            transcript,
            committment_scheme,
            lcs_key,
            folding_key,
            folding_transcript,
            zerocheck_transcript,
        }
    }
}

fn structure<F: Field, const IO: usize, const S: usize>(
    ccs_structure: CcsStructure<F, IO, S>,
) -> Vec<LcsMles<F, IO, S>> {
    let len = ccs_structure.trace_len.next_power_of_two();
    let mut mles = Vec::with_capacity(len);
    //TODO: use next_power_of_two(max(trace,constraints))
    for i in 0..ccs_structure.trace_len {
        let input_selector = if i < ccs_structure.input_len { 1u8 } else { 0 };
        let input_selector = F::from(input_selector);

        let active_selector = ccs_structure.gate_selectors.get(i);
        let gate_selectors = match active_selector {
            Some(gate) => {
                let mut gate_selectors = [F::zero(); S];
                gate_selectors[*gate] = F::one();
                gate_selectors
            }
            None => [F::zero(); S],
        };

        let constant = ccs_structure
            .constants
            .get(&i)
            .cloned()
            .unwrap_or(F::zero());

        let row = LcsMles::new_structure(input_selector, gate_selectors, constant);
        mles.push(row)
    }
    let padding_row = LcsMles::new_structure(F::zero(), [F::zero(); S], F::zero());
    mles.resize(len, padding_row);
    mles
}
