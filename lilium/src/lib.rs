use ark_ff::Field;
use commit::{batching::BatchingError, CommmitmentScheme};
use std::marker::PhantomData;
use sumcheck::SumcheckError;

mod circuit_key;
pub mod circuits;
mod folding;
mod instances;
mod prove;
mod proving;
pub mod simple_cs;
#[cfg(all(test, feature = "ipa"))]
mod test;
pub mod testing;
mod verify;

pub use circuit_key::CircuitKey;
pub use folding::InstancePair;
pub(crate) use instances::flcs;

pub struct Prover<F: Field, const IO: usize = 0> {
    _phantom: PhantomData<F>,
}

#[derive(Debug, Clone)]
pub enum Error<F: Field, C: CommmitmentScheme<F>> {
    TranscriptError(transcript::Error),
    /// Committed spark error
    Spark(spark::committed_spark::Error<F, C>),
    Pcs(C::Error),
    Sumcheck(SumcheckError),
    /// Polynomial doesn't evaluate to the expected value at the point
    /// given by sumcheck
    EvalCheck,
    Batching(BatchingError<F, C>),
}

impl<F: Field, C: CommmitmentScheme<F>> From<transcript::Error> for Error<F, C> {
    fn from(value: transcript::Error) -> Self {
        Self::TranscriptError(value)
    }
}

impl<F: Field, C: CommmitmentScheme<F>> From<spark::committed_spark::Error<F, C>> for Error<F, C> {
    fn from(value: spark::committed_spark::Error<F, C>) -> Self {
        Self::Spark(value)
    }
}

impl<F: Field, C: CommmitmentScheme<F>> From<SumcheckError> for Error<F, C> {
    fn from(value: SumcheckError) -> Self {
        Self::Sumcheck(value)
    }
}

impl<F: Field, C: CommmitmentScheme<F>> From<BatchingError<F, C>> for Error<F, C> {
    fn from(value: BatchingError<F, C>) -> Self {
        Self::Batching(value)
    }
}

/*impl<F: Field, const IO: usize> Prover<F, IO> {
    /// Generates key for given circuit
    pub fn circuit_key<
        C: Circuit<F, IN, OUT, PRIV_OUT>,
        const IN: usize,
        const OUT: usize,
        const PRIV_OUT: usize,
    >() -> CircuitKey<F, C, IN, OUT, PRIV_OUT> {
        let structure = C::structure();
        CircuitKey {
            _phantom: PhantomData,
            structure,
        }
    }
}

/// Sumcheck function to represent a constraint system
struct CsFunction<F: Field>(PhantomData<F>);

#[derive(Clone, Copy)]
/// Index to implement the constraint system on sumcheck
enum CsIdx {
    Selector(usize),
    Matrix(usize),
    Witness,
}

/// Mle type for the constraint system
struct CsMle<F: Field> {
    matrices: [F; 3],
    selectors: [F; 3],
    witness: F,
}

/// Implement Index as required to implement Evals
impl<F: Field> Index<CsIdx> for CsMle<F> {
    type Output = F;

    fn index(&self, index: CsIdx) -> &Self::Output {
        match index {
            CsIdx::Selector(i) => &self.selectors[i],
            CsIdx::Matrix(i) => &self.matrices[i],
            CsIdx::Witness => &self.witness,
        }
    }
}
/// Implement Evals
impl<F: Field> Evals<F> for CsMle<F> {
    type Idx = CsIdx;

    fn combine<C: Fn(F, F) -> F>(&self, other: &Self, f: C) -> Self {
        let mut matrices = self.matrices.clone();
        for i in 0..3 {
            matrices[i] = f(matrices[i], other.matrices[i]);
        }
        let mut selectors = self.selectors.clone();
        for i in 0..3 {
            selectors[i] = f(selectors[i], other.selectors[i]);
        }
        let witness = f(self.witness, other.witness);
        Self {
            matrices,
            selectors,
            witness,
        }
    }
}

/// Implementing SumcheckFunction generically for all constraint systems
impl<F: Field> SumcheckFunction<F> for CsFunction<F> {
    type Idx = CsIdx;

    type Mles = CsMle<F>;

    type Challs = ();

    fn function<V: Var<F>, E: Env<F, V, Self::Idx>>(env: E, challs: &Self::Challs) -> V {
        todo!()
    }
}

impl<F: Field, const IO: usize> Prover<F, IO> {
    fn prove<
        C: Circuit<F, IN, OUT, PRIV_OUT>,
        const IN: usize,
        const OUT: usize,
        const PRIV_OUT: usize,
        const S: usize,
    >(
        key: &CircuitKey<F, C, IN, OUT, PRIV_OUT, IO, S>,
    ) {
        // let sumcheck_prover = SumcheckProver::new(8);
    }
}
*/
