use crate::{sumcheck2::oracles::Oracle, zerocheck::CompactPowers};
use ark_ff::Field;

pub use evals::ZerocheckNature;
pub use reduction::{ZerocheckReduction, ZerocheckSumcheckReduction};
pub use relation::{ZeroSumcheck, Zerocheck};

mod evals;
mod reduction;
mod relation;

#[derive(Clone, Debug)]
pub struct ZeroSumcheckInstance<F: Field, O: Oracle<F>> {
    /// Same sum as in sumcheck, with the particularity that it will be
    /// zero unless the instance is the result of folding.
    sum: F,
    zerocheck_powers: CompactPowers<F>,
    oracle_instance: O::Instance,
}
