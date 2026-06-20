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
    zerocheck_powers: CompactPowers<F>,
    oracle_instance: O::Instance,
}
