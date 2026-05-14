//! New sumcheck implementation based on the new Reduction.

pub mod oracles;
mod prove;
mod reduction;
mod relation;

pub use oracles::OracleQueryInstance;
pub use reduction::SumcheckReduction;
pub use relation::{SumcheckInstance, SumcheckRelation};

#[derive(Clone, Debug)]
/// A message of the sumchecks protocol, represented as
/// the evaluations of polynomial over the domain 0..d.
pub struct SumcheckMessage<F>(Vec<F>);
