//! A linear sumcheck prover

pub(crate) mod barycentric_eval;
pub(crate) mod degree;
pub mod eq;
pub mod eval_check;
mod eval_impls;
pub mod folding;
pub(crate) mod message;
pub mod polynomials;
pub mod sumcheck;
pub mod sumcheck2;
mod symbolic;
mod tests;
pub mod utils;
pub mod zerocheck;

pub use tests::prove_and_verify;
pub use tests::TestSponge;

#[derive(Debug, Clone)]
pub enum SumcheckError {
    /// A message had an incorrect degree
    MessageDegree,
    /// The sum of both halves defers from the claimed sum
    RoundSum,
    // Transcript error
    TranscriptError(transcript::Error),
}
