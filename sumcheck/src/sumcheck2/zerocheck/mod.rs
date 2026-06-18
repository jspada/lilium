use crate::sumcheck2::{
    oracles::{Oracle, QueryRelation},
    OracleQueryInstance,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::reduction2::{
    GuardedProof, ProverOutput, Reduction, Relation, Transcript, TranscriptBuilder,
    VerifierTranscript,
};

pub use evals::ZerocheckNature;
pub use reduction::ZerocheckReduction;
pub use relation::{ZeroSumcheck, Zerocheck};

mod evals;
mod reduction;
mod relation;
