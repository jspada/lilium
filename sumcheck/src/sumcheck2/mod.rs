//! New sumcheck implementation based on the new Reduction.

use crate::{
    barycentric_eval::BarycentricWeights, polynomials::MultiPoint,
    sumcheck2::oracles::QueryRelation,
};
use ark_ff::Field;
use oracles::{Oracle, SumcheckFunction};
use sponge::sponge::Duplex;
use std::{fmt::Debug, marker::PhantomData};
use transcript::reduction2::{
    GuardedProof, Message, ProverOutput, Reduction, Relation, Transcript, TranscriptBuilder,
    VerifierTranscript,
};

mod oracles;

pub use oracles::OracleQueryInstance;

fn merge<A>(a: A, b: &A) -> A {
    let _ = (a, b);
    todo!()
}

#[derive(Clone, Copy, Debug)]
struct SumcheckInstance<F: Field, O: Oracle<F>> {
    /// The claimed sum.
    sum: F,
    oracle_instance: O::Instance,
}

impl<F: Field, O: Oracle<F>> Message<F> for SumcheckInstance<F, O> {
    type Params = <O::Instance as Message<F>>::Params;

    type Error = <O::Instance as Message<F>>::Error;

    fn len(params: &Self::Params) -> usize {
        1 + O::Instance::len(params)
    }

    fn to_field_elements(&self, expected_len: usize) -> Result<Vec<F>, Self::Error> {
        let mut elems = self.oracle_instance.to_field_elements(expected_len - 1)?;
        elems.insert(0, self.sum);
        Ok(elems)
    }
}

struct SumcheckRelation<F, O>(PhantomData<(F, O)>);

impl<F: Field, O: Oracle<F>> Relation for SumcheckRelation<F, O> {
    type Structure = O;

    type Instance = SumcheckInstance<F, O>;

    type Witness = Vec<O::Evals<F>>;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let mle = structure.mle();
        // Creating such a thing shouldn't be allowed, thus it will
        // panic instead of returning false.
        assert_eq!(mle.len(), witness.len());

        let f = structure.function();
        let mut sum = F::ZERO;
        for (structure, witness) in mle.iter().zip(witness) {
            let evals = merge(structure, &witness);
            let eval: F = f.function(evals);
            sum += eval;
        }

        sum == instance.sum
    }
}

#[derive(Clone, Debug)]
struct SumcheckMessage<F>(Vec<F>);

impl<F: Field> SumcheckMessage<F> {
    fn to_message(&self) -> crate::message::Message<F> {
        crate::message::Message::new(self.0.clone())
    }
}

/// A sumcheck message had an unexpected degree.
#[derive(Clone, Copy, Debug)]
pub struct UnexpectedDegree;

impl<F: Field> Message<F> for SumcheckMessage<F> {
    type Params = usize;

    type Error = UnexpectedDegree;

    fn len(params: &Self::Params) -> usize {
        *params + 1
    }

    fn to_field_elements(&self, expected_len: usize) -> Result<Vec<F>, Self::Error> {
        if self.0.len() == expected_len {
            Ok(self.0.clone())
        } else {
            Err(UnexpectedDegree)
        }
    }
}

pub struct SumcheckReduction<F, O>(PhantomData<(F, O)>);

#[derive(Clone, Copy, Debug)]
pub enum SumcheckError {
    /// Some message had the wrong degree.
    Degree(UnexpectedDegree),
    /// In some round, the 2 new sums didn't add up to the original sum.
    RoundSum,
}

struct SumcheckVerifierKey<F: Field, O: Oracle<F>> {
    oracle_instance_params: <SumcheckInstance<F, O> as Message<F>>::Params,
    degree: usize,
    vars: usize,
    weights: BarycentricWeights<F>,
}

impl<F: Field, O: Oracle<F>> Reduction<F, SumcheckRelation<F, O>, QueryRelation<F, O>>
    for SumcheckReduction<F, O>
{
    type ProverKey = O;

    type VerifierKey = SumcheckVerifierKey<F, O>;

    type Proof = Vec<SumcheckMessage<F>>;

    type Error = SumcheckError;

    fn transcript_pattern(
        key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        //builder.round::<O::QueryRelation::Instance>(params);
        let degree = key.degree;
        (0..key.vars).fold(builder, |builder, _| {
            builder.round::<F, SumcheckMessage<F>, 1>(degree)
        })
    }

    fn verifier_key(
        structure_1: &O,
        _structure_2: &<QueryRelation<F, O> as Relation>::Structure,
    ) -> Self::VerifierKey {
        let vars = structure_1.vars();
        //TODO: Compute using the function
        let degree: usize = 5;

        let weights = BarycentricWeights::compute(degree as u32);

        let oracle_instance_params = structure_1.oracle_params();

        SumcheckVerifierKey {
            oracle_instance_params,
            degree,
            vars,
            weights,
        }
    }

    fn key_pair(
        _structure_1: &O,
        _structure_2: &<QueryRelation<F, O> as Relation>::Structure,
    ) -> (Self::VerifierKey, Self::ProverKey) {
        todo!()
    }

    fn instance_params(
        key: &Self::VerifierKey,
    ) -> <<SumcheckRelation<F, O> as Relation>::Instance as Message<F>>::Params
    where
        <SumcheckRelation<F, O> as Relation>::Instance: Message<F>,
    {
        key.oracle_instance_params
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: SumcheckInstance<F, O>,
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<<QueryRelation<F, O> as Relation>::Instance, Self::Error> {
        let mut sum = instance.sum;

        let mut vars = vec![];
        for i in 0..key.vars {
            let (message, [r]) = transcript
                .receive_message(|proof| proof[i].clone(), &proof)
                .map_err(SumcheckError::Degree)?;

            let message = message.to_message();

            let e0 = message.eval_at_0();
            let e1 = message.eval_at_1();
            if e0 + e1 != sum {
                return Err(SumcheckError::RoundSum);
            }
            vars.push(r);
            sum = message.eval_at_x(r, &key.weights);
        }
        vars.reverse();
        let eval = sum;
        let point = MultiPoint::new(vars);
        let instance = OracleQueryInstance {
            oracle_instance: instance.oracle_instance,
            point,
            eval,
        };
        Ok(instance)
    }

    fn prove<S: Duplex<F>>(
        _key: &Self::ProverKey,
        _instance: <SumcheckRelation<F, O> as Relation>::Instance,
        _witness: <SumcheckRelation<F, O> as Relation>::Witness,
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<QueryRelation<F, O>, Self::Proof> {
        todo!()
    }
}
