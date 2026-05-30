use crate::{
    polynomials::{Evals, MultiPoint},
    sumcheck2::oracles::{
        composite::Either,
        partial::{OracleEval, OracleParams, PartialOracle, PartialQueryInstance},
        EvalLocation, SumcheckFunction,
    },
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use transcript::reduction2::{
    Argument, GuardedProof, Message, ProverOutput, Reduction, Relation, Transcript,
    TranscriptBuilder, VerifierTranscript,
};

/// The number of coefficients used to represent the small polynomial.
#[derive(Clone, Copy, Debug)]
pub enum Coeffs {
    /// For purely structural polynomials.
    None,
    /// Single element, typical of challenges.
    One,
    Two,
    OnePerVariable,
}

type Func<F> = fn(&[F], &MultiPoint<F>) -> F;

#[derive(Clone, Debug)]
pub struct CoreOracle<F: Field, SF: SumcheckFunction<F>> {
    functions: SF::Mles<Func<F>>,
}

#[derive(Clone, Debug)]
pub struct CoreOracleInstance<F, SF> {
    /// Elements which define small polynomials.
    elements: Vec<Vec<F>>,
    _f: PhantomData<SF>,
}

/// Unpacks the vector of coefficients into SF::Mles acording to SF::natures().
/// CoreNature::SmallStructure will get an empty vec![].
fn decode<F, SF>(coefficients: Vec<Vec<F>>) -> SF::Mles<Option<Vec<F>>>
where
    F: Field,
    SF: SumcheckFunction<F>,
    Option<CoreNature>: From<SF::Natures>,
{
    let natures = SF::natures();
    let mut coefficients = coefficients.into_iter();

    let evals = natures
        .flatten_vec()
        .into_iter()
        .map(|nature| {
            Option::from(nature).map(|nature| match nature {
                CoreNature::SmallStructure => vec![],
                CoreNature::SmallInstance(n) => {
                    let coeff = coefficients.next().unwrap();
                    assert_eq!(n, coeff.len());
                    coeff
                }
                CoreNature::Challenge => {
                    let coeff = coefficients.next().unwrap();
                    assert_eq!(1, coeff.len());
                    coeff
                }
            })
        })
        .collect();
    let evals = SF::Mles::unflatten_vec(evals);
    assert!(coefficients.next().is_none());
    evals
}

#[derive(Clone, Copy, Debug)]
pub enum CoreOracleError {
    MissingCoefficients,
    CoefficientsLength,
    UnexpectedCoefficients,
}

impl<F, SF> Message<F> for CoreOracleInstance<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
    Option<CoreNature>: From<SF::Natures>,
{
    type Params = OracleParams;

    type Error = CoreOracleError;

    fn len(_params: &Self::Params) -> usize {
        let natures = SF::natures().flatten_vec();
        let mut len = 0;
        for nature in natures {
            let eval_len = match Option::<CoreNature>::from(nature) {
                Some(CoreNature::SmallStructure) => 0,
                Some(CoreNature::SmallInstance(coeffs)) => coeffs,
                Some(CoreNature::Challenge) => 1,
                None => 0,
            };
            len += eval_len;
        }
        len
    }

    fn to_field_elements(&self, _params: &OracleParams) -> Result<Vec<F>, Self::Error> {
        use CoreOracleError::*;
        let natures = SF::natures().flatten_vec();

        let mut coefficients = self.elements.iter();

        for nature in natures {
            match Option::<CoreNature>::from(nature) {
                Some(CoreNature::SmallInstance(coeffs)) => {
                    let expected = coeffs;
                    if let Some(coeffs) = coefficients.next() {
                        if coeffs.len() != expected {
                            return Err(CoefficientsLength);
                        }
                    } else {
                        return Err(MissingCoefficients);
                    }
                }
                Some(CoreNature::Challenge) => {
                    if let Some(coeffs) = coefficients.next() {
                        if coeffs.len() != 1 {
                            return Err(CoefficientsLength);
                        }
                    } else {
                        return Err(MissingCoefficients);
                    }
                }
                _ => {}
            };
        }
        if coefficients.next().is_some() {
            return Err(UnexpectedCoefficients);
        }
        Ok(self.elements.iter().flatten().cloned().collect())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CoreNature {
    SmallStructure,
    /// With n coefficients in the instance.
    SmallInstance(usize),
    Challenge,
}

impl From<CoreNature> for EvalLocation {
    fn from(val: CoreNature) -> Self {
        use CoreNature::*;
        match val {
            SmallStructure => EvalLocation::Structure,
            SmallInstance(_) => EvalLocation::Witness,
            Challenge => EvalLocation::Instance,
        }
    }
}

impl<A> From<Either<CoreNature, A>> for Option<CoreNature> {
    fn from(value: Either<CoreNature, A>) -> Self {
        match value {
            Either::Left(x) => Some(x),
            Either::Right(_) => None,
        }
    }
}

impl<F: Field, SF: SumcheckFunction<F>> PartialOracle<F, SF> for CoreOracle<F, SF>
where
    Option<CoreNature>: From<SF::Natures>,
{
    type Instance = CoreOracleInstance<F, SF>;

    type VerifierKey = Self;

    type Nature = CoreNature;

    type QueryRelation = CoreQueryRelation<F, SF>;

    fn instance_evals(instance: &Self::Instance) -> <SF as SumcheckFunction<F>>::Mles<F> {
        let natures = SF::natures();
        let mut coefficients = instance.elements.iter();

        let evals = natures.flatten_vec().into_iter().map(|nature| {
            if let Some(nature) = Option::from(nature) {
                match nature {
                    CoreNature::SmallInstance(n) => {
                        let coeffs = coefficients.next().unwrap();
                        assert_eq!(coeffs.len(), n);
                        F::ZERO
                    }
                    CoreNature::Challenge => coefficients.next().unwrap()[0],
                    _ => F::ZERO,
                }
            } else {
                F::ZERO
            }
        });
        let evals = SF::Mles::unflatten_vec(evals.collect());
        assert!(coefficients.next().is_none());
        evals
    }

    fn evals(
        key: &Self::VerifierKey,
        instance: &Self::Instance,
        point: &MultiPoint<F>,
    ) -> <SF as SumcheckFunction<F>>::Mles<OracleEval<F>> {
        let coeffs = decode::<F, SF>(instance.elements.clone());
        let functions = &key.functions;
        SF::combine(functions, &coeffs, |function, coeff| {
            let eval = coeff.as_ref().map(|coeff| function(coeff, point));
            match eval {
                Some(e) => OracleEval::Computed(e),
                None => OracleEval::None,
            }
        })
    }

    fn prover_provided(_nature: &Self::Nature) -> bool {
        false
    }
}

pub struct CoreQueryRelation<F, SF>(PhantomData<(F, SF)>);

impl<F, SF> Relation for CoreQueryRelation<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
    Option<CoreNature>: From<SF::Natures>,
{
    type Structure = CoreOracle<F, SF>;

    type Instance = PartialQueryInstance<F, CoreOracleInstance<F, SF>>;

    type Witness = Vec<SF::Mles<F>>;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        // While the PartialOracle trait fixes the type of the witness,
        // this relation has no witness.
        let _ = witness;
        let oracle_instance = instance.oracle_instance();
        let point = instance.point();
        let expected_evals = instance.evals();

        let coefficients = decode::<F, SF>(oracle_instance.elements.clone());
        let functions = &structure.functions;
        let natures = SF::natures();

        let evals = SF::combine(functions, &coefficients, |func, coeff| {
            coeff.as_ref().map(|coeff| func(coeff, point))
        });
        let _ = SF::combine(&evals, &natures, |eval, nature| {
            match (eval, Option::from(*nature)) {
                (None, None) | (Some(_), Some(_)) => {}
                (None, Some(_)) | (Some(_), None) => {
                    panic!()
                }
            };
        });

        let evals: Vec<F> = evals.flatten_vec().into_iter().flatten().collect();
        evals == expected_evals
    }
}

impl<F, SF> Reduction<F, CoreQueryRelation<F, SF>, ()> for CoreOracle<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
    Option<CoreNature>: From<SF::Natures>,
{
    type ProverKey = Self;

    type VerifierKey = Self;

    type Proof = ();

    type Error = ();

    fn transcript_pattern(
        _key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        // It is a non-interactive protocol
        builder
    }

    fn verifier_key(oracle: &Self, _: &()) -> Self::VerifierKey {
        oracle.clone()
    }

    fn key_pair(oracle: &Self, _: &()) -> (Self::VerifierKey, Self::ProverKey) {
        (oracle.clone(), oracle.clone())
    }

    fn prove<S: Duplex<F>>(
        key: &Self::ProverKey,
        instance: PartialQueryInstance<F, CoreOracleInstance<F, SF>>,
        witness: Vec<SF::Mles<F>>,
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<(), Self::Proof> {
        assert!(CoreQueryRelation::check(key, &instance, &witness));
        ProverOutput {
            instance: (),
            witness: (),
            proof: (),
        }
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: PartialQueryInstance<F, CoreOracleInstance<F, SF>>,
        _proof: GuardedProof<Self::Proof>,
        _transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<(), Self::Error> {
        // TODO: It would be better to implement it here with better errors
        // instead of relying on check().
        // As check doesn't make use of it.
        let witness = vec![];
        if CoreQueryRelation::check(key, &instance, &witness) {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl<F, SF> Argument<F, CoreQueryRelation<F, SF>> for CoreOracle<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
    Option<CoreNature>: From<SF::Natures>,
{
}
