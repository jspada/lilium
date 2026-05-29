use crate::commit2::{CommitmentScheme, OpenInstance, OpeningRelation};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::{convert::identity, marker::PhantomData, rc::Rc};
use sumcheck::{
    polynomials::{Evals, EvalsExt, MultiPoint},
    sumcheck2::oracles::{
        partial::{merge, OracleEval, OracleParams, PartialOracle, PartialQueryInstance},
        EvalLocation, SumcheckFunction,
    },
};
use transcript::reduction2::{
    GuardedProof, Message, NoError, ProverOutput, Reduction, Relation, Transcript,
    TranscriptBuilder, VerifierTranscript,
};

/// An oracle based on a commitment scheme.
#[derive(Clone, Debug)]
pub struct CommittedOracle<F: Field, C, SF: SumcheckFunction<F>> {
    // f: SF,
    structure_evals: Rc<Vec<SF::Mles<F>>>,
    // instance_commitments: usize,
    // structure_commitments: usize,
    // challenges: usize,
    // vars: usize,
    scheme: C,
}

#[derive(Clone, Copy, Debug)]
pub enum CommittedNature {
    CommittedStructure,
    CommittedWitness,
}

impl From<CommittedNature> for EvalLocation {
    fn from(value: CommittedNature) -> Self {
        use CommittedNature::*;
        match value {
            CommittedStructure => EvalLocation::Structure,
            CommittedWitness => EvalLocation::Witness,
        }
    }
}

pub trait CommittedFunction<F: Field>: SumcheckFunction<F> {
    fn natures() -> Self::Mles<CommittedNature>;
}

#[derive(Clone, Debug)]
pub struct CommittedOracleInstance<F: Field, C: CommitmentScheme<F>, SF> {
    commitments: Vec<C::Commitment>,
    _sf: PhantomData<SF>,
}

fn witness_commits<F: Field, SF: SumcheckFunction<F>>() -> usize
where
    Option<CommittedNature>: From<SF::Natures>,
{
    SF::natures()
        .flatten_vec()
        .into_iter()
        .map(|nature| {
            if let Some(CommittedNature::CommittedWitness) = Option::from(nature) {
                1
            } else {
                0
            }
        })
        .sum()
}

impl<F, C, SF> Message<F> for CommittedOracleInstance<F, C, SF>
where
    F: Field,
    C: CommitmentScheme<F>,
    SF: SumcheckFunction<F>,
    Option<CommittedNature>: From<SF::Natures>,
{
    type Params = OracleParams;

    type Error = ();

    fn len(_params: &Self::Params) -> usize {
        let commits: usize = witness_commits::<F, SF>();
        C::Commitment::len(&()) * commits
    }

    fn to_field_elements(&self, _params: &OracleParams) -> Result<Vec<F>, Self::Error> {
        let mut elems: Vec<F> = vec![];

        let commits = witness_commits::<F, SF>();
        if commits != self.commitments.len() {
            return Err(());
        }
        for commitment in &self.commitments {
            let Ok(commitment_elements) = commitment.to_field_elements(&());
            elems.extend(commitment_elements);
        }
        Ok(elems)
    }
}

//NOTE: It may be worth providing a similar method in the pcs
//trait itself so that it can be implemented better on each pcs.
fn commit_filtered<F, SF, C>(
    evals: &[SF::Mles<F>],
    pcs: &C,
    filter: SF::Mles<bool>,
) -> SF::Mles<Option<C::Commitment>>
where
    F: Field,
    SF: SumcheckFunction<F>,
    C: CommitmentScheme<F>,
{
    let mut evals_to_commit = SF::map_evals(&filter, |_| vec![]);
    let condition = filter;

    for eval in evals {
        let condition = condition.clone();
        SF::combine_mut_conditional(&mut evals_to_commit, eval, condition, |a, b, c| {
            if c {
                a.push(*b);
            }
        });
    }

    SF::map_evals(&evals_to_commit, |evals| {
        if !evals.is_empty() {
            Some(pcs.commit_mle(evals))
        } else {
            None
        }
    })
}

#[derive(Clone, Debug)]
pub struct VerifierKey<F: Field, C: CommitmentScheme<F>> {
    structure_commits: Vec<C::Commitment>,
}

impl<F, C, SF> From<CommittedOracle<F, C, SF>> for VerifierKey<F, C>
where
    F: Field,
    C: CommitmentScheme<F>,
    SF: SumcheckFunction<F>,
    Option<CommittedNature>: From<SF::Natures>,
{
    fn from(value: CommittedOracle<F, C, SF>) -> Self {
        let condition = SF::map_evals(&SF::natures(), |nature| {
            matches!(
                Option::from(*nature),
                Some(CommittedNature::CommittedStructure)
            )
        });

        let structure_commits =
            commit_filtered::<F, SF, C>(&value.structure_evals, &value.scheme, condition)
                .flatten_vec()
                .into_iter()
                .flatten()
                .collect();

        Self { structure_commits }
    }
}

impl<F, C, SF> PartialOracle<F, SF> for CommittedOracle<F, C, SF>
where
    F: Field,
    C: CommitmentScheme<F>,
    SF: SumcheckFunction<F>,
    Option<CommittedNature>: From<SF::Natures>,
    SF::Natures: Into<EvalLocation>,
{
    type Instance = CommittedOracleInstance<F, C, SF>;

    type VerifierKey = VerifierKey<F, C>;

    type Nature = CommittedNature;

    type QueryRelation = CommittedQueryRelation<F, C, SF>;

    fn instance_evals(_instance: &Self::Instance) -> SF::Mles<F> {
        SF::map_evals(&SF::natures(), |_| F::ZERO)
    }

    fn evals(
        _key: &Self::VerifierKey,
        _instance: &Self::Instance,
        _point: &MultiPoint<F>,
    ) -> SF::Mles<OracleEval<F>> {
        SF::map_evals(&SF::natures(), |nature| match Option::from(*nature) {
            Some(_) => OracleEval::ProverProvided,
            None => OracleEval::None,
        })
    }

    fn prover_provided(_nature: &Self::Nature) -> bool {
        true
    }
}

pub struct CommittedQueryRelation<F, C, SF>(PhantomData<(F, C, SF)>);

impl<F, C, SF> Relation for CommittedQueryRelation<F, C, SF>
where
    F: Field,
    C: CommitmentScheme<F>,
    SF: SumcheckFunction<F>,
    Option<CommittedNature>: From<SF::Natures>,
    SF::Natures: Copy,
    SF::Natures: Into<EvalLocation>,
{
    type Structure = CommittedOracle<F, C, SF>;

    type Instance = PartialQueryInstance<F, CommittedOracleInstance<F, C, SF>>;

    type Witness = Vec<SF::Mles<F>>;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let oracle_instance = instance.oracle_instance();
        let mut expected_evals = instance.evals().iter();
        let expected_evals = SF::natures()
            .flatten_vec()
            .into_iter()
            .map(|nature| Option::from(nature).map(|_| *expected_evals.next().unwrap()))
            .collect();
        let expected_evals = SF::Mles::unflatten_vec(expected_evals);

        let mut expected_commits = oracle_instance.commitments.clone().into_iter();
        let expected_commits = SF::natures()
            .flatten_vec()
            .iter()
            .map(|nature| {
                if let Some(CommittedNature::CommittedWitness) = Option::from(*nature) {
                    Some(expected_commits.next().unwrap())
                } else {
                    None
                }
            })
            .collect();
        let expected_commits = SF::Mles::unflatten_vec(expected_commits);

        let instance_evals = SF::map_evals(&SF::natures(), |_| F::ZERO);
        let locations = SF::map_evals(&SF::natures(), |nature| (*nature).into());
        let evals: Vec<SF::Mles<F>> = structure
            .structure_evals
            .iter()
            .zip(witness)
            .map(|(structure, witness)| {
                merge::<F, SF>(structure, &instance_evals, witness, &locations)
            })
            .collect();

        let filter = SF::map_evals(&SF::natures(), |nature| {
            matches!(
                Option::from(*nature),
                Some(CommittedNature::CommittedWitness)
            )
        });
        let commits = commit_filtered::<F, SF, C>(&evals, &structure.scheme, filter);

        let point_evals = EvalsExt::eval(&evals, instance.point().clone());

        let valid_evals = SF::combine(
            &expected_evals,
            &point_evals,
            |expected, eval| match expected {
                Some(expected) => expected == eval,
                None => true,
            },
        );

        if !valid_evals.flatten_vec().into_iter().all(identity) {
            return false;
        }

        let valid_commits = SF::combine(&expected_commits, &commits, |expected, commit| {
            match (expected, commit) {
                (None, None) => true,
                (Some(expected), Some(commit)) => expected == commit,
                _ => unreachable!(),
            }
        });

        valid_commits.flatten_vec().into_iter().all(identity)
    }
}

fn fold_instance<F, SF, C>(
    instance: PartialQueryInstance<F, CommittedOracleInstance<F, C, SF>>,
    structure_commits: &[C::Commitment],
    chall: F,
) -> OpenInstance<F, C>
where
    F: Field,
    C: CommitmentScheme<F>,
    SF: SumcheckFunction<F>,
    Option<CommittedNature>: From<SF::Natures>,
{
    let eval = instance
        .evals()
        .iter()
        .fold(F::ZERO, |acc, eval| acc * chall + eval);

    let mut instance_commits = instance.oracle_instance().commitments.iter();
    let mut structure_commits = structure_commits.iter();

    let mut commits = SF::natures()
        .flatten_vec()
        .into_iter()
        .filter_map(|nature| {
            Option::from(nature).map(|nature| match nature {
                CommittedNature::CommittedStructure => structure_commits.next().unwrap(),
                CommittedNature::CommittedWitness => instance_commits.next().unwrap(),
            })
        })
        .cloned();
    let first_commit = commits.next().unwrap();
    let commit = commits.fold(first_commit, |acc, commit| acc * chall + commit);

    assert!(instance_commits.next().is_none());
    assert!(structure_commits.next().is_none());

    let point = instance.point().clone();
    OpenInstance {
        commit,
        point,
        eval,
    }
}

#[derive(Clone, Debug)]
pub struct ProverKey<F: Field, SF: SumcheckFunction<F>, C: CommitmentScheme<F>> {
    structure_commits: Vec<C::Commitment>,
    structure_evals: Rc<Vec<SF::Mles<F>>>,
}

impl<F, C, SF> Reduction<F, CommittedQueryRelation<F, C, SF>, OpeningRelation<F, C>>
    for CommittedOracle<F, C, SF>
where
    F: Field,
    C: CommitmentScheme<F>,
    SF: SumcheckFunction<F>,
    Option<CommittedNature>: From<SF::Natures>,
    SF::Natures: Copy,
    SF::Natures: Into<EvalLocation>,
{
    type ProverKey = ProverKey<F, SF, C>;

    type VerifierKey = VerifierKey<F, C>;

    type Proof = ();

    type Error = NoError;

    fn transcript_pattern(
        _key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        builder.round::<F, (), 1>(&())
    }

    fn verifier_key(oracle: &Self, _: &C) -> Self::VerifierKey {
        let structure_filter = SF::map_evals(&SF::natures(), |nature| {
            matches!(
                Option::from(*nature),
                Some(CommittedNature::CommittedStructure)
            )
        });
        let commits =
            commit_filtered::<F, SF, C>(&oracle.structure_evals, &oracle.scheme, structure_filter);
        let structure_commits = commits.flatten_vec().into_iter().flatten().collect();
        VerifierKey { structure_commits }
    }

    fn instance_params(
        _key: &Self::VerifierKey,
    ) -> <<CommittedQueryRelation<F, C, SF> as Relation>::Instance as Message<F>>::Params
    where
        <CommittedQueryRelation<F, C, SF> as Relation>::Instance: Message<F>,
    {
        todo!()
    }

    fn key_pair(oracle: &Self, structure_2: &C) -> (Self::VerifierKey, Self::ProverKey) {
        let verifier_key = Self::verifier_key(oracle, structure_2);
        let structure_commits = verifier_key.structure_commits.clone();
        let structure_evals = Rc::clone(&oracle.structure_evals);
        let prover_key = ProverKey {
            structure_commits,
            structure_evals,
        };
        (verifier_key, prover_key)
    }

    fn prove<S: Duplex<F>>(
        key: &Self::ProverKey,
        instance: PartialQueryInstance<F, CommittedOracleInstance<F, C, SF>>,
        witness: Vec<SF::Mles<F>>,
        transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<OpeningRelation<F, C>, Self::Proof> {
        let filter: Vec<bool> = SF::natures()
            .flatten_vec()
            .into_iter()
            .map(|nature| Option::from(nature).is_some())
            .collect();

        let locations = SF::map_evals(&SF::natures(), |nature| (*nature).into());
        let mut space = vec![F::ZERO; filter.len()];

        let [chall] = transcript.send_message(&(), &());

        let instance_evals = SF::map_evals(&locations, |_| F::ZERO);
        let witness: Vec<F> = witness
            .into_iter()
            .zip(key.structure_evals.iter())
            .map(|(witness, structure)| {
                let evals = merge::<F, SF>(structure, &instance_evals, &witness, &locations);
                evals.flatten(&mut space);
                let mut combined_eval = F::ZERO;
                for (eval, is_committed) in space.iter().zip(&filter) {
                    if *is_committed {
                        combined_eval *= chall;
                        combined_eval += eval;
                    }
                }
                combined_eval
            })
            .collect();

        let instance = fold_instance(instance, &key.structure_commits, chall);

        ProverOutput {
            instance,
            witness,
            proof: (),
        }
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: PartialQueryInstance<F, CommittedOracleInstance<F, C, SF>>,
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<OpenInstance<F, C>, Self::Error> {
        let Ok((_, [chall])) = transcript.receive_message(|_| (), &proof, &());

        Ok(fold_instance(instance, &key.structure_commits, chall))
    }
}
