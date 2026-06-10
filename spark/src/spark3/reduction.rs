use crate::spark3::{
    committed::{MinorStructure, SparkOracle},
    sumcheck_argument::{SparkChallenges, SparkEvals},
    SparkInstance, StaticSparkRelation, StaticSparkStructure,
};
use ark_ff::Field;
use commit::commit2::{
    oracle::{CommittedOracle, CommittedOracleInstance},
    CommitmentScheme, OpenInstance, OpeningRelation,
};
use sponge::sponge::Duplex;
use std::marker::PhantomData;
use sumcheck::{
    polynomials::MultiPoint,
    sumcheck2::{
        oracles::{
            composite::{
                CompositeOracle, CompositeOracleInstance, CompositeReductionKey, ProverEvals,
            },
            core::{CoreOracle, CoreOracleInstance},
            partial::{Nature, PartialOracle, PartialQueryInstance},
            SumcheckFunction,
        },
        SumcheckInstance, SumcheckMessage, SumcheckReduction, SumcheckVerifierKey,
    },
};
use transcript::reduction2::{
    GuardedProof, ProverOutput, Reduction, Transcript, TranscriptBuilder, VerifierTranscript,
};

pub struct SparkReduction<F: Field, C: CommitmentScheme<F>, const N: usize>(PhantomData<(F, C)>);

type Rel1<F, const N: usize> = StaticSparkRelation<F, N>;
type Rel2<F, C> = OpeningRelation<F, C>;

#[derive(Clone, Debug)]
pub struct Proof<F: Field, C: CommitmentScheme<F>, const N: usize> {
    lookup_commitments: [C::Commitment; N],
    inverse_commitments: [C::Commitment; N],
    sumcheck_proof: Vec<SumcheckMessage<F>>,
    oracle_query_proof: ProverEvals<F>,
}

fn split_point<F: Field, const N: usize>(point: &MultiPoint<F>) -> [MultiPoint<F>; N] {
    point
        .inner_ref()
        .chunks(8)
        .map(|segment| {
            assert_eq!(segment.len(), 8);
            MultiPoint::new(segment.to_vec())
        })
        .collect::<Vec<MultiPoint<F>>>()
        .try_into()
        .unwrap()
}

pub struct Key<F, C, SF, const N: usize>
where
    F: Field,
    C: CommitmentScheme<F>,
    SF: SumcheckFunction<F>,
    SF::Natures: Nature,
    CommittedOracle<F, C, SF>: PartialOracle<F, SF>,
{
    minor_structure: MinorStructure<N>,
    sumcheck_key: SumcheckVerifierKey<F>,
    oracle_key: CompositeReductionKey<F, SF, CoreOracle<F, SF>, CommittedOracle<F, C, SF>>,
}

impl<F, C, const N: usize> Reduction<F, Rel1<F, N>, Rel2<F, C>> for SparkReduction<F, C, N>
where
    F: Field,
    C: CommitmentScheme<F>,
{
    type ProverKey = ();

    type VerifierKey = Key<F, C, SparkEvals<(), N>, N>;

    type Proof = Proof<F, C, N>;

    type Error = ();

    fn transcript_pattern(
        key: &Self::VerifierKey,
        builder: TranscriptBuilder,
    ) -> TranscriptBuilder {
        let vars = key.sumcheck_key.vars();
        builder
            .round::<F, [C::Commitment; N], 2>(&())
            .point::<F>(vars)
            .round::<F, [C::Commitment; N], 1>(&())
            .subprotocol::<SumcheckReduction<F, SparkOracle<F, C, N>>, _, _, _>(&key.sumcheck_key)
            .subprotocol::<CompositeOracle<F, SparkEvals<(), N>, _, _>, _, _, _>(&key.oracle_key)
            .subprotocol::<CoreOracle<F, SparkEvals<(), N>>, _, _, _>(key.oracle_key.p1_key())
            .subprotocol::<CommittedOracle<F, C, SparkEvals<(), N>>, F, _, _>(
                key.oracle_key.p2_key(),
            )
    }

    fn verifier_key(
        _structure_1: &StaticSparkStructure<F, N>,
        _structure_2: &C,
    ) -> Self::VerifierKey {
        todo!()
    }

    fn key_pair(
        _structure_1: &StaticSparkStructure<F, N>,
        _structure_2: &C,
    ) -> (Self::VerifierKey, Self::ProverKey) {
        todo!()
    }

    fn prove<S: Duplex<F>>(
        _key: &Self::ProverKey,
        _instance: SparkInstance<F>,
        _witness: (),
        _transcript: &mut Transcript<F, S>,
    ) -> ProverOutput<OpeningRelation<F, C>, Self::Proof> {
        todo!()
    }

    fn verify<S: Duplex<F>>(
        key: &Self::VerifierKey,
        instance: SparkInstance<F>,
        proof: GuardedProof<Self::Proof>,
        transcript: &mut VerifierTranscript<F, S>,
    ) -> Result<OpenInstance<F, C>, Self::Error> {
        // FIRST ROUND: Sending commitments to lookups, getting challenges
        // for lookup argument.
        let Ok((lookup_commitments, [c1, c2])) =
            transcript.receive_message(|proof| proof.lookup_commitments.clone(), &proof, &());

        let lookup_chall = c1;
        let compression_chall = c2;

        let zerocheck_point = MultiPoint::new(transcript.point());

        // SECOND ROUND: Sending commitments to the inverses of the indexed lookups.
        // Another challenge is received to combine the multiple sumchecks into 1.
        let Ok((inverse_commitments, [c3])) =
            transcript.receive_message(|proof| proof.inverse_commitments.clone(), &proof, &());
        let combination_chall = c3;

        let SparkInstance { point, eval } = instance;

        let points = split_point(&point);
        // Expected sums from computing the left side directly.
        let expected_sums =
            key.minor_structure
                .expected_sums(&points, lookup_chall, compression_chall);

        let sum = expected_sums
            .into_iter()
            .fold(F::zero(), |acc, s| acc * combination_chall + s);
        let sum = sum * combination_chall + eval;

        let challenges = SparkChallenges::new(combination_chall, compression_chall, lookup_chall);

        let sumcheck_instance = sumcheck_instance::<F, C, N>(
            sum,
            lookup_commitments,
            inverse_commitments,
            zerocheck_point,
            &challenges,
        );

        let sumcheck_proof = proof.clone().map(|proof| proof.sumcheck_proof);
        //TODO: handle
        let query_instance = SumcheckReduction::verify(
            &key.sumcheck_key,
            sumcheck_instance,
            sumcheck_proof,
            transcript,
        )
        .unwrap();

        let oracle_proof = proof.map(|proof| proof.oracle_query_proof);
        //TODO: handle
        let red =
            CompositeOracle::verify(&key.oracle_key, query_instance, oracle_proof, transcript)
                .unwrap();

        let (core_query, committed_query) = red;
        let core_query: PartialQueryInstance<F, CoreOracleInstance<F, _>> = core_query;

        let core_proof = GuardedProof::empty();
        //TODO: handle
        CoreOracle::verify(key.oracle_key.p1_key(), core_query, core_proof, transcript).unwrap();

        let committed_query: PartialQueryInstance<F, CommittedOracleInstance<F, C, _>> =
            committed_query;

        let proof = GuardedProof::empty();
        let Ok(open_instance) =
            CommittedOracle::verify(key.oracle_key.p2_key(), committed_query, proof, transcript);

        Ok(open_instance)
    }
}

fn sumcheck_instance<F, C, const N: usize>(
    sum: F,
    lookup_commitments: [C::Commitment; N],
    inverse_commitments: [C::Commitment; N],
    zerocheck_point: MultiPoint<F>,
    challenges: &SparkChallenges<F>,
) -> SumcheckInstance<F, SparkOracle<F, C, N>>
where
    F: Field,
    C: CommitmentScheme<F>,
{
    let coefficients: SparkEvals<Vec<F>, N> =
        SparkEvals::oracle_instance(challenges, zerocheck_point);
    let core_oracle_instance = CoreOracleInstance::new(&coefficients);

    let commits = SparkEvals::arrange_commitments(lookup_commitments, inverse_commitments);
    let committed_oracle_instance = CommittedOracleInstance::new(commits);

    let oracle_instance = CompositeOracleInstance {
        oracle1_instance: core_oracle_instance,
        oracle2_instance: committed_oracle_instance,
    };

    SumcheckInstance::new(sum, oracle_instance)
}
