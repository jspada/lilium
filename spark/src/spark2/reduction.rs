use crate::{
    challenges::SparkChallenges,
    committed_spark::{CommittedSparkInstance, Error},
    spark2::{
        evals::SparkOpen, sumcheck_argument::SparkOpenSumcheck, CommittedSpark,
        CommittedSparkProof, InstanceEvals, MinorStructure, StructureEvals,
    },
};
use ark_ff::{batch_inversion, Field};
use commit::{
    batching::{structured::StructuredBatchEval, BatchEval},
    committed_structure::CommittedStructure,
    CommmitmentScheme, OpenInstance,
};
use sumcheck::{
    eq,
    polynomials::{Evals, MultiPoint},
    sumcheck::{Sum, SumcheckFunction, SumcheckVerifier},
};
use transcript::{messages::SingleElement, protocols::Reduction, MessageGuard, TranscriptBuilder};

impl<const N: usize> MinorStructure<N> {
    /// Computes the sums at the left of the equation, thanks to restricting the
    /// lookup table to 8 bits it can be done in about 256 operations.
    fn expected_sums<F: Field>(
        &self,
        point: &[MultiPoint<F>; N],
        lookup_challenge: F,
        compression_challenge: F,
    ) -> [F; N] {
        let mut res = [F::zero(); N];

        #[allow(clippy::needless_range_loop)]
        for i in 0..N {
            let point = &point[i];
            let counts = &self.counts[i];
            let mut denominators = eq::eq(point);
            for (i, e) in denominators.iter_mut().enumerate() {
                let address = F::from(i as u8);
                *e = address * compression_challenge + *e + lookup_challenge;
            }
            batch_inversion(&mut denominators);
            let inverses = denominators;
            res[i] = inverses
                .into_iter()
                .zip(counts.iter())
                .fold(F::zero(), |acc, e| {
                    let (inverse, count) = e;
                    let count = F::from(*count as u64);
                    acc + inverse * count
                });
        }
        res
    }
}

impl<F, C, const N: usize> Reduction<F> for CommittedSpark<F, C, N>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = CommittedSparkInstance<F, N>;

    type B = OpenInstance<F, C::Commitment>;

    type Key = Self;

    type Proof = CommittedSparkProof<F, C, N>;

    type Error = Error<F, C>;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        builder
            .round::<F, CommittedSparkInstance<F, N>, 0>()
            // Lookup and compression challenges
            .round::<F, [C::Commitment; N], 2>()
            // Random point for zerocheck.
            .point()
            // Combination challenge.
            .round::<F, [C::Commitment; N], 1>()
            .add_reduction_pattern::<F, SumcheckVerifier<F, SparkOpenSumcheck<N>>>(
                &key.sumcheck_verifier,
            )
            .round::<F, InstanceEvals<SingleElement<F>, N>, 0>()
            .round::<F, StructureEvals<SingleElement<F>, N>, 0>()
            .add_reduction_pattern::<F, CommittedStructure<F, SparkOpenSumcheck<N>, C>>(
                &key.committed_structure,
            )
    }

    fn verify_reduction<S: sponge::sponge::Duplex<F>>(
        key: &Self::Key,
        instance: transcript::MessageGuard<Self::A>,
        mut transcript: transcript::TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        let (instance, []) = transcript.unwrap_guard(instance)?;

        // FIRST ROUND: Sending commitments to lookups, getting challenges
        // for lookup argument.
        let (eq_lookup_commitments, [c1, c2]) =
            transcript.receive_message(|proof| proof.eq_lookup_commitments.clone())?;

        let lookup_challenge = c1;
        let compression_challenge = c2;

        let zero_check_point = MultiPoint::new(transcript.point()?);

        // SECOND ROUND: Sending commitments to the inverses of the indexed lookups.
        // Another challenge is received to combine the multiple sumchecks into 1.
        let (fraction_lookup_commitments, [c3]) =
            transcript.receive_message(|proof| proof.fraction_lookup_commitments.clone())?;
        let combination_challenge = c3;

        let CommittedSparkInstance { point, eval } = instance;
        assert_eq!(point[0].vars(), 8);
        // Expected sums from computing the left side directly.
        let expected_sums =
            key.minor_structure
                .expected_sums(&point, lookup_challenge, compression_challenge);

        let sum = expected_sums
            .into_iter()
            .fold(F::zero(), |acc, s| acc * combination_challenge + s);
        let sum = sum * combination_challenge + eval;
        let sumcheck_instance = MessageGuard::new(Sum(sum));

        let sumcheck_proof =
            transcript.receive_message_delayed(|proof| proof.sumcheck_proof.clone());

        // THIRD ROUND: Sumcheck is ran, reducing the sumcheck claim to checking
        // point evaluation.
        let reduced = SumcheckVerifier::verify_reduction(
            &key.sumcheck_verifier,
            sumcheck_instance,
            transcript.new_guard(sumcheck_proof),
        )?;

        // Checking the evaluation.
        let r = MultiPoint::new(reduced.vars);
        let zero_eq_eval = zero_check_point.eval_as_eq(&r);
        // let eq_evals = point.map(|x| x.eval_as_eq(&r));
        // let small_evals = SparkEval::<F, D>::small_evals(zero_eq_eval, eq_evals);
        let small_evals = SparkOpen::<F, N>::small_evals(zero_eq_eval);

        // FOURTH ROUND: Received the alleged evaluation of the commitments at r.
        // And prepare a batch opening to check them all.
        let instance: MessageGuard<StructuredBatchEval<F, C>> = {
            let commitments: Vec<C::Commitment> = eq_lookup_commitments
                .into_iter()
                .zip(fraction_lookup_commitments)
                .flat_map(|(eq, frac)| [eq, frac])
                .collect();

            let (instance_evals, []) = transcript
                .receive_message(|proof| proof.instance_evals.map(|x| x.map(SingleElement)))?;
            let (structure_evals, []) = transcript.receive_message(|proof| {
                let shared = SingleElement(proof.structure_evals.1);
                let per_dimension = proof.structure_evals.0.map(SingleElement);
                (per_dimension, shared)
            })?;

            let commitments_and_evals: Vec<(C::Commitment, F)> = commitments
                .into_iter()
                .zip(instance_evals.into_iter().flatten().map(|x| x.0))
                .collect();

            let dynamic_batch: BatchEval<F, C> = BatchEval::new(r, commitments_and_evals);

            let structure_evals: Vec<F> = structure_evals
                .0
                .into_iter()
                .chain([structure_evals.1])
                .map(|x| x.0)
                .collect();

            let instance = StructuredBatchEval::new(dynamic_batch, structure_evals);
            MessageGuard::new(instance)
        };

        // SIXTH ROUND: Reduce all polynomial oppening claims to a single one.
        let (open_instance, evals) = CommittedStructure::verify_reduction(
            &key.committed_structure,
            instance,
            transcript.new_guard(()),
        )?;

        let evals = evals.combine(&small_evals, |committed, small| committed.xor(small));
        let evals: SparkOpen<F, N> =
            <SparkOpenSumcheck<N> as SumcheckFunction<F>>::map_evals(evals, Option::unwrap);

        let challenges = SparkChallenges::new(
            lookup_challenge,
            combination_challenge,
            compression_challenge,
        );

        // Finally, check the sumcheck evaluation.
        let checks =
            key.sumcheck_verifier
                .check_evals_at_r_symbolic(evals, reduced.eval, &challenges);

        if checks {
            Ok(open_instance)
        } else {
            Err(Error::EvalCheck)
        }
    }
}
