use ark_ff::Field;
use commit::commit2::oracle::CommittedNature;
use std::fmt::Debug;
use std::vec::IntoIter;
use sumcheck::{
    sumcheck::Var,
    sumcheck2::{
        evals::{Evals, EvalsCore},
        oracles::{composite::Either, core::CoreNature, SumcheckFunction},
    },
};
use sumcheck_derive::EvalsCore;

#[derive(Clone, Debug, EvalsCore)]
pub struct DimensionEvals<V: Clone + Debug = ()> {
    address: V,
    eq_lookup: V,
    inverse: V,
}

#[derive(Clone, Debug, EvalsCore)]
pub struct SparkEvals<V: Clone + Debug, const N: usize> {
    dimensions: [DimensionEvals<V>; N],
    value: V,
    zerocheck: V,
    challenges: SparkChallenges<V>,
}

#[derive(Clone, Debug, EvalsCore)]
pub struct SparkChallenges<V: Clone + Debug> {
    combination: V,
    compression: V,
    lookup: V,
}

impl SparkChallenges<Either<CoreNature, CommittedNature>> {
    pub fn natures() -> Self {
        let challenge = Either::Left(CoreNature::Challenge);
        Self {
            combination: challenge,
            compression: challenge,
            lookup: challenge,
        }
    }
}

impl<F: Field, const N: usize> SumcheckFunction<F> for SparkEvals<(), N> {
    type Natures = Either<CoreNature, CommittedNature>;

    fn natures() -> Self::Mles<Self::Natures> {
        let r = |n| Either::Right(n);

        let dimensions = [(); N].map(|_| DimensionEvals {
            address: r(CommittedNature::Structure),
            eq_lookup: r(CommittedNature::Witness),
            inverse: r(CommittedNature::Witness),
        });
        SparkEvals {
            dimensions,
            value: r(CommittedNature::Structure),
            //TODO: actually is 1 per variable.
            zerocheck: Either::Left(CoreNature::SmallInstance(2)),
            challenges: SparkChallenges::natures(),
        }
    }

    fn function<V: Var<F> + Debug>(&self, evals: &Self::Mles<V>) -> V {
        let SparkEvals {
            dimensions,
            value,
            zerocheck,
            challenges,
        } = &evals;

        let dimensions: &[DimensionEvals<V>; N] = dimensions;

        let mut checks = form_check::<F, V>(&dimensions[0], challenges);
        let mut eq = dimensions[0].eq_lookup.clone();

        for dimension in &dimensions[1..] {
            let check = form_check(dimension, challenges);
            checks = checks * &challenges.combination + check;
            let eq_segment = &dimension.eq_lookup;
            eq = eq * eq_segment;
        }

        let eval = eq * value;

        let zerocheck = checks * zerocheck;
        let mut inverse_sums = zerocheck;

        for dimension in dimensions {
            let inverse = &dimension.inverse;
            inverse_sums = inverse_sums * &challenges.combination + inverse;
        }

        inverse_sums * &challenges.combination + eval
    }
}

fn form_check<F, V>(dim: &DimensionEvals<V>, challenges: &SparkChallenges<V>) -> V
where
    F: Field,
    V: Var<F> + Debug,
{
    let indexed_lookup = dim.address.clone() * &challenges.compression + &dim.eq_lookup;

    let product = (indexed_lookup + &challenges.lookup) * &dim.inverse;

    product - F::one()
}
