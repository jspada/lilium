use crate::spark3::{
    sumcheck_argument::SparkEvals, SparkInstance, SparseMle, StaticSparkRelation,
    StaticSparkStructure, BYTE,
};
use ark_ff::Field;
use commit::commit2::{oracle::CommittedOracle, CommitmentScheme};
use std::{marker::PhantomData, rc::Rc};
use sumcheck::sumcheck2::{
    evals::Evals,
    oracles::{composite::CompositeOracle, core::CoreOracle, SumcheckFunction},
};
use transcript::reduction2::Relation;

pub struct CommittedSparkRelation<F, C, const N: usize>(PhantomData<(F, C)>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinorStructure<const N: usize> {
    pub counts: [Box<[usize; BYTE]>; N],
}

impl<const N: usize> MinorStructure<N> {
    fn new<F: Field>(mle: &SparseMle<F, N>) -> Self {
        let mut counts: [Box<[usize; 256]>; N] =
            [(); N].map(|_| (vec![0; BYTE]).into_boxed_slice().try_into().unwrap());

        for (i, counts) in counts.iter_mut().enumerate() {
            for addr in mle.addresses.iter() {
                let segment = addr[i];
                counts[segment as usize] += 1;
            }
        }

        Self { counts }
    }
}

type Oracle<F, C, SF> = CompositeOracle<F, SF, CoreOracle<F, SF>, CommittedOracle<F, C, SF>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedSparkStructure<F: Field, C: CommitmentScheme<F>, const N: usize> {
    oracle: Oracle<F, C, SparkEvals<(), N>>,
    minor_structure: MinorStructure<N>,
    mle: Rc<SparseMle<F, N>>,
    pcs: C,
}

impl<F, C, const N: usize> Relation for CommittedSparkRelation<F, C, N>
where
    F: Field,
    C: CommitmentScheme<F>,
{
    type Structure = CommittedSparkStructure<F, C, N>;

    type Instance = SparkInstance<F>;

    type Witness = ();

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        let static_spark = StaticSparkStructure {
            mle: Rc::clone(&structure.mle),
        };
        if !StaticSparkRelation::check(&static_spark, instance, witness) {
            return false;
        }
        let minor_structure = MinorStructure::new(&structure.mle);
        if minor_structure != structure.minor_structure {
            return false;
        }

        let oracle = oracle(&structure.mle, structure.pcs.clone());
        oracle == structure.oracle
    }
}

fn oracle<F, C, const N: usize>(mles: &SparseMle<F, N>, pcs: C) -> Oracle<F, C, SparkEvals<(), N>>
where
    F: Field,
    C: CommitmentScheme<F>,
{
    let natures = <SparkEvals<(), N> as SumcheckFunction<F>>::natures();
    let f: SparkEvals<(), N> = SparkEvals::map_evals(&natures, |_| ());

    let builder1: CoreOracle<F, SparkEvals<(), N>> = {
        let functions = SparkEvals::small_functions();
        CoreOracle::new(functions)
    };

    let builder2 = { pcs };

    let mles = Rc::new(SparkEvals::structure(mles));

    CompositeOracle::new(f, mles, builder1, builder2)
}

impl<F: Field, C: CommitmentScheme<F>, const N: usize> CommittedSparkStructure<F, C, N> {
    pub fn new(mle: Rc<SparseMle<F, N>>, pcs: C) -> Self {
        let minor_structure = MinorStructure::new(&mle);
        let oracle = oracle(&mle, pcs.clone());
        Self {
            oracle,
            minor_structure,
            mle,
            pcs,
        }
    }
}
