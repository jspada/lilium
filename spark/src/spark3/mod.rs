use ark_ff::Field;
use std::{marker::PhantomData, rc::Rc};
use sumcheck::{eq, polynomials::MultiPoint};
use transcript::reduction2::Relation;

mod committed;
pub mod sumcheck_argument;

pub use committed::CommittedSparkRelation;

const BYTE: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMle<F, const N: usize> {
    /// Addresses in u8 segments.
    addresses: Vec<[u8; N]>,
    /// The value at given address.
    values: Vec<F>,
}

impl<F: Field, const N: usize> SparseMle<F, N> {
    pub fn eval(&self, point: &MultiPoint<F>) -> F {
        assert_eq!(point.vars(), N * 8);
        assert!(self.values.len().is_power_of_two());
        assert_eq!(self.values.len(), self.addresses.len());
        let segments: [MultiPoint<F>; N] = point
            .inner_ref()
            .chunks(8)
            .map(|segment| MultiPoint::new(segment.to_vec()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let eqs = segments.map(|segment| eq::eq(&segment));

        self.addresses
            .iter()
            .zip(&self.values)
            .fold(F::ZERO, |acc, (addr, val)| {
                let eq: F = addr
                    .iter()
                    .enumerate()
                    .fold(F::ONE, |acc, (i, addr)| acc * eqs[i][*addr as usize]);
                acc + eq * val
            })
    }
}

// #[derive(Clone, Debug)]
// struct MinorStructure<const N: usize> {
// counts: [Box<[usize; BYTE]>; N],
// }

#[derive(Clone, Debug)]
pub struct StaticSparkStructure<F: Field, const N: usize> {
    // minor_structure: MinorStructure<N>,
    mle: Rc<SparseMle<F, N>>,
}

pub struct StaticSparkRelation<F, const N: usize>(PhantomData<F>);

pub struct SparkInstance<F: Field> {
    point: MultiPoint<F>,
    eval: F,
}

impl<F, const N: usize> Relation for StaticSparkRelation<F, N>
where
    F: Field,
{
    type Structure = StaticSparkStructure<F, N>;

    type Instance = SparkInstance<F>;

    type Witness = ();

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        _witness: &Self::Witness,
    ) -> bool {
        if instance.point.vars() % 8 != 0 {
            return false;
        }

        let eval = structure.mle.eval(&instance.point);

        if eval != instance.eval {
            return false;
        }

        true
    }
}

// t' = eq(r,x)
// t = (0..256) * t'
// f = addr * eq
//
//      m           1
//  Σ -----  = Σ  -----
//    t + µ       f + µ
//
// for the right:
// r_inv = 1 / (f + µ)
// check that r_inv * (f + µ) == 1
