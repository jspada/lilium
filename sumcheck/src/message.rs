use crate::{
    barycentric_eval::BarycentricWeights,
    polynomials::Evals,
    sumcheck::{DegreeParam, Env, Var},
};
use ark_ff::Field;
use std::ops::{Add, AddAssign, Index, Mul, MulAssign, Sub};
use transcript::params::ParamResolver;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message<F: Field>(Vec<F>);

impl<F: Field> transcript::Message<F> for Message<F> {
    fn len(_vars: usize, param_resolver: &ParamResolver) -> usize {
        let degree = param_resolver.get::<DegreeParam>();
        degree + 1
    }

    fn to_field_elements(&self) -> Vec<F> {
        self.0.clone()
    }
}

impl<F: Field> Message<F> {
    pub(crate) fn new(evals: Vec<F>) -> Self {
        Self(evals)
    }

    pub(crate) fn inner(&self) -> &[F] {
        &self.0
    }

    pub(crate) fn new_degree_n(eval_at_0: F, eval_at_1: F, degree: usize) -> Self {
        assert!(degree >= 1, "degree should be >= 1");
        // e0, e1
        // P(x) = (e1 - e0)x + e0
        // TODO: it may be possible to exploit this structure further
        let mut message = Vec::with_capacity(degree + 1);
        let diff = eval_at_1 - eval_at_0;
        let mut last = F::zero();
        //as x is 0..d multiplication is unnecessary
        for _ in 0..=degree {
            message.push(last + eval_at_0);
            last += diff;
        }
        Message(message)
    }

    pub(crate) fn degree(&self) -> usize {
        self.0.len() - 1
    }

    /// Adds an extra evaluation to handle a bigger degree.
    pub(crate) fn extend(self, weights: &BarycentricWeights<F>) -> Self {
        let next_point = F::from(self.degree() as u32 + 1);
        let message_extra_eval = self.eval_at_x(next_point, weights);
        let evals = self.0.into_iter().chain([message_extra_eval]);
        Self(evals.collect())
    }
}

impl<F: Field> Message<F> {
    fn bin_op<B: Fn(F, F) -> F>(mut self, rhs: &Self, f: B) -> Self {
        for ab in self.0.iter_mut().zip(rhs.0.iter()) {
            let (a, b): (&mut F, &F) = ab;
            *a = f(*a, *b);
        }
        self
    }
    pub fn eval_at_0(&self) -> F {
        self.0[0]
    }
    pub fn eval_at_1(&self) -> F {
        self.0[1]
    }
    pub(crate) fn eval_at_x(&self, x: F, weights: &BarycentricWeights<F>) -> F {
        weights.evaluate(&self.0, x)
    }
}

impl<F: Field> Add<Self> for Message<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.bin_op(&rhs, |a: F, b: F| a + b)
    }
}
impl<F: Field> Sub<Self> for Message<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.bin_op(&rhs, |a: F, b: F| a - b)
    }
}
impl<F: Field> Mul<Self> for Message<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.bin_op(&rhs, |a: F, b: F| a * b)
    }
}
impl<F: Field> Add<&Self> for Message<F> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs, |a: F, b: F| a + b)
    }
}
impl<F: Field> Sub<&Self> for Message<F> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs, |a: F, b: F| a - b)
    }
}
impl<F: Field> Mul<&Self> for Message<F> {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        self.bin_op(rhs, |a: F, b: F| a * b)
    }
}
impl<F: Field> Add<F> for Message<F> {
    type Output = Self;

    fn add(mut self, rhs: F) -> Self::Output {
        for e in self.0.iter_mut() {
            *e += rhs
        }
        self
    }
}
impl<F: Field> Sub<F> for Message<F> {
    type Output = Self;

    fn sub(mut self, rhs: F) -> Self::Output {
        for e in self.0.iter_mut() {
            *e -= rhs
        }
        self
    }
}
impl<F: Field> Mul<F> for Message<F> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self::Output {
        for e in self.0.iter_mut() {
            *e *= rhs
        }
        self
    }
}
impl<F: Field> MulAssign<F> for Message<F> {
    fn mul_assign(&mut self, rhs: F) {
        for e in self.0.iter_mut() {
            *e *= rhs
        }
    }
}
impl<F: Field> AddAssign<&Self> for Message<F> {
    fn add_assign(&mut self, rhs: &Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l += r;
        }
    }
}

impl<F: Field> Var<F> for Message<F> {}
impl<F: Field> AddAssign for Message<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = rhs + &*self;
    }
}
pub struct MessageEnv<'a, E, C> {
    evals_left: &'a E,
    evals_right: &'a E,
    challs: C,
    degree: usize,
}

impl<'a, E, C> MessageEnv<'a, E, C> {
    pub fn new(evals_left: &'a E, evals_right: &'a E, degree: usize, challs: C) -> Self {
        Self {
            evals_left,
            evals_right,
            degree,
            challs,
        }
    }
}

impl<I1, I2, F, E, C> Env<F, Message<F>, I1, I2> for MessageEnv<'_, E, C>
where
    I1: Copy,
    F: Field,
    E: Evals<F, Idx = I1>,
    C: Index<I2, Output = F>,
{
    fn get(&self, i: I1) -> Message<F> {
        let e0 = self.evals_left.index(i);
        let e1 = self.evals_right.index(i);
        Message::new_degree_n(*e0, *e1, self.degree)
    }
    fn get_chall(&self, chall_idx: I2) -> Message<F> {
        let chall = self.challs[chall_idx];
        // Not optimal, but this Environment won't be performance critical.
        Message::new_degree_n(chall, chall, self.degree)
    }
}
