//! An environment to check the function of evaluations in a point.
//! At the end of sumcheck G(x) has to be checked at a point r, as
//! G is merely a composition of several multilinear polynomials, we instead
//! evaluate each of those polynomials at r and then apply the function
//! to get the evaluation. For example:
//! G(r) = f_0(r) * f_1(r) + f_2(r)

use crate::{
    polynomials::Evals,
    sumcheck::{Env, Var},
};
use ark_ff::Field;
use std::{marker::PhantomData, ops::Index};

impl<F: Field> Var<F> for F {}

pub struct EvalCheckEnv<F, E, C> {
    evals: E,
    challs: C,
    _phantom: PhantomData<F>,
}

impl<F, E, C> EvalCheckEnv<F, E, C> {
    pub fn new(eval: E, challs: C) -> Self {
        Self {
            evals: eval,
            challs,
            _phantom: PhantomData,
        }
    }
}

impl<F, I1, I2, C, E> Env<F, F, I1, I2> for EvalCheckEnv<F, E, C>
where
    F: Field,
    E: Evals<F, Idx = I1>,
    C: Index<I2, Output = F>,
{
    fn get(&self, i: I1) -> F {
        let f = *self.evals.index(i);
        f
    }
    fn get_chall(&self, chall_idx: I2) -> F {
        self.challs[chall_idx]
    }
}
