use crate::{
    barycentric_eval::BarycentricWeights,
    folding::{
        prover::SumFoldProverOutput, utils::FieldFolder, SumFold, SumFoldInstance, SumFoldProof,
    },
    message::Message,
    polynomials::Evals,
    sumcheck::{Sum, SumcheckFunction, SumcheckProver},
    zerocheck::CompactPowers,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use transcript::Transcript;

/// Specialized `SumFold` prover for zerocheck, verification remains
/// as usual through `SumFold`, available at `ZeroFold::sumfold_key`.
/// The main difference is that the message size increases by 1 for each
/// variable, but the impact of such higher degree sumcheck in the prover
/// is minimal.
pub struct ZeroFold<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    sumfold: SumFold<F, SF>,
    /// Weights to interpolate polynomials of degrees between degree(SF) and
    /// degree(SF) + vars.
    weights: Vec<BarycentricWeights<F>>,
}

impl<F, SF> ZeroFold<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    pub fn new(f: SF, vars: usize) -> Self {
        let degree = SumcheckProver::<F, SF>::degree_symbolic(&f);
        let sumfold = SumFold::new_custom_degree(degree + vars, &f);
        let weights = (0..vars)
            .map(|i| BarycentricWeights::compute((degree + i) as u32))
            .collect();
        Self { sumfold, weights }
    }

    pub fn sumfold_key(&self) -> &SumFold<F, SF> {
        &self.sumfold
    }

    /// Same as `SumFold::fold`, speciallized to efficiely handle the particularities
    /// of zerocheck.
    pub fn fold_zerocheck<S>(
        &self,
        w1: Vec<SF::Mles<F>>,
        w2: &[SF::Mles<F>],
        sums: Option<SumFoldInstance<F, 2>>,
        powers: [CompactPowers<F>; 2],
        challenges: SF::Challs,
        transcript: &mut Transcript<F, S>,
    ) -> SumFoldProverOutput<F, SF>
    where
        S: Duplex<F>,
    {
        assert_eq!(w1.len(), w2.len());
        let mut w1 = w1;

        let message = self.sum_messages(&w1, w2, powers, challenges);

        // Check against sums if provided.
        let instance = if let Some(sums) = sums {
            assert_eq!(sums.sums[0].0, message.eval_at_0());
            assert_eq!(sums.sums[1].0, message.eval_at_1());
            sums
        } else {
            SumFoldInstance {
                sums: [message.eval_at_0(), message.eval_at_1()].map(Sum),
            }
        };

        // Lock instance an generate challenge.
        let [beta] = transcript.send_message(&instance).unwrap();

        let eq_beta = Message::new_degree_n(F::one() - beta, beta, self.sumfold.degree + 1);
        // Compute final message eq(beta,x) * f(x).
        // By doing it at the end, having to compute d+2 points in the whole hypercube is
        // avoided, it is done instead over d+1 points.
        // For that same reason the original message has to be extended to d+2 points.
        let message = {
            let extended = message.clone().extend(&self.sumfold.weights);
            extended * eq_beta
        };
        // Message is sent and sumcheck challenge received.
        let [r] = transcript.send_message(&message).unwrap();

        // Checking that message agrees with sum.
        {
            let sum = instance.sums[0].0 * (F::ONE - beta) + instance.sums[1].0 * beta;
            let eval_zero = message.eval_at_0();
            let eval_one = message.eval_at_1();
            assert_eq!(sum, eval_zero + eval_one);
        };

        let sum = {
            let sum = message.eval_at_x(r, &self.sumfold.extended_weights);
            let eqr = r * beta + (F::one() - r) * (F::one() - beta);
            sum / eqr
        };

        let proof = SumFoldProof { message };

        // Witness is folded as expected from the sumcheck reduction.
        for (e1, e2) in w1.iter_mut().zip(w2.iter()) {
            let folded = e1.combine(e2, |e1, e2| e1 * (F::ONE - r) + e2 * r);
            *e1 = folded;
        }
        let folded_witness = w1;

        let folder = FieldFolder::new(r);

        SumFoldProverOutput {
            instance,
            folded_witness,
            proof,
            folder,
            sum,
        }
    }

    fn sum_messages(
        &self,
        w1: &[SF::Mles<F>],
        w2: &[SF::Mles<F>],
        powers: [CompactPowers<F>; 2],
        challenges: SF::Challs,
    ) -> Message<F> {
        let mut evaluator = self.sumfold.evaluator.clone();
        let mut accumulator = evaluator.accumulator(&challenges);

        let base_weights = &self.weights[0];
        let mut messages = Vec::with_capacity(w1.len() * base_weights.domain_size());

        let powers_left = powers[0].factors();
        let powers_right = powers[1].factors();

        let powers_even = Message::new_degree_n(
            powers_left[0].1,
            powers_right[0].1,
            base_weights.domain_size() - 1,
        );
        let powers_even_last = base_weights.extend(powers_even.inner());
        let powers_odd = Message::new_degree_n(
            powers_left[0].0,
            powers_right[0].0,
            base_weights.domain_size() - 1,
        );
        let powers_odd_last = base_weights.extend(powers_odd.inner());

        // Multiply the first variable and fold into Vec<F>.
        for i in 0..(w1.len() / 2) {
            let evals = [&w1[i * 2], &w2[i * 2]];
            let res0 = accumulator.eval_and_zero(evals);
            let evals = [&w1[i * 2 + 1], &w2[i * 2 + 1]];
            let res1 = accumulator.eval_and_zero(evals);
            for i in 0..res0.len() {
                let even = res0[i] * powers_even.inner()[i];
                let odd = res1[i] * powers_odd.inner()[i];
                messages.push(even + odd);
            }
            let res0 = base_weights.extend(&res0);
            let res1 = base_weights.extend(&res1);
            messages.push(res0 * powers_even_last + res1 * powers_odd_last);
        }

        // Repeat with the rest of variables until a single message is left.
        let message = powers_left
            .iter()
            .zip(powers_right)
            .zip(&self.weights)
            .skip(1)
            .fold(messages, |messages, (powers, weights)| {
                let (powers_left, powers_right) = powers;
                let powers_even = [powers_left.1, powers_right.1];
                let powers_odd = [powers_left.0, powers_right.0];
                let powers = [powers_even, powers_odd];
                Self::fold_with_powers(powers, messages, weights)
            });

        assert_eq!(
            message.len(),
            self.weights.last().unwrap().domain_size() + 1
        );
        Message::new(message)
    }

    fn fold_with_powers(
        powers: [[F; 2]; 2],
        messages: Vec<F>,
        weights: &BarycentricWeights<F>,
    ) -> Vec<F> {
        let [powers_even, powers_odd] = powers;
        // As domain_size = degree + 1.
        let powers_degree = weights.domain_size();
        let powers_even = Message::new_degree_n(powers_even[0], powers_even[1], powers_degree - 1);
        let powers_even = powers_even.inner();
        let powers_even_last = weights.extend(powers_even);
        let powers_odd = Message::new_degree_n(powers_odd[0], powers_odd[1], powers_degree - 1);
        let powers_odd = powers_odd.inner();
        let powers_odd_last = weights.extend(powers_odd);
        assert_eq!(messages.len() % weights.domain_size(), 0);
        let n = messages.len() / weights.domain_size();

        let mut res = vec![];

        for i in 0..(n / 2) {
            let size = weights.domain_size();
            let offset = i * size * 2;
            let messages = &messages[offset..offset + size * 2];
            let (msg0, msg1) = messages.split_at(size);
            for i in 0..msg0.len() {
                let even = msg0[i] * powers_even[i];
                let odd = msg1[i] * powers_odd[i];
                res.push(even + odd);
            }
            let msg0 = weights.extend(msg0);
            let msg1 = weights.extend(msg1);
            res.push(msg0 * powers_even_last + msg1 * powers_odd_last);
        }
        assert_eq!(res.len(), (n / 2) * (weights.domain_size() + 1));
        res
    }
}
