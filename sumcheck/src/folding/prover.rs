use crate::{
    folding::{utils::FieldFolder, SumFold, SumFoldInstance, SumFoldProof},
    message::Message,
    polynomials::Evals,
    sumcheck::{Sum, SumcheckFunction},
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use transcript::Transcript;

pub struct SumFoldProverOutput<F: Field, SF: SumcheckFunction<F>> {
    /// The sum of each sumcheck instance being folded.
    pub instance: SumFoldInstance<F, 2>,
    pub folded_witness: Vec<SF::Mles<F>>,
    pub proof: SumFoldProof<F>,
    /// Structure used to fold field elements and other type.
    pub folder: FieldFolder<F>,
    /// The sum of the new sumcheck instance
    pub sum: F,
}

impl<F: Field, SF: SumcheckFunction<F>> SumFold<F, SF> {
    /// Given 2 sumcheck instance-witness pairs, proves reduction and returns
    /// new instance-witness pair.
    /// Claimed sums are optional, as they are computed again for free, if provided
    /// they will be checked against the result.
    //TODO: knowledge of the sums could be used to save message computation in 2 points.
    pub fn fold<S: Duplex<F>>(
        &self,
        mut w1: Vec<SF::Mles<F>>,
        w2: &[SF::Mles<F>],
        sums: Option<SumFoldInstance<F, 2>>,
        transcript: &mut Transcript<F, S>,
        sumcheck_challs: SF::Challs,
    ) -> SumFoldProverOutput<F, SF> {
        let mut evaluator = self.evaluator.clone();
        let accumulator = evaluator.accumulator(&sumcheck_challs);

        // Compute message with original function first.
        let message = w1
            .iter()
            .zip(w2.iter())
            .fold(accumulator, |mut acc, evals| {
                let (e1, e2) = evals;
                acc.eval_accumulate([e1, e2]);
                acc
            })
            .finish();
        let message = Message::new(message);

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

        // Lock instance and generate challenge.
        let [beta] = transcript.send_message(&instance).unwrap();

        let eq_beta = Message::new_degree_n(F::one() - beta, beta, self.degree + 1);
        // Compute final message eq(beta,x) * f(x).
        // By doing it at the end, having to compute d+2 points in the whole hypercube is
        // avoided, it is done instead over d+1 points.
        // For that same reason the original message has to be extended to d+2 points.
        let message = {
            let extended = message.clone().extend(&self.weights);
            extended * eq_beta
        };
        // Message is sent and sumcheck challenge received.
        let [r] = transcript.send_message(&message).unwrap();

        // Checking that message agrees with sum.
        let sum = {
            let sum = instance.sums[0].0 * (F::ONE - beta) + instance.sums[1].0 * beta;
            let eval_zero = message.eval_at_0();
            let eval_one = message.eval_at_1();
            assert_eq!(sum, eval_zero + eval_one);
            sum
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
}
