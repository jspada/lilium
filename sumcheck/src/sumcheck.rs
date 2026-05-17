use crate::{
    barycentric_eval::BarycentricWeights,
    degree::DegreeEnv,
    eval_check::EvalCheckEnv,
    message::{Message, MessageEnv},
    polynomials::{Evals, EvalsExt, MultiPoint},
    symbolic::sumcheck_eval::SumcheckEvaluator,
    SumcheckError,
};
use ark_ff::Field;
use sponge::sponge::Duplex;
use std::{
    fmt::Debug,
    marker::PhantomData,
    ops::{Add, AddAssign, Index, Mul, MulAssign, Sub},
};
use transcript::{
    instances::PolyEvalCheck, params::ParamResolver, protocols::Reduction, Transcript,
    TranscriptGuard,
};

pub trait Var<F: Field>:
    Sized
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + Mul<Self, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + Add<F, Output = Self>
    + Sub<F, Output = Self>
    + Mul<F, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + MulAssign<F>
    + Clone
{
}

//type SumcheckResult<T> = Result<T, crate::SumcheckError>;

// TODO: With symbolic evaluation now available, Env can move into a
// concrete type supporting only symbolic expressions. And all other
// environments be replaced with expression evaluation algorithms.
/// allows access to variables
pub trait Env<F, V, I, C>
where
    F: Field,
    V: Var<F>,
{
    fn get(&self, i: I) -> V;
    fn get_chall(&self, chall_idx: C) -> V;
}
// implement also for references
impl<F, V, I, C, E> Env<F, V, I, C> for &E
where
    F: Field,
    V: Var<F>,
    E: Env<F, V, I, C>,
{
    fn get(&self, i: I) -> V {
        (*self).get(i)
    }
    fn get_chall(&self, chall_idx: C) -> V {
        (*self).get_chall(chall_idx)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum CommitType {
    /// Structure commitments to public mles
    Structure,
    /// Instance commitments generally provided by a prover
    Instance,
}

#[derive(Clone, Copy, Debug)]
/// Describes how a given mle should be evaluated at a point
pub enum EvalKind {
    /// To be evaluated through opening a commitment
    Committed(CommitType),
    /// Small representation that can be just evaluated by the verifier
    FixedSmall,
    /// Some MLE that can't be directly evaluated, the evaluation is
    /// provided as a claim to be verified later through other means.
    /// The specific use of this is for matrix evalation with spark.
    Virtual,
}

#[derive(Debug, Clone, Copy, Default)]
/// To be used when no challenges are needed.
pub struct NoChallenges<F>(PhantomData<F>);

/// Index for `NoChallenges`, being a variant-less enum, it has no values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NoChallIdx {}

impl<F> Index<NoChallIdx> for NoChallenges<F> {
    type Output = F;

    fn index(&self, _index: NoChallIdx) -> &Self::Output {
        unreachable!()
    }
}

/// Defines a polynomial used in sumcheck as a function of multilinear
/// polynomials
pub trait SumcheckFunction<F: Field> {
    type Idx: Copy + Ord + Eq + Debug;
    type Mles<V: Copy + Debug>: Evals<V, Idx = Self::Idx>;
    type Challs: Index<Self::ChallIdx, Output = F> + Clone + Default;
    type ChallIdx: Copy + Ord + Eq + Debug;

    /// Provides a description of how each mle should be evaluated
    const KINDS: Self::Mles<EvalKind>;
    fn map_evals<A, B, M>(evals: Self::Mles<A>, f: M) -> Self::Mles<B>
    where
        A: Copy + Debug,
        B: Copy + Debug,
        M: Fn(A) -> B;
    ///computes the arbitrary degree polynomial as a function of multilinear polynomials
    fn function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(env: E) -> V;
    // TODO: unify both methods and make everything symbolic.
    /// Same as `Self::function` but allows runtime configuration through `&self`.
    fn symbolic_function<V: Var<F>, E: Env<F, V, Self::Idx, Self::ChallIdx>>(
        &self,
        _env: E,
    ) -> Option<V> {
        None
    }
}

pub fn sumcheck_degree<F: Field, SF: SumcheckFunction<F>>() -> usize {
    let degree_env = DegreeEnv::new();
    let degree = SF::function(degree_env);
    degree.0
}

#[derive(Clone, Debug)]
pub struct SumcheckProver<F: Field, SF: SumcheckFunction<F>> {
    vars: usize,
    degree: usize,
    evaluator: SumcheckEvaluator<F, SF>,
}

pub struct Proof<F: Field, SF: SumcheckFunction<F>> {
    messages: Vec<Message<F>>,
    _f: PhantomData<SF>,
}

impl<F: Field, SF: SumcheckFunction<F>> Proof<F, SF> {
    pub fn from_messages(messages: Vec<Message<F>>) -> Self {
        Self {
            messages,
            _f: PhantomData,
        }
    }
}

impl<F: Field, SF: SumcheckFunction<F>> Debug for Proof<F, SF> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proof")
            .field("messages", &self.messages)
            .field("_f", &self._f)
            .finish()
    }
}

impl<F: Field, SF: SumcheckFunction<F>> Clone for Proof<F, SF> {
    fn clone(&self) -> Self {
        Self {
            messages: self.messages.clone(),
            _f: self._f,
        }
    }
}

/// degree of sumcheck messages
pub struct DegreeParam;

impl<F: Field, SF: SumcheckFunction<F>> transcript::Message<F> for Proof<F, SF> {
    fn len(vars: usize, param_resolver: &ParamResolver) -> usize {
        vars * Message::<F>::len(vars, param_resolver)
    }

    fn to_field_elements(&self) -> Vec<F> {
        self.messages
            .iter()
            .flat_map(transcript::Message::to_field_elements)
            .collect()
    }
}

pub struct ProverOutput<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    /// Point where to evaluate the sumcheck polynomial.
    pub point: MultiPoint<F>,
    pub proof: Proof<F, SF>,
    /// Evaluation of each MLE in the point.
    pub evals: SF::Mles<F>,
}

impl<F, SF> SumcheckProver<F, SF>
where
    F: Field,
    SF: SumcheckFunction<F>,
{
    pub fn new(vars: usize) -> Self {
        let degree = Self::degree();
        let evaluator = SumcheckEvaluator::new(None);
        Self {
            degree,
            vars,
            evaluator,
        }
    }

    pub(crate) fn degree_symbolic(function: &SF) -> usize {
        let degree_env = DegreeEnv::new();
        let degree =
            SF::symbolic_function(function, degree_env).expect("symbolic function not implemented");
        degree.0
    }

    pub fn new_symbolic(vars: usize, function: &SF) -> Self {
        let degree = Self::degree_symbolic(function);
        let evaluator = SumcheckEvaluator::new(Some(function));
        Self {
            degree,
            vars,
            evaluator,
        }
    }

    fn degree() -> usize {
        sumcheck_degree::<F, SF>()
    }

    fn message(&self, mle: &[SF::Mles<F>], challs: &SF::Challs) -> Message<F> {
        let half_len = mle.len() / 2;
        let (left, right) = mle.split_at(half_len);
        let degree = self.degree;

        let mut message = Message::new_degree_n(F::zero(), F::zero(), degree);
        for (left, right) in left.iter().zip(right) {
            // let left: &mut Eval<F, SF> = left;
            // left.combine(right, f);
            let env = MessageEnv::new(left, right, degree, challs.clone());
            let m = SF::function(env);
            message += m;
        }
        message
    }

    pub(crate) fn message_symbolic(&self, mle: &[SF::Mles<F>], challs: &SF::Challs) -> Message<F> {
        let half_len = mle.len() / 2;
        let (left, right) = mle.split_at(half_len);
        let mut evaluator = self.evaluator.clone();
        let mut accumulator = evaluator.accumulator(challs);

        for (left, right) in left.iter().zip(right) {
            accumulator.eval_accumulate([left, right]);
        }
        Message::new(accumulator.finish())
    }

    pub fn prove<D: Duplex<F>>(
        &self,
        transcript: &mut Transcript<F, D>,
        mle: Vec<SF::Mles<F>>,
        challs: &SF::Challs,
    ) -> Result<ProverOutput<F, SF>, SumcheckError> {
        let mut messages = Vec::with_capacity(self.vars);

        let mut vars = vec![];
        let mles = (0..self.vars).try_fold(mle, |mle, _| {
            let mle: Vec<SF::Mles<F>> = mle;
            let m = self.message(&mle, challs);
            let [var] = transcript
                .send_message(&m)
                .map_err(SumcheckError::TranscriptError)?;
            messages.push(m);
            vars.push(var);
            Ok(EvalsExt::fix_var(mle, var))
        })?;

        vars.reverse();
        let point = MultiPoint::new(vars);
        debug_assert_eq!(mles.len(), 1);
        let evals = mles[0].clone();

        let proof = Proof {
            messages,
            _f: PhantomData,
        };

        Ok(ProverOutput {
            point,
            proof,
            evals,
        })
    }

    pub fn prove_symbolic<D: Duplex<F>>(
        &self,
        transcript: &mut Transcript<F, D>,
        mle: Vec<SF::Mles<F>>,
        challs: &SF::Challs,
    ) -> Result<ProverOutput<F, SF>, SumcheckError> {
        let mut messages = Vec::with_capacity(self.vars);

        let mut vars = vec![];
        let mles = (0..self.vars).try_fold(mle, |mle, _| {
            let mle: Vec<SF::Mles<F>> = mle;
            let m = self.message_symbolic(&mle, challs);
            let [var] = transcript
                .send_message(&m)
                .map_err(SumcheckError::TranscriptError)?;
            messages.push(m);
            vars.push(var);
            Ok(EvalsExt::fix_var(mle, var))
        })?;

        vars.reverse();
        let point = MultiPoint::new(vars);
        debug_assert_eq!(mles.len(), 1);
        let evals = mles[0].clone();

        let proof = Proof {
            messages,
            _f: PhantomData,
        };

        Ok(ProverOutput {
            point,
            proof,
            evals,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SumcheckVerifier<F: Field, SF: SumcheckFunction<F>> {
    vars: usize,
    weights: BarycentricWeights<F>,
    degree: usize,
    f: Option<SF>,
}

impl<F: Field, SF: SumcheckFunction<F>> SumcheckVerifier<F, SF> {
    fn degree() -> u32 {
        sumcheck_degree::<F, SF>() as u32
    }

    fn degree_symbolic(function: &SF) -> usize {
        let degree_env = DegreeEnv::new();
        let degree =
            SF::symbolic_function(function, degree_env).expect("symbolic function not implemented");
        degree.0
    }

    pub fn new_symbolic(function: SF, vars: usize) -> Self {
        let degree = Self::degree_symbolic(&function);
        let weights = BarycentricWeights::compute(degree as u32);
        Self {
            vars,
            weights,
            degree,
            f: Some(function),
        }
    }

    pub fn new(vars: usize) -> Self {
        let degree = Self::degree();
        let weights = BarycentricWeights::compute(degree);
        let degree = degree as usize;
        Self {
            vars,
            weights,
            degree,
            f: None,
        }
    }
    /// Verifies sumcheck, leaving it up to the caller to evaluate the polynomial
    /// in the point r and check that c = P(r) for Ok(c) the return value
    pub fn verify(
        &self,
        r: &MultiPoint<F>,
        proof: Proof<F, SF>,
        sum: F,
    ) -> Result<F, SumcheckError> {
        assert_eq!(self.vars, r.vars());
        let Proof { messages, _f } = proof;
        let mut point = r.clone();
        let mut sum = sum;
        for message in messages {
            if message.degree() != self.degree {
                return Err(SumcheckError::MessageDegree);
            }
            let e0 = message.eval_at_0();
            let e1 = message.eval_at_1();

            if e0 + e1 != sum {
                return Err(SumcheckError::RoundSum);
            }
            let var = point.pop_mut();
            sum = message.eval_at_x(var, &self.weights);
        }
        let check_eval = sum;
        Ok(check_eval)
    }
    // Will check that c = P(r) from the evaluations of the
    // multilinear polynomials that compose it
    pub fn check_evals_at_r(&self, evals: SF::Mles<F>, c: F, challs: &SF::Challs) -> bool {
        let env = EvalCheckEnv::new(evals, challs.clone());
        let eval = SF::function(env);
        eval == c
    }

    // Will check that c = P(r) from the evaluations of the
    // multilinear polynomials that compose it
    pub fn check_evals_at_r_symbolic(&self, evals: SF::Mles<F>, c: F, challs: &SF::Challs) -> bool {
        let env = EvalCheckEnv::new(evals, challs.clone());
        let f = self.f.as_ref().unwrap();
        let eval = f.symbolic_function(env).unwrap();
        eval == c
    }
}

pub struct Sum<F>(pub F);
impl<F: Field> transcript::Message<F> for Sum<F> {
    fn len(_vars: usize, _param_resolver: &ParamResolver) -> usize {
        1
    }

    fn to_field_elements(&self) -> Vec<F> {
        vec![self.0]
    }
}

impl<F: Field, SF: SumcheckFunction<F>> Reduction<F> for SumcheckVerifier<F, SF> {
    type A = Sum<F>;

    type B = PolyEvalCheck<F>;

    type Key = Self;

    type Proof = Proof<F, SF>;

    type Error = SumcheckError;

    fn transcript_pattern(
        key: &Self::Key,
        builder: transcript::TranscriptBuilder,
    ) -> transcript::TranscriptBuilder {
        let params = ParamResolver::new().set::<DegreeParam>(key.degree);
        builder.with_params(params, |builder| builder.fold_rounds::<F, Message<F>, 1>())
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: transcript::MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        // let (sum, []) = transcript
        // .unwrap_instance_unsafe(instance)
        // .map_err(SumcheckError::TranscriptError)?;
        let sum = transcript.unwrap_instance_unsafe(instance);
        let mut sum = sum.0;
        let mut vars = vec![];
        for i in 0..key.vars {
            let (message, [r]) = transcript
                .receive_message(|proof| proof.messages[i].clone())
                .map_err(SumcheckError::TranscriptError)?;
            if message.degree() != key.degree {
                return Err(SumcheckError::MessageDegree);
            }
            let e0 = message.eval_at_0();
            let e1 = message.eval_at_1();
            if e0 + e1 != sum {
                return Err(SumcheckError::RoundSum);
            }
            vars.push(r);
            sum = message.eval_at_x(r, &key.weights);
        }
        // as sumcheck handles the point in the opposite way
        // TODO: establish a stricter point representation.
        vars.reverse();
        let eval = sum;
        Ok(PolyEvalCheck { vars, eval })
    }
}
