use crate::{
    committed_spark::{CommittedSparkInstance, Error},
    spark2::{prove, CommittedSpark, CommittedSparkProof, SparkSparseMle},
};
use ark_ff::Field;
use commit::{CommmitmentScheme, OpenInstance};
use sponge::sponge::Duplex;
use std::rc::Rc;
use sumcheck::polynomials::MultiPoint;
use transcript::{
    params::ParamResolver, protocols::Reduction, Message, MessageGuard, Transcript,
    TranscriptBuilder, TranscriptGuard,
};

/// Wrapper which dynamically chooses N as required, currently implemented up to
/// 64 bits/8 segments.
pub enum FlexibleSpark<F: Field, C: CommmitmentScheme<F>> {
    S1(CommittedSpark<F, C, 1>),
    S2(CommittedSpark<F, C, 2>),
    S3(CommittedSpark<F, C, 3>),
    S4(CommittedSpark<F, C, 4>),
    S5(CommittedSpark<F, C, 5>),
    S6(CommittedSpark<F, C, 6>),
    S7(CommittedSpark<F, C, 7>),
    S8(CommittedSpark<F, C, 8>),
}

impl<F: Field, C: CommmitmentScheme<F>> FlexibleSpark<F, C> {
    fn inner_key<const N: usize>(evals: Vec<(u64, F)>, scheme: &C) -> CommittedSpark<F, C, N> {
        let (addresses, values) = evals
            .into_iter()
            .map(|(addr, val)| {
                let bytes: [u8; 8] = addr.to_le_bytes();
                let mut address_segments = [0; N];
                address_segments.copy_from_slice(&bytes[0..N]);
                (address_segments, val)
            })
            .unzip();
        let mle = SparkSparseMle::new(addresses, values);
        CommittedSpark::new(Rc::new(mle), scheme)
    }

    pub fn new(evals: Vec<(u64, F)>, scheme: &C) -> Self {
        assert!(evals.len().is_power_of_two());
        let max: u64 = evals
            .iter()
            .fold(0, |acc, (addr, _)| std::cmp::max(acc, *addr));
        let bits = max.next_power_of_two().ilog2();

        // Edge case when some matrix is unused.
        if bits == 0 {
            return S1(Self::inner_key(evals, scheme));
        }

        use FlexibleSpark::*;
        match bits - 1 {
            0..8 => S1(Self::inner_key(evals, scheme)),
            8..16 => S2(Self::inner_key(evals, scheme)),
            16..24 => S3(Self::inner_key(evals, scheme)),
            24..32 => S4(Self::inner_key(evals, scheme)),
            32..40 => S5(Self::inner_key(evals, scheme)),
            40..48 => S6(Self::inner_key(evals, scheme)),
            48..56 => S7(Self::inner_key(evals, scheme)),
            56..64 => S8(Self::inner_key(evals, scheme)),
            _ => panic!("unsupported (and impossible) size"),
        }
    }

    fn segments(&self) -> usize {
        use FlexibleSpark::*;
        match self {
            S1(_) => 1,
            S2(_) => 2,
            S3(_) => 3,
            S4(_) => 4,
            S5(_) => 5,
            S6(_) => 6,
            S7(_) => 7,
            S8(_) => 8,
        }
    }

    /// Creates an instance by properly truncating the point if needed.
    pub fn instance(&self, point: MultiPoint<F>, eval: F) -> Instance<F> {
        let mut vars = point.inner();
        let n = self.segments();
        if vars.len() > n * 8 {
            vars.truncate(n * 8);
        }
        let point = MultiPoint::new(vars);
        Instance { point, eval }
    }
}

pub struct Instance<F: Field> {
    /// One single big point for all segments
    pub point: MultiPoint<F>,
    pub eval: F,
}

impl<F: Field> Instance<F> {
    fn slice<const N: usize>(self) -> CommittedSparkInstance<F, N> {
        let Self { point, eval } = self;
        let mut vars = point.inner();
        if vars.len() > N * 8 {
            vars.truncate(N * 8);
        }
        let original_len = vars.len();

        assert!(
            N * 8 - original_len < 8,
            "only the last segment may be incomplete"
        );

        vars.resize(N * 8, F::zero());
        let point = MultiPoint::new(vars);

        //TODO: this is enforcing by alignment, may want to remove.
        assert_eq!(point.vars(), N * 8);

        let mut vars = point.inner().into_iter();

        let point = [(); N].map(|_| {
            let vars: Vec<F> = vars.by_ref().take(8).collect();
            MultiPoint::new(vars)
        });

        CommittedSparkInstance { point, eval }
    }
}

/// How many 8-bits segments Spark is using.
struct SegmentsParam;

impl<F: Field> Message<F> for Instance<F> {
    fn len(_vars: usize, param_resolver: &ParamResolver) -> usize {
        //TODO: could use bits instead and compute segments from them.
        let segments = param_resolver.get::<SegmentsParam>();
        segments * 8 + 1
    }

    fn to_field_elements(&self) -> Vec<F> {
        let mut elems = Vec::with_capacity(self.point.vars() + 1);
        elems.extend(self.point.inner_ref());
        if elems.len() % 8 != 0 {
            elems.resize((elems.len() / 8 + 1) * 8, F::zero());
        }
        elems.push(self.eval);
        elems
    }
}

#[derive(Clone, Debug)]
pub enum Proof<F: Field, C: CommmitmentScheme<F>> {
    S1(CommittedSparkProof<F, C, 1>),
    S2(CommittedSparkProof<F, C, 2>),
    S3(CommittedSparkProof<F, C, 3>),
    S4(CommittedSparkProof<F, C, 4>),
    S5(CommittedSparkProof<F, C, 5>),
    S6(CommittedSparkProof<F, C, 6>),
    S7(CommittedSparkProof<F, C, 7>),
    S8(CommittedSparkProof<F, C, 8>),
}

impl<F, C> Reduction<F> for FlexibleSpark<F, C>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    type A = Instance<F>;

    type B = OpenInstance<F, C::Commitment>;

    type Key = Self;

    type Proof = Proof<F, C>;

    type Error = Error<F, C>;

    fn transcript_pattern(key: &Self::Key, builder: TranscriptBuilder) -> TranscriptBuilder {
        use FlexibleSpark::*;
        let params = ParamResolver::new().set::<SegmentsParam>(key.segments());
        builder.with_params(params, |builder| {
            let builder = builder.round::<F, Self::A, 0>();
            match key {
                S1(key) => CommittedSpark::transcript_pattern(key, builder),
                S2(key) => CommittedSpark::transcript_pattern(key, builder),
                S3(key) => CommittedSpark::transcript_pattern(key, builder),
                S4(key) => CommittedSpark::transcript_pattern(key, builder),
                S5(key) => CommittedSpark::transcript_pattern(key, builder),
                S6(key) => CommittedSpark::transcript_pattern(key, builder),
                S7(key) => CommittedSpark::transcript_pattern(key, builder),
                S8(key) => CommittedSpark::transcript_pattern(key, builder),
            }
        })
    }

    fn verify_reduction<S: Duplex<F>>(
        key: &Self::Key,
        instance: MessageGuard<Self::A>,
        mut transcript: TranscriptGuard<F, S, Self::Proof>,
    ) -> Result<Self::B, Self::Error> {
        use FlexibleSpark::*;
        let (instance, []) = transcript.unwrap_guard(instance)?;
        macro_rules! verify {
            ($variant:path,$key:ident) => {{
                let instance = MessageGuard::new(instance.slice());
                let proof = transcript.receive_message_delayed(|proof| {
                    if let $variant(proof) = proof {
                        proof.clone()
                    } else {
                        panic!()
                    }
                });
                let transcript = transcript.new_guard(proof);
                CommittedSpark::verify_reduction($key, instance, transcript)
            }};
        }
        match key {
            S1(key) => {
                verify!(Proof::S1, key)
            }
            S2(key) => {
                verify!(Proof::S2, key)
            }
            S3(key) => {
                verify!(Proof::S3, key)
            }
            S4(key) => {
                verify!(Proof::S4, key)
            }
            S5(key) => {
                verify!(Proof::S5, key)
            }
            S6(key) => {
                verify!(Proof::S6, key)
            }
            S7(key) => {
                verify!(Proof::S7, key)
            }
            S8(key) => {
                verify!(Proof::S8, key)
            }
        }
    }
}

pub struct ProverOutput<F: Field, C: CommmitmentScheme<F>> {
    pub open_instance: OpenInstance<F, C::Commitment>,
    pub witness: Vec<F>,
    pub proof: Proof<F, C>,
}

impl<F, C> FlexibleSpark<F, C>
where
    F: Field,
    C: CommmitmentScheme<F> + 'static,
{
    pub fn prove<S: Duplex<F>>(
        &self,
        transcript: &mut Transcript<F, S>,
        instance: Instance<F>,
        scheme: &C,
    ) -> ProverOutput<F, C>
    where
        C: 'static,
    {
        use FlexibleSpark::*;

        let [] = transcript.send_message(&instance).unwrap();

        macro_rules! prove {
            ($variant:path,$key:ident) => {{
                let instance = instance.slice();
                let out = $key.prove(transcript, instance, scheme);
                let prove::ProverOutput {
                    open_instance,
                    witness,
                    proof,
                } = out;
                let proof = $variant(proof);
                ProverOutput {
                    open_instance,
                    witness,
                    proof,
                }
            }};
        }

        match self {
            S1(key) => {
                prove!(Proof::S1, key)
            }
            S2(key) => {
                prove!(Proof::S2, key)
            }
            S3(key) => {
                prove!(Proof::S3, key)
            }
            S4(key) => {
                prove!(Proof::S4, key)
            }
            S5(key) => {
                prove!(Proof::S5, key)
            }
            S6(key) => {
                prove!(Proof::S6, key)
            }
            S7(key) => {
                prove!(Proof::S7, key)
            }
            S8(key) => {
                prove!(Proof::S8, key)
            }
        }
    }
}
