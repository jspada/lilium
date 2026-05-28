use crate::{
    messages::PointRound,
    params::{ParamResolver, ParamStack},
    protocols::{Protocol, Reduction},
    Message, Transcript,
};
use ark_ff::Field;
use sponge::sponge::{Duplex, SpongeBuilder};
use std::any::{Any, TypeId};

pub struct TranscriptBuilder {
    rounds: Vec<(TypeId, usize)>,
    //TODO: can likely be handled through params
    vars: usize,
    sponge_builder: SpongeBuilder,
    params: ParamStack,
}

impl TranscriptBuilder {
    pub fn with_params<F>(mut self, params: ParamResolver, f: F) -> Self
    where
        F: Fn(Self) -> Self,
    {
        self.params.push(params);
        let mut builder = f(self);
        builder.params.pop();
        builder
    }

    pub fn add_protocol_pattern<F: Field, S: Protocol<F>>(self, key: &S::Key) -> Self {
        S::transcript_pattern(key, self)
    }

    pub fn add_reduction_pattern<F: Field, S: Reduction<F>>(self, key: &S::Key) -> Self {
        S::transcript_pattern(key, self)
    }

    pub fn new(vars: usize, params: ParamResolver) -> Self {
        let sponge_builder = SpongeBuilder::new();
        Self {
            rounds: vec![],
            vars,
            sponge_builder,
            params: ParamStack::new(vec![params]),
        }
    }

    pub fn round<F: Field, T: Any + Message<F>, const N: usize>(self) -> Self {
        let Self {
            mut rounds,
            sponge_builder,
            vars,
            params,
        } = self;
        let id = TypeId::of::<T>();
        rounds.push((id, N));

        let resolver = params.top();
        let sponge_builder = sponge_builder
            .absorb(T::len(vars, resolver).try_into().unwrap())
            .squeeze(N.try_into().unwrap());

        Self {
            rounds,
            sponge_builder,
            params,
            ..self
        }
    }

    pub fn point(self) -> Self {
        let Self {
            mut rounds,
            vars,
            sponge_builder,
            ..
        } = self;
        let round = (TypeId::of::<PointRound>(), vars);
        rounds.push(round);
        let sponge_builder = sponge_builder.squeeze(vars.try_into().unwrap());
        Self {
            rounds,
            vars,
            sponge_builder,
            ..self
        }
    }

    fn fold_round_rec<F: Field, T: Any + Message<F>, const N: usize>(self, left: usize) -> Self {
        if left == 0 {
            self
        } else {
            let builder = self.round::<F, T, N>();
            builder.fold_round_rec::<F, T, N>(left - 1)
        }
    }

    /// Adds V rounds for the V variables in the transcript for split and fold
    /// protocols which send one message per variable.
    pub fn fold_rounds<F: Field, T: Any + Message<F>, const N: usize>(self) -> Self {
        let vars = self.vars;
        self.fold_round_rec::<F, T, N>(vars)
    }

    pub fn finish<F: Field, S: Duplex<F>>(self) -> TranscriptDescriptor<F, S> {
        let Self {
            rounds,
            sponge_builder,
            vars,
            ..
        } = self;
        let sponge = S::from_builder(sponge_builder);
        TranscriptDescriptor {
            sponge,
            rounds,
            vars,
        }
    }

    pub fn repeat<const N: usize, M: Fn(Self, usize) -> Self>(self, f: M) -> Self {
        (0..N).fold(self, f)
    }
}

pub struct TranscriptDescriptor<F: Field, S: Duplex<F>> {
    sponge: S::Initializer,
    rounds: Vec<(TypeId, usize)>,
    vars: usize,
}

impl<F: Field, S: Duplex<F>> TranscriptDescriptor<F, S> {
    pub fn instantiate(&self) -> Transcript<F, S> {
        let sponge = S::instantiate(&self.sponge);
        let rounds = self.rounds.clone().into_iter();
        Transcript::new(sponge, rounds, self.vars)
    }
}
