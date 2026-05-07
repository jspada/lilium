#[derive(Clone, Copy, Debug)]
pub struct GuardedProof<P>(P);

impl<P> GuardedProof<P> {
    pub fn map<P2, F: FnOnce(P) -> P2>(self, f: F) -> GuardedProof<P2> {
        GuardedProof(f(self.0))
    }

    pub(crate) fn inner(&self) -> &P {
        &self.0
    }

    pub(crate) fn new(proof: P) -> Self {
        GuardedProof(proof)
    }
}

impl<A, B> GuardedProof<(A, B)> {
    pub(crate) fn split(self) -> (GuardedProof<A>, GuardedProof<B>) {
        let GuardedProof((a, b)) = self;
        (GuardedProof(a), GuardedProof(b))
    }
}
