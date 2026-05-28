use super::permutation::{ExternalMatrix, InternalMatrix};
use ark_ff::Field;

// |2 1 1|
// |1 2 1|
// |1 1 3|
// TODO: automatically generate and verify properties
/// Internal rounds matrix, it must not have infinitely long subspace
/// trails, nor infinitely long iterative subspace trails of period above
/// 2t (t = 3 in this case).
/// In this particular case of t=3 the internal matrix is also used as the
/// external matrix, for which it fulfills the additional requirement of
/// being MDS.
/// Verified for Pallas and Vesta, may work for others too.
#[must_use]
fn internal_matrix_3<F: Field>(state: &[F; 3]) -> [F; 3] {
    let sum = state[0] + state[1] + state[2];
    [sum + state[0], sum + state[1], sum + state[2].double()]
}

//TODO: perform a check to know it works for the given field
pub struct InternalMatrix3;
impl<F: Field> InternalMatrix<F, 3> for InternalMatrix3 {
    fn apply(state: &mut [F; 3]) {
        *state = internal_matrix_3(state);
    }
}
impl<F: Field> ExternalMatrix<F, 3> for InternalMatrix3 {
    fn apply(state: &mut [F; 3]) {
        *state = internal_matrix_3(state);
    }
}
