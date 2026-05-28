use ark_ec::ScalarMul;
use ark_ff::{BigInteger, Field, PrimeField};

pub fn fold_vec<F: Field>(mut vec: Vec<F>, challs: [F; 2]) -> Vec<F> {
    assert!(vec.len().is_power_of_two());
    let half_len = vec.len() / 2;
    let [chall_l, chall_r] = challs;
    let (vec_l, vec_r) = vec.split_at_mut(half_len);
    for (l, r) in vec_l.iter_mut().zip(vec_r.iter()) {
        *l = *l * chall_l + *r * chall_r;
    }
    vec.truncate(half_len);
    vec
}

// Compute the Non-Adjacent Form (NAF) of a scalar
// Returns digits in little-endian order (index 0 is the coefficient of 2^0)
fn scalar_to_naf<B: BigInteger>(mut s: B) -> Vec<i8> {
    let mut naf = Vec::new();

    let one = B::from(1u64);
    while !s.is_zero() {
        let digit = if s.is_odd() {
            // Inspect the two lowest bits (n mod 4).
            if s.as_ref()[0] & 3 == 3 {
                // 11
                s.add_with_carry(&one);
                -1i8
            } else {
                // 01
                s.sub_with_borrow(&one);
                1i8
            }
        } else {
            0i8
        };
        naf.push(digit);
        s.div2();
    }
    naf
}

// Compute l * chall_l + r * chall_r for one basis-pair using Shamir's trick,
// where chall_l and chall_r are NAF digit arrays of the challenge scalars
fn shamirs_trick<G: ScalarMul>(l: G::MulBase, r: G::MulBase, chall_l: &[i8], chall_r: &[i8]) -> G {
    let len = chall_l.len().max(chall_r.len());
    let mut acc = G::zero();

    for i in (0..len).rev() {
        acc.double_in_place();

        match chall_l.get(i).copied().unwrap_or(0) {
            1 => acc += l,
            -1 => acc -= l,
            _ => {}
        }
        match chall_r.get(i).copied().unwrap_or(0) {
            1 => acc += r,
            -1 => acc -= r,
            _ => {}
        }
    }
    acc
}

pub fn fold_basis<G>(vec: Vec<G::MulBase>, challs: [G::ScalarField; 2]) -> Vec<G::MulBase>
where
    G: ScalarMul,
{
    assert!(vec.len().is_power_of_two());
    let half_len = vec.len() / 2;
    let [chall_l, chall_r] = challs;
    let (basis_l, basis_r) = vec.split_at(half_len);

    let chall_l = scalar_to_naf(chall_l.into_bigint());
    let chall_r = scalar_to_naf(chall_r.into_bigint());

    let basis: Vec<G> = basis_l
        .iter()
        .zip(basis_r.iter())
        .map(|(l, r)| shamirs_trick::<G>(*l, *r, &chall_l, &chall_r))
        .collect();

    //TODO: Not sure if this as good as it could be, check later
    G::batch_convert_to_mul_base(&basis)
}

pub fn compute_inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    debug_assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(F::zero(), |acc, (a, b)| acc + *a * b)
}

/// Computes the vector of 2^n combinations of n challenges and their inverses
pub fn challenge_combinations<F: Field>(challs: &[F], challs_inv: &[F]) -> Vec<F> {
    assert_eq!(challs.len(), challs_inv.len());
    let zero: F = challs_inv.iter().cloned().product();
    let flips: Vec<F> = challs.iter().map(|x| x.square()).collect();
    let mut combinations = vec![F::zero(); 1 << challs.len()];
    combine_rec(&flips, zero, &mut combinations);
    combinations
}

pub fn combine_rec<F: Field>(flips: &[F], zero: F, vec: &mut [F]) {
    assert!(vec.len().is_power_of_two());
    let half_len = vec.len() / 2;
    if flips.is_empty() {
        vec[0] = zero;
    } else {
        let (low, high) = vec.split_at_mut(half_len);
        combine_rec(&flips[1..], zero, low);
        let flip = flips[0];
        for (l, r) in low.iter().zip(high.iter_mut()) {
            *r = flip * l;
        }
    }
}
