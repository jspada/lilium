//! small exponent exponentiation

use ark_ff::Field;

// compiler should be able to optimize this for the given P
pub fn pow<F: Field, const P: u8>(val: F) -> F {
    let one = F::one();
    let x = val;
    let xx = x * x;
    let xxx = xx * x;

    let lookup_power = |p: u8| match p {
        0 => one,
        1 => x,
        2 => xx,
        3 => xxx,
        _ => unreachable!(),
    };

    // Radix-4 windowed exponentiation using Horner's method over 2-bit digits of P
    //     x^P = ((((x^d3)^4 * x^d2)^4 * x^d1)^4 * x^d0
    let pow = lookup_power((P & 0b11000000) >> 6);
    let pow = pow.square().square() * lookup_power((P & 0b00110000) >> 4);
    let pow = pow.square().square() * lookup_power((P & 0b00001100) >> 2);
    pow.square().square() * lookup_power(P & 0b11)
}

#[cfg(test)]
mod tests {
    use super::pow;
    use ark_ff::Field;
    use ark_vesta::Fr;
    use seq_macro::seq;

    fn check_pow<const P: u8>(x: Fr) {
        assert_eq!(pow::<Fr, P>(x), x.pow([P as u64]), "P={P},x={x}");
    }

    #[test]
    fn pow_matches_reference() {
        for x in [
            Fr::from(0u64),
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(1729u64),
        ] {
            seq!(P in 0u8..=255 { check_pow::<P>(x); });
        }
    }
}
