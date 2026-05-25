use crate::{
    challenges::SparkChallenges,
    evals::SparkEval,
    spark::SparkEvalCheck,
    structure::{DimensionStructure, SparkStructure},
};
use ark_ff::Field;
use rand::{rngs::StdRng, SeedableRng};
use std::iter::successors;
use sumcheck::{
    polynomials::{EvalsExt, MultiPoint, SingleEval},
    prove_and_verify,
};

const VARS: usize = 4;

fn test<F: Field>() {
    let mut rng = StdRng::seed_from_u64(3);
    let len = 1 << VARS;

    let mut elem = || F::rand(&mut rng);
    let evals = vec![elem(); len];

    let eval_point = vec![elem(); VARS];
    let eval_point = MultiPoint::new(eval_point);
    let poly = SingleEval::from_field_elements(&evals);
    let true_eval = EvalsExt::eval(&poly, eval_point.clone());

    let counts = vec![1; len];
    let lookups = successors(Some(0), |x| Some(x + 1)).take(len).collect();
    let dimension = DimensionStructure::new(counts, lookups);
    let normal_index = dimension.lookups_field.clone();
    let dimensions = [dimension];
    let val = evals;

    let structure = SparkStructure {
        dimensions,
        normal_index,
        val,
    };

    let challenges = SparkChallenges::new(elem(), elem(), elem());
    let zero_check_point = vec![elem(); VARS];
    let zero_check_point = MultiPoint::new(zero_check_point);
    let points = [eval_point];
    let mle = SparkEval::evals(&structure, points, challenges, zero_check_point);

    let sum = true_eval.0;
    prove_and_verify::<F, SparkEvalCheck<1>>(mle, sum, challenges);
}

#[test]
fn single_dimension_spark() {
    test::<ark_vesta::Fq>();
}

// Spark proves a sparse polynomial evaluates to y at point x. Unit test by
// computing the same evaluation densely using eq polynomials. Note that this
// dense test computes all eq weights; a real sparse Spark evaluation would
// compute eq(eval_point, i) only for nonzero indices i.
#[test]
fn spark_sparse_dense_equality() {
    use ark_ff::UniformRand;
    use rand::{rngs::StdRng, SeedableRng};
    use sumcheck::polynomials::{EvalsExt, MultiPoint, SingleEval};

    let mut rng = StdRng::seed_from_u64(42);
    let len = 1 << VARS;

    let mut rand_elem = || ark_vesta::Fq::rand(&mut rng);
    let poly_evals: Vec<_> = (0..len).map(|_| rand_elem()).collect();
    let x = MultiPoint::new((0..VARS).map(|_| rand_elem()).collect());

    // Dense representation: full evaluation table over the Boolean hypercube
    let dense_poly = SingleEval::from_field_elements(&poly_evals);

    // Dense evaluation: evaluate the MLE at x
    let dense_y = EvalsExt::eval(&dense_poly, x.clone());

    // Sparse-style construction: equality-basis weights indexed by
    // their position on the hypercube. For this test eq_evals is actually
    // dense (Spark would compute only the weights for nonzero indices), but
    // we materialize all weights to keep the unit test simple.
    let eq_evals = sumcheck::eq::eq(&x);

    // Sparse-style evaluation: sum_i poly_evals[i] * eq(x, i)
    let sparse_y: ark_vesta::Fq = poly_evals
        .iter()
        .zip(eq_evals.iter())
        .map(|(e, q)| *e * *q)
        .sum();

    // The dense evaluation via MLE should match the sparse sum
    assert_eq!(
        eq_evals.len(),
        poly_evals.len(),
        "Length mismatch for eq table and polynomial evaluation table"
    );
    assert_eq!(
        dense_y.0, sparse_y,
        "Dense MLE evaluation does not match eq-basis sparse evaluation"
    );
}
