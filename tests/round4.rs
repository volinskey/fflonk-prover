//! Integration test for prover Round 4 (our "Round 5" task, partial — produces W1).
//!
//! Structural correctness signals:
//! 1. Roots computed from xi_seed raise to the expected identities:
//!    `h0w8[i]^8 = xi`, `h1w4[i]^4 = xi`, `h2w3[i]^3 = xi`, `h3w3[i]^3 = xiw`.
//! 2. The three R polynomials have the expected degrees (R0<8, R1<4, R2<6).
//! 3. All three polynomial divisions inside Round 4 succeed (they would fail
//!    if the R_i don't match the C_i at the interpolation roots, which is a
//!    consistency check on our Round 1/2/3 outputs).
//! 4. F's effective degree < 9n − 6 (the snarkjs invariant).
//! 5. W1 commitment is a valid (non-identity) G1 point.

use ark_ff::{Field, Zero};
use fflonk_prover::challenges::derive_beta_gamma;
use fflonk_prover::poly::eval_horner;
use fflonk_prover::prover::{
    round1, round2, round3, round4, round5, Round1Blinders, Round2Blinders,
};
use fflonk_prover::wtns;

fn run_all_rounds(
    zkey_path: &str,
    wtns_path: &str,
) -> (
    fflonk_prover::prover::Round1Output,
    fflonk_prover::prover::Round2Output,
    fflonk_prover::prover::Round3Evaluations,
    fflonk_prover::prover::Round4Output,
) {
    let zkey = std::fs::read(zkey_path).unwrap();
    let witness = wtns::read_from_path(std::path::Path::new(wtns_path))
        .unwrap()
        .values;
    let r1 = round1(&zkey, &witness, &Round1Blinders::zero()).unwrap();
    let n_public = r1.header.n_public as usize;
    let public_inputs: Vec<_> = (1..=n_public).map(|j| witness[j]).collect();
    let (beta, gamma) = derive_beta_gamma(&r1.header.c0, &public_inputs, &r1.c1_commitment);
    let r2 = round2(&zkey, &r1, beta, gamma, &Round2Blinders::zero()).unwrap();
    let r3 = round3(&zkey, &r1, &r2, gamma).unwrap();
    let r4 = round4(&zkey, &r1, &r2, &r3).expect("Round 4");
    (r1, r2, r3, r4)
}

#[test]
fn multiplier_round4_produces_w1() {
    let (r1, r2, r3, r4) = run_all_rounds(
        "tests/fixtures/multiplier/circuit.zkey",
        "tests/fixtures/multiplier/witness.wtns",
    );

    let n = r1.header.domain_size as usize;

    // Root identities: h0w8[i]^8 = xi, etc.
    let xi = r3.xi;
    let xiw = r3.xiw;
    for (i, &h) in r4.roots.h0w8.iter().enumerate() {
        assert_eq!(h.pow([8u64]), xi, "h0w8[{i}]^8 must equal xi");
    }
    for (i, &h) in r4.roots.h1w4.iter().enumerate() {
        assert_eq!(h.pow([4u64]), xi, "h1w4[{i}]^4 must equal xi");
    }
    for (i, &h) in r4.roots.h2w3.iter().enumerate() {
        assert_eq!(h.pow([3u64]), xi, "h2w3[{i}]^3 must equal xi");
    }
    for (i, &h) in r4.roots.h3w3.iter().enumerate() {
        assert_eq!(h.pow([3u64]), xiw, "h3w3[{i}]^3 must equal xiw");
    }

    // R polynomial degree bounds.
    assert!(r4.r0_coeffs.len() <= 8);
    assert!(r4.r1_coeffs.len() <= 4);
    assert!(r4.r2_coeffs.len() <= 6);

    // R_i must match C_i at every root.
    for &h in &r4.roots.h0w8 {
        assert_eq!(
            eval_horner(&r4.r0_coeffs, &h),
            eval_horner(&r4.c0_coeffs, &h),
            "R0 must agree with C0 at h0w8[...]"
        );
    }
    for &h in &r4.roots.h1w4 {
        assert_eq!(
            eval_horner(&r4.r1_coeffs, &h),
            eval_horner(&r1.c1_coeffs, &h),
            "R1 must agree with C1 at h1w4[...]"
        );
    }
    for &h in r4.roots.h2w3.iter().chain(r4.roots.h3w3.iter()) {
        assert_eq!(
            eval_horner(&r4.r2_coeffs, &h),
            eval_horner(&r2.c2_coeffs, &h),
            "R2 must agree with C2 at h2w3/h3w3"
        );
    }

    // F effective degree < 9n - 6.
    for (i, c) in r4.f_coeffs.iter().enumerate() {
        if i >= 9 * n - 6 {
            assert!(c.is_zero(), "F coef at {i} must be zero (deg < 9n−6)");
        }
    }

    assert!(
        !r4.w1_commitment.infinity,
        "W1 commitment must not be the point at infinity"
    );
}

#[test]
fn poseidon_round4_produces_w1() {
    let (_r1, _r2, _r3, r4) = run_all_rounds(
        "tests/fixtures/poseidon/circuit.zkey",
        "tests/fixtures/poseidon/witness.wtns",
    );
    assert!(!r4.w1_commitment.infinity);
}

#[test]
fn multiplier_round5_produces_w2() {
    let zkey = std::fs::read("tests/fixtures/multiplier/circuit.zkey").unwrap();
    let (r1, r2, r3, r4) = run_all_rounds(
        "tests/fixtures/multiplier/circuit.zkey",
        "tests/fixtures/multiplier/witness.wtns",
    );
    let r5 = round5(&zkey, &r1, &r2, &r3, &r4).expect("Round 5");
    assert!(!r5.w2_commitment.infinity, "W2 must be non-infinity");
    assert!(!r5.y.is_zero(), "y must be non-zero");
    assert!(!r5.inv.is_zero(), "inv must be non-zero");
}

#[test]
fn poseidon_round5_produces_w2() {
    let zkey = std::fs::read("tests/fixtures/poseidon/circuit.zkey").unwrap();
    let (r1, r2, r3, r4) = run_all_rounds(
        "tests/fixtures/poseidon/circuit.zkey",
        "tests/fixtures/poseidon/witness.wtns",
    );
    let r5 = round5(&zkey, &r1, &r2, &r3, &r4).expect("Round 5");
    assert!(!r5.w2_commitment.infinity);
    assert!(!r5.inv.is_zero());
}
