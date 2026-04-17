//! Structural integration test for prover Round 1.
//!
//! The single strongest correctness signal available in Round 1 without end-
//! to-end verification is: `compute_t0` returns `Ok(_)`. Internally, it runs
//! the gate-polynomial numerator's evaluation buffer through iFFT and then
//! divides by Z_H = X^n − 1. Divisibility holds iff the PLONK gate equation
//!
//!     q_L·A + q_R·B + q_M·A·B + q_O·C + q_C + PI = 0
//!
//! holds at every base-domain point ω^i — which in turn requires correct
//! wire construction, correct preprocessed-polynomial reading, and correct
//! public-input Lagrange evaluation. So `round1(...).is_ok()` is a
//! substantive correctness check, not just a smoke test.

use ark_ff::Zero;
use fflonk_prover::prover::{round1, Round1Blinders};
use fflonk_prover::wtns;

#[test]
fn multiplier_round1_gate_equation_holds() {
    let zkey = std::fs::read("tests/fixtures/multiplier/circuit.zkey").unwrap();
    let witness = wtns::read_from_path(std::path::Path::new(
        "tests/fixtures/multiplier/witness.wtns",
    ))
    .unwrap()
    .values;

    let out = round1(&zkey, &witness, &Round1Blinders::zero())
        .expect("Round 1 must succeed — gate equation satisfied and T0 divisible by Z_H");

    let n = out.header.domain_size as usize;

    assert_eq!(out.a_poly.len(), n, "A poly has {n} coeffs");
    assert_eq!(out.b_poly.len(), n, "B poly has {n} coeffs");
    assert_eq!(out.c_poly.len(), n, "C poly has {n} coeffs");

    // T0 has at most 3n coeffs post-div-by-Zh. Effective degree < 2n-2.
    assert!(out.t0_poly.len() <= 3 * n, "T0 vec length <= 3n");
    for (i, c) in out.t0_poly.iter().enumerate() {
        if i >= 2 * n - 2 {
            assert!(
                c.is_zero(),
                "T0 coef at index {i} must be zero (degree < 2n-2 = {})",
                2 * n - 2
            );
        }
    }

    // C1 degree constraint from snarkjs fflonk_prove.js: C1.degree() < 8n - 8.
    for (i, c) in out.c1_coeffs.iter().enumerate() {
        if i >= 8 * n - 8 {
            assert!(
                c.is_zero(),
                "C1 coef at index {i} must be zero (degree < 8n-8 = {})",
                8 * n - 8
            );
        }
    }

    // Commitment is a real (non-identity) G1 point.
    assert!(
        !out.c1_commitment.infinity,
        "C1 commitment must not be the point at infinity"
    );
}

#[test]
fn poseidon_round1_gate_equation_holds() {
    let zkey = std::fs::read("tests/fixtures/poseidon/circuit.zkey").unwrap();
    let witness =
        wtns::read_from_path(std::path::Path::new("tests/fixtures/poseidon/witness.wtns"))
            .unwrap()
            .values;

    let out = round1(&zkey, &witness, &Round1Blinders::zero())
        .expect("poseidon Round 1 must succeed — gate equation + divisibility");

    let n = out.header.domain_size as usize;
    assert_eq!(out.a_poly.len(), n);
    assert_eq!(out.b_poly.len(), n);
    assert_eq!(out.c_poly.len(), n);
    assert!(
        !out.c1_commitment.infinity,
        "poseidon C1 commitment must not be the point at infinity"
    );
}
