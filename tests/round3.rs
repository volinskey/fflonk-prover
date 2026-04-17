//! Integration test for prover Round 3 (our "evaluate at xi" task).
//!
//! End-to-end sanity: rounds 1→2→3 complete on both fixtures, xi is derived
//! via the snarkjs chain (xi_seed = H(γ, C2); xi = xi_seed^24), and the 16
//! evaluations are produced. We also assert:
//!
//! - For multiplier the `qc` coefficient block is all zero (qc = 0 everywhere
//!   per its reference proof), so the evaluation must be zero.
//! - xi ≠ 0 and xiw = xi · ω_n.

use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use fflonk_prover::challenges::derive_beta_gamma;
use fflonk_prover::prover::{round1, round2, round3, Round1Blinders, Round2Blinders};
use fflonk_prover::wtns;

fn run_r1_r2_r3(
    zkey_path: &str,
    wtns_path: &str,
) -> (
    fflonk_prover::prover::Round1Output,
    fflonk_prover::prover::Round2Output,
    fflonk_prover::prover::Round3Evaluations,
) {
    let zkey = std::fs::read(zkey_path).unwrap();
    let witness = wtns::read_from_path(std::path::Path::new(wtns_path))
        .unwrap()
        .values;
    let r1 = round1(&zkey, &witness, &Round1Blinders::zero()).unwrap();
    let n_public = r1.header.n_public as usize;
    let public_inputs: Vec<_> = (1..=n_public).map(|j| witness[j]).collect();
    let (_beta, gamma) = derive_beta_gamma(&r1.header.c0, &public_inputs, &r1.c1_commitment);
    let r2 = round2(&zkey, &r1, _beta, gamma, &Round2Blinders::zero()).unwrap();
    let r3 = round3(&zkey, &r1, &r2, gamma).unwrap();
    (r1, r2, r3)
}

#[test]
fn multiplier_round3_evaluations_are_well_formed() {
    let (r1, _r2, r3) = run_r1_r2_r3(
        "tests/fixtures/multiplier/circuit.zkey",
        "tests/fixtures/multiplier/witness.wtns",
    );

    let n = r1.header.domain_size as usize;
    let domain = Radix2EvaluationDomain::<ark_bn254::Fr>::new(n).unwrap();
    assert!(!r3.xi.is_zero(), "xi must be non-zero");
    assert_eq!(r3.xiw, r3.xi * domain.group_gen, "xiw = xi · ω_n");

    // Multiplier qc(X) ≡ 0, so qc evaluated at any xi is 0.
    assert!(r3.qc.is_zero(), "multiplier qc(xi) must be zero");
    // Multiplier qr(X) ≡ 0 likewise.
    assert!(r3.qr.is_zero(), "multiplier qr(xi) must be zero");
}

#[test]
fn poseidon_round3_evaluations_are_well_formed() {
    let (r1, _r2, r3) = run_r1_r2_r3(
        "tests/fixtures/poseidon/circuit.zkey",
        "tests/fixtures/poseidon/witness.wtns",
    );

    let n = r1.header.domain_size as usize;
    let domain = Radix2EvaluationDomain::<ark_bn254::Fr>::new(n).unwrap();
    assert!(!r3.xi.is_zero());
    assert_eq!(r3.xiw, r3.xi * domain.group_gen);
}
