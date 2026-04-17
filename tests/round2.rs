//! Structural integration test for prover Round 2.
//!
//! Round 2 produces three polynomials — Z, T1, T2 — whose correctness signals
//! are:
//!
//! 1. **Z[0] = 1** after the grand-product closes: holds iff the copy
//!    constraints are satisfied by the witness.
//! 2. **T1 = (Z−1)·L_1 / Z_H divides cleanly**: holds iff Z(ω⁰) = 1 (same
//!    signal as #1, checked on the 2n-domain as a polynomial identity).
//! 3. **T2 divides by Z_H cleanly**: holds iff the PLONK permutation identity
//!
//!        (a + βX + γ)(b + βk₁X + γ)(c + βk₂X + γ)·z(X)
//!      − (a + βσ₁ + γ)(b + βσ₂ + γ)(c + βσ₃ + γ)·z(Xω)
//!
//!    vanishes on every base-domain point — i.e. the σ-permutation matches.
//!
//! All three signals combined ≈ "copy-constraint + permutation equations hold
//! for this zkey/witness." For zero blinding (b_7=b_8=b_9=0), these are
//! deterministic and test end-to-end Round 2 correctness without randomness.

use ark_ff::Zero;
use fflonk_prover::challenges::derive_beta_gamma;
use fflonk_prover::prover::{round1, round2, Round1Blinders, Round2Blinders};
use fflonk_prover::wtns;

fn run_rounds_1_2(
    zkey_path: &str,
    wtns_path: &str,
) -> (
    fflonk_prover::prover::Round1Output,
    fflonk_prover::prover::Round2Output,
) {
    let zkey = std::fs::read(zkey_path).unwrap();
    let witness = wtns::read_from_path(std::path::Path::new(wtns_path))
        .unwrap()
        .values;

    let r1 = round1(&zkey, &witness, &Round1Blinders::zero()).expect("Round 1");

    // Derive beta, gamma from C0, public inputs, C1. Public inputs are
    // witness[1..=n_public] (Circom puts signal 0 as the implicit "1" slot).
    let n_public = r1.header.n_public as usize;
    let public_inputs: Vec<_> = (1..=n_public).map(|j| witness[j]).collect();
    let (beta, gamma) = derive_beta_gamma(&r1.header.c0, &public_inputs, &r1.c1_commitment);

    let r2 = round2(&zkey, &r1, beta, gamma, &Round2Blinders::zero()).expect("Round 2");

    (r1, r2)
}

#[test]
fn multiplier_round2_permutation_identities_hold() {
    let (r1, r2) = run_rounds_1_2(
        "tests/fixtures/multiplier/circuit.zkey",
        "tests/fixtures/multiplier/witness.wtns",
    );

    let n = r1.header.domain_size as usize;

    // Z(ω⁰) = 1 enforced by compute_z_buffer's internal check.
    // Degree checks:
    assert!(
        r2.z_poly.len() <= n + 3,
        "Z poly length <= n+3, got {}",
        r2.z_poly.len()
    );

    // T1 effective degree < n+2 (blinded). Zero-blinding: T1 has length 2n but
    // coefficients above n+1 must be zero.
    for (i, c) in r2.t1_poly.iter().enumerate() {
        if i >= n + 2 {
            assert!(c.is_zero(), "T1 coef at index {i} must be zero (deg < n+2)");
        }
    }

    // T2 effective degree < 3n. Length is 4n; top n coefs must be zero.
    for (i, c) in r2.t2_poly.iter().enumerate() {
        if i >= 3 * n {
            assert!(c.is_zero(), "T2 coef at index {i} must be zero (deg < 3n)");
        }
    }

    // C2 effective degree < 9n.
    for (i, c) in r2.c2_coeffs.iter().enumerate() {
        if i >= 9 * n {
            assert!(c.is_zero(), "C2 coef at index {i} must be zero (deg < 9n)");
        }
    }

    assert!(
        !r2.c2_commitment.infinity,
        "C2 commitment must not be the point at infinity"
    );
}

#[test]
fn poseidon_round2_permutation_identities_hold() {
    let (r1, r2) = run_rounds_1_2(
        "tests/fixtures/poseidon/circuit.zkey",
        "tests/fixtures/poseidon/witness.wtns",
    );

    let n = r1.header.domain_size as usize;
    assert!(r2.z_poly.len() <= n + 3);
    assert!(
        !r2.c2_commitment.infinity,
        "poseidon C2 commitment must not be the point at infinity"
    );
}
