//! FFLONK challenge derivation (Fiat-Shamir chain matching snarkjs 0.7.6).
//!
//! The prover chains Keccak256 transcripts to derive verifier challenges.
//! This module covers the pre-evaluation chain — beta, gamma, xiSeed, xi —
//! which is all we need to evaluate the preprocessed polynomials at xi
//! (a blinder-independent ground-truth check).
//!
//! Chain (from `snarkjs/src/fflonk_prove.js`):
//! 1. `beta  = H(C0 || A[0..nPublic] || C1)`
//! 2. `gamma = H(beta)` — transcript is reset, then beta is absorbed
//! 3. `xiSeed = H(gamma || C2)` — a fresh transcript
//! 4. `xi = xiSeed^24`

use ark_bn254::{Fr, G1Affine};
use ark_ff::Field;

use crate::transcript::Keccak256Transcript;

/// Derived challenges needed to evaluate the preprocessed polynomials at xi.
#[derive(Debug, Clone)]
pub struct PreEvalChallenges {
    pub beta: Fr,
    pub gamma: Fr,
    pub xi_seed: Fr,
    pub xi: Fr,
}

/// Derive (beta, gamma) — the Round-2 permutation challenges.
///
/// - `c0`: the zkey's C0 (commitment to the merged preprocessed polynomial)
/// - `public_inputs`: the first `nPublic` entries of buffer A (i.e. the public
///   signals, in the order snarkjs emits them)
/// - `c1`: the round-1 commitment
pub fn derive_beta_gamma(c0: &G1Affine, public_inputs: &[Fr], c1: &G1Affine) -> (Fr, Fr) {
    let mut t = Keccak256Transcript::new();
    t.add_g1_point(c0);
    for a in public_inputs {
        t.add_scalar(a);
    }
    t.add_g1_point(c1);
    let beta = t.get_challenge();

    t.reset();
    t.add_scalar(&beta);
    let gamma = t.get_challenge();

    (beta, gamma)
}

/// Run the pre-evaluation Fiat-Shamir chain.
///
/// - `c0`: the zkey's C0 (commitment to the merged preprocessed polynomial)
/// - `public_inputs`: the first `nPublic` entries of buffer A (i.e. the public
///   signals, in the order snarkjs emits them)
/// - `c1`: the round-1 commitment (output of the prover's Round 1)
/// - `c2`: the round-2 commitment (output of the prover's Round 2)
pub fn derive_pre_eval_challenges(
    c0: &G1Affine,
    public_inputs: &[Fr],
    c1: &G1Affine,
    c2: &G1Affine,
) -> PreEvalChallenges {
    let (beta, gamma) = derive_beta_gamma(c0, public_inputs, c1);

    // Step 3: xiSeed — fresh transcript with (gamma, C2).
    let mut t = Keccak256Transcript::new();
    t.add_scalar(&gamma);
    t.add_g1_point(c2);
    let xi_seed = t.get_challenge();

    // Step 4: xi = xiSeed^24 (snarkjs: h2 = xiSeed^8, xi = h2^3).
    let xi = xi_seed.pow([24u64]);

    PreEvalChallenges {
        beta,
        gamma,
        xi_seed,
        xi,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fq;
    use std::str::FromStr;

    fn fr(s: &str) -> Fr {
        Fr::from_str(s).unwrap()
    }
    fn fq(s: &str) -> Fq {
        Fq::from_str(s).unwrap()
    }
    fn g1(x: &str, y: &str) -> G1Affine {
        G1Affine::new_unchecked(fq(x), fq(y))
    }

    /// Reference xi from the snarkjs fflonk_prove verbose log on multiplier
    /// (captured previously during Phase 3 transcript bring-up).
    #[test]
    fn multiplier_pre_eval_chain_matches_reference() {
        // C0 from vkey.json.
        let c0 = g1(
            "11865776073359729040794258160793130354546641422008347334213198060920506239709",
            "5524268144136126767933990501392740300548075291727485037030383383698594318676",
        );
        // Public input A[0] = c = 3 * 11 = 33.
        let a0 = Fr::from(33u64);
        // C1, C2 from reference_proof.json.
        let c1 = g1(
            "17256955544720010681668327440745774482888643498003365476558443417839496374119",
            "10014919292886339171655109553878758397079400172242899911914719305365841767683",
        );
        let c2 = g1(
            "3989673609061789950409244862037062929227173903571937065370636622611135085513",
            "6001160714579456671825974713880720307084678625405829727727240696134952136276",
        );

        let ch = derive_pre_eval_challenges(&c0, &[a0], &c1, &c2);

        let expected_xi =
            fr("20443477157474477067726745912638374445877616467670459784841395663060888101329");
        assert_eq!(ch.xi, expected_xi, "xi from chain must match snarkjs log");
    }
}
