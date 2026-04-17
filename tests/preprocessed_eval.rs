//! Integration test: preprocessed polynomial evaluations at xi match snarkjs.
//!
//! The reference proof's `evaluations.ql/qr/qm/qo/qc/s1/s2/s3` are
//! **blinder-independent** — they depend only on the preprocessed polynomials
//! and the challenge xi (which is deterministic given C0, public inputs, C1,
//! C2). This gives us a ground-truth correctness check for:
//!
//! 1. zkey section parsing (we're reading the coefficient block, not the
//!    extended-evaluation block that follows it)
//! 2. Fiat-Shamir challenge derivation (beta → gamma → xiSeed → xi)
//! 3. Horner evaluation of the coefficient form
//!
//! Because C1 and C2 here come from the reference proof (snarkjs applies
//! random blinding, so we can't yet produce matching ones ourselves), this
//! test validates everything upstream of Round 1 blinding.

use std::str::FromStr;

use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::PrimeField;

use fflonk_prover::challenges::derive_pre_eval_challenges;
use fflonk_prover::poly::eval_horner;
use fflonk_prover::zkey::{
    read_fflonk_header, read_fr_section, SECTION_QC, SECTION_QL, SECTION_QM, SECTION_QO,
    SECTION_QR, SECTION_SIGMA1, SECTION_SIGMA2, SECTION_SIGMA3,
};

fn fr(s: &str) -> Fr {
    Fr::from_str(s).unwrap()
}
fn fq(s: &str) -> Fq {
    Fq::from_str(s).unwrap()
}
fn g1(x: &str, y: &str) -> G1Affine {
    G1Affine::new_unchecked(fq(x), fq(y))
}

fn fr_decimal(x: &Fr) -> String {
    x.into_bigint().to_string()
}

/// Evaluate each preprocessed poly's coefficient block (the first `domain_size`
/// entries of its zkey section) at `xi` via Horner, and compare against the
/// named reference values.
#[allow(clippy::too_many_arguments)]
fn check_preprocessed_eval_matches_reference(
    zkey_path: &str,
    c0: G1Affine,
    public_inputs: &[Fr],
    c1: G1Affine,
    c2: G1Affine,
    ref_ql: &str,
    ref_qr: &str,
    ref_qm: &str,
    ref_qo: &str,
    ref_qc: &str,
    ref_s1: &str,
    ref_s2: &str,
    ref_s3: &str,
) {
    let bytes = std::fs::read(zkey_path).expect("read zkey");
    let header = read_fflonk_header(&bytes).expect("fflonk header");
    let n = header.domain_size as usize;

    let ch = derive_pre_eval_challenges(&c0, public_inputs, &c1, &c2);
    let xi = ch.xi;

    // Sections 7-14 each store domain_size coefficients followed by 4*domain_size
    // extended-domain evaluations. Horner eval uses only the first domain_size.
    let sections_and_refs = [
        (SECTION_QL, ref_ql, "ql"),
        (SECTION_QR, ref_qr, "qr"),
        (SECTION_QM, ref_qm, "qm"),
        (SECTION_QO, ref_qo, "qo"),
        (SECTION_QC, ref_qc, "qc"),
        (SECTION_SIGMA1, ref_s1, "s1"),
        (SECTION_SIGMA2, ref_s2, "s2"),
        (SECTION_SIGMA3, ref_s3, "s3"),
    ];

    for (section, expected, name) in sections_and_refs {
        let all = read_fr_section(&bytes, section).expect("read section");
        assert!(
            all.len() >= n,
            "{name} section has {} entries, need at least domain_size = {}",
            all.len(),
            n
        );
        let coeffs = &all[..n];
        let got = eval_horner(coeffs, &xi);
        assert_eq!(
            fr_decimal(&got),
            expected,
            "{name}(xi) mismatch for {zkey_path}"
        );
    }
}

#[test]
fn multiplier_preprocessed_evals_match_reference_proof() {
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

    check_preprocessed_eval_matches_reference(
        "tests/fixtures/multiplier/circuit.zkey",
        c0,
        &[a0],
        c1,
        c2,
        "8656540919485434325127996463862963077422400187418464280627379020094348872551", // ql
        "0",                                                                            // qr
        "2614769233458373575914167661386876499189977403679308856418227786252928171678", // qm
        "19273473638380901646332238083870398589358386996736725487279976400322880323939", // qo
        "0",                                                                            // qc
        "2149601555970763550502742290511066346210126521388222512348169637526747700236", // s1
        "7665469566589217530047082740024900379575949551084655260788477394062900215820", // s2
        "9593052032151367161561845615248167687278938119063653268474063026781260594803", // s3
    );
}

#[test]
fn poseidon_preprocessed_evals_match_reference_proof() {
    // C0 from poseidon vkey.json.
    let c0 = g1(
        "21342674531087010225385741050229704484891596360707604170547584125555214038872",
        "8365339691681069099917077877426775495641845901682885382732018839834527778288",
    );
    // Public input from poseidon reference_public.json (Poseidon hash output).
    let a0 = fr("12642653099436540934183106170508806679762362202642476214742223175554403097455");
    // Poseidon reference_proof.json C1, C2.
    let c1 = g1(
        "10345539896790562310268545719484618624878724164467406853202670388873566487584",
        "14791947975223532527810520936945344675936099071990049395243073751357451209310",
    );
    let c2 = g1(
        "13491252662025650996215451483323904900479097719434743233423113904284018577945",
        "17948112801711914074942629668441071112750140862914053127078607339583115421494",
    );

    check_preprocessed_eval_matches_reference(
        "tests/fixtures/poseidon/circuit.zkey",
        c0,
        &[a0],
        c1,
        c2,
        "19946649818808256646253007200142144768381156103858135407351238993471955454529", // ql
        "7655104822918949681016750869247242549102484394597938420120938936910127962840",  // qr
        "11655784851329885286746831537179143054528037302140104206262156432799084245475", // qm
        "17453935515845557541307084855654303908329335512590875543386356634616584898416", // qo
        "19989896804235406082365645321558809684265039185957782235135909346152031927980", // qc
        "2395034355081231068101664757912052272054123639915491688834958243337450741043",  // s1
        "6202150022760558673528290640261837981497609250855045228153588568873624869338",  // s2
        "6379289685134109605310871618567835280296558946015216813595246186050081402562",  // s3
    );
}
