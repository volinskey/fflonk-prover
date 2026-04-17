//! Native Rust FFLONK verifier — matches snarkjs 0.7.6 `fflonk_verify.js`.
//!
//! Verifies a proof produced either by `fflonk-prover prove` or by `snarkjs
//! fflonk prove` (both are byte-compatible). Uses `ark_bn254`'s pairing.
//!
//! Provided primarily as a convenience for library users who don't want to
//! shell out to Node. For on-chain verification, use the Solidity contract
//! emitted by `snarkjs fflonk exportsoliditycalldata`.

use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::AffineRepr;
use ark_ff::{Field, One, Zero};
use serde::Deserialize;
use thiserror::Error;

use crate::transcript::Keccak256Transcript;
use crate::vkey::{parse_vkey, VerificationKey, VkeyError};

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("json parse: {0}")]
    Json(#[from] serde_json::Error),
    #[error("vkey parse: {0}")]
    Vkey(#[from] VkeyError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("proof has wrong protocol: {0}")]
    WrongProtocol(String),
    #[error("proof has wrong curve: {0}")]
    WrongCurve(String),
    #[error("public inputs count {got} != vk.n_public {want}")]
    WrongPublicCount { got: usize, want: usize },
    #[error("invalid Fr/Fq decimal: {0}")]
    BadFieldElement(String),
    #[error("commitment not on G1 curve: {0}")]
    BadG1(String),
}

#[derive(Debug, Deserialize)]
struct RawProof {
    polynomials: RawPolynomials,
    evaluations: RawEvaluations,
    protocol: String,
    curve: String,
}

#[derive(Debug, Deserialize)]
struct RawPolynomials {
    #[serde(rename = "C1")]
    c1: [String; 3],
    #[serde(rename = "C2")]
    c2: [String; 3],
    #[serde(rename = "W1")]
    w1: [String; 3],
    #[serde(rename = "W2")]
    w2: [String; 3],
}

#[derive(Debug, Deserialize)]
struct RawEvaluations {
    ql: String,
    qr: String,
    qm: String,
    qo: String,
    qc: String,
    s1: String,
    s2: String,
    s3: String,
    a: String,
    b: String,
    c: String,
    z: String,
    zw: String,
    t1w: String,
    t2w: String,
    // inv is present but snarkjs's verifier recomputes the Montgomery batched
    // inverse itself. It's there for on-chain verifier gas optimization.
    #[allow(dead_code)]
    inv: String,
}

#[derive(Debug, Clone)]
struct ParsedProof {
    c1: G1Affine,
    c2: G1Affine,
    w1: G1Affine,
    w2: G1Affine,
    ql: Fr,
    qr: Fr,
    qm: Fr,
    qo: Fr,
    qc: Fr,
    s1: Fr,
    s2: Fr,
    s3: Fr,
    a: Fr,
    b: Fr,
    c: Fr,
    z: Fr,
    zw: Fr,
    t1w: Fr,
    t2w: Fr,
}

fn fr_decimal(s: &str) -> Result<Fr, VerifyError> {
    Fr::from_str(s).map_err(|_| VerifyError::BadFieldElement(s.to_owned()))
}
fn fq_decimal(s: &str) -> Result<Fq, VerifyError> {
    Fq::from_str(s).map_err(|_| VerifyError::BadFieldElement(s.to_owned()))
}
fn g1_from_triple(t: &[String; 3]) -> Result<G1Affine, VerifyError> {
    let x = fq_decimal(&t[0])?;
    let y = fq_decimal(&t[1])?;
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(VerifyError::BadG1(format!("[{}, {}]", t[0], t[1])));
    }
    Ok(p)
}

fn parse_proof(json: &[u8]) -> Result<ParsedProof, VerifyError> {
    let raw: RawProof = serde_json::from_slice(json)?;
    if raw.protocol != "fflonk" {
        return Err(VerifyError::WrongProtocol(raw.protocol));
    }
    if raw.curve != "bn128" {
        return Err(VerifyError::WrongCurve(raw.curve));
    }
    Ok(ParsedProof {
        c1: g1_from_triple(&raw.polynomials.c1)?,
        c2: g1_from_triple(&raw.polynomials.c2)?,
        w1: g1_from_triple(&raw.polynomials.w1)?,
        w2: g1_from_triple(&raw.polynomials.w2)?,
        ql: fr_decimal(&raw.evaluations.ql)?,
        qr: fr_decimal(&raw.evaluations.qr)?,
        qm: fr_decimal(&raw.evaluations.qm)?,
        qo: fr_decimal(&raw.evaluations.qo)?,
        qc: fr_decimal(&raw.evaluations.qc)?,
        s1: fr_decimal(&raw.evaluations.s1)?,
        s2: fr_decimal(&raw.evaluations.s2)?,
        s3: fr_decimal(&raw.evaluations.s3)?,
        a: fr_decimal(&raw.evaluations.a)?,
        b: fr_decimal(&raw.evaluations.b)?,
        c: fr_decimal(&raw.evaluations.c)?,
        z: fr_decimal(&raw.evaluations.z)?,
        zw: fr_decimal(&raw.evaluations.zw)?,
        t1w: fr_decimal(&raw.evaluations.t1w)?,
        t2w: fr_decimal(&raw.evaluations.t2w)?,
    })
}

fn parse_public(json: &[u8]) -> Result<Vec<Fr>, VerifyError> {
    let raw: Vec<String> = serde_json::from_slice(json)?;
    raw.iter().map(|s| fr_decimal(s)).collect()
}

struct Challenges {
    beta: Fr,
    gamma: Fr,
    xi: Fr,
    xi_n: Fr,
    #[allow(dead_code)] // kept for diagnostics / future verbose mode
    alpha: Fr,
    y: Fr,
    inv_zh: Fr,
    temp: Fr, // mulH0
    quotient1: Fr,
    quotient2: Fr,
}

struct Roots {
    h0w8: [Fr; 8],
    h1w4: [Fr; 4],
    h2w3: [Fr; 3],
    h3w3: [Fr; 3],
}

fn compute_challenges(
    proof: &ParsedProof,
    vk: &VerificationKey,
    public: &[Fr],
) -> (Challenges, Roots) {
    let mut t = Keccak256Transcript::new();
    t.add_g1_point(&vk.c0);
    for p in public {
        t.add_scalar(p);
    }
    t.add_g1_point(&proof.c1);
    let beta = t.get_challenge();

    t.reset();
    t.add_scalar(&beta);
    let gamma = t.get_challenge();

    let mut t = Keccak256Transcript::new();
    t.add_scalar(&gamma);
    t.add_g1_point(&proof.c2);
    let xi_seed = t.get_challenge();
    let xi_seed2 = xi_seed * xi_seed;

    let mut w8 = [Fr::one(); 8];
    for i in 1..8 {
        w8[i] = w8[i - 1] * vk.w8;
    }
    let mut w4 = [Fr::one(); 4];
    for i in 1..4 {
        w4[i] = w4[i - 1] * vk.w4;
    }
    let w3 = [Fr::one(), vk.w3, vk.w3 * vk.w3];

    let h0 = xi_seed2 * xi_seed;
    let mut h0w8 = [Fr::zero(); 8];
    h0w8[0] = h0;
    for i in 1..8 {
        h0w8[i] = h0 * w8[i];
    }

    let h1 = h0 * h0;
    let mut h1w4 = [Fr::zero(); 4];
    h1w4[0] = h1;
    for i in 1..4 {
        h1w4[i] = h1 * w4[i];
    }

    let h2 = h1 * xi_seed2;
    let h2w3 = [h2, h2 * w3[1], h2 * w3[2]];

    let h3 = h2 * vk.wr;
    let h3w3 = [h3, h3 * w3[1], h3 * w3[2]];

    let xi = (h2 * h2) * h2; // xi_seed^24 = (h2)^3

    let mut xi_n = xi;
    for _ in 0..vk.power {
        xi_n = xi_n * xi_n;
    }

    // alpha = H(xi_seed || 15 evaluations)
    let mut t = Keccak256Transcript::new();
    t.add_scalar(&xi_seed);
    for ev in [
        &proof.ql, &proof.qr, &proof.qm, &proof.qo, &proof.qc, &proof.s1, &proof.s2, &proof.s3,
        &proof.a, &proof.b, &proof.c, &proof.z, &proof.zw, &proof.t1w, &proof.t2w,
    ] {
        t.add_scalar(ev);
    }
    let alpha = t.get_challenge();

    let mut t = Keccak256Transcript::new();
    t.add_scalar(&alpha);
    t.add_g1_point(&proof.w1);
    let y = t.get_challenge();

    let zh = xi_n - Fr::one();
    let inv_zh = zh.inverse().expect("Z_H(xi) = 0; xi lies on the domain");

    let roots = Roots {
        h0w8,
        h1w4,
        h2w3,
        h3w3,
    };

    let mut ch = Challenges {
        beta,
        gamma,
        xi,
        xi_n,
        alpha,
        y,
        inv_zh,
        temp: Fr::zero(),
        quotient1: Fr::zero(),
        quotient2: Fr::zero(),
    };

    // Compute mulH0, mulH1, mulH2 and quotient{1,2}; stored here for reuse.
    let mul_h0: Fr = roots.h0w8.iter().map(|&h| y - h).product();
    let mul_h1: Fr = roots.h1w4.iter().map(|&h| y - h).product();
    let mul_h2: Fr = roots
        .h2w3
        .iter()
        .chain(roots.h3w3.iter())
        .map(|&h| y - h)
        .product();
    ch.temp = mul_h0;
    ch.quotient1 = alpha * mul_h0 * mul_h1.inverse().expect("mulH1≠0");
    ch.quotient2 = (alpha * alpha) * mul_h0 * mul_h2.inverse().expect("mulH2≠0");

    (ch, roots)
}

fn lagrange_1_at_xi(ch: &Challenges, vk: &VerificationKey) -> Fr {
    // L_1(xi) = (xi^n - 1) / (n · (xi - 1))
    let num = ch.xi_n - Fr::one();
    let den = Fr::from(vk.domain_size as u64) * (ch.xi - Fr::one());
    num * den.inverse().expect("denominator zero in L_1(xi)")
}

fn lagrange_public(public: &[Fr], ch: &Challenges, vk: &VerificationKey) -> Vec<Fr> {
    // L_i(xi) for i in 1..=n_public: = ω^{i-1} · (xi^n - 1) / (n · (xi - ω^{i-1}))
    let n = vk.n_public.max(1) as usize;
    let mut out = Vec::with_capacity(n);
    let mut w = Fr::one();
    let zh = ch.xi_n - Fr::one();
    let n_fr = Fr::from(vk.domain_size as u64);
    for _ in 0..n {
        let num = w * zh;
        let den = n_fr * (ch.xi - w);
        out.push(num * den.inverse().expect("L_i denom zero"));
        w *= vk.w;
    }
    let _ = public;
    out
}

fn pi_at_xi(public: &[Fr], lagrange_evals: &[Fr]) -> Fr {
    let mut pi = Fr::zero();
    for (i, w) in public.iter().enumerate() {
        pi -= *w * lagrange_evals[i];
    }
    pi
}

/// Evaluate L_i(y) for each of `roots` (where the roots are n points whose
/// products form the zerofier X^n − xi). Matches snarkjs `computeLagrangeLiSi`.
fn compute_li_s<const N: usize>(roots: &[Fr; N], y: Fr, xi: Fr) -> [Fr; N] {
    let len = N as u64;
    let num = y.pow([len]) - xi;
    let den1 = Fr::from(len) * roots[0].pow([(len - 2)]);
    let mut li = [Fr::zero(); N];
    for i in 0..N {
        let den2 = roots[((N - 1) * i) % N];
        let den3 = y - roots[i];
        li[i] = num * (den1 * den2 * den3).inverse().expect("LiS denom zero");
    }
    li
}

/// Evaluate L_i(y) for the 6-point S2 set (h2w3 ++ h3w3) with zerofier
/// (X^3 − xi)(X^3 − xiw).
fn compute_li_s2(roots_a: &[Fr; 3], roots_b: &[Fr; 3], y: Fr, xi: Fr, xiw: Fr) -> [Fr; 6] {
    let len = 3u64;
    let n = 6u64;
    let y_n = y.pow([n]);
    let y_l = y.pow([len]);
    let num = y_n - (xi + xiw) * y_l + xi * xiw;

    let mut li = [Fr::zero(); 6];
    let den1_a = Fr::from(len) * roots_a[0] * (xi - xiw);
    for i in 0..3usize {
        let den2 = roots_a[(2 * i) % 3];
        let den3 = y - roots_a[i];
        li[i] = num * (den1_a * den2 * den3).inverse().expect("LiS2 denom zero");
    }
    let den1_b = Fr::from(len) * roots_b[0] * (xiw - xi);
    for i in 0..3usize {
        let den2 = roots_b[(2 * i) % 3];
        let den3 = y - roots_b[i];
        li[i + 3] = num * (den1_b * den2 * den3).inverse().expect("LiS2 denom zero");
    }
    li
}

fn compute_r0(proof: &ParsedProof, ch: &Challenges, roots: &Roots) -> Fr {
    let li = compute_li_s(&roots.h0w8, ch.y, ch.xi);
    let mut res = Fr::zero();
    for (i, &h) in roots.h0w8.iter().enumerate() {
        let mut pow = [Fr::one(); 8];
        for j in 1..8 {
            pow[j] = pow[j - 1] * h;
        }
        let c0 = proof.ql
            + proof.qr * pow[1]
            + proof.qo * pow[2]
            + proof.qm * pow[3]
            + proof.qc * pow[4]
            + proof.s1 * pow[5]
            + proof.s2 * pow[6]
            + proof.s3 * pow[7];
        res += c0 * li[i];
    }
    res
}

fn compute_r1(proof: &ParsedProof, ch: &Challenges, roots: &Roots, pi: Fr) -> Fr {
    let li = compute_li_s(&roots.h1w4, ch.y, ch.xi);
    // T0(xi) = (ql·a + qr·b + qm·a·b + qo·c + qc + PI(xi)) / Z_H(xi)
    let t0 = (proof.ql * proof.a
        + proof.qr * proof.b
        + proof.qm * proof.a * proof.b
        + proof.qo * proof.c
        + proof.qc
        + pi)
        * ch.inv_zh;
    let mut res = Fr::zero();
    for (i, &h) in roots.h1w4.iter().enumerate() {
        let h2 = h * h;
        let c1 = proof.a + h * proof.b + h2 * proof.c + h2 * h * t0;
        res += c1 * li[i];
    }
    res
}

fn compute_r2(
    proof: &ParsedProof,
    ch: &Challenges,
    roots: &Roots,
    lagrange1: Fr,
    vk: &VerificationKey,
) -> Fr {
    let li = compute_li_s2(&roots.h2w3, &roots.h3w3, ch.y, ch.xi, ch.xi * vk.w);
    let t1 = (proof.z - Fr::one()) * lagrange1 * ch.inv_zh;

    let betaxi = ch.beta * ch.xi;
    let t211 = proof.a + betaxi + ch.gamma;
    let t212 = proof.b + betaxi * vk.k1 + ch.gamma;
    let t213 = proof.c + betaxi * vk.k2 + ch.gamma;
    let t21 = t211 * t212 * t213 * proof.z;

    let t221 = proof.a + ch.beta * proof.s1 + ch.gamma;
    let t222 = proof.b + ch.beta * proof.s2 + ch.gamma;
    let t223 = proof.c + ch.beta * proof.s3 + ch.gamma;
    let t22 = t221 * t222 * t223 * proof.zw;

    let t2 = (t21 - t22) * ch.inv_zh;

    let mut res = Fr::zero();
    for (i, &h) in roots.h2w3.iter().enumerate() {
        let c2 = proof.z + h * t1 + (h * h) * t2;
        res += c2 * li[i];
    }
    for (i, &h) in roots.h3w3.iter().enumerate() {
        let c2 = proof.zw + h * proof.t1w + (h * h) * proof.t2w;
        res += c2 * li[i + 3];
    }
    res
}

fn compute_f_point(proof: &ParsedProof, vk: &VerificationKey, ch: &Challenges) -> G1Affine {
    let f2: G1Projective = G1Projective::from(proof.c1) * ch.quotient1;
    let f3: G1Projective = G1Projective::from(proof.c2) * ch.quotient2;
    let f: G1Projective = G1Projective::from(vk.c0) + f2 + f3;
    f.into()
}

fn compute_e_point(ch: &Challenges, r0: Fr, r1: Fr, r2: Fr) -> G1Affine {
    let e2 = r1 * ch.quotient1;
    let e3 = r2 * ch.quotient2;
    (G1Affine::generator() * (r0 + e2 + e3)).into()
}

fn compute_j_point(proof: &ParsedProof, ch: &Challenges) -> G1Affine {
    (G1Projective::from(proof.w1) * ch.temp).into()
}

fn pairing_check(
    proof: &ParsedProof,
    vk: &VerificationKey,
    ch: &Challenges,
    f: G1Affine,
    e: G1Affine,
    j: G1Affine,
) -> bool {
    // A1 = F - E - J + y·W2
    let a1_proj: G1Projective =
        G1Projective::from(f) - G1Projective::from(e) - G1Projective::from(j)
            + G1Projective::from(proof.w2) * ch.y;
    let a1: G1Affine = a1_proj.into();
    let a2 = G2Affine::generator();
    let b1 = proof.w2;
    let b2 = vk.x_2;

    // Pairing eq: e(-A1, A2) · e(B1, B2) = 1.
    let lhs = Bn254::pairing(-a1, a2);
    let rhs = Bn254::pairing(b1, b2);
    (lhs.0 * rhs.0).is_one()
}

/// Verify an FFLONK proof. Returns `Ok(true)` on accept, `Ok(false)` on reject,
/// `Err(_)` on malformed inputs.
pub fn verify(
    vkey_json: &[u8],
    public_json: &[u8],
    proof_json: &[u8],
) -> Result<bool, VerifyError> {
    let vk = parse_vkey(vkey_json)?;
    let public = parse_public(public_json)?;
    let proof = parse_proof(proof_json)?;

    if public.len() != vk.n_public as usize {
        return Err(VerifyError::WrongPublicCount {
            got: public.len(),
            want: vk.n_public as usize,
        });
    }

    // Step 1: commitments on curve (already checked by `g1_from_triple`).
    if !proof.c1.is_on_curve()
        || !proof.c2.is_on_curve()
        || !proof.w1.is_on_curve()
        || !proof.w2.is_on_curve()
        || !vk.c0.is_on_curve()
    {
        return Ok(false);
    }

    let (ch, roots) = compute_challenges(&proof, &vk, &public);
    let lagrange_evals = lagrange_public(&public, &ch, &vk);
    let lagrange1 = lagrange_1_at_xi(&ch, &vk);
    let pi = pi_at_xi(&public, &lagrange_evals);

    let r0 = compute_r0(&proof, &ch, &roots);
    let r1 = compute_r1(&proof, &ch, &roots, pi);
    let r2 = compute_r2(&proof, &ch, &roots, lagrange1, &vk);

    let f = compute_f_point(&proof, &vk, &ch);
    let e = compute_e_point(&ch, r0, r1, r2);
    let j = compute_j_point(&proof, &ch);

    Ok(pairing_check(&proof, &vk, &ch, f, e, j))
}

/// Convenience: verify directly from file paths.
pub fn verify_paths(
    vkey_path: &std::path::Path,
    public_path: &std::path::Path,
    proof_path: &std::path::Path,
) -> Result<bool, VerifyError> {
    let vk = std::fs::read(vkey_path)?;
    let pb = std::fs::read(public_path)?;
    let pr = std::fs::read(proof_path)?;
    verify(&vk, &pb, &pr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_multiplier_reference_proof() {
        let vk = std::fs::read("tests/fixtures/multiplier/vkey.json").unwrap();
        let public = std::fs::read("tests/fixtures/multiplier/reference_public.json").unwrap();
        let proof = std::fs::read("tests/fixtures/multiplier/reference_proof.json").unwrap();
        let ok = verify(&vk, &public, &proof).unwrap();
        assert!(ok, "multiplier reference proof must verify");
    }

    #[test]
    fn verifies_poseidon_reference_proof() {
        let vk = std::fs::read("tests/fixtures/poseidon/vkey.json").unwrap();
        let public = std::fs::read("tests/fixtures/poseidon/reference_public.json").unwrap();
        let proof = std::fs::read("tests/fixtures/poseidon/reference_proof.json").unwrap();
        let ok = verify(&vk, &public, &proof).unwrap();
        assert!(ok, "poseidon reference proof must verify");
    }

    #[test]
    fn rejects_tampered_multiplier_proof() {
        let vk = std::fs::read("tests/fixtures/multiplier/vkey.json").unwrap();
        let public = std::fs::read("tests/fixtures/multiplier/reference_public.json").unwrap();
        let mut proof_json: serde_json::Value = serde_json::from_slice(
            &std::fs::read("tests/fixtures/multiplier/reference_proof.json").unwrap(),
        )
        .unwrap();
        // Flip evaluations.a to a different value.
        proof_json["evaluations"]["a"] = serde_json::Value::String("42".to_string());
        let tampered = serde_json::to_vec(&proof_json).unwrap();
        let ok = verify(&vk, &public, &tampered).unwrap();
        assert!(!ok, "tampered proof must be rejected");
    }

    #[test]
    fn rejects_multiplier_with_wrong_public_inputs() {
        let vk = std::fs::read("tests/fixtures/multiplier/vkey.json").unwrap();
        let proof = std::fs::read("tests/fixtures/multiplier/reference_proof.json").unwrap();
        // Legitimate public is "33"; substitute "34" to simulate wrong inputs.
        let bad_public = b"[\"34\"]";
        let ok = verify(&vk, bad_public, &proof).unwrap();
        assert!(!ok, "wrong public input must be rejected");
    }
}
