//! Snarkjs-compatible proof serialization.
//!
//! The FFLONK proof JSON has this shape (matches `reference_proof.json`):
//! ```json
//! {
//!   "polynomials": {
//!     "C1": [x, y, "1"],
//!     "C2": [x, y, "1"],
//!     "W1": [x, y, "1"],
//!     "W2": [x, y, "1"]
//!   },
//!   "evaluations": {
//!     "ql": "...", "qr": "...", "qm": "...", "qo": "...", "qc": "...",
//!     "s1": "...", "s2": "...", "s3": "...",
//!     "a": "...",  "b": "...",  "c": "...",
//!     "z": "...",  "zw": "...",
//!     "t1w": "...", "t2w": "...",
//!     "inv": "..."
//!   },
//!   "protocol": "fflonk",
//!   "curve": "bn128"
//! }
//! ```
//! All scalars are decimal strings, all G1 points are `[x, y, "1"]` decimal
//! triples (Jacobian with z=1, equivalent to affine).
//!
//! Public signals go in a separate `public.json` as a JSON array of decimal
//! strings.

use ark_bn254::{Fr, G1Affine};
use ark_ff::PrimeField;
use serde::Serialize;

use crate::prover::{Round1Output, Round2Output, Round3Evaluations, Round4Output, Round5Output};

#[derive(Debug, Serialize)]
pub struct Polynomials {
    #[serde(rename = "C1")]
    pub c1: [String; 3],
    #[serde(rename = "C2")]
    pub c2: [String; 3],
    #[serde(rename = "W1")]
    pub w1: [String; 3],
    #[serde(rename = "W2")]
    pub w2: [String; 3],
}

#[derive(Debug, Serialize)]
pub struct Evaluations {
    pub ql: String,
    pub qr: String,
    pub qm: String,
    pub qo: String,
    pub qc: String,
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub a: String,
    pub b: String,
    pub c: String,
    pub z: String,
    pub zw: String,
    pub t1w: String,
    pub t2w: String,
    pub inv: String,
}

#[derive(Debug, Serialize)]
pub struct Proof {
    pub polynomials: Polynomials,
    pub evaluations: Evaluations,
    pub protocol: &'static str,
    pub curve: &'static str,
}

fn fr_dec(x: &Fr) -> String {
    x.into_bigint().to_string()
}

fn g1_triple(p: &G1Affine) -> [String; 3] {
    [
        p.x.into_bigint().to_string(),
        p.y.into_bigint().to_string(),
        "1".to_string(),
    ]
}

/// Assemble a snarkjs-compatible proof struct from the five round outputs.
pub fn build_proof(
    r1: &Round1Output,
    r2: &Round2Output,
    r3: &Round3Evaluations,
    r4: &Round4Output,
    r5: &Round5Output,
) -> Proof {
    Proof {
        polynomials: Polynomials {
            c1: g1_triple(&r1.c1_commitment),
            c2: g1_triple(&r2.c2_commitment),
            w1: g1_triple(&r4.w1_commitment),
            w2: g1_triple(&r5.w2_commitment),
        },
        evaluations: Evaluations {
            ql: fr_dec(&r3.ql),
            qr: fr_dec(&r3.qr),
            qm: fr_dec(&r3.qm),
            qo: fr_dec(&r3.qo),
            qc: fr_dec(&r3.qc),
            s1: fr_dec(&r3.s1),
            s2: fr_dec(&r3.s2),
            s3: fr_dec(&r3.s3),
            a: fr_dec(&r3.a),
            b: fr_dec(&r3.b),
            c: fr_dec(&r3.c),
            z: fr_dec(&r3.z),
            zw: fr_dec(&r3.zw),
            t1w: fr_dec(&r3.t1w),
            t2w: fr_dec(&r3.t2w),
            inv: fr_dec(&r5.inv),
        },
        protocol: "fflonk",
        curve: "bn128",
    }
}

/// Serialize the public signals buffer (witness[1..=n_public]) to the snarkjs
/// `public.json` format — a JSON array of decimal strings.
pub fn public_signals_json(public_inputs: &[Fr]) -> String {
    let strs: Vec<String> = public_inputs.iter().map(fr_dec).collect();
    serde_json::to_string_pretty(&strs).unwrap()
}
