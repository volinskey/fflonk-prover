//! snarkjs-format FFLONK verification key (`vkey.json`) parser.
//!
//! JSON shape (matches `tests/fixtures/*/vkey.json`):
//! ```json
//! {
//!   "protocol": "fflonk",
//!   "curve": "bn128",
//!   "nPublic": 1,
//!   "power": 3,
//!   "k1": "2", "k2": "3",
//!   "w": "...", "w3": "...", "w4": "...", "w8": "...", "wr": "...",
//!   "X_2": [[..., ...], [..., ...], ["1", "0"]],
//!   "C0":  [x, y, "1"]
//! }
//! ```

use std::str::FromStr;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VkeyError {
    #[error("json parse: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not fflonk: protocol={protocol}")]
    WrongProtocol { protocol: String },
    #[error("not bn128: curve={curve}")]
    WrongCurve { curve: String },
    #[error("invalid Fr decimal: {0}")]
    BadFr(String),
    #[error("invalid Fq decimal: {0}")]
    BadFq(String),
}

#[derive(Debug, Deserialize)]
struct RawVkey {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    n_public: u32,
    power: u32,
    k1: String,
    k2: String,
    w: String,
    w3: String,
    w4: String,
    w8: String,
    wr: String,
    #[serde(rename = "X_2")]
    x_2: [[String; 2]; 3],
    #[serde(rename = "C0")]
    c0: [String; 3],
}

/// Parsed FFLONK verification key.
#[derive(Debug, Clone)]
pub struct VerificationKey {
    pub n_public: u32,
    pub power: u32,
    pub domain_size: u32,
    pub k1: Fr,
    pub k2: Fr,
    pub w: Fr,
    pub w3: Fr,
    pub w4: Fr,
    pub w8: Fr,
    pub wr: Fr,
    pub x_2: G2Affine,
    pub c0: G1Affine,
}

fn fr_from_decimal(s: &str) -> Result<Fr, VkeyError> {
    Fr::from_str(s).map_err(|_| VkeyError::BadFr(s.to_owned()))
}
fn fq_from_decimal(s: &str) -> Result<Fq, VkeyError> {
    Fq::from_str(s).map_err(|_| VkeyError::BadFq(s.to_owned()))
}

pub fn parse_vkey(json: &[u8]) -> Result<VerificationKey, VkeyError> {
    let raw: RawVkey = serde_json::from_slice(json)?;
    if raw.protocol != "fflonk" {
        return Err(VkeyError::WrongProtocol {
            protocol: raw.protocol,
        });
    }
    if raw.curve != "bn128" {
        return Err(VkeyError::WrongCurve { curve: raw.curve });
    }
    let k1 = fr_from_decimal(&raw.k1)?;
    let k2 = fr_from_decimal(&raw.k2)?;
    let w = fr_from_decimal(&raw.w)?;
    let w3 = fr_from_decimal(&raw.w3)?;
    let w4 = fr_from_decimal(&raw.w4)?;
    let w8 = fr_from_decimal(&raw.w8)?;
    let wr = fr_from_decimal(&raw.wr)?;

    // X_2 is [[x.c0, x.c1], [y.c0, y.c1], [1, 0]] — we ignore the z row.
    let x2_x = Fq2::new(
        fq_from_decimal(&raw.x_2[0][0])?,
        fq_from_decimal(&raw.x_2[0][1])?,
    );
    let x2_y = Fq2::new(
        fq_from_decimal(&raw.x_2[1][0])?,
        fq_from_decimal(&raw.x_2[1][1])?,
    );
    let x_2 = G2Affine::new_unchecked(x2_x, x2_y);

    // C0 is [x, y, "1"] — ignore z.
    let c0 = G1Affine::new_unchecked(fq_from_decimal(&raw.c0[0])?, fq_from_decimal(&raw.c0[1])?);

    let domain_size = 1u32 << raw.power;

    Ok(VerificationKey {
        n_public: raw.n_public,
        power: raw.power,
        domain_size,
        k1,
        k2,
        w,
        w3,
        w4,
        w8,
        wr,
        x_2,
        c0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiplier_vkey() {
        let json = std::fs::read("tests/fixtures/multiplier/vkey.json").unwrap();
        let vk = parse_vkey(&json).unwrap();
        assert_eq!(vk.n_public, 1);
        assert_eq!(vk.power, 3);
        assert_eq!(vk.domain_size, 8);
    }

    #[test]
    fn parses_poseidon_vkey() {
        let json = std::fs::read("tests/fixtures/poseidon/vkey.json").unwrap();
        let vk = parse_vkey(&json).unwrap();
        assert_eq!(vk.n_public, 1);
        assert_eq!(vk.domain_size, 65536, "poseidon power=16 → 2^16 = 65536");
    }
}
