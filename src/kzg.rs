//! KZG polynomial commitments over BN254.
//!
//! Given a polynomial `P(X) = c_0 + c_1·X + ... + c_{n-1}·X^{n-1}` and an SRS
//! `[G1_0, G1_1, ..., G1_{m-1}]` where `G1_i = [τ^i] · G1` (points from the
//! powers-of-tau trusted setup), the KZG commitment is
//!
//!   `commit(P) = Σ c_i · G1_i`
//!
//! which is a multi-scalar multiplication (MSM). We require `srs.len() ≥ coeffs.len()`.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::VariableBaseMSM;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KzgError {
    #[error("srs has {srs} points but polynomial has {coeffs} coefficients (need srs ≥ coeffs)")]
    SrsTooSmall { srs: usize, coeffs: usize },
}

/// Compute the KZG commitment `[P(τ)] · G1` as a MSM.
pub fn commit(coeffs: &[Fr], srs: &[G1Affine]) -> Result<G1Affine, KzgError> {
    if srs.len() < coeffs.len() {
        return Err(KzgError::SrsTooSmall {
            srs: srs.len(),
            coeffs: coeffs.len(),
        });
    }
    let bases = &srs[..coeffs.len()];
    let proj: G1Projective = VariableBaseMSM::msm_unchecked(bases, coeffs);
    Ok(proj.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkey::{
        read_fflonk_header, read_fr_section, read_g1_section, SECTION_C0, SECTION_PTAU,
    };
    use ark_ff::PrimeField;

    const MULT_ZKEY: &str = "tests/fixtures/multiplier/circuit.zkey";

    /// The FFLONK vkey contains a precomputed commitment `C0` to the merged
    /// preprocessed polynomial. The zkey stores both the SRS (section 16) and
    /// the C0 polynomial in coefficient form (section 17). Our KZG commit of
    /// the poly against the SRS must reproduce C0 byte-for-byte.
    #[test]
    fn reproduces_multiplier_c0_from_zkey_srs_and_c0_coeffs() {
        let bytes = std::fs::read(MULT_ZKEY).unwrap();
        let srs = read_g1_section(&bytes, SECTION_PTAU).expect("read PTau");
        let coeffs = read_fr_section(&bytes, SECTION_C0).expect("read C0 coeffs");
        let commitment = commit(&coeffs, &srs).expect("msm");
        let header = read_fflonk_header(&bytes).expect("fflonk header");
        assert_eq!(
            commitment.x.into_bigint().to_string(),
            header.c0_x_decimal(),
            "C0.x must match vkey"
        );
        assert_eq!(
            commitment.y.into_bigint().to_string(),
            header.c0_y_decimal(),
            "C0.y must match vkey"
        );
    }

    #[test]
    fn rejects_srs_shorter_than_poly() {
        let coeffs = vec![Fr::from(1u64); 10];
        let srs: Vec<G1Affine> = vec![];
        assert!(matches!(
            commit(&coeffs, &srs),
            Err(KzgError::SrsTooSmall { .. })
        ));
    }
}
