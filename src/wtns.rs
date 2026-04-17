//! Circom `.wtns` (witness) reader.
//!
//! Format (little-endian):
//! - Magic: `b"wtns"` (4 bytes)
//! - Version: u32 (we support 2)
//! - nSections: u32 (always 2: header + data)
//! - Section 1 header: n8 (u32) + q (n8 bytes, field modulus) + nWitness (u32)
//! - Section 2 data: nWitness × n8 bytes, each a scalar in **canonical** LE form
//!   (NOT Montgomery — witnesses are logical values, not field-arithmetic intermediates).

use std::path::Path;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use thiserror::Error;

pub const WTNS_MAGIC: &[u8; 4] = b"wtns";
pub const WTNS_VERSION: u32 = 2;

#[derive(Debug, Error)]
pub enum WtnsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("file too small: expected at least {expected} bytes, got {actual}")]
    FileTooSmall { expected: usize, actual: usize },

    #[error("bad magic: expected 'wtns', got {0:?}")]
    BadMagic([u8; 4]),

    #[error("unsupported wtns version: {0} (expected {1})")]
    UnsupportedVersion(u32, u32),

    #[error("only BN254 is supported — got n8={0}")]
    UnsupportedCurve(u32),

    #[error("witness data size {data_size} != nWitness({n}) × n8({n8})")]
    BadDataSize { data_size: u64, n: u32, n8: u32 },
}

#[derive(Debug, Clone)]
pub struct Witness {
    pub values: Vec<Fr>,
}

impl Witness {
    pub fn len(&self) -> usize {
        self.values.len()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

pub fn read(bytes: &[u8]) -> Result<Witness, WtnsError> {
    if bytes.len() < 12 {
        return Err(WtnsError::FileTooSmall {
            expected: 12,
            actual: bytes.len(),
        });
    }
    let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
    if &magic != WTNS_MAGIC {
        return Err(WtnsError::BadMagic(magic));
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != WTNS_VERSION {
        return Err(WtnsError::UnsupportedVersion(version, WTNS_VERSION));
    }
    // nSections (bytes 8..12) — we don't use it; format always has two.

    // Section 1 (header): type=1, size=?
    let mut c = 12usize;
    let s1_type = u32::from_le_bytes(bytes[c..c + 4].try_into().unwrap());
    c += 4;
    let s1_size = u64::from_le_bytes(bytes[c..c + 8].try_into().unwrap()) as usize;
    c += 8;
    assert_eq!(s1_type, 1, "wtns section 1 must be type 1");
    let s1_end = c + s1_size;

    let n8 = u32::from_le_bytes(bytes[c..c + 4].try_into().unwrap());
    c += 4;
    if n8 != 32 {
        return Err(WtnsError::UnsupportedCurve(n8));
    }
    c += n8 as usize; // skip q (we trust BN254 constants in arkworks)
    let n_witness = u32::from_le_bytes(bytes[c..c + 4].try_into().unwrap());
    c = s1_end;

    // Section 2 (data): type=2, size = n_witness × n8
    let s2_type = u32::from_le_bytes(bytes[c..c + 4].try_into().unwrap());
    c += 4;
    let s2_size = u64::from_le_bytes(bytes[c..c + 8].try_into().unwrap());
    c += 8;
    assert_eq!(s2_type, 2, "wtns section 2 must be type 2");
    if s2_size != (n_witness as u64) * (n8 as u64) {
        return Err(WtnsError::BadDataSize {
            data_size: s2_size,
            n: n_witness,
            n8,
        });
    }

    let mut values = Vec::with_capacity(n_witness as usize);
    for _ in 0..n_witness {
        let slice = &bytes[c..c + n8 as usize];
        values.push(Fr::from_le_bytes_mod_order(slice));
        c += n8 as usize;
    }

    Ok(Witness { values })
}

pub fn read_from_path(path: &Path) -> Result<Witness, WtnsError> {
    let bytes = std::fs::read(path)?;
    read(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULT_WTNS: &str = "tests/fixtures/multiplier/witness.wtns";

    fn load() -> Vec<u8> {
        std::fs::read(MULT_WTNS).unwrap()
    }

    #[test]
    fn multiplier_witness_has_four_values() {
        let w = read(&load()).unwrap();
        assert_eq!(w.len(), 4);
    }

    #[test]
    fn multiplier_witness_values_are_one_thirtythree_three_eleven() {
        let w = read(&load()).unwrap();
        let decimals: Vec<String> = w
            .values
            .iter()
            .map(|fr| fr.into_bigint().to_string())
            .collect();
        assert_eq!(decimals, vec!["1", "33", "3", "11"]);
    }

    #[test]
    fn rejects_bad_magic() {
        // Need ≥12 bytes (magic + version + nSections) to pass the size check and reach the magic check.
        let bytes = b"wxyz\x02\x00\x00\x00\x02\x00\x00\x00".to_vec();
        assert!(matches!(read(&bytes), Err(WtnsError::BadMagic(_))));
    }

    #[test]
    fn rejects_bad_version() {
        let bytes = b"wtns\x09\x00\x00\x00\x02\x00\x00\x00".to_vec();
        assert!(matches!(
            read(&bytes),
            Err(WtnsError::UnsupportedVersion(9, 2))
        ));
    }

    #[test]
    fn rejects_truncated_file() {
        let bytes = b"wtns".to_vec();
        assert!(matches!(read(&bytes), Err(WtnsError::FileTooSmall { .. })));
    }

    #[test]
    fn rejects_non_bn254_curve() {
        // Construct a wtns header claiming n8 = 48 (BLS12-381).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"wtns");
        bytes.extend_from_slice(&2u32.to_le_bytes()); // version
        bytes.extend_from_slice(&2u32.to_le_bytes()); // nSections
        bytes.extend_from_slice(&1u32.to_le_bytes()); // section 1 type
        bytes.extend_from_slice(&56u64.to_le_bytes()); // section 1 size (n8 + 48 bytes q + nWitness = 4 + 48 + 4 = 56)
        bytes.extend_from_slice(&48u32.to_le_bytes()); // n8 = 48 (not 32)
        bytes.extend_from_slice(&[0u8; 48]); // q placeholder
        bytes.extend_from_slice(&0u32.to_le_bytes()); // nWitness
        bytes.extend_from_slice(&2u32.to_le_bytes()); // section 2 type
        bytes.extend_from_slice(&0u64.to_le_bytes()); // section 2 size
        assert!(matches!(read(&bytes), Err(WtnsError::UnsupportedCurve(48))));
    }
}
