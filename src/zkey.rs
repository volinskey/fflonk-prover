//! FFLONK zkey (proving key) reader.
//!
//! Parses snarkjs 0.7.6 FFLONK zkey binary files.
//!
//! Format (little-endian):
//! - Global header: `b"zkey"` magic (4 bytes), version (u32), nSections (u32)
//! - For each section: sectionType (u32), sectionSize (u64), data (sectionSize bytes)
//!
//! Sections may appear in any order. Section IDs are not sequential in the file.
//!
//! Field elements (Fr, Fq) are written in Montgomery form, little-endian. This
//! matches arkworks' internal representation, so `Fp::new_unchecked(BigInt(..))`
//! is the zero-cost bridge.

use std::path::Path;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInt, Fp, PrimeField};
use thiserror::Error;

pub const ZKEY_MAGIC: &[u8; 4] = b"zkey";
pub const ZKEY_VERSION: u32 = 1;

/// Snarkjs protocol identifiers (appear as u32 in zkey section 1).
pub const PROTOCOL_GROTH16: u32 = 1;
pub const PROTOCOL_PLONK: u32 = 2;
pub const PROTOCOL_FFLONK: u32 = 10;

#[derive(Debug, Error)]
pub enum ZkeyError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("file too small: expected at least {expected} bytes, got {actual}")]
    FileTooSmall { expected: usize, actual: usize },

    #[error("bad magic: expected 'zkey', got {0:?}")]
    BadMagic([u8; 4]),

    #[error("unsupported zkey version: {0} (expected {1})")]
    UnsupportedVersion(u32, u32),

    #[error("section size {size} exceeds remaining file bytes {remaining}")]
    SectionTooLarge { size: u64, remaining: u64 },

    #[error("FFLONK header section (type 2) not found in zkey")]
    NoFflonkHeader,

    #[error("FFLONK header size {size} does not match expected {expected}")]
    BadFflonkHeaderSize { size: u64, expected: u64 },

    #[error("only BN254 is supported — got n8q={n8q}, n8r={n8r}")]
    UnsupportedCurve { n8q: u32, n8r: u32 },

    #[error("section type {section_type} not found in zkey")]
    SectionNotFound { section_type: u32 },

    #[error("section {section_type} size {size} is not a multiple of 32 (Fr byte width)")]
    SectionNotFrAligned { section_type: u32, size: u64 },
}

/// Global header of a zkey file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkeyHeader {
    pub version: u32,
    pub n_sections: u32,
}

/// Parses the global zkey header from the first 12 bytes of the file.
pub fn read_header(bytes: &[u8]) -> Result<ZkeyHeader, ZkeyError> {
    if bytes.len() < 12 {
        return Err(ZkeyError::FileTooSmall {
            expected: 12,
            actual: bytes.len(),
        });
    }
    let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
    if &magic != ZKEY_MAGIC {
        return Err(ZkeyError::BadMagic(magic));
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != ZKEY_VERSION {
        return Err(ZkeyError::UnsupportedVersion(version, ZKEY_VERSION));
    }
    let n_sections = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    Ok(ZkeyHeader {
        version,
        n_sections,
    })
}

/// Convenience wrapper: read entire zkey file into memory and parse the header.
pub fn read_header_from_path(path: &Path) -> Result<ZkeyHeader, ZkeyError> {
    let bytes = std::fs::read(path)?;
    read_header(&bytes)
}

/// Raw section metadata (type + size + offset into file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionMeta {
    pub section_type: u32,
    pub size: u64,
    /// Offset into the zkey file where the section's data begins (just after
    /// the 12-byte section header holding `section_type` + `size`).
    pub data_offset: u64,
}

/// Section IDs for FFLONK zkey (snarkjs 0.7.6).
pub const SECTION_PROTOCOL_HEADER: u32 = 1;
pub const SECTION_FFLONK_HEADER: u32 = 2;
pub const SECTION_ADDITIONS: u32 = 3;
pub const SECTION_A_MAP: u32 = 4;
pub const SECTION_B_MAP: u32 = 5;
pub const SECTION_C_MAP: u32 = 6;
pub const SECTION_QL: u32 = 7;
pub const SECTION_QR: u32 = 8;
pub const SECTION_QM: u32 = 9;
pub const SECTION_QO: u32 = 10;
pub const SECTION_QC: u32 = 11;
pub const SECTION_SIGMA1: u32 = 12;
pub const SECTION_SIGMA2: u32 = 13;
pub const SECTION_SIGMA3: u32 = 14;
pub const SECTION_LAGRANGE: u32 = 15;
pub const SECTION_PTAU: u32 = 16;
pub const SECTION_C0: u32 = 17;

/// Parsed FFLONK header (zkey section type 2).
#[derive(Debug, Clone)]
pub struct FflonkHeader {
    pub n_vars: u32,
    pub n_public: u32,
    pub domain_size: u32,
    pub n_additions: u32,
    pub n_constraints: u32,
    pub k1: Fr,
    pub k2: Fr,
    pub w3: Fr,
    pub w4: Fr,
    pub w8: Fr,
    pub wr: Fr,
    pub x2: G2Affine,
    pub c0: G1Affine,
}

impl FflonkHeader {
    pub fn k1_decimal(&self) -> String {
        self.k1.into_bigint().to_string()
    }
    pub fn k2_decimal(&self) -> String {
        self.k2.into_bigint().to_string()
    }
    pub fn w3_decimal(&self) -> String {
        self.w3.into_bigint().to_string()
    }
    pub fn w4_decimal(&self) -> String {
        self.w4.into_bigint().to_string()
    }
    pub fn w8_decimal(&self) -> String {
        self.w8.into_bigint().to_string()
    }
    pub fn wr_decimal(&self) -> String {
        self.wr.into_bigint().to_string()
    }
    pub fn c0_x_decimal(&self) -> String {
        self.c0.x.into_bigint().to_string()
    }
    pub fn c0_y_decimal(&self) -> String {
        self.c0.y.into_bigint().to_string()
    }
    /// G2 as [x.c0, x.c1, y.c0, y.c1] — matches snarkjs vkey's flattened Fp2 ordering.
    pub fn x2_decimal(&self) -> [String; 4] {
        [
            self.x2.x.c0.into_bigint().to_string(),
            self.x2.x.c1.into_bigint().to_string(),
            self.x2.y.c0.into_bigint().to_string(),
            self.x2.y.c1.into_bigint().to_string(),
        ]
    }
}

/// Reads a 32-byte Fr from Montgomery-form LE bytes (snarkjs on-disk format).
fn fr_from_mont_le(bytes: &[u8]) -> Fr {
    assert_eq!(bytes.len(), 32);
    let limbs = [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ];
    Fp::new_unchecked(BigInt(limbs))
}

/// Reads a 32-byte Fq from Montgomery-form LE bytes.
fn fq_from_mont_le(bytes: &[u8]) -> Fq {
    assert_eq!(bytes.len(), 32);
    let limbs = [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ];
    Fp::new_unchecked(BigInt(limbs))
}

/// Parses the FFLONK header (section type 2) from the zkey.
pub fn read_fflonk_header(bytes: &[u8]) -> Result<FflonkHeader, ZkeyError> {
    let metas = section_metas(bytes)?;
    let meta = metas
        .iter()
        .find(|m| m.section_type == SECTION_FFLONK_HEADER)
        .ok_or(ZkeyError::NoFflonkHeader)?;

    // Expected layout for BN254 (n8q=n8r=32):
    //   4   n8q
    //   32  q
    //   4   n8r
    //   32  r
    //   4   nVars
    //   4   nPublic
    //   4   domainSize
    //   4   nAdditions
    //   4   nConstraints
    //   32  k1
    //   32  k2
    //   32  w3
    //   32  w4
    //   32  w8
    //   32  wr
    //   128 X_2   (Fq2 x || Fq2 y, each Fq2 = 2 × 32 bytes)
    //   64  C0    (Fq x || Fq y)
    //   Total: 476 bytes
    const EXPECTED: u64 = 4 + 32 + 4 + 32 + 4 + 4 + 4 + 4 + 4 + 32 * 6 + 128 + 64;
    if meta.size != EXPECTED {
        return Err(ZkeyError::BadFflonkHeaderSize {
            size: meta.size,
            expected: EXPECTED,
        });
    }

    let start = meta.data_offset as usize;
    let mut c = start;
    let read_u32 = |pos: usize| u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());

    let n8q = read_u32(c);
    c += 4;
    if n8q != 32 {
        return Err(ZkeyError::UnsupportedCurve { n8q, n8r: 0 });
    }
    // Skip q (field modulus) — we assume BN254 and rely on arkworks' compiled-in constants.
    c += 32;
    let n8r = read_u32(c);
    c += 4;
    if n8r != 32 {
        return Err(ZkeyError::UnsupportedCurve { n8q, n8r });
    }
    c += 32; // skip r

    let n_vars = read_u32(c);
    c += 4;
    let n_public = read_u32(c);
    c += 4;
    let domain_size = read_u32(c);
    c += 4;
    let n_additions = read_u32(c);
    c += 4;
    let n_constraints = read_u32(c);
    c += 4;

    let k1 = fr_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let k2 = fr_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let w3 = fr_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let w4 = fr_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let w8 = fr_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let wr = fr_from_mont_le(&bytes[c..c + 32]);
    c += 32;

    // X_2: G2 point in affine form. snarkjs stores as (x.c0, x.c1, y.c0, y.c1).
    let x2_x_c0 = fq_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let x2_x_c1 = fq_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let x2_y_c0 = fq_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let x2_y_c1 = fq_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let x2 = G2Affine::new_unchecked(Fq2::new(x2_x_c0, x2_x_c1), Fq2::new(x2_y_c0, x2_y_c1));

    // C0: G1 point in affine form (x, y).
    let c0_x = fq_from_mont_le(&bytes[c..c + 32]);
    c += 32;
    let c0_y = fq_from_mont_le(&bytes[c..c + 32]);
    let c0 = G1Affine::new_unchecked(c0_x, c0_y);

    Ok(FflonkHeader {
        n_vars,
        n_public,
        domain_size,
        n_additions,
        n_constraints,
        k1,
        k2,
        w3,
        w4,
        w8,
        wr,
        x2,
        c0,
    })
}

/// Reads every u32 entry from a section. Used for A_map/B_map/C_map sections:
/// each entry is a witness index telling which witness wire feeds into the
/// A / B / C column at constraint row i.
pub fn read_u32_section(bytes: &[u8], section_type: u32) -> Result<Vec<u32>, ZkeyError> {
    let metas = section_metas(bytes)?;
    let meta = metas
        .iter()
        .find(|m| m.section_type == section_type)
        .ok_or(ZkeyError::SectionNotFound { section_type })?;
    if meta.size % 4 != 0 {
        return Err(ZkeyError::SectionNotFrAligned {
            section_type,
            size: meta.size,
        });
    }
    let n = (meta.size / 4) as usize;
    let mut out = Vec::with_capacity(n);
    let mut c = meta.data_offset as usize;
    for _ in 0..n {
        out.push(u32::from_le_bytes(bytes[c..c + 4].try_into().unwrap()));
        c += 4;
    }
    Ok(out)
}

/// Reads every G1 point from a section (each 64 bytes = 2 × 32-byte Fq coords,
/// uncompressed affine, Montgomery-LE). Used for the PTau SRS section (type 16).
pub fn read_g1_section(bytes: &[u8], section_type: u32) -> Result<Vec<G1Affine>, ZkeyError> {
    let metas = section_metas(bytes)?;
    let meta = metas
        .iter()
        .find(|m| m.section_type == section_type)
        .ok_or(ZkeyError::SectionNotFound { section_type })?;
    if meta.size % 64 != 0 {
        return Err(ZkeyError::SectionNotFrAligned {
            section_type,
            size: meta.size,
        });
    }
    let n = (meta.size / 64) as usize;
    let mut out = Vec::with_capacity(n);
    let mut c = meta.data_offset as usize;
    for _ in 0..n {
        let x = fq_from_mont_le(&bytes[c..c + 32]);
        let y = fq_from_mont_le(&bytes[c + 32..c + 64]);
        out.push(G1Affine::new_unchecked(x, y));
        c += 64;
    }
    Ok(out)
}

/// Reads every Fr coefficient from a section (each 32 bytes, Montgomery-LE).
/// Used for Q_L..Q_C, sigma1..sigma3, C0, Lagrange, etc.
pub fn read_fr_section(bytes: &[u8], section_type: u32) -> Result<Vec<Fr>, ZkeyError> {
    let metas = section_metas(bytes)?;
    let meta = metas
        .iter()
        .find(|m| m.section_type == section_type)
        .ok_or(ZkeyError::SectionNotFound { section_type })?;
    if meta.size % 32 != 0 {
        return Err(ZkeyError::SectionNotFrAligned {
            section_type,
            size: meta.size,
        });
    }
    let n = (meta.size / 32) as usize;
    let mut out = Vec::with_capacity(n);
    let mut c = meta.data_offset as usize;
    for _ in 0..n {
        out.push(fr_from_mont_le(&bytes[c..c + 32]));
        c += 32;
    }
    Ok(out)
}

/// Walks the zkey file and returns metadata for every section in file order.
pub fn section_metas(bytes: &[u8]) -> Result<Vec<SectionMeta>, ZkeyError> {
    let header = read_header(bytes)?;
    let mut metas = Vec::with_capacity(header.n_sections as usize);
    let mut cursor: u64 = 12;
    let total = bytes.len() as u64;
    for _ in 0..header.n_sections {
        if cursor + 12 > total {
            return Err(ZkeyError::FileTooSmall {
                expected: (cursor + 12) as usize,
                actual: bytes.len(),
            });
        }
        let ty_bytes: [u8; 4] = bytes[cursor as usize..(cursor + 4) as usize]
            .try_into()
            .unwrap();
        let size_bytes: [u8; 8] = bytes[(cursor + 4) as usize..(cursor + 12) as usize]
            .try_into()
            .unwrap();
        let section_type = u32::from_le_bytes(ty_bytes);
        let size = u64::from_le_bytes(size_bytes);
        let data_offset = cursor + 12;
        let remaining = total.saturating_sub(data_offset);
        if size > remaining {
            return Err(ZkeyError::SectionTooLarge { size, remaining });
        }
        metas.push(SectionMeta {
            section_type,
            size,
            data_offset,
        });
        cursor = data_offset + size;
    }
    Ok(metas)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTIPLIER_ZKEY_PATH: &str = "tests/fixtures/multiplier/circuit.zkey";

    fn load_multiplier() -> Vec<u8> {
        std::fs::read(MULTIPLIER_ZKEY_PATH)
            .unwrap_or_else(|e| panic!("load {MULTIPLIER_ZKEY_PATH}: {e}"))
    }

    #[test]
    fn parses_multiplier_global_header() {
        let bytes = load_multiplier();
        let header = read_header(&bytes).expect("parse header");
        assert_eq!(header.version, 1);
        // Empirically, snarkjs fflonk setup emits 17 sections.
        assert_eq!(header.n_sections, 17);
    }

    #[test]
    fn rejects_file_without_magic() {
        let bytes = b"xxxx\x01\x00\x00\x00\x01\x00\x00\x00".to_vec();
        let err = read_header(&bytes).unwrap_err();
        assert!(matches!(err, ZkeyError::BadMagic(_)));
    }

    #[test]
    fn rejects_truncated_file() {
        let bytes = b"zkey\x01\x00\x00".to_vec();
        let err = read_header(&bytes).unwrap_err();
        assert!(matches!(err, ZkeyError::FileTooSmall { .. }));
    }

    #[test]
    fn rejects_bad_version() {
        let bytes = b"zkey\x99\x00\x00\x00\x01\x00\x00\x00".to_vec();
        let err = read_header(&bytes).unwrap_err();
        assert!(matches!(err, ZkeyError::UnsupportedVersion(0x99, 1)));
    }

    // --- Section iterator tests ---

    #[test]
    fn section_metas_enumerates_all_seventeen() {
        let bytes = load_multiplier();
        let metas = section_metas(&bytes).expect("parse sections");
        assert_eq!(metas.len(), 17);
    }

    #[test]
    fn first_section_is_protocol_header_with_fflonk_id() {
        let bytes = load_multiplier();
        let metas = section_metas(&bytes).expect("parse sections");
        let first = metas[0];
        assert_eq!(first.section_type, 1, "protocol header is section type 1");
        assert_eq!(
            first.size, 4,
            "protocol header payload is 4 bytes (protocol id u32)"
        );
        let data_start = first.data_offset as usize;
        let id = u32::from_le_bytes(bytes[data_start..data_start + 4].try_into().unwrap());
        assert_eq!(id, PROTOCOL_FFLONK);
    }

    #[test]
    fn section_data_offsets_do_not_overlap() {
        let bytes = load_multiplier();
        let metas = section_metas(&bytes).expect("parse sections");
        for w in metas.windows(2) {
            let (a, b) = (w[0], w[1]);
            let a_end = a.data_offset + a.size;
            // Next section's header sits right after previous section's data (12-byte gap for next header).
            assert_eq!(b.data_offset, a_end + 12, "sections are contiguous");
        }
    }

    // --- FFLONK header (section type 2) tests ---
    //
    // Reference values come from tests/fixtures/multiplier/vkey.json, which
    // snarkjs produced from the same zkey we're parsing. If our parser reads
    // the zkey correctly, every field here should match the vkey exactly.

    #[test]
    fn fflonk_header_matches_multiplier_vkey_scalars() {
        let bytes = load_multiplier();
        let header = read_fflonk_header(&bytes).expect("parse fflonk header");
        assert_eq!(header.n_public, 1);
        assert_eq!(header.domain_size, 8, "multiplier has power=3 → domain 2^3");
        assert_eq!(header.k1_decimal(), "2");
        assert_eq!(header.k2_decimal(), "3");
    }

    #[test]
    fn fflonk_header_matches_multiplier_vkey_roots() {
        let bytes = load_multiplier();
        let header = read_fflonk_header(&bytes).expect("parse fflonk header");
        assert_eq!(
            header.w3_decimal(),
            "21888242871839275217838484774961031246154997185409878258781734729429964517155"
        );
        assert_eq!(
            header.w4_decimal(),
            "21888242871839275217838484774961031246007050428528088939761107053157389710902"
        );
        assert_eq!(
            header.w8_decimal(),
            "19540430494807482326159819597004422086093766032135589407132600596362845576832"
        );
        assert_eq!(
            header.wr_decimal(),
            "13274704216607947843011480449124596415239537050559949017414504948711435969894"
        );
    }

    #[test]
    fn fflonk_header_matches_multiplier_vkey_c0() {
        let bytes = load_multiplier();
        let header = read_fflonk_header(&bytes).expect("parse fflonk header");
        // vkey: "C0": [x, y, 1]
        assert_eq!(
            header.c0_x_decimal(),
            "11865776073359729040794258160793130354546641422008347334213198060920506239709"
        );
        assert_eq!(
            header.c0_y_decimal(),
            "5524268144136126767933990501392740300548075291727485037030383383698594318676"
        );
    }

    #[test]
    fn fflonk_header_matches_multiplier_vkey_x2() {
        let bytes = load_multiplier();
        let header = read_fflonk_header(&bytes).expect("parse fflonk header");
        // vkey: "X_2": [[x0, x1], [y0, y1], [1, 0]]
        assert_eq!(
            header.x2_decimal(),
            [
                "21831381940315734285607113342023901060522397560371972897001948545212302161822",
                "17231025384763736816414546592865244497437017442647097510447326538965263639101",
                "2388026358213174446665280700919698872609886601280537296205114254867301080648",
                "11507326595632554467052522095592665270651932854513688777769618397986436103170",
            ]
        );
    }

    // --- Preprocessed polynomial section reader tests ---

    #[test]
    fn reads_ql_section_coefficients() {
        let bytes = load_multiplier();
        // Section sizes for Q_L..sigma3 are all 1280 bytes → 40 Fr coeffs (domain_size 8 × 5 for FFLONK fan-in).
        let ql = read_fr_section(&bytes, SECTION_QL).expect("read Q_L");
        assert_eq!(ql.len(), 40);
    }

    #[test]
    fn reads_sigma3_section_coefficients() {
        let bytes = load_multiplier();
        let s3 = read_fr_section(&bytes, SECTION_SIGMA3).expect("read sigma3");
        assert_eq!(s3.len(), 40);
    }

    #[test]
    fn reads_missing_section_returns_error() {
        let bytes = load_multiplier();
        // Section ID 99 doesn't exist.
        let err = read_fr_section(&bytes, 99).unwrap_err();
        assert!(matches!(err, ZkeyError::SectionNotFound { .. }));
    }

    // --- Defensive / malformed-input tests ---

    #[test]
    fn rejects_section_size_overflowing_file() {
        // Build a minimal header claiming 1 section with size 9999 in an 24-byte file.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"zkey");
        bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        bytes.extend_from_slice(&1u32.to_le_bytes()); // nSections = 1
        bytes.extend_from_slice(&1u32.to_le_bytes()); // section type
        bytes.extend_from_slice(&9999u64.to_le_bytes()); // section size
                                                         // No data bytes — size declares 9999 but we only have 0 remaining.
        let err = section_metas(&bytes).unwrap_err();
        assert!(matches!(err, ZkeyError::SectionTooLarge { .. }));
    }

    #[test]
    fn rejects_ncsection_header_pointing_past_eof() {
        // Header says 5 sections but file has bytes for only one section header.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"zkey");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&5u32.to_le_bytes()); // nSections = 5 (lying)
        bytes.extend_from_slice(&1u32.to_le_bytes()); // section 1 type
        bytes.extend_from_slice(&0u64.to_le_bytes()); // section 1 size = 0
                                                      // ...then we claim 4 more sections exist, but no bytes follow.
        let err = section_metas(&bytes).unwrap_err();
        assert!(matches!(err, ZkeyError::FileTooSmall { .. }));
    }

    // --- Witness-map (A_map/B_map/C_map) tests ---

    #[test]
    fn reads_multiplier_wire_maps() {
        let bytes = load_multiplier();
        let a_map = read_u32_section(&bytes, SECTION_A_MAP).expect("A_map");
        let b_map = read_u32_section(&bytes, SECTION_B_MAP).expect("B_map");
        let c_map = read_u32_section(&bytes, SECTION_C_MAP).expect("C_map");
        // Multiplier has 2 constraint rows (one for the gate a*b=c, one for the public input).
        assert_eq!(a_map.len(), 2);
        assert_eq!(b_map.len(), 2);
        assert_eq!(c_map.len(), 2);
    }

    // --- Cross-circuit sanity: parser generalizes to poseidon (larger domain) ---

    #[test]
    fn poseidon_fflonk_header_has_larger_domain() {
        let bytes =
            std::fs::read("tests/fixtures/poseidon/circuit.zkey").expect("load poseidon zkey");
        let header = read_fflonk_header(&bytes).expect("parse poseidon fflonk header");
        assert!(
            header.domain_size > 8,
            "poseidon domain should exceed multiplier's 8, got {}",
            header.domain_size
        );
        assert!(
            header.domain_size.is_power_of_two(),
            "domain must be power of 2"
        );
    }
}
