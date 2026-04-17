//! Keccak-256 Fiat-Shamir transcript matching snarkjs 0.7.6's `Keccak256Transcript`.
//!
//! Encoding details (verified empirically against the multiplier fixture's alpha):
//! - **Scalars** (Fr): 32 bytes, **canonical big-endian** (not Montgomery — the
//!   `toRprBE` name in ffjavascript is misleading; it writes canonical bytes)
//! - **G1 points**: uncompressed affine `[x || y]`, each coord 32 bytes canonical-BE
//!   → 64 bytes total
//! - **Digest → challenge**: Keccak-256 → 32-byte digest, interpreted as big-endian
//!   integer, reduced mod r
//!
//! See `src/Keccak256Transcript.js` in snarkjs v0.7.6 for the reference impl.

use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::PrimeField;
use sha3::{Digest, Keccak256};

/// Transcript state: the accumulated input buffer that gets hashed on `get_challenge`.
#[derive(Default, Debug, Clone)]
pub struct Keccak256Transcript {
    buf: Vec<u8>,
}

impl Keccak256Transcript {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Reset the transcript — clears the buffer. snarkjs's `reset()`.
    pub fn reset(&mut self) {
        self.buf.clear();
    }

    /// Absorb an Fr scalar (32 bytes, canonical big-endian).
    pub fn add_scalar(&mut self, fr: &Fr) {
        self.buf.extend_from_slice(&fr_to_canonical_be_bytes(fr));
    }

    /// Absorb a G1 point in uncompressed affine form: `x_bytes || y_bytes`, each
    /// 32 bytes canonical-BE (matches snarkjs's `toRprUncompressed`).
    pub fn add_g1_point(&mut self, point: &G1Affine) {
        self.buf
            .extend_from_slice(&fq_to_canonical_be_bytes(&point.x));
        self.buf
            .extend_from_slice(&fq_to_canonical_be_bytes(&point.y));
    }

    /// Hash the buffer and reduce the 32-byte digest mod r as a big-endian integer.
    pub fn get_challenge(&self) -> Fr {
        let digest = Keccak256::digest(&self.buf);
        Fr::from_be_bytes_mod_order(&digest)
    }
}

fn fr_to_canonical_be_bytes(fr: &Fr) -> [u8; 32] {
    canonical_bigint_to_be_bytes(fr.into_bigint().0)
}

fn fq_to_canonical_be_bytes(fq: &Fq) -> [u8; 32] {
    canonical_bigint_to_be_bytes(fq.into_bigint().0)
}

fn canonical_bigint_to_be_bytes(limbs: [u64; 4]) -> [u8; 32] {
    // Canonical 256-bit value stored as 4 u64 limbs with `limbs[0]` least significant.
    // For big-endian: most-significant limb first, each limb written big-endian.
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&limbs[3].to_be_bytes());
    out[8..16].copy_from_slice(&limbs[2].to_be_bytes());
    out[16..24].copy_from_slice(&limbs[1].to_be_bytes());
    out[24..32].copy_from_slice(&limbs[0].to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr_canonical_be_bytes_small_value() {
        // Fr::from(33) canonical BE bytes = 31 zeros + 0x21.
        let bytes = fr_to_canonical_be_bytes(&Fr::from(33u64));
        let mut expected = [0u8; 32];
        expected[31] = 0x21;
        assert_eq!(bytes, expected);
    }

    #[test]
    fn empty_transcript_challenge_is_deterministic() {
        let t1 = Keccak256Transcript::new();
        let t2 = Keccak256Transcript::new();
        assert_eq!(t1.get_challenge(), t2.get_challenge());
    }

    #[test]
    fn reset_clears_buffer() {
        let mut t = Keccak256Transcript::new();
        t.add_scalar(&Fr::from(42u64));
        let before_reset = t.get_challenge();
        t.reset();
        let after_reset = t.get_challenge();
        // After reset, transcript matches empty-transcript.
        assert_eq!(after_reset, Keccak256Transcript::new().get_challenge());
        assert_ne!(before_reset, after_reset);
    }

    #[test]
    fn different_scalars_give_different_challenges() {
        let mut t1 = Keccak256Transcript::new();
        let mut t2 = Keccak256Transcript::new();
        t1.add_scalar(&Fr::from(1u64));
        t2.add_scalar(&Fr::from(2u64));
        assert_ne!(t1.get_challenge(), t2.get_challenge());
    }

    // --- Reference-matching tests against the multiplier fixture ---
    //
    // We chain the transcripts exactly as snarkjs fflonk_prove.js does to derive
    // challenges.alpha. A matching alpha proves our transcript agrees with snarkjs
    // on every preceding link (beta → gamma → xiSeed → alpha).
    //
    // Reference alpha (captured from snarkjs fflonk prove verbose log on multiplier):
    //   12408407455021234893912772114318207158684737532346130920639855224568806032927

    use ark_bn254::G1Affine;
    use ark_ff::Field;
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

    #[test]
    fn reproduces_multiplier_alpha_from_reference_chain() {
        // From tests/fixtures/multiplier/vkey.json
        let c0 = g1(
            "11865776073359729040794258160793130354546641422008347334213198060920506239709",
            "5524268144136126767933990501392740300548075291727485037030383383698594318676",
        );
        // Public input A[0] — for multiplier the public output c = 3 * 11 = 33.
        let a0 = Fr::from(33u64);
        // From tests/fixtures/multiplier/reference_proof.json
        let c1 = g1(
            "17256955544720010681668327440745774482888643498003365476558443417839496374119",
            "10014919292886339171655109553878758397079400172242899911914719305365841767683",
        );
        let c2 = g1(
            "3989673609061789950409244862037062929227173903571937065370636622611135085513",
            "6001160714579456671825974713880720307084678625405829727727240696134952136276",
        );

        // Round-2 transcript: C0, A[0], C1 → beta.
        let mut t = Keccak256Transcript::new();
        t.add_g1_point(&c0);
        t.add_scalar(&a0);
        t.add_g1_point(&c1);
        let beta = t.get_challenge();

        // gamma is derived by resetting then adding beta alone.
        t.reset();
        t.add_scalar(&beta);
        let gamma = t.get_challenge();

        // Round-3 transcript: gamma, C2 → xiSeed.
        let mut t = Keccak256Transcript::new();
        t.add_scalar(&gamma);
        t.add_g1_point(&c2);
        let xi_seed = t.get_challenge();

        // Round-4 transcript: xiSeed, then the 15 scalar evaluations in snarkjs's order.
        let mut t = Keccak256Transcript::new();
        t.add_scalar(&xi_seed);
        t.add_scalar(&fr(
            "8656540919485434325127996463862963077422400187418464280627379020094348872551",
        )); // ql
        t.add_scalar(&fr("0")); // qr
        t.add_scalar(&fr(
            "2614769233458373575914167661386876499189977403679308856418227786252928171678",
        )); // qm
        t.add_scalar(&fr(
            "19273473638380901646332238083870398589358386996736725487279976400322880323939",
        )); // qo
        t.add_scalar(&fr("0")); // qc
        t.add_scalar(&fr(
            "2149601555970763550502742290511066346210126521388222512348169637526747700236",
        )); // s1
        t.add_scalar(&fr(
            "7665469566589217530047082740024900379575949551084655260788477394062900215820",
        )); // s2
        t.add_scalar(&fr(
            "9593052032151367161561845615248167687278938119063653268474063026781260594803",
        )); // s3
        t.add_scalar(&fr(
            "16127061633303507620994494118418859935014078291353908877586231175433014908086",
        )); // a
        t.add_scalar(&fr(
            "10481924070205961981688681564524817045099149903371547605480211094869994165600",
        )); // b
        t.add_scalar(&fr(
            "11165319260432401010175261312139144201227551818404445502013201559202664335104",
        )); // c
        t.add_scalar(&fr(
            "414154269577338230123695308905609275000771520577836775585168828854428911021",
        )); // z
        t.add_scalar(&fr(
            "20032753347252750623757752495127622395615307912815516003156251467213315967927",
        )); // zw
        t.add_scalar(&fr(
            "528472514911415871465957436906207785247458062589561186936125913093451716131",
        )); // t1w
        t.add_scalar(&fr(
            "1735584312925944748061585464799496108892046647899363999711364062499048168279",
        )); // t2w
        let alpha = t.get_challenge();

        let expected_alpha =
            fr("12408407455021234893912772114318207158684737532346130920639855224568806032927");
        assert_eq!(alpha, expected_alpha);

        // Continue chain: y = H(alpha, W1). W1 from reference_proof.json.
        let w1 = g1(
            "17081214923860998837004564450514163691745904059929806099075459825515272439815",
            "19856250073451418650421446643378076545939068614237958371221610792435347872038",
        );
        let mut t = Keccak256Transcript::new();
        t.add_scalar(&alpha);
        t.add_g1_point(&w1);
        let y = t.get_challenge();
        let expected_y =
            fr("9172056470351198115702670557931351629286098597617941730766195584529074137327");
        assert_eq!(y, expected_y);

        // Also verify xiSeed via xi = xiSeed^24 from the log.
        // challenges.xi: 20443477157474477067726745912638374445877616467670459784841395663060888101329
        let xi = xi_seed.pow([24u64]);
        let expected_xi =
            fr("20443477157474477067726745912638374445877616467670459784841395663060888101329");
        assert_eq!(xi, expected_xi);
    }
}
