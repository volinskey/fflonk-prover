//! FFLONK prover rounds.
//!
//! This module implements the prover side of the snarkjs 0.7.6 FFLONK
//! protocol. Proving proceeds in three commitment rounds plus evaluation
//! and opening, but many sub-steps are helpers shared across rounds.
//!
//! Round 1 (this file currently):
//! 1. Build wire buffers A, B, C from witness + A_map/B_map/C_map
//! 2. Apply blinding to last two entries of each
//! 3. iFFT to coefficient form → polynomials.A/B/C
//! 4. Compute T0(X) = (q_L·A + q_R·B + q_M·A·B + q_O·C + q_C + PI) / Z_H(X)
//! 5. Fan-in-4 interleave A, B, C, T0 → C1 poly
//! 6. KZG commit → proof.C1
//!
//! The `Round1Blinders::zero()` constructor enables deterministic testing
//! (the real prover uses cryptographic randomness — blinding is for
//! zero-knowledge, not correctness).

use ark_bn254::{Fr, G1Affine};
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use thiserror::Error;

use crate::kzg;
use crate::poly::{
    add_assign, div_by_linear, div_by_x_n_minus_beta, eval_horner, lagrange_interpolate,
    scalar_mul_assign, sub_assign, sub_scalar_assign,
};
use crate::transcript::Keccak256Transcript;
use crate::zkey::{
    read_additions, read_fflonk_header, read_fr_section, read_g1_section, read_u32_section,
    Addition, FflonkHeader, ZkeyError, SECTION_A_MAP, SECTION_B_MAP, SECTION_C0, SECTION_C_MAP,
    SECTION_LAGRANGE, SECTION_PTAU, SECTION_QC, SECTION_QL, SECTION_QM, SECTION_QO, SECTION_QR,
    SECTION_SIGMA1, SECTION_SIGMA2, SECTION_SIGMA3,
};

#[derive(Debug, Error)]
pub enum ProverError {
    #[error("zkey parse: {0}")]
    Zkey(#[from] ZkeyError),

    #[error("witness signal {signal} out of range (witness has {len} entries)")]
    WitnessOutOfRange { signal: u32, len: usize },

    #[error("polynomial not divisible by X^{n} - 1 (nonzero coefficient at index {index})")]
    NotDivisibleByZh { n: usize, index: usize },

    #[error("FFT domain of size {n} not constructible")]
    BadDomain { n: usize },

    #[error("KZG: {0}")]
    Kzg(#[from] kzg::KzgError),

    #[error("structural check failed: {0}")]
    Structural(String),
}

/// Round 1 blinding scalars b_1..b_6. Snarkjs uses 9 total; b_7..b_9 are
/// used in Round 2.
#[derive(Debug, Clone, Copy)]
pub struct Round1Blinders {
    pub b1: Fr,
    pub b2: Fr,
    pub b3: Fr,
    pub b4: Fr,
    pub b5: Fr,
    pub b6: Fr,
}

impl Round1Blinders {
    /// All-zero blinders — deterministic, for testing. Not zero-knowledge.
    pub fn zero() -> Self {
        Self {
            b1: Fr::zero(),
            b2: Fr::zero(),
            b3: Fr::zero(),
            b4: Fr::zero(),
            b5: Fr::zero(),
            b6: Fr::zero(),
        }
    }
}

/// Round 1 outputs. Also carries intermediate buffers required by Round 2.
#[derive(Debug, Clone)]
pub struct Round1Output {
    /// Header of the zkey, re-exposed for convenience.
    pub header: FflonkHeader,
    /// A(X), B(X), C(X) in coefficient form (length = domain_size).
    pub a_poly: Vec<Fr>,
    pub b_poly: Vec<Fr>,
    pub c_poly: Vec<Fr>,
    /// Base-domain evaluation buffers (pre-blinding witness values written at
    /// positions [0, n_constraints), blinders at [n-2, n-1]). Kept for Round 2's
    /// grand-product Z evaluation which needs A/B/C values at each ω^i.
    pub a_buf: Vec<Fr>,
    pub b_buf: Vec<Fr>,
    pub c_buf: Vec<Fr>,
    /// Extended 4n-domain evaluations of A/B/C. Needed by Round 2's T2.
    pub a_ext: Vec<Fr>,
    pub b_ext: Vec<Fr>,
    pub c_ext: Vec<Fr>,
    /// T0(X) in coefficient form (length = 3·domain_size; effective degree < 2n-2).
    pub t0_poly: Vec<Fr>,
    /// The fan-in-4 merged C1(X) in coefficient form.
    pub c1_coeffs: Vec<Fr>,
    /// The round-1 commitment [C1(τ)]_1.
    pub c1_commitment: G1Affine,
}

/// Execute prover Round 1 on a full zkey blob + witness vector.
pub fn round1(
    zkey_bytes: &[u8],
    witness: &[Fr],
    blinders: &Round1Blinders,
) -> Result<Round1Output, ProverError> {
    let header = read_fflonk_header(zkey_bytes)?;
    let n = header.domain_size as usize;

    // snarkjs zeroes witness[0] before proving — Circom's signal 0 is the
    // "constant one" slot for witness-generation semantics, but in the fflonk
    // prover it marks "unused" positions. Setting it to 0 ensures the σ
    // permutation cycles (which link padding rows to signal 0) close: all
    // cells in those cycles end up holding value 0.
    let mut w = witness.to_vec();
    if !w.is_empty() {
        w[0] = Fr::zero();
    }

    // Build the internal-witness table (empty if no additions).
    // Snarkjs's `getWitness(id)` transparently handles three ranges:
    //   - `id < nVars - nAdditions`: direct `witness[id]`
    //   - `id < nVars`: computed `internal_witness[id - diff]`
    //   - otherwise: `Fr::zero()` fallback
    // For circuits where the R1CS→PLONK transpiler coalesces constraints
    // (kysigned-approval: nAdditions ≈ 3.7M), the wire maps reference
    // signal ids in the middle range.
    let additions = read_additions(zkey_bytes)?;
    let n_vars = header.n_vars as usize;
    let internal_witness = compute_internal_witness(&w, &additions, n_vars);

    let (a_buf, b_buf, c_buf, a_poly, b_poly, c_poly) =
        build_wire_polynomials(zkey_bytes, &w, &internal_witness, n_vars, n, blinders)?;
    let a_ext = extended_evaluations(&a_poly, n)?;
    let b_ext = extended_evaluations(&b_poly, n)?;
    let c_ext = extended_evaluations(&c_poly, n)?;
    let t0_poly = compute_t0(
        zkey_bytes,
        &header,
        &a_ext,
        &b_ext,
        &c_ext,
        &w,
        &internal_witness,
    )?;
    let c1_coeffs = cpoly_fan_in_4_merge(&[&a_poly, &b_poly, &c_poly, &t0_poly]);

    // KZG commit only needs coefficients up to the last non-zero term. The
    // PTau SRS in the zkey is sized for the largest commitment in the protocol
    // (C2, which is 9n+18 points); C1's effective length must fit within that.
    let c1_commit_coeffs = trim_trailing_zeros(&c1_coeffs);
    let srs = read_g1_section(zkey_bytes, SECTION_PTAU)?;
    let c1_commitment = kzg::commit(c1_commit_coeffs, &srs)?;

    Ok(Round1Output {
        header,
        a_poly,
        b_poly,
        c_poly,
        a_buf,
        b_buf,
        c_buf,
        a_ext,
        b_ext,
        c_ext,
        t0_poly,
        c1_coeffs,
        c1_commitment,
    })
}

/// Snarkjs's `getWitness(id)`: three ranges — direct witness, internal
/// (computed from additions), or zero fallback. Signals up to
/// `nVars - nAdditions` map to `witness[id]`; the next `nAdditions` entries
/// map to `internal_witness[id - diff]`; anything beyond `nVars` is zero.
///
/// `n_additions` is the TOTAL number of additions (= FINAL length of the
/// internal-witness buffer). During the incremental build inside
/// `compute_internal_witness`, the `internal_witness` slice is shorter than
/// `n_additions` — but `diff` must still be based on the final count to
/// match snarkjs's pre-allocated-buffer semantics. Using
/// `internal_witness.len()` as `diff` gave wrong indices for earlier
/// additions and broke the gate polynomial's divisibility by Z_H on the
/// kysigned circuit.
fn get_witness(
    id: u32,
    witness: &[Fr],
    internal_witness: &[Fr],
    n_vars: usize,
    n_additions: usize,
) -> Fr {
    let idx = id as usize;
    let diff = n_vars - n_additions;
    if idx < diff {
        witness.get(idx).copied().unwrap_or(Fr::zero())
    } else if idx < n_vars {
        internal_witness
            .get(idx - diff)
            .copied()
            .unwrap_or(Fr::zero())
    } else {
        Fr::zero()
    }
}

/// Compute the internal witness values from the Additions section.
/// Each addition defines `internal[i] = factor_a · get_witness(a) + factor_b · get_witness(b)`.
/// Because additions are emitted in topological order by snarkjs (each entry
/// can only reference earlier entries), a single forward pass suffices.
pub fn compute_internal_witness(witness: &[Fr], additions: &[Addition], n_vars: usize) -> Vec<Fr> {
    let n_additions = additions.len();
    let mut internal = Vec::with_capacity(n_additions);
    for add in additions {
        let aw = get_witness(add.a, witness, &internal, n_vars, n_additions);
        let bw = get_witness(add.b, witness, &internal, n_vars, n_additions);
        internal.push(aw * add.factor_a + bw * add.factor_b);
    }
    internal
}

/// Build A, B, C wire polynomials in coefficient form (length = domain_size).
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
fn build_wire_polynomials(
    zkey_bytes: &[u8],
    witness: &[Fr],
    internal_witness: &[Fr],
    n_vars: usize,
    n: usize,
    blinders: &Round1Blinders,
) -> Result<(Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>), ProverError> {
    let a_map = read_u32_section(zkey_bytes, SECTION_A_MAP)?;
    let b_map = read_u32_section(zkey_bytes, SECTION_B_MAP)?;
    let c_map = read_u32_section(zkey_bytes, SECTION_C_MAP)?;

    let n_constraints = a_map.len();

    let mut a_buf = vec![Fr::zero(); n];
    let mut b_buf = vec![Fr::zero(); n];
    let mut c_buf = vec![Fr::zero(); n];

    let n_additions = internal_witness.len();
    for i in 0..n_constraints {
        a_buf[i] = get_witness(a_map[i], witness, internal_witness, n_vars, n_additions);
        b_buf[i] = get_witness(b_map[i], witness, internal_witness, n_vars, n_additions);
        c_buf[i] = get_witness(c_map[i], witness, internal_witness, n_vars, n_additions);
    }

    // Blinding: overwrite last two domain-evaluation slots of each buffer.
    a_buf[n - 2] = blinders.b1;
    a_buf[n - 1] = blinders.b2;
    b_buf[n - 2] = blinders.b3;
    b_buf[n - 1] = blinders.b4;
    c_buf[n - 2] = blinders.b5;
    c_buf[n - 1] = blinders.b6;

    let domain = Radix2EvaluationDomain::<Fr>::new(n).ok_or(ProverError::BadDomain { n })?;
    let a_poly = domain.ifft(&a_buf);
    let b_poly = domain.ifft(&b_buf);
    let c_poly = domain.ifft(&c_buf);

    Ok((a_buf, b_buf, c_buf, a_poly, b_poly, c_poly))
}

/// Extend a coefficient vector of length `n` to `4n` by zero-padding and FFT,
/// yielding evaluations on the 4n-th roots of unity.
fn extended_evaluations(coefs: &[Fr], n: usize) -> Result<Vec<Fr>, ProverError> {
    debug_assert_eq!(coefs.len(), n);
    let domain_4n =
        Radix2EvaluationDomain::<Fr>::new(4 * n).ok_or(ProverError::BadDomain { n: 4 * n })?;
    let mut padded = coefs.to_vec();
    padded.resize(4 * n, Fr::zero());
    Ok(domain_4n.fft(&padded))
}

/// Compute T0(X) = (q_L·A + q_R·B + q_M·A·B + q_O·C + q_C + PI) / Z_H(X).
///
/// Works on the 4n-domain: we compute the numerator's evaluations at every
/// 4n-th root of unity, iFFT to coefficient form, then divide by Z_H = X^n - 1.
#[allow(clippy::too_many_arguments)]
fn compute_t0(
    zkey_bytes: &[u8],
    header: &FflonkHeader,
    a_ext: &[Fr],
    b_ext: &[Fr],
    c_ext: &[Fr],
    witness: &[Fr],
    internal_witness: &[Fr],
) -> Result<Vec<Fr>, ProverError> {
    let n = header.domain_size as usize;
    let four_n = 4 * n;

    // Preprocessed selector extended evaluations: stored in zkey sections
    // 7-11 right after the first `domain_size` coefficients.
    let ql_ext = load_extended_evals(zkey_bytes, SECTION_QL, n)?;
    let qr_ext = load_extended_evals(zkey_bytes, SECTION_QR, n)?;
    let qm_ext = load_extended_evals(zkey_bytes, SECTION_QM, n)?;
    let qo_ext = load_extended_evals(zkey_bytes, SECTION_QO, n)?;
    let qc_ext = load_extended_evals(zkey_bytes, SECTION_QC, n)?;

    // Public-input Lagrange evaluations: section 15 holds `nPublic` blocks,
    // each 5n Fr entries (n coefs + 4n extended evals). For public input j,
    // the extended evaluation at 4n-domain index i sits at j*5n + n + i.
    let lagrange = read_fr_section(zkey_bytes, SECTION_LAGRANGE)?;
    let n_public = header.n_public as usize;

    // Precompute the base-domain evaluations at public-input rows — the j-th
    // public input is `get_witness(a_map[j])` (not a raw witness[a_map[j]] —
    // additions may map public-input slots to virtual signals).
    let a_map = read_u32_section(zkey_bytes, SECTION_A_MAP)?;
    let n_vars = header.n_vars as usize;
    let n_additions = internal_witness.len();
    let public_evals: Vec<Fr> = a_map
        .iter()
        .take(n_public)
        .map(|&sig| get_witness(sig, witness, internal_witness, n_vars, n_additions))
        .collect();

    let mut t0_num_ext = vec![Fr::zero(); four_n];
    for i in 0..four_n {
        let a = a_ext[i];
        let b = b_ext[i];
        let c = c_ext[i];
        let ql = ql_ext[i];
        let qr = qr_ext[i];
        let qm = qm_ext[i];
        let qo = qo_ext[i];
        let qc = qc_ext[i];

        // PI(x_i) = -Σ_j L_j(x_i) · A_j   where A_j is the j-th public input
        // (i.e. pre-blinding A buffer value at row j).
        let mut pi = Fr::zero();
        for (j, &a_j) in public_evals.iter().enumerate() {
            let offset = j * 5 * n + n + i;
            pi -= lagrange[offset] * a_j;
        }

        let gate = ql * a + qr * b + qm * a * b + qo * c + qc + pi;
        t0_num_ext[i] = gate;
    }

    let domain_4n =
        Radix2EvaluationDomain::<Fr>::new(four_n).ok_or(ProverError::BadDomain { n: four_n })?;
    let t0_zh_coefs = domain_4n.ifft(&t0_num_ext);
    let _ = witness; // now only used via public_evals
    div_by_zh(&t0_zh_coefs, n)
}

/// Read a preprocessed polynomial section and return just the extended-evaluation
/// slice (the 4n entries following the first n coefficients).
fn load_extended_evals(zkey_bytes: &[u8], section: u32, n: usize) -> Result<Vec<Fr>, ProverError> {
    let all = read_fr_section(zkey_bytes, section)?;
    let expected = 5 * n;
    if all.len() < expected {
        return Err(ProverError::Structural(format!(
            "section {section} has {} entries, expected at least {}",
            all.len(),
            expected
        )));
    }
    Ok(all[n..5 * n].to_vec())
}

/// Polynomial division by Z_H(X) = X^n − 1.
///
/// Given coefficients of P(X) of length L ≥ n, and if P is exactly divisible
/// by Z_H, returns coefficients of Q(X) = P(X) / Z_H(X) of length L−n.
/// Recurrence: q_j = -p_j for j < n, q_j = q_{j−n} − p_j for j ≥ n.
/// Divisibility is checked by requiring the top n entries of q (at indices
/// L−n..L) to be zero.
fn div_by_zh(coefs: &[Fr], n: usize) -> Result<Vec<Fr>, ProverError> {
    let l = coefs.len();
    assert!(l >= n, "poly length {l} < zerofier degree {n}");
    let mut q = vec![Fr::zero(); l];
    for (i, c) in coefs.iter().enumerate().take(n) {
        q[i] = -*c;
    }
    for i in n..l {
        q[i] = q[i - n] - coefs[i];
    }
    for (i, q_i) in q.iter().enumerate().skip(l - n) {
        if !q_i.is_zero() {
            return Err(ProverError::NotDivisibleByZh { n, index: i });
        }
    }
    q.truncate(l - n);
    Ok(q)
}

/// Slice off trailing zero coefficients so KZG MSM isn't asked for wasted points.
fn trim_trailing_zeros(coefs: &[Fr]) -> &[Fr] {
    let end = coefs
        .iter()
        .rposition(|c| !c.is_zero())
        .map(|i| i + 1)
        .unwrap_or(0);
    &coefs[..end]
}

/// Fan-in-N interleave (snarkjs `CPolynomial(n)`):
/// `merged[i*n + j] = P_j[i]`. Output length = `n · max(P_j.len())`.
fn cpoly_merge(polys: &[&[Fr]], fan_in: usize) -> Vec<Fr> {
    let max_len = polys.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut out = vec![Fr::zero(); max_len * fan_in];
    for (j, p) in polys.iter().enumerate() {
        for (i, &c) in p.iter().enumerate() {
            out[i * fan_in + j] = c;
        }
    }
    out
}

/// Thin wrapper for callers with exactly 4 polys (Round 1 C1).
fn cpoly_fan_in_4_merge(polys: &[&Vec<Fr>; 4]) -> Vec<Fr> {
    let max_len = polys.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut out = vec![Fr::zero(); max_len * 4];
    for (j, p) in polys.iter().enumerate() {
        for (i, &c) in p.iter().enumerate() {
            out[i * 4 + j] = c;
        }
    }
    out
}

// ============================================================================
// Round 2: permutation polynomial Z, quotients T1 & T2, commitment C2.
// ============================================================================

/// Round 2 blinding scalars b_7..b_9 (snarkjs's `challenges.b[7..=9]`).
/// These blind the Z polynomial in coefficient space: Z_blinded(X) = Z(X) +
/// (b_9 + b_8·X + b_7·X²) · Z_H(X). Setting all three to zero yields a
/// deterministic (non-zero-knowledge) prover — fine for correctness tests.
#[derive(Debug, Clone, Copy)]
pub struct Round2Blinders {
    pub b7: Fr,
    pub b8: Fr,
    pub b9: Fr,
}

impl Round2Blinders {
    pub fn zero() -> Self {
        Self {
            b7: Fr::zero(),
            b8: Fr::zero(),
            b9: Fr::zero(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Round2Output {
    /// Blinded Z(X) coefficients (length up to n+3).
    pub z_poly: Vec<Fr>,
    /// T1(X) final coefficients (length 2n; effective degree < n+2).
    pub t1_poly: Vec<Fr>,
    /// T2(X) final coefficients (length 4n; effective degree < 3n).
    pub t2_poly: Vec<Fr>,
    /// Pre-blinding Z's 4n-extended evaluations (reused by downstream rounds).
    pub z_ext: Vec<Fr>,
    /// The fan-in-3 merged C2(X) coefficients.
    pub c2_coeffs: Vec<Fr>,
    /// Round-2 commitment [C2(τ)]_1.
    pub c2_commitment: G1Affine,
}

/// Execute prover Round 2.
pub fn round2(
    zkey_bytes: &[u8],
    r1: &Round1Output,
    beta: Fr,
    gamma: Fr,
    blinders: &Round2Blinders,
) -> Result<Round2Output, ProverError> {
    let n = r1.header.domain_size as usize;

    let z_buf = compute_z_buffer(zkey_bytes, r1, beta, gamma)?;

    let domain_n = Radix2EvaluationDomain::<Fr>::new(n).ok_or(ProverError::BadDomain { n })?;
    let z_poly_unblinded = domain_n.ifft(&z_buf);
    let z_ext = extended_evaluations(&z_poly_unblinded, n)?;

    let mut z_poly = z_poly_unblinded;
    blind_z(&mut z_poly, n, blinders);

    let t1_poly = compute_t1(zkey_bytes, &z_ext, n, blinders)?;
    let t2_poly = compute_t2(zkey_bytes, r1, &z_ext, beta, gamma, n, blinders)?;

    let c2_coeffs = cpoly_merge(
        &[z_poly.as_slice(), t1_poly.as_slice(), t2_poly.as_slice()],
        3,
    );

    let c2_commit_coeffs = trim_trailing_zeros(&c2_coeffs);
    let srs = read_g1_section(zkey_bytes, SECTION_PTAU)?;
    let c2_commitment = kzg::commit(c2_commit_coeffs, &srs)?;

    Ok(Round2Output {
        z_poly,
        t1_poly,
        t2_poly,
        z_ext,
        c2_coeffs,
        c2_commitment,
    })
}

/// Compute the grand-product Z evaluations on the base domain. Z[0] = 1, and
/// the grand-product factors accumulate around the n-element cycle.
fn compute_z_buffer(
    zkey_bytes: &[u8],
    r1: &Round1Output,
    beta: Fr,
    gamma: Fr,
) -> Result<Vec<Fr>, ProverError> {
    let n = r1.header.domain_size as usize;
    let k1 = r1.header.k1;
    let k2 = r1.header.k2;

    let domain_n = Radix2EvaluationDomain::<Fr>::new(n).ok_or(ProverError::BadDomain { n })?;

    // σ values at each base-domain point: every 4th entry of the 4n-extended
    // evaluation block (the 4n domain contains the n domain at stride 4).
    let sigma1_ext = load_extended_evals(zkey_bytes, SECTION_SIGMA1, n)?;
    let sigma2_ext = load_extended_evals(zkey_bytes, SECTION_SIGMA2, n)?;
    let sigma3_ext = load_extended_evals(zkey_bytes, SECTION_SIGMA3, n)?;

    let mut num_arr = vec![Fr::zero(); n];
    let mut den_arr = vec![Fr::zero(); n];
    num_arr[0] = Fr::one();
    den_arr[0] = Fr::one();

    let mut w = Fr::one(); // ω^i
    for i in 0..n {
        let next = (i + 1) % n;
        let betaw = beta * w;

        let num1 = r1.a_buf[i] + betaw + gamma;
        let num2 = r1.b_buf[i] + k1 * betaw + gamma;
        let num3 = r1.c_buf[i] + k2 * betaw + gamma;
        let num = num1 * num2 * num3;

        let s1_i = sigma1_ext[i * 4];
        let s2_i = sigma2_ext[i * 4];
        let s3_i = sigma3_ext[i * 4];

        let den1 = r1.a_buf[i] + beta * s1_i + gamma;
        let den2 = r1.b_buf[i] + beta * s2_i + gamma;
        let den3 = r1.c_buf[i] + beta * s3_i + gamma;
        let den = den1 * den2 * den3;

        num_arr[next] = num_arr[i] * num;
        den_arr[next] = den_arr[i] * den;

        w *= domain_n.group_gen;
    }

    // Batch-invert denArr then Z[i] = num_arr[i] / den_arr[i].
    ark_ff::fields::batch_inversion(&mut den_arr);
    let z_buf: Vec<Fr> = num_arr
        .iter()
        .zip(den_arr.iter())
        .map(|(n, d)| *n * *d)
        .collect();

    if z_buf[0] != Fr::one() {
        return Err(ProverError::Structural(
            "copy constraints do not match — grand-product Z[0] ≠ 1".into(),
        ));
    }
    Ok(z_buf)
}

/// Blind Z coefficients in place: Z_blinded(X) = Z(X) + (b_9 + b_8·X + b_7·X²)·Z_H(X),
/// where Z_H(X) = X^n − 1. This expands to subtracting b_9, b_8, b_7 from
/// coefs[0..3] and adding them to coefs[n..n+3].
fn blind_z(z_poly: &mut Vec<Fr>, n: usize, b: &Round2Blinders) {
    if z_poly.len() < n + 3 {
        z_poly.resize(n + 3, Fr::zero());
    }
    z_poly[0] -= b.b9;
    z_poly[1] -= b.b8;
    z_poly[2] -= b.b7;
    z_poly[n] += b.b9;
    z_poly[n + 1] += b.b8;
    z_poly[n + 2] += b.b7;
}

/// T1(X) = (Z(X) − 1) · L_1(X) / Z_H(X) + Z_p(X) · L_1(X),
/// where Z_p(X) = b_7·X² + b_8·X + b_9 is the blinding correction.
///
/// Works on the 2n-domain: we compute the numerator's evaluations at each
/// 2n-th root of unity, iFFT to coefficients, divide by Z_H, then add the
/// T1z correction (which is not divided by Z_H).
fn compute_t1(
    zkey_bytes: &[u8],
    z_ext: &[Fr],
    n: usize,
    b: &Round2Blinders,
) -> Result<Vec<Fr>, ProverError> {
    let two_n = 2 * n;
    let domain_2n =
        Radix2EvaluationDomain::<Fr>::new(two_n).ok_or(ProverError::BadDomain { n: two_n })?;

    // L_1 extended evaluations: in the lagrange section, public input 0 lives
    // at [0, 5n). Its extended-eval block starts at offset n and has 4n entries.
    let lagrange = read_fr_section(zkey_bytes, SECTION_LAGRANGE)?;
    if lagrange.len() < n + 4 * n {
        return Err(ProverError::Structural(format!(
            "Lagrange section too small: {} < {}",
            lagrange.len(),
            5 * n
        )));
    }

    let mut t1_buf = vec![Fr::zero(); two_n];
    let mut t1z_buf = vec![Fr::zero(); two_n];

    let mut omega = Fr::one();
    for i in 0..two_n {
        let omega2 = omega * omega;
        let z = z_ext[i * 2]; // Z at ω_{4n}^{2i} = ω_{2n}^i
        let zp = b.b7 * omega2 + b.b8 * omega + b.b9;
        let l1 = lagrange[n + i * 2];

        t1_buf[i] = (z - Fr::one()) * l1;
        t1z_buf[i] = zp * l1;

        omega *= domain_2n.group_gen;
    }

    let t1_times_zh_coefs = domain_2n.ifft(&t1_buf);
    let t1_coefs = div_by_zh(&t1_times_zh_coefs, n)?; // length = n

    let t1z_coefs = domain_2n.ifft(&t1z_buf); // length = 2n

    // Sum: t1_final[i] = t1z_coefs[i] + (t1_coefs[i] if i < n else 0)
    let mut t1_final = t1z_coefs;
    for (i, &c) in t1_coefs.iter().enumerate() {
        t1_final[i] += c;
    }
    Ok(t1_final)
}

/// T2(X) = [e1(X)·z(X) − e2(X)·z(Xω)] / Z_H(X) + [e1(X)·zp(X) − e2(X)·zwp(X)],
/// where
///   e1 = (a + βX + γ)(b + βk₁X + γ)(c + βk₂X + γ)
///   e2 = (a + βσ₁ + γ)(b + βσ₂ + γ)(c + βσ₃ + γ)
///   zp(X) = b₇·X² + b₈·X + b₉
///   zwp(X) = b₇·(Xω)² + b₈·(Xω) + b₉
///
/// Computed on the 4n-domain using A/B/C/Z's extended evaluations and the
/// zkey's σ extended evaluations.
#[allow(clippy::too_many_arguments)]
fn compute_t2(
    zkey_bytes: &[u8],
    r1: &Round1Output,
    z_ext: &[Fr],
    beta: Fr,
    gamma: Fr,
    n: usize,
    b: &Round2Blinders,
) -> Result<Vec<Fr>, ProverError> {
    let four_n = 4 * n;
    let domain_4n =
        Radix2EvaluationDomain::<Fr>::new(four_n).ok_or(ProverError::BadDomain { n: four_n })?;
    let domain_n = Radix2EvaluationDomain::<Fr>::new(n).ok_or(ProverError::BadDomain { n })?;
    let omega_n = domain_n.group_gen;

    let sigma1_ext = load_extended_evals(zkey_bytes, SECTION_SIGMA1, n)?;
    let sigma2_ext = load_extended_evals(zkey_bytes, SECTION_SIGMA2, n)?;
    let sigma3_ext = load_extended_evals(zkey_bytes, SECTION_SIGMA3, n)?;

    let k1 = r1.header.k1;
    let k2 = r1.header.k2;

    let mut t2_buf = vec![Fr::zero(); four_n];
    let mut t2z_buf = vec![Fr::zero(); four_n];

    let mut omega = Fr::one();
    for i in 0..four_n {
        let omega2 = omega * omega;
        let omega_w = omega * omega_n;
        let omega_w2 = omega_w * omega_w;

        let a = r1.a_ext[i];
        let b_eval = r1.b_ext[i];
        let c = r1.c_ext[i];
        let z = z_ext[i];
        let z_w = z_ext[(i + 4) % four_n];

        let zp = b.b7 * omega2 + b.b8 * omega + b.b9;
        let z_wp = b.b7 * omega_w2 + b.b8 * omega_w + b.b9;

        let s1 = sigma1_ext[i];
        let s2 = sigma2_ext[i];
        let s3 = sigma3_ext[i];

        let beta_x = beta * omega;

        let e11 = a + beta_x + gamma;
        let e12 = b_eval + beta_x * k1 + gamma;
        let e13 = c + beta_x * k2 + gamma;
        let e1_common = e11 * e12 * e13;
        let e1 = e1_common * z;
        let e1z = e1_common * zp;

        let e21 = a + beta * s1 + gamma;
        let e22 = b_eval + beta * s2 + gamma;
        let e23 = c + beta * s3 + gamma;
        let e2_common = e21 * e22 * e23;
        let e2 = e2_common * z_w;
        let e2z = e2_common * z_wp;

        t2_buf[i] = e1 - e2;
        t2z_buf[i] = e1z - e2z;

        omega *= domain_4n.group_gen;
    }

    let t2_times_zh_coefs = domain_4n.ifft(&t2_buf);
    let t2_coefs = div_by_zh(&t2_times_zh_coefs, n)?; // length 3n

    let t2z_coefs = domain_4n.ifft(&t2z_buf); // length 4n

    let mut t2_final = t2z_coefs;
    for (i, &c) in t2_coefs.iter().enumerate() {
        t2_final[i] += c;
    }
    Ok(t2_final)
}

// ============================================================================
// Round 3: xi challenge + 16 polynomial evaluations at xi (and 3 at xi·ω).
// ============================================================================

/// The 16 polynomial evaluations that go into `proof.evaluations`, plus the
/// challenges that generated them (kept for the later rounds' transcript chains).
#[derive(Debug, Clone, Copy)]
pub struct Round3Evaluations {
    pub ql: Fr,
    pub qr: Fr,
    pub qm: Fr,
    pub qo: Fr,
    pub qc: Fr,
    pub s1: Fr,
    pub s2: Fr,
    pub s3: Fr,
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
    pub z: Fr,
    pub zw: Fr,
    pub t1w: Fr,
    pub t2w: Fr,
    pub xi: Fr,
    pub xi_seed: Fr,
    pub xiw: Fr,
}

/// Execute prover Round 3 — derive xi and compute the opening evaluations.
pub fn round3(
    zkey_bytes: &[u8],
    r1: &Round1Output,
    r2: &Round2Output,
    gamma: Fr,
) -> Result<Round3Evaluations, ProverError> {
    let n = r1.header.domain_size as usize;

    // xiSeed = H(gamma || C2). xi = xiSeed^24. xiw = xi · ω_n.
    let mut t = Keccak256Transcript::new();
    t.add_scalar(&gamma);
    t.add_g1_point(&r2.c2_commitment);
    let xi_seed = t.get_challenge();
    let xi = xi_seed.pow([24u64]);

    let domain_n = Radix2EvaluationDomain::<Fr>::new(n).ok_or(ProverError::BadDomain { n })?;
    let omega_n = domain_n.group_gen;
    let xiw = xi * omega_n;

    // Load preprocessed polynomial coefficient blocks (first `n` Fr of each
    // section). Evaluate via Horner at xi.
    let ql_coefs = coef_block(zkey_bytes, SECTION_QL, n)?;
    let qr_coefs = coef_block(zkey_bytes, SECTION_QR, n)?;
    let qm_coefs = coef_block(zkey_bytes, SECTION_QM, n)?;
    let qo_coefs = coef_block(zkey_bytes, SECTION_QO, n)?;
    let qc_coefs = coef_block(zkey_bytes, SECTION_QC, n)?;
    let s1_coefs = coef_block(zkey_bytes, SECTION_SIGMA1, n)?;
    let s2_coefs = coef_block(zkey_bytes, SECTION_SIGMA2, n)?;
    let s3_coefs = coef_block(zkey_bytes, SECTION_SIGMA3, n)?;

    Ok(Round3Evaluations {
        ql: eval_horner(&ql_coefs, &xi),
        qr: eval_horner(&qr_coefs, &xi),
        qm: eval_horner(&qm_coefs, &xi),
        qo: eval_horner(&qo_coefs, &xi),
        qc: eval_horner(&qc_coefs, &xi),
        s1: eval_horner(&s1_coefs, &xi),
        s2: eval_horner(&s2_coefs, &xi),
        s3: eval_horner(&s3_coefs, &xi),
        a: eval_horner(&r1.a_poly, &xi),
        b: eval_horner(&r1.b_poly, &xi),
        c: eval_horner(&r1.c_poly, &xi),
        z: eval_horner(&r2.z_poly, &xi),
        zw: eval_horner(&r2.z_poly, &xiw),
        t1w: eval_horner(&r2.t1_poly, &xiw),
        t2w: eval_horner(&r2.t2_poly, &xiw),
        xi,
        xi_seed,
        xiw,
    })
}

/// Read just the first `n` Fr elements of a section (the coefficient block).
fn coef_block(zkey_bytes: &[u8], section: u32, n: usize) -> Result<Vec<Fr>, ProverError> {
    let all = read_fr_section(zkey_bytes, section)?;
    if all.len() < n {
        return Err(ProverError::Structural(format!(
            "section {section} has {} entries, expected at least {}",
            all.len(),
            n
        )));
    }
    Ok(all[..n].to_vec())
}

// ============================================================================
// Round 4 (snarkjs's round4): alpha challenge, R0/R1/R2 interpolation,
// F(X) quotient polynomial, W1 KZG commitment.
// ============================================================================

/// The 18 FFLONK roots used by rounds 4 and 5 for the R-polynomial
/// interpolation and the final zerofier computations.
#[derive(Debug, Clone)]
pub struct FflonkRoots {
    pub h0w8: [Fr; 8],
    pub h1w4: [Fr; 4],
    pub h2w3: [Fr; 3],
    pub h3w3: [Fr; 3],
}

/// Output of Round 4: alpha, the F(X) quotient polynomial (input to W1 commit),
/// and the W1 commitment itself. Also emits the derived roots and the C0/R0/R1/R2
/// polynomials for reuse by Round 5.
#[derive(Debug, Clone)]
pub struct Round4Output {
    pub alpha: Fr,
    pub roots: FflonkRoots,
    pub c0_coeffs: Vec<Fr>,
    pub r0_coeffs: Vec<Fr>,
    pub r1_coeffs: Vec<Fr>,
    pub r2_coeffs: Vec<Fr>,
    pub f_coeffs: Vec<Fr>,
    pub w1_commitment: G1Affine,
}

pub fn round4(
    zkey_bytes: &[u8],
    r1: &Round1Output,
    r2: &Round2Output,
    r3: &Round3Evaluations,
) -> Result<Round4Output, ProverError> {
    // Derive alpha.
    let mut t = Keccak256Transcript::new();
    t.add_scalar(&r3.xi_seed);
    for ev in [
        &r3.ql, &r3.qr, &r3.qm, &r3.qo, &r3.qc, &r3.s1, &r3.s2, &r3.s3, &r3.a, &r3.b, &r3.c, &r3.z,
        &r3.zw, &r3.t1w, &r3.t2w,
    ] {
        t.add_scalar(ev);
    }
    let alpha = t.get_challenge();

    // Compute roots.
    let roots = compute_fflonk_roots(&r3.xi_seed, &r1.header);

    // Read C0 coefficients (full polynomial — section 17).
    let c0_coeffs = read_fr_section(zkey_bytes, SECTION_C0)?;

    // R0: Lagrange interpolate through (h0w8[i], C0(h0w8[i])) for i in 0..8.
    let r0_coeffs = interpolate_at_roots(&c0_coeffs, &roots.h0w8);
    // R1: ... through (h1w4[i], C1(h1w4[i])) for i in 0..4.
    let r1_coeffs = interpolate_at_roots(&r1.c1_coeffs, &roots.h1w4);
    // R2: ... through (h2w3[0..3] ++ h3w3[0..3], C2(...)).
    let mut r2_points = Vec::with_capacity(6);
    for &x in &roots.h2w3 {
        r2_points.push((x, eval_horner(&r2.c2_coeffs, &x)));
    }
    for &x in &roots.h3w3 {
        r2_points.push((x, eval_horner(&r2.c2_coeffs, &x)));
    }
    let r2_coeffs = lagrange_interpolate(&r2_points);

    // F(X) = (C0 − R0)/(X^8 − xi) + α·(C1 − R1)/(X^4 − xi) + α²·(C2 − R2)/((X^3 − xi)(X^3 − xiw)).
    let mut f = c0_coeffs.clone();
    sub_assign(&mut f, &r0_coeffs);
    let f_q = div_by_x_n_minus_beta(&f, 8, &r3.xi)
        .ok_or_else(|| ProverError::Structural("(C0 − R0) not divisible by (X^8 − xi)".into()))?;

    let mut f2 = r1.c1_coeffs.clone();
    sub_assign(&mut f2, &r1_coeffs);
    scalar_mul_assign(&mut f2, &alpha);
    let f2_q = div_by_x_n_minus_beta(&f2, 4, &r3.xi)
        .ok_or_else(|| ProverError::Structural("(C1 − R1) not divisible by (X^4 − xi)".into()))?;

    let alpha_sq = alpha * alpha;
    let mut f3 = r2.c2_coeffs.clone();
    sub_assign(&mut f3, &r2_coeffs);
    scalar_mul_assign(&mut f3, &alpha_sq);
    let f3_q1 = div_by_x_n_minus_beta(&f3, 3, &r3.xi)
        .ok_or_else(|| ProverError::Structural("(C2 − R2) not divisible by (X^3 − xi)".into()))?;
    let f3_q = div_by_x_n_minus_beta(&f3_q1, 3, &r3.xiw).ok_or_else(|| {
        ProverError::Structural("(C2 − R2)/(X^3 − xi) not divisible by (X^3 − xiw)".into())
    })?;

    let mut f_coeffs = f_q;
    add_assign(&mut f_coeffs, &f2_q);
    add_assign(&mut f_coeffs, &f3_q);

    // KZG commit F → W1.
    let srs = read_g1_section(zkey_bytes, SECTION_PTAU)?;
    let f_commit_coeffs = trim_trailing_zeros(&f_coeffs);
    let w1_commitment = kzg::commit(f_commit_coeffs, &srs)?;

    Ok(Round4Output {
        alpha,
        roots,
        c0_coeffs,
        r0_coeffs,
        r1_coeffs,
        r2_coeffs,
        f_coeffs,
        w1_commitment,
    })
}

/// Compute (root, poly(root)) Lagrange interpolation for an array of roots
/// against a polynomial's coefficients via Horner.
fn interpolate_at_roots<const N: usize>(poly_coeffs: &[Fr], roots: &[Fr; N]) -> Vec<Fr> {
    let pts: Vec<(Fr, Fr)> = roots
        .iter()
        .map(|&x| (x, eval_horner(poly_coeffs, &x)))
        .collect();
    lagrange_interpolate(&pts)
}

// ============================================================================
// Round 5 (snarkjs's round5): y challenge, L(X) polynomial, W2 commitment.
// ============================================================================

#[derive(Debug, Clone)]
pub struct Round5Output {
    pub y: Fr,
    pub l_coeffs: Vec<Fr>,
    pub w2_commitment: G1Affine,
    /// The batched-inverse helper `inv = 1 / Π(all verifier denominators)`.
    /// Emitted in `proof.evaluations.inv` so the verifier avoids one inversion.
    pub inv: Fr,
}

pub fn round5(
    zkey_bytes: &[u8],
    r1: &Round1Output,
    r2: &Round2Output,
    r3: &Round3Evaluations,
    r4: &Round4Output,
) -> Result<Round5Output, ProverError> {
    // y = H(alpha || W1)
    let mut t = Keccak256Transcript::new();
    t.add_scalar(&r4.alpha);
    t.add_g1_point(&r4.w1_commitment);
    let y = t.get_challenge();

    // Evaluate R_i at y.
    let eval_r0_y = eval_horner(&r4.r0_coeffs, &y);
    let eval_r1_y = eval_horner(&r4.r1_coeffs, &y);
    let eval_r2_y = eval_horner(&r4.r2_coeffs, &y);

    // mulL0 = Π (y − h0w8[i]); mulL1 = Π (y − h1w4[i]); mulL2 = Π (y − h2w3[i])·Π (y − h3w3[i]).
    let mul_l0: Fr = r4.roots.h0w8.iter().map(|&h| y - h).product();
    let mul_l1: Fr = r4.roots.h1w4.iter().map(|&h| y - h).product();
    let mul_l2_h2: Fr = r4.roots.h2w3.iter().map(|&h| y - h).product();
    let mul_l2_h3: Fr = r4.roots.h3w3.iter().map(|&h| y - h).product();
    let mul_l2 = mul_l2_h2 * mul_l2_h3;

    let alpha = r4.alpha;
    let alpha_sq = alpha * alpha;
    let pre_l0 = mul_l1 * mul_l2;
    let pre_l1 = alpha * mul_l0 * mul_l2;
    let pre_l2 = alpha_sq * mul_l0 * mul_l1;

    // L(X) = (C0 − R0(y))·preL0 + (C1 − R1(y))·preL1 + (C2 − R2(y))·preL2 − F·ZT(y).
    let mut l = r4.c0_coeffs.clone();
    sub_scalar_assign(&mut l, &eval_r0_y);
    scalar_mul_assign(&mut l, &pre_l0);

    let mut l2 = r1.c1_coeffs.clone();
    sub_scalar_assign(&mut l2, &eval_r1_y);
    scalar_mul_assign(&mut l2, &pre_l1);
    add_assign(&mut l, &l2);

    let mut l3 = r2.c2_coeffs.clone();
    sub_scalar_assign(&mut l3, &eval_r2_y);
    scalar_mul_assign(&mut l3, &pre_l2);
    add_assign(&mut l, &l3);

    // ZT(y) = mulL0 · mulL1 · mulL2 (product over all 18 FFLONK roots).
    let eval_zt_y = mul_l0 * mul_l1 * mul_l2;
    let mut f_scaled = r4.f_coeffs.clone();
    scalar_mul_assign(&mut f_scaled, &eval_zt_y);
    sub_assign(&mut l, &f_scaled);

    // L /= ZTS2(y) = mulL1 · mulL2.
    let zts2_y = mul_l1 * mul_l2;
    let inv_zts2_y = zts2_y
        .inverse()
        .ok_or_else(|| ProverError::Structural("ZTS2(y) is zero".into()))?;
    scalar_mul_assign(&mut l, &inv_zts2_y);

    // Divide L by (X − y) — must be exact.
    let w_coeffs = div_by_linear(&l, &y).ok_or_else(|| {
        ProverError::Structural("L is not divisible by (X − y); proof malformed".into())
    })?;

    let srs = read_g1_section(zkey_bytes, SECTION_PTAU)?;
    let w2_commit_coeffs = trim_trailing_zeros(&w_coeffs);
    let w2_commitment = kzg::commit(w2_commit_coeffs, &srs)?;

    // Compute `inv` — the batched inverse of all verifier denominators.
    let inv = compute_inv(&r1.header, r3, r4, y, mul_l1, mul_l2)?;

    Ok(Round5Output {
        y,
        l_coeffs: w_coeffs,
        w2_commitment,
        inv,
    })
}

/// Compute the `inv` proof field = 1 / (product of all verifier-side
/// denominators that can be batch-inverted into a single scalar).
/// See snarkjs `getMontgomeryBatchedInverse` for the full list.
fn compute_inv(
    header: &FflonkHeader,
    r3: &Round3Evaluations,
    r4: &Round4Output,
    y: Fr,
    mul_l1: Fr,
    mul_l2: Fr,
) -> Result<Fr, ProverError> {
    let n = header.domain_size as usize;
    let xi = r3.xi;
    let xiw = r3.xiw;

    // Z_H(xi) = xi^n - 1.
    let mut xi_n = xi;
    let mut k = 1usize;
    while k < n {
        xi_n = xi_n * xi_n;
        k *= 2;
    }
    let zh_val = xi_n - Fr::one();

    let mut acc = Fr::one();
    acc *= zh_val;
    acc *= mul_l1;
    acc *= mul_l2;

    // LiS0 denominators (8 values).
    {
        let roots = &r4.roots.h0w8;
        let len = 8usize;
        let den1 = Fr::from(len as u64) * roots[0].pow([(len - 2) as u64]);
        for i in 0..len {
            let den2 = roots[((len - 1) * i) % len];
            let den3 = y - roots[i];
            acc *= den1 * den2 * den3;
        }
    }

    // LiS1 denominators (4 values).
    {
        let roots = &r4.roots.h1w4;
        let len = 4usize;
        let den1 = Fr::from(len as u64) * roots[0].pow([(len - 2) as u64]);
        for i in 0..len {
            let den2 = roots[((len - 1) * i) % len];
            let den3 = y - roots[i];
            acc *= den1 * den2 * den3;
        }
    }

    // LiS2 denominators (6 values — 3 for h2w3, 3 for h3w3).
    {
        let s2 = &r4.roots.h2w3;
        let s2p = &r4.roots.h3w3;
        let xisubxiw = xi - xiw;
        let three = Fr::from(3u64);
        let den1_a = three * s2[0] * xisubxiw;
        for i in 0..3 {
            let den2 = s2[(2 * i) % 3];
            let den3 = y - s2[i];
            acc *= den1_a * den2 * den3;
        }
        let xiwsubxi = xiw - xi;
        let den1_b = three * s2p[0] * xiwsubxi;
        for i in 0..3 {
            let den2 = s2p[(2 * i) % 3];
            let den3 = y - s2p[i];
            acc *= den1_b * den2 * den3;
        }
    }

    // Li_i for i in 1..=max(1, n_public): n · (xi − ω^i).
    {
        let n_public = header.n_public as usize;
        let size = n_public.max(1);
        let domain = Radix2EvaluationDomain::<Fr>::new(n).ok_or(ProverError::BadDomain { n })?;
        let n_fr = Fr::from(n as u64);
        let mut w = Fr::one();
        for _ in 0..size {
            acc *= n_fr * (xi - w);
            w *= domain.group_gen;
        }
    }

    acc.inverse()
        .ok_or_else(|| ProverError::Structural("inv denominator product is zero".into()))
}

/// Compute the 18 FFLONK roots from xi_seed and the zkey header's ω values.
fn compute_fflonk_roots(xi_seed: &Fr, header: &FflonkHeader) -> FflonkRoots {
    let xi_seed2 = *xi_seed * xi_seed;

    // w8 powers: [1, w8, w8^2, ..., w8^7]
    let mut w8 = [Fr::one(); 8];
    for i in 1..8 {
        w8[i] = w8[i - 1] * header.w8;
    }
    // w4 powers: [1, w4, w4^2, w4^3]
    let mut w4 = [Fr::one(); 4];
    for i in 1..4 {
        w4[i] = w4[i - 1] * header.w4;
    }
    // w3 powers: [1, w3, w3^2]
    let w3 = [Fr::one(), header.w3, header.w3 * header.w3];

    // h0 = xi_seed^3
    let h0 = xi_seed2 * xi_seed;
    let mut h0w8 = [Fr::zero(); 8];
    h0w8[0] = h0;
    for i in 1..8 {
        h0w8[i] = h0 * w8[i];
    }

    // h1 = h0^2 = xi_seed^6
    let h1 = h0 * h0;
    let mut h1w4 = [Fr::zero(); 4];
    h1w4[0] = h1;
    for i in 1..4 {
        h1w4[i] = h1 * w4[i];
    }

    // h2 = h1 * xi_seed^2 = xi_seed^8
    let h2 = h1 * xi_seed2;
    let h2w3 = [h2, h2 * w3[1], h2 * w3[2]];

    // h3 = h2 * wr
    let h3 = h2 * header.wr;
    let h3w3 = [h3, h3 * w3[1], h3 * w3[2]];

    FflonkRoots {
        h0w8,
        h1w4,
        h2w3,
        h3w3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Pre-flight: ark-poly's 8-th root of unity matches snarkjs's vkey.w.
    #[test]
    fn ark_poly_omega_8_matches_snarkjs_vkey() {
        let domain = Radix2EvaluationDomain::<Fr>::new(8).unwrap();
        let expected = Fr::from_str(
            "19540430494807482326159819597004422086093766032135589407132600596362845576832",
        )
        .unwrap();
        assert_eq!(
            domain.group_gen, expected,
            "ark-poly ω_8 must equal snarkjs ω_8"
        );
    }

    #[test]
    fn div_by_zh_x2_minus_1_over_x_minus_1() {
        // P(X) = X^2 - 1 = (X-1)(X+1). P / (X^1 - 1) = X + 1.
        let p = vec![-Fr::one(), Fr::zero(), Fr::one()];
        let q = div_by_zh(&p, 1).unwrap();
        assert_eq!(q, vec![Fr::one(), Fr::one()]);
    }

    #[test]
    fn div_by_zh_rejects_nondivisible() {
        // P(X) = X^2 + 1 is not divisible by X^1 - 1.
        let p = vec![Fr::one(), Fr::zero(), Fr::one()];
        assert!(matches!(
            div_by_zh(&p, 1),
            Err(ProverError::NotDivisibleByZh { .. })
        ));
    }

    #[test]
    fn cpoly_merge_interleaves_coefficients() {
        let a = vec![Fr::from(1u64), Fr::from(2u64)];
        let b = vec![Fr::from(10u64), Fr::from(20u64)];
        let c = vec![Fr::from(100u64), Fr::from(200u64)];
        let d = vec![Fr::from(1000u64), Fr::from(2000u64)];
        let merged = cpoly_fan_in_4_merge(&[&a, &b, &c, &d]);
        assert_eq!(
            merged,
            vec![
                Fr::from(1u64),
                Fr::from(10u64),
                Fr::from(100u64),
                Fr::from(1000u64),
                Fr::from(2u64),
                Fr::from(20u64),
                Fr::from(200u64),
                Fr::from(2000u64),
            ]
        );
    }

    #[test]
    fn cpoly_merge_zero_pads_shorter_polynomials() {
        let a = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let b = vec![Fr::from(10u64)]; // shorter
        let c = vec![Fr::from(100u64), Fr::from(200u64)];
        let d = vec![Fr::from(1000u64)];
        let merged = cpoly_fan_in_4_merge(&[&a, &b, &c, &d]);
        // max_len = 3, so output length = 12
        assert_eq!(merged.len(), 12);
        assert_eq!(merged[0], Fr::from(1u64));
        assert_eq!(merged[1], Fr::from(10u64));
        assert_eq!(merged[2], Fr::from(100u64));
        assert_eq!(merged[3], Fr::from(1000u64));
        assert_eq!(merged[4], Fr::from(2u64));
        assert_eq!(merged[5], Fr::zero()); // b has no coef at index 1
        assert_eq!(merged[6], Fr::from(200u64));
        assert_eq!(merged[7], Fr::zero()); // d has no coef at index 1
        assert_eq!(merged[8], Fr::from(3u64));
        assert_eq!(merged[9], Fr::zero());
        assert_eq!(merged[10], Fr::zero());
        assert_eq!(merged[11], Fr::zero());
    }
}
