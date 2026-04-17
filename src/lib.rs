//! FFLONK prover — native Rust FFLONK prover for Circom R1CS circuits.
//!
//! Byte-compatible with snarkjs 0.7.6 FFLONK Solidity verifiers on BN254.

pub mod challenges;
pub mod kzg;
pub mod poly;
pub mod proof;
pub mod prover;
pub mod transcript;
pub mod verifier;
pub mod vkey;
pub mod wtns;
pub mod zkey;

use std::path::Path;
use std::time::{Duration, Instant};

use ark_bn254::Fr;

/// Per-round wall-clock timings emitted by `prove_timed`.
#[derive(Debug, Clone, Default)]
pub struct ProveTimings {
    pub read_inputs: Duration,
    pub round1: Duration,
    pub round2: Duration,
    pub round3: Duration,
    pub round4: Duration,
    pub round5: Duration,
    pub serialize: Duration,
    pub total: Duration,
}

/// High-level entry point: produce a snarkjs-compatible FFLONK proof.
///
/// Reads the zkey and witness from disk, runs all 5 prover rounds with the
/// supplied blinding (use `Round1Blinders::zero()` / `Round2Blinders::zero()`
/// for deterministic non-ZK proofs — useful for correctness tests), and returns
/// the assembled `Proof` struct alongside the public signals.
pub fn prove(
    zkey_path: &Path,
    witness_path: &Path,
    r1_blinders: &prover::Round1Blinders,
    r2_blinders: &prover::Round2Blinders,
) -> Result<(proof::Proof, Vec<Fr>), ProveError> {
    let (proof, public, _) = prove_timed(zkey_path, witness_path, r1_blinders, r2_blinders)?;
    Ok((proof, public))
}

/// Like [`prove`] but also returns per-round wall-clock timings for profiling.
pub fn prove_timed(
    zkey_path: &Path,
    witness_path: &Path,
    r1_blinders: &prover::Round1Blinders,
    r2_blinders: &prover::Round2Blinders,
) -> Result<(proof::Proof, Vec<Fr>, ProveTimings), ProveError> {
    let total_start = Instant::now();

    let t0 = Instant::now();
    let zkey_bytes = std::fs::read(zkey_path)?;
    let witness = wtns::read_from_path(witness_path)?.values;
    let read_inputs = t0.elapsed();

    let t0 = Instant::now();
    let r1 = prover::round1(&zkey_bytes, &witness, r1_blinders)?;
    let round1 = t0.elapsed();

    let n_public = r1.header.n_public as usize;
    if witness.len() < n_public + 1 {
        return Err(ProveError::Prover(prover::ProverError::Structural(
            format!(
                "witness has {} values, fewer than n_public+1 = {}",
                witness.len(),
                n_public + 1
            ),
        )));
    }
    let public_inputs: Vec<Fr> = (1..=n_public).map(|j| witness[j]).collect();

    let (beta, gamma) =
        challenges::derive_beta_gamma(&r1.header.c0, &public_inputs, &r1.c1_commitment);

    let t0 = Instant::now();
    let r2 = prover::round2(&zkey_bytes, &r1, beta, gamma, r2_blinders)?;
    let round2 = t0.elapsed();

    let t0 = Instant::now();
    let r3 = prover::round3(&zkey_bytes, &r1, &r2, gamma)?;
    let round3 = t0.elapsed();

    let t0 = Instant::now();
    let r4 = prover::round4(&zkey_bytes, &r1, &r2, &r3)?;
    let round4 = t0.elapsed();

    let t0 = Instant::now();
    let r5 = prover::round5(&zkey_bytes, &r1, &r2, &r3, &r4)?;
    let round5 = t0.elapsed();

    let t0 = Instant::now();
    let proof = proof::build_proof(&r1, &r2, &r3, &r4, &r5);
    let serialize = t0.elapsed();

    let timings = ProveTimings {
        read_inputs,
        round1,
        round2,
        round3,
        round4,
        round5,
        serialize,
        total: total_start.elapsed(),
    };
    Ok((proof, public_inputs, timings))
}

#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("witness parse: {0}")]
    Wtns(#[from] wtns::WtnsError),
    #[error("prover: {0}")]
    Prover(#[from] prover::ProverError),
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_package() {
        assert_eq!(VERSION, "0.1.0");
    }
}
