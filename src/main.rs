//! fflonk-prover CLI.
//!
//! Subcommands:
//! - `prove <zkey> <witness> <proof_out> <public_out>` — generate a proof.
//! - `info <zkey>` — print zkey metadata (protocol, curve, constraints...).
//! - `verify` — not yet implemented (use `snarkjs fflonk verify` for now).
//!
//! Exit codes:
//!   0  success
//!   1  invalid input / prove failed
//!   2  verify failed (not used yet)

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};

use fflonk_prover::prover::{Round1Blinders, Round2Blinders};
use fflonk_prover::verifier::verify_paths;
use fflonk_prover::{proof::public_signals_json, prove_timed};

#[derive(Debug, Parser)]
#[command(name = "fflonk-prover", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Parallel threads for FFT / MSM (defaults to physical core count).
    #[arg(long, global = true)]
    threads: Option<usize>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate a FFLONK proof from a zkey and witness.
    Prove {
        zkey: PathBuf,
        witness: PathBuf,
        proof_out: PathBuf,
        public_out: PathBuf,
    },
    /// Verify a FFLONK proof locally. Not yet implemented — use `snarkjs fflonk verify`.
    Verify {
        vkey: PathBuf,
        public: PathBuf,
        proof: PathBuf,
    },
    /// Print zkey metadata.
    Info { zkey: PathBuf },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Some(threads) = cli.threads {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global();
    }

    match cli.cmd {
        Cmd::Prove {
            zkey,
            witness,
            proof_out,
            public_out,
        } => run_prove(&zkey, &witness, &proof_out, &public_out),
        Cmd::Info { zkey } => run_info(&zkey),
        Cmd::Verify {
            vkey,
            public,
            proof,
        } => run_verify(&vkey, &public, &proof),
    }
}

fn run_prove(zkey: &Path, witness: &Path, proof_out: &Path, public_out: &Path) -> ExitCode {
    eprintln!("fflonk-prover: proving");
    eprintln!("  zkey    = {}", zkey.display());
    eprintln!("  witness = {}", witness.display());

    let result = prove_timed(
        zkey,
        witness,
        &Round1Blinders::zero(),
        &Round2Blinders::zero(),
    );

    let (proof, public, t) = match result {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: prove failed: {e}");
            return ExitCode::from(1);
        }
    };

    let write_start = Instant::now();
    let proof_json = match serde_json::to_string_pretty(&proof) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: serialize proof: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = std::fs::write(proof_out, proof_json) {
        eprintln!("error: write {}: {e}", proof_out.display());
        return ExitCode::from(1);
    }
    if let Err(e) = std::fs::write(public_out, public_signals_json(&public)) {
        eprintln!("error: write {}: {e}", public_out.display());
        return ExitCode::from(1);
    }
    let write_time = write_start.elapsed();

    eprintln!("fflonk-prover: timing breakdown");
    eprintln!("  read inputs  {:>10.2?}", t.read_inputs);
    eprintln!("  round 1      {:>10.2?}  (A/B/C, T0, C1)", t.round1);
    eprintln!("  round 2      {:>10.2?}  (Z, T1, T2, C2)", t.round2);
    eprintln!("  round 3      {:>10.2?}  (16 evaluations at xi)", t.round3);
    eprintln!("  round 4      {:>10.2?}  (F, W1)", t.round4);
    eprintln!("  round 5      {:>10.2?}  (L, W2, inv)", t.round5);
    eprintln!(
        "  serialize    {:>10.2?}  (build proof struct)",
        t.serialize
    );
    eprintln!(
        "  write JSON   {:>10.2?}  ({} + {})",
        write_time,
        proof_out.display(),
        public_out.display()
    );
    eprintln!("  total        {:>10.2?}", t.total + write_time);
    ExitCode::SUCCESS
}

fn run_verify(vkey: &Path, public: &Path, proof: &Path) -> ExitCode {
    let start = Instant::now();
    match verify_paths(vkey, public, proof) {
        Ok(true) => {
            eprintln!(
                "fflonk-prover: PROOF VERIFIED SUCCESSFULLY ({:.2?})",
                start.elapsed()
            );
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("fflonk-prover: proof rejected ({:.2?})", start.elapsed());
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("error: verify failed: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_info(zkey: &Path) -> ExitCode {
    let bytes = match std::fs::read(zkey) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {}: {e}", zkey.display());
            return ExitCode::from(1);
        }
    };
    let header = match fflonk_prover::zkey::read_fflonk_header(&bytes) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("error: parse zkey: {e}");
            return ExitCode::from(1);
        }
    };
    println!("protocol:      fflonk");
    println!("curve:         bn128");
    println!("nVars:         {}", header.n_vars);
    println!("nPublic:       {}", header.n_public);
    println!("nConstraints:  {}", header.n_constraints);
    println!("nAdditions:    {}", header.n_additions);
    println!("domainSize:    {}", header.domain_size);
    ExitCode::SUCCESS
}
