//! End-to-end correctness test: run our prover and confirm snarkjs accepts
//! the resulting proof. This is the authoritative correctness gate for
//! everything from zkey parsing through Round 5.
//!
//! Requires: Node.js on PATH and `npx snarkjs@0.7.6 fflonk verify ...` able to
//! run. Tests that can't shell out to npx are skipped with a diagnostic.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use fflonk_prover::prover::{Round1Blinders, Round2Blinders};
use fflonk_prover::{proof::public_signals_json, prove};

/// Windows uses `npx.cmd`; Linux/macOS uses `npx`.
fn npx_cmd() -> &'static str {
    if cfg!(windows) {
        "npx.cmd"
    } else {
        "npx"
    }
}

/// We cannot cheaply probe "is snarkjs installed" via --version (snarkjs exits 99
/// because --version isn't a real subcommand) without actually running a verify.
/// Instead: check that `npx.cmd` is invokable at all. If snarkjs isn't installed
/// yet, `npx --yes` downloads it on first run (slow but robust).
fn have_npx() -> bool {
    Command::new(npx_cmd())
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_verify_test(circuit_dir: &Path) {
    if !have_npx() {
        eprintln!(
            "SKIP: `npx` unavailable in this environment — cannot run snarkjs fflonk verify."
        );
        return;
    }

    let zkey = circuit_dir.join("circuit.zkey");
    let witness = circuit_dir.join("witness.wtns");
    let vkey = circuit_dir.join("vkey.json");

    let (proof, public) = prove(
        &zkey,
        &witness,
        &Round1Blinders::zero(),
        &Round2Blinders::zero(),
    )
    .expect("prove");

    let tmp = tempdir();
    let proof_path = tmp.join("proof.json");
    let public_path = tmp.join("public.json");
    std::fs::write(&proof_path, serde_json::to_string_pretty(&proof).unwrap()).unwrap();
    std::fs::write(&public_path, public_signals_json(&public)).unwrap();

    let output = Command::new(npx_cmd())
        .args([
            "--yes",
            "snarkjs@0.7.6",
            "fflonk",
            "verify",
            vkey.to_str().unwrap(),
            public_path.to_str().unwrap(),
            proof_path.to_str().unwrap(),
        ])
        .output()
        .expect("run snarkjs verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("--- snarkjs stdout ---\n{stdout}");
    println!("--- snarkjs stderr ---\n{stderr}");

    assert!(
        output.status.success(),
        "snarkjs fflonk verify rejected our proof (exit {:?}). stdout: {stdout}, stderr: {stderr}",
        output.status.code()
    );
    // snarkjs prints "OK" or similar on success; PROOF VERIFIED SUCCESSFULLY is
    // the explicit log line. But exit code 0 is sufficient for pass/fail.
    assert!(
        stdout.contains("VERIFIED") || stderr.contains("VERIFIED"),
        "snarkjs output should contain VERIFIED on success; got stdout={stdout}, stderr={stderr}"
    );
}

fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    let dir = base.join(format!("fflonk-prover-test-{pid}-{micros}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// tempfile-less helper: write proof.json straight. (no extra dep needed)
fn _write_to(path: &Path, content: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
}

#[test]
fn multiplier_proof_verifies_with_snarkjs() {
    run_verify_test(Path::new("tests/fixtures/multiplier"));
}

#[test]
#[ignore = "slow (~2 min poseidon); run with --ignored"]
fn poseidon_proof_verifies_with_snarkjs() {
    run_verify_test(Path::new("tests/fixtures/poseidon"));
}
