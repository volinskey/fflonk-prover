//! CLI integration tests — spawn the `fflonk-prover` binary and exercise its
//! subcommands from the user's perspective.

use std::path::PathBuf;
use std::process::Command;

fn bin_path() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // remove test binary name
    if p.ends_with("deps") {
        p.pop();
    }
    let name = if cfg!(windows) {
        "fflonk-prover.exe"
    } else {
        "fflonk-prover"
    };
    p.join(name)
}

#[test]
fn cli_version_flag() {
    let out = Command::new(bin_path()).arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("0.1.0"),
        "--version should print 0.1.0, got: {stdout}"
    );
}

#[test]
fn cli_info_multiplier() {
    let out = Command::new(bin_path())
        .args(["info", "tests/fixtures/multiplier/circuit.zkey"])
        .output()
        .unwrap();
    assert!(out.status.success(), "info exited non-zero");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("protocol:      fflonk"));
    assert!(stdout.contains("nPublic:       1"));
    assert!(stdout.contains("domainSize:    8"));
}

#[test]
fn cli_prove_emits_valid_outputs() {
    let tmp = tempdir();
    let proof = tmp.join("proof.json");
    let public = tmp.join("public.json");

    let out = Command::new(bin_path())
        .args([
            "prove",
            "tests/fixtures/multiplier/circuit.zkey",
            "tests/fixtures/multiplier/witness.wtns",
            proof.to_str().unwrap(),
            public.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "prove exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Structural checks on the outputs.
    let proof_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&proof).unwrap()).unwrap();
    assert_eq!(proof_json["protocol"], "fflonk");
    assert_eq!(proof_json["curve"], "bn128");
    for key in ["C1", "C2", "W1", "W2"] {
        assert_eq!(
            proof_json["polynomials"][key].as_array().unwrap().len(),
            3,
            "{key} must be [x, y, 1]"
        );
    }
    for key in [
        "ql", "qr", "qm", "qo", "qc", "s1", "s2", "s3", "a", "b", "c", "z", "zw", "t1w", "t2w",
        "inv",
    ] {
        assert!(
            proof_json["evaluations"][key].is_string(),
            "evaluations.{key} must be a string"
        );
    }

    let public_json: Vec<String> =
        serde_json::from_str(&std::fs::read_to_string(&public).unwrap()).unwrap();
    assert_eq!(public_json.len(), 1);
    assert_eq!(public_json[0], "33", "multiplier public signal = 33");
}

#[test]
fn cli_verify_reference_proof_exits_0() {
    let out = Command::new(bin_path())
        .args([
            "verify",
            "tests/fixtures/multiplier/vkey.json",
            "tests/fixtures/multiplier/reference_public.json",
            "tests/fixtures/multiplier/reference_proof.json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "verify exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("VERIFIED"),
        "stderr should contain VERIFIED: {stderr}"
    );
}

#[test]
fn cli_verify_wrong_public_exits_2() {
    let tmp = tempdir();
    let bad_public = tmp.join("public.json");
    std::fs::write(&bad_public, b"[\"34\"]").unwrap();
    let out = Command::new(bin_path())
        .args([
            "verify",
            "tests/fixtures/multiplier/vkey.json",
            bad_public.to_str().unwrap(),
            "tests/fixtures/multiplier/reference_proof.json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "verify must exit 2 for rejected proof, got: {:?}",
        out.status.code()
    );
}

#[test]
fn cli_prove_then_verify_roundtrip_multiplier() {
    let tmp = tempdir();
    let proof = tmp.join("proof.json");
    let public = tmp.join("public.json");

    let out = Command::new(bin_path())
        .args([
            "prove",
            "tests/fixtures/multiplier/circuit.zkey",
            "tests/fixtures/multiplier/witness.wtns",
            proof.to_str().unwrap(),
            public.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "prove: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = Command::new(bin_path())
        .args([
            "verify",
            "tests/fixtures/multiplier/vkey.json",
            public.to_str().unwrap(),
            proof.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "our verifier must accept our prover's output: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_prove_with_bogus_zkey_exits_1() {
    let tmp = tempdir();
    let bogus = tmp.join("not-a-zkey");
    std::fs::write(&bogus, b"garbage").unwrap();
    let proof = tmp.join("proof.json");
    let public = tmp.join("public.json");

    let out = Command::new(bin_path())
        .args([
            "prove",
            bogus.to_str().unwrap(),
            "tests/fixtures/multiplier/witness.wtns",
            proof.to_str().unwrap(),
            public.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "invalid zkey must exit 1, got: {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn tempdir() -> PathBuf {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros())
        .unwrap_or(0);
    let dir = base.join(format!("fflonk-prover-cli-{pid}-{micros}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
