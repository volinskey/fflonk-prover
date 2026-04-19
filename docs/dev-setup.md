# Developer Setup

This document covers the tooling you need to work on `fflonk-prover`. CI uses committed fixtures so none of the heavy tooling is required to merge a PR — these steps are only for regenerating fixtures, doing the Phase 5 on-chain integration test locally, or developing features.

## Required (always)

| Tool | Version | Install |
|------|---------|---------|
| Rust | 1.85+ (edition 2021) | [rustup.rs](https://rustup.rs) |
| cargo-deny | latest | `cargo install cargo-deny --locked` |

## Required for fixture regeneration (rare — see `tests/fixtures/README.md`)

| Tool | Version | Install |
|------|---------|---------|
| Node.js | 20 LTS or 22 LTS | [nodejs.org](https://nodejs.org) |
| snarkjs | 0.7.6 (pinned — see DD-1) | Used via `npx -y snarkjs@0.7.6` (no global install needed) |
| circom | 2.x | `cargo install --git https://github.com/iden3/circom.git circom --locked` |
| AWS CLI | 2.x | [aws.amazon.com/cli](https://aws.amazon.com/cli/) — for downloading ptau from S3 |

### Powers of Tau

Two Hermez PTau files are used in this project:

| File | Size | Supports | Used for |
|------|------|----------|----------|
| `powersOfTau28_hez_final_23.ptau` | ~9.7 GB | 2²³ constraints (FFLONK needs up to 2²⁰ circuits) | `multiplier`, `poseidon` fixtures |
| `powersOfTau28_hez_final_26.ptau` | ~77 GB | 2²⁶ constraints (FFLONK needs up to 2²³ circuits) | `kysigned-approval` fixture (~4.7M constraints) |

**Why FFLONK setup needs a larger PTau than the circuit's domain_size suggests:** FFLONK's `fflonk setup` requires Section 2 (G1 series) of the PTau to hold at least `(9 · domain_size + 18) · 64` bytes. For `domain_size = 2^23`, that's ~4.83 GB of G1 points. The `_final_23.ptau` Section 2 holds only ~1 GB — so we need `_final_26.ptau` for anything near 2²³ constraints.

PTau files are NOT committed to the repo (too large) and NOT required by CI — CI uses committed fixtures.

**Kychee S3 (fast, if you have AWS access):**
```bash
aws s3 cp s3://kychee-zkprover-artifacts/shared/powersOfTau28_hez_final_23.ptau fixtures-src/ptau/ --profile kychee
# _final_26.ptau is not yet in S3; use the Hermez fallback below.
```

**Hermez canonical (public, free, slower):**
```bash
curl -L -o fixtures-src/ptau/powersOfTau28_hez_final_23.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_23.ptau
curl -L -o fixtures-src/ptau/powersOfTau28_hez_final_26.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_26.ptau
```

The `fixtures-src/` directory is gitignored.

## Required for Phase 5 on-chain integration tests

| Tool | Version | Install |
|------|---------|---------|
| Foundry (anvil + forge) | 1.5.1-stable (pinned for Phase 8 acceptance — any 1.x works) | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` (Linux/macOS, and Git Bash on Windows). Installs to `~/.foundry/bin` — add to PATH or `export PATH="$HOME/.foundry/bin:$PATH"` in your shell rc. |

## Verify your setup

```bash
rustc --version              # 1.85+
cargo deny --version         # present
node --version               # v20+ or v22+
npx -y snarkjs@0.7.6 --version   # snarkjs@0.7.6
circom --version             # 2.x.x
aws --version                # 2.x (only for S3 ptau)
anvil --version              # only for Phase 5
```

## Common commands

```bash
cargo build                                    # compile
cargo test                                     # full test suite
cargo fmt --all -- --check                     # format check (CI-equivalent)
cargo clippy --all-targets -- -D warnings      # lint (CI-equivalent)
cargo deny check licenses                      # license audit
./scripts/regenerate-fixtures.sh multiplier    # regenerate one fixture circuit
./scripts/regenerate-fixtures.sh poseidon      # regenerate another
```

## Why snarkjs is pinned

FFLONK challenge derivation and encoding have drifted across snarkjs versions. "Byte-compatible with snarkjs" is undefined without a pinned version. DD-1 in [the plan](plans/fflonk-prover-plan.md) pins snarkjs 0.7.6 as the compatibility target. Updating the pin requires regenerating all committed fixtures.
