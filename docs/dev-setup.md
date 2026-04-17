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

The Phase 1 Hermez SRS (`powersOfTau28_hez_final_23.ptau`, ~9 GB, supports up to 2²³ = 8.4M constraints) is used once to generate FFLONK proving/verification keys via snarkjs. It is NOT committed to the repo (too large) and NOT required by CI — CI uses committed fixtures.

Two sources:

**Kychee S3 (fast, if you have AWS access):**
```bash
aws s3 cp s3://kychee-zkprover-artifacts/shared/powersOfTau28_hez_final_23.ptau fixtures-src/ptau/
```

**Hermez canonical (public, free, slower):**
```bash
curl -L -o fixtures-src/ptau/powersOfTau28_hez_final_23.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_23.ptau
```

The `fixtures-src/` directory is gitignored.

## Required for Phase 5 on-chain integration tests

| Tool | Version | Install |
|------|---------|---------|
| Foundry (anvil + forge) | latest | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` (Linux/macOS) — see [book.getfoundry.sh](https://book.getfoundry.sh) for Windows |

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
