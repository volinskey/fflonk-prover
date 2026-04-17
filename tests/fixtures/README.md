# Test Fixtures

This directory contains pre-generated FFLONK proof artifacts. They are the correctness ground-truth for this crate: tests compare the Rust prover's output against these reference artifacts byte-for-byte.

## Per-circuit contents

Each subdirectory (`multiplier/`, `poseidon/`, ...) contains:

| File | Purpose |
|------|---------|
| `<circuit>.r1cs` | Circuit constraints from `circom` |
| `<circuit>.wasm` | Witness calculator WASM from `circom` |
| `<circuit>.sym` | Symbol table (for debugging) |
| `circuit.zkey` | FFLONK proving key from `snarkjs fflonk setup` |
| `vkey.json` | Verification key from `snarkjs zkey export verificationkey` |
| `verifier.sol` | Solidity verifier contract from `snarkjs zkey export solidityverifier` |
| `sample_input.json` | Public+private signals in snarkjs's input format |
| `witness.wtns` | Witness bytes produced by the WASM from `sample_input.json` |
| `reference_proof.json` | Reference proof from `snarkjs fflonk prove` |
| `reference_public.json` | Reference public signals (matches `reference_proof.json`) |

## When to regenerate

Regenerate fixtures when **any** of these change:

1. **The snarkjs pin in DD-1 bumps** (currently pinned to `0.7.6` — see [the plan](../../docs/plans/fflonk-prover-plan.md)). A snarkjs minor version can silently alter Fiat-Shamir challenge ordering or point serialization, breaking byte-compatibility. Regenerating recaptures the new reference behaviour.
2. **A circuit definition changes** — e.g., editing `circuits/multiplier.circom`. The R1CS and everything downstream change.
3. **The sample input changes** — editing `circuits/<circuit>_input.json` changes the witness and therefore the proof.
4. **The ptau changes** — unlikely, but if we move to a different trusted setup the zkey changes.

CI never regenerates fixtures; it just reads them. Fixture regeneration is a deliberate developer action gated on the conditions above.

## How to regenerate

From the repo root (in the worktree during implementation):

```bash
./scripts/regenerate-fixtures.sh multiplier
./scripts/regenerate-fixtures.sh poseidon
```

Prerequisites are documented in [docs/dev-setup.md](../../docs/dev-setup.md). In brief: circom, Node, snarkjs@0.7.6 (used via `npx`), and the 9GB Hermez ptau at `fixtures-src/ptau/`.

After running the script, inspect `git diff tests/fixtures/` — most of these files are binary, but `reference_proof.json`, `reference_public.json`, `vkey.json`, `verifier.sol`, and `sample_input.json` are JSON/Solidity and the diff is readable. Commit the update as a single PR with the reason in the message (e.g., `fixtures: regenerate for snarkjs 0.7.7 bump`).

## Why these fixtures are committed

CI runs on every PR need to verify proof byte-compatibility quickly. Running `snarkjs fflonk setup` in CI is minutes-slow (depends on ptau size and circuit size) and requires the 9GB ptau file. Committing the setup outputs means CI only runs the fast steps (witness, Rust prove, compare to reference, snarkjs JS-verify). Binary fixture size is on the order of hundreds of KB to a few MB per circuit — cheap to commit, massive CI speedup.
