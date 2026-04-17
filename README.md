# fflonk-prover

Native Rust FFLONK prover for Circom R1CS circuits. Produces proofs that the
snarkjs 0.7.6 FFLONK verifier (JavaScript CLI or generated Solidity contract)
accepts byte-for-byte.

Why it exists: snarkjs is the standard FFLONK prover in the Circom toolchain
but runs in JavaScript and is slow. `fflonk-prover` is a drop-in replacement
for the prove step with identical output semantics — generate your proving key
once with `snarkjs fflonk setup`, then use this crate in production paths
where prove time matters.

## Compatibility

- **snarkjs:** `0.7.6` (pinned — FFLONK transcript/commitment ordering has
  drifted across snarkjs versions; the zkey format too. Fixtures regenerate
  via `scripts/regenerate-fixtures.sh` if the pin bumps).
- **Curve:** BN254 only. Any BN254 snarkjs-produced `.zkey` works.
- **Verifier:** both `snarkjs fflonk verify` and the Solidity contract
  emitted by `snarkjs fflonk exportsoliditycalldata` accept proofs from this
  crate.

## Install

### CLI (via cargo)

```sh
cargo install fflonk-prover
fflonk-prover --version
```

### Library (Rust dependency)

```toml
[dependencies]
fflonk-prover = "0.1"
```

## CLI usage

```sh
# Generate a proof
fflonk-prover prove circuit.zkey witness.wtns proof.json public.json

# Inspect a zkey's metadata
fflonk-prover info circuit.zkey

# Verify — not yet implemented. Shell out to snarkjs:
npx snarkjs@0.7.6 fflonk verify vkey.json public.json proof.json
```

The CLI emits a per-round timing breakdown on stderr:

```
fflonk-prover: timing breakdown
  read inputs     51.71ms
  round 1        321.98ms  (A/B/C, T0, C1)
  round 2        416.71ms  (Z, T1, T2, C2)
  round 3         50.40ms  (16 evaluations at xi)
  round 4        588.04ms  (F, W1)
  round 5        406.07ms  (L, W2, inv)
  serialize       31.20µs
  write JSON     627.00µs
  total            1.84s
```

### Flags

- `--threads <N>` — override the rayon thread pool size (default: physical core count).

### Exit codes

- `0` — success
- `1` — invalid input or prove failed (bad zkey, bad witness, etc.)
- `2` — verify failed (reserved for the upcoming `verify` subcommand)

## Library usage

```rust
use std::path::Path;

use fflonk_prover::{prove, prover::{Round1Blinders, Round2Blinders}};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (proof, public_signals) = prove(
        Path::new("circuit.zkey"),
        Path::new("witness.wtns"),
        // For production, swap these for randomized blinders (see
        // `Round1Blinders`/`Round2Blinders` docs). `::zero()` produces
        // deterministic, non-zero-knowledge proofs — fine for testing.
        &Round1Blinders::zero(),
        &Round2Blinders::zero(),
    )?;

    std::fs::write("proof.json", serde_json::to_string_pretty(&proof)?)?;
    std::fs::write(
        "public.json",
        fflonk_prover::proof::public_signals_json(&public_signals),
    )?;
    Ok(())
}
```

For profiling, use `prove_timed` which returns a `ProveTimings` struct.

## Performance

On a dev laptop (Windows, single user process):

| Circuit    | Constraints | Prove time |
|------------|-------------|------------|
| multiplier | 2           | ~5 ms      |
| poseidon   | ~32,768     | ~1.84 s    |

Larger circuits benefit from the `parallel` feature already enabled on all
arkworks dependencies. See [`docs/benchmarks.md`](docs/benchmarks.md) for
the full breakdown + extrapolation to larger circuits.

## Limitations

- **v0.1.0 does not ship its own Rust verifier.** `verify` is a planned
  Phase 4 task; today, use `snarkjs fflonk verify` or the Solidity verifier
  for verification.
- **No `prove-from-input` yet.** You must generate the witness externally
  (e.g., via the Circom-generated WASM witness calculator) and pass the
  `.wtns` file.
- **`getWitness` additions.** Snarkjs's getWitness handles the zkey
  "additions" optimization (linear-combination signals). Simple circuits
  don't hit this; complex circuits with n_additions > 0 may not yet be
  supported.

## Security model

The prover is **outside the trust boundary** by design. It cannot forge
proofs regardless of implementation bugs — it can only produce valid proofs
(verifier accepts), invalid proofs (verifier rejects), or crash. System
security lives in the circuit, the verifier, and the SRS (Hermez PPoT).
The prover is a performance optimization, not a security component.

## License

MIT.
