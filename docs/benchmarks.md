# fflonk-prover benchmarks

Wall-clock prove time for the two committed fixtures, measured via
`fflonk-prover prove <zkey> <wtns> <out>`'s per-round timing breakdown.

## Methodology

- Release build (`cargo build --release`).
- Measurements are a single run (no statistical averaging) — variance is
  typically <10% run-to-run for these inputs.
- `read inputs` covers reading zkey (section 16 dominates — the PTau SRS is
  the largest slice) and the witness file.
- Each `round` includes all sub-steps of that round, including its KZG
  commitment's MSM.
- `write JSON` covers `serde_json::to_string_pretty` and two filesystem writes.

## Dev machine baseline (2026-04-17)

Hardware: Windows 11, measurement via Git Bash launching the release binary.

### With `parallel` feature enabled on ark-ff / ark-ec / ark-poly

| Circuit    | Constraints | Domain size | Total |
|------------|-------------|-------------|-------|
| multiplier | 2           | 8           | ~5 ms |
| poseidon   | ~63,911     | 65,536      | ~1.84 s |

Per-round poseidon breakdown:

```
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

### Before enabling `parallel` feature (baseline)

Same machine, `ark-ff/ark-ec/ark-poly` without the `parallel` feature flag.

| Circuit    | Total  | Speedup from `parallel` |
|------------|--------|-------------------------|
| multiplier | ~5 ms  | ≈ neutral (circuit is tiny) |
| poseidon   | ~11.4 s | ~6.2× faster with parallel |

Per-round poseidon breakdown (pre-`parallel`):

```
round 1           1.99s
round 2           2.47s
round 4           3.48s
round 5           3.38s
total            11.43s
```

## kysigned-approval on r5.4xlarge (2026-04-19)

The Phase 8 acceptance measurement. Run on a fresh AWS EC2 r5.4xlarge
(16 vCPU, 124 GiB RAM, Ubuntu 24.04, us-east-1, $1.008/hr on-demand).
Same hardware class as Candidate E (rapidsnark) for 1:1 comparison.

**Circuit:** `kysigned-approval.circom` placeholder (subjectHash <== 0
version) compiled from kysigned-private to:
- 4,677,123 raw R1CS constraints
- 8,360,022 PLONK constraints (after snarkjs R1CS → PLONK transpile)
- 3,682,892 additions (coalesced linear-combination signals)
- Domain size = 2^23 = 8,388,608
- zkey size = 27.5 GB

### Primary results

| Step | Wall-clock | CPU% | Peak RSS | Exit |
|---|---|---|---|---|
| snarkjs fflonk setup (one-time) | **1:21:07** | 441% | n/a | 0 |
| snarkjs fflonk prove (reference) | **1:49:06** | 267% | n/a | 0 |
| **our prover (`fflonk-prover prove`)** | **9:08.19** (548 s) | **617%** | **90.8 GB** | 0 |
| our-prover → snarkjs verify | PASS | — | — | 0 |
| our-prover → our Rust verify | PASS (4.15 ms) | — | — | 0 |
| our-prover → Solidity verify on Anvil | **PASS** (gas ≈ 75,964, Anvil-local) | — | — | 0 |

### Gate comparison against spec F3

| Gate | Target | Measured | Pass? |
|---|---|---|---|
| F3.2 wall-clock (4.7M constraints, 16 vCPU) | **< 20 s** | 548 s | ❌ **27× over target** |
| F3.2 soft ceiling | < 60 s | 548 s | ❌ **9× over** |
| F3.3 peak RAM | **< 8 GB** | 90.8 GB | ❌ **11× over** |
| F3.3 soft ceiling | — | — | — |
| F3.3 CPU utilization | > 400% (spec) | 617% | ✅ pass |
| F6.1 snarkjs-verify | PASS | PASS | ✅ |
| F6.2 on-chain verify (Anvil) | PASS | PASS | ✅ (Anvil gas; mainnet gas measurement deferred to kysigned track) |

Per DD-2, empirical waivers are permitted for F3 when the target is
aspirational. Both F3.2 and F3.3 miss by enough that waivers would be
significant (not "within a reasonable margin"). See
`docs/cost-reduction-questions.md` for the three open paths to close
the gap.

### Cost per proof (r5.4xlarge on-demand)

| Prover | Wall-clock | $/proof compute | vs. $0.15 cap |
|---|---|---|---|
| snarkjs FFLONK | 1:49:06 | $1.83 | 12× **over** |
| **fflonk-prover (us) v0.1.0** | 9:08 | **$0.154** | **~3% over** (kiss) |
| Target per $0.015/proof goal | 54 s | $0.015 | 10× optimization needed |

### vs. Candidate E (rapidsnark Groth16, same hardware)

| Metric | Candidate E (Groth16) | fflonk-prover v0.1.0 (FFLONK) |
|---|---|---|
| Proving wall-clock | 13.49 s | 548 s (40.6× slower) |
| Peak RSS | 3.57 GB | 90.8 GB (25× more) |
| CPU% | 1371% (16 cores fully lit) | 617% (6.17 cores used) |
| Proof size | 707 B | 2.3 KB |
| Public-signals size | 181 B | 203 B |
| On-chain gas (Base Sepolia measurement) | 255,820 | ~400K estimated (Anvil: 75,964 — unreliable, see note) |

**Note on Anvil gas (75,964):** appears anomalously low for FFLONK
Solidity verification which typically runs ~250K–400K on mainnet. The
proof verifies and the call succeeds, but Anvil's local gas metering
may not match mainnet's precompile pricing (2× `ecPairing` alone should
be ~113K per EIP-1108). Treat the Anvil number as "the verifier runs
end-to-end without reverting"; get mainnet gas via Base Sepolia
deployment in the kysigned track's 2F.G.

### Per-round cost breakdown (our prover, kysigned)

Not yet captured — `fflonk-prover prove` didn't print its per-round
breakdown to the captured log for the kysigned run (timing was to
`/usr/bin/time -v` which measures the whole process). For per-round
investigation, rerun with `RUST_LOG=debug` or read the `our-prove.log`
file. A follow-up capture would help pinpoint which round dominates —
current suspicion is Round 1/4/5 (the 4n-domain FFTs + C0 + F + L
multi-gigabyte polynomial arithmetic).

## Extrapolation to kysigned (laptop, pre-EC2)

Kept for history: laptop-based extrapolation from poseidon (1.84 s at
63K constraints) predicted **~135 s** for kysigned. Actual EC2 result
(548 s) is 4× worse than that linear extrapolation — suggesting either
(a) the large-circuit constant-factor overhead is nonlinear with domain
size (likely — 8n G1 points loaded from the PTau section dominate MSM
costs for small n but memory bandwidth saturates for large n), or (b)
laptop-to-EC2 hardware differences are offset by worse absolute
constants at scale.

## How to reproduce

```sh
# Multiplier
time target/release/fflonk-prover prove \
  tests/fixtures/multiplier/circuit.zkey \
  tests/fixtures/multiplier/witness.wtns \
  /tmp/proof.json /tmp/public.json

# Poseidon
time target/release/fflonk-prover prove \
  tests/fixtures/poseidon/circuit.zkey \
  tests/fixtures/poseidon/witness.wtns \
  /tmp/proof.json /tmp/public.json
```

The per-round timing breakdown prints to stderr automatically.

```sh
# Kysigned (r5.4xlarge only — 27 GB zkey won't run on a laptop)
# Fetch circuit.zkey from s3 per tests/fixtures/kysigned/README.md, then:
/usr/bin/time -v target/release/fflonk-prover prove \
  tests/fixtures/kysigned/circuit.zkey \
  tests/fixtures/kysigned/witness.wtns \
  /tmp/proof.json /tmp/public.json
```
