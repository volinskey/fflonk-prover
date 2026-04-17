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

## Extrapolation to the kysigned-approval circuit

The kysigned-approval circuit is **~4.7 M constraints**, ~74× larger than
the poseidon fixture's effective size. FFLONK round costs scale roughly
linearly with `domain_size` for the dominant operations (4n-domain FFTs/iFFTs
+ MSMs). Linear extrapolation from the poseidon `1.84 s` baseline:

```
kysigned_estimate ≈ 1.84s × (4_700_000 / 63_911)
                  ≈ 1.84s × 73.5
                  ≈ 135 s   (~2.3 min)
```

**This exceeds the spec's 20 s target by ~6.7×** on the current dev machine
with the current implementation. Phase 7 requires either (a) larger CPU (16-
vCPU r5.4xlarge as the spec specifies for acceptance testing), (b) a faster
MSM backend than stock `ark-ec`, or (c) both.

Reasons to expect dev-machine estimates to be pessimistic:
- The target hardware is 16 physical vCPU vs. a laptop — large parallel
  speedup in MSM / FFT over current dev numbers.
- Release-build MSM on bn254 with `ark-ec`'s Pippenger is not the fastest
  available — candidates include `halo2_curves`, `blitzar-rs`, or a custom
  Pippenger with the GLV endomorphism.

**Action:** measure kysigned end-to-end on the r5.4xlarge before any
optimization work. Stock `ark-ec` + 16 physical cores might already land
under 20 s; if not, the decision point opens per DD-8.

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
