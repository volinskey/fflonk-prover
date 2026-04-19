# Cost-reduction open questions — targeting $0.015 per proof

Phase 8 measured the fflonk-prover v0.1.0 at **$0.154/proof** on r5.4xlarge
(9:08 wall-clock × $1.008/hr). The kysigned economic model's hard cap is
**$0.15/proof** (kissed, effectively a fail at production scale). The
aspirational target from the user is **$0.015/proof — 10× lower**.

Three orthogonal paths could each deliver part (or all) of that 10×.
We've measured enough of the blackbox now that the right next step is
a dedicated investigation / spec conversation on each, *before* we spend
more engineering on any one of them.

**Record as a trio of parallel open questions. Pick in order of
expected payoff × lowest risk, not necessarily in order below.**

---

## Q1. Can we optimize the current fflonk-prover black-box to 10×?

**Claim to test:** with the same spec (same FFLONK proof system, same
Circom `@zk-email/circuits` audited stack, no spec changes), we can
shave the prover from 548 s / 90.8 GB / 617% CPU down to ≤ 54 s with
≤ ~30 GB RSS on r5.4xlarge.

### Concrete attack surface (ordered by expected payoff)

1. **MSM backend swap** — `ark-ec`'s Pippenger is not the fastest
   bn254 MSM in the Rust ecosystem. Candidates:
   - `halo2_curves` MSM (used by Halo2, extensively tuned bn254 path)
   - `blitzar-rs` (GPU-optional MSM from Space and Time)
   - Hand-rolled Pippenger with the GLV endomorphism and multi-scalar
     batching (typical 2–4× over stock `ark-ec`)
   Expected: **2–4× total wall-clock** if MSMs dominate, which they
   likely do for Round 1/4/5 on a 2²³ domain.

2. **Parallelize what we wrote by hand** — CPU% only reached 617% out
   of a theoretical 1600%. Known serial hot spots:
   - `div_by_zh` — the `q[i] = q[i-n] - p[i]` recurrence is sequential;
     can be parallelized by block-decomposing and fixing up boundary
     terms, or by reformulating in the frequency domain.
   - Witness-map gather in `build_wire_polynomials` — currently
     serial; can be a `par_iter().map()`.
   - `compute_internal_witness` — sequential due to dependencies
     between additions, but the arkworks `Fr::mul` and `Fr::add` on
     each row could be vectorized via AVX-512.
   - `cpoly_merge` (fan-in-4, fan-in-3) — embarrassingly parallel.
   Expected: **1.5–2.5× wall-clock** from moving CPU% up toward 1500%.

3. **mmap the zkey instead of `std::fs::read`** — we currently slurp
   the entire 27.5 GB zkey into a `Vec<u8>` (see `prove_timed` in
   `src/lib.rs`). Switch to `memmap2::Mmap`. Dramatically drops peak
   RSS; modest wall-clock improvement (disk cache already warm between
   rounds, but the initial slurp is a big chunk of `read_inputs`).
   Expected: **RSS drop 25–40 GB**, wall-clock neutral-to-minor.

4. **Don't materialize full preprocessed polys** — we load QL, QR,
   QM, QO, QC, Σ₁, Σ₂, Σ₃ each as both coefficients and 4n extended
   evaluations (that's why each section is `5n · Fr`). Some rounds
   only need the coef form (Round 4 Horner evals), others only the
   extended form (Round 1 T0). Load on demand, drop when done.
   Expected: **RSS drop ~10 GB**.

5. **Swap the global allocator** — `glibc malloc` fragments badly on
   long-running FFLONK proofs (92 GB RSS observed, ~40% of which is
   arena fragmentation per typical jemalloc vs glibc comparisons).
   Drop in `jemalloc` or `mimalloc` via `#[global_allocator]`.
   Expected: **RSS drop 10–20 GB**, wall-clock minor.

6. **Streaming / chunked MSM** — the PTau section in the zkey holds
   ~75M G1 points. Today we materialize all of them in a `Vec<G1Affine>`
   before calling `msm_unchecked`. With mmap + chunked MSM, we could
   process bases in chunks of e.g. 1M and sum the partial results.
   Expected: **RSS drop substantial** (the PTau alone is ~5 GB of
   G1 data in RAM), wall-clock neutral.

### Stacked expected ceiling

Rough back-of-envelope if items 1+2+4 stack independently:
`548 s / 3 (MSM) / 2 (CPU) / 1.2 (poly loading) ≈ 76 s` — not quite 10×
(still $0.021/proof — 40% over the $0.015 target) but under $0.15 cap
by a comfortable margin and under the F3.2 < 60 s soft ceiling.

To reliably hit $0.015/proof via Q1 alone, we probably need a GPU MSM
(blitzar-rs or icicle), which changes the hardware story: either
specialized EC2 (g4dn.xlarge, ~$0.526/hr), or shift the break-even
math so a 3× longer GPU run still costs less than 10× shorter CPU run.

### Risks

- MSM backend swap: potential correctness regression; need end-to-end
  snarkjs-verify test on kysigned every time.
- Serial → parallel conversions in `div_by_zh`: non-trivial math,
  easy to introduce a bug that only shows up at large n.
- GPU path: new operational complexity, new dependency surface, new
  license considerations (icicle is Apache-2.0, blitzar-rs is
  BUSL — copyleft-adjacent and disallowed by DD-7 / F7.1).

### Investigation plan (when we pursue Q1)

1. Profile a `kysigned` run with `perf record` / `flamegraph` /
   `samply` on r5.4xlarge. Identify the actual time distribution by
   round and by function.
2. Pick the single highest-impact item above and implement.
3. Re-measure on r5.4xlarge. Decide whether to stack the next item or
   pursue Q2/Q3 instead.

---

## Q2. Can we change the spec in ways that lower cost without
weakening the security/absolute-proof guarantees?

**Claim to test:** some of the spec's circuit constraints can be
simplified, deferred, or swapped for a computationally cheaper formulation
that still satisfies the "legally binding signature" requirement
(kysigned's `docs/consultations/kysigned-crypto-architecture-review.md`
and `-attack-review.md`).

### Candidates to explore

1. **Reduce maxHeadersLength / maxBodyLength.** Current circuit uses
   1024/1024. Approval replies are short; enforce a shorter body cap
   (e.g. 256 bytes with `I APPROVE` always within the first 50) and a
   shorter header cap (most DKIM-signed header sets are under 512
   bytes). Each halving of these parameters directly halves the
   constraint count of DKIM and regex components.
   Constraints cost: ~linear in max lengths. 2× reduction = ~40%
   constraint reduction = ~40% prover time reduction.
   Risk: breaks real emails whose headers exceed the new cap.
   Mitigation: operator pre-check rejects before circuit sees them.

2. **Move sub-circuits outside the SNARK.** Some clauses don't need
   to be inside the zk-SNARK if they're verifiable deterministically
   on-chain with the already-committed public signals. Candidates:
   - Subject-content binding (currently placeholder `subjectHash <== 0`,
     spec F3.3.1). If the circuit commits a Poseidon of `To`/`Subject`
     bytes, the contract can re-do the envelope-id + docHash check
     on calldata. Move the regex matching to pre-check.
   - Header-format validation (duplicate headers, `d=`/From alignment,
     reject-`l=`) could run in the operator pre-check and be
     represented by an attested hash rather than an in-circuit regex.
     Risk: pre-check is now part of the trust boundary; weakens the
     "outside trust boundary" claim for non-proof path.

3. **Swap `@zk-email/circuits` for a slimmer DKIM verifier.** The
   zk-email library is comprehensive (DKIM, regex, reveal, body hash
   with precomputed SHA-256 leaf), but our use case is narrow:
   ONLY `I APPROVE` in a short body. Candidates:
   - `zkemail-nr` (Rust-native zkEmail by Aztec/Noir) — different
     audit stack; would reset the audit claim but the ACP proof-system
     choice might allow smaller circuits.
   - Custom-minimal DKIM circuit — the current library includes
     features we don't use. A purpose-built variant could be ~40%
     smaller.
   Risk: loses the `@zk-email/circuits` audit claim (5 firms,
   5000+ production proofs). Spec §F4 (trust anchor) would need a
   revision + new audit budget.

4. **Combine two signers into one proof / batch proofs.** Today each
   of 2 signers produces an independent proof; combined cost is 2×.
   A recursive-SNARK aggregation (Nova, Sonobe, Plonky2-on-bn254)
   could amortize. Out of scope for v0.1.0 but worth flagging.

5. **Drop the zk part entirely for dev/testnet.** Dark-launch and
   canary phases could use a plaintext DKIM-to-Registry flow without
   the SNARK, saving ~$0.15/sig during the pre-production period.
   Not a mainline cost reduction, but relevant for pre-launch cost
   budgets.

### Risks

- All changes here touch the kysigned spec, not fflonk-prover. Spec
  ownership lives in the kysigned track (per Phase 2F.A1). Any change
  would need user approval and a spec-version bump.
- Audit chain: `@zk-email/circuits` has 5 independent firm audits.
  Swapping it reopens that audit claim.
- Legal-defensibility story depends on the concrete circuit claims.
  Changing clauses (b), (d), (f), (g), (h) from §F3.3.4 could create
  attack surface even if the residual math is smaller.

### Investigation plan (when we pursue Q2)

1. List every spec clause in F3.3.3/F3.3.4 with its constraint-count
   contribution (requires either circuit profiling or careful
   reasoning about the zk-email library).
2. Flag which clauses could move to pre-check without weakening the
   "outside trust boundary" property (via operator-signed attestation
   + on-chain replay).
3. Bring to user for spec-version approval per the skill's guardrail.

---

## Q3. Did we make the right proof-system choice?
Is snarkjs FFLONK the right call, or does PLONK (or another system)
give better native-prover numbers?

**Claim to test:** FFLONK was chosen (kysigned spec v0.14.0) because
it's universal-SRS (no per-circuit Phase 2 ceremony) and has a Solidity
verifier with reasonable gas. But our observed constants suggest the
**FFLONK prover overhead is much higher than the spec's estimation
assumed.** A PLONK prover on the same circuit might be faster to
implement and run, at comparable correctness.

### What we observed that might suggest FFLONK was mis-estimated

- snarkjs FFLONK prover on 4.7M constraints took **109 minutes** on
  r5.4xlarge (12× more than Candidate E's Groth16 rapidsnark).
- Our Rust FFLONK prover at 9 min is 12× faster than snarkjs but
  still 40× slower than rapidsnark Groth16 on the same circuit.
- The 9× MSM overhead (FFLONK commits to `9 · domain_size + 18` G1
  points vs Groth16's ~n) is a fundamental constant factor that no
  amount of engineering will eliminate while staying in FFLONK.
- `snarkjs plonk prove` is faster than `snarkjs fflonk prove` at the
  same N (FFLONK pays the fan-in-8 merging cost on commit in exchange
  for smaller/cheaper on-chain verification).

### Options to evaluate

1. **snarkjs PLONK instead of FFLONK.** Same proof-system family,
   same Circom front-end, same universal SRS (the PTau we already
   have works for both). Trade-offs:
   - Pros: ~3–4× faster prover (no fan-in-8 merging); our Rust port
     would also inherit that speedup (~150 s at same optimization
     level, hitting $0.042/proof).
   - Cons: larger proof (~800 B vs FFLONK's 700 B), higher Solidity
     verify gas (~400K vs FFLONK's ~250K — offset maybe 2×). Net
     on-chain $/proof goes up, compute $/proof goes down; net cost
     story depends on chain gas vs compute rate.
   - Migration effort: substantial. Our round1..round5 code is
     FFLONK-specific. We'd be writing a new prover.

2. **Plonky2 / Plonky3 (FRI-based).** Plonky3 is Rust-native, fast
   prover, no ceremony. Cons: proofs don't verify on EVM efficiently
   without an FRI-to-Snark recursion step (adds back a Groth16 wrapper
   = ceremony again).
   Rating: probably worse when on-chain verification is required.

3. **Halo2 with KZG.** PSE's Halo2-KZG fork, Scroll's, Axiom's. Very
   mature Rust ecosystems, universal SRS, on-chain verifier. Pros:
   audited provers (Scroll zkEVM, Axiom). Cons: different circuit
   front-end (Halo2 chips, not Circom) — throws away the 5-audit
   `@zk-email/circuits` library.

4. **Groth16 (like Candidate E).** 40× faster (13.49s on r5.4xlarge).
   But requires a per-circuit Phase 2 ceremony every time the circuit
   changes. The spec chose FFLONK specifically to avoid this
   operational burden (§F4 trust-anchor story). Reverting to Groth16
   would require either:
   - A real multi-party Phase 2 ceremony each circuit release (months
     of coordination), or
   - A single-party ceremony with the caveat that ANY trusted-setup
     compromise breaks soundness — which the spec explicitly rejects.

### Risks of re-opening the proof-system choice

- Spec v0.14.0 closed this discussion with a documented rationale
  (`docs/products/kysigned/zkprover/research/IMPORTANT-zkprover-viable-paths.md`
  in kysigned-private). Re-opening it costs project time and may
  surface the same trade-offs.
- Ceremony-based systems (Groth16, certain halo2 flavors) bring in
  a setup-trust story that the spec deliberately avoided.
- The `@zk-email/circuits` audit pedigree applies to the Circom
  circuit, not to any specific proof system. PLONK on the same
  circuit preserves the audit claim. Halo2/plonky3 does not.

### Investigation plan (when we pursue Q3)

1. Run `snarkjs plonk prove` on the same kysigned zkey (or re-run
   setup in PLONK mode) to establish the "snarkjs PLONK" baseline on
   r5.4xlarge.
2. If PLONK is >2× faster, estimate the effort to port our fflonk-prover
   internals to PLONK — probably 2–3 weeks for a native prover with
   comparable maturity to today's fflonk-prover v0.1.0.
3. Bring to user for a spec-version conversation: "we move from
   FFLONK to PLONK, keeping the same circuit + audit chain, trading
   on-chain gas up and compute cost down by X factor."

---

## Interactions between the three questions

The three aren't fully independent. Payoff stacking:

| Pursue… | Expected cost floor |
|---|---|
| Q1 only (CPU-only) | ~$0.04/proof |
| Q1 with GPU (blitzar/icicle) | ~$0.01/proof but new deps / licensing |
| Q2 only (shrink circuit, keep FFLONK) | ~$0.08/proof |
| Q3 switch to PLONK | ~$0.04/proof |
| Q1 + Q2 | ~$0.02/proof |
| Q1 + Q3 | ~$0.015/proof (the target) |
| Q2 + Q3 | ~$0.02/proof |

Recommended first move: **Q3 research**. A few days of profiling +
snarkjs PLONK measurement clarifies whether the FFLONK choice is the
real blocker before we sink weeks into Q1 optimization that a proof-
system swap would obviate.

Recommended second move: **Q1 parallelization + mmap** (items 2 & 3
from Q1). Cheap engineering wins that apply regardless of which proof
system we end up with.

Recommended third move: **Q2 with user** — the spec-change conversation.
Not to pursue until we know Q1+Q3 won't get us there.

---

_This document is the starting point for a future `/spec` or `/plan`
session on cost optimization. Spawn that work from the kysigned repo,
not here — the decisions touch the kysigned spec, not fflonk-prover's
own spec._
