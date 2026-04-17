# Plan: fflonk-prover

**Owner:** volinskey
**Created:** 2026-04-17
**Status:** In Progress
**Spec:** docs/products/fflonk-prover/fflonk-prover-spec.md
**Spec-Version:** 0.1.1
**Source:** spec
**Worktree:** ../fflonk-prover-worktree

## Legend
- `[ ]` Todo | `[~]` In Progress | `[x]` Done

---

## Design Decisions

### DD-1: Pin snarkjs 0.7.6 as byte-compatibility reference
- **Alternatives:** track latest snarkjs; target 0.6.x
- **Chosen because:** deterministic target. "Byte-compatible with snarkjs" is meaningless without a pinned version — FFLONK challenge ordering and encoding has drifted across versions. 0.7.6 is the current latest stable release (confirmed via `npx snarkjs --version` on 2026-04-17); 0.7.5 in the original DD was my guess before checking.
- **Trade-offs:** must regenerate committed fixtures on snarkjs bumps
- **Rollback:** change pin, re-run fixture regeneration script

### DD-2: Target <20s proving on 4.7M constraints; empirical waivers permitted
- **Alternatives:** ship at <60s requirement; target <20s only in v0.2.0
- **Chosen because:** ambitious target drives optimization effort inside v0.1.0 rather than deferring it indefinitely
- **Trade-offs:** Phase 7 may not hit target; waiver policy protects ship date
- **Rollback:** document measured waiver, defer further perf to v0.2.0

### DD-3: Witness-from-input out of scope for v0.1.0
- **Alternatives:** add `prove-from-input` subcommand that runs circom WASM internally
- **Chosen because:** WASM runtime is a separate subsystem; keeps v0.1.0 focused on proving itself
- **Trade-offs:** operators must run circom's WASM witness calculator separately and pass `.wtns`
- **Rollback:** add `prove-from-input` in v0.2.0

### DD-4: Library API takes `&Path`, not `&[u8]` (SPEC CHANGE — approved by user)
- **Alternatives:** `&[u8]` as originally spec'd; generic `R: Read + Seek`
- **Chosen because:** zkey's section table requires random access; `&[u8]` forces callers to load multi-GB into memory; `R: Read + Seek` adds generic complexity without serving a real consumer
- **Trade-offs:** callers must have a filesystem path (in-memory callers must write a temp file — acceptable, nobody has asked for this)
- **Rollback:** add `prove_from_bytes(zkey: &[u8], witness: &[u8])` as a second entry point if a real in-memory use case appears

### DD-5: Dual-circuit test strategy — small circuits for iteration + kysigned-approval for acceptance
- **Alternatives:** small-only; kysigned-only
- **Chosen because:** small circuits (2^10, 2^15 constraints) give a fast correctness iteration loop; kysigned-approval (4.7M constraints) is the real acceptance gate
- **Trade-offs:** must build and maintain a small test circuit family
- **Rollback:** N/A — this is the iteration/acceptance split

### DD-6: CI uses committed fixtures; ptau is dev-only
- **Alternatives:** download ptau in CI; nightly-only integration tests
- **Chosen because:** PR volume is low; every PR runs the full snarkjs-verify + Anvil on-chain chain on small circuits using committed fixtures, giving immediate correctness signal
- **Trade-offs:** fixture regeneration is a manual dev workflow triggered by snarkjs bumps
- **Rollback:** add on-demand fixture-regen GitHub workflow (`workflow_dispatch`)

### DD-7: Zkey parser — try taceo-circom-types first, fork if it lacks FFLONK
- **Alternatives:** write our own parser from day 1; contribute FFLONK support upstream first
- **Chosen because:** Phase 0 spike is cheap; leverage existing code if possible, fall through if not
- **Trade-offs:** plan branches if the spike fails — a `zkey-fflonk` parser module is added as a Phase 2 task
- **Rollback:** N/A — this is the hedging structure

### DD-8: MSM optimization deferred until correctness ships
- **Alternatives:** custom MSM from day 1; integrate `halo2_curves` / `icicle` from day 1; GPU from day 1
- **Chosen because:** establish a correct baseline before optimizing. Perf work is easier to iterate against a correct reference than to debug correctness + perf simultaneously
- **Trade-offs:** Phase 7 may discover stock `ark-ec` can't be tuned far enough and require swapping MSM backends — a decision point, not a risk to correctness
- **Rollback:** accept <60s requirement, defer <20s to v0.2.0

### Spec Changes (approved by user)
- **2026-04-17 — F5.1 signature change (spec v0.1.0):** `prove(zkey: &[u8], witness: &[u8])` → `prove(zkey_path: &Path, witness_path: &Path)`. See DD-4 for rationale. Spec updated in place.
- **2026-04-17 — F7.1 + AC F7 license allowlist relaxation (spec v0.1.0 → v0.1.1):** Original "MIT or Apache-2.0 only" wording was infeasible — `unicode-ident` (transitive via every Rust derive macro) carries `(MIT OR Apache-2.0) AND Unicode-3.0`. F7.1 now specifies a permissive-only allowlist (MIT, Apache-2.0, BSD, ISC, Unicode-3.0, Zlib, CC0-1.0, Apache-2.0 WITH LLVM-exception) with explicit no-copyleft ban. AC F7 references `deny.toml` as the authoritative allowlist. Spec intent ("no copyleft") preserved. Spec version bumped to 0.1.1.

---

## Tasks

### Phase 0: Foundation & Spike

- [x] Initialize Cargo workspace with library crate + `fflonk-prover` binary target [infra]
- [x] Add pinned core dependencies: `ark-bn254`, `ark-ff`, `ark-ec`, `ark-poly`, `ark-serialize`, `rayon`, `clap`, `serde`, `serde_json`, `thiserror` [infra]
- [x] Configure `cargo-deny` with permissive license policy (per revised spec F7.1); commit `deny.toml` [infra]
- [x] Set up GitHub Actions CI skeleton: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`, `cargo deny check licenses` [infra]
- [x] Commit `Cargo.lock` to repo [infra]
- [x] Spike: verify `taceo-circom-types` parses a snarkjs 0.7.6 FFLONK `.zkey` — result: FAIL, taking DD-7 fallback (write custom parser in Phase 2) [code]

### Phase 1: Test fixtures

- [x] Document dev-machine setup in `docs/dev-setup.md`: Node 22, snarkjs 0.7.6 (via `npx`), circom 2.x (installed via `cargo install --git`), Foundry (only needed Phase 5), AWS CLI [infra]
- [x] Fetch `powersOfTau28_hez_final_23.ptau` from `s3://kychee-zkprover-artifacts/shared/` to `fixtures-src/ptau/` (gitignored — 9 GB, verified 9,663,759,512 bytes) [infra]
- [x] Write `circuits/multiplier.circom` — smoke-test circuit (`a * b = c`, public `c`) [code]
- [x] Write `circuits/poseidon.circom` — poseidon hash circuit (154 iterations ≈ 2^15 constraints) [code]
- [x] Write `scripts/regenerate-fixtures.sh` — circom compile → snarkjs fflonk setup → export vkey + Solidity verifier → generate witness → produce reference proof [infra]
- [x] Run fixture generation for multiplier and poseidon; commit to `tests/fixtures/{multiplier,poseidon}/` [infra]
- [x] Document fixture regeneration trigger conditions in `tests/fixtures/README.md` [code]

### Phase 2: Parsers

- [x] Implement custom FFLONK zkey reader [code]
- [x] Implement Circom `.wtns` reader [code]
- [x] Fuzz parsers against malformed inputs (truncated files, wrong magic, bad section lengths) [code]

### Phase 3: FFLONK proving — correctness

**Important context for anyone resuming Phase 3.** snarkjs applies random blinding
scalars to the witness polynomials A, B, C inside Round 1 for zero-knowledge. This
means the `C1`, `C2`, `W1`, `W2` commitments and the `a`, `b`, `c`, `z`, `zw`,
`t1w`, `t2w`, `inv` evaluations in `tests/fixtures/*/reference_proof.json` are
**specific to the snarkjs run that produced them and cannot be reproduced
deterministically** by any independent prover. Do NOT write round-level tests
that assert byte equality against those values.

Incremental validation is still possible:
1. **Preprocessed-poly evaluations** (`ql`, `qr`, `qm`, `qo`, `qc`, `s1`, `s2`,
   `s3` in the reference proof) are blinder-independent. Evaluating the zkey's
   Q_L..Q_C, σ_1..σ_3 coefficient sections at the derived challenge `xi` must
   match the reference proof exactly. Use this as Phase 3's first ground-truth
   test (task below).
2. **End-to-end** via Phase 5's `snarkjs fflonk verify` check on our produced
   proof — the authoritative correctness signal for everything blinding touches.
3. **Structural checks** per round (degrees, vanishing at specific points,
   pairing identities that don't involve blinded values).

- [x] Implement Fiat-Shamir transcript matching snarkjs 0.7.6 exactly [code]
- [x] Implement KZG polynomial commitment over BN254 [code]
- [ ] Implement preprocessed-polynomial evaluation at the xi challenge (blinder-independent ground-truth test) [code]
  - Derive xi via transcript chain: beta → gamma → xiSeed → xi = xiSeed^24 (use our transcript; inputs: C0 from vkey, A[0]=public inputs, C1, C2 — take C1/C2 from the reference proof since we can't produce matching ones ourselves yet)
  - Read Q_L, Q_R, Q_M, Q_O, Q_C, σ_1, σ_2, σ_3 coefficient vectors via `read_fr_section`
  - Horner-evaluate each at xi
  - Assert each equals the corresponding `ql`, `qr`, `qm`, `qo`, `qc`, `s1`, `s2`, `s3` decimal in `reference_proof.json` for both multiplier and poseidon
- [ ] Implement prover Round 1: build A/B/C from witness + maps, compute T0 quotient, merge (fan-in-4) → C1 [code]
  - Subtasks:
    - Read A_map/B_map/C_map (use existing `read_u32_section`); construct A/B/C buffers of length `domain_size` by setting `A[i] = witness[A_map[i]]` etc.
    - Apply blinding scalars at high coefficient indices (snarkjs uses 9 blinders total — see snarkjs `fflonk_prove.js`). For deterministic testing, optionally expose a zero-blinding mode.
    - iFFT A/B/C from evaluation-on-domain form to coefficient form via `ark_poly::Radix2EvaluationDomain`.
    - Compute T0 = (q_L·A + q_R·B + q_M·A·B + q_O·C + q_C + PI(X)) / Z_H(X) in extended evaluation domain (oversample by 4×), iFFT back. Z_H(X) = X^domain_size − 1. PI(X) is the public-input Lagrange interpolation.
    - Merge A/B/C/T0 via snarkjs's `CPolynomial(4)`: **interleave coefficients** — if each input has coeffs `[c_0, c_1, ...]`, the merged poly has coeffs `[A_0, B_0, C_0, T0_0, A_1, B_1, C_1, T0_1, ...]`.
    - KZG commit merged poly → `proof.C1`.
  - Round 1 output: `C1` G1 point. Absorb into transcript (chained in subsequent challenges).
  - **Test strategy:** structural only (degree < 4·domain_size). Correctness is via end-to-end verify.
- [ ] Implement prover Round 2: permutation polynomial Z + quotient decomposition T0/T1/T2 → C2 merge [code]
  - Uses beta, gamma challenges. Z(X) encodes the grand-product permutation check over σ_1, σ_2, σ_3.
  - Decompose T = T0 + X^domain·T1 + X^(2·domain)·T2 (each Ti of degree < domain_size).
  - Fan-in-4 merge Z, T0, T1, T2 into C2 (per `CPolynomial(4)`; see snarkjs round3 code).
  - KZG commit → `proof.C2`. Absorb into transcript.
  - Test: structural (degree, non-zero commitment).
- [ ] Implement prover Round 4: evaluate polynomials at xi [code]
  - Compute the 16 proof evaluations: `ql, qr, qm, qo, qc, s1, s2, s3, a, b, c, z, zw, t1w, t2w, inv`.
  - `ql..s3`: covered by the preprocessed-eval test above.
  - `a, b, c, z, zw, t1w, t2w, inv`: blinding-dependent. Test via end-to-end verify.
- [ ] Implement prover Round 5: FFLONK fan-in merging + KZG opening proofs W1, W2 [code]
  - W1: opens the round-1/round-2 merged polynomial at `xi` (fan-in-3 merge of sub-openings).
  - W2: opens at `xi·ω` (the shifted evaluation for the permutation argument).
  - KZG opening = `(P(X) − P(z)) / (X − z)`, committed.
  - Test: structural; end-to-end via verify.
- [ ] Serialize proof struct + public signals to snarkjs-compatible JSON [code]
  - Output format per `reference_proof.json`: `{ polynomials: { C1, C2, W1, W2 }, evaluations: { ql, qr, qm, qo, qc, s1, s2, s3, a, b, c, z, zw, t1w, t2w, inv }, protocol: "fflonk", curve: "bn128" }`.
  - G1 points serialize as `[x, y, "1"]` (decimal strings, Jacobian with z=1 meaning affine).
  - Scalars serialize as decimal strings (not hex, not Montgomery).
  - `public.json` is a JSON array of decimal strings: `[public_signal_0, public_signal_1, ...]`.
  - Test: roundtrip — serialize our Proof struct, parse with `serde_json`, compare to original.
- [ ] Library API: `prove(zkey_path: &Path, witness_path: &Path) -> Result<(Proof, PublicSignals), ProverError>` [code]
  - Wraps all rounds. Returns typed `Proof` + `PublicSignals`.
  - Test: call on multiplier zkey + wtns, assert returned Proof has expected structure (4 G1 points in polynomials, 16 scalar evaluations, correct protocol/curve markers). Byte-exact values are validated by Phase 5 end-to-end test.

### Phase 4: Local verifier

- [ ] Implement FFLONK verifier using `ark-ec` pairing check (for local testing only; on-chain verifier is the snarkjs-generated Solidity contract) [code]
  - Write failing test: verify multiplier reference proof → PASS
  - Write failing test: verify tampered proof (flip a byte in A) → FAIL
  - Write failing test: verify proof with wrong public signals → FAIL
- [ ] Expose `verify()` via library API [code]

### Phase 5: Integration tests

**This phase is the authoritative correctness gate for Phase 3.** Because snarkjs's
random blinding prevents byte-matching our commitments against any committed
reference proof, "our prover is correct" is ultimately "`snarkjs fflonk verify`
accepts our proof" and/or "the Solidity verifier accepts it on-chain." Expect
most Phase 3 bugs to surface here, not in Phase 3's own unit tests.

- [ ] Integration test: our prover on multiplier → `snarkjs fflonk verify` PASS [code]
- [ ] Integration test: our prover on poseidon → `snarkjs fflonk verify` PASS [code]
- [ ] Integration test: deploy committed multiplier Solidity verifier to Anvil, submit our proof, expect tx success [code]
- [ ] Integration test: deploy committed poseidon Solidity verifier to Anvil, submit our proof, expect tx success [code]
- [ ] Wire all integration tests into CI: install Node.js 20 + snarkjs 0.7.6 + Foundry in CI image; run on every PR [infra]

### Phase 6: CLI

- [ ] Implement `fflonk-prover prove <zkey> <witness> <proof-out> <public-out>` subcommand [code]
- [ ] Implement `fflonk-prover verify <vkey> <public> <proof>` subcommand [code]
- [ ] Implement `fflonk-prover info <zkey>` subcommand — prints proof system, constraint count, curve, nVars, nPublic [code]
- [ ] Implement `fflonk-prover --version` [code]
- [ ] Implement `--threads <N>` flag; default to `num_cpus::get_physical()` [code]
- [ ] Emit timing breakdown to stderr during `prove` (FFT, MSM, poly eval, commitment, total wall-clock, peak RSS) [code]
- [ ] Exit codes: 0 success, 1 invalid input / prove fail, 2 verify fail [code]
- [ ] CLI integration tests: spawn binary as subprocess, assert outputs and exit codes [code]

### Phase 7: Performance

- [ ] Establish baseline: run prover on multiplier, poseidon; record wall-clock, CPU utilization %, peak RSS in `docs/benchmarks.md` [code]
- [ ] Parallelize NTT/FFT with rayon [code]
- [ ] Parallelize MSM with rayon [code]
- [ ] Re-baseline on multiplier + poseidon after parallelization [code]
- [ ] Extrapolate projected 4.7M-constraint performance from parallel baseline [code]
- [ ] Decision point: if extrapolated kysigned time > 20s, evaluate candidates (`halo2_curves` MSM, `blitzar-rs`, custom Pippenger with GLV endomorphism) and integrate the best option [code]
- [ ] Profile peak RSS against 8GB requirement (target 4GB); reduce if needed [code]

### Phase 8: Kysigned acceptance

- [ ] Receive kysigned-approval circuit artifacts from user: `.r1cs`, `.wasm`, sample input JSONs [manual]
- [ ] Generate kysigned fixtures via snarkjs 0.7.6: zkey, vkey, witness for sample inputs, reference proof.json, Solidity verifier; commit to `tests/fixtures/kysigned/` [manual]
- [ ] Run our prover on kysigned witness → `snarkjs fflonk verify` PASS [code]
- [ ] Run our prover on kysigned witness → Anvil on-chain verify PASS [code]
- [ ] Measure kysigned perf on 16-vCPU r5.4xlarge: wall-clock, peak RSS, CPU% — record in `docs/benchmarks.md` [code]
- [ ] Gate: wall-clock <20s (or record waiver with measured number + reason), RSS <8GB, CPU% >400% [code]

### Phase 9: Ship & Verify

- [ ] Finalize `Cargo.toml` publish metadata: description, repository URL, license "MIT", keywords, categories, readme [infra]
- [ ] Write `README.md` with install, CLI usage, library usage, performance numbers, and snarkjs version compatibility note [code]
- [ ] Ship "CLI binary" surface — `cargo publish`; then smoke check: `cargo install fflonk-prover && fflonk-prover --version` prints "0.1.0" [ship]
- [ ] Ship "Rust crate" surface — same `cargo publish` crate; smoke check: in a throwaway project, `cargo add fflonk-prover && cargo build` succeeds and a minimal `prove()` call compiles [ship]
- [ ] Tag `v0.1.0` in git; draft GitHub release with pre-built binaries for linux-x86_64, macos-aarch64, windows-x86_64 [infra]

---

## Implementation Log

_Populated during implementation by `/implement`, AFTER tasks are being executed. Captures discoveries, gotchas, deviations, and emergent decisions found while coding. Never populated during planning._

### Repo commands (discovered on Phase 0 task 1)

- **Full test suite:** `cargo test`
- **Build:** `cargo build`
- **Release build:** `cargo build --release`
- **Format check:** `cargo fmt --check`
- **Lint:** `cargo clippy --all-targets -- -D warnings`
- **License audit:** `cargo deny check licenses` (after Phase 0 task 3 configures deny.toml)

### Gotchas

- **Spec F7.1 over-specification:** Original "MIT or Apache-2.0 only" license policy is infeasible in practice because `unicode-ident` (transitive via every Rust derive macro) requires Unicode-3.0. Any Rust project using serde/thiserror/clap/arkworks-derive hits this. Spec had to be relaxed to permissive-allowlist. Lesson: future specs should frame license policy as "no copyleft" rather than enumerating allowed licenses.

- **taceo-circom-types lacks FFLONK support (Phase 0 spike, 2026-04-17):** Crate 0.2.5 on crates.io only exposes Groth16 + PLONK zkey parsing; no FFLONK zkey API. Per DD-7, fell back to custom FFLONK zkey parser (Phase 2). Evidence: docs.rs API inspection showed no `fflonk`/`FFlonk`/`FFLONK` items; crates.io metadata confirms only `full-groth16` and `full-plonk` features. Spec's dependency table was updated to remove `taceo-circom-types`. The `.wtns` parser will also be written custom (already planned in Phase 2); no alternative dep needed since wtns format is simple (byte-level section layout).

- **Two different encodings in the snarkjs toolchain for Fr/Fq field elements:**
  - **Zkey file on disk (Q_L, Q_R, ..., C0 coefficients, wire maps, SRS, FFLONK header fields like k1/k2/w3):** Montgomery-form, little-endian. Parse via `Fp::new_unchecked(BigInt([u64; 4]))` — zero-cost bridge since arkworks also stores Montgomery internally.
  - **Witness file (.wtns) values:** Canonical, little-endian. Parse via `from_le_bytes_mod_order`.
  - **Keccak256Transcript for Fiat-Shamir:** **Canonical, big-endian** — despite ffjavascript naming the encoder `toRprBE` which strongly implies Montgomery. The reference alpha did NOT reproduce when using Montgomery-BE; it DID reproduce with canonical-BE. **Lesson: don't trust snarkjs/ffjavascript function names — verify against a reference value.**

- **FFLONK Round 1 output is non-deterministic due to random blinding.** snarkjs applies random blinding scalars to high-degree coefficients of A/B/C before committing, so `proof.C1` in our `reference_proof.json` is specific to the exact RNG state of the `snarkjs fflonk prove` run that produced it — any independent prover run yields different commitment bytes. This means intermediate-round unit tests against the reference proof are NOT a valid correctness signal. The only end-to-end correctness test is: run our full prover → run `snarkjs fflonk verify` on our output → PASS. Plan this into Phase 5.

### Deviations

- **Phase 0 task 1:** `src/main.rs` was given a minimal hand-rolled `--help` / `--version` handler instead of waiting for clap integration in Phase 6. Rationale: required to verify the binary target wires up correctly (`cargo run -- --help` smoke test). Phase 6's first CLI task will replace this with clap-based parsing.

- **Phase 0 task 6 (spike):** Concluded via static API inspection rather than empirical test. No FFLONK zkey file exists yet (Phase 1 fixture work) and the crate's API has no FFLONK entry points — a runtime test is unnecessary when the compile-time API surface is definitive. TDD skipped because this sub-task was research, not production code.

- **Phase 3 (partial) — transcript & KZG primitives complete, prover rounds deferred:** Got as far as proving the transcript + KZG commit work byte-exactly against the multiplier reference. Did not start Round 1 because it's an atomic chunk that requires implementing witness-column construction, FFT/iFFT, T0 quotient computation (q_L·a + q_R·b + q_M·a·b + q_O·c + q_C + PI, divided by Z_H), fan-in-4 CPolynomial merge, and random blinding — all without intermediate ground-truth checks (snarkjs applies random blinders to A/B/C, so reference_proof.json's C1 cannot be reproduced deterministically; validation is end-to-end via `snarkjs fflonk verify` only).

---

## Log

- 2026-04-17: Plan created from spec v0.1.0. Eight design decisions recorded. Spec edited in place to change F5.1 library API signature from `&[u8]` to `&Path` (DD-4).
- 2026-04-17: Completed "Initialize Cargo workspace" — Cargo.toml + src/lib.rs + src/main.rs + .gitignore. `cargo build`, `cargo test` (1 passing), `cargo run -- --help`, `cargo run -- --version` all verified. Test command recorded in Implementation Log.
- 2026-04-17: Completed "Add pinned core dependencies" — arkworks 0.5.0 suite (bn254, ff, ec, poly, serialize), rayon 1.12, clap 4.6 (derive), serde 1.0 (derive), serde_json, thiserror 2.0. Cold build 14s; test suite still green.
- 2026-04-17: Completed "Configure cargo-deny" — installed cargo-deny, wrote deny.toml with permissive allowlist. Discovered spec F7.1 MIT/Apache-2.0-only was infeasible (unicode-ident requires Unicode-3.0). Applied spec change with user approval: relaxed F7.1 + AC F7 to permissive-only (no copyleft). Spec bumped 0.1.0 → 0.1.1. `cargo deny check licenses` PASSES.
- 2026-04-17: Completed "Set up GitHub Actions CI skeleton" — wrote `.github/workflows/ci.yml` with 4 jobs (fmt, clippy, test matrix on ubuntu/macos/windows, deny). All jobs' commands verified locally: fmt ok, clippy (no warnings), test (1 passing), deny licenses ok.
- 2026-04-17: Completed "Commit Cargo.lock to repo" — Cargo.lock exists (17KB), not in .gitignore, ready for inclusion in first commit. Actual git commit deferred to normal workflow per session rule (no commits without explicit user request).
- 2026-04-17: Completed "Phase 0 spike" — taceo-circom-types 0.2.5 confirmed to lack FFLONK zkey support. Triggering DD-7 fallback: custom FFLONK zkey parser in Phase 2 (already covered by that phase's existing task). Spec dep table updated to remove taceo-circom-types. **Phase 0 complete.**
- 2026-04-17: User pushback on over-broad `[manual]` task classification. Revised Phase 1 annotations: most tasks are `[infra]`/`[code]`; only Phase 8 kysigned artifact handoff remains truly manual. Installed circom 2.2.3 via `cargo install --git https://github.com/iden3/circom.git`. Pinned snarkjs version adjusted 0.7.5 → 0.7.6 (current latest on npm; 0.7.5 was my initial guess).
- 2026-04-17: Completed Phase 1 tasks 1-7 — dev-setup.md, ptau download (9.7 GB from S3), multiplier.circom (1 constraint), poseidon.circom (~63k wires via 154 Poseidon(1) iterations via circomlib), regenerate-fixtures.sh, sample input JSONs, tests/fixtures/README.md. Generated committed fixtures for both circuits (multiplier ~130 KB; poseidon ~166 MB, zkey 150 MB). Both reference proofs verified by `snarkjs fflonk verify` — **PROOF VERIFIED SUCCESSFULLY**. Cargo.toml extended with `exclude` patterns to keep published crate tarball small. **Phase 1 complete.**
- 2026-04-17: Completed Phase 2 via TDD. `src/zkey.rs`: global header + section iterator + full FFLONK section-2 parser + generic `read_fr_section` for preprocessed polynomial sections. Every vkey.json field (k1=2, k2=3, w3/w4/w8/wr, C0, X_2) matches byte-exact against our parser. Cross-circuit sanity verified on poseidon. `src/wtns.rs`: canonical-LE witness parser, multiplier witness decodes to [1, 33, 3, 11]. Defensive tests for truncated/malformed inputs (bad magic, bad version, overflow section size, non-BN254 curve, misaligned Fr section). Discovered key format difference: zkey Fr/Fq is Montgomery-LE (use `Fp::new_unchecked`), wtns Fr is canonical-LE (use `from_le_bytes_mod_order`). 24 tests total, all green. Lint + fmt clean. **Phase 2 complete.**
- 2026-04-17: **Phase 3 partial — primitives done, rounds deferred.** Two protocol primitives implemented and verified byte-exact vs snarkjs: (1) `src/transcript.rs` — Keccak256 Fiat-Shamir matching snarkjs 0.7.6. Encoding is canonical-BE for Fr/Fq (NOT Montgomery, despite ffjavascript's `toRprBE` naming). Verified via full chain reproduction: `alpha`, `y`, and `xi = xiSeed^24` all match the reference values logged from `snarkjs fflonk prove` on multiplier. (2) `src/kzg.rs` — KZG polynomial commitment as arkworks `VariableBaseMSM`. Verified by reading `C0` coefficients (section 17) + PTau SRS (section 16) from the multiplier zkey, committing, and matching `vkey.json`'s C0 x,y exactly. Added supporting zkey readers: `read_g1_section` (64-byte uncompressed affine entries) and `read_u32_section` (for A_map/B_map/C_map — multiplier has 2 constraint rows per map). Paused before Round 1 — remaining Phase 3 work (rounds 1-5 + proof serialization + library API) is a multi-session effort that can only be validated end-to-end due to random-blinding non-determinism. **32 tests passing, lint + fmt clean.**
- 2026-04-17: Phase 3 task descriptions revised for fresh-session resumption. Round 1-5 sub-tasks no longer assume byte-match against `reference_proof.json` (impossible due to snarkjs random blinding). Added a new incremental-validation task (preprocessed-polynomial evaluation at xi — the one blinder-independent signal) as the first Round 3 step. Phase 5 header updated to flag it as the authoritative correctness gate.
