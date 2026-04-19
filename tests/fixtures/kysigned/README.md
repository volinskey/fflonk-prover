# kysigned fixture — the acceptance gate

This directory holds the fixtures for Phase 8 (kysigned-approval acceptance)
of the `fflonk-prover` v0.1.0 plan. Unlike the `multiplier` and `poseidon`
fixtures (small, fully committed), the kysigned fixture's **`circuit.zkey`
is multi-GB** and lives in private Kychee S3 rather than the git repo.

The small artifacts (`vkey.json`, `Verifier.sol`, `witness.wtns`,
`reference_proof.json`, `reference_public.json`, `input.json`) **are
committed** in this directory so CI and smoke tests can access them without
S3 credentials.

## Origin of the artifacts

The R1CS + WASM + sample input come from the kysigned-private repo, which
tracks the production kysigned-approval circuit. Current placeholder
circuit: `subjectHash <== 0` version (~4.7M constraints). When the real
production circuit lands, the kysigned plan's 2F.G step regenerates these
artifacts and re-uploads to S3 under a new version prefix.

## S3 layout

```
s3://kychee-zkprover-artifacts/fflonk-prover-test-fixture/v0.1.0/
  ├── circuit.zkey          (multi-GB — NOT committed; fetched via fetch-fixture.sh)
  ├── circuit.wasm          (27 MB — also staged in S3 for convenience)
  ├── vkey.json             (tiny — also committed in-tree)
  ├── Verifier.sol          (tiny — also committed in-tree)
  ├── witness.wtns          (small — also committed in-tree)
  ├── reference_proof.json  (snarkjs's own proof on witness — committed in-tree)
  ├── reference_public.json (committed in-tree)
  └── input.json            (21 KB — committed in-tree)
```

AWS profile: `kychee` (account 472210437512, region us-east-1).

## Fetching `circuit.zkey` locally

```bash
./fetch-fixture.sh
```

This downloads `circuit.zkey` (and optionally `circuit.wasm`) from S3 into
this directory, then verifies every downloaded artifact's SHA-256 against
`hashes.manifest`. If any hash mismatches, the script exits non-zero.

If you don't have AWS access, ask the circuit team to drop you the zkey
bundle manually — the manifest hashes still apply.

## Regenerating the fixture (circuit changes, snarkjs bump, etc.)

Only needed when:
- snarkjs 0.7.6 pin in [DD-1](../../../docs/plans/fflonk-prover-plan.md) moves
- The kysigned-approval circuit changes substantially (new wire layout,
  new constraint count, etc.)

Steps (mirrors `scripts/regenerate-fixtures.sh` but tuned for the big
circuit):

1. Copy fresh artifacts from kysigned-private:
   ```bash
   cp <kysigned-private>/zkprover-candidates/E-rapidsnark/build/kysigned-approval.r1cs .
   cp <kysigned-private>/zkprover-candidates/E-rapidsnark/build/kysigned-approval_js/kysigned-approval.wasm circuit.wasm
   cp <kysigned-private>/zkprover-candidates/E-rapidsnark/build/input.json .
   ```

2. Ensure `../../../fixtures-src/ptau/powersOfTau28_hez_final_26.ptau` is
   present (~77 GB; see `docs/dev-setup.md`). **Important:** `_final_23.ptau`
   (used for multiplier/poseidon) is too small for this circuit — FFLONK on
   4.7M constraints requires Section 2 ≈ 4.83 GB (`_final_26` provides ~8.6 GB;
   `_final_23` has only ~1 GB).

3. Generate zkey + derived artifacts (expect ~30–60 min RAM-heavy run):
   ```bash
   # Setup (needs NODE_OPTIONS for the heap, large ptau for section 2 size)
   export NODE_OPTIONS="--max-old-space-size=24576"
   npx -y snarkjs@0.7.6 fflonk setup \
     kysigned-approval.r1cs \
     ../../../fixtures-src/ptau/powersOfTau28_hez_final_26.ptau \
     circuit.zkey

   # Export vkey + Solidity verifier
   npx -y snarkjs@0.7.6 zkey export verificationkey circuit.zkey vkey.json
   npx -y snarkjs@0.7.6 zkey export solidityverifier circuit.zkey Verifier.sol

   # Witness from input (uses wasm)
   npx -y snarkjs@0.7.6 wtns calculate circuit.wasm input.json witness.wtns

   # Reference proof (snarkjs proves its own witness; optional sanity check)
   npx -y snarkjs@0.7.6 fflonk prove circuit.zkey witness.wtns \
     reference_proof.json reference_public.json

   # Sanity: snarkjs accepts its own reference proof
   npx -y snarkjs@0.7.6 fflonk verify vkey.json reference_public.json reference_proof.json
   ```

4. Regenerate `hashes.manifest`:
   ```bash
   ./regen-manifest.sh   # or: sha256sum circuit.zkey circuit.wasm vkey.json Verifier.sol witness.wtns reference_proof.json reference_public.json input.json > hashes.manifest
   ```

5. Upload non-committed artifacts to S3:
   ```bash
   aws s3 cp circuit.zkey  s3://kychee-zkprover-artifacts/fflonk-prover-test-fixture/v0.1.0/ --profile kychee
   aws s3 cp circuit.wasm  s3://kychee-zkprover-artifacts/fflonk-prover-test-fixture/v0.1.0/ --profile kychee
   ```

6. Commit the small artifacts + updated `hashes.manifest`.

## Note on storage migration (deferred)

Per kysigned plan's [DD-43 / 2F.R8](../../../../kysigned/docs/plans/),
once `fflonk-prover` merges into the kysigned public repo (kysigned plan
step 2F.F), this fetch path migrates from direct S3 to the run402
cross-project endpoint (no public AWS credentials needed). Deferred
until kysigned step 2F.R13 ships. For now, S3 is the right near-term store.
