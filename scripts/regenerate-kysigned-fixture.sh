#!/usr/bin/env bash
#
# Regenerate the kysigned-approval FFLONK fixture via snarkjs 0.7.6.
#
# Unlike scripts/regenerate-fixtures.sh (compiles from circuits/*.circom),
# this one takes pre-compiled artifacts from the kysigned-private repo:
# the 738 MB R1CS and 27 MB witness-calculator WASM. Those come from
# kysigned-private's `zkprover-candidates/E-rapidsnark/build/` tree and
# are re-copied/re-generated over there whenever the circuit changes.
#
# Produces into tests/fixtures/kysigned/:
#   circuit.zkey           (multi-GB — also uploaded to S3, gitignored)
#   circuit.wasm           (27 MB — gitignored; copy in S3)
#   vkey.json              (committed)
#   Verifier.sol           (committed)
#   witness.wtns           (small — committed)
#   reference_proof.json   (committed)
#   reference_public.json  (committed)
#   hashes.manifest        (SHA-256 of every artifact; committed)
#
# Inputs expected (copy these in by hand or run with defaults):
#   tests/fixtures/kysigned/kysigned-approval.r1cs   (gitignored)
#   tests/fixtures/kysigned/circuit.wasm             (gitignored)
#   tests/fixtures/kysigned/input.json               (committed)
#   fixtures-src/ptau/powersOfTau28_hez_final_26.ptau  (gitignored, ~77 GB)
#
# Usage:
#   ./scripts/regenerate-kysigned-fixture.sh            # run the full pipeline
#   ./scripts/regenerate-kysigned-fixture.sh --upload   # also upload zkey to S3
#
# Runtime: expect 30–60 minutes on a dev laptop, 16+ GB peak RAM.
# Requires `NODE_OPTIONS=--max-old-space-size=24576` to avoid Node's default
# 4 GB heap OOM (exported below).

export NODE_OPTIONS="--max-old-space-size=24576"

set -euo pipefail

readonly SNARKJS="snarkjs@0.7.6"
readonly PTAU="fixtures-src/ptau/powersOfTau28_hez_final_26.ptau"
# NOTE: FFLONK on 4.7M constraints requires _final_26.ptau — _final_23 is too
# small (Section 2 only ~1 GB, FFLONK needs ~4.83 GB for a 2²³ domain).
# See plan.md Implementation Log for the derivation.
readonly OUT="tests/fixtures/kysigned"
readonly S3_PREFIX="s3://kychee-zkprover-artifacts/fflonk-prover-test-fixture/v0.1.0"
readonly AWS_PROFILE="kychee"

UPLOAD=0
if [[ "${1:-}" == "--upload" ]]; then
    UPLOAD=1
fi

for f in "$PTAU" "$OUT/kysigned-approval.r1cs" "$OUT/circuit.wasm" "$OUT/input.json"; do
    if [[ ! -f "$f" ]]; then
        echo "error: missing required input: $f" >&2
        echo "see $OUT/README.md for where to obtain it" >&2
        exit 1
    fi
done

echo "==> [1/6] snarkjs fflonk setup  (expect 30-60 min, RAM-heavy)"
time npx -y "$SNARKJS" fflonk setup \
    "$OUT/kysigned-approval.r1cs" \
    "$PTAU" \
    "$OUT/circuit.zkey"

echo "==> [2/6] snarkjs zkey export verificationkey"
npx -y "$SNARKJS" zkey export verificationkey "$OUT/circuit.zkey" "$OUT/vkey.json"

echo "==> [3/6] snarkjs zkey export solidityverifier"
npx -y "$SNARKJS" zkey export solidityverifier "$OUT/circuit.zkey" "$OUT/Verifier.sol"

echo "==> [4/6] Witness calculation (circuit.wasm + input.json)"
# The wasm ships as a .wasm file plus its generate_witness.js alongside in
# kysigned-private. Copying just the wasm into the fixture dir means we use
# snarkjs's generic `wtns calculate` path which only needs the wasm + input.
npx -y "$SNARKJS" wtns calculate "$OUT/circuit.wasm" "$OUT/input.json" "$OUT/witness.wtns"

echo "==> [5/6] snarkjs fflonk prove (reference proof, from snarkjs itself)"
time npx -y "$SNARKJS" fflonk prove \
    "$OUT/circuit.zkey" \
    "$OUT/witness.wtns" \
    "$OUT/reference_proof.json" \
    "$OUT/reference_public.json"

echo "==> [5b/6] Sanity: snarkjs accepts its own reference proof"
npx -y "$SNARKJS" fflonk verify \
    "$OUT/vkey.json" \
    "$OUT/reference_public.json" \
    "$OUT/reference_proof.json"

echo "==> [6/6] Regenerating hashes.manifest"
(
    cd "$OUT"
    sha256sum circuit.zkey circuit.wasm vkey.json Verifier.sol witness.wtns \
              reference_proof.json reference_public.json input.json \
        > hashes.manifest
    echo "--- hashes.manifest ---"
    cat hashes.manifest
)

if [[ "$UPLOAD" -eq 1 ]]; then
    echo "==> [upload] syncing circuit.zkey + circuit.wasm to S3"
    aws s3 cp "$OUT/circuit.zkey" "$S3_PREFIX/circuit.zkey" --profile "$AWS_PROFILE"
    aws s3 cp "$OUT/circuit.wasm" "$S3_PREFIX/circuit.wasm" --profile "$AWS_PROFILE"
    echo "    uploaded to $S3_PREFIX/"
fi

echo
echo "Done. Commit the tree artifacts:"
echo "  git add $OUT/vkey.json $OUT/Verifier.sol $OUT/witness.wtns \\"
echo "          $OUT/reference_proof.json $OUT/reference_public.json \\"
echo "          $OUT/input.json $OUT/hashes.manifest"
