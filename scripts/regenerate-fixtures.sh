#!/usr/bin/env bash
#
# Regenerate FFLONK test fixtures for a named circuit via snarkjs 0.7.6.
#
# Usage:
#   ./scripts/regenerate-fixtures.sh <circuit-name>
#
# Produces fixtures under tests/fixtures/<circuit-name>/:
#   <circuit>.r1cs, <circuit>.wasm, <circuit>.sym
#   circuit.zkey, vkey.json, verifier.sol
#   sample_input.json, witness.wtns
#   reference_proof.json, reference_public.json
#
# Prerequisites: circom, Node.js, AWS CLI (for ptau), the 9GB ptau at
# fixtures-src/ptau/powersOfTau28_hez_final_23.ptau. See docs/dev-setup.md.
#
# This script is idempotent — rerunning overwrites previous fixtures.
# It should only be run when the snarkjs pin (DD-1) bumps or when a
# circuit definition changes.

set -euo pipefail

CIRCUIT="${1:-}"
if [[ -z "$CIRCUIT" ]]; then
    echo "Usage: $0 <circuit-name>" >&2
    echo "Example: $0 multiplier" >&2
    exit 1
fi

readonly SNARKJS_VERSION="0.7.6"
readonly PTAU="fixtures-src/ptau/powersOfTau28_hez_final_23.ptau"
readonly CIRCUIT_SRC="circuits/${CIRCUIT}.circom"
readonly INPUT_SRC="circuits/${CIRCUIT}_input.json"
readonly BUILD="fixtures-src/build/${CIRCUIT}"
readonly OUT="tests/fixtures/${CIRCUIT}"

for f in "$CIRCUIT_SRC" "$INPUT_SRC" "$PTAU"; do
    if [[ ! -f "$f" ]]; then
        echo "error: missing required file: $f" >&2
        exit 1
    fi
done

mkdir -p "$BUILD" "$OUT"

echo "==> [1/7] Compiling ${CIRCUIT}.circom"
circom "$CIRCUIT_SRC" --r1cs --wasm --sym -o "$BUILD"

echo "==> [2/7] snarkjs fflonk setup"
npx -y "snarkjs@${SNARKJS_VERSION}" fflonk setup "$BUILD/${CIRCUIT}.r1cs" "$PTAU" "$BUILD/circuit.zkey"

echo "==> [3/7] snarkjs zkey export verificationkey"
npx -y "snarkjs@${SNARKJS_VERSION}" zkey export verificationkey "$BUILD/circuit.zkey" "$BUILD/vkey.json"

echo "==> [4/7] snarkjs zkey export solidityverifier"
npx -y "snarkjs@${SNARKJS_VERSION}" zkey export solidityverifier "$BUILD/circuit.zkey" "$BUILD/verifier.sol"

echo "==> [5/7] Generating witness from sample input"
node "$BUILD/${CIRCUIT}_js/generate_witness.js" \
    "$BUILD/${CIRCUIT}_js/${CIRCUIT}.wasm" \
    "$INPUT_SRC" \
    "$BUILD/witness.wtns"

echo "==> [6/7] snarkjs fflonk prove (reference proof)"
npx -y "snarkjs@${SNARKJS_VERSION}" fflonk prove \
    "$BUILD/circuit.zkey" \
    "$BUILD/witness.wtns" \
    "$BUILD/reference_proof.json" \
    "$BUILD/reference_public.json"

echo "==> [7/7] Copying committed fixtures to $OUT"
cp "$BUILD/${CIRCUIT}.r1cs" "$OUT/"
cp "$BUILD/${CIRCUIT}_js/${CIRCUIT}.wasm" "$OUT/"
cp "$BUILD/${CIRCUIT}.sym" "$OUT/"
cp "$BUILD/circuit.zkey" "$OUT/"
cp "$BUILD/vkey.json" "$OUT/"
cp "$BUILD/verifier.sol" "$OUT/"
cp "$BUILD/witness.wtns" "$OUT/"
cp "$BUILD/reference_proof.json" "$OUT/"
cp "$BUILD/reference_public.json" "$OUT/"
cp "$INPUT_SRC" "$OUT/sample_input.json"

echo
echo "Done. Fixtures for '${CIRCUIT}' written to ${OUT}/"
ls -l "$OUT/"
