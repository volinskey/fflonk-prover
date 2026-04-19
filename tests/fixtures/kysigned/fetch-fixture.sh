#!/usr/bin/env bash
# Fetch the multi-GB kysigned circuit.zkey from Kychee S3 + verify SHA-256
# against hashes.manifest. Skips already-present artifacts whose hash already
# matches.
#
# Usage: from this directory: ./fetch-fixture.sh
# Requires: awscli v2 on PATH, AWS profile `kychee` configured.

set -euo pipefail

S3_PREFIX="s3://kychee-zkprover-artifacts/fflonk-prover-test-fixture/v0.1.0"
AWS_PROFILE="kychee"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [[ ! -f hashes.manifest ]]; then
    echo "error: hashes.manifest missing — regenerate the fixture first (see README.md)" >&2
    exit 1
fi

# Files we actually need to pull from S3 (others are committed in-tree).
REMOTE_FILES=(circuit.zkey circuit.wasm)

verify_one() {
    local f="$1"
    if [[ ! -f "$f" ]]; then
        return 1
    fi
    local want got
    want="$(grep -E " \*?$f\$" hashes.manifest | awk '{print $1}' | head -n1)"
    if [[ -z "$want" ]]; then
        echo "warn: $f not listed in hashes.manifest; skipping verification" >&2
        return 0
    fi
    got="$(sha256sum "$f" | awk '{print $1}')"
    [[ "$want" == "$got" ]]
}

for f in "${REMOTE_FILES[@]}"; do
    if verify_one "$f"; then
        echo "✓ $f already present and matches manifest — skipping download"
        continue
    fi
    echo "→ downloading $f from $S3_PREFIX/$f ..."
    aws s3 cp "$S3_PREFIX/$f" "./$f" --profile "$AWS_PROFILE"
    if ! verify_one "$f"; then
        echo "error: $f hash mismatch after download — manifest is stale or download corrupted" >&2
        exit 2
    fi
    echo "✓ $f verified"
done

# Verify committed artifacts too — cheap, catches bit-rot.
COMMITTED=(vkey.json Verifier.sol witness.wtns reference_proof.json reference_public.json input.json)
for f in "${COMMITTED[@]}"; do
    if [[ -f "$f" ]]; then
        if verify_one "$f"; then
            echo "✓ $f (committed) verified"
        else
            echo "error: $f hash mismatch — did you regenerate without updating manifest?" >&2
            exit 3
        fi
    fi
done

echo
echo "kysigned fixture ready."
