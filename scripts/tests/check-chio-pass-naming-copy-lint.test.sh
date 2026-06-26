#!/usr/bin/env bash
set -euo pipefail

# Proves the pass_passport_naming_overload COPY_STOP_PATTERN in
# scripts/check-chio-proof-room-release-truth.sh:
#   - fires when launch copy calls the Chio Pass a passport
#     (AgentPassport / transaction / settlement / order passport),
#   - passes when the Pass is described as a portable reputation credential,
#   - does NOT false-positive on legitimate prose about the existing passport
#     artifacts when the "Pass" credential noun is absent.

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
lint="${repo_root}/scripts/check-chio-proof-room-release-truth.sh"
work="$(mktemp -d -t chio-pass-naming-XXXXXX)"
trap 'rm -rf "$work"' EXIT
truth="$work/release-truth.json"
bundle_truth="$work/bundle-release-truth.json"

cat > "$truth" <<'EOF'
{
  "schema": "chio.proof.release-truth.v1",
  "id": "test-release-truth",
  "truth": {
    "public_release": false,
    "package_published": false,
    "docker_quickstart": false,
    "hosted_demo": false,
    "chain_evidence": false,
    "transparency_log": false
  },
  "allowed_copy": [
    "local fixture proof"
  ]
}
EOF
cp "$truth" "$bundle_truth"

# Bad: the Chio Pass is named as a passport artifact.
cat > "$work/pass-naming-fail.md" <<'EOF'
The Chio Pass is your AgentPassport for every settlement.
EOF

# Good: the Chio Pass is a portable reputation credential.
cat > "$work/pass-naming-pass.md" <<'EOF'
The Chio Pass is a portable reputation credential gifted on day zero.
EOF

# Good (scoping proof): legitimate prose about the existing passport
# artifacts, with no "Pass" credential noun, must not be flagged.
cat > "$work/passport-artifact-legit.md" <<'EOF'
The native AgentPassport artifact and the transaction-passport schema remain unchanged.
Commerce emits chio.commerce.order-passport.v1 for each settled order.
EOF

if ! grep -Fq "pass_passport_naming_overload" "$lint"; then
  echo "lint is missing the pass_passport_naming_overload stop pattern" >&2
  exit 1
fi

# Negative: the bad string must be flagged by the new pattern.
if CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass-naming-fail.md" \
  "$lint" >"$work/pass-naming-fail.out" 2>&1; then
  echo "Pass-as-passport naming overclaim unexpectedly passed" >&2
  cat "$work/pass-naming-fail.out" >&2
  exit 1
fi
grep -q \
  "proof-room.release.copy-forbidden: pass_passport_naming_overload" \
  "$work/pass-naming-fail.out"

# Positive: the good reputation-credential string must pass.
CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/pass-naming-pass.md" \
  "$lint"

# Scoping: legitimate passport-artifact prose must not false-positive.
CHIO_PROOF_ROOM_RELEASE_TRUTH="$truth" \
  CHIO_PROOF_ROOM_BUNDLE_RELEASE_TRUTH="$bundle_truth" \
  CHIO_PROOF_ROOM_RELEASE_DOCS="$work/passport-artifact-legit.md" \
  "$lint"

echo "check-chio-pass-naming-copy-lint.test.sh: pass naming positives and negatives passed"
