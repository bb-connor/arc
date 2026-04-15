#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

OUT_DIR="$(stage_bundle \
  "federated-review" \
  "Scenario 05: Federated Review" \
  "A third-party reviewer imports bounded evidence, preserves upstream lineage, and verifies the transaction without rewriting local issuance history.")"

cat > "${OUT_DIR}/steps.md" <<'EOF'
# Steps

1. Export the buyer/provider evidence package after settlement or dispute.
2. Import the bounded package into the reviewer environment.
3. Verify receipt lineage, checkpoint material, and reconciliation context.
4. Confirm that imported evidence remains imported rather than becoming local issuance.
EOF

cat > "${OUT_DIR}/expected-outputs.md" <<'EOF'
# Expected ARC Outputs

- exported evidence bundle
- imported evidence lineage or verification output
- reviewer-side summary of what is authoritative and what remains imported
- no silent trust upgrade across operator boundaries
EOF

echo "Staged federated-review bundle at: ${OUT_DIR}"
