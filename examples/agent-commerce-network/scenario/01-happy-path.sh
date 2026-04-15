#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

OUT_DIR="$(stage_bundle \
  "happy-path" \
  "Scenario 01: Happy Path" \
  "Buyer requests a quote, receives an in-policy offer, executes the review, and reconciles settlement successfully.")"

cat > "${OUT_DIR}/steps.md" <<'EOF'
# Steps

1. Start trust control and the buyer/provider topology.
2. Submit `contracts/quote-request.json` through the buyer procurement API.
3. Have the provider return `contracts/quote-response.json`.
4. Create a buyer job from the accepted quote.
5. Execute the provider review and emit `contracts/fulfillment-package.json`.
6. Reconcile using `contracts/settlement-reconciliation.json`.
EOF

cat > "${OUT_DIR}/expected-outputs.md" <<'EOF'
# Expected ARC Outputs

- buyer quote-request receipt
- provider quote-generation receipt
- buyer purchase submission receipt
- provider fulfillment receipts
- settlement reconciliation artifact
- operator report entry for the fulfilled job
EOF

echo "Staged happy-path bundle at: ${OUT_DIR}"
