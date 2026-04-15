#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

OUT_DIR="$(stage_bundle \
  "dispute-and-reversal" \
  "Scenario 04: Dispute and Reversal" \
  "The provider delivers a fulfillment package, the buyer disputes it, and reconciliation records a partial payout or reversal path.")"

cat > "${OUT_DIR}/steps.md" <<'EOF'
# Steps

1. Execute the happy-path flow through fulfillment.
2. Open a dispute through the buyer API.
3. Attach the fulfillment package and dispute summary.
4. Produce a revised reconciliation decision showing partial payout or reversal.
EOF

cat > "${OUT_DIR}/expected-outputs.md" <<'EOF'
# Expected ARC Outputs

- fulfillment receipts
- dispute-opened receipt
- reconciliation update or reversal artifact
- operator report entries showing the dispute path
EOF

echo "Staged dispute-and-reversal bundle at: ${OUT_DIR}"
