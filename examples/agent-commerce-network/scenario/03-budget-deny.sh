#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

OUT_DIR="$(stage_bundle \
  "budget-deny" \
  "Scenario 03: Budget Deny" \
  "Buyer attempts a purchase that exceeds the governed budget envelope and ARC denies the action before execution begins.")"

cat > "${OUT_DIR}/steps.md" <<'EOF'
# Steps

1. Use the high-value quote from `contracts/quote-response.json`.
2. Configure the buyer-side budget lower than the quoted amount.
3. Attempt job submission.
4. Observe the fail-closed denial and operator-facing explanation.
EOF

cat > "${OUT_DIR}/expected-outputs.md" <<'EOF'
# Expected ARC Outputs

- deny receipt linked to the attempted submission
- budget-utilization or authorization-context operator output
- no fulfillment receipt
- no settlement artifact
EOF

echo "Staged budget-deny bundle at: ${OUT_DIR}"
