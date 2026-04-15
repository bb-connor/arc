#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

OUT_DIR="$(stage_bundle \
  "approval-required" \
  "Scenario 02: Approval Required" \
  "Provider quote exceeds the buyer auto-approve threshold, so ARC requires an approval artifact before execution.")"

cat > "${OUT_DIR}/steps.md" <<'EOF'
# Steps

1. Submit the quote request and accept the returned high-value quote.
2. Attempt to create the job without approval and observe the fail-closed outcome.
3. Issue `contracts/approval-ticket.json`.
4. Resubmit the purchase with the approval artifact attached.
5. Continue to fulfillment and settlement once approval is present.
EOF

cat > "${OUT_DIR}/expected-outputs.md" <<'EOF'
# Expected ARC Outputs

- denial or pending-state receipt for missing approval
- approval issuance / review artifact
- approved job submission receipt
- fulfillment and reconciliation artifacts after approval
EOF

echo "Staged approval-required bundle at: ${OUT_DIR}"
