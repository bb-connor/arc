#!/usr/bin/env bash
# Self-test for scripts/check-http-egress-contract.sh.
#
# Synthesizes both a positive and a negative case and asserts the lint
# behaves correctly on each. The negative case constructs a tiny fake crate
# under a temp dir and points the lint at it via repo-root override.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LINT="$REPO_ROOT/scripts/check-http-egress-contract.sh"

work="$(mktemp -d -t chio-egress-lint-XXXXXX)"
trap 'rm -rf "$work"' EXIT

# Synthetic positive: crate that uses reqwest::Client AND HttpEgressContract.
mkdir -p "$work/positive/crates/chio-fake-positive/src"
cat > "$work/positive/crates/chio-fake-positive/src/lib.rs" <<'EOF'
use chio_egress_contract::{send_with_contract, HttpEgressContract};

pub async fn dispatch(client: &reqwest::Client, contract: &HttpEgressContract) {
    let req = client.get("https://example.com").build().unwrap();
    let _ = send_with_contract(contract, client, req).await;
}
EOF

# Synthetic negative: crate that uses reqwest::Client without the contract.
mkdir -p "$work/negative/crates/chio-fake-negative/src"
cat > "$work/negative/crates/chio-fake-negative/src/lib.rs" <<'EOF'
pub async fn dispatch(client: &reqwest::Client) {
    let _ = client.get("https://example.com").send().await;
}
EOF

# Run the lint with a per-case repo-root override via env var.
positive_output=$(CHIO_EGRESS_LINT_ROOT="$work/positive" bash "$LINT" 2>&1) && positive_status=0 || positive_status=$?
negative_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative" bash "$LINT" 2>&1) && negative_status=0 || negative_status=$?

echo "positive case: status=$positive_status output=$positive_output"
echo "negative case: status=$negative_status output=$negative_output"

if [[ $positive_status -ne 0 ]]; then
    echo "FAIL: lint should accept the positive synthetic crate" >&2
    exit 1
fi

if [[ $negative_status -eq 0 ]]; then
    echo "FAIL: lint should reject the negative synthetic crate (bare reqwest::Client without contract)" >&2
    exit 1
fi

echo "OK: HttpEgressContract lint correctly accepts wired callers and rejects bare reqwest dispatch."
