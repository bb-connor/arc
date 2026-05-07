#!/usr/bin/env bash
# Self-test for scripts/check-http-egress-contract.sh.
#
# Synthesizes positive and negative cases for each pattern the lint
# claims to recognise (direct, ClientBuilder, aliased, indirect binding).
# The negative cases construct tiny fake crates under a temp dir and
# point the lint at each via the CHIO_EGRESS_LINT_ROOT override.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LINT="$REPO_ROOT/scripts/check-http-egress-contract.sh"

work="$(mktemp -d -t chio-egress-lint-XXXXXX)"
trap 'rm -rf "$work"' EXIT

# Synthetic positive: crate that builds the reqwest client through the egress
# helper and dispatches through send_with_contract.
mkdir -p "$work/positive/crates/chio-fake-positive/src"
cat > "$work/positive/crates/chio-fake-positive/src/lib.rs" <<'EOF'
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};

pub async fn dispatch(contract: &HttpEgressContract) {
    let client: reqwest::Client = client_builder_with_contract(contract).build().unwrap();
    let req = client.get("https://example.com").build().unwrap();
    let _ = send_with_contract(contract, &client, req).await;
}
EOF

# Synthetic negative: crate that uses reqwest::Client without the contract.
mkdir -p "$work/negative/crates/chio-fake-negative/src"
cat > "$work/negative/crates/chio-fake-negative/src/lib.rs" <<'EOF'
pub async fn dispatch(client: &reqwest::Client) {
    let _ = client.get("https://example.com").send().await;
}
EOF

# Synthetic negative: crate that uses reqwest::ClientBuilder + .send() with
# no contract. The previous (literal-only) lint missed this.
mkdir -p "$work/negative_builder/crates/chio-fake-builder/src"
cat > "$work/negative_builder/crates/chio-fake-builder/src/lib.rs" <<'EOF'
pub async fn dispatch() {
    let client = reqwest::Client::builder().build().unwrap();
    let _ = client.get("https://example.com").send().await;
}
EOF

# Synthetic negative: aliased reqwest import (`use reqwest as rq;`) used
# to construct a Client. The previous lint did not match the alias.
mkdir -p "$work/negative_aliased/crates/chio-fake-aliased/src"
cat > "$work/negative_aliased/crates/chio-fake-aliased/src/lib.rs" <<'EOF'
use reqwest as rq;

pub async fn dispatch() {
    let client = rq::Client::builder().build().unwrap();
    let _ = client.post("https://example.com").send().await;
}
EOF

# Synthetic negative: mentions HttpEgressContract but still dispatches through
# bare reqwest. This guards against comment/import-only false positives.
mkdir -p "$work/negative_mention/crates/chio-fake-mention/src"
cat > "$work/negative_mention/crates/chio-fake-mention/src/lib.rs" <<'EOF'
use chio_egress_contract::HttpEgressContract;

pub async fn dispatch(client: &reqwest::Client, _contract: &HttpEgressContract) {
    let _ = client.get("https://example.com").send().await;
}
EOF

# Synthetic negative: dispatches through send_with_contract but accepts a
# caller-supplied client, so the lint cannot prove automatic redirects were
# disabled through client_builder_with_contract.
mkdir -p "$work/negative_send_without_builder/crates/chio-fake-send/src"
cat > "$work/negative_send_without_builder/crates/chio-fake-send/src/lib.rs" <<'EOF'
use chio_egress_contract::{send_with_contract, HttpEgressContract};

pub async fn dispatch(client: &reqwest::Client, contract: &HttpEgressContract) {
    let req = client.get("https://example.com").build().unwrap();
    let _ = send_with_contract(contract, client, req).await;
}
EOF

# Synthetic positive: ClientBuilder with the contract helper.
mkdir -p "$work/positive_builder/crates/chio-fake-pos-builder/src"
cat > "$work/positive_builder/crates/chio-fake-pos-builder/src/lib.rs" <<'EOF'
use chio_egress_contract::{client_builder_with_contract, HttpEgressContract};

pub fn make_client(contract: &HttpEgressContract) -> reqwest::Client {
    client_builder_with_contract(contract).build().unwrap()
}
EOF

# Run the lint with a per-case repo-root override via env var.
positive_output=$(CHIO_EGRESS_LINT_ROOT="$work/positive" bash "$LINT" 2>&1) && positive_status=0 || positive_status=$?
negative_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative" bash "$LINT" 2>&1) && negative_status=0 || negative_status=$?
negative_builder_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_builder" bash "$LINT" 2>&1) && negative_builder_status=0 || negative_builder_status=$?
negative_aliased_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_aliased" bash "$LINT" 2>&1) && negative_aliased_status=0 || negative_aliased_status=$?
negative_mention_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_mention" bash "$LINT" 2>&1) && negative_mention_status=0 || negative_mention_status=$?
negative_send_without_builder_output=$(CHIO_EGRESS_LINT_ROOT="$work/negative_send_without_builder" bash "$LINT" 2>&1) && negative_send_without_builder_status=0 || negative_send_without_builder_status=$?
positive_builder_output=$(CHIO_EGRESS_LINT_ROOT="$work/positive_builder" bash "$LINT" 2>&1) && positive_builder_status=0 || positive_builder_status=$?

echo "positive case: status=$positive_status output=$positive_output"
echo "negative case: status=$negative_status output=$negative_output"
echo "negative builder case: status=$negative_builder_status output=$negative_builder_output"
echo "negative aliased case: status=$negative_aliased_status output=$negative_aliased_output"
echo "negative mention case: status=$negative_mention_status output=$negative_mention_output"
echo "negative send-without-builder case: status=$negative_send_without_builder_status output=$negative_send_without_builder_output"
echo "positive builder case: status=$positive_builder_status output=$positive_builder_output"

if [[ $positive_status -ne 0 ]]; then
    echo "FAIL: lint should accept the positive synthetic crate" >&2
    exit 1
fi

if [[ $negative_status -eq 0 ]]; then
    echo "FAIL: lint should reject the negative synthetic crate (bare reqwest::Client without contract)" >&2
    exit 1
fi

if [[ $negative_builder_status -eq 0 ]]; then
    echo "FAIL: lint should reject the ClientBuilder synthetic crate without contract" >&2
    exit 1
fi

if [[ $negative_aliased_status -eq 0 ]]; then
    echo "FAIL: lint should reject the aliased reqwest crate without contract" >&2
    exit 1
fi

if [[ $negative_mention_status -eq 0 ]]; then
    echo "FAIL: lint should reject mention-only HttpEgressContract coverage" >&2
    exit 1
fi

if [[ $negative_send_without_builder_status -eq 0 ]]; then
    echo "FAIL: lint should reject send_with_contract without client_builder_with_contract" >&2
    exit 1
fi

if [[ $positive_builder_status -ne 0 ]]; then
    echo "FAIL: lint should accept the positive ClientBuilder + contract crate" >&2
    exit 1
fi

echo "OK: HttpEgressContract lint correctly accepts wired callers and rejects bare reqwest dispatch (including ClientBuilder, alias, mention-only, and send-without-builder forms)."
