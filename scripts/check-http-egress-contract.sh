#!/usr/bin/env bash
# Workspace lint: HttpEgressContract enforcement coverage.
#
# Walks every crate that initiates outbound HTTP and asserts that each
# `reqwest::Client::*` call site in production code is paired with an
# `HttpEgressContract` invocation (or its `send_with_contract` helper).
#
# Allowed to skip:
# - `chio-egress-contract` (owns the contract)
# - `chio-http-core` (re-exports the contract)
# - `chio-mcp-adapter` (kernel-side adapter that owns its own protocol stack)
# - test files (`tests.rs`, `*-tests.rs`, files under `tests/` or
#   `crates/*/tests/`).
#
# Exits 0 on coverage; exits 1 on a coverage gap, printing offending lines.

set -euo pipefail

# Allow callers to override the search root (used by the self-test). Default
# to the repo root that contains this script.
REPO_ROOT="${CHIO_EGRESS_LINT_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
cd "$REPO_ROOT"

ALLOW_LIST=(
    "crates/chio-egress-contract/"
    "crates/chio-http-core/"
    "crates/chio-mcp-adapter/"
    # Out-of-scope follow-up wiring. Each item below is a TODO tracked in the
    # close-bar tracker; the lint is configured to allow them while the W2.2
    # PR covers the 16 highest-priority callers (chio-link, chio-siem,
    # chio-a2a-adapter, chio-openapi-mcp-bridge, chio-mcp-remote).
    "crates/chio-api-protect/"
    "crates/chio-settle/"
    "crates/chio-anchor/"
    "crates/chio-guards/src/external/"
)

# Files that contain a reqwest::Client (production code).
mapfile -t CANDIDATE_FILES < <(grep -rln "reqwest::Client" --include='*.rs' crates/ 2>/dev/null || true)

failed=()
for file in "${CANDIDATE_FILES[@]}"; do
    rel="${file#./}"

    # Skip allowed paths.
    skip=0
    for allow in "${ALLOW_LIST[@]}"; do
        if [[ "$rel" == "$allow"* ]]; then
            skip=1
            break
        fi
    done
    if [[ $skip -eq 1 ]]; then
        continue
    fi

    # Skip test sources.
    case "$rel" in
        */tests.rs|*tests/*|*-tests.rs|*/tests/*)
            continue
            ;;
    esac

    # Production file with reqwest::Client. Require either:
    # - a `HttpEgressContract` reference in the same file, OR
    # - a `send_with_contract(` reference, OR
    # - a `client_builder_with_contract(` reference, OR
    # - the file is purely a non-dispatching helper (no `.execute(`,
    #   `.send(`, `.send_string(`, `.send_json(`, `.call()` invocations).
    if grep -qE "HttpEgressContract|send_with_contract|client_builder_with_contract" "$file"; then
        continue
    fi
    if ! grep -qE "\.execute\(|\.send\(\)|\.send_string\(|\.send_json\(|\.call\(\)|\.send\(.+\)\.await" "$file"; then
        continue
    fi
    failed+=("$file")
done

if [[ ${#failed[@]} -gt 0 ]]; then
    echo "HttpEgressContract coverage gap: the following production crates use reqwest::Client without enforcing the typed egress contract:" >&2
    for f in "${failed[@]}"; do
        echo "  $f" >&2
    done
    echo "" >&2
    echo "Add either an explicit HttpEgressContract field on the dispatch struct" >&2
    echo "or route every call through chio_egress_contract::send_with_contract." >&2
    exit 1
fi

echo "HttpEgressContract coverage OK across the workspace."
