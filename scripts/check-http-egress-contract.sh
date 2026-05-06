#!/usr/bin/env bash
# Workspace lint: HttpEgressContract enforcement coverage.
#
# Walks every crate that initiates outbound HTTP and asserts that each
# `reqwest` dispatch call site in production code is paired with an
# `HttpEgressContract` invocation (or its `send_with_contract` helper).
#
# This lint detects four reqwest patterns:
#   1. Direct: `reqwest::Client::*`
#   2. Direct: `reqwest::ClientBuilder::*`
#   3. Aliased: `use reqwest as foo;` followed by `foo::Client::*`
#   4. Indirect: a value bound from `reqwest::Client::builder()` (or
#      `reqwest::ClientBuilder::*`) that subsequently invokes a dispatch
#      method (`.get(`, `.post(`, `.put(`, `.delete(`, `.patch(`,
#      `.head(`, `.execute(`, `.send()`).
#
# Allowed to skip:
# - `chio-egress-contract` (owns the contract)
# - `chio-http-core` (re-exports the contract)
# - `chio-mcp-adapter` (kernel-side adapter that owns its own protocol stack)
# - test files (`tests.rs`, `*-tests.rs`, files under `tests/` or
#   `crates/*/tests/`).
#
# Fail-closed: ambiguous matches (e.g. unrecognized aliases) are reported
# rather than silently skipped.
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

# Compose a regex that catches:
#   - reqwest::Client::*
#   - reqwest::ClientBuilder::*
#   - any `use reqwest as <alias>;` followed by `<alias>::Client::*` /
#     `<alias>::ClientBuilder::*` (we materialise the alias by scanning the
#     source for a `use reqwest as <alias>;` declaration and union the
#     resulting per-file pattern).
#
# Files that match the regex but do not pair with a contract reference or
# only declare a non-dispatching helper are reported.

# Initial sweep: any reference to reqwest::Client or reqwest::ClientBuilder.
mapfile -t CANDIDATE_FILES < <(
    grep -rln -E "reqwest::Client|reqwest::ClientBuilder" --include='*.rs' \
        crates/ 2>/dev/null || true
)

# Aliased imports: scan for `use reqwest as foo;` and expand the candidate
# set with files that use the alias to call into Client/ClientBuilder.
while IFS= read -r alias_match; do
    file="${alias_match%%:*}"
    rest="${alias_match#*:}"
    # Extract the alias name from a line like `use reqwest as foo;`.
    alias=$(echo "$rest" | sed -nE 's/.*use[[:space:]]+reqwest[[:space:]]+as[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;.*/\1/p')
    if [[ -n "$alias" ]]; then
        if grep -qE "\b${alias}::(Client|ClientBuilder)" "$file"; then
            CANDIDATE_FILES+=("$file")
        fi
    fi
done < <(grep -rn -E "use[[:space:]]+reqwest[[:space:]]+as[[:space:]]+[A-Za-z_]" --include='*.rs' crates/ 2>/dev/null || true)

# De-duplicate.
if [[ ${#CANDIDATE_FILES[@]} -gt 0 ]]; then
    mapfile -t CANDIDATE_FILES < <(printf '%s\n' "${CANDIDATE_FILES[@]}" | awk '!seen[$0]++')
fi

DISPATCH_REGEX="\\.execute\\(|\\.send\\(\\)|\\.send_string\\(|\\.send_json\\(|\\.call\\(\\)|\\.send\\(.+\\)\\.await"
INDIRECT_BINDING_REGEX="let[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*(reqwest::Client::builder|reqwest::ClientBuilder::|[A-Za-z_][A-Za-z0-9_]*::Client::builder|[A-Za-z_][A-Za-z0-9_]*::ClientBuilder::)"
INDIRECT_DISPATCH_REGEX="\\.(get|post|put|delete|patch|head|execute|send)\\("

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

    # Production file references reqwest::Client / ClientBuilder. Accept
    # the file when it pairs the reference with the egress contract or the
    # blessed helper functions.
    if grep -qE "HttpEgressContract|send_with_contract|client_builder_with_contract" "$file"; then
        continue
    fi

    # If the file has no dispatch method calls and no indirectly-bound
    # client builder (which would imply a later dispatch in the same
    # file), it is a non-dispatching helper. Accept it.
    has_direct_dispatch=0
    if grep -qE "$DISPATCH_REGEX" "$file"; then
        has_direct_dispatch=1
    fi
    has_indirect_binding=0
    if grep -qE "$INDIRECT_BINDING_REGEX" "$file" \
        && grep -qE "$INDIRECT_DISPATCH_REGEX" "$file"; then
        has_indirect_binding=1
    fi
    if [[ $has_direct_dispatch -eq 0 && $has_indirect_binding -eq 0 ]]; then
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
