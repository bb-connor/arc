#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required" >&2
  exit 2
fi

# This gate freezes the core CapabilityToken and receipt wire at v1. Other
# independently versioned Chio subsystem schemas may advance without implying
# a new core receipt or capability version.
pattern='ReceiptV[2-9]|CapabilityTokenV[2-9]|ACCEPTS_(RECEIPT|CAPABILITY|TOKEN)_[A-Z0-9_]*V[2-9]|CapabilitySchemaVersion|KernelReceiptVersion|NegotiationDowngrade|chio_receipts_v[2-9]|receipt/v[2-9][0-9]*\.schema\.json|receipt_v[2-9]\b|capability_v[2-9]\b|token_v[2-9]\b|delegation_v[2-9]\b|lineage_statement_v[2-9]\b|\b[Aa] v[2-9] CapabilityToken\b|\b[Vv][2-9] tokens?\b|schema[- ]ceiling|maximum capability-token schema|chio\.security-check-authority\.v([2-9]|[1-9][0-9]+)\b'
normative_claim_pattern='\b[Cc]urrently v[2-9](\.[0-9]+)?\b|\b[Cc]urrent( Chio-owned)? (protocol|schema|runtime|SDK|wire|API|storage|receipt)( surface| surfaces)?( is| are| remains)? v[2-9](\.[0-9]+)?\b|\b[Cc]urrent( Chio)? release( line| version| surface)?( is| are| remains|:)? v[2-9](\.[0-9]+)?\b|\b[Cc]urrent[- ]release( line| version| surface)?( is| are| remains|:)? v[2-9](\.[0-9]+)?\b|\b[Cc]urrent boundary: v[2-9](\.[0-9]+)?\b|\b[Cc]urrent v[2-9](\.[0-9]+)? (Chio-owned )?(protocol|schema|runtime|SDK|wire|API|storage|receipt|surface)\b|\bextension of v[2-9](\.[0-9]+)?\b|\bextends v[2-9](\.[0-9]+)?\b'

authority_pattern='chio\.security-check-authority\.v([2-9]|[1-9][0-9]+)\b'

normative_roots=(
  spec
  docs/adr
  docs/operations
  docs/protocols
  docs/reference
  docs/release
  docs/start-here
  docs/standards
)

existing_normative_roots=()
for root in "${normative_roots[@]}"; do
  if [[ -d "$root" ]]; then
    existing_normative_roots+=("$root")
  fi
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

set +e
rg -n --hidden \
  --glob '!target/**' \
  --glob '!audits/**' \
  --glob '!docs/research/protocol-strategy/**' \
  --glob '!docs/archive/**' \
  --glob '!**/node_modules/**' \
  --glob '!**/.git/**' \
  --glob '!scripts/check-chio-owned-v1-only.sh' \
  --glob '!**/CHANGELOG.md' \
  --glob '!docs/adr/**' \
  --glob '!**/in-toto/**' \
  --glob '!**/runtime-trace/**' \
  --glob '!docs/superpowers/**' \
  "$pattern" \
  crates spec sdks scripts docs formal xtask >"$tmp"
rg_status=$?
set -e
if ((rg_status > 1)); then
  echo "ripgrep failed while scanning Chio-owned version remnants" >&2
  exit "$rg_status"
fi

if ((${#existing_normative_roots[@]})); then
  set +e
  rg -n --hidden \
    --glob '*.md' \
    --glob '!target/**' \
    --glob '!audits/**' \
    --glob '!docs/research/**' \
    --glob '!docs/superpowers/**' \
    --glob '!docs/archive/**' \
    --glob '!**/node_modules/**' \
    --glob '!**/.git/**' \
    "$normative_claim_pattern" \
    "${existing_normative_roots[@]}" >>"$tmp"
  rg_status=$?
  set -e
  if ((rg_status > 1)); then
    echo "ripgrep failed while scanning normative version claims" >&2
    exit "$rg_status"
  fi
fi

failures=()
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  path="${line%%:*}"
  rest="${line#*:}"
  text="${rest#*:}"

  # The trusted qualification auditor consumes internal App metadata v3.
  # Exempt only this exact quoted identifier in reviewed producer, validator
  # and regression paths, and its backtick-quoted form only in the reviewed
  # evidence narrative. An adjacent future core-wire, normative or other
  # authority claim on the same line must still fail.
  authority_text="$text"
  if [[ "$path" == "scripts/audit-security-merge-qualification.py" ||
        "$path" == "scripts/check-security-ci-contract.py" ||
        "$path" == "scripts/tests/check-security-definitions.test.py" ||
        "$path" == "scripts/tests/trusted-ci-identity-regressions.test.py" ||
        "$path" == "scripts/tests/trusted-ci-landing-regressions.test.py" ||
        "$path" == "scripts/tests/trusted-ci-revocation-regressions.test.py" ||
        "$path" == "scripts/tests/trusted-main-codegen-regressions.test.py" ]]; then
    authority_text="${authority_text//\"chio.security-check-authority.v3\"/}"
  fi
  if [[ "$path" == "docs/security/committed-linux-evidence.md" ]]; then
    authority_text="${authority_text//\`chio.security-check-authority.v3\`/}"
  fi
  if [[ "$path" == "scripts/check-security-ci-contract.py" ||
        "$path" == "scripts/tests/trusted-ci-identity-regressions.test.py" ]]; then
    authority_text="${authority_text//\"chio.security-check-authority.v2\"/}"
  fi
  if [[ "$authority_text" != "$text" ]]; then
    authority_scan_status=0
    rg -q "$pattern|$normative_claim_pattern" <<<"$authority_text" || authority_scan_status=$?
    if ((authority_scan_status > 1)); then
      echo "ripgrep failed while rechecking the trusted auditor schema line" >&2
      exit "$authority_scan_status"
    fi
    if ((authority_scan_status == 1)); then
      continue
    fi
  fi

  # Negative fixture corpora may include forbidden Chio-owned versions by design.
  if [[ "$path" =~ (^|/)(negative-fixture|negative_fixtures|negative-fixtures|negative-fixture-corpus) ]]; then
    continue
  fi

  # A producer cannot borrow the generic future-fixture shortcut for App metadata.
  authority_scan_status=0
  rg -q "$authority_pattern" <<<"$text" || authority_scan_status=$?
  if ((authority_scan_status > 1)); then
    echo "ripgrep failed while checking the authority schema namespace" >&2
    exit "$authority_scan_status"
  fi
  if ((authority_scan_status == 0)); then
    failures+=("$line")
    continue
  fi

  # Future-version negative fixtures intentionally use .v9-style schema IDs.
  if [[ "$text" =~ chio\.[A-Za-z0-9_.-]+\.v9[0-9]* ]]; then
    continue
  fi


  # External ecosystem/tool versions are not Chio-owned schema or API versions.
  if [[ "$text" =~ pydantic_v2|Pydantic\ v2|oapi-codegen\ v2|OpenAPI\ 3|IPv4|IPv6|UUID-v4|uuid-v4|uuid::now_v7|envoy\.service\.auth\.v3|Envoy\ ext_authz\ v3|PagerDuty\ Events\ API\ v2|Rekor\ v2|cosign\ at\ v2 ]]; then
    continue
  fi

  # Attest, federation, and pheromone are independently-versioned subsystems
  # that ship inside the Chio repo but are not the v1 Chio-owned wire / SDK /
  # receipt surface this scan is intended to gate. Their schema IDs use their
  # own version numbering (chio.attest.*.vN, chio.federation.*.vN,
  # chio.pheromone.*.vN) and may legitimately advance past v1 ahead of the v1
  # wire surface.
  if [[ "$text" =~ chio\.attest\.[A-Za-z0-9_.-]+\.v[2-9][0-9]* ]]; then
    continue
  fi
  if [[ "$text" =~ chio\.federation\.[A-Za-z0-9_.-]+\.v[2-9][0-9]* ]]; then
    continue
  fi
  if [[ "$text" =~ chio\.pheromone\.[A-Za-z0-9_.-]+\.v[2-9][0-9]* ]]; then
    continue
  fi

  # Attest bilateral-cosign / 3-vendor proof-package fixtures embed
  # workflow-receipt slices keyed at v2 as fixture data; the canonical
  # Chio-owned workflow-receipt schema (spec/WORKFLOW.md) remains v1.
  # Limit this exclusion to attest test/fixture/example surfaces.
  if [[ "$text" =~ chio\.workflow-receipt\.v[2-9][0-9]* ]] && \
     [[ "$path" =~ (^|/)(chio-attest-)|fixtures/|examples/chio- ]]; then
    continue
  fi

  if [[ "$text" =~ chio\.mercury\.proof_package\.v2 ]]; then
    continue
  fi

  if [[ "$path" == "crates/platform/chio-store-sqlite/src/finding_challenge_store_tests.rs" ]] && \
     [[ "$text" =~ migrate\ v[2-9][0-9]*\ schema ]]; then
    continue
  fi

  failures+=("$line")
done <"$tmp"

if ((${#failures[@]})); then
  printf '%s\n' "Core capability or receipt v1 contract remnants found:" >&2
  printf '  %s\n' "${failures[@]}" >&2
  exit 1
fi

echo "Core capability and receipt surfaces remain v1-only."
