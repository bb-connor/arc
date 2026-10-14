#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
gate="${repo_root}/scripts/check-agent-web-proof-envelope-schema.sh"

if [[ ! -x "$gate" ]]; then
  echo "agent-web.proof-envelope-schema.gate-missing: scripts/check-agent-web-proof-envelope-schema.sh" >&2
  exit 1
fi

if ! grep -Fq "published_agent_web_schemas_accept_supported_projection_fixtures" "$gate"; then
  echo "agent-web.proof-envelope-schema.coverage-missing: published Agent Web schema fixture test" >&2
  exit 1
fi

if ! grep -Fq "published_v2_proof_envelope_schema_requires_scope_and_unique_receipts" "$gate"; then
  echo "agent-web.proof-envelope-schema.contract-missing: scope-bound v2 schema test" >&2
  exit 1
fi

if ! grep -Fq "verifier_refuses_unsupported_envelope_schema" "$gate"; then
  echo "agent-web.proof-envelope-schema.refusal-missing: unsupported envelope schema refusal test" >&2
  exit 1
fi

"$gate"

echo "check-agent-web-proof-envelope-schema.test.sh: Agent Web proof-envelope schema gate passed"
