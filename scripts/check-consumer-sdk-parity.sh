#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Install the Python SDK with its dev extra and the locked TypeScript workspace
# first. This gate never skips an unavailable language or installs dependencies.
consumer_python="${CHIO_CONSUMER_PYTHON:-python3}"
command -v "${consumer_python}" >/dev/null
command -v node >/dev/null
command -v go >/dev/null
test -x sdks/typescript/node_modules/.bin/vitest
consumer_evidence="$(mktemp -d "${TMPDIR:-/tmp}/chio-consumer-sdk.XXXXXX")"
trap 'rm -rf "${consumer_evidence}"' EXIT

"${consumer_python}" -m pytest -q \
  sdks/python/chio-sdk-python/tests/test_generated_manifest_v2.py \
  sdks/python/chio-sdk-python/tests/test_models.py::TestGeneratedWireModels::test_protocol_primitives_shared_fixtures_parse_reject_and_round_trip \
  --junitxml="${consumer_evidence}/python.xml"

(
  cd sdks/go/chio-go-http
  go test -count=1 -json -run '^(TestGeneratedProtocolPrimitivesConsumeSharedFixtures|TestGeneratedManifestV2RuntimeCorpus|TestChioToolCallRequestPreservesApprovalSetAndOpaqueExtension|TestProtocolPublicDecoderRejectsMutationsWithoutReplacingPriorValue|TestProtocolNumbersPreserveOpaqueValuesAndRejectTypedOverflow|TestAggregatePublicUnionRejectsUnknownAndForbiddenRootProperties|TestProtocolWireBoundsAndOpaqueDuplicatesReject|TestReceiptOriginRejectsInvalidValuesWithoutReplacingPriorValue)$' ./...
) >"${consumer_evidence}/go.jsonl"

(
  cd sdks/typescript
  # Exercise the actual public package entrypoint, not a stricter test-only
  # wrapper or a previously built dist directory.
  npm run build --workspace @chio-protocol/node-http
  node_modules/.bin/vitest run \
    packages/conformance/test/manifest_v2_schema.test.ts \
    packages/conformance/test/protocol_primitives_schema.test.ts \
    packages/conformance/test/wire_schema.test.ts \
    --reporter=json --outputFile="${consumer_evidence}/typescript.json"
)

python3 scripts/check-consumer-sdk-inventory.py "${consumer_evidence}"
echo "Current consumer SDK gate passed (Python, TypeScript, Go; Rust is in the consumer boundary gate)"
