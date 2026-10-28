#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
script="$repo_root/scripts/check-chio-transaction-passport.sh"

if [[ ! -x "$script" ]]; then
  echo "check-chio-transaction-passport.test.sh: missing executable gate script" >&2
  exit 1
fi

output="$("$script" --schema-only)"
printf '%s\n' "$output"

if ! grep -Fq "proof-room" <<<"$output"; then
  echo "check-chio-transaction-passport.test.sh: gate must account for Proof Room catalog entries" >&2
  exit 1
fi

lib="$repo_root/scripts/lib/chio-proof-trusted-keys.sh"
quickstart_env="$repo_root/scripts/proof-room-quickstart-env.sh"
flagship_runner="$repo_root/scripts/demo/flagship-wall-stops-money.sh"

canonical_agent_web_kernel_key="204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21"
negative_sidecar_key="d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
before_source="$(date +%s)"
mapfile -t shared_values < <(
  # Expand fixture variables inside the clean child environment.
  # shellcheck disable=SC2016
  env -i PATH="$PATH" bash -c '
    source "$1"
    printf "%s\n%s\n%s\n%s\n" \
      "$CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS" \
      "$CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS" \
      "$CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS" \
      "$CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS"
  ' _ "$lib"
)
after_source="$(date +%s)"

if [[ ",${shared_values[0]}," != *",$canonical_agent_web_kernel_key,"* ]]; then
  echo "check-chio-transaction-passport.test.sh: shared trust config must pin the fixture kernel key" >&2
  exit 1
fi
if [[ ",${shared_values[0]}," == *",$negative_sidecar_key,"* ]]; then
  echo "check-chio-transaction-passport.test.sh: invalid unbound-receipt sidecar key must not be trusted as a kernel key" >&2
  exit 1
fi
if [[ "${shared_values[1]}" != "$negative_sidecar_key" ]]; then
  echo "check-chio-transaction-passport.test.sh: shared trust config must keep the envelope sidecar key in its own trust class" >&2
  exit 1
fi
if (( shared_values[2] < before_source + 60 || shared_values[2] > after_source + 60 )); then
  echo "check-chio-transaction-passport.test.sh: shared verifier time must track the live clock" >&2
  exit 1
fi
if (( shared_values[3] != shared_values[2] - 1770508800 + 300 )); then
  echo "check-chio-transaction-passport.test.sh: shared fixture freshness window is inconsistent" >&2
  exit 1
fi

for consumer in "$script" "$quickstart_env" "$flagship_runner"; do
  if ! grep -Fq "chio-proof-trusted-keys.sh" "$consumer"; then
    echo "check-chio-transaction-passport.test.sh: $consumer must source the shared proof trust config" >&2
    exit 1
  fi
done

if ! grep -Fq "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS" "$script" && ! grep -Fq "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS" "$lib"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin enterprise receipt kernel keys" >&2
  exit 1
fi

if ! grep -Fq "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS" "$script" && ! grep -Fq "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS" "$lib"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin commerce event authority receipt keys" >&2
  exit 1
fi

if ! grep -Fq "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS" "$script" && ! grep -Fq "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS" "$lib"; then
  echo "check-chio-transaction-passport.test.sh: gate must pin commerce payment signer keys" >&2
  exit 1
fi

fixture_tree="$(mktemp -d)"
trap 'rm -rf "$fixture_tree"' EXIT
mkdir -p \
  "$fixture_tree/scripts/lib" \
  "$fixture_tree/spec/schemas/chio-transaction/v1" \
  "$fixture_tree/crates/core/chio-core-types/src" \
  "$fixture_tree/fixtures/proof-room/family/valid" \
  "$fixture_tree/fixtures/proof-room/family/digest-mismatch" \
  "$fixture_tree/fixtures/proof-room/family/head-reorged" \
  "$fixture_tree/fixtures/proof-room/family/negatives" \
  "$fixture_tree/fixtures/proof-room/room/proof-room-bundle/roots" \
  "$fixture_tree/bin" \
  "$fixture_tree/stub"
cp "$script" "$fixture_tree/scripts/check-chio-transaction-passport.sh"
cp "$lib" "$fixture_tree/scripts/lib/chio-proof-trusted-keys.sh"
printf '{}\n' >"$fixture_tree/spec/schemas/chio-transaction/v1/transaction-passport.schema.json"
cat >"$fixture_tree/spec/schemas/registry.json" <<'JSON'
{"artifacts": [{"schema": "chio.transaction-passport.v1", "schemaFile": "spec/schemas/chio-transaction/v1/transaction-passport.schema.json"}]}
JSON
cat >"$fixture_tree/crates/core/chio-core-types/src/signed_artifact.rs" <<'RS'
pub const CHIO_TRANSACTION_PASSPORT_V1_SCHEMA: &str = "chio.transaction-passport.v1";
("transaction_passport", "transaction-passport-v1")
RS
cat >"$fixture_tree/fixtures/proof-room/catalog.json" <<'JSON'
{"fixtures": [
  {"id": "family-valid", "kind": "transaction-passport", "path": "fixtures/proof-room/family/valid"},
  {"id": "family-digest-mismatch", "kind": "negative-transaction-passport", "path": "fixtures/proof-room/family/digest-mismatch"},
  {"id": "family-head-reorged", "kind": "negative-transaction-passport", "path": "fixtures/proof-room/family/head-reorged"},
  {"id": "room", "kind": "proof-room", "path": "fixtures/proof-room/room"}
]}
JSON
cat >"$fixture_tree/fixtures/proof-room/family/negatives/digest-mismatch.json" <<'JSON'
{"id": "digest-mismatch", "expected_failure_code": "proof-room.negative.evidence-graph-digest-mismatch"}
JSON
cat >"$fixture_tree/fixtures/proof-room/family/negatives/head-reorged.json" <<'JSON'
{"id": "head-reorged", "expected_failure_code": "proof-room.negative.public-settlement-independent-head-block-hash-mismatch", "verifier_context": {"public_settlement_independent_chain_head": "block_hash_mismatch"}}
JSON
for passport in family/valid family/digest-mismatch family/head-reorged room/proof-room-bundle/roots; do
  printf '{}\n' >"$fixture_tree/fixtures/proof-room/$passport/transaction-passport.json"
done
printf '{}\n' >"$fixture_tree/fixtures/proof-room/room/proof-room-bundle/manifest.json"
printf '#!/usr/bin/env bash\nexit 0\n' >"$fixture_tree/bin/cargo"
chmod +x "$fixture_tree/bin/cargo"
stub_chio="$fixture_tree/bin/chio"
cat >"$stub_chio" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
stub_dir="$(cd "$(dirname "$0")/../stub" && pwd)"
[[ "${1:-}" == "--json" ]] && shift
[[ "${1:-}" == "proof" && "${2:-}" == "verify" ]] || exit 2
case "${3:-}" in
  */family/valid/*|*/room/proof-room-bundle) printf '{"verdict":"verified"}\n'; exit 0 ;;
  */family/head-reorged/*)
    if [[ -z "${CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON:-}" || -n "${CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL:-}" ]]; then
      printf '{"message":"proof verify: unexpected verifier context"}\n' >&2
      exit 1
    fi
    printf '{"code":"urn:chio:error:transaction:artifact-hash-mismatch","message":"proof verify: invalid settlement: public settlement independent head block hash mismatch"}\n' >&2
    exit 20
    ;;
  */family/digest-mismatch/*)
    printf '%s\n' "$(cat "$stub_dir/message")" >&2
    exit "$(cat "$stub_dir/exit")"
    ;;
esac
exit 2
STUB
chmod +x "$stub_chio"

run_stub_report() {
  local exit_code="$1"
  local report="$2"
  printf '%s\n' "$exit_code" >"$fixture_tree/stub/exit"
  printf '%s\n' "$report" >"$fixture_tree/stub/message"
  CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL=http://127.0.0.1:9 \
    PATH="$fixture_tree/bin:$PATH" CHIO_BIN="$stub_chio" \
    bash "$fixture_tree/scripts/check-chio-transaction-passport.sh" >"$fixture_tree/gate.log" 2>&1
}

run_stub_gate() {
  local exit_code="$1"
  local message="$2"
  local code="${3-urn:chio:error:transaction:passport-hash-mismatch}"
  local report
  report="$(python3 - "$code" "$message" <<'PY'
import json
import sys
print(json.dumps({"code": sys.argv[1], "message": sys.argv[2]}))
PY
)"
  run_stub_report "$exit_code" "$report"
}

right_message="proof verify: evidence graph digest mismatch: expected 01, got 02"
for rejected in \
  "10|$right_message|requires exit 20" \
  "30|$right_message|requires exit 20" \
  "50|$right_message|requires exit 20" \
  "1|$right_message|exited 1" \
  "2|$right_message|exited 2" \
  "101|$right_message|exited 101" \
  "127|$right_message|exited 127" \
  "20|proof verify: claim set digest mismatch: expected 01, got 02|wrong reason: expected proof-room.negative.evidence-graph-digest-mismatch, got proof-room.negative.claim-set-digest-mismatch" \
  "20|proof verify: evidence graph digest mismatch extended: expected 01|wrong reason" \
  "0|$right_message|unexpectedly verified"; do
  IFS='|' read -r exit_code message reason <<<"$rejected"
  if run_stub_gate "$exit_code" "$message"; then
    echo "check-chio-transaction-passport.test.sh: gate accepted a negative that exited $exit_code with: $message" >&2
    exit 1
  fi
  if ! grep -Fq "$reason" "$fixture_tree/gate.log"; then
    echo "check-chio-transaction-passport.test.sh: gate rejected exit $exit_code without naming: $reason" >&2
    cat "$fixture_tree/gate.log" >&2
    exit 1
  fi
done

for valid in \
  "10|urn:chio:error:transaction:required-claim-missing" \
  "20|urn:chio:error:transaction:passport-hash-mismatch" \
  "20|CHIO-TRANSACTION-PASSPORT-HASH-MISMATCH" \
  "30|urn:chio:error:transaction:artifact-schema-invalid" \
  "30|urn:chio:error:attest:signed-json-invalid-input" \
  "30|CHIO-CLI-JSON" \
  "50|urn:chio:error:transaction:verifier-context-invalid"; do
  IFS='|' read -r accepted code <<<"$valid"
  if ! run_stub_gate "$accepted" "$right_message" "$code"; then
    echo "check-chio-transaction-passport.test.sh: gate refused a negative rejected with exit $accepted and the expected code" >&2
    cat "$fixture_tree/gate.log" >&2
    exit 1
  fi
  if ! grep -Fq "OK transaction-passport verifier gate: 1 positive, 2 negative, 1 proof-room" "$fixture_tree/gate.log"; then
    echo "check-chio-transaction-passport.test.sh: gate did not count every fixture" >&2
    cat "$fixture_tree/gate.log" >&2
    exit 1
  fi
done

for invalid_code in \
  "urn:chio:error:transaction:unknown" \
  "urn:chio:error:attest:signed-json-unknown" \
  ""; do
  if run_stub_gate 30 "$right_message" "$invalid_code"; then
    echo "check-chio-transaction-passport.test.sh: gate accepted unknown registry code: $invalid_code" >&2
    exit 1
  fi
  grep -Fq "unknown or missing registry code" "$fixture_tree/gate.log"
done

for invalid_report in \
  '{"message":"proof verify: evidence graph digest mismatch"}' \
  '{"code":null,"message":"proof verify: evidence graph digest mismatch"}' \
  '{"code":20,"message":"proof verify: evidence graph digest mismatch"}' \
  '{"code":{},"message":"proof verify: evidence graph digest mismatch"}'; do
  if run_stub_report 20 "$invalid_report"; then
    echo "check-chio-transaction-passport.test.sh: gate accepted a report without a string registry code" >&2
    exit 1
  fi
  grep -Fq "unknown or missing registry code" "$fixture_tree/gate.log"
done

for mismatch in \
  "20|urn:chio:error:transaction:required-claim-missing|10" \
  "20|urn:chio:error:transaction:artifact-schema-invalid|30" \
  "20|urn:chio:error:transaction:verifier-context-invalid|50" \
  "10|urn:chio:error:transaction:negative-case-mismatch|40"; do
  IFS='|' read -r actual code expected <<<"$mismatch"
  if run_stub_gate "$actual" "$right_message" "$code"; then
    echo "check-chio-transaction-passport.test.sh: gate accepted exit $actual for $code" >&2
    exit 1
  fi
  grep -Fq "requires exit $expected" "$fixture_tree/gate.log"
done

echo "check-chio-transaction-passport.test.sh: transaction passport gate contract passed"
