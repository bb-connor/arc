#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="all"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    shift
    ;;
  *)
    echo "usage: check-chio-transaction-passport.sh [--schema-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-transaction-passport.sh [--schema-only]" >&2
  exit 2
fi

CATALOG="$ROOT/fixtures/proof-room/catalog.json"
REGISTRY="$ROOT/spec/schemas/registry.json"
SCHEMA_ID="chio.transaction-passport.v1"
SCHEMA_FILE="spec/schemas/chio-transaction/v1/transaction-passport.schema.json"

python3 - "$ROOT" "$REGISTRY" "$CATALOG" "$SCHEMA_ID" "$SCHEMA_FILE" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
registry_path = pathlib.Path(sys.argv[2])
catalog_path = pathlib.Path(sys.argv[3])
schema_id = sys.argv[4]
schema_file = sys.argv[5]

registry = json.loads(registry_path.read_text(encoding="utf-8"))
rows = [
    row
    for row in registry.get("artifacts", [])
    if row.get("schema") == schema_id and row.get("schemaFile") == schema_file
]
if len(rows) != 1:
    raise SystemExit(
        f"transaction-passport schema must have exactly one registry row for {schema_file}"
    )
if not (root / schema_file).is_file():
    raise SystemExit(f"transaction-passport schema file is missing: {schema_file}")

signed_artifact_root = root / "crates/core/chio-core-types/src"
catalog_dir = signed_artifact_root / "signed_artifact/schema_specs"
catalog_files = sorted(catalog_dir.rglob("*.rs")) if catalog_dir.is_dir() else []
if not catalog_files:
    raise SystemExit(f"signed artifact catalog has no modules under {catalog_dir.relative_to(root)}")
signed_artifact = "".join(
    path.read_text(encoding="utf-8")
    for path in [
        signed_artifact_root / "signed_artifact.rs",
        signed_artifact_root / "signed_artifact/schema_specs.rs",
        *catalog_files,
    ]
)
if 'CHIO_TRANSACTION_PASSPORT_V1_SCHEMA: &str = "chio.transaction-passport.v1"' not in signed_artifact:
    raise SystemExit("transaction-passport schema is not named by chio-core-types")
if '"transaction_passport", "transaction-passport-v1"' not in signed_artifact:
    raise SystemExit("transaction-passport schema is not reachable from the built-in signed artifact registry")

catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
positive = []
negative = []
proof_room = []
for entry in catalog.get("fixtures", []):
    kind = entry.get("kind")
    if kind not in {"transaction-passport", "negative-transaction-passport", "proof-room"}:
        continue
    fixture_id = entry.get("id")
    fixture_path = entry.get("path")
    if not fixture_id or not fixture_path:
        raise SystemExit(f"transaction-passport catalog entry is missing id/path: {entry}")
    if kind == "proof-room":
        bundle_path = root / fixture_path / "proof-room-bundle"
        manifest_path = bundle_path / "manifest.json"
        passport_path = bundle_path / "roots" / "transaction-passport.json"
        if not manifest_path.is_file():
            raise SystemExit(f"Proof Room fixture manifest is missing: {manifest_path.relative_to(root)}")
        if not passport_path.is_file():
            raise SystemExit(f"Proof Room fixture passport is missing: {passport_path.relative_to(root)}")
        proof_room.append(fixture_id)
    elif kind == "transaction-passport":
        passport_path = root / fixture_path / "transaction-passport.json"
        if not passport_path.is_file():
            raise SystemExit(f"transaction-passport fixture is missing: {passport_path.relative_to(root)}")
        positive.append(fixture_id)
    else:
        passport_path = root / fixture_path / "transaction-passport.json"
        if not passport_path.is_file():
            raise SystemExit(f"transaction-passport fixture is missing: {passport_path.relative_to(root)}")
        negative.append(fixture_id)

if not positive:
    raise SystemExit("transaction-passport catalog has no positive fixtures")
if not negative:
    raise SystemExit("transaction-passport catalog has no negative fixtures")
if not proof_room:
    raise SystemExit("transaction-passport catalog has no Proof Room fixtures")

print(
    f"OK transaction-passport schema and catalog metadata: "
    f"{len(positive)} positive, {len(negative)} negative, {len(proof_room)} proof-room"
)
PY

cargo test -p chio-core-types --test signed_artifact_schema known_signed_artifact_schemas -- --nocapture

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

target_dir="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ -n "${CHIO_BIN:-}" ]]; then
  if [[ ! -x "$CHIO_BIN" ]]; then
    echo "CHIO_BIN is not executable: $CHIO_BIN" >&2
    exit 2
  fi
elif [[ -x "$target_dir/debug/chio" ]]; then
  CHIO_BIN="$target_dir/debug/chio"
else
  cargo build -p chio-cli --bin chio
  CHIO_BIN="$target_dir/debug/chio"
fi
unset target_dir

# shellcheck source=scripts/lib/chio-proof-trusted-keys.sh
source "$ROOT/scripts/lib/chio-proof-trusted-keys.sh"
PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON='{"chain_id":"eip155:8453","observed_block_number":12345678,"observed_block_hash":"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","latest_block_number":12345701}'

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

verify_positive() {
  local fixture_id="$1"
  local passport_path="$2"
  local stdout_path="$tmpdir/${fixture_id}.stdout.json"
  local stderr_path="$tmpdir/${fixture_id}.stderr.log"

  if ! "$CHIO_BIN" proof verify "$passport_path" >"$stdout_path" 2>"$stderr_path"; then
    echo "transaction-passport positive fixture failed: $fixture_id" >&2
    cat "$stderr_path" >&2
    cat "$stdout_path" >&2
    return 1
  fi
  python3 - "$stdout_path" "$fixture_id" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
fixture_id = sys.argv[2]
if report.get("verdict") != "verified":
    raise SystemExit(f"positive fixture {fixture_id} did not verify: {report.get('verdict')}")
PY
}

verify_negative() {
  local fixture_id="$1"
  local passport_path="$2"
  local metadata_path="$3"
  local stdout_path="$tmpdir/${fixture_id}.stdout.json"
  local stderr_path="$tmpdir/${fixture_id}.stderr.log"
  local verifier_context
  local status=0

  verifier_context="$(negative_verifier_context "$metadata_path")"

  run_negative_verify "$verifier_context" "$passport_path" "$stdout_path" "$stderr_path" || status=$?
  if [[ "$status" -eq 0 ]]; then
    echo "transaction-passport negative fixture unexpectedly verified: $fixture_id" >&2
    cat "$stdout_path" >&2
    return 1
  fi
  if ! python3 - "$fixture_id" "$metadata_path" "$status" "$stderr_path" <<'PY'; then
import json
import pathlib
import re
import sys

# Exit classes of `chio proof verify` for a rejected passport: 10 required
# claim, 20 integrity, 30 parse or schema, 50 unsupported verifier feature.
# The generic exit (1), a usage error (2), a panic (101) or a missing command
# (126, 127) is not a typed rejection.
REJECTION_EXITS = {10, 20, 30, 50}
TRANSACTION_CODES_BY_EXIT = {
    10: (
        "required-claim-missing", "claim-rejected", "identity-not-bound",
        "authorization-not-bound", "receipt-uncheckpointed", "runtime-proof-rejected",
        "buyer-review-rejected", "settlement-unverified", "dispute-unbound",
        "transparency-preview-not-allowed",
    ),
    20: (
        "passport-hash-mismatch", "artifact-hash-mismatch", "graph-not-closed",
        "graph-cycle", "signature-invalid",
    ),
    30: ("passport-schema-unsupported", "artifact-schema-invalid"),
    40: ("negative-case-mismatch",),
    50: ("verifier-feature-unsupported", "verifier-context-invalid"),
}
EXIT_BY_CODE = {
    code: exit_code
    for exit_code, names in TRANSACTION_CODES_BY_EXIT.items()
    for name in names
    for code in (
        f"urn:chio:error:transaction:{name}",
        f"CHIO-TRANSACTION-{name.upper()}",
    )
}
EXIT_BY_CODE["CHIO-CLI-JSON"] = 30
for name in (
    "too-large", "not-utf8", "invalid-input", "invalid-shape",
    "canonicalization", "noncanonical",
):
    EXIT_BY_CODE[f"urn:chio:error:attest:signed-json-{name}"] = 30

# Mirrors semantic_negative_failure_code and negative_failure_code_matches in
# crates/products/chio-cli/src/cli/dispatch/proof.rs.
CONTEXT_PREFIXES = (
    "invalid disclosure lineage artifact: ",
    "proof-room.source-verifier.failed: ",
    "proof-room.passport.invalid: ",
    "invalid agent web interop artifact: ",
    "invalid Agent Web interop artifact: ",
    "invalid public settlement artifact: ",
    "invalid enterprise export artifact: ",
    "invalid trust market artifact: ",
    "invalid runtime security artifact: ",
    "runtime security claim failed: ",
    "invalid evidence graph artifact: ",
    "minimal governed action evidence invalid: ",
    "commerce payment failed: ",
    "commerce mandate failed: ",
    "commerce event log failed: ",
    "commerce replay failed: ",
    "commerce recovery failed: ",
    "commerce fraud failed: ",
    "swarm authority invalid: ",
    "public settlement proof invalid: ",
    "invalid settlement: ",
    "invalid proof: ",
    "agent web interop invalid: ",
    "agent web claim failed: ",
    "Agent Web claim failed: ",
    "enterprise export invalid: ",
    "enterprise export claim failed: ",
    "risk comptroller claim failed: ",
    "trust market context invalid: ",
    "trust market claim failed: ",
    "trust-market claim failed: ",
    "Trust market claim failed: ",
    "Trust Market claim failed: ",
)
ASCII_WHITESPACE = " \t\n\x0c\r"


def is_dotted(code):
    base = code.split(":", 1)[0]
    return (
        bool(base)
        and "." in base
        and not any(character.isspace() for character in base)
        and all(
            ("a" <= character <= "z") or ("0" <= character <= "9") or character in ".-_"
            for character in base
        )
    )


def strip_context(code):
    code = code.strip()
    for prefix in CONTEXT_PREFIXES:
        if code.startswith(prefix):
            code = code[len(prefix):].strip()
    if not is_dotted(code) and ": " in code:
        code = code.split(": ", 1)[0].strip()
    return code


def slug(code):
    characters = []
    last_was_separator = False
    for character in code.lower():
        if character.isascii() and character.isalnum():
            characters.append(character)
            last_was_separator = False
        elif not last_was_separator:
            characters.append("-")
            last_was_separator = True
    return "".join(characters).strip("-")


def semantic_failure_code(error):
    parts = error.split("proof verify: ")
    code = (parts[1] if len(parts) > 1 else error).split(" (", 1)[0].strip()
    if not code:
        return error
    normalized = strip_context(code)
    if is_dotted(normalized):
        return normalized
    slugged = slug(normalized)
    return f"proof-room.negative.{slugged}" if slugged else "proof-room.negative.unknown"


def failure_code_matches(observed, expected):
    for match in re.finditer(re.escape(expected), observed):
        before = observed[: match.start()][-1:]
        after = observed[match.end():][:1]
        if before in ("", ":") or before in ASCII_WHITESPACE:
            if after in ("", ":"):
                return True
    return False


fixture_id = sys.argv[1]
metadata = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
status = int(sys.argv[3])
stderr_text = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8", errors="replace")
expected = metadata.get("expected_failure_code")
if not isinstance(expected, str) or not expected:
    raise SystemExit(f"negative fixture {fixture_id} has no expected_failure_code")
if status not in REJECTION_EXITS:
    raise SystemExit(
        f"negative fixture {fixture_id} exited {status}, not a proof rejection exit {sorted(REJECTION_EXITS)}"
    )
lines = [line for line in stderr_text.splitlines() if line.strip()]
try:
    report = json.loads(lines[-1]) if lines else None
except json.JSONDecodeError:
    report = None
message = report.get("message") if isinstance(report, dict) else None
if not isinstance(message, str):
    raise SystemExit(f"negative fixture {fixture_id} did not emit a JSON error report")
code = report.get("code")
expected_exit = EXIT_BY_CODE.get(code) if isinstance(code, str) else None
if expected_exit is None:
    raise SystemExit(f"negative fixture {fixture_id} has an unknown or missing registry code")
if status != expected_exit:
    raise SystemExit(
        f"negative fixture {fixture_id} code {code} requires exit {expected_exit}, got {status}"
    )
observed = semantic_failure_code(message)
if not failure_code_matches(observed, expected):
    raise SystemExit(
        f"negative fixture {fixture_id} rejected for the wrong reason: expected {expected}, got {observed}"
    )
PY
    echo "transaction-passport negative fixture failed: $fixture_id" >&2
    cat "$stderr_path" >&2
    return 1
  fi
}

negative_verifier_context() {
  local metadata_path="$1"
  python3 - "$metadata_path" <<'PY'
import json
import pathlib
import sys

metadata = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
context = metadata.get("verifier_context") or {}
print(context.get("public_settlement_independent_chain_head") or "none")
PY
}

run_negative_verify() {
  local verifier_context="$1"
  local passport_path="$2"
  local stdout_path="$3"
  local stderr_path="$4"

  case "$verifier_context" in
    missing)
      env -u CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON \
        -u CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL \
        "$CHIO_BIN" --json proof verify "$passport_path" >"$stdout_path" 2>"$stderr_path"
      ;;
    block_hash_mismatch)
      env -u CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL \
        CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON="$PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON" \
        "$CHIO_BIN" --json proof verify "$passport_path" >"$stdout_path" 2>"$stderr_path"
      ;;
    none)
      "$CHIO_BIN" --json proof verify "$passport_path" >"$stdout_path" 2>"$stderr_path"
      ;;
    *)
      echo "unknown negative verifier context: $verifier_context" >&2
      return 2
      ;;
  esac
}

verify_proof_room() {
  local fixture_id="$1"
  local bundle_path="$2"
  local stdout_path="$tmpdir/${fixture_id}.stdout.json"
  local stderr_path="$tmpdir/${fixture_id}.stderr.log"

  if ! "$CHIO_BIN" proof verify "$bundle_path" >"$stdout_path" 2>"$stderr_path"; then
    echo "Proof Room fixture failed: $fixture_id" >&2
    cat "$stderr_path" >&2
    cat "$stdout_path" >&2
    return 1
  fi
  python3 - "$stdout_path" "$fixture_id" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
fixture_id = sys.argv[2]
if report.get("verdict") != "verified":
    raise SystemExit(f"Proof Room fixture {fixture_id} did not verify: {report.get('verdict')}")
PY
}

positive_count=0
negative_count=0
proof_room_count=0
fixture_rows="$tmpdir/transaction-passport-fixtures.tsv"
python3 - "$ROOT" "$CATALOG" >"$fixture_rows" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
catalog = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
for entry in catalog.get("fixtures", []):
    kind = entry.get("kind")
    if kind not in {"transaction-passport", "negative-transaction-passport", "proof-room"}:
        continue
    fixture_id = entry["id"]
    if kind == "proof-room":
        rel = pathlib.Path(entry["path"]) / "proof-room-bundle"
        metadata = ""
        if not (root / rel / "manifest.json").is_file():
            raise SystemExit(f"missing Proof Room fixture manifest: {rel / 'manifest.json'}")
    else:
        base = pathlib.Path(entry["path"])
        rel = base / "transaction-passport.json"
        metadata = ""
        if kind == "negative-transaction-passport":
            metadata_path = base.parent / "negatives" / f"{base.name}.json"
            if not (root / metadata_path).is_file():
                raise SystemExit(f"missing negative fixture metadata: {metadata_path}")
            metadata = str(metadata_path)
        if not (root / rel).is_file():
            raise SystemExit(f"missing fixture passport: {rel}")
    print(f"{kind}\t{fixture_id}\t{rel}\t{metadata}")
PY

while IFS=$'\t' read -r kind fixture_id fixture_path metadata_path; do
  case "$kind" in
    transaction-passport)
      verify_positive "$fixture_id" "$ROOT/$fixture_path"
      positive_count=$((positive_count + 1))
      ;;
    negative-transaction-passport)
      verify_negative "$fixture_id" "$ROOT/$fixture_path" "$ROOT/$metadata_path"
      negative_count=$((negative_count + 1))
      ;;
    proof-room)
      verify_proof_room "$fixture_id" "$ROOT/$fixture_path"
      proof_room_count=$((proof_room_count + 1))
      ;;
    *)
      echo "unexpected proof fixture kind: $kind" >&2
      exit 1
      ;;
  esac
done <"$fixture_rows"

printf 'OK transaction-passport verifier gate: %s positive, %s negative, %s proof-room\n' \
  "$positive_count" "$negative_count" "$proof_room_count"
