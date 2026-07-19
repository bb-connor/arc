#!/usr/bin/env bash
# Self-test for scripts/check-threat-coverage-mutants.sh.
#
# Owner: threat-coverage evidence gate.
#
# Exercises the core threat-coverage evidence scenarios:
#
#   1. A row with valid evidence (caught >= 1) PASSES.
#   2. A row with `needs_real_run: true` produces a downgrade hint
#      (`bootstrap_placeholder`) and fails by default.
#   3. A row with `coverage_state: weak_coverage` in the JSON
#      causes `check-threat-coverage.sh` (the file-existence gate
#      that owns enum policy) to FAIL with a clear message naming
#      the row.
#   4. A missing evidence file produces a downgrade hint
#      (`missing_evidence`) and FAILS the gate (without --dry-run)
#      while passing under --dry-run.
#
# We also lock in two extra invariants:
#   - `caught: 0` without `needs_real_run` produces `zero_kills`
#     and FAILS.
#   - A covered row with no `coveredBy`/`covered_by_tests` produces
#     `no_coveredby` and FAILS.
#   - Generated or conformance-only metadata cannot pass as real
#     cargo-mutants evidence by setting `needs_real_run=false`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Each case below sets CI explicitly when it needs it (case 9 opts into
# CI=true to assert the dry-run refusal). Neutralize any ambient CI value so
# the local-mode dry-run pass-cases are not tripped by the runner's CI=true.
unset CI

MODEL="$TMP_DIR/threat-model.json"
EVIDENCE_DIR="$TMP_DIR/evidence"
CASES_DIR="$TMP_DIR/cases"
TESTS_DIR="$TMP_DIR/tests"
STUBS="$TMP_DIR/stubs"
OUT="$TMP_DIR/out"
ERR="$TMP_DIR/err"

reset_fixture() {
    rm -rf "$MODEL" "$EVIDENCE_DIR" "$CASES_DIR" "$TESTS_DIR" "$STUBS"
    mkdir -p "$EVIDENCE_DIR" "$CASES_DIR" "$TESTS_DIR" "$STUBS"
}

write_adversarial_case() {
    # write_adversarial_case <case_id> <threat_id> <campaign_id> <outcome_path>
    local case_id="$1"
    local threat_id="$2"
    local campaign_id="$3"
    local outcome_path="$4"
    python3 - "$CASES_DIR/$case_id.json" "$case_id" "$threat_id" "$campaign_id" "$outcome_path" <<'PY'
import json
import sys

path, case_id, threat_id, campaign_id, outcome_path = sys.argv[1:6]
with open(path, "w", encoding="utf-8") as destination:
    json.dump(
        {
            "id": case_id,
            "threat_id": threat_id,
            "artifact": {
                "campaigns": [
                    {
                        "id": campaign_id,
                        "outcomes": {"path": outcome_path},
                    }
                ]
            },
        },
        destination,
        sort_keys=True,
        separators=(",", ":"),
    )
PY
}

write_closed_subvector_test() {
    local id="$1"
    printf '%s\n' \
        '#[test]' \
        "fn ${id}_closed_subvector() {" \
        '    assert!(true);' \
        '}' > "$TESTS_DIR/$id.rs"
}

write_model_single() {
    # write_model_single <id> <state> [<has_coveredby>=1]
    local id="$1"
    local state="$2"
    local has_coveredby="${3:-1}"
    python3 - "$MODEL" "$id" "$state" "$has_coveredby" <<'PY'
import json
import sys

path, threat_id, state, has_coveredby = sys.argv[1:5]
threat = {
    "id": threat_id,
    "name": threat_id.replace("_", " ").title(),
    "surfaces": ["native_chio"],
    "coverage_state": state,
}
if has_coveredby == "1":
    threat["coveredBy"] = [f"crates/tooling/chio-conformance/tests/threats/{threat_id}.rs"]

with open(path, "w") as fh:
    json.dump({"threats": [threat]}, fh)
    fh.write("\n")
PY
}

write_evidence() {
    # write_evidence <id> <caught> [<needs_real_run>=false] [<ran_at_override>]
    #                [<timestamp_kind>] [<evidence_status>]
    #                [<mutation_evidence_status>] [<promotion_status>]
    # Bootstrap placeholders (needs_real_run=true) require ran_at to be the
    # 1970 epoch sentinel; real-run rows record the actual timestamp.
    local id="$1"
    local caught="$2"
    local needs_real_run="${3:-false}"
    local ran_at_override="${4:-}"
    local timestamp_kind="${5:-}"
    local evidence_status="${6:-}"
    local mutation_evidence_status="${7:-}"
    local promotion_status="${8:-}"
    local ran_at
    if [[ -n "$ran_at_override" ]]; then
        ran_at="$ran_at_override"
    elif [[ "$needs_real_run" == "true" ]]; then
        ran_at="1970-01-01T00:00:00Z"
    else
        ran_at="2026-05-05T00:00:00Z"
    fi
    if [[ -z "$timestamp_kind" ]]; then
        if [[ "$needs_real_run" == "true" ]]; then
            timestamp_kind="bootstrap-placeholder"
        else
            timestamp_kind="command-wall-clock"
        fi
    fi
    if [[ -z "$evidence_status" ]]; then
        if [[ "$needs_real_run" == "true" ]]; then
            evidence_status="conformance-only"
        else
            evidence_status="cargo-mutants-run"
        fi
    fi
    if [[ -z "$mutation_evidence_status" ]]; then
        if [[ "$needs_real_run" == "true" ]]; then
            mutation_evidence_status="not-run"
        else
            mutation_evidence_status="complete"
        fi
    fi
    if [[ -z "$promotion_status" ]]; then
        if [[ "$needs_real_run" == "true" ]]; then
            promotion_status="not-promoted"
        else
            promotion_status="promoted"
        fi
    fi
    local child_relative=""
    local digest=""
    if [[ "$needs_real_run" == "false" && "$caught" -ge 1 ]]; then
        local child="$TMP_DIR/${id}-outcomes.json"
        python3 - "$child" "$caught" <<'PY'
import json
import sys

path, caught = sys.argv[1:3]
caught = int(caught)
with open(path, "w", encoding="utf-8") as destination:
    json.dump(
        {
            "caught": caught,
            "missed": 0,
            "timeout": 0,
            "unviable": 0,
            "success": 0,
            "total_mutants": caught,
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                *[
                    {
                        "scenario": {"Mutant": {"fixture_index": index}},
                        "summary": "CaughtMutant",
                    }
                    for index in range(caught)
                ],
            ],
        },
        destination,
        sort_keys=True,
        separators=(",", ":"),
    )
PY
        child_relative="${child#"$TMP_DIR"/}"
        digest="$(sha256sum "$child" | cut -d' ' -f1)"
        write_adversarial_case "${id}_case" "$id" "${id}_mutation" "$child_relative"
        write_closed_subvector_test "$id"
    fi
    cat > "$EVIDENCE_DIR/$id.json" <<JSON
{
  "caught": $caught,
  "survivors": [],
  "ran_at": "$ran_at",
  "timestamp_kind": "$timestamp_kind",
  "evidence_status": "$evidence_status",
  "mutation_evidence_status": "$mutation_evidence_status",
  "promotion_status": "$promotion_status",
  "needs_real_run": $needs_real_run
}
JSON
    if [[ -n "$child_relative" ]]; then
        python3 - "$EVIDENCE_DIR/$id.json" "$id" "$child_relative" "$digest" <<'PY'
import json
import sys

path, threat_id, child_path, digest = sys.argv[1:5]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["mutation_case_path"] = f"cases/{threat_id}_case.json"
body["closed_subvector_test"] = {
    "path": f"tests/{threat_id}.rs",
    "name": f"{threat_id}_closed_subvector",
}
body["note"] = (
    "Digest-bound caught-only cargo-mutants outcomes cover the closed sub-vector: "
    f"{threat_id}_mutation caught {body['caught']}, with zero missed, timed-out, "
    "or unviable mutants."
)
body["reproduction_command"] = (
    "./scripts/check-security-adversarial-evidence.sh --verify-outcome "
    f"{threat_id}_mutation {child_path}"
)
body["timestamp_note"] = (
    "The timestamp records completion of caught-only mutation rerun validation. "
    "Native outcomes retain cargo-mutants phase records and durations."
)
body["outcomes"] = [
    {
        "id": f"{threat_id}_mutation",
        "path": child_path,
        "sha256": digest,
    }
]
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
    fi
}

write_nested_evidence() {
    # write_nested_evidence <id> <parent_caught> <child_caught> [<recorded_sha>]
    local id="$1"
    local parent_caught="$2"
    local child_caught="$3"
    local child="$TMP_DIR/${id}-outcomes.json"
    python3 - "$child" "$child_caught" <<'PY'
import json
import sys

path, caught = sys.argv[1:3]
caught = int(caught)
with open(path, "w", encoding="utf-8") as destination:
    json.dump(
        {
            "caught": caught,
            "missed": 0,
            "timeout": 0,
            "unviable": 0,
            "success": 0,
            "total_mutants": caught,
            "outcomes": [
                {"scenario": "Baseline", "summary": "Success"},
                *[
                    {
                        "scenario": {"Mutant": {"fixture_index": index}},
                        "summary": "CaughtMutant",
                    }
                    for index in range(caught)
                ],
            ],
        },
        destination,
        sort_keys=True,
        separators=(",", ":"),
    )
PY
    local digest="${4:-$(sha256sum "$child" | cut -d' ' -f1)}"
    cat > "$EVIDENCE_DIR/$id.json" <<JSON
{
  "caught": $parent_caught,
  "survivors": [],
  "ran_at": "2026-05-05T12:34:56Z",
  "timestamp_kind": "command-wall-clock",
  "evidence_status": "cargo-mutants-run",
  "mutation_evidence_status": "complete",
  "promotion_status": "promoted",
  "needs_real_run": false,
  "mutation_case_path": "cases/${id}_case.json",
  "closed_subvector_test": {
    "path": "tests/$id.rs",
    "name": "${id}_closed_subvector"
  },
  "note": "Digest-bound caught-only cargo-mutants outcomes cover the closed sub-vector: ${id}_mutation caught $child_caught, with zero missed, timed-out, or unviable mutants.",
  "reproduction_command": "./scripts/check-security-adversarial-evidence.sh --verify-outcome ${id}_mutation ${child#"$TMP_DIR"/}",
  "timestamp_note": "The timestamp records completion of caught-only mutation rerun validation. Native outcomes retain cargo-mutants phase records and durations.",
  "outcomes": [
    {
      "id": "${id}_mutation",
      "path": "${child#"$TMP_DIR"/}",
      "sha256": "$digest"
    }
  ]
}
JSON
    write_adversarial_case "${id}_case" "$id" "${id}_mutation" "${child#"$TMP_DIR"/}"
    write_closed_subvector_test "$id"
}

refresh_nested_digest() {
    local id="$1"
    python3 - \
        "$TMP_DIR/${id}-outcomes.json" \
        "$EVIDENCE_DIR/$id.json" <<'PY'
import hashlib
import json
import sys

child_path, evidence_path = sys.argv[1:3]
digest = hashlib.sha256(open(child_path, "rb").read()).hexdigest()
with open(evidence_path, encoding="utf-8") as source:
    evidence = json.load(source)
evidence["outcomes"][0]["sha256"] = digest
with open(evidence_path, "w", encoding="utf-8") as destination:
    json.dump(evidence, destination)
PY
}

write_stub() {
    local id="$1"
    local body="$2"
    printf '%s\n' '#[test]' "fn ${id}_stub() {" "    ${body}" '}' > "$STUBS/$id.rs"
}

run_mutants_gate() {
    local extra_args=("$@")
    CHIO_THREAT_MODEL_PATH="$MODEL" \
    CHIO_THREAT_EVIDENCE_DIR="$EVIDENCE_DIR" \
    CHIO_THREAT_EVIDENCE_REPOSITORY_ROOT="$TMP_DIR" \
    CHIO_SECURITY_ADVERSARIAL_CASES_DIR="$CASES_DIR" \
        bash "$REPO_ROOT/scripts/check-threat-coverage-mutants.sh" ${extra_args[@]+"${extra_args[@]}"} \
        >"$OUT" 2>"$ERR"
}

run_file_gate() {
    CHIO_THREAT_MODEL_PATH="$MODEL" \
    CHIO_THREAT_STUBS_DIR="$STUBS" \
        bash "$REPO_ROOT/scripts/check-threat-coverage.sh" >"$OUT" 2>"$ERR"
}

assert_passes() {
    local label="$1"; shift
    if ! "$@"; then
        echo "FAIL: expected pass for $label" >&2
        echo "--- stdout ---" >&2
        cat "$OUT" >&2
        echo "--- stderr ---" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

assert_fails() {
    local label="$1"; shift
    if "$@"; then
        echo "FAIL: expected failure for $label" >&2
        echo "--- stdout ---" >&2
        cat "$OUT" >&2
        echo "--- stderr ---" >&2
        cat "$ERR" >&2
        exit 1
    fi
}

# Case 1: valid evidence (caught >= 1) PASSES.
reset_fixture
write_model_single "valid_threat" "covered"
write_evidence "valid_threat" 7 false
assert_passes "valid evidence passes" run_mutants_gate
grep -q "passed: 1" "$OUT"

# Case 2: bootstrap placeholder produces hint and fails by default because
# placeholders are not release-covered evidence.
reset_fixture
write_model_single "bootstrap_threat" "covered"
write_evidence "bootstrap_threat" 0 true
assert_fails "bootstrap placeholder fails by default" run_mutants_gate
grep -q "bootstrap placeholders: 1" "$OUT"
grep -q "WEAK: bootstrap_threat should be marked weak_coverage; reason=bootstrap_placeholder" "$OUT"

# Case 2b: same input passes only under the explicit placeholder fixture mode
# or dry-run. Release/preflight callers do not use this flag.
assert_passes "bootstrap placeholder passes under explicit fixture mode" \
    run_mutants_gate --allow-bootstrap-placeholders
grep -q "bootstrap placeholders: 1" "$OUT"

# Case 2c: same input, dry-run, also passes.
assert_passes "bootstrap placeholder passes under --dry-run" run_mutants_gate --dry-run
grep -q "bootstrap placeholders: 1" "$OUT"

# Case 3: weak_coverage in JSON FAILS the file-existence gate with a
# clear message naming the row.
reset_fixture
write_model_single "weak_threat" "weak_coverage"
write_stub "weak_threat" "assert!(true);"
assert_fails "weak_coverage state fails the file-existence gate" run_file_gate
grep -q "weak_threat (coverage_state weak_coverage" "$ERR"

# Case 4: missing evidence file produces hint and FAILS by default,
# but PASSES under --dry-run.
reset_fixture
write_model_single "missing_evidence_threat" "covered"
# Intentionally do NOT write evidence file.
assert_fails "missing evidence fails by default" run_mutants_gate
grep -q "WEAK: missing_evidence_threat should be marked weak_coverage; reason=missing_evidence" "$ERR"

assert_passes "missing evidence passes under --dry-run" run_mutants_gate --dry-run
grep -q "WEAK: missing_evidence_threat should be marked weak_coverage; reason=missing_evidence" "$ERR"

# Case 5 (extra): caught: 0 without needs_real_run FAILS with zero_kills.
reset_fixture
write_model_single "zero_kills_threat" "covered"
write_evidence "zero_kills_threat" 0 false
assert_fails "zero kills fails the gate" run_mutants_gate
grep -q "WEAK: zero_kills_threat should be marked weak_coverage; reason=zero_kills" "$ERR"

# Case 6 (extra): no coveredBy/covered_by_tests FAILS with no_coveredby.
reset_fixture
write_model_single "no_coveredby_threat" "covered" 0
# Even with valid evidence, missing coveredBy should still flag.
write_evidence "no_coveredby_threat" 5 false
assert_fails "no coveredBy fails the gate" run_mutants_gate
grep -q "WEAK: no_coveredby_threat should be marked weak_coverage; reason=no_coveredby" "$ERR"

# Case 7: bootstrap placeholder AFTER expiry FAILS with
# reason=bootstrap_expired. CHIO_BOOTSTRAP_EXPIRY=1970-01-01 forces the
# accommodation to be expired regardless of today's date.
reset_fixture
write_model_single "expired_bootstrap_threat" "covered"
write_evidence "expired_bootstrap_threat" 0 true
CHIO_BOOTSTRAP_EXPIRY="1970-01-01" \
    assert_fails "bootstrap_expired fails after expiry date" run_mutants_gate
grep -q "WEAK: expired_bootstrap_threat should be marked weak_coverage; reason=bootstrap_expired" "$ERR" \
    || { echo "FAIL: missing bootstrap_expired diagnostic"; cat "$ERR"; exit 1; }

# Case 7b: same input WITHOUT the expiry override still fails by default.
CHIO_BOOTSTRAP_EXPIRY="2099-01-01" \
    assert_fails "bootstrap placeholder fails before expiry by default" run_mutants_gate

# Case 7c: explicit fixture mode can still admit the pre-expiry placeholder.
CHIO_BOOTSTRAP_EXPIRY="2099-01-01" \
    assert_passes "bootstrap placeholder fixture mode before expiry" \
    run_mutants_gate --allow-bootstrap-placeholders

# Case 8: needs_real_run=true with non-1970 ran_at is
# rejected as inconsistent_bootstrap.
reset_fixture
write_model_single "inconsistent_bootstrap_threat" "covered"
write_evidence "inconsistent_bootstrap_threat" 0 true "2026-05-05T12:00:00Z"
assert_fails "inconsistent bootstrap (real ran_at + needs_real_run) fails" run_mutants_gate
grep -q "WEAK: inconsistent_bootstrap_threat should be marked weak_coverage; reason=inconsistent_bootstrap" "$ERR" \
    || { echo "FAIL: missing inconsistent_bootstrap diagnostic"; cat "$ERR"; exit 1; }

# Case 9: CI=true + --dry-run is rejected (exit 2).
reset_fixture
write_model_single "ci_dryrun_threat" "covered"
write_evidence "ci_dryrun_threat" 1 false
CI=true assert_fails "CI=true forbids --dry-run" run_mutants_gate --dry-run
grep -q "dry-run is not allowed in CI" "$ERR" \
    || { echo "FAIL: missing CI dry-run diagnostic"; cat "$ERR"; exit 1; }

# Case 10: partial rows are still gated by per-row mutants
# evidence. The row can remain partial, but the defended sub-vector must
# have present, non-placeholder evidence with caught >= 1.
reset_fixture
python3 - "$MODEL" <<'PY'
import json, sys
with open(sys.argv[1], "w") as fh:
    json.dump({"threats": [{
        "id": "partial_with_deferred",
        "name": "Partial With Deferred",
        "surfaces": ["native_chio"],
        "coverage_state": "partial",
        "deferred_to": "future-threat-coverage-closure",
        "coveredBy": ["crates/tooling/chio-conformance/tests/threats/partial_with_deferred.rs"],
    }]}, fh)
    fh.write("\n")
PY
# Intentionally no evidence file: partial rows now fail the mutants gate.
assert_fails "partial-with-deferred row without evidence fails" run_mutants_gate
grep -q "WEAK: partial_with_deferred should be marked weak_coverage; reason=missing_evidence" "$ERR"

write_evidence "partial_with_deferred" 2 false "2026-05-05T12:34:56Z"
assert_passes "partial-with-deferred row with evidence passes" run_mutants_gate
grep -q "passed: 1" "$OUT" \
    || { echo "FAIL: partial row with evidence should be counted as passed"; cat "$OUT"; exit 1; }

# Case 11: generated conformance metadata cannot be promoted as cargo-mutants
# evidence just by flipping needs_real_run=false and caught>=1. Exact-midnight
# timestamps are valid only when they are honestly labeled as generated
# metadata, not command wall-clock evidence.
reset_fixture
write_model_single "generated_metadata_threat" "covered"
write_evidence \
    "generated_metadata_threat" \
    1 \
    false \
    "2026-05-08T00:00:00Z" \
    "generated-metadata" \
    "conformance-only" \
    "not-run" \
    "not-promoted"
assert_fails "generated metadata cannot pass as mutants evidence" run_mutants_gate
grep -q "WEAK: generated_metadata_threat should be marked weak_coverage; reason=non_mutants_metadata" "$ERR" \
    || { echo "FAIL: missing non_mutants_metadata diagnostic"; cat "$ERR"; exit 1; }

# Case 12: a required mutation gate cannot pass without evaluating at least
# one covered or partial row.
reset_fixture
write_model_single "pending_only_threat" "pending"
assert_fails "zero eligible rows fail the gate" run_mutants_gate
grep -q "zero covered or partial rows" "$ERR" \
    || { echo "FAIL: missing zero-row diagnostic"; cat "$ERR"; exit 1; }

# Case 13: nested evidence cannot inflate the parent caught count.
reset_fixture
write_model_single "inflated_aggregate" "partial"
write_nested_evidence "inflated_aggregate" 5 1
assert_fails "nested caught count mismatch fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: missing aggregate-rejection diagnostic"; cat "$ERR"; exit 1; }

# Case 14: nested evidence must bind the exact child bytes.
reset_fixture
write_model_single "wrong_child_digest" "partial"
write_nested_evidence "wrong_child_digest" 1 1 \
    "0000000000000000000000000000000000000000000000000000000000000000"
assert_fails "nested child digest mismatch fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: missing child-digest diagnostic"; cat "$ERR"; exit 1; }

# Case 15: an exact caught-only child aggregate passes fixture validation.
reset_fixture
write_model_single "valid_aggregate" "partial"
write_nested_evidence "valid_aggregate" 1 1
assert_passes "valid nested aggregate passes" run_mutants_gate
grep -q "passed: 1" "$OUT"

# Case 16: a non-placeholder row cannot pass without a nonempty outcomes
# array, even when its parent caught count is positive.
reset_fixture
write_model_single "missing_outcomes" "partial"
write_evidence "missing_outcomes" 1 false "2026-05-05T12:34:56Z"
python3 - "$EVIDENCE_DIR/missing_outcomes.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body.pop("outcomes")
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "non-placeholder evidence without outcomes fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: missing outcomes were not rejected"; cat "$ERR"; exit 1; }

# Case 17: an outcome campaign cannot be borrowed from a case that cites a
# different threat-model row.
reset_fixture
write_model_single "wrong_case_threat" "partial"
write_nested_evidence "wrong_case_threat" 1 1
python3 - "$CASES_DIR/wrong_case_threat_case.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["threat_id"] = "different_threat"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "outcome bound to a different case threat fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: wrong case threat was not rejected"; cat "$ERR"; exit 1; }

# Case 18: the evidence record id must identify a campaign in the adversarial
# case index.
reset_fixture
write_model_single "unknown_campaign" "partial"
write_nested_evidence "unknown_campaign" 1 1
python3 - "$EVIDENCE_DIR/unknown_campaign.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["outcomes"][0]["id"] = "not_in_the_case_index"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "unknown outcome campaign id fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: unknown campaign id was not rejected"; cat "$ERR"; exit 1; }

# Case 19: a valid child cannot be substituted at a path other than the one
# bound to the campaign in the adversarial case index.
reset_fixture
write_model_single "wrong_campaign_path" "partial"
write_nested_evidence "wrong_campaign_path" 1 1
cp "$TMP_DIR/wrong_campaign_path-outcomes.json" "$TMP_DIR/substituted-outcomes.json"
python3 - "$EVIDENCE_DIR/wrong_campaign_path.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["outcomes"][0]["path"] = "substituted-outcomes.json"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "outcome path different from indexed campaign path fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: wrong campaign path was not rejected"; cat "$ERR"; exit 1; }

# Case 20: mutation_case_path must name the exact adversarial case that owns
# every campaign cited by the aggregate.
reset_fixture
write_model_single "wrong_case_link" "partial"
write_nested_evidence "wrong_case_link" 1 1
python3 - "$CASES_DIR/decoy-case.json" "$EVIDENCE_DIR/wrong_case_link.json" <<'PY'
import json
import sys

decoy_path, evidence_path = sys.argv[1:3]
with open(decoy_path, "w", encoding="utf-8") as destination:
    json.dump(
        {
            "id": "decoy-case",
            "threat_id": "wrong_case_link",
            "artifact": {"case_kind": "decoy"},
        },
        destination,
    )
with open(evidence_path, encoding="utf-8") as source:
    body = json.load(source)
body["mutation_case_path"] = "cases/decoy-case.json"
with open(evidence_path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "aggregate linked to a different case path fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: wrong mutation case link was not rejected"; cat "$ERR"; exit 1; }

# Case 21: closed_subvector_test must identify an actual #[test] function in
# the bound Rust source file.
reset_fixture
write_model_single "wrong_closed_test" "partial"
write_nested_evidence "wrong_closed_test" 1 1
python3 - "$EVIDENCE_DIR/wrong_closed_test.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["closed_subvector_test"]["name"] = "not_a_rust_test"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "aggregate linked to a nonexistent Rust test fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: wrong closed-subvector test was not rejected"; cat "$ERR"; exit 1; }

# Case 22: positive real evidence must carry both structured aggregate-linkage
# fields.
reset_fixture
write_model_single "missing_case_link" "partial"
write_nested_evidence "missing_case_link" 1 1
python3 - "$EVIDENCE_DIR/missing_case_link.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body.pop("mutation_case_path")
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "positive evidence without structured case linkage fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: missing mutation case link was not rejected"; cat "$ERR"; exit 1; }

# Case 23: a digest-bound child with any missed mutant is not caught-only
# evidence.
reset_fixture
write_model_single "missed_child_mutant" "partial"
write_nested_evidence "missed_child_mutant" 1 1
python3 - \
    "$TMP_DIR/missed_child_mutant-outcomes.json" \
    "$EVIDENCE_DIR/missed_child_mutant.json" <<'PY'
import hashlib
import json
import sys

child_path, evidence_path = sys.argv[1:3]
with open(child_path, encoding="utf-8") as source:
    child = json.load(source)
child["missed"] = 1
child["total_mutants"] = 2
with open(child_path, "w", encoding="utf-8") as destination:
    json.dump(child, destination, sort_keys=True, separators=(",", ":"))
digest = hashlib.sha256(open(child_path, "rb").read()).hexdigest()
with open(evidence_path, encoding="utf-8") as source:
    evidence = json.load(source)
evidence["outcomes"][0]["sha256"] = digest
with open(evidence_path, "w", encoding="utf-8") as destination:
    json.dump(evidence, destination)
PY
assert_fails "nested evidence with a missed mutant fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: non-caught child evidence was not rejected"; cat "$ERR"; exit 1; }

# Case 24: each child total must equal its caught count even when every
# non-caught counter is zero.
reset_fixture
write_model_single "inconsistent_child_total" "partial"
write_nested_evidence "inconsistent_child_total" 1 1
python3 - \
    "$TMP_DIR/inconsistent_child_total-outcomes.json" \
    "$EVIDENCE_DIR/inconsistent_child_total.json" <<'PY'
import hashlib
import json
import sys

child_path, evidence_path = sys.argv[1:3]
with open(child_path, encoding="utf-8") as source:
    child = json.load(source)
child["total_mutants"] = 2
with open(child_path, "w", encoding="utf-8") as destination:
    json.dump(child, destination, sort_keys=True, separators=(",", ":"))
digest = hashlib.sha256(open(child_path, "rb").read()).hexdigest()
with open(evidence_path, encoding="utf-8") as source:
    evidence = json.load(source)
evidence["outcomes"][0]["sha256"] = digest
with open(evidence_path, "w", encoding="utf-8") as destination:
    json.dump(evidence, destination)
PY
assert_fails "nested evidence with an inconsistent child total fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: inconsistent child count was not rejected"; cat "$ERR"; exit 1; }

# Case 25: duplicate keys in the aggregate row cannot override an earlier
# value under the JSON parser's last-key-wins behavior.
reset_fixture
write_model_single "duplicate_row_key" "partial"
write_nested_evidence "duplicate_row_key" 1 1
python3 - "$EVIDENCE_DIR/duplicate_row_key.json" <<'PY'
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    payload = source.read()
payload = payload.replace('"caught": 1,', '"caught": 999,\n  "caught": 1,', 1)
with open(path, "w", encoding="utf-8") as destination:
    destination.write(payload)
PY
assert_fails "duplicate aggregate-row key fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: duplicate aggregate-row key was not rejected"; cat "$ERR"; exit 1; }

# Case 26: duplicate keys in an indexed adversarial case are ambiguous even
# when the final value matches the threat row.
reset_fixture
write_model_single "duplicate_case_key" "partial"
write_nested_evidence "duplicate_case_key" 1 1
python3 - "$CASES_DIR/duplicate_case_key_case.json" <<'PY'
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    payload = source.read()
payload = payload.replace(
    '"threat_id":"duplicate_case_key"',
    '"threat_id":"different_threat","threat_id":"duplicate_case_key"',
    1,
)
with open(path, "w", encoding="utf-8") as destination:
    destination.write(payload)
PY
assert_fails "duplicate adversarial-case key fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: duplicate adversarial-case key was not rejected"; cat "$ERR"; exit 1; }

# Case 27: duplicate keys in a digest-bound native child are ambiguous even
# when the final value is internally consistent.
reset_fixture
write_model_single "duplicate_child_key" "partial"
write_nested_evidence "duplicate_child_key" 1 1
python3 - "$TMP_DIR/duplicate_child_key-outcomes.json" <<'PY'
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    payload = source.read()
payload = payload.replace('"caught":1', '"caught":999,"caught":1', 1)
with open(path, "w", encoding="utf-8") as destination:
    destination.write(payload)
PY
refresh_nested_digest "duplicate_child_key"
assert_fails "duplicate native-child key fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: duplicate native-child key was not rejected"; cat "$ERR"; exit 1; }

# Case 28: duplicate keys in a threat-model row are rejected before row
# classification.
reset_fixture
write_model_single "duplicate_model_key" "partial"
write_nested_evidence "duplicate_model_key" 1 1
python3 - "$MODEL" <<'PY'
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    payload = source.read()
payload = payload.replace(
    '"coverage_state": "partial"',
    '"coverage_state": "pending", "coverage_state": "partial"',
    1,
)
with open(path, "w", encoding="utf-8") as destination:
    destination.write(payload)
PY
assert_fails "duplicate threat-model-row key fails" run_mutants_gate

# Case 29: a decimal string cannot be coerced into the aggregate caught count.
reset_fixture
write_model_single "string_caught" "partial"
write_nested_evidence "string_caught" 1 1
python3 - "$EVIDENCE_DIR/string_caught.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["caught"] = "1"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "string aggregate caught count fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: string caught count was not rejected"; cat "$ERR"; exit 1; }

# Case 30: a JSON boolean cannot be coerced into the aggregate caught count.
reset_fixture
write_model_single "boolean_caught" "partial"
write_nested_evidence "boolean_caught" 1 1
python3 - "$EVIDENCE_DIR/boolean_caught.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["caught"] = True
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "boolean aggregate caught count fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: boolean caught count was not rejected"; cat "$ERR"; exit 1; }

# Case 31: a fractional JSON number cannot be truncated into the aggregate
# caught count.
reset_fixture
write_model_single "fractional_caught" "partial"
write_nested_evidence "fractional_caught" 1 1
python3 - "$EVIDENCE_DIR/fractional_caught.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["caught"] = 1.5
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "fractional aggregate caught count fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: fractional caught count was not rejected"; cat "$ERR"; exit 1; }

# Case 32: needs_real_run accepts only a JSON boolean, not a false-like
# integer.
reset_fixture
write_model_single "integer_placeholder_flag" "partial"
write_nested_evidence "integer_placeholder_flag" 1 1
python3 - "$EVIDENCE_DIR/integer_placeholder_flag.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["needs_real_run"] = 0
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "integer needs_real_run flag fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: integer needs_real_run was not rejected"; cat "$ERR"; exit 1; }

# Case 33: mutation_case_path cannot traverse a symlink, even when that link
# resolves to the original case bytes inside the fixture repository.
reset_fixture
write_model_single "symlink_case" "partial"
write_nested_evidence "symlink_case" 1 1
mv "$CASES_DIR/symlink_case_case.json" "$TMP_DIR/symlink-case-target.json"
ln -s "../symlink-case-target.json" "$CASES_DIR/symlink_case_case.json"
assert_fails "symlinked mutation case fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: symlinked mutation case was not rejected"; cat "$ERR"; exit 1; }

# Case 34: closed_subvector_test cannot traverse a symlink to otherwise valid
# Rust test bytes.
reset_fixture
write_model_single "symlink_closed_test" "partial"
write_nested_evidence "symlink_closed_test" 1 1
mv "$TESTS_DIR/symlink_closed_test.rs" "$TMP_DIR/symlink-closed-test-target.rs"
ln -s "../symlink-closed-test-target.rs" "$TESTS_DIR/symlink_closed_test.rs"
assert_fails "symlinked closed-subvector test fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: symlinked closed-subvector test was not rejected"; cat "$ERR"; exit 1; }

# Case 35: a native outcome child cannot be rebound through a symlink after
# its digest is recorded.
reset_fixture
write_model_single "symlink_child" "partial"
write_nested_evidence "symlink_child" 1 1
mv "$TMP_DIR/symlink_child-outcomes.json" "$TMP_DIR/symlink-child-target.json"
ln -s "symlink-child-target.json" "$TMP_DIR/symlink_child-outcomes.json"
assert_fails "symlinked native child fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: symlinked native child was not rejected"; cat "$ERR"; exit 1; }

# Case 36: the aggregate row itself cannot be supplied through a symlink.
reset_fixture
write_model_single "symlink_row" "partial"
write_nested_evidence "symlink_row" 1 1
mv "$EVIDENCE_DIR/symlink_row.json" "$TMP_DIR/symlink-row-target.json"
ln -s "../symlink-row-target.json" "$EVIDENCE_DIR/symlink_row.json"
assert_fails "symlinked aggregate row fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: symlinked aggregate row was not rejected"; cat "$ERR"; exit 1; }

# Case 37: success counts surviving mutants and must remain zero for caught-only
# evidence.
reset_fixture
write_model_single "successful_mutant" "partial"
write_nested_evidence "successful_mutant" 1 1
python3 - "$TMP_DIR/successful_mutant-outcomes.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    child = json.load(source)
child["success"] = 1
with open(path, "w", encoding="utf-8") as destination:
    json.dump(child, destination, sort_keys=True, separators=(",", ":"))
PY
refresh_nested_digest "successful_mutant"
assert_fails "native child with a success count fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: nonzero success count was not rejected"; cat "$ERR"; exit 1; }

# Case 38: native mutation evidence must include exactly one successful
# baseline and caught-mutant outcome records. A count-only child is inadequate.
reset_fixture
write_model_single "missing_native_records" "partial"
write_nested_evidence "missing_native_records" 1 1
python3 - "$TMP_DIR/missing_native_records-outcomes.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    child = json.load(source)
child.pop("outcomes")
with open(path, "w", encoding="utf-8") as destination:
    json.dump(child, destination, sort_keys=True, separators=(",", ":"))
PY
refresh_nested_digest "missing_native_records"
assert_fails "native child without outcome records fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: missing native outcome records were not rejected"; cat "$ERR"; exit 1; }

# Case 39: a native record classified as missed cannot be reconciled with a
# caught-only aggregate count.
reset_fixture
write_model_single "wrong_native_summary" "partial"
write_nested_evidence "wrong_native_summary" 1 1
python3 - "$TMP_DIR/wrong_native_summary-outcomes.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    child = json.load(source)
child["success"] = 0
child["outcomes"] = [
    {"scenario": "Baseline", "summary": "Success"},
    {"scenario": {"Mutant": {}}, "summary": "MissedMutant"},
]
with open(path, "w", encoding="utf-8") as destination:
    json.dump(child, destination, sort_keys=True, separators=(",", ":"))
PY
refresh_nested_digest "wrong_native_summary"
assert_fails "native child with a non-caught summary fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: wrong native outcome summary was not rejected"; cat "$ERR"; exit 1; }

# Case 40: native record cardinality must equal both total_mutants and caught.
reset_fixture
write_model_single "wrong_native_count" "partial"
write_nested_evidence "wrong_native_count" 1 1
python3 - "$TMP_DIR/wrong_native_count-outcomes.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    child = json.load(source)
child["success"] = 0
child["outcomes"] = [
    {"scenario": "Baseline", "summary": "Success"},
    {"scenario": {"Mutant": {"id": 1}}, "summary": "CaughtMutant"},
    {"scenario": {"Mutant": {"id": 2}}, "summary": "CaughtMutant"},
]
with open(path, "w", encoding="utf-8") as destination:
    json.dump(child, destination, sort_keys=True, separators=(",", ":"))
PY
refresh_nested_digest "wrong_native_count"
assert_fails "native child with inconsistent record count fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: native record count mismatch was not rejected"; cat "$ERR"; exit 1; }

# Case 41: real caught-only aggregates cannot retain top-level survivors even
# when every cited native child is caught-only.
reset_fixture
write_model_single "aggregate_survivor" "partial"
write_nested_evidence "aggregate_survivor" 1 1
python3 - "$EVIDENCE_DIR/aggregate_survivor.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["survivors"] = ["surviving_mutant"]
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "real aggregate with survivors fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: aggregate survivors were not rejected"; cat "$ERR"; exit 1; }

# Case 42: numeric metadata cannot disappear through false-like string
# coercion.
reset_fixture
write_model_single "numeric_run_timestamp" "partial"
write_nested_evidence "numeric_run_timestamp" 1 1
python3 - "$EVIDENCE_DIR/numeric_run_timestamp.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["ran_at"] = 0
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "numeric ran_at metadata fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: numeric ran_at metadata was not rejected"; cat "$ERR"; exit 1; }

# Case 43: a test-shaped declaration inside a Rust comment is not an actual
# closed-subvector control.
reset_fixture
write_model_single "comment_spoofed_test" "partial"
write_nested_evidence "comment_spoofed_test" 1 1
printf '%s\n' \
    '/*' \
    '#[test]' \
    'fn comment_spoofed_test_closed_subvector() {}' \
    '*/' > "$TESTS_DIR/comment_spoofed_test.rs"
assert_fails "comment-spoofed Rust test linkage fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: comment-spoofed Rust test was not rejected"; cat "$ERR"; exit 1; }

# Case 44: test-shaped text inside a multiline raw string is also non-code.
reset_fixture
write_model_single "string_spoofed_test" "partial"
write_nested_evidence "string_spoofed_test" 1 1
printf '%s\n' \
    'const SPOOF: &str = r#"' \
    '#[test]' \
    'fn string_spoofed_test_closed_subvector() {}' \
    '"#;' > "$TESTS_DIR/string_spoofed_test.rs"
assert_fails "string-spoofed Rust test linkage fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: string-spoofed Rust test was not rejected"; cat "$ERR"; exit 1; }

# Case 45: classifier failure after an earlier valid row cannot be lost through
# process-substitution status handling.
reset_fixture
write_model_single "valid_before_malformed" "partial"
write_nested_evidence "valid_before_malformed" 1 1
python3 - "$MODEL" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["threats"].append(
    {
        "id": ["not", "a", "string"],
        "coverage_state": "partial",
        "coveredBy": ["invalid.rs"],
    }
)
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "partial classifier output followed by failure fails the gate" run_mutants_gate

# Case 46: metadata cannot inject TSV fields that hide forbidden evidence
# status values beyond the shell reader's fixed field count.
reset_fixture
write_model_single "metadata_field_injection" "partial"
write_nested_evidence "metadata_field_injection" 1 1
python3 - "$EVIDENCE_DIR/metadata_field_injection.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["timestamp_kind"] = "cargo-mutants-run\tcargo-mutants-run\tcomplete\tpromoted"
body["evidence_status"] = "conformance-only"
body["mutation_evidence_status"] = "not-run"
body["promotion_status"] = "not-promoted"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "metadata TSV field injection fails" run_mutants_gate
grep -q "reason=missing_evidence" "$ERR" \
    || { echo "FAIL: metadata TSV injection was not rejected"; cat "$ERR"; exit 1; }

# Case 47: promoted positive aggregates require evidence_status explicitly.
reset_fixture
write_model_single "missing_evidence_status" "partial"
write_nested_evidence "missing_evidence_status" 1 1
python3 - "$EVIDENCE_DIR/missing_evidence_status.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body.pop("evidence_status")
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "positive aggregate without evidence_status fails" run_mutants_gate

# Case 48: evidence_status admits only its declared enum spellings.
reset_fixture
write_model_single "invalid_evidence_status" "partial"
write_nested_evidence "invalid_evidence_status" 1 1
python3 - "$EVIDENCE_DIR/invalid_evidence_status.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["evidence_status"] = "cargo_mutants_run"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "unknown evidence_status fails" run_mutants_gate

# Case 49: mutation_evidence_status admits only its declared enum spellings.
reset_fixture
write_model_single "invalid_mutation_status" "partial"
write_nested_evidence "invalid_mutation_status" 1 1
python3 - "$EVIDENCE_DIR/invalid_mutation_status.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["mutation_evidence_status"] = "not_run"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "unknown mutation_evidence_status fails" run_mutants_gate

# Case 50: promotion_status admits only its declared enum spellings.
reset_fixture
write_model_single "invalid_promotion_status" "partial"
write_nested_evidence "invalid_promotion_status" 1 1
python3 - "$EVIDENCE_DIR/invalid_promotion_status.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["promotion_status"] = "not_promoted"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "unknown promotion_status fails" run_mutants_gate

# Case 51: aggregate notes are derived exactly from the cited child counts.
reset_fixture
write_model_single "stale_aggregate_note" "partial"
write_nested_evidence "stale_aggregate_note" 1 1
python3 - "$EVIDENCE_DIR/stale_aggregate_note.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["note"] = "stale aggregate note"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "stale aggregate note fails" run_mutants_gate

# Case 52: the reproduction command is derived exactly from outcome id/path
# bindings.
reset_fixture
write_model_single "stale_reproduction" "partial"
write_nested_evidence "stale_reproduction" 1 1
python3 - "$EVIDENCE_DIR/stale_reproduction.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["reproduction_command"] = "stale command"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "stale reproduction command fails" run_mutants_gate

# Case 53: timestamp provenance text is exact, not inherited from an older
# refresh.
reset_fixture
write_model_single "stale_timestamp_note" "partial"
write_nested_evidence "stale_timestamp_note" 1 1
python3 - "$EVIDENCE_DIR/stale_timestamp_note.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["timestamp_note"] = "stale timestamp explanation"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "stale timestamp note fails" run_mutants_gate

# Case 54: promoted aggregate ran_at uses a real UTC calendar timestamp at
# whole-second precision.
reset_fixture
write_model_single "invalid_aggregate_time" "partial"
write_nested_evidence "invalid_aggregate_time" 1 1
python3 - "$EVIDENCE_DIR/invalid_aggregate_time.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as source:
    body = json.load(source)
body["ran_at"] = "2026-02-30T25:61:61Z"
with open(path, "w", encoding="utf-8") as destination:
    json.dump(body, destination)
PY
assert_fails "invalid aggregate UTC timestamp fails" run_mutants_gate

# Case 55: lexical aliases of the production model and evidence directory must
# still run the complete adversarial preflight.
reset_fixture
write_model_single "production_alias" "partial"
write_nested_evidence "production_alias" 1 1
ALIAS_REPO="$TMP_DIR/production-alias-repo"
PREFLIGHT_MARKER="$TMP_DIR/production-alias-preflight-ran"
rm -rf "$ALIAS_REPO" "$PREFLIGHT_MARKER"
mkdir -p \
    "$ALIAS_REPO/scripts" \
    "$ALIAS_REPO/spec/security" \
    "$ALIAS_REPO/audits/evidence/threats" \
    "$ALIAS_REPO/cases" \
    "$ALIAS_REPO/tests"
cp "$REPO_ROOT/scripts/check-threat-coverage-mutants.sh" "$ALIAS_REPO/scripts/"
cp "$MODEL" "$ALIAS_REPO/spec/security/chio-threat-model.v1.json"
cp "$EVIDENCE_DIR/production_alias.json" "$ALIAS_REPO/audits/evidence/threats/"
cp "$CASES_DIR/production_alias_case.json" "$ALIAS_REPO/cases/"
cp "$TESTS_DIR/production_alias.rs" "$ALIAS_REPO/tests/"
cp "$TMP_DIR/production_alias-outcomes.json" "$ALIAS_REPO/"
cat > "$ALIAS_REPO/scripts/check-security-adversarial-evidence.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
: "${CHIO_PREFLIGHT_MARKER:?}"
: > "$CHIO_PREFLIGHT_MARKER"
exit 91
SH
chmod +x "$ALIAS_REPO/scripts/check-security-adversarial-evidence.sh"
run_production_alias_gate() {
    CHIO_THREAT_MODEL_PATH="$ALIAS_REPO/spec/security/./chio-threat-model.v1.json" \
    CHIO_THREAT_EVIDENCE_DIR="$ALIAS_REPO/audits/evidence/threats/" \
    CHIO_THREAT_EVIDENCE_REPOSITORY_ROOT="$ALIAS_REPO" \
    CHIO_SECURITY_ADVERSARIAL_CASES_DIR="$ALIAS_REPO/cases" \
    CHIO_PREFLIGHT_MARKER="$PREFLIGHT_MARKER" \
        bash "$ALIAS_REPO/scripts/check-threat-coverage-mutants.sh" \
        >"$OUT" 2>"$ERR"
}
assert_fails "production path aliases run adversarial preflight" \
    run_production_alias_gate
[[ -f "$PREFLIGHT_MARKER" ]] \
    || { echo "FAIL: production path aliases skipped adversarial preflight"; cat "$ERR"; exit 1; }

# Case 56: the threat model itself cannot be supplied through a symlink.
reset_fixture
write_model_single "symlink_model" "partial"
write_nested_evidence "symlink_model" 1 1
mv "$MODEL" "$TMP_DIR/symlink-model-target.json"
ln -s "symlink-model-target.json" "$MODEL"
assert_fails "symlinked threat model fails" run_mutants_gate

# Case 57: no-follow traversal also rejects a symlinked parent directory below
# the repository root.
reset_fixture
write_model_single "symlink_model_parent" "partial"
write_nested_evidence "symlink_model_parent" 1 1
MODEL_PARENT_REAL="$TMP_DIR/model-parent-real"
MODEL_PARENT_LINK="$TMP_DIR/model-parent-link"
rm -rf "$MODEL_PARENT_REAL" "$MODEL_PARENT_LINK"
mkdir -p "$MODEL_PARENT_REAL"
mv "$MODEL" "$MODEL_PARENT_REAL/threat-model.json"
ln -s "model-parent-real" "$MODEL_PARENT_LINK"
ORIGINAL_MODEL="$MODEL"
MODEL="$MODEL_PARENT_LINK/threat-model.json"
assert_fails "threat model below symlinked parent fails" run_mutants_gate
MODEL="$ORIGINAL_MODEL"

# Case 58: the threat-model read is bounded even when the JSON remains valid.
reset_fixture
write_model_single "oversized_model" "partial"
write_nested_evidence "oversized_model" 1 1
python3 - "$MODEL" <<'PY'
import sys

with open(sys.argv[1], "ab") as destination:
    destination.write(b" " * (16 * 1024 * 1024 + 1))
PY
assert_fails "oversized threat model fails" run_mutants_gate

# Case 59: an ignored Rust test cannot satisfy closed_subvector_test.
reset_fixture
write_model_single "ignored_closed_test" "partial"
write_nested_evidence "ignored_closed_test" 1 1
printf '%s\n' \
    '#[test]' \
    '#[ignore]' \
    'fn ignored_closed_test_closed_subvector() {}' \
    > "$TESTS_DIR/ignored_closed_test.rs"
assert_fails "ignored closed-subvector test fails" run_mutants_gate

# Case 60: a Rust test disabled by a false cfg cannot satisfy linkage.
reset_fixture
write_model_single "cfg_closed_test" "partial"
write_nested_evidence "cfg_closed_test" 1 1
printf '%s\n' \
    '#[test]' \
    '#[cfg(any())]' \
    'fn cfg_closed_test_closed_subvector() {}' \
    > "$TESTS_DIR/cfg_closed_test.rs"
assert_fails "cfg-disabled closed-subvector test fails" run_mutants_gate

# Case 61: a cfg_attr that resolves to ignore cannot satisfy linkage.
reset_fixture
write_model_single "cfg_attr_closed_test" "partial"
write_nested_evidence "cfg_attr_closed_test" 1 1
printf '%s\n' \
    '#[test]' \
    '#[cfg_attr(all(), ignore)]' \
    'fn cfg_attr_closed_test_closed_subvector() {}' \
    > "$TESTS_DIR/cfg_attr_closed_test.rs"
assert_fails "cfg_attr-disabled closed-subvector test fails" run_mutants_gate

# Case 62: test-shaped tokens in an unused macro body are not an executable
# closed-subvector control.
reset_fixture
write_model_single "macro_closed_test" "partial"
write_nested_evidence "macro_closed_test" 1 1
cat > "$TESTS_DIR/macro_closed_test.rs" <<'RS'
macro_rules! never_used {
    () => {
        #[test]
        fn macro_closed_test_closed_subvector() {}
    };
}
RS
assert_fails "unused-macro closed-subvector test fails" run_mutants_gate

echo "PASS: check-threat-coverage-mutants evidence matrix"
