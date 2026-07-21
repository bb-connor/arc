#!/usr/bin/env bash
# Per-row cargo-mutants gate for threat coverage.
#
# Owner: threat-coverage evidence gate.
#
# Mutation-testing backstop for threat coverage: the threat-stub
# existence gate accepts a one-line `assert!(true)` body that exercises
# no defensive logic, so this gate verifies each row's tests actually
# kill mutants.
#
# For each threat in `spec/security/chio-threat-model.v1.json`
# whose `coverage_state` is `covered` (or absent, which defaults to
# covered) or `partial`:
#
#   1. Read the threat's `coveredBy` (preferred) or
#      `covered_by_tests` cross-link list. If both are missing or
#      empty, emit a downgrade hint with reason `no_coveredby` and
#      exit 1.
#
#   2. Look up the evidence file at
#      `audits/evidence/threats/<threat_id>.json`. The file is
#      expected to record the most recent mutation-testing run with
#      shape:
#
#          {
#            "caught": <int>,
#            "survivors": [<string>, ...],
#            "ran_at": "<iso8601>",
#            "timestamp_kind": "cargo-mutants-run" | "command-wall-clock"
#                | "generated-metadata" (optional),
#            "evidence_status": "cargo-mutants-run" | "conformance-only"
#                (optional),
#            "mutation_evidence_status": "complete" | "not-run" (optional),
#            "promotion_status": "promoted" | "not-promoted" (optional),
#            "mutation_case_path": "crates/.../cases/<case>.json",
#            "closed_subvector_test": {
#              "path": "crates/.../<test>.rs",
#              "name": "exact_rust_test_function"
#            }
#          }
#
#      Every row with a positive caught count must contain a nonempty `outcomes`
#      array. Each outcome id and path must identify the
#      same campaign in the security adversarial case index, and that case must
#      cite this threat row. Every child must also resolve below the repository,
#      match its recorded SHA-256, contain only caught mutants, and sum exactly
#      to the parent `caught` count. The production repository gate additionally
#      validates the complete adversarial suite's current-source input bindings
#      before classifying any row.
#
#      Legacy `needs_real_run` metadata and unknown timestamp kinds are
#      rejected. They are not evidence states and cannot be enabled by an
#      argument or environment variable.
#
#      Generated conformance metadata is not mutation evidence. A row
#      whose metadata says `generated-metadata`, `conformance-only`,
#      `not-run`, or `not-promoted` cannot pass the mutants evidence
#      gate by recording a positive caught count.
#
#   3. If the evidence file is missing, emit a downgrade hint with
#      reason `missing_evidence` and exit 1.
#
#   4. If `caught == 0`, emit a downgrade hint with reason `zero_kills`
#      and exit 1.
#
#   5. If `caught >= 1`, the row passes.
#
# Partial rows are still required to carry evidence. The row can remain
# `partial` in the threat model, but the defended sub-vector must have
# a present source-bound evidence file and caught >= 1.
#
# Downgrade hint format (single line, machine-grep-able):
#
#     WEAK: <threat_id> should be marked weak_coverage; reason=<reason>
#
# Where `<reason>` is one of:
#   - `missing_evidence` - audits/evidence/threats/<id>.json is missing
#   - `zero_kills`       - the evidence file records caught == 0
#   - `no_coveredby`     - no coveredBy / covered_by_tests cross-link
#   - `invalid_evidence` - the evidence file is malformed, legacy, unbound,
#     or inconsistent with source-bound cargo-mutants outcomes
#   - `non_mutants_metadata` - the row tries to pass with generated,
#     conformance-only, not-run, or not-promoted metadata
#   - `pending_without_deferred_to` - a pending row lacks its explicit
#     technical closure condition
#
# Exit codes:
#   0 - every pending row has a technical closure condition and every covered
#       or partial row has source-bound evidence with caught >= 1.
#   1 - the threat model or required evidence fails validation.
#   2 - argument error.

set -euo pipefail

for arg in "$@"; do
    case "$arg" in
        -h|--help)
            sed -n '1,80p' "$0"
            exit 0
            ;;
        *)
            echo "error: unknown argument $arg" >&2
            echo "usage: $(basename "$0") [--help]" >&2
            exit 2
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

THREAT_MODEL="${CHIO_THREAT_MODEL_PATH:-$REPO_ROOT/spec/security/chio-threat-model.v1.json}"
EVIDENCE_DIR="${CHIO_THREAT_EVIDENCE_DIR:-$REPO_ROOT/audits/evidence/threats}"
EVIDENCE_REPOSITORY_ROOT="${CHIO_THREAT_EVIDENCE_REPOSITORY_ROOT:-$REPO_ROOT}"
ADVERSARIAL_CASES_DIR="${CHIO_SECURITY_ADVERSARIAL_CASES_DIR:-$REPO_ROOT/crates/core/chio-adversarial-suite/cases}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to parse threat-model JSON" >&2
    exit 1
fi

# Production evidence is valid only when the native cargo-mutants records are
# still bound to the current source and behavioral controls. Fixture callers
# override at least one filesystem object and exercise the row-classification
# logic below. Compare object identity so dot components, trailing separators,
# and other lexical aliases cannot skip the production preflight.
PRODUCTION_INPUTS="$(python3 - \
    "$THREAT_MODEL" \
    "$EVIDENCE_DIR" \
    "$REPO_ROOT/spec/security/chio-threat-model.v1.json" \
    "$REPO_ROOT/audits/evidence/threats" <<'PY'
import os
import sys


def same_object(left, right):
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


print(
    "1"
    if same_object(sys.argv[1], sys.argv[3])
    and same_object(sys.argv[2], sys.argv[4])
    else "0"
)
PY
)"
if [[ "$PRODUCTION_INPUTS" == "1" ]]; then
    "$REPO_ROOT/scripts/check-security-adversarial-evidence.sh" --require-complete
fi

# Emit one tab-separated record per row needing classification:
#   <threat_id>\t<state>\t<has_coveredby>\t<has_deferred_to>
# where state is whatever appears in the JSON (default 'covered').
classify_threats() {
    python3 - "$THREAT_MODEL" "$EVIDENCE_REPOSITORY_ROOT" <<'PY'
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath


MAX_THREAT_MODEL_BYTES = 16 * 1024 * 1024


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonfinite_number(value):
    raise ValueError(f"non-finite JSON number: {value}")


def threat_model_relative_path(model_argument, repo_root):
    absolute_model = Path(os.path.abspath(model_argument))
    try:
        relative_model = absolute_model.relative_to(repo_root)
    except ValueError as error:
        raise ValueError("threat model escapes the repository") from error
    if not relative_model.parts or ".." in relative_model.parts:
        raise ValueError("threat model path is invalid")
    return relative_model.as_posix()


def open_repository_directory(repo_root, relative_path):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("no-follow threat-model reads are unsupported")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        descriptor = os.open(repo_root, directory_flags)
        for component in PurePosixPath(relative_path).parts:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError(
            "threat model parent is not a no-follow repository directory"
        ) from error


def read_threat_model(repo_root, relative_path):
    parsed = PurePosixPath(relative_path)
    parent = parsed.parent.as_posix()
    parent_descriptor = open_repository_directory(
        repo_root,
        "" if parent == "." else parent,
    )
    file_descriptor = None
    try:
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        file_descriptor = os.open(
            parsed.name,
            file_flags,
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("threat model is not a regular file")
        if metadata.st_size > MAX_THREAT_MODEL_BYTES:
            raise ValueError("threat model exceeds the 16 MiB limit")
        with os.fdopen(file_descriptor, "rb", closefd=True) as source:
            file_descriptor = None
            payload = source.read(MAX_THREAT_MODEL_BYTES + 1)
        if len(payload) > MAX_THREAT_MODEL_BYTES:
            raise ValueError("threat model grew beyond the 16 MiB limit")
        return payload
    except OSError as error:
        raise ValueError("threat model is not a no-follow repository file") from error
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(parent_descriptor)


repo_root = Path(os.path.abspath(sys.argv[2]))
model_relative = threat_model_relative_path(sys.argv[1], repo_root)
payload = read_threat_model(repo_root, model_relative)
try:
    doc = json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite_number,
    )
except (UnicodeError, json.JSONDecodeError) as error:
    raise ValueError(f"threat model is invalid JSON: {error}") from error
if not isinstance(doc, dict) or not isinstance(doc.get("threats"), list):
    raise ValueError("threat model must contain a threats array")

observed_ids = set()
for offset, t in enumerate(doc["threats"]):
    if not isinstance(t, dict):
        raise ValueError(f"threats[{offset}] must be an object")
    tid = t.get("id")
    if not isinstance(tid, str) or re.fullmatch(r"[a-z][a-z0-9_]*", tid) is None:
        raise ValueError(f"threats[{offset}].id is invalid")
    if tid in observed_ids:
        raise ValueError(f"duplicate threat id: {tid}")
    observed_ids.add(tid)
    state = t.get("coverage_state", "covered")
    if state not in {"covered", "partial", "pending", "weak_coverage"}:
        raise ValueError(f"threat {tid} has an invalid coverage_state")
    if "coveredBy" in t and "covered_by_tests" in t:
        raise ValueError(f"threat {tid} uses both coveredBy aliases")
    coveredby = t.get("coveredBy", t.get("covered_by_tests", []))
    if not isinstance(coveredby, list) or any(
        not isinstance(reference, str) or not reference.strip()
        for reference in coveredby
    ):
        raise ValueError(f"threat {tid} has invalid coveredBy references")
    deferred_to = t.get("deferred_to")
    if deferred_to is not None and not isinstance(deferred_to, str):
        raise ValueError(f"threat {tid} has an invalid deferred_to")
    has_coveredby = "1" if coveredby else "0"
    has_deferred_to = "1" if deferred_to and deferred_to.strip() else "0"
    print(f"{tid}\t{state}\t{has_coveredby}\t{has_deferred_to}")
PY
}

# Read the evidence file and emit a tab-separated record:
#   <caught> <ran_at> <survivor_count> <timestamp_kind>
#   <evidence_status> <mutation_evidence_status> <promotion_status>
# Returns nonzero if the file is missing or invalid.
read_evidence() {
    local evidence_file="$1"
    local threat_id="$2"
    if [[ ! -f "$evidence_file" ]]; then
        return 1
    fi
    python3 - \
        "$evidence_file" \
        "$EVIDENCE_REPOSITORY_ROOT" \
        "$ADVERSARIAL_CASES_DIR" \
        "$threat_id" <<'PY'
import hashlib
import datetime
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonfinite_number(value):
    raise ValueError(f"non-finite JSON number: {value}")


def parse_json(payload, label):
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_number,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is invalid JSON: {error}") from error


def nonempty_string(value, label):
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError(f"{label} must be a nonempty trimmed string")
    return value


def optional_trimmed_string(data, name):
    if name not in data:
        return ""
    value = data[name]
    if (
        not isinstance(value, str)
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError(f"{name} must be a trimmed string")
    return value


def optional_enum(data, name, allowed):
    if name not in data:
        return ""
    value = optional_trimmed_string(data, name)
    if not value or value not in allowed:
        raise ValueError(f"{name} has an invalid enum value")
    return value


def repository_relative_path(value, label):
    value = nonempty_string(value, label)
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or value != parsed.as_posix()
        or value == "."
        or ".." in parsed.parts
        or "\\" in value
    ):
        raise ValueError(f"{label} must be a canonical repository-relative path")
    return value


def argument_repository_path(repo_root_argument, value, label):
    raw_path = Path(value)
    absolute_path = Path(os.path.abspath(raw_path))
    try:
        relative_path = absolute_path.relative_to(repo_root_argument).as_posix()
    except ValueError as error:
        raise ValueError(f"{label} escapes the repository") from error
    return repository_relative_path(relative_path, label)


def open_repository_directory(repo_root, relative_path, label):
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("no-follow repository reads are unsupported")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        descriptor = os.open(repo_root, directory_flags)
        for component in PurePosixPath(relative_path).parts:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise ValueError(f"{label} is not a directory")
        return descriptor
    except (OSError, ValueError) as error:
        if descriptor is not None:
            os.close(descriptor)
        raise ValueError(f"{label} is not a no-follow repository directory") from error


def read_repository_file(repo_root, relative_path, label):
    parsed = PurePosixPath(relative_path)
    parent = parsed.parent.as_posix()
    parent_descriptor = open_repository_directory(
        repo_root,
        "" if parent == "." else parent,
        f"{label} parent",
    )
    file_descriptor = None
    try:
        file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        file_descriptor = os.open(
            parsed.name,
            file_flags,
            dir_fd=parent_descriptor,
        )
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{label} is not a regular file")
        if metadata.st_size > 16 * 1024 * 1024:
            raise ValueError(f"{label} exceeds the 16 MiB evidence limit")
        with os.fdopen(file_descriptor, "rb", closefd=True) as source:
            file_descriptor = None
            payload = source.read(16 * 1024 * 1024 + 1)
            if len(payload) > 16 * 1024 * 1024:
                raise ValueError(f"{label} grew beyond the 16 MiB evidence limit")
            return payload
    except (OSError, ValueError) as error:
        raise ValueError(f"{label} is not a no-follow repository file") from error
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(parent_descriptor)


def repository_file(repo_root, value, label, suffix):
    relative_path = repository_relative_path(value, label)
    if not relative_path.endswith(suffix):
        raise ValueError(f"{label} must end with {suffix}")
    payload = read_repository_file(repo_root, relative_path, label)
    return relative_path, payload


def rust_code_without_comments_and_strings(source):
    scrubbed = list(source)

    def blank(start, end):
        for offset in range(start, end):
            if scrubbed[offset] not in "\r\n":
                scrubbed[offset] = " "

    offset = 0
    while offset < len(source):
        if source.startswith("//", offset):
            end = source.find("\n", offset + 2)
            end = len(source) if end < 0 else end
            blank(offset, end)
            offset = end
            continue
        if source.startswith("/*", offset):
            depth = 1
            end = offset + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            if depth:
                raise ValueError("closed_subvector_test.path has an unterminated comment")
            blank(offset, end)
            offset = end
            continue

        raw_match = None
        if offset == 0 or not (source[offset - 1].isalnum() or source[offset - 1] == "_"):
            for prefix in ("br", "cr", "r"):
                if not source.startswith(prefix, offset):
                    continue
                marker = offset + len(prefix)
                while marker < len(source) and source[marker] == "#":
                    marker += 1
                if marker < len(source) and source[marker] == '"':
                    raw_match = (marker, marker - offset - len(prefix))
                    break
        if raw_match is not None:
            quote_offset, hash_count = raw_match
            terminator = '"' + "#" * hash_count
            end = source.find(terminator, quote_offset + 1)
            if end < 0:
                raise ValueError("closed_subvector_test.path has an unterminated raw string")
            end += len(terminator)
            blank(offset, end)
            offset = end
            continue

        quote_offset = None
        if source[offset] == '"':
            quote_offset = offset
        elif (
            source[offset] in "bc"
            and offset + 1 < len(source)
            and source[offset + 1] == '"'
            and (offset == 0 or not (source[offset - 1].isalnum() or source[offset - 1] == "_"))
        ):
            quote_offset = offset + 1
        if quote_offset is not None:
            end = quote_offset + 1
            while end < len(source):
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == '"':
                    end += 1
                    break
                end += 1
            else:
                raise ValueError("closed_subvector_test.path has an unterminated string")
            blank(offset, min(end, len(source)))
            offset = end
            continue

        character_quote = None
        if source[offset] == "'":
            character_quote = offset
        elif (
            source[offset] == "b"
            and offset + 1 < len(source)
            and source[offset + 1] == "'"
            and (offset == 0 or not (source[offset - 1].isalnum() or source[offset - 1] == "_"))
        ):
            character_quote = offset + 1
        if character_quote is not None:
            end = character_quote + 1
            if end < len(source) and source[end] == "\\":
                end += 1
                if end < len(source) and source[end] == "x":
                    end += 3
                elif (
                    end + 1 < len(source)
                    and source[end] == "u"
                    and source[end + 1] == "{"
                ):
                    closing_brace = source.find("}", end + 2)
                    end = len(source) if closing_brace < 0 else closing_brace + 1
                else:
                    end += 1
            elif end < len(source) and source[end] not in "'\r\n":
                end += 1
            if end < len(source) and source[end] == "'":
                end += 1
                blank(offset, end)
                offset = end
                continue
        offset += 1
    return "".join(scrubbed)


def is_top_level_rust_item(source, item_offset):
    delimiter_stack = []
    closing_delimiters = {"}": "{", "]": "[", ")": "("}
    for character in source[:item_offset]:
        if character in "{[(":
            delimiter_stack.append(character)
        elif character in closing_delimiters:
            if (
                not delimiter_stack
                or delimiter_stack[-1] != closing_delimiters[character]
            ):
                return False
            delimiter_stack.pop()
    return not delimiter_stack


def validate_aggregate_linkage(data, repo_root):
    case_path, _ = repository_file(
        repo_root,
        data.get("mutation_case_path"),
        "mutation_case_path",
        ".json",
    )
    closed_test = data.get("closed_subvector_test")
    if not isinstance(closed_test, dict) or set(closed_test) != {"path", "name"}:
        raise ValueError("closed_subvector_test must contain exactly path and name")
    _, test_payload = repository_file(
        repo_root,
        closed_test["path"],
        "closed_subvector_test.path",
        ".rs",
    )
    test_name = nonempty_string(
        closed_test["name"], "closed_subvector_test.name"
    )
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", test_name) is None:
        raise ValueError("closed_subvector_test.name must be a Rust identifier")
    attribute_block_and_function = re.compile(
        r"(?m)(?P<attributes>"
        r"(?:^[ \t]*#\s*\[[^\]\r\n]+\][ \t]*\r?\n"
        r"(?:^[ \t]*\r?\n)*)+)"
        r"^[ \t]*(?:(?:pub(?:\([^\)\n]+\))?)[ \t]+)?"
        r"(?:async[ \t]+)?fn[ \t]+"
        + re.escape(test_name)
        + r"[ \t]*\("
    )
    active_test_attribute = re.compile(
        r"[ \t]*#\s*\[\s*test\s*\][ \t]*\r?\n"
        r"(?:[ \t]*\r?\n)*"
    )
    try:
        test_source = test_payload.decode("utf-8")
    except UnicodeError as error:
        raise ValueError("closed_subvector_test.path is not UTF-8") from error
    test_code = rust_code_without_comments_and_strings(test_source)
    active_matches = [
        match
        for match in attribute_block_and_function.finditer(test_code)
        if active_test_attribute.fullmatch(match.group("attributes")) is not None
        and is_top_level_rust_item(test_code, match.start())
    ]
    if len(active_matches) != 1:
        raise ValueError(
            "closed_subvector_test.name must identify exactly one active top-level "
            "unignored Rust test"
        )
    return case_path


def load_campaign_index(repo_root, cases_root_relative):
    cases_root_descriptor = open_repository_directory(
        repo_root, cases_root_relative, "adversarial cases directory"
    )
    os.close(cases_root_descriptor)
    cases_root = repo_root / cases_root_relative
    campaigns = {}
    indexed_paths = {}
    for case_path in sorted(cases_root.rglob("*.json")):
        try:
            case_relative = repository_relative_path(
                case_path.relative_to(repo_root).as_posix(),
                "adversarial case path",
            )
        except ValueError as error:
            raise ValueError(f"adversarial case escaped the repository: {case_path}") from error
        case = parse_json(
            read_repository_file(repo_root, case_relative, str(case_path)),
            str(case_path),
        )
        if not isinstance(case, dict):
            raise ValueError(f"adversarial case is not an object: {case_path}")
        artifact = case.get("artifact")
        if not isinstance(artifact, dict) or "campaigns" not in artifact:
            continue
        case_campaigns = artifact["campaigns"]
        if not isinstance(case_campaigns, list) or not case_campaigns:
            raise ValueError(f"adversarial case has an invalid campaign list: {case_path}")
        case_threat_id = nonempty_string(
            case.get("threat_id"), f"{case_path}: threat_id"
        )
        for campaign_offset, campaign in enumerate(case_campaigns):
            label = f"{case_path}: campaigns[{campaign_offset}]"
            if not isinstance(campaign, dict):
                raise ValueError(f"{label} must be an object")
            campaign_id = nonempty_string(campaign.get("id"), f"{label}.id")
            outcome_binding = campaign.get("outcomes")
            if not isinstance(outcome_binding, dict):
                raise ValueError(f"{label}.outcomes must be an object")
            outcome_path = repository_relative_path(
                outcome_binding.get("path"), f"{label}.outcomes.path"
            )
            if campaign_id in campaigns:
                raise ValueError(f"duplicate adversarial campaign id: {campaign_id}")
            if outcome_path in indexed_paths:
                raise ValueError(
                    f"duplicate adversarial campaign outcome path: {outcome_path}"
                )
            campaigns[campaign_id] = (
                outcome_path,
                case_threat_id,
                case_relative,
            )
            indexed_paths[outcome_path] = campaign_id
    if not campaigns:
        raise ValueError(f"adversarial case index contains no campaigns: {cases_root}")
    return campaigns

repo_root_argument = Path(os.path.abspath(sys.argv[2]))
repo_root = repo_root_argument.resolve(strict=True)
evidence_relative = argument_repository_path(
    repo_root_argument, sys.argv[1], "threat evidence path"
)
cases_root_relative = argument_repository_path(
    repo_root_argument, sys.argv[3], "adversarial cases directory"
)
row_threat_id = nonempty_string(sys.argv[4], "threat row id")
data = parse_json(
    read_repository_file(repo_root, evidence_relative, "threat evidence row"),
    "threat evidence row",
)
if not isinstance(data, dict):
    raise ValueError("threat evidence row must be an object")

caught = data.get("caught")
if type(caught) is not int or caught < 0:
    raise ValueError("caught must be a nonnegative integer")
if "needs_real_run" in data:
    raise ValueError("needs_real_run is not valid mutation evidence")
ran_at = nonempty_string(data.get("ran_at"), "ran_at")
if "timestamp_kind" in data and "timestamp_source" in data:
    raise ValueError("timestamp_kind and timestamp_source are mutually exclusive")
timestamp_kind = (
    optional_enum(
        data,
        "timestamp_kind",
        {
            "cargo-mutants-run",
            "command-wall-clock",
            "generated-metadata",
        },
    )
    or optional_enum(
        data,
        "timestamp_source",
        {
            "cargo-mutants-run",
            "command-wall-clock",
            "generated-metadata",
        },
    )
)
survivors = data.get("survivors", [])
if not isinstance(survivors, list) or any(
    not isinstance(survivor, str) or not survivor for survivor in survivors
):
    raise ValueError("survivors must be an array of nonempty strings")
if survivors:
    raise ValueError("promoted evidence must not retain survivors")
evidence_status = optional_enum(
    data, "evidence_status", {"cargo-mutants-run", "conformance-only"}
)
mutation_evidence_status = optional_enum(
    data, "mutation_evidence_status", {"complete", "not-run"}
)
promotion_status = optional_enum(
    data, "promotion_status", {"promoted", "not-promoted"}
)
outcome_records = data.get("outcomes")
requires_aggregate_evidence = caught >= 1
if requires_aggregate_evidence and (
    not isinstance(outcome_records, list) or not outcome_records
):
    raise ValueError("positive evidence requires nonempty outcomes")
aggregate_case_path = None
if (
    requires_aggregate_evidence
    or "mutation_case_path" in data
    or "closed_subvector_test" in data
):
    aggregate_case_path = validate_aggregate_linkage(data, repo_root)
if outcome_records is not None:
    if not isinstance(outcome_records, list) or not outcome_records:
        raise ValueError("outcomes must be a nonempty array when present")
    campaign_index = load_campaign_index(repo_root, cases_root_relative)
    observed_ids = set()
    child_caught = 0
    rendered_counts = []
    reproduction_records = []
    for index, record in enumerate(outcome_records):
        if not isinstance(record, dict) or set(record) != {"id", "path", "sha256"}:
            raise ValueError(f"outcomes[{index}] must contain exactly id, path, and sha256")
        mutation_id = record["id"]
        relative_path = record["path"]
        digest = record["sha256"]
        if not isinstance(mutation_id, str) or not mutation_id or mutation_id in observed_ids:
            raise ValueError(f"outcomes[{index}] has an invalid or duplicate id")
        relative_path = repository_relative_path(
            relative_path, f"outcomes[{index}].path"
        )
        campaign_binding = campaign_index.get(mutation_id)
        if campaign_binding is None:
            raise ValueError(f"outcomes[{index}] id is absent from the campaign index")
        expected_path, indexed_threat_id, case_path = campaign_binding
        if relative_path != expected_path:
            raise ValueError(
                f"outcomes[{index}] path differs from its indexed campaign path"
            )
        if indexed_threat_id != row_threat_id:
            raise ValueError(
                f"outcomes[{index}] campaign case {case_path} cites threat "
                f"{indexed_threat_id}, not {row_threat_id}"
            )
        if aggregate_case_path is not None and case_path != aggregate_case_path:
            raise ValueError(
                f"outcomes[{index}] campaign belongs to {case_path}, not the "
                f"aggregate mutation_case_path {aggregate_case_path}"
            )
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise ValueError(f"outcomes[{index}] has an invalid SHA-256")
        _, payload = repository_file(
            repo_root,
            relative_path,
            f"outcomes[{index}].path",
            ".json",
        )
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f"outcomes[{index}] digest does not match its child")
        child = parse_json(payload, f"outcomes[{index}] child")
        if not isinstance(child, dict):
            raise ValueError(f"outcomes[{index}] child must be an object")
        counts = {
            name: child.get(name)
            for name in (
                "caught",
                "missed",
                "timeout",
                "unviable",
                "success",
                "total_mutants",
            )
        }
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts.values()):
            raise ValueError(f"outcomes[{index}] has invalid mutation counts")
        if counts["caught"] < 1 or any(
            counts[name] != 0
            for name in ("missed", "timeout", "unviable", "success")
        ):
            raise ValueError(f"outcomes[{index}] is not caught-only evidence")
        if counts["total_mutants"] != counts["caught"]:
            raise ValueError(f"outcomes[{index}] total does not equal its caught count")
        native_outcomes = child.get("outcomes")
        if not isinstance(native_outcomes, list) or not native_outcomes:
            raise ValueError(f"outcomes[{index}] child has no native outcome records")
        baseline_count = 0
        native_caught = 0
        for native_offset, native_outcome in enumerate(native_outcomes):
            if not isinstance(native_outcome, dict):
                raise ValueError(
                    f"outcomes[{index}] native outcome {native_offset} is not an object"
                )
            scenario = native_outcome.get("scenario")
            summary = native_outcome.get("summary")
            if scenario == "Baseline":
                baseline_count += 1
                if summary != "Success":
                    raise ValueError(
                        f"outcomes[{index}] native baseline did not succeed"
                    )
                continue
            mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
            if not isinstance(mutant, dict) or summary != "CaughtMutant":
                raise ValueError(
                    f"outcomes[{index}] native mutant is not caught evidence"
                )
            native_caught += 1
        if baseline_count != 1:
            raise ValueError(
                f"outcomes[{index}] must contain exactly one successful baseline"
            )
        if (
            native_caught != counts["caught"]
            or native_caught != counts["total_mutants"]
            or len(native_outcomes) != native_caught + 1
        ):
            raise ValueError(
                f"outcomes[{index}] native summaries do not reconcile with counts"
            )
        observed_ids.add(mutation_id)
        child_caught += counts["caught"]
        rendered_counts.append((mutation_id, counts["caught"]))
        reproduction_records.append((mutation_id, relative_path))
    if child_caught != caught:
        raise ValueError("parent caught count does not equal the child outcome sum")
    if requires_aggregate_evidence:
        if not evidence_status or not mutation_evidence_status or not promotion_status:
            raise ValueError("positive aggregate evidence requires explicit status metadata")
        try:
            datetime.datetime.strptime(ran_at, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as error:
            raise ValueError("ran_at must be a valid UTC whole-second timestamp") from error
        promoted_tuple = (
            evidence_status == "cargo-mutants-run"
            and mutation_evidence_status == "complete"
            and promotion_status == "promoted"
        )
        if promoted_tuple:
            if timestamp_kind != "command-wall-clock":
                raise ValueError(
                    "promoted aggregate timestamp_kind must be command-wall-clock"
                )
            details = " and ".join(
                f"{campaign_id} caught {campaign_caught}"
                for campaign_id, campaign_caught in rendered_counts
            )
            expected_note = (
                "Digest-bound caught-only cargo-mutants outcomes cover the closed "
                f"sub-vector: {details}, with zero missed, timed-out, or unviable "
                "mutants."
            )
            expected_reproduction = " && ".join(
                "./scripts/check-security-adversarial-evidence.sh "
                f"--verify-outcome {campaign_id} {campaign_path}"
                for campaign_id, campaign_path in reproduction_records
            )
            expected_timestamp_note = (
                "The timestamp records completion of caught-only mutation rerun "
                "validation. Native outcomes retain cargo-mutants phase records and "
                "durations."
            )
            if nonempty_string(data.get("note"), "note") != expected_note:
                raise ValueError("aggregate note is stale or inconsistent")
            if (
                nonempty_string(
                    data.get("reproduction_command"), "reproduction_command"
                )
                != expected_reproduction
            ):
                raise ValueError("aggregate reproduction_command is stale")
            if (
                nonempty_string(data.get("timestamp_note"), "timestamp_note")
                != expected_timestamp_note
            ):
                raise ValueError("aggregate timestamp_note is stale")
print(
    f"{caught}\t{ran_at}\t{len(survivors)}\t"
    f"{timestamp_kind}\t{evidence_status}\t{mutation_evidence_status}\t{promotion_status}"
)
PY
}

passed=()
pending=()
weak_hints=()
fail=0
row_count=0

if ! threat_records="$(classify_threats)"; then
    echo "FAIL: threat-model row classification did not complete." >&2
    exit 1
fi

while IFS=$'\t' read -r tid state has_coveredby has_deferred_to; do
    [[ -z "$tid" ]] && continue
    row_count=$((row_count + 1))

    case "$state" in
        pending)
            if [[ "$has_deferred_to" != "1" ]]; then
                weak_hints+=("WEAK: $tid pending row rejected; reason=pending_without_deferred_to")
                fail=1
            else
                pending+=("$tid")
            fi
            continue
            ;;
        weak_coverage)
            weak_hints+=("WEAK: $tid is not release-closed; reason=weak_coverage_state")
            fail=1
            continue
            ;;
        covered|partial)
            ;;
    esac

    if [[ "$has_coveredby" != "1" ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=no_coveredby")
        fail=1
        continue
    fi

    evidence_file="$EVIDENCE_DIR/$tid.json"
    if [[ ! -f "$evidence_file" ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=missing_evidence")
        fail=1
        continue
    fi
    if ! evidence_record="$(read_evidence "$evidence_file" "$tid" 2>/dev/null)"; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=invalid_evidence")
        fail=1
        continue
    fi

    caught="$(printf '%s' "$evidence_record" | cut -f1)"
    ran_at="$(printf '%s' "$evidence_record" | cut -f2)"
    survivor_count="$(printf '%s' "$evidence_record" | cut -f3)"
    timestamp_kind="$(printf '%s' "$evidence_record" | cut -f4)"
    evidence_status="$(printf '%s' "$evidence_record" | cut -f5)"
    mutation_evidence_status="$(printf '%s' "$evidence_record" | cut -f6)"
    promotion_status="$(printf '%s' "$evidence_record" | cut -f7)"

    if [[ -n "$timestamp_kind" && "$timestamp_kind" != "cargo-mutants-run" && "$timestamp_kind" != "command-wall-clock" ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=non_mutants_metadata (timestamp_kind=$timestamp_kind cannot pass as cargo-mutants evidence)")
        fail=1
        continue
    fi
    if [[ "$evidence_status" == "conformance-only" || "$mutation_evidence_status" == "not-run" || "$promotion_status" == "not-promoted" ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=non_mutants_metadata (metadata is ${evidence_status:-unspecified}/${mutation_evidence_status:-unspecified}/${promotion_status:-unspecified})")
        fail=1
        continue
    fi

    if [[ "$ran_at" == *"T00:00:00Z" && "$timestamp_kind" != "cargo-mutants-run" && "$timestamp_kind" != "command-wall-clock" ]]; then
        weak_hints+=("WEAK: $tid should label synthetic-looking ran_at metadata; reason=synthetic_timestamp_unlabeled")
        fail=1
        continue
    fi

    if [[ "${caught:-0}" -lt 1 ]]; then
        weak_hints+=("WEAK: $tid should be marked weak_coverage; reason=zero_kills")
        fail=1
        continue
    fi

    passed+=("$tid")
done <<< "$threat_records"

if [[ "$row_count" -eq 0 ]]; then
    echo "FAIL: zero threat-model rows were evaluated by the mutants gate." >&2
    fail=1
fi

echo "threat-model mutants gate:"
echo "  passed: ${#passed[@]}"
echo "  pending: ${#pending[@]}"
echo "  failures: ${#weak_hints[@]}"

# The indirection keeps empty arrays safe under older Bash `set -u` behavior.
for h in ${weak_hints[@]+"${weak_hints[@]}"}; do
    echo "$h" >&2
done

if [[ "$fail" -eq 1 ]]; then
    echo "" >&2
    echo "FAIL: threat mutation-evidence contract rejected one or more rows." >&2
    exit 1
fi

echo "PASS: per-row mutants evidence gate"
