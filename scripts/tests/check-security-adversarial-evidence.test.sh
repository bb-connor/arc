#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

test -x scripts/check-security-adversarial-evidence.sh
bash -n scripts/check-security-adversarial-evidence.sh
python3 -m py_compile scripts/check-security-adversarial-evidence.py

if enterprise_promotion_output="$(
  CHIO_ENTERPRISE_SECURITY_RUNNER=1 \
    python3 scripts/check-security-adversarial-evidence.py \
      --promote-outcome forbidden /candidate/outcomes.json 2>&1
)"; then
  echo "enterprise legacy outcome promotion passed unexpectedly" >&2
  exit 1
fi
grep -Fq \
  "legacy --promote-outcome is forbidden in the enterprise boundary" \
  <<<"${enterprise_promotion_output}"

full_validation="$(./scripts/check-security-adversarial-evidence.sh)"
test "$full_validation" = "validated 28 security adversarial cases and 35 mutation selections"
pending_campaigns="$(./scripts/check-security-adversarial-evidence.sh --list-pending)"
if [[ -n "${pending_campaigns}" ]]; then
  test "${pending_campaigns}" = "$(printf '%s\n' "${pending_campaigns}" | LC_ALL=C sort -u)"
  if grep -Ev '^[a-z0-9][a-z0-9_]*$' <<<"${pending_campaigns}"; then
    echo "pending mutation campaign list contains an invalid identifier" >&2
    exit 1
  fi
fi

python3 - <<'PY'
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path.cwd()
gate = root / "scripts/check-security-adversarial-evidence.sh"
temporal = root / (
    "crates/core/chio-adversarial-suite/cases/temporal_evasion/"
    "temporal-evasion-001.json"
)
module_spec = importlib.util.spec_from_file_location(
    "security_adversarial_evidence",
    root / "scripts/check-security-adversarial-evidence.py",
)
if module_spec is None or module_spec.loader is None:
    raise AssertionError("unable to load adversarial evidence checker")
checker = importlib.util.module_from_spec(module_spec)
sys.modules[module_spec.name] = checker
module_spec.loader.exec_module(checker)


def write_json(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def invoke(
    cases: Path,
    *extra: str,
    invocation_root: Path = root,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(gate),
            "--root",
            str(invocation_root),
            "--cases",
            str(cases),
            "--fixture",
            *extra,
        ],
        cwd=invocation_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def expect_rejected(result: subprocess.CompletedProcess[str], needle: str) -> None:
    if result.returncode == 0:
        raise AssertionError(f"invalid evidence passed unexpectedly: {result.stdout}")
    if needle not in result.stdout:
        raise AssertionError(
            f"expected rejection containing {needle!r}, observed: {result.stdout}"
        )


with tempfile.TemporaryDirectory(prefix="chio-adversarial-evidence-selftest-") as raw:
    temp = Path(raw).resolve()

    valid_root = temp / "valid-root"
    valid_root.mkdir()
    (valid_root / "Cargo.toml").write_text(
        (
            "[workspace]\n"
            "members = [\n"
            "  \"crates/fixture-package\",\n"
            "  \"crates/core/chio-adversarial-suite\",\n"
            "]\n"
            "resolver = \"2\"\n"
        ),
        encoding="utf-8",
    )
    (valid_root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    valid_package = valid_root / "crates/fixture-package"
    valid_package.mkdir(parents=True)
    (valid_package / "Cargo.toml").write_text(
        (
            "[package]\n"
            "name = \"fixture-package\"\n"
            "version = \"0.0.0\"\n"
            "edition = \"2021\"\n"
        ),
        encoding="utf-8",
    )
    valid_source = valid_package / "src/lib.rs"
    valid_source.parent.mkdir()
    valid_source.write_text(
        "fn fixture_function() -> bool { true }\n"
        "#[test]\nfn fixture_test() {}\n",
        encoding="utf-8",
    )
    valid_evidence_package = valid_root / "crates/core/chio-adversarial-suite"
    valid_evidence_package.mkdir(parents=True)
    (valid_evidence_package / "Cargo.toml").write_text(
        (
            "[package]\n"
            "name = \"fixture-evidence\"\n"
            "version = \"0.0.0\"\n"
            "edition = \"2021\"\n"
        ),
        encoding="utf-8",
    )
    valid_evidence_source = valid_evidence_package / "src/lib.rs"
    valid_evidence_source.parent.mkdir()
    valid_evidence_source.write_text(
        "pub fn evidence_fixture() -> bool { true }\n", encoding="utf-8"
    )
    valid_cases = valid_evidence_package / "cases"
    valid_case_path = valid_cases / "temporal_evasion/temporal-evasion-001.json"
    valid_case = json.loads(temporal.read_text(encoding="utf-8"))
    valid_case["artifact"]["controls"][0].update(
        {
            "package": "fixture-package",
            "test_source": "crates/fixture-package/src/lib.rs",
            "test_name": "fixture_test",
        }
    )
    valid_campaign_body = valid_case["artifact"]["campaigns"][0]
    valid_campaign_body.update(
        {
            "package": "fixture-package",
            "source": "crates/fixture-package/src/lib.rs",
            "function": "fixture_function",
            "minimum_caught": 1,
            "mutant": {"genre": "FnValue", "replacement": "false"},
        }
    )
    valid_campaign_body["outcomes"].pop("sha256", None)
    valid_campaign_body["outcomes"].pop("inputs_sha256", None)
    write_json(valid_case_path, valid_case)
    valid_outcome_body = {
        "caught": 1,
        "missed": 0,
        "timeout": 0,
        "unviable": 0,
        "success": 0,
        "total_mutants": 1,
        "outcomes": [
            {"scenario": "Baseline", "summary": "Success"},
            {
                "scenario": {
                    "Mutant": {
                        "package": "fixture-package",
                        "file": "crates/fixture-package/src/lib.rs",
                        "function": {
                            "function_name": "fixture_function",
                            "return_type": "-> bool",
                            "span": {
                                "start": {"line": 1, "column": 1},
                                "end": {"line": 1, "column": 39},
                            },
                        },
                        "span": {
                            "start": {"line": 1, "column": 33},
                            "end": {"line": 1, "column": 37},
                        },
                        "replacement": "false",
                        "genre": "FnValue",
                    }
                },
                "summary": "CaughtMutant",
            },
        ],
    }
    valid_outcome = valid_root / valid_campaign_body["outcomes"]["path"]
    _valid_cases, valid_index = checker.load_cases(
        valid_root,
        valid_cases,
        False,
        True,
        refresh_campaign="ingest_time_substitution",
    )
    _loaded_case, valid_campaign, valid_control = valid_index[
        "ingest_time_substitution"
    ]
    write_json(valid_outcome, valid_outcome_body)
    valid_case["artifact"]["campaigns"][0]["outcomes"]["sha256"] = (
        hashlib.sha256(valid_outcome.read_bytes()).hexdigest()
    )
    valid_case["artifact"]["campaigns"][0]["outcomes"]["inputs_sha256"] = (
        checker.campaign_input_digest(
            valid_root,
            checker.package_roots(valid_root),
            valid_campaign,
            valid_control,
            valid_case_path,
        )
    )
    valid_case["pending"] = False
    write_json(valid_case_path, valid_case)
    valid = invoke(valid_cases, invocation_root=valid_root)
    if valid.returncode != 0:
        raise AssertionError(valid.stdout)

    legacy_cases = temp / "legacy"
    legacy = copy.deepcopy(valid_case)
    legacy["pending"] = True
    legacy["artifact"] = {
        "required_check": "temporal_evasion",
        "control": {"check_present": True, "expected_verdict": "DENY"},
        "mutant": {"check_present": False, "expected_verdict": "ALLOW"},
    }
    write_json(
        legacy_cases / "temporal_evasion/temporal-evasion-001.json",
        legacy,
    )
    expect_rejected(
        invoke(legacy_cases, invocation_root=valid_root), "artifact: field mismatch"
    )

    unknown_cases = temp / "unknown"
    unknown = copy.deepcopy(valid_case)
    unknown["artifact"]["unexpectedField"] = True
    write_json(
        unknown_cases / "temporal_evasion/temporal-evasion-001.json",
        unknown,
    )
    expect_rejected(
        invoke(unknown_cases, invocation_root=valid_root),
        "unknown=['unexpectedField']",
    )

    digest_cases = temp / "digest"
    digest = copy.deepcopy(valid_case)
    digest["artifact"]["campaigns"][0]["outcomes"]["sha256"] = "0" * 64
    write_json(
        digest_cases / "temporal_evasion/temporal-evasion-001.json",
        digest,
    )
    expect_rejected(
        invoke(digest_cases, invocation_root=valid_root), "digest mismatch"
    )

    unbound_inputs_cases = temp / "unbound-inputs"
    unbound_inputs = copy.deepcopy(valid_case)
    unbound_inputs["artifact"]["campaigns"][0]["outcomes"].pop(
        "inputs_sha256"
    )
    write_json(
        unbound_inputs_cases / "temporal_evasion/temporal-evasion-001.json",
        unbound_inputs,
    )
    expect_rejected(
        invoke(unbound_inputs_cases, invocation_root=valid_root),
        "outcome and input digests must be bound together",
    )

    missing_cases = temp / "missing"
    missing = copy.deepcopy(valid_case)
    missing["pending"] = False
    missing["artifact"]["campaigns"][0]["outcomes"].pop("sha256", None)
    missing["artifact"]["campaigns"][0]["outcomes"].pop(
        "inputs_sha256", None
    )
    write_json(
        missing_cases / "temporal_evasion/temporal-evasion-001.json",
        missing,
    )
    expect_rejected(
        invoke(missing_cases, invocation_root=valid_root),
        "outcome exists without a bound digest",
    )

    base_outcome = copy.deepcopy(valid_outcome_body)
    missed = copy.deepcopy(base_outcome)
    missed["outcomes"][1]["summary"] = "MissedMutant"
    missed["caught"] -= 1
    missed["missed"] = 1
    missed_path = temp / "missed.json"
    write_json(missed_path, missed)
    expect_rejected(
        invoke(
            valid_cases,
            "--verify-outcome",
            "ingest_time_substitution",
            str(missed_path),
            invocation_root=valid_root,
        ),
        "missed, timed out, unviable, or surviving mutant",
    )

    unviable = copy.deepcopy(base_outcome)
    unviable["outcomes"][1]["summary"] = "Unviable"
    unviable["caught"] -= 1
    unviable["unviable"] = 1
    unviable_path = temp / "unviable.json"
    write_json(unviable_path, unviable)
    expect_rejected(
        invoke(
            valid_cases,
            "--verify-outcome",
            "ingest_time_substitution",
            str(unviable_path),
            invocation_root=valid_root,
        ),
        "missed, timed out, unviable, or surviving mutant",
    )

    single_open_outcome = temp / "single-open-outcomes.json"
    single_open_source = temp / "single-open-source.rs"
    single_open_source_text = (
        "fn fixture_function() -> bool { true && false }\n"
    )
    single_open_source.write_text(single_open_source_text, encoding="utf-8")
    operator_column = single_open_source_text.index("&&") + 1
    single_open_mutant = {
        "package": "fixture-package",
        "file": "src/lib.rs",
        "function": {
            "function_name": "fixture_function",
            "return_type": "-> bool",
        },
        "span": {
            "start": {"line": 1, "column": operator_column},
            "end": {"line": 1, "column": operator_column + 2},
        },
        "replacement": "||",
        "genre": "BinaryOperator",
    }
    single_open_campaign = {
        "id": "single_open_campaign",
        "package": "fixture-package",
        "source": "src/lib.rs",
        "function": "fixture_function",
        "minimum_caught": 1,
        "mutant": {
            "genre": "BinaryOperator",
            "original": "&&",
            "replacement": "||",
        },
    }
    single_open_body = {
        "caught": 1,
        "missed": 0,
        "timeout": 0,
        "unviable": 0,
        "success": 0,
        "total_mutants": 1,
        "outcomes": [
            {"scenario": "Baseline", "summary": "Success"},
            {
                "scenario": {"Mutant": single_open_mutant},
                "summary": "CaughtMutant",
            },
        ],
    }
    write_json(single_open_outcome, single_open_body)
    single_open_outcome_payload = single_open_outcome.read_bytes()
    hostile_outcome = copy.deepcopy(single_open_body)
    hostile_outcome["caught"] = 0
    hostile_outcome["missed"] = 1
    hostile_outcome["outcomes"][1]["summary"] = "MissedMutant"
    hostile_payloads = {
        single_open_outcome: checker.canonical_json_bytes(hostile_outcome),
        single_open_source: single_open_source_text.replace("&&", "||").encode(
            "utf-8"
        ),
    }
    hostile_captures = {path: 0 for path in hostile_payloads}
    actual_no_follow_reader = checker.read_regular_file_no_follow
    actual_path_read_bytes = Path.read_bytes

    def replace_after_no_follow_capture(
        path: Path,
        label: str,
        *,
        root: Path | None = None,
    ) -> bytes:
        payload = actual_no_follow_reader(path, label, root=root)
        resolved = path.resolve()
        if resolved in hostile_payloads and hostile_captures[resolved] == 0:
            hostile_captures[resolved] += 1
            resolved.write_bytes(hostile_payloads[resolved])
        return payload

    def replace_after_legacy_read(path: Path) -> bytes:
        payload = actual_path_read_bytes(path)
        resolved = path.resolve()
        if resolved == single_open_outcome and hostile_captures[resolved] == 0:
            hostile_captures[resolved] += 1
            resolved.write_bytes(hostile_payloads[resolved])
        return payload

    checker.read_regular_file_no_follow = replace_after_no_follow_capture
    Path.read_bytes = replace_after_legacy_read
    try:
        observed_single_open_payload = checker.validate_outcomes(
            single_open_outcome,
            single_open_campaign,
            hashlib.sha256(single_open_outcome_payload).hexdigest(),
            single_open_source,
        )
    finally:
        checker.read_regular_file_no_follow = actual_no_follow_reader
        Path.read_bytes = actual_path_read_bytes
    if observed_single_open_payload != single_open_outcome_payload:
        raise AssertionError("outcome validation did not retain its captured payload")
    if any(count != 1 for count in hostile_captures.values()):
        raise AssertionError(
            "source and outcome validation did not use one immutable capture each"
        )

    closure_root = temp / "repository-input-closure"
    closure_package = closure_root / "crates/fixture-package"
    closure_source = closure_package / "src/lib.rs"
    closure_external = closure_root / "external-inputs"
    closure_external.mkdir(parents=True)
    (closure_root / "Cargo.toml").write_text(
        (
            "[workspace]\n"
            "members = [\"crates/fixture-package\"]\n"
            "resolver = \"2\"\n"
        ),
        encoding="utf-8",
    )
    (closure_root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    closure_package.mkdir(parents=True)
    (closure_package / "Cargo.toml").write_text(
        (
            "[package]\n"
            "name = \"fixture-package\"\n"
            "version = \"0.0.0\"\n"
            "edition = \"2021\"\n"
            "build = \"build.rs\"\n"
        ),
        encoding="utf-8",
    )
    closure_source.parent.mkdir()
    closure_source.write_text(
        (
            "const EXTERNAL_TEXT: &str = "
            "include_str!(\"../../../external-inputs/included.txt\");\n"
            "include!(\"../../../external-inputs/generated.inc\");\n"
            "fn fixture_function() -> bool { true }\n"
            "#[test]\nfn fixture_test() {}\n"
        ),
        encoding="utf-8",
    )
    (closure_package / "build.rs").write_text(
        (
            "const BUILD_INPUT: &[u8] = "
            "include_bytes!(\"../../external-inputs/build.txt\");\n"
            "fn main() {\n"
            "    println!(\"cargo:rerun-if-changed=../../external-inputs/build.txt\");\n"
            "    let _ = BUILD_INPUT.len();\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    external_include_str = closure_external / "included.txt"
    external_include = closure_external / "generated.inc"
    external_build_input = closure_external / "build.txt"
    external_include_str.write_text("included text\n", encoding="utf-8")
    external_include.write_text(
        "const GENERATED_VALUE: bool = true;\n", encoding="utf-8"
    )
    external_build_input.write_text("build input\n", encoding="utf-8")
    (closure_root / "crates/core/chio-adversarial-suite").mkdir(parents=True)
    derived_mutation_root = closure_root / "audits/evidence/mutants/security"
    derived_mutation_root.mkdir(parents=True)
    (derived_mutation_root / ".gitignore").write_text("*\n!.gitignore\n", encoding="utf-8")
    closure_campaign = {
        "id": "fixture_campaign",
        "control_id": "fixture_control",
        "package": "fixture-package",
        "source": "crates/fixture-package/src/lib.rs",
        "function": "fixture_function",
        "minimum_caught": 1,
        "mutant": {"genre": "FnValue", "replacement": "false"},
        "outcomes": {
            "path": (
                "audits/evidence/mutants/security/fixture_campaign/"
                "mutants.out/outcomes.json"
            )
        },
    }
    closure_control = {
        "id": "fixture_control",
        "package": "fixture-package",
        "test_source": "crates/fixture-package/src/lib.rs",
        "target_kind": "lib",
        "target": "",
        "features": [],
        "required_target_os": None,
        "test_name": "fixture_test",
    }
    closure_packages = {"fixture-package": closure_package.resolve()}
    closure_case_path = closure_root / (
        "crates/core/chio-adversarial-suite/cases/fixture/fixture.json"
    )

    def closure_digest() -> str:
        return checker.campaign_input_digest(
            closure_root,
            closure_packages,
            closure_campaign,
            closure_control,
            closure_case_path,
        )

    base_closure_digest = closure_digest()
    derived_artifacts = {
        closure_case_path: b"{}\n",
        closure_root / "crates/core/chio-adversarial-suite/manifest.json": b"{}\n",
        derived_mutation_root
        / "fixture_campaign/mutants.out/outcomes.json": b"{}\n",
        closure_root / "audits/evidence/threats/fixture.json": b"{}\n",
    }
    for derived_path, derived_payload in derived_artifacts.items():
        derived_path.parent.mkdir(parents=True, exist_ok=True)
        derived_path.write_bytes(derived_payload)
    if closure_digest() != base_closure_digest:
        raise AssertionError("derived adversarial outputs invalidated the input closure")

    generated_input = closure_root / "node_modules/generated/cache.js"
    generated_input.parent.mkdir(parents=True)
    generated_input.write_text("generated cache\n", encoding="utf-8")
    if closure_digest() != base_closure_digest:
        raise AssertionError("generated dependency state invalidated the input closure")

    for external_path in (
        external_include_str,
        external_include,
        external_build_input,
    ):
        original_payload = external_path.read_bytes()
        external_path.write_bytes(original_payload + b"hostile drift\n")
        if closure_digest() == base_closure_digest:
            raise AssertionError(
                f"out-of-package compile input drift was not bound: {external_path}"
            )
        external_path.write_bytes(original_payload)

    closure_source_payload = closure_source.read_text(encoding="utf-8")
    closure_source.write_text(
        closure_source_payload
        + (
            "const EXCLUDED_OUTPUT: &str = include_str!(\"../../../audits/evidence/"
            "mutants/security/fixture_campaign/mutants.out/outcomes.json\");\n"
        ),
        encoding="utf-8",
    )
    try:
        closure_digest()
    except checker.EvidenceError as error:
        if "references excluded generated or derived input" not in str(error):
            raise AssertionError(
                f"unexpected excluded compile-input rejection: {error}"
            ) from error
    else:
        raise AssertionError("participating source consumed an excluded output")
    closure_source.write_text(closure_source_payload, encoding="utf-8")

    closure_source.write_text(
        closure_source_payload
        + (
            "const GENERATED_INPUT: &str = include_str!(\"../../../node_modules/"
            "generated/cache.js\");\n"
        ),
        encoding="utf-8",
    )
    try:
        closure_digest()
    except checker.EvidenceError as error:
        if "references excluded generated or derived input" not in str(error):
            raise AssertionError(
                f"unexpected generated compile-input rejection: {error}"
            ) from error
    else:
        raise AssertionError("participating source consumed generated dependency state")
    closure_source.write_text(closure_source_payload, encoding="utf-8")

    promotion_root = temp / "promotion-root"
    (promotion_root / "Cargo.toml").parent.mkdir(parents=True)
    (promotion_root / "Cargo.toml").write_text(
        (
            "[workspace]\n"
            "members = [\n"
            "  \"crates/fixture-package\",\n"
            "  \"crates/fixture-dependency\",\n"
            "  \"crates/fixture-test-helper\",\n"
            "  \"crates/core/chio-adversarial-suite\",\n"
            "]\n"
            "resolver = \"2\"\n"
        ),
        encoding="utf-8",
    )
    (promotion_root / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
    package_root = promotion_root / "crates/fixture-package"
    package_root.mkdir(parents=True)
    (package_root / "Cargo.toml").write_text(
        (
            "[package]\n"
            "name = \"fixture-package\"\n"
            "version = \"0.0.0\"\n"
            "edition = \"2021\"\n"
            "\n"
            "[dependencies]\n"
            "fixture-dependency = { path = \"../fixture-dependency\" }\n"
            "\n"
            "[dev-dependencies]\n"
            "fixture-test-helper = { path = \"../fixture-test-helper\" }\n"
            "\n"
            "[[bin]]\n"
            "name = \"fixture-explicit\"\n"
            "path = \"custom/explicit.rs\"\n"
            "\n"
            "[[bin]]\n"
            "name = \"fixture-inc-root\"\n"
            "path = \"custom/root.inc\"\n"
        ),
        encoding="utf-8",
    )
    fixture_source = package_root / "src/lib.rs"
    fixture_source.parent.mkdir()
    fixture_source.write_text(
        (
            "fn fixture_function() -> bool { true }\n"
            "fn fixture_function_changed() -> bool { true }\n"
            "#[test]\nfn fixture_test() {}\n"
            "#[test]\nfn fixture_test_changed() {}\n"
            "mod fixture_module;\n"
            "#[path = \"path_modules/fixture_path.rs\"]\n"
            "mod fixture_path_module;\n"
            "#[path = \"path_modules/fixture_path.inc\"]\n"
            "mod fixture_path_inc_module;\n"
            "mod directory_module;\n"
            "mod dual_module;\n"
            "include!(\"dual_module.rs\");\n"
            "include!(\"included_fragment.rs\");\n"
            "include!(\"included_fragment.inc\");\n"
            "#[cfg(test)]\nmod test_only_module;\n"
            "#[cfg_attr(mutants, mutants::skip)]\nmod skipped_module;\n"
            "mod inner_skipped_module;\n"
            "mod inline_outer {\n"
            "    #[path = \"nested/path_nested.rs\"]\n"
            "    mod nested_path;\n"
            "    mod nested_default;\n"
            "}\n"
            "#[path = \"same_line.rs\"] mod same_line_path;\n"
            "#[path =\n"
            "    \"multiline_path.rs\"]\n"
            "mod multiline_path;\n"
            "mod race_source;\n"
            "// mod line_commented_module;\n"
            "/*\nmod block_commented_module;\n*/\n"
            "const RAW_MODULE_TEXT: &str = r#\"\n"
            "mod raw_string_module;\n"
            "\"#;\n"
            "macro_rules! fake_module_declaration {\n"
            "    () => { mod macro_module; };\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    fixture_module = package_root / "src/fixture_module.rs"
    fixture_module.write_text(
        "fn fixture_module_function() -> bool { true }\n", encoding="utf-8"
    )
    fixture_path_module = package_root / "src/path_modules/fixture_path.rs"
    fixture_path_module.parent.mkdir()
    fixture_path_module.write_text(
        "fn fixture_path_function() -> bool { true }\n", encoding="utf-8"
    )
    fixture_path_inc_module = package_root / "src/path_modules/fixture_path.inc"
    fixture_path_inc_module.write_text(
        "fn fixture_path_inc_function() -> bool { true }\n", encoding="utf-8"
    )
    directory_module = package_root / "src/directory_module/mod.rs"
    directory_module.parent.mkdir()
    directory_module.write_text(
        "fn directory_module_function() -> bool { true }\n", encoding="utf-8"
    )
    dual_module = package_root / "src/dual_module.rs"
    dual_module.write_text(
        "fn dual_module_function() -> bool { true }\n", encoding="utf-8"
    )
    included_rs_fragment = package_root / "src/included_fragment.rs"
    included_rs_fragment.write_text(
        "fn included_rs_function() -> bool { true }\n", encoding="utf-8"
    )
    included_inc_fragment = package_root / "src/included_fragment.inc"
    included_inc_fragment.write_text(
        "fn included_inc_function() -> bool { true }\n", encoding="utf-8"
    )
    orphan_rs_fragment = package_root / "src/orphan_fragment.rs"
    orphan_rs_fragment.write_text(
        "fn orphan_rs_function() -> bool { true }\n", encoding="utf-8"
    )
    orphan_inc_fragment = package_root / "src/orphan_fragment.inc"
    orphan_inc_fragment.write_text(
        "fn orphan_inc_function() -> bool { true }\n", encoding="utf-8"
    )
    test_only_module = package_root / "src/test_only_module.rs"
    test_only_module.write_text(
        "fn test_only_function() -> bool { true }\n", encoding="utf-8"
    )
    skipped_module = package_root / "src/skipped_module.rs"
    skipped_module.write_text(
        "fn skipped_function() -> bool { true }\n", encoding="utf-8"
    )
    inner_skipped_module = package_root / "src/inner_skipped_module.rs"
    inner_skipped_module.write_text(
        "#![cfg_attr(mutants, mutants::skip)]\n"
        "fn inner_skipped_function() -> bool { true }\n",
        encoding="utf-8",
    )
    nested_path_module = package_root / "src/inline_outer/nested/path_nested.rs"
    nested_path_module.parent.mkdir(parents=True)
    nested_path_module.write_text(
        "fn nested_path_function() -> bool { true }\n", encoding="utf-8"
    )
    nested_default_module = package_root / "src/inline_outer/nested_default.rs"
    nested_default_module.write_text(
        "fn nested_default_function() -> bool { true }\n", encoding="utf-8"
    )
    same_line_module = package_root / "src/same_line.rs"
    same_line_module.write_text(
        "fn same_line_function() -> bool { true }\n", encoding="utf-8"
    )
    multiline_path_module = package_root / "src/multiline_path.rs"
    multiline_path_module.write_text(
        "fn multiline_path_function() -> bool { true }\n", encoding="utf-8"
    )
    race_source = package_root / "src/race_source.rs"
    race_source_payload = b"fn captured_only_function() -> bool { true }\n"
    race_source.write_bytes(race_source_payload)
    for hidden_module, hidden_function in (
        ("line_commented_module", "line_commented_function"),
        ("block_commented_module", "block_commented_function"),
        ("raw_string_module", "raw_string_function"),
        ("macro_module", "macro_module_function"),
    ):
        (package_root / f"src/{hidden_module}.rs").write_text(
            f"fn {hidden_function}() -> bool {{ true }}\n", encoding="utf-8"
        )
    fixture_binary = package_root / "src/bin/fixture-tool.rs"
    fixture_binary.parent.mkdir()
    fixture_binary.write_text(
        "fn fixture_binary_function() -> bool { true }\nfn main() {}\n",
        encoding="utf-8",
    )
    explicit_fixture_binary = package_root / "custom/explicit.rs"
    explicit_fixture_binary.parent.mkdir()
    explicit_fixture_binary.write_text(
        "fn fixture_explicit_binary_function() -> bool { true }\nfn main() {}\n",
        encoding="utf-8",
    )
    explicit_inc_binary = package_root / "custom/root.inc"
    explicit_inc_binary.write_text(
        "fn fixture_inc_root_function() -> bool { true }\nfn main() {}\n",
        encoding="utf-8",
    )
    fixture_module_alias = package_root / "src/fixture_module_alias.rs"
    fixture_module_alias.symlink_to("fixture_module.rs")
    shared_input_root = promotion_root / "tests/shared-fixture-inputs"
    shared_input_root.mkdir(parents=True)
    shared_input_source = shared_input_root / "shared.rs"
    shared_input_source.write_text(
        "pub fn shared_input() -> bool { true }\n", encoding="utf-8"
    )
    shared_input_link = package_root / "tests/shared"
    shared_input_link.parent.mkdir()
    shared_input_link.symlink_to(shared_input_root, target_is_directory=True)
    dependency_root = promotion_root / "crates/fixture-dependency"
    dependency_root.mkdir(parents=True)
    (dependency_root / "Cargo.toml").write_text(
        (
            "[package]\n"
            "name = \"fixture-dependency\"\n"
            "version = \"0.0.0\"\n"
            "edition = \"2021\"\n"
            "\n"
            "[dev-dependencies]\n"
            "fixture-evidence = { path = \"../core/chio-adversarial-suite\" }\n"
        ),
        encoding="utf-8",
    )
    dependency_source = dependency_root / "src/lib.rs"
    dependency_source.parent.mkdir()
    dependency_source.write_text(
        "pub fn transitive_input() -> bool { true }\n", encoding="utf-8"
    )
    test_helper_root = promotion_root / "crates/fixture-test-helper"
    test_helper_root.mkdir(parents=True)
    (test_helper_root / "Cargo.toml").write_text(
        (
            "[package]\n"
            "name = \"fixture-test-helper\"\n"
            "version = \"0.0.0\"\n"
            "edition = \"2021\"\n"
        ),
        encoding="utf-8",
    )
    test_helper_source = test_helper_root / "src/lib.rs"
    test_helper_source.parent.mkdir()
    test_helper_source.write_text(
        "pub fn root_dev_input() -> bool { true }\n", encoding="utf-8"
    )
    promotion_case = json.loads(temporal.read_text(encoding="utf-8"))
    promotion_case["pending"] = True
    promotion_case["artifact"]["controls"][0].update(
        {
            "package": "fixture-package",
            "test_source": "crates/fixture-package/src/lib.rs",
            "test_name": "fixture_test",
        }
    )
    promotion_campaign = promotion_case["artifact"]["campaigns"][0]
    promotion_campaign.update(
        {
            "package": "fixture-package",
            "source": "crates/fixture-package/src/lib.rs",
            "function": "fixture_function",
            "minimum_caught": 1,
            "mutant": {
                "genre": "FnValue",
                "replacement": "false",
            },
        }
    )
    promotion_campaign["outcomes"].pop("sha256", None)
    promotion_campaign["outcomes"].pop("inputs_sha256", None)
    promotion_case_path = promotion_root / (
        "crates/core/chio-adversarial-suite/cases/temporal_evasion/"
        "temporal-evasion-001.json"
    )
    evidence_package_root = promotion_case_path.parents[2]
    evidence_package_root.mkdir(parents=True, exist_ok=True)
    (evidence_package_root / "Cargo.toml").write_text(
        (
            "[package]\n"
            "name = \"fixture-evidence\"\n"
            "version = \"0.0.0\"\n"
            "edition = \"2021\"\n"
        ),
        encoding="utf-8",
    )
    evidence_source = evidence_package_root / "src/lib.rs"
    evidence_source.parent.mkdir()
    evidence_source.write_text(
        "pub fn evidence_fixture() -> bool { true }\n", encoding="utf-8"
    )
    write_json(promotion_case_path, promotion_case)
    manifest_path = promotion_root / "crates/core/chio-adversarial-suite/manifest.json"
    write_json(
        manifest_path,
        {
            "schema_version": 1,
            "producer": "chio-adversarial-suite",
            "case_count": 0,
            "cases": [],
        },
    )
    fixture_mutant = {
        "package": "fixture-package",
        "file": "crates/fixture-package/src/lib.rs",
        "function": {
            "function_name": "fixture_function",
            "return_type": "-> bool",
            "span": {
                "start": {"line": 1, "column": 1},
                "end": {"line": 1, "column": 39},
            },
        },
        "span": {
            "start": {"line": 1, "column": 33},
            "end": {"line": 1, "column": 37},
        },
        "replacement": "false",
        "genre": "FnValue",
    }
    promotion_outcome = {
        "caught": 1,
        "missed": 0,
        "timeout": 0,
        "unviable": 0,
        "success": 0,
        "total_mutants": 1,
        "outcomes": [
            {"scenario": "Baseline", "summary": "Success"},
            {
                "scenario": {"Mutant": fixture_mutant},
                "summary": "CaughtMutant",
            },
        ],
    }
    candidate_root = promotion_root / "candidate"
    candidate_path = candidate_root / "mutants.out/outcomes.json"
    write_json(candidate_path, promotion_outcome)
    candidate_bytes = candidate_path.read_bytes()
    _pending_cases, pending_index = checker.load_cases(
        promotion_root, promotion_case_path.parents[1], False, True
    )
    pending_record = pending_index["ingest_time_substitution"]
    pending_inputs = checker.campaign_input_snapshot(
        promotion_root,
        checker.package_roots(promotion_root),
        pending_record[1],
        pending_record[2],
        pending_record[0].path,
    )
    original_case_bytes = promotion_case_path.read_bytes()
    original_manifest_bytes = manifest_path.read_bytes()
    canonical_outcome = promotion_root / promotion_campaign["outcomes"]["path"]
    for label, expected_payload, expected_inputs, expected_error in (
        (
            "changed outcome",
            candidate_bytes + b" ",
            pending_inputs,
            "outcome changed after the promotion run",
        ),
        (
            "changed input closure",
            candidate_bytes,
            ("0" * 64, pending_inputs[1]),
            "source or control changed before promotion",
        ),
    ):
        try:
            checker.promote_outcome(
                promotion_root,
                checker.package_roots(promotion_root),
                pending_record,
                str(candidate_root),
                expected_outcome_payload=expected_payload,
                expected_inputs_snapshot=expected_inputs,
            )
        except checker.EvidenceError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"unexpected {label} promotion rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"promotion accepted {label}")
        if (
            canonical_outcome.exists()
            or promotion_case_path.read_bytes() != original_case_bytes
            or manifest_path.read_bytes() != original_manifest_bytes
            or checker.trusted_transaction_exists(promotion_root)
        ):
            raise AssertionError(f"failed {label} promotion changed repository state")

    bootstrap_root = temp / "pending-bootstrap-root"
    shutil.copytree(promotion_root, bootstrap_root)
    bootstrap_case_path = bootstrap_root / promotion_case_path.relative_to(promotion_root)
    _bootstrap_cases, bootstrap_index = checker.load_cases(
        bootstrap_root, bootstrap_case_path.parents[1], False, True
    )
    actual_run_campaign = checker.run_campaign

    def successful_pending_runner(
        _root: Path,
        _campaign: object,
        _control: object,
        output_root: Path,
        _environment: object,
    ) -> Path:
        outcome = output_root / "mutants.out/outcomes.json"
        write_json(outcome, promotion_outcome)
        return outcome

    checker.run_campaign = successful_pending_runner
    try:
        bootstrap_destination, bootstrap_digest, bootstrap_complete = (
            checker.promote_pending_outcome(
                bootstrap_root,
                checker.package_roots(bootstrap_root),
                bootstrap_index["ingest_time_substitution"],
                {},
            )
        )
    finally:
        checker.run_campaign = actual_run_campaign
    if (
        bootstrap_destination.read_bytes() != candidate_bytes
        or bootstrap_digest != hashlib.sha256(candidate_bytes).hexdigest()
        or bootstrap_complete is not True
        or json.loads(bootstrap_case_path.read_text(encoding="utf-8"))["pending"]
        is not False
    ):
        raise AssertionError("pending campaign bootstrap did not bind its fresh outcome")

    promoted = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
            "--promote-outcome",
            "ingest_time_substitution",
            str(candidate_root),
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if promoted.returncode != 0:
        raise AssertionError(promoted.stdout)
    if canonical_outcome.read_bytes() != candidate_bytes:
        raise AssertionError("promotion did not preserve the validated outcome bytes")
    promoted_case = json.loads(promotion_case_path.read_text(encoding="utf-8"))
    expected_outcome_digest = hashlib.sha256(candidate_bytes).hexdigest()
    if promoted_case["pending"] is not False:
        raise AssertionError("the fully evidenced case remained pending")
    if (
        promoted_case["artifact"]["campaigns"][0]["outcomes"].get("sha256")
        != expected_outcome_digest
    ):
        raise AssertionError("the promoted case did not bind the exact outcome digest")
    promoted_inputs_digest = promoted_case["artifact"]["campaigns"][0][
        "outcomes"
    ].get("inputs_sha256")
    if not isinstance(promoted_inputs_digest, str) or len(promoted_inputs_digest) != 64:
        raise AssertionError("the promoted case did not bind its exact execution inputs")
    promoted_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if promoted_manifest["case_count"] != 1 or len(promoted_manifest["cases"]) != 1:
        raise AssertionError("promotion did not add exactly one manifest entry")
    manifest_entry = promoted_manifest["cases"][0]
    if manifest_entry["id"] != promoted_case["id"]:
        raise AssertionError("promotion added the wrong manifest case")
    if manifest_entry["content_sha256"] != hashlib.sha256(
        promotion_case_path.read_bytes()
    ).hexdigest():
        raise AssertionError("manifest did not bind the promoted case bytes")

    stable_after_promotion = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if stable_after_promotion.returncode != 0:
        raise AssertionError(
            "promoted evidence recursively invalidated its own input binding: "
            f"{stable_after_promotion.stdout}"
        )

    original_shared_input = shared_input_source.read_text(encoding="utf-8")
    shared_input_source.write_text(
        original_shared_input + "// linked input drift\n", encoding="utf-8"
    )
    stale_linked_input = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(stale_linked_input, "stale mutation input binding")
    shared_input_source.write_text(original_shared_input, encoding="utf-8")

    escaped_input_root = temp / "escaped-fixture-inputs"
    escaped_input_root.mkdir()
    (escaped_input_root / "outside.rs").write_text(
        "pub fn outside() -> bool { true }\n", encoding="utf-8"
    )
    escaped_input_link = package_root / "tests/escaped"
    escaped_input_link.symlink_to(escaped_input_root, target_is_directory=True)
    escaped_link = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(escaped_link, "Cargo input symlink escaped the repository")
    escaped_input_link.unlink()

    original_dependency_source = dependency_source.read_text(encoding="utf-8")
    dependency_source.write_text(
        original_dependency_source + "// transitive source drift\n", encoding="utf-8"
    )
    stale_transitive_dependency = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(stale_transitive_dependency, "stale mutation input binding")
    dependency_source.write_text(original_dependency_source, encoding="utf-8")

    original_test_helper_source = test_helper_source.read_text(encoding="utf-8")
    test_helper_source.write_text(
        original_test_helper_source + "// root dev-dependency drift\n",
        encoding="utf-8",
    )
    stale_root_dev_dependency = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(stale_root_dev_dependency, "stale mutation input binding")
    test_helper_source.write_text(original_test_helper_source, encoding="utf-8")

    fixture_manifest = package_root / "Cargo.toml"
    original_fixture_manifest = fixture_manifest.read_text(encoding="utf-8")
    fixture_manifest.write_text(
        original_fixture_manifest
        + "fixture-evidence = { path = \"../core/chio-adversarial-suite\" }\n",
        encoding="utf-8",
    )
    recursive_evidence_input = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(
        recursive_evidence_input,
        "mutation evidence output entered its Cargo input closure",
    )
    fixture_manifest.write_text(original_fixture_manifest, encoding="utf-8")

    original_fixture_source = fixture_source.read_text(encoding="utf-8")
    fixture_source.write_text(original_fixture_source + "// source drift\n", encoding="utf-8")
    stale_source = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(stale_source, "stale mutation input binding")
    fixture_source.write_text(original_fixture_source, encoding="utf-8")

    original_promoted_case = json.loads(promotion_case_path.read_text(encoding="utf-8"))
    drifted_control = copy.deepcopy(original_promoted_case)
    drifted_control["artifact"]["controls"][0]["test_name"] = "fixture_test_changed"
    write_json(promotion_case_path, drifted_control)
    stale_control = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(stale_control, "stale mutation input binding")

    drifted_campaign = copy.deepcopy(original_promoted_case)
    drifted_campaign["artifact"]["campaigns"][0][
        "function"
    ] = "fixture_function_changed"
    write_json(promotion_case_path, drifted_campaign)
    stale_campaign = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(stale_campaign, "stale mutation input binding")
    write_json(promotion_case_path, original_promoted_case)

    repeated = subprocess.run(
        [
            str(gate),
            "--root",
            str(promotion_root),
            "--cases",
            str(promotion_case_path.parents[1]),
            "--fixture",
            "--promote-outcome",
            "ingest_time_substitution",
            str(candidate_root),
        ],
        cwd=promotion_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    expect_rejected(repeated, "already has a bound outcome digest")

    partial_root = temp / "partial-promotion-root"
    partial_root.mkdir()
    shutil.copy2(promotion_root / "Cargo.toml", partial_root / "Cargo.toml")
    shutil.copy2(promotion_root / "Cargo.lock", partial_root / "Cargo.lock")
    for package_name in (
        "fixture-package",
        "fixture-dependency",
        "fixture-test-helper",
    ):
        shutil.copytree(
            promotion_root / f"crates/{package_name}",
            partial_root / f"crates/{package_name}",
        )
    partial_evidence_root = partial_root / "crates/core/chio-adversarial-suite"
    partial_evidence_root.mkdir(parents=True)
    shutil.copy2(
        evidence_package_root / "Cargo.toml",
        partial_evidence_root / "Cargo.toml",
    )
    shutil.copytree(evidence_package_root / "src", partial_evidence_root / "src")
    partial_case = copy.deepcopy(promotion_case)
    partial_case.update(
        {
            "id": "sandbox-fd-or-env-leak-001",
            "class": "sandbox_fd_or_env_leak",
            "expected_reason": "sandbox_fd_or_env_leak_detected",
        }
    )
    partial_campaigns = []
    for campaign_id in ("sandbox_fd_leak", "sandbox_env_leak"):
        campaign = copy.deepcopy(promotion_campaign)
        campaign["id"] = campaign_id
        campaign["outcomes"] = {
            "path": (
                f"audits/evidence/mutants/security/{campaign_id}/"
                "mutants.out/outcomes.json"
            )
        }
        partial_campaigns.append(campaign)
    partial_case["artifact"]["campaigns"] = partial_campaigns
    partial_case_path = partial_root / (
        "crates/core/chio-adversarial-suite/cases/sandbox_fd_or_env_leak/"
        "sandbox-fd-or-env-leak-001.json"
    )
    write_json(partial_case_path, partial_case)
    partial_manifest_path = partial_root / "crates/core/chio-adversarial-suite/manifest.json"
    write_json(
        partial_manifest_path,
        {
            "schema_version": 1,
            "producer": "chio-adversarial-suite",
            "case_count": 0,
            "cases": [],
        },
    )
    for index, campaign_id in enumerate(("sandbox_fd_leak", "sandbox_env_leak")):
        result = subprocess.run(
            [
                str(gate),
                "--root",
                str(partial_root),
                "--cases",
                str(partial_case_path.parents[1]),
                "--fixture",
                "--promote-outcome",
                campaign_id,
                str(candidate_root),
            ],
            cwd=partial_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(result.stdout)
        observed_case = json.loads(partial_case_path.read_text(encoding="utf-8"))
        observed_manifest = json.loads(partial_manifest_path.read_text(encoding="utf-8"))
        if index == 0:
            if observed_case["pending"] is not True or observed_manifest["case_count"] != 0:
                raise AssertionError("partial campaign promotion became coverage-eligible")
        elif observed_case["pending"] is not False or observed_manifest["case_count"] != 1:
            raise AssertionError("final campaign promotion did not complete the case")

    if checker.safe_rust_path(
        "crates/fixture-package/src/generated_fragment.inc",
        "valid included Rust fragment",
    ) != "crates/fixture-package/src/generated_fragment.inc":
        raise AssertionError("repository-owned Rust include path was not preserved")
    for unsafe_rust_path in (
        "crates/fixture-package/src/generated_fragment.toml",
        "crates/fixture-package/src/generated_fragment.inc.txt",
        "crates/fixture-package/src/../generated_fragment.inc",
        "crates/fixture-package/src/generated_fragment.rs\ninjected.rs",
        "/crates/fixture-package/src/generated_fragment.inc",
    ):
        try:
            checker.safe_rust_path(unsafe_rust_path, "unsafe Rust fragment")
        except checker.EvidenceError:
            pass
        else:
            raise AssertionError(f"unsafe Rust path passed: {unsafe_rust_path}")

    source_validation_packages = checker.package_roots(promotion_root)
    source_validation_control = checker.validate_control(
        promotion_root,
        source_validation_packages,
        promotion_case["artifact"]["controls"][0],
        promotion_case["id"],
    )
    source_validation_controls = {
        source_validation_control["id"]: source_validation_control
    }

    trusted_tool = Path("/usr/local/cargo/bin/cargo-mutants")
    if (
        checker.TRUSTED_CARGO_MUTANTS != trusted_tool
        or checker.TRUSTED_CARGO_MUTANTS_ANCESTORS
        != (
            Path("/"),
            Path("/usr"),
            Path("/usr/local"),
            Path("/usr/local/cargo"),
            Path("/usr/local/cargo/bin"),
        )
    ):
        raise AssertionError("cargo-mutants executable authority is not fixed")

    def synthetic_metadata(
        kind: int,
        mode: int,
        *,
        inode: int = 1,
        links: int = 1,
        uid: int = 0,
        gid: int = 0,
    ) -> os.stat_result:
        return os.stat_result(
            (kind | mode, inode, 1, links, uid, gid, 0, 0, 0, 0)
        )

    trusted_ancestor = synthetic_metadata(stat.S_IFDIR, 0o755, links=2)
    trusted_executable = synthetic_metadata(stat.S_IFREG, 0o555)
    checker.require_trusted_cargo_mutants_ancestor(
        trusted_ancestor, Path("/usr/local/cargo/bin")
    )
    checker.require_trusted_cargo_mutants_file(
        trusted_executable, trusted_tool
    )
    trusted_host_executable = synthetic_metadata(stat.S_IFREG, 0o755)
    checker.require_host_cargo_mutants_file(
        trusted_host_executable, Path("/trusted-host/cargo-mutants")
    )
    for hostile_ancestor in (
        synthetic_metadata(stat.S_IFLNK, 0o755),
        synthetic_metadata(stat.S_IFDIR, 0o775, links=2),
        synthetic_metadata(stat.S_IFDIR, 0o755, links=2, uid=65532),
        synthetic_metadata(stat.S_IFDIR, 0o755, links=2, gid=65532),
    ):
        try:
            checker.require_trusted_cargo_mutants_ancestor(
                hostile_ancestor, Path("/usr/local/cargo/bin")
            )
        except checker.EvidenceError:
            pass
        else:
            raise AssertionError("mutable cargo-mutants ancestor was accepted")
    for hostile_executable in (
        synthetic_metadata(stat.S_IFLNK, 0o555),
        synthetic_metadata(stat.S_IFDIR, 0o555, links=2),
        synthetic_metadata(stat.S_IFREG, 0o755),
        synthetic_metadata(stat.S_IFREG, 0o555, links=2),
        synthetic_metadata(stat.S_IFREG, 0o555, uid=65532),
        synthetic_metadata(stat.S_IFREG, 0o555, gid=65532),
    ):
        try:
            checker.require_trusted_cargo_mutants_file(
                hostile_executable, trusted_tool
            )
        except checker.EvidenceError:
            pass
        else:
            raise AssertionError("mutable cargo-mutants executable was accepted")
    for hostile_host_executable in (
        synthetic_metadata(stat.S_IFLNK, 0o755),
        synthetic_metadata(stat.S_IFDIR, 0o755, links=2),
        synthetic_metadata(stat.S_IFREG, 0o644),
        synthetic_metadata(stat.S_IFREG, 0o755, links=2),
    ):
        try:
            checker.require_host_cargo_mutants_file(
                hostile_host_executable, Path("/trusted-host/cargo-mutants")
            )
        except checker.EvidenceError:
            pass
        else:
            raise AssertionError("unsafe host cargo-mutants executable was accepted")
    try:
        checker.require_unchanged_cargo_mutants_identity(
            trusted_executable,
            synthetic_metadata(stat.S_IFREG, 0o555, inode=2),
            trusted_tool,
        )
    except checker.EvidenceError:
        pass
    else:
        raise AssertionError("replaced cargo-mutants executable was accepted")
    try:
        checker.require_unchanged_cargo_mutants_identity(
            trusted_ancestor,
            synthetic_metadata(stat.S_IFDIR, 0o755, inode=2, links=2),
            Path("/usr/local/cargo/bin"),
        )
    except checker.EvidenceError:
        pass
    else:
        raise AssertionError("replaced cargo-mutants ancestor was accepted")

    trusted_tool_metadata = {
        path: trusted_ancestor
        for path in checker.TRUSTED_CARGO_MUTANTS_ANCESTORS
    }
    trusted_tool_metadata[trusted_tool] = trusted_executable
    trusted_tool_lstats: list[Path] = []
    actual_path_lstat = checker.Path.lstat
    actual_path_resolve = checker.Path.resolve

    def trusted_lstat(path: Path) -> os.stat_result:
        trusted_tool_lstats.append(path)
        return trusted_tool_metadata[path]

    def identity_resolve(path: Path, strict: bool = False) -> Path:
        _ = strict
        return path

    checker.Path.lstat = trusted_lstat
    checker.Path.resolve = identity_resolve
    actual_which = checker.shutil.which

    def forbidden_host_lookup(_name: str) -> str | None:
        raise AssertionError("enterprise cargo-mutants fell back to PATH")

    checker.shutil.which = forbidden_host_lookup
    try:
        authenticated_inventory = checker.CargoMutantsSourceInventory()
        if (
            checker.cargo_mutants_executable(
                promotion_root,
                authenticated_inventory,
                {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"},
            )
            != trusted_tool
            or authenticated_inventory.executable != trusted_tool
        ):
            raise AssertionError("fixed cargo-mutants executable was not retained")
    finally:
        checker.Path.lstat = actual_path_lstat
        checker.Path.resolve = actual_path_resolve
        checker.shutil.which = actual_which
    expected_tool_lstats = [
        *checker.TRUSTED_CARGO_MUTANTS_ANCESTORS,
        trusted_tool,
        *checker.TRUSTED_CARGO_MUTANTS_ANCESTORS,
        trusted_tool,
    ]
    if trusted_tool_lstats != expected_tool_lstats:
        raise AssertionError(
            f"cargo-mutants authority chain was not authenticated twice: "
            f"{trusted_tool_lstats}"
        )
    for replaced_path in (checker.TRUSTED_CARGO_MUTANTS_ANCESTORS[-1], trusted_tool):
        replacement_reads: dict[Path, int] = {}

        def replaced_identity_lstat(path: Path) -> os.stat_result:
            replacement_reads[path] = replacement_reads.get(path, 0) + 1
            original = trusted_tool_metadata[path]
            if path == replaced_path and replacement_reads[path] == 2:
                return synthetic_metadata(
                    stat.S_IFREG if path == trusted_tool else stat.S_IFDIR,
                    0o555 if path == trusted_tool else 0o755,
                    inode=2,
                    links=1 if path == trusted_tool else 2,
                )
            return original

        checker.Path.lstat = replaced_identity_lstat
        checker.Path.resolve = identity_resolve
        checker.shutil.which = forbidden_host_lookup
        try:
            checker.cargo_mutants_executable(
                promotion_root,
                checker.CargoMutantsSourceInventory(),
                {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"},
            )
        except checker.EvidenceError as error:
            if "identity changed" not in str(error):
                raise AssertionError(
                    f"unexpected cargo-mutants replacement rejection: {error}"
                ) from error
        else:
            raise AssertionError(
                f"replaced cargo-mutants authority passed: {replaced_path}"
            )
        finally:
            checker.Path.lstat = actual_path_lstat
            checker.Path.resolve = actual_path_resolve
            checker.shutil.which = actual_which

    actual_enterprise_cargo_mutants_executable = (
        checker.enterprise_cargo_mutants_executable
    )
    actual_os_open = checker.os.open
    actual_os_fstat = checker.os.fstat
    actual_os_close = checker.os.close
    actual_path_lstat = checker.Path.lstat
    pinned_authentications: list[Path] = []
    pinned_closes: list[int] = []

    def pinned_enterprise_executable(_root: Path) -> Path:
        pinned_authentications.append(trusted_tool)
        return trusted_tool

    def pinned_open(path: Path, flags: int) -> int:
        if path != trusted_tool or flags & getattr(checker.os, "O_NOFOLLOW", 0) == 0:
            raise AssertionError("cargo-mutants descriptor open was not exact")
        return 97

    checker.enterprise_cargo_mutants_executable = pinned_enterprise_executable
    checker.os.open = pinned_open
    checker.os.fstat = lambda descriptor: (
        trusted_executable
        if descriptor == 97
        else (_ for _ in ()).throw(AssertionError("unexpected descriptor"))
    )
    checker.os.close = lambda descriptor: pinned_closes.append(descriptor)
    checker.Path.lstat = lambda path: trusted_tool_metadata[path]
    try:
        with checker.cargo_mutants_subprocess_options(
            promotion_root,
            [str(trusted_tool), "mutants", "--version"],
            {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"},
            checker.metadata_identity(trusted_executable),
        ) as (execution_options, observed_identity):
            if execution_options != {
                "executable": "/proc/self/fd/97",
                "pass_fds": (97,),
            } or observed_identity != checker.metadata_identity(trusted_executable):
                raise AssertionError(
                    f"cargo-mutants execution was not descriptor-pinned: "
                    f"{execution_options}, {observed_identity}"
                )
        if (
            pinned_authentications != [trusted_tool, trusted_tool, trusted_tool]
            or pinned_closes != [97]
        ):
            raise AssertionError("descriptor-pinned cargo-mutants was not reauthenticated")

        pinned_authentications.clear()
        pinned_closes.clear()
        replacement_executable = synthetic_metadata(
            stat.S_IFREG, 0o555, inode=2
        )
        checker.os.fstat = lambda descriptor: (
            replacement_executable
            if descriptor == 97
            else (_ for _ in ()).throw(AssertionError("unexpected descriptor"))
        )
        checker.Path.lstat = lambda path: (
            replacement_executable
            if path == trusted_tool
            else (_ for _ in ()).throw(AssertionError(f"unexpected path: {path}"))
        )
        try:
            with checker.cargo_mutants_subprocess_options(
                promotion_root,
                [str(trusted_tool), "mutants", "--list-files", "--json"],
                {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"},
                checker.metadata_identity(trusted_executable),
            ):
                pass
        except checker.EvidenceError as error:
            if "differs from the version-verified inode" not in str(error):
                raise AssertionError(
                    f"unexpected cross-command inode rejection: {error}"
                ) from error
        else:
            raise AssertionError("post-version cargo-mutants replacement was accepted")
        if pinned_closes != [97]:
            raise AssertionError("post-version replacement descriptor was not closed")

        pinned_authentications.clear()
        pinned_closes.clear()
        checker.os.fstat = lambda descriptor: (
            trusted_executable
            if descriptor == 97
            else (_ for _ in ()).throw(AssertionError("unexpected descriptor"))
        )
        named_reads = [0]

        def replaced_named_executable(path: Path) -> os.stat_result:
            if path != trusted_tool:
                raise AssertionError(f"unexpected named executable: {path}")
            named_reads[0] += 1
            if named_reads[0] == 2:
                return synthetic_metadata(stat.S_IFREG, 0o555, inode=2)
            return trusted_executable

        checker.Path.lstat = replaced_named_executable
        try:
            with checker.cargo_mutants_subprocess_options(
                promotion_root,
                [str(trusted_tool), "mutants", "--version"],
                {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"},
                checker.metadata_identity(trusted_executable),
            ):
                pass
        except checker.EvidenceError as error:
            if "identity changed" not in str(error):
                raise AssertionError(
                    f"unexpected pinned executable replacement rejection: {error}"
                ) from error
        else:
            raise AssertionError("named cargo-mutants replacement after exec was accepted")
        if pinned_closes != [97]:
            raise AssertionError("replaced cargo-mutants descriptor was not closed")
    finally:
        checker.enterprise_cargo_mutants_executable = (
            actual_enterprise_cargo_mutants_executable
        )
        checker.os.open = actual_os_open
        checker.os.fstat = actual_os_fstat
        checker.os.close = actual_os_close
        checker.Path.lstat = actual_path_lstat

    host_tool = temp / "host-cargo-bin/cargo-mutants"
    host_tool.parent.mkdir()
    host_tool.write_text("host cargo-mutants fixture\n", encoding="utf-8")
    host_tool.chmod(0o755)
    workspace_tool = promotion_root / "cargo-mutants"
    workspace_tool.write_text("workspace cargo-mutants fixture\n", encoding="utf-8")
    workspace_tool.chmod(0o755)
    checker.shutil.which = lambda _name: str(workspace_tool)
    try:
        checker.cargo_mutants_executable(
            promotion_root, checker.CargoMutantsSourceInventory(), {}
        )
    except checker.EvidenceError as error:
        if "cannot be workspace-owned" not in str(error):
            raise AssertionError(
                f"unexpected workspace cargo-mutants rejection: {error}"
            ) from error
    else:
        raise AssertionError("workspace-owned host cargo-mutants was accepted")
    checker.shutil.which = lambda _name: str(host_tool)

    inventory_commands: list[list[str]] = []
    inventory_version = [checker.PINNED_CARGO_MUTANTS_VERSION]
    inventory_paths = ["crates/fixture-package/src/lib.rs"]
    inventory_package = ["fixture-package"]
    inventory_payload_override: list[str | None] = [None]
    inventory_enterprise_identities: list[tuple[int, int]] = []
    actual_subprocess_run = checker.subprocess.run
    actual_cargo_mutants_subprocess_options = (
        checker.cargo_mutants_subprocess_options
    )
    actual_enterprise_cargo_mutants_executable = (
        checker.enterprise_cargo_mutants_executable
    )
    inventory_enterprise_authentications: list[Path] = []

    def inventory_enterprise_executable(_root: Path) -> Path:
        inventory_enterprise_authentications.append(trusted_tool)
        return trusted_tool

    @checker.contextmanager
    def inventory_execution_options(
        _root: Path,
        command: list[str],
        environment: dict[str, str] | None,
        expected_identity: tuple[int, int] | None = None,
    ) -> object:
        if checker.enterprise_security_runner(environment):
            if command[:2] != [str(trusted_tool), "mutants"]:
                raise AssertionError(
                    f"enterprise inventory bypassed trusted executable: {command}"
                )
            observed_identity = (
                inventory_enterprise_identities.pop(0)
                if inventory_enterprise_identities
                else (1, 1)
            )
            if (
                expected_identity is not None
                and expected_identity != observed_identity
            ):
                raise checker.EvidenceError(
                    "cargo-mutants differs from the version-verified inode"
                )
            yield (
                {
                    "executable": "/proc/self/fd/97",
                    "pass_fds": (97,),
                },
                observed_identity,
            )
        else:
            if expected_identity is not None:
                raise AssertionError("host inventory received an enterprise identity")
            yield {}, None

    def fake_cargo_mutants(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        inventory_commands.append(list(command))
        if kwargs.get("cwd") != promotion_root:
            raise AssertionError("cargo-mutants inventory used the wrong workspace")
        if command[0] == str(trusted_tool):
            if (
                kwargs.get("executable") != "/proc/self/fd/97"
                or kwargs.get("pass_fds") != (97,)
            ):
                raise AssertionError(
                    "enterprise inventory command was not descriptor-pinned"
                )
        elif "executable" in kwargs or "pass_fds" in kwargs:
            raise AssertionError("host inventory unexpectedly used verifier execution")
        if command in (
            [str(host_tool), "mutants", "--version"],
            [str(trusted_tool), "mutants", "--version"],
        ):
            stdout = inventory_version[0] + "\n"
        elif command[:2] in (
            [str(host_tool), "mutants"],
            [str(trusted_tool), "mutants"],
        ) and command[2:] == [
            "--no-config",
            "-p",
            "fixture-package",
            "--list-files",
            "--json",
        ]:
            stdout = inventory_payload_override[0] or (
                json.dumps(
                    [
                        {"path": path, "package": inventory_package[0]}
                        for path in inventory_paths
                    ]
                )
                + "\n"
            )
        else:
            raise AssertionError(f"unexpected cargo-mutants command: {command}")
        return subprocess.CompletedProcess(command, 0, stdout, "")

    checker.cargo_mutants_subprocess_options = inventory_execution_options
    checker.enterprise_cargo_mutants_executable = inventory_enterprise_executable
    checker.subprocess.run = fake_cargo_mutants
    try:
        if checker.require_cargo_mutants_version(
            host_tool, promotion_root, {}
        ) is not None:
            raise AssertionError("host cargo-mutants version acquired enterprise identity")
        enterprise_environment = {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"}
        if checker.require_cargo_mutants_version(
            trusted_tool, promotion_root, enterprise_environment
        ) != (1, 1):
            raise AssertionError("enterprise cargo-mutants version lost its inode")
        if inventory_commands != [
            [str(host_tool), "mutants", "--version"],
            [str(trusted_tool), "mutants", "--version"],
        ]:
            raise AssertionError(
                f"cargo-mutants version return-shape probe drifted: "
                f"{inventory_commands}"
            )
        inventory_commands.clear()

        command_inventory = checker.CargoMutantsSourceInventory()
        first_inventory = checker.cargo_mutants_source_inventory(
            promotion_root,
            source_validation_packages["fixture-package"],
            "fixture-package",
            command_inventory,
        )
        second_inventory = checker.cargo_mutants_source_inventory(
            promotion_root,
            source_validation_packages["fixture-package"],
            "fixture-package",
            command_inventory,
        )
        if (
            first_inventory != frozenset(inventory_paths)
            or second_inventory is not first_inventory
            or command_inventory.executable != host_tool
            or inventory_commands
            != [
                [str(host_tool), "mutants", "--version"],
                [
                    str(host_tool),
                    "mutants",
                    "--no-config",
                    "-p",
                    "fixture-package",
                    "--list-files",
                    "--json",
                ],
            ]
        ):
            raise AssertionError("cargo-mutants source inventory was not exact and cached")

        inventory_commands.clear()
        enterprise_inventory = checker.CargoMutantsSourceInventory(
            executable=trusted_tool
        )
        enterprise_sources = checker.cargo_mutants_source_inventory(
            promotion_root,
            source_validation_packages["fixture-package"],
            "fixture-package",
            enterprise_inventory,
            enterprise_environment,
        )
        if (
            enterprise_sources != frozenset(inventory_paths)
            or enterprise_inventory.verified_identity != (1, 1)
            or inventory_commands
            != [
                [str(trusted_tool), "mutants", "--version"],
                [
                    str(trusted_tool),
                    "mutants",
                    "--no-config",
                    "-p",
                    "fixture-package",
                    "--list-files",
                    "--json",
                ],
            ]
        ):
            raise AssertionError(
                "enterprise source inventory bypassed the fixed cargo-mutants"
            )

        try:
            checker.cargo_mutants_executable(
                promotion_root,
                checker.CargoMutantsSourceInventory(executable=host_tool),
                enterprise_environment,
            )
        except checker.EvidenceError:
            pass
        else:
            raise AssertionError("enterprise accepted a PATH-resolved cargo-mutants")
        if inventory_enterprise_authentications != [trusted_tool, trusted_tool]:
            raise AssertionError(
                "enterprise cached cargo-mutants paths were not reauthenticated"
            )

        inventory_enterprise_identities[:] = [(1, 1), (1, 2)]
        inventory_commands.clear()
        try:
            checker.cargo_mutants_source_inventory(
                promotion_root,
                source_validation_packages["fixture-package"],
                "fixture-package",
                checker.CargoMutantsSourceInventory(executable=trusted_tool),
                enterprise_environment,
            )
        except checker.EvidenceError as error:
            if "differs from the version-verified inode" not in str(error):
                raise AssertionError(
                    f"unexpected cross-command inventory rejection: {error}"
                ) from error
        else:
            raise AssertionError(
                "cargo-mutants replacement between version and inventory was accepted"
            )
        if inventory_commands != [
            [str(trusted_tool), "mutants", "--version"]
        ]:
            raise AssertionError(
                "replacement inventory executed after its inode binding changed"
            )

        inventory_commands.clear()
        inventory_version[0] = "cargo-mutants 25.3.2"
        try:
            checker.cargo_mutants_source_inventory(
                promotion_root,
                source_validation_packages["fixture-package"],
                "fixture-package",
                checker.CargoMutantsSourceInventory(),
            )
        except checker.EvidenceError as error:
            if "cargo-mutants version mismatch" not in str(error):
                raise AssertionError(
                    f"unexpected cargo-mutants version rejection: {error}"
                ) from error
        else:
            raise AssertionError("unpinned cargo-mutants version was accepted")

        inventory_paths[:] = [
            "crates/fixture-package/src/../src/lib.rs"
        ]
        try:
            checker.cargo_mutants_source_inventory(
                promotion_root,
                source_validation_packages["fixture-package"],
                "fixture-package",
                checker.CargoMutantsSourceInventory(
                    executable=host_tool, version_checked=True
                ),
            )
        except checker.EvidenceError as error:
            if "invalid repository-relative path" not in str(error):
                raise AssertionError(
                    f"unexpected noncanonical inventory rejection: {error}"
                ) from error
        else:
            raise AssertionError("noncanonical cargo-mutants source path was accepted")

        inventory_paths[:] = [
            "crates/fixture-package/src/cover.rs\n"
            "crates/fixture-package/src/injected.rs"
        ]
        inventory_commands.clear()
        try:
            checker.cargo_mutants_source_inventory(
                promotion_root,
                source_validation_packages["fixture-package"],
                "fixture-package",
                checker.CargoMutantsSourceInventory(
                    executable=host_tool, version_checked=True
                ),
            )
        except checker.EvidenceError as error:
            if "unsafe Rust path" not in str(error):
                raise AssertionError(
                    f"unexpected newline inventory rejection: {error}"
                ) from error
        else:
            raise AssertionError(
                "JSON-escaped symlink/newline cargo-mutants inventory was accepted"
            )

        inventory_paths[:] = ["crates/fixture-package/src/lib.rs"]
        inventory_package[0] = "different-package"
        try:
            checker.cargo_mutants_source_inventory(
                promotion_root,
                source_validation_packages["fixture-package"],
                "fixture-package",
                checker.CargoMutantsSourceInventory(
                    executable=host_tool, version_checked=True
                ),
            )
        except checker.EvidenceError as error:
            if "package binding differs" not in str(error):
                raise AssertionError(
                    f"unexpected inventory package rejection: {error}"
                ) from error
        else:
            raise AssertionError("cross-package JSON source inventory was accepted")

        inventory_package[0] = "fixture-package"
        inventory_payload_override[0] = (
            '[{"path":"crates/fixture-package/src/lib.rs",'
            '"package":"fixture-package","extra":true}]\n'
        )
        try:
            checker.cargo_mutants_source_inventory(
                promotion_root,
                source_validation_packages["fixture-package"],
                "fixture-package",
                checker.CargoMutantsSourceInventory(
                    executable=host_tool, version_checked=True
                ),
            )
        except checker.EvidenceError as error:
            if "field mismatch" not in str(error):
                raise AssertionError(
                    f"unexpected inventory schema rejection: {error}"
                ) from error
        else:
            raise AssertionError("extended JSON source inventory schema was accepted")
        inventory_payload_override[0] = None
    finally:
        checker.subprocess.run = actual_subprocess_run
        checker.shutil.which = actual_which
        checker.cargo_mutants_subprocess_options = (
            actual_cargo_mutants_subprocess_options
        )
        checker.enterprise_cargo_mutants_executable = (
            actual_enterprise_cargo_mutants_executable
        )

    for artifact_environment, expected_error in (
        (
            {"CHIO_SECURITY_CANDIDATE_ARTIFACTS": "/target/artifacts"},
            "candidate artifact authority is forbidden",
        ),
        (
            {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"},
            "verifier artifact authority is absent",
        ),
        (
            {"CHIO_SECURITY_VERIFIER_ARTIFACTS": "/target/verifier"},
            "only valid in the enterprise boundary",
        ),
        (
            {
                "CHIO_ENTERPRISE_SECURITY_RUNNER": "1",
                "CHIO_SECURITY_VERIFIER_ARTIFACTS": "/target/artifacts",
            },
            "escaped its state root",
        ),
        (
            {
                "CHIO_ENTERPRISE_SECURITY_RUNNER": "1",
                "CHIO_SECURITY_VERIFIER_ARTIFACTS": (
                    "/baseline/candidate-state/not-a-token/verifier/artifacts"
                ),
            },
            "is not exact",
        ),
    ):
        try:
            checker.verifier_artifact_root(artifact_environment)
        except checker.EvidenceError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"unexpected artifact-authority rejection: {error}"
                ) from error
        else:
            raise AssertionError(
                f"unsafe artifact authority passed: {artifact_environment}"
            )

    trusted_artifact_directory = synthetic_metadata(
        stat.S_IFDIR,
        0o700,
        links=2,
        uid=checker.ENTERPRISE_VERIFIER_UID,
        gid=checker.ENTERPRISE_VERIFIER_GID,
    )
    checker.require_directory_authority(
        trusted_artifact_directory,
        Path("/baseline/candidate-state/token/verifier/artifacts"),
        uid=checker.ENTERPRISE_VERIFIER_UID,
        gid=checker.ENTERPRISE_VERIFIER_GID,
        mode=0o700,
    )
    if checker.ENTERPRISE_BASELINE_MODE != 0o555:
        raise AssertionError("frozen baseline authority mode is not exact")
    for hostile_artifact_directory in (
        synthetic_metadata(
            stat.S_IFLNK,
            0o700,
            uid=checker.ENTERPRISE_VERIFIER_UID,
            gid=checker.ENTERPRISE_VERIFIER_GID,
        ),
        synthetic_metadata(
            stat.S_IFDIR,
            0o770,
            links=2,
            uid=checker.ENTERPRISE_VERIFIER_UID,
            gid=checker.ENTERPRISE_VERIFIER_GID,
        ),
        synthetic_metadata(
            stat.S_IFDIR,
            0o700,
            links=2,
            uid=65532,
            gid=65532,
        ),
    ):
        try:
            checker.require_directory_authority(
                hostile_artifact_directory,
                Path("/baseline/candidate-state/token/verifier/artifacts"),
                uid=checker.ENTERPRISE_VERIFIER_UID,
                gid=checker.ENTERPRISE_VERIFIER_GID,
                mode=0o700,
            )
        except checker.EvidenceError:
            pass
        else:
            raise AssertionError("candidate-writable artifact authority was accepted")

    artifact_token = "a" * 64
    artifact_authority = Path(
        f"/baseline/candidate-state/{artifact_token}/verifier/artifacts"
    )
    artifact_verifier_root = artifact_authority.parent
    artifact_gate_root = artifact_verifier_root.parent
    artifact_metadata = {
        Path("/baseline"): synthetic_metadata(stat.S_IFDIR, 0o555, links=2),
        checker.ENTERPRISE_STATE_ROOT: synthetic_metadata(
            stat.S_IFDIR, 0o711, links=2
        ),
        artifact_gate_root: synthetic_metadata(stat.S_IFDIR, 0o711, links=2),
        artifact_verifier_root: synthetic_metadata(
            stat.S_IFDIR,
            0o770,
            links=2,
            gid=checker.ENTERPRISE_VERIFIER_GID,
        ),
        artifact_authority: trusted_artifact_directory,
    }
    actual_path_lstat = checker.Path.lstat
    actual_path_resolve = checker.Path.resolve
    artifact_lstats: list[Path] = []

    def artifact_lstat(path: Path) -> os.stat_result:
        artifact_lstats.append(path)
        return artifact_metadata[path]

    checker.Path.lstat = artifact_lstat
    checker.Path.resolve = identity_resolve
    artifact_environment = {
        "CHIO_ENTERPRISE_SECURITY_RUNNER": "1",
        "CHIO_SECURITY_VERIFIER_ARTIFACTS": str(artifact_authority),
    }
    try:
        if checker.verifier_artifact_root(artifact_environment) != artifact_authority:
            raise AssertionError("verifier artifact authority was not authenticated")
        if artifact_lstats != [*artifact_metadata, *artifact_metadata]:
            raise AssertionError(
                f"verifier artifact authority was not authenticated twice: "
                f"{artifact_lstats}"
            )

        artifact_identity_reads: dict[Path, int] = {}

        def replaced_artifact_lstat(path: Path) -> os.stat_result:
            artifact_identity_reads[path] = artifact_identity_reads.get(path, 0) + 1
            if path == artifact_authority and artifact_identity_reads[path] == 2:
                return synthetic_metadata(
                    stat.S_IFDIR,
                    0o700,
                    inode=2,
                    links=2,
                    uid=checker.ENTERPRISE_VERIFIER_UID,
                    gid=checker.ENTERPRISE_VERIFIER_GID,
                )
            return artifact_metadata[path]

        checker.Path.lstat = replaced_artifact_lstat
        try:
            checker.verifier_artifact_root(artifact_environment)
        except checker.EvidenceError as error:
            if "authority changed" not in str(error):
                raise AssertionError(
                    f"unexpected verifier artifact replacement rejection: {error}"
                ) from error
        else:
            raise AssertionError("replaced verifier artifact authority was accepted")

        checker.Path.lstat = artifact_lstat
        artifact_metadata[Path("/baseline")] = synthetic_metadata(
            stat.S_IFDIR, 0o755, links=2
        )
        try:
            checker.verifier_artifact_root(artifact_environment)
        except checker.EvidenceError:
            pass
        else:
            raise AssertionError("mutable baseline authority was accepted")
    finally:
        checker.Path.lstat = actual_path_lstat
        checker.Path.resolve = actual_path_resolve

    verifier_output_authority = temp / "verifier-output-authority"
    verifier_output_authority.mkdir()
    actual_verifier_artifact_root = checker.verifier_artifact_root
    checker.verifier_artifact_root = lambda _environment: verifier_output_authority
    try:
        allowed_output = verifier_output_authority / "campaign"
        if checker.validate_mutation_output_root(allowed_output, {}) != (
            verifier_output_authority
        ):
            raise AssertionError("verifier mutation output authority was not retained")
        for rejected_output in (
            verifier_output_authority,
            temp / "escaped-verifier-output",
            Path("relative-verifier-output"),
        ):
            try:
                checker.validate_mutation_output_root(rejected_output, {})
            except checker.EvidenceError:
                pass
            else:
                raise AssertionError(
                    f"unsafe verifier mutation output passed: {rejected_output}"
                )
        with checker.mutation_output_workspace({}, "fixture-output") as output:
            if output.parent != verifier_output_authority or output.exists():
                raise AssertionError("mutation workspace escaped verifier authority")
    finally:
        checker.verifier_artifact_root = actual_verifier_artifact_root

    source_inventory = checker.CargoMutantsSourceInventory()
    discoverable_sources = checker.cargo_mutants_source_inventory(
        promotion_root,
        source_validation_packages["fixture-package"],
        "fixture-package",
        source_inventory,
    )
    expected_discoverable_sources = {
        "crates/fixture-package/src/lib.rs",
        "crates/fixture-package/src/fixture_module.rs",
        "crates/fixture-package/src/path_modules/fixture_path.rs",
        "crates/fixture-package/src/path_modules/fixture_path.inc",
        "crates/fixture-package/src/directory_module/mod.rs",
        "crates/fixture-package/src/dual_module.rs",
        "crates/fixture-package/src/inline_outer/nested/path_nested.rs",
        "crates/fixture-package/src/inline_outer/nested_default.rs",
        "crates/fixture-package/src/same_line.rs",
        "crates/fixture-package/src/multiline_path.rs",
        "crates/fixture-package/src/race_source.rs",
        "crates/fixture-package/src/inner_skipped_module.rs",
        "crates/fixture-package/src/bin/fixture-tool.rs",
        "crates/fixture-package/custom/explicit.rs",
        "crates/fixture-package/custom/root.inc",
    }
    expected_undiscoverable_sources = {
        "crates/fixture-package/src/included_fragment.inc",
        "crates/fixture-package/src/included_fragment.rs",
        "crates/fixture-package/src/orphan_fragment.inc",
        "crates/fixture-package/src/orphan_fragment.rs",
        "crates/fixture-package/src/test_only_module.rs",
        "crates/fixture-package/src/skipped_module.rs",
        "crates/fixture-package/src/line_commented_module.rs",
        "crates/fixture-package/src/block_commented_module.rs",
        "crates/fixture-package/src/raw_string_module.rs",
        "crates/fixture-package/src/macro_module.rs",
        "crates/fixture-package/src/fixture_module_alias.rs",
    }
    missing_discoverable_sources = expected_discoverable_sources - discoverable_sources
    unexpected_discoverable_sources = (
        expected_undiscoverable_sources & discoverable_sources
    )
    if missing_discoverable_sources or unexpected_discoverable_sources:
        raise AssertionError(
            "cargo-mutants live discovery differed from the fixture contract: "
            f"missing={sorted(missing_discoverable_sources)}, "
            f"unexpected={sorted(unexpected_discoverable_sources)}"
        )

    def validate_fixture_campaign_source(source: str, function: str) -> None:
        campaign = copy.deepcopy(promotion_campaign)
        campaign["source"] = source
        campaign["function"] = function
        checker.validate_campaign(
            promotion_root,
            source_validation_packages,
            campaign,
            source_validation_controls,
            promotion_case["id"],
            source_inventory=source_inventory,
        )

    validate_fixture_campaign_source(
        "crates/fixture-package/src/lib.rs", "fixture_function"
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/fixture_module.rs",
        "fixture_module_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/path_modules/fixture_path.rs",
        "fixture_path_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/path_modules/fixture_path.inc",
        "fixture_path_inc_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/directory_module/mod.rs",
        "directory_module_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/dual_module.rs",
        "dual_module_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/inline_outer/nested/path_nested.rs",
        "nested_path_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/inline_outer/nested_default.rs",
        "nested_default_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/same_line.rs",
        "same_line_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/multiline_path.rs",
        "multiline_path_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/inner_skipped_module.rs",
        "inner_skipped_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/src/bin/fixture-tool.rs",
        "fixture_binary_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/custom/explicit.rs",
        "fixture_explicit_binary_function",
    )
    validate_fixture_campaign_source(
        "crates/fixture-package/custom/root.inc",
        "fixture_inc_root_function",
    )
    try:
        validate_fixture_campaign_source(
            "crates/fixture-package/src/fixture_module_alias.rs",
            "fixture_module_function",
        )
    except checker.EvidenceError as error:
        if "symlink" not in str(error):
            raise AssertionError(
                f"unexpected mutation-source symlink rejection: {error}"
            ) from error
    else:
        raise AssertionError("symlink alias passed mutation-source validation")

    outside_race_source = temp / "outside-race-source.rs"
    outside_race_source.write_text(
        "fn outside_only_function() -> bool { true }\n", encoding="utf-8"
    )
    actual_repository_reader = checker.read_regular_file_below_root
    race_injected = [False]

    def swap_source_after_no_follow_read(
        repository_root: Path, path: Path, label: str
    ) -> bytes:
        payload = actual_repository_reader(repository_root, path, label)
        if path == race_source and not race_injected[0]:
            race_injected[0] = True
            race_source.unlink()
            race_source.symlink_to(outside_race_source)
        return payload

    checker.read_regular_file_below_root = swap_source_after_no_follow_read
    try:
        try:
            validate_fixture_campaign_source(
                "crates/fixture-package/src/race_source.rs",
                "outside_only_function",
            )
        except checker.EvidenceError as error:
            if "function outside_only_function is absent" not in str(error):
                raise AssertionError(
                    f"unexpected no-follow snapshot rejection: {error}"
                ) from error
        else:
            raise AssertionError("mutation source was reopened after no-follow capture")
    finally:
        checker.read_regular_file_below_root = actual_repository_reader
        if race_source.is_symlink():
            race_source.unlink()
        race_source.write_bytes(race_source_payload)
    if not race_injected[0]:
        raise AssertionError("mutation-source replacement race was not exercised")

    for rejected_source, rejected_function in (
        (
            "crates/fixture-package/src/included_fragment.inc",
            "included_inc_function",
        ),
        (
            "crates/fixture-package/src/included_fragment.rs",
            "included_rs_function",
        ),
        (
            "crates/fixture-package/src/orphan_fragment.inc",
            "orphan_inc_function",
        ),
        (
            "crates/fixture-package/src/orphan_fragment.rs",
            "orphan_rs_function",
        ),
        (
            "crates/fixture-package/src/test_only_module.rs",
            "test_only_function",
        ),
        (
            "crates/fixture-package/src/skipped_module.rs",
            "skipped_function",
        ),
        (
            "crates/fixture-package/src/line_commented_module.rs",
            "line_commented_function",
        ),
        (
            "crates/fixture-package/src/block_commented_module.rs",
            "block_commented_function",
        ),
        (
            "crates/fixture-package/src/raw_string_module.rs",
            "raw_string_function",
        ),
        (
            "crates/fixture-package/src/macro_module.rs",
            "macro_module_function",
        ),
    ):
        try:
            validate_fixture_campaign_source(rejected_source, rejected_function)
        except checker.EvidenceError as error:
            if "not cargo-mutants-discoverable" not in str(error):
                raise AssertionError(
                    f"unexpected mutation-source rejection: {error}"
                ) from error
        else:
            raise AssertionError(
                f"undiscoverable mutation source passed: {rejected_source}"
            )

    legacy_broad_outcome = copy.deepcopy(promotion_outcome)
    legacy_mutant = copy.deepcopy(fixture_mutant)
    legacy_mutant["replacement"] = "true"
    legacy_broad_outcome["caught"] = 2
    legacy_broad_outcome["total_mutants"] = 2
    legacy_broad_outcome["outcomes"].append(
        {
            "scenario": {"Mutant": legacy_mutant},
            "summary": "CaughtMutant",
        }
    )
    legacy_broad_path = temp / "legacy-broad-outcomes.json"
    write_json(legacy_broad_path, legacy_broad_outcome)
    try:
        checker.validate_outcomes(
            legacy_broad_path,
            promotion_campaign,
            None,
            fixture_source,
        )
    except checker.EvidenceError as error:
        if "semantic campaign did not execute exactly one mutant" not in str(error):
            raise AssertionError(
                f"unexpected current semantic binding rejection: {error}"
            ) from error
    else:
        raise AssertionError("current semantic binding accepted broad mutation evidence")
    checker.validate_outcomes(
        legacy_broad_path,
        promotion_campaign,
        None,
        fixture_source,
        bind_identity=False,
    )

    pending_release_cases = temp / "pending-release-cases"
    pending_release_root = temp / "pending-release-root"
    shutil.copytree(promotion_root, pending_release_root)
    (
        pending_release_root
        / promotion_case["artifact"]["campaigns"][0]["outcomes"]["path"]
    ).unlink(missing_ok=True)
    pending_release_case = copy.deepcopy(promotion_case)
    pending_release_case["pending"] = True
    write_json(
        pending_release_cases / "temporal_evasion/temporal-evasion-001.json",
        pending_release_case,
    )
    checker.load_cases(
        pending_release_root,
        pending_release_cases,
        False,
        True,
    )
    actual_release_verification = checker.run_release_verification

    def reject_release_execution(*_arguments: object) -> None:
        raise AssertionError("release campaign execution started before completeness validation")

    checker.run_release_verification = reject_release_execution
    original_arguments = sys.argv
    sys.argv = [
        str(root / "scripts/check-security-adversarial-evidence.py"),
        "--root",
        str(pending_release_root),
        "--cases",
        str(pending_release_cases),
        "--fixture",
        "--release",
    ]
    try:
        checker.main()
    except checker.EvidenceError as error:
        if "pending case cannot pass the release evidence gate" not in str(error):
            raise AssertionError(f"unexpected pending release rejection: {error}") from error
    else:
        raise AssertionError("release accepted pending mutation evidence")
    finally:
        sys.argv = original_arguments
        checker.run_release_verification = actual_release_verification

    refresh_root = temp / "refresh-root"
    shutil.copytree(promotion_root, refresh_root)
    refresh_root = refresh_root.resolve()
    refresh_case_path = refresh_root / promotion_case_path.relative_to(promotion_root)
    refresh_manifest_path = refresh_root / manifest_path.relative_to(promotion_root)
    refresh_source = refresh_root / fixture_source.relative_to(promotion_root)
    refresh_case_before = json.loads(refresh_case_path.read_text(encoding="utf-8"))
    refresh_threat_path = (
        refresh_root
        / "audits/evidence/threats"
        / f"{refresh_case_before['threat_id']}.json"
    )
    refresh_campaign_before = refresh_case_before["artifact"]["campaigns"][0]
    write_json(
        refresh_threat_path,
        {
            "caught": 99,
            "mutation_case_path": refresh_case_path.relative_to(refresh_root).as_posix(),
            "note": "stale count-bearing aggregate claimed 99 caught mutants",
            "outcomes": [
                {
                    "id": refresh_campaign_before["id"],
                    "path": refresh_campaign_before["outcomes"]["path"],
                    "sha256": "0" * 64,
                }
            ],
            "ran_at": "2000-01-01T00:00:00Z",
            "reproduction_command": "stale command",
            "survivors": [],
            "timestamp_kind": "command-wall-clock",
            "timestamp_note": "stale timestamp explanation",
        },
    )
    refresh_source.write_text(
        refresh_source.read_text(encoding="utf-8") + "// refreshed source contract\n",
        encoding="utf-8",
    )
    refresh_cases_path = refresh_case_path.parents[1]
    refresh_package_dirs = checker.package_roots(refresh_root)
    actual_run_campaign = checker.run_campaign
    refresh_runs: list[tuple[object, object]] = []

    refreshed_outcome = copy.deepcopy(promotion_outcome)
    refreshed_outcome["fixture_refresh"] = "verified"
    refreshed_outcome_bytes = checker.canonical_json_bytes(refreshed_outcome)

    def successful_refresh_runner(
        _root: Path,
        campaign: object,
        control: object,
        output_root: Path,
        _environment: object,
    ) -> Path:
        refresh_runs.append((copy.deepcopy(campaign), copy.deepcopy(control)))
        output_path = output_root / "mutants.out/outcomes.json"
        write_json(output_path, refreshed_outcome)
        return output_path

    checker.run_campaign = successful_refresh_runner
    _refresh_cases, refresh_index = checker.load_cases(
        refresh_root,
        refresh_cases_path,
        False,
        True,
        refresh_campaign="ingest_time_substitution",
    )
    refresh_record = refresh_index["ingest_time_substitution"]
    refreshed_path, refreshed_digest, refreshed_inputs = checker.refresh_outcome(
        refresh_root,
        refresh_package_dirs,
        refresh_record,
        {},
    )
    if len(refresh_runs) != 1:
        raise AssertionError("refresh did not execute its checked-in campaign exactly once")
    if refresh_runs[0] != (refresh_record[1], refresh_record[2]):
        raise AssertionError("refresh altered the checked-in campaign or control contract")
    if refreshed_path.read_bytes() != refreshed_outcome_bytes:
        raise AssertionError("refresh did not preserve the verified rerun outcome bytes")
    if refreshed_digest != hashlib.sha256(refreshed_outcome_bytes).hexdigest():
        raise AssertionError("refresh returned the wrong outcome digest")
    refreshed_case_bytes = refresh_case_path.read_bytes()
    refreshed_case = json.loads(refreshed_case_bytes)
    if refreshed_case_bytes != checker.canonical_json_bytes(refreshed_case):
        raise AssertionError("refresh did not write canonical case JSON")
    refreshed_binding = refreshed_case["artifact"]["campaigns"][0]["outcomes"]
    if refreshed_binding["sha256"] != refreshed_digest:
        raise AssertionError("refresh did not atomically bind the new outcome digest")
    if refreshed_binding["inputs_sha256"] != refreshed_inputs:
        raise AssertionError("refresh did not atomically bind the current input digest")
    refreshed_manifest = json.loads(refresh_manifest_path.read_text(encoding="utf-8"))
    refreshed_manifest_entry = next(
        entry
        for entry in refreshed_manifest["cases"]
        if entry["id"] == refreshed_case["id"]
    )
    if refreshed_manifest_entry["content_sha256"] != hashlib.sha256(
        refreshed_case_bytes
    ).hexdigest():
        raise AssertionError("refresh did not bind the new canonical case bytes in the manifest")
    refreshed_threat = json.loads(refresh_threat_path.read_text(encoding="utf-8"))
    if refreshed_threat["caught"] != refreshed_outcome["caught"]:
        raise AssertionError("refresh did not derive the threat aggregate caught count")
    if refreshed_threat["outcomes"] != [
        {
            "id": refresh_campaign_before["id"],
            "path": refresh_campaign_before["outcomes"]["path"],
            "sha256": refreshed_digest,
        }
    ]:
        raise AssertionError("refresh did not repair the threat aggregate child binding")
    if "99" in refreshed_threat["note"] or "caught 1" not in refreshed_threat["note"]:
        raise AssertionError("refresh retained stale count-bearing aggregate prose")
    if refresh_campaign_before["id"] not in refreshed_threat["reproduction_command"]:
        raise AssertionError("refresh did not derive the aggregate reproduction command")
    if refreshed_threat["ran_at"] == "2000-01-01T00:00:00Z":
        raise AssertionError("refresh retained the stale aggregate run timestamp")
    if refreshed_threat["timestamp_kind"] != "command-wall-clock":
        raise AssertionError("refresh wrote the wrong aggregate timestamp kind")
    if "caught-only mutation rerun validation" not in refreshed_threat[
        "timestamp_note"
    ]:
        raise AssertionError("refresh retained the stale aggregate timestamp explanation")

    aggregate_snapshot = checker.snapshot_threat_aggregates(refresh_root)
    aggregate_path = next(iter(aggregate_snapshot))
    aggregate_body = json.loads(aggregate_snapshot[aggregate_path])

    def require_aggregate_render_rejected(
        body: object,
        needle: str,
        *,
        path: Path = aggregate_path,
    ) -> None:
        try:
            checker.render_threat_aggregate_replacements(
                refresh_root,
                refresh_record[0],
                refresh_record[1],
                refreshed_outcome_bytes,
                {path: checker.canonical_json_bytes(body)},
                "2026-07-17T00:00:00Z",
            )
        except checker.EvidenceError as error:
            if needle not in str(error):
                raise AssertionError(
                    f"unexpected aggregate rejection, expected {needle!r}: {error}"
                ) from error
        else:
            raise AssertionError("malformed threat aggregate passed refresh rendering")

    missing_case_aggregate = copy.deepcopy(aggregate_body)
    missing_case_aggregate.pop("mutation_case_path")
    require_aggregate_render_rejected(
        missing_case_aggregate,
        "mutation_case_path: expected a repository-relative path",
    )
    for malformed_outcomes in ({}, [], ["not-an-outcome-record"]):
        malformed_aggregate = copy.deepcopy(aggregate_body)
        malformed_aggregate["outcomes"] = malformed_outcomes
        require_aggregate_render_rejected(
            malformed_aggregate,
            (
                "aggregate outcome must be an object"
                if malformed_outcomes == ["not-an-outcome-record"]
                else "aggregate outcomes must be a nonempty array"
            ),
        )
    wrong_path_aggregate = copy.deepcopy(aggregate_body)
    wrong_path_aggregate["outcomes"][0]["path"] = (
        "audits/evidence/mutants/security/reader_subset_direction/"
        "mutants.out/wrong.json"
    )
    require_aggregate_render_rejected(
        wrong_path_aggregate,
        "path differs from its mapped campaign outcome",
    )
    wrong_id_aggregate = copy.deepcopy(aggregate_body)
    wrong_id_aggregate["outcomes"][0]["id"] = "unmapped_campaign"
    require_aggregate_render_rejected(
        wrong_id_aggregate,
        "campaign is not mapped by the aggregate mutation case",
    )
    require_aggregate_render_rejected(
        aggregate_body,
        "refreshed campaign belongs to threat",
        path=aggregate_path.with_name("wrong_threat.json"),
    )
    checker.load_cases(refresh_root, refresh_cases_path, False, True)

    multi_refresh_root = temp / "multi-refresh-root"
    shutil.copytree(partial_root, multi_refresh_root)
    multi_refresh_root = multi_refresh_root.resolve()
    multi_case_path = multi_refresh_root / partial_case_path.relative_to(partial_root)
    multi_cases_path = multi_case_path.parents[1]
    multi_source = multi_refresh_root / "crates/fixture-package/src/lib.rs"
    multi_source.write_text(
        multi_source.read_text(encoding="utf-8") + "// shared stale source contract\n",
        encoding="utf-8",
    )
    multi_case_before = json.loads(multi_case_path.read_text(encoding="utf-8"))
    multi_threat_path = (
        multi_refresh_root
        / "audits/evidence/threats"
        / f"{multi_case_before['threat_id']}.json"
    )
    multi_campaigns = multi_case_before["artifact"]["campaigns"]
    write_json(
        multi_threat_path,
        {
            "caught": 200,
            "mutation_case_path": multi_case_path.relative_to(
                multi_refresh_root
            ).as_posix(),
            "note": "stale two-child aggregate",
            "outcomes": [
                {
                    "id": campaign["id"],
                    "path": campaign["outcomes"]["path"],
                    "sha256": "0" * 64,
                }
                for campaign in multi_campaigns
            ],
            "reproduction_command": "stale command",
            "survivors": [],
        },
    )
    actual_campaign_input_digest = checker.campaign_input_digest
    refresh_input_digest_campaigns: list[str] = []

    def capture_refresh_input_digest(
        root: Path,
        package_dirs: dict[str, Path],
        campaign: dict[str, object],
        control: dict[str, object],
        case_path: Path,
        *,
        captured_files: dict[Path, bytes | None] | None = None,
    ) -> str:
        refresh_input_digest_campaigns.append(str(campaign["id"]))
        return actual_campaign_input_digest(
            root,
            package_dirs,
            campaign,
            control,
            case_path,
            captured_files=captured_files,
        )

    checker.campaign_input_digest = capture_refresh_input_digest
    try:
        _multi_cases, multi_index = checker.load_cases(
            multi_refresh_root,
            multi_cases_path,
            False,
            True,
            refresh_campaign="sandbox_fd_leak",
        )
    finally:
        checker.campaign_input_digest = actual_campaign_input_digest
    if refresh_input_digest_campaigns != ["sandbox_fd_leak"]:
        raise AssertionError(
            "targeted refresh recomputed an untouched campaign input closure: "
            f"{refresh_input_digest_campaigns}"
        )
    untouched_outcome = multi_refresh_root / (
        multi_index["sandbox_env_leak"][1]["outcomes"]["path"]
    )
    untouched_outcome_bytes = untouched_outcome.read_bytes()
    real_atomic_replace_many = checker.atomic_replace_many
    observed_read_guards: list[dict[Path, bytes]] = []

    def capture_atomic_read_guards(
        replacements: object,
        originals: object,
        guards: dict[Path, bytes] | None = None,
        journal_root: Path | None = None,
    ) -> None:
        observed_read_guards.append(dict(guards or {}))
        real_atomic_replace_many(replacements, originals, guards, journal_root)

    checker.atomic_replace_many = capture_atomic_read_guards
    try:
        checker.refresh_outcome(
            multi_refresh_root,
            checker.package_roots(multi_refresh_root),
            multi_index["sandbox_fd_leak"],
            {},
        )
    finally:
        checker.atomic_replace_many = real_atomic_replace_many
    if len(observed_read_guards) != 1:
        raise AssertionError("refresh did not capture one transaction read set")
    captured_read_guards = observed_read_guards[0]
    if captured_read_guards.get(
        untouched_outcome
    ) != checker.regular_file_guard_payload(untouched_outcome_bytes):
        raise AssertionError("multi-child aggregate sibling was absent from the read set")
    required_input_guards = (
        multi_source,
        multi_source.parent,
        multi_refresh_root / ".cargo/config.toml",
    )
    if any(path not in captured_read_guards for path in required_input_guards):
        raise AssertionError("source/control input closure was absent from the read set")
    if (
        captured_read_guards[multi_refresh_root / ".cargo/config.toml"]
        != checker.MISSING_GUARD_PAYLOAD
    ):
        raise AssertionError("absent optional Cargo config was not guarded as missing")
    if untouched_outcome.read_bytes() != untouched_outcome_bytes:
        raise AssertionError("targeted refresh changed a different stale campaign outcome")
    multi_threat = json.loads(multi_threat_path.read_text(encoding="utf-8"))
    if multi_threat["caught"] != 2 or len(multi_threat["outcomes"]) != 2:
        raise AssertionError("multi-child aggregate was not derived from both outcomes")
    for record in multi_threat["outcomes"]:
        child = multi_refresh_root / record["path"]
        if record["sha256"] != hashlib.sha256(child.read_bytes()).hexdigest():
            raise AssertionError("multi-child aggregate retained a stale child digest")
    checker.load_cases(
        multi_refresh_root,
        multi_cases_path,
        False,
        True,
        refresh_campaign="sandbox_env_leak",
    )
    try:
        checker.load_cases(multi_refresh_root, multi_cases_path, False, True)
    except checker.EvidenceError as error:
        if "stale mutation input binding for sandbox_env_leak" not in str(error):
            raise AssertionError(f"unexpected remaining-stale rejection: {error}") from error
    else:
        raise AssertionError("targeted refresh silently refreshed a different stale campaign")

    no_threat_root = temp / "no-threat-refresh-root"
    shutil.copytree(promotion_root, no_threat_root)
    no_threat_root = no_threat_root.resolve()
    no_threat_case = no_threat_root / promotion_case_path.relative_to(promotion_root)
    no_threat_source = no_threat_root / fixture_source.relative_to(promotion_root)
    no_threat_source.write_text(
        no_threat_source.read_text(encoding="utf-8") + "// no aggregate refresh\n",
        encoding="utf-8",
    )
    no_threat_dir = no_threat_root / "audits/evidence/threats"
    if no_threat_dir.exists():
        shutil.rmtree(no_threat_dir)
    _no_threat_cases, no_threat_index = checker.load_cases(
        no_threat_root,
        no_threat_case.parents[1],
        False,
        True,
        refresh_campaign="ingest_time_substitution",
    )
    checker.refresh_outcome(
        no_threat_root,
        checker.package_roots(no_threat_root),
        no_threat_index["ingest_time_substitution"],
        {},
    )
    if no_threat_dir.exists():
        raise AssertionError("refresh without a citing aggregate created threat evidence")

    refresh_source.write_text(
        refresh_source.read_text(encoding="utf-8") + "// second source contract\n",
        encoding="utf-8",
    )

    def refresh_record_for_failure() -> object:
        _cases, index = checker.load_cases(
            refresh_root,
            refresh_cases_path,
            False,
            True,
            refresh_campaign="ingest_time_substitution",
        )
        return index["ingest_time_substitution"]

    def refresh_artifact_snapshot() -> tuple[bytes, bytes, bytes, bytes]:
        return (
            refreshed_path.read_bytes(),
            refresh_case_path.read_bytes(),
            refresh_manifest_path.read_bytes(),
            refresh_threat_path.read_bytes(),
        )

    def require_refresh_rejected_without_overwrite(
        runner: object,
        needle: str,
    ) -> None:
        before = refresh_artifact_snapshot()
        checker.run_campaign = runner
        try:
            checker.refresh_outcome(
                refresh_root,
                refresh_package_dirs,
                refresh_record_for_failure(),
                {},
            )
        except checker.EvidenceError as error:
            if needle not in str(error):
                raise AssertionError(
                    f"unexpected refresh rejection, expected {needle!r}: {error}"
                ) from error
        else:
            raise AssertionError("invalid refresh rerun replaced promoted evidence")
        if refresh_artifact_snapshot() != before:
            raise AssertionError("rejected refresh overwrote existing promoted evidence")

    def invalid_refresh_runner(
        _root: Path,
        _campaign: object,
        _control: object,
        output_root: Path,
        _environment: object,
    ) -> Path:
        output_path = output_root / "mutants.out/outcomes.json"
        output_path.parent.mkdir(parents=True)
        output_path.write_text("not-json\n", encoding="utf-8")
        return output_path

    require_refresh_rejected_without_overwrite(invalid_refresh_runner, "invalid JSON")

    uncaught_refresh_outcome = copy.deepcopy(refreshed_outcome)
    uncaught_refresh_outcome["caught"] = 0
    uncaught_refresh_outcome["missed"] = 1
    uncaught_refresh_outcome["outcomes"][1]["summary"] = "MissedMutant"

    def uncaught_refresh_runner(
        _root: Path,
        _campaign: object,
        _control: object,
        output_root: Path,
        _environment: object,
    ) -> Path:
        output_path = output_root / "mutants.out/outcomes.json"
        write_json(output_path, uncaught_refresh_outcome)
        return output_path

    require_refresh_rejected_without_overwrite(
        uncaught_refresh_runner,
        "missed, timed out, unviable, or surviving mutant",
    )

    def failed_refresh_runner(*_args: object, **_kwargs: object) -> Path:
        raise checker.EvidenceError("fixture rerun failed before verification")

    require_refresh_rejected_without_overwrite(
        failed_refresh_runner,
        "rerun failed before verification",
    )

    aggregate_before_unmapped = json.loads(
        refresh_threat_path.read_text(encoding="utf-8")
    )
    unmapped_aggregate = copy.deepcopy(aggregate_before_unmapped)
    unmapped_aggregate["outcomes"].append(
        {
            "id": "unmapped_campaign",
            "path": (
                "audits/evidence/mutants/security/unmapped_campaign/"
                "mutants.out/outcomes.json"
            ),
            "sha256": "0" * 64,
        }
    )
    write_json(refresh_threat_path, unmapped_aggregate)
    require_refresh_rejected_without_overwrite(
        successful_refresh_runner,
        "campaign is not mapped by the aggregate mutation case",
    )
    write_json(refresh_threat_path, aggregate_before_unmapped)

    transaction_root = temp / "refresh-transaction"
    transaction_root.mkdir()
    transaction_paths = [transaction_root / f"artifact-{index}" for index in range(4)]
    transaction_originals = {
        path: f"original-{index}\n".encode()
        for index, path in enumerate(transaction_paths)
    }
    for path, payload in transaction_originals.items():
        path.write_bytes(payload)
    real_replace = checker.os.replace
    replace_calls = [0]

    def is_prepared_publication(destination: object) -> bool:
        return Path(str(destination)).name == "prepared"

    def fail_fourth_transaction_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        if not is_prepared_publication(destination):
            replace_calls[0] += 1
            if replace_calls[0] == 4:
                raise OSError("fixture commit interruption")
        real_replace(source, destination, *args, **kwargs)

    checker.os.replace = fail_fourth_transaction_replace
    try:
        checker.atomic_replace_many(
            [
                (path, f"replacement-{index}\n".encode())
                for index, path in enumerate(transaction_paths)
            ],
            transaction_originals,
            journal_root=transaction_root,
        )
    except checker.EvidenceError as error:
        if "refresh commit failed" not in str(error):
            raise AssertionError(f"unexpected transaction failure: {error}") from error
    else:
        raise AssertionError("interrupted multi-file refresh commit passed")
    finally:
        checker.os.replace = real_replace
    if any(path.read_bytes() != transaction_originals[path] for path in transaction_paths):
        raise AssertionError("interrupted refresh commit did not roll back every artifact")

    root_guard_path = transaction_root / "root-guard-artifact"
    root_guard_original = b"root-guard-original\n"
    root_guard_replacement = b"root-guard-replacement\n"
    root_guard_path.write_bytes(root_guard_original)
    root_guard_snapshot = checker.read_guard_payload(
        transaction_root,
        str(transaction_root),
    )
    checker.atomic_replace_many(
        [(root_guard_path, root_guard_replacement)],
        {root_guard_path: root_guard_original},
        {transaction_root: root_guard_snapshot},
        transaction_root,
    )
    if root_guard_path.read_bytes() != root_guard_replacement:
        raise AssertionError("repository-root read guard blocked a valid transaction")
    if checker.transaction_directory(transaction_root).exists():
        raise AssertionError("root-guard transaction retained a completed journal")

    guard_path = transaction_root / "sibling-outcome"
    guard_original = b"caught-only sibling\n"
    guard_concurrent = b"concurrent sibling edit\n"
    guard_path.write_bytes(guard_original)
    guard_snapshot = checker.regular_file_guard_payload(guard_original)
    replace_calls[0] = 0

    def mutate_guard_during_first_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        if not is_prepared_publication(destination):
            replace_calls[0] += 1
            if replace_calls[0] == 1:
                guard_path.write_bytes(guard_concurrent)
        real_replace(source, destination, *args, **kwargs)

    checker.os.replace = mutate_guard_during_first_replace
    try:
        checker.atomic_replace_many(
            [
                (path, f"guarded-replacement-{index}\n".encode())
                for index, path in enumerate(transaction_paths)
            ],
            transaction_originals,
            {guard_path: guard_snapshot},
            transaction_root,
        )
    except checker.EvidenceError as error:
        if "transaction read guard changed" not in str(error):
            raise AssertionError(f"unexpected sibling race rejection: {error}") from error
    else:
        raise AssertionError("refresh committed after a sibling outcome changed")
    finally:
        checker.os.replace = real_replace
    if any(path.read_bytes() != transaction_originals[path] for path in transaction_paths):
        raise AssertionError("sibling race did not roll back every replaced destination")
    if guard_path.read_bytes() != guard_concurrent:
        raise AssertionError("sibling race rollback overwrote the concurrent child edit")

    absent_guard_path = transaction_root / "absent-cargo-config"
    absent_snapshot = checker.read_guard_payload(
        absent_guard_path,
        str(absent_guard_path),
    )
    absent_guard_path.write_bytes(absent_snapshot)
    try:
        checker.atomic_replace_many(
            [(transaction_paths[0], b"sentinel-collision-replacement\n")],
            {transaction_paths[0]: transaction_originals[transaction_paths[0]]},
            {absent_guard_path: absent_snapshot},
            transaction_root,
        )
    except checker.EvidenceError as error:
        if "transaction read guard changed" not in str(error):
            raise AssertionError(f"unexpected sentinel collision rejection: {error}") from error
    else:
        raise AssertionError("missing read guard collided with ordinary file bytes")
    absent_guard_path.unlink()

    unknown_destination_edit = b"unknown-concurrent-edit\n"
    real_replace_below_root = checker.replace_below_root

    def inject_destination_edit(
        journal_root: Path,
        source: Path,
        destination: Path,
        expected_destination: bytes,
    ) -> None:
        destination.write_bytes(unknown_destination_edit)
        real_replace_below_root(
            journal_root,
            source,
            destination,
            expected_destination,
        )

    checker.replace_below_root = inject_destination_edit
    try:
        checker.atomic_replace_many(
            [(transaction_paths[0], b"concurrent-check-replacement\n")],
            {transaction_paths[0]: transaction_originals[transaction_paths[0]]},
            journal_root=transaction_root,
        )
    except checker.EvidenceError as error:
        if "changed immediately before replacement" not in str(error):
            raise AssertionError(f"unexpected destination race rejection: {error}") from error
    else:
        raise AssertionError("transaction overwrote a final concurrent destination edit")
    finally:
        checker.replace_below_root = real_replace_below_root
    if transaction_paths[0].read_bytes() != unknown_destination_edit:
        raise AssertionError("destination race rejection overwrote the unknown edit")
    transaction_paths[0].write_bytes(transaction_originals[transaction_paths[0]])

    rollback_unknown_edit = b"unknown-edit-before-rollback\n"
    real_fchmod = checker.os.fchmod
    replacement_calls = [0]
    rollback_stage_injected = [False]
    rollback_started = [False]

    def fail_second_destination(
        journal_root: Path,
        source: Path,
        destination: Path,
        expected_destination: bytes,
    ) -> None:
        replacement_calls[0] += 1
        if replacement_calls[0] == 2:
            rollback_started[0] = True
            raise OSError("force rollback authentication probe")
        real_replace_below_root(
            journal_root,
            source,
            destination,
            expected_destination,
        )

    def inject_during_rollback_stage(descriptor: int, mode: int) -> None:
        if rollback_started[0] and not rollback_stage_injected[0]:
            rollback_stage_injected[0] = True
            transaction_paths[0].write_bytes(rollback_unknown_edit)
        real_fchmod(descriptor, mode)

    checker.replace_below_root = fail_second_destination
    checker.os.fchmod = inject_during_rollback_stage
    try:
        checker.atomic_replace_many(
            [
                (transaction_paths[0], b"rollback-probe-first\n"),
                (transaction_paths[1], b"rollback-probe-second\n"),
            ],
            {
                transaction_paths[0]: transaction_originals[transaction_paths[0]],
                transaction_paths[1]: transaction_originals[transaction_paths[1]],
            },
            journal_root=transaction_root,
        )
    except checker.EvidenceError as error:
        if "rollback was incomplete" not in str(error):
            raise AssertionError(f"unexpected rollback race rejection: {error}") from error
    else:
        raise AssertionError("rollback overwrote an unauthenticated destination edit")
    finally:
        checker.replace_below_root = real_replace_below_root
        checker.os.fchmod = real_fchmod
    if not rollback_stage_injected[0]:
        raise AssertionError("rollback-stage race fixture did not inject its edit")
    if transaction_paths[0].read_bytes() != rollback_unknown_edit:
        raise AssertionError("authenticated rollback overwrote the unknown edit")
    rollback_journal = checker.transaction_directory(transaction_root)
    if not rollback_journal.is_dir():
        raise AssertionError("incomplete rollback discarded its recovery journal")
    try:
        checker.recover_atomic_replace_journal(transaction_root)
    except checker.EvidenceError as error:
        if "differs from both journaled transaction states" not in str(error):
            raise AssertionError(f"unexpected preserved-journal rejection: {error}") from error
    else:
        raise AssertionError("recovery overwrote an unknown post-replacement edit")
    if not rollback_journal.is_dir():
        raise AssertionError("failed recovery discarded the forensic journal")
    shutil.rmtree(rollback_journal)
    transaction_paths[0].write_bytes(transaction_originals[transaction_paths[0]])
    transaction_paths[1].write_bytes(transaction_originals[transaction_paths[1]])

    crash_paths = [transaction_root / f"crash-artifact-{index}" for index in range(4)]
    crash_originals = {
        path: f"crash-original-{index}\n".encode()
        for index, path in enumerate(crash_paths)
    }
    for path, payload in crash_originals.items():
        path.write_bytes(payload)
    crash_program = r'''
import importlib.util
import os
import signal
import sys
from pathlib import Path

module_path = Path(sys.argv[1])
root = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("crash_refresh_checker", module_path)
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)
paths = [root / f"crash-artifact-{index}" for index in range(4)]
originals = {path: path.read_bytes() for path in paths}
real_replace = checker.os.replace
calls = 0

def kill_after_first_replace(source, destination, *args, **kwargs):
    global calls
    real_replace(source, destination, *args, **kwargs)
    if Path(str(destination)).name != "prepared":
        calls += 1
        if calls == 1:
            os.kill(os.getpid(), signal.SIGKILL)

checker.os.replace = kill_after_first_replace
checker.atomic_replace_many(
    [(path, f"crash-replacement-{index}\n".encode()) for index, path in enumerate(paths)],
    originals,
    {root: checker.read_guard_payload(root, str(root))},
    journal_root=root,
)
'''
    crashed = subprocess.run(
        [
            sys.executable,
            "-c",
            crash_program,
            str(root / "scripts/check-security-adversarial-evidence.py"),
            str(transaction_root),
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if crashed.returncode != -signal.SIGKILL:
        raise AssertionError(
            f"crash fixture did not die during commit: {crashed.returncode} {crashed.stdout}"
        )
    if not checker.transaction_directory(transaction_root).is_dir():
        raise AssertionError("crash-interrupted refresh left no durable journal")
    if checker.recover_atomic_replace_journal(transaction_root) != "rolled-back":
        raise AssertionError("crash-interrupted refresh did not report rollback recovery")
    if any(path.read_bytes() != crash_originals[path] for path in crash_paths):
        raise AssertionError("crash recovery did not restore every original artifact")
    if checker.transaction_directory(transaction_root).exists():
        raise AssertionError("crash recovery retained a completed transaction journal")

    marker_crash_path = transaction_root / "marker-crash-artifact"
    marker_crash_path.write_bytes(b"marker-original\n")
    marker_crash_program = r'''
import importlib.util
import os
import signal
import sys
from pathlib import Path

module_path = Path(sys.argv[1])
root = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("marker_crash_checker", module_path)
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)
path = root / "marker-crash-artifact"
real_replace = checker.os.replace

def kill_before_prepared_publication(source, destination, *args, **kwargs):
    if Path(str(destination)).name == "prepared":
        os.kill(os.getpid(), signal.SIGKILL)
    real_replace(source, destination, *args, **kwargs)

checker.os.replace = kill_before_prepared_publication
checker.atomic_replace_many(
    [(path, b"marker-replacement\n")],
    {path: path.read_bytes()},
    journal_root=root,
)
'''
    marker_crash = subprocess.run(
        [
            sys.executable,
            "-c",
            marker_crash_program,
            str(root / "scripts/check-security-adversarial-evidence.py"),
            str(transaction_root),
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if marker_crash.returncode != -signal.SIGKILL:
        raise AssertionError("prepared-marker fixture did not terminate before publication")
    if checker.recover_atomic_replace_journal(transaction_root) != "discarded-unprepared":
        raise AssertionError("partial prepared-marker state was not discarded as unprepared")
    if marker_crash_path.read_bytes() != b"marker-original\n":
        raise AssertionError("unprepared transaction changed its destination")

    stale_lock_root = temp / "stale-refresh-lock"
    stale_lock_root.mkdir()
    stale_lock_program = r'''
import importlib.util
import os
import signal
import sys
from pathlib import Path

module_path = Path(sys.argv[1])
root = Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("stale_lock_checker", module_path)
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)
with checker.refresh_lock(root):
    os.kill(os.getpid(), signal.SIGKILL)
'''
    stale_lock = subprocess.run(
        [
            sys.executable,
            "-c",
            stale_lock_program,
            str(root / "scripts/check-security-adversarial-evidence.py"),
            str(stale_lock_root),
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if stale_lock.returncode != -signal.SIGKILL:
        raise AssertionError("stale-lock fixture did not terminate while holding the lock")
    with checker.refresh_lock(stale_lock_root):
        pass
    if (stale_lock_root / ".chio-security-adversarial-evidence.refresh.lock").exists():
        raise AssertionError("dead-owner refresh lock was not reclaimed and released")

    untrusted_journal_root = temp / "untrusted-in-root-journal"
    untrusted_journal_root.mkdir()
    untrusted_victim = untrusted_journal_root / "victim"
    untrusted_victim.write_bytes(b"trusted victim\n")
    untrusted_journal = (
        untrusted_journal_root / checker.LEGACY_TRANSACTION_DIRECTORY
    )
    untrusted_journal.mkdir()
    untrusted_sentinel = untrusted_journal / "manifest.json"
    untrusted_sentinel.write_bytes(b"checkout-seeded journal\n")
    untrusted_state = checker.trusted_state_path(untrusted_journal_root)
    try:
        checker.recover_atomic_replace_journal(untrusted_journal_root)
    except checker.EvidenceError as error:
        if "untrusted in-repository transaction state" not in str(error):
            raise AssertionError(f"unexpected in-root journal rejection: {error}") from error
    else:
        raise AssertionError("checkout-seeded transaction journal was trusted")
    if untrusted_victim.read_bytes() != b"trusted victim\n":
        raise AssertionError("checkout-seeded journal changed a repository file")
    if untrusted_sentinel.read_bytes() != b"checkout-seeded journal\n":
        raise AssertionError("checkout-seeded journal was not preserved for inspection")
    if untrusted_state.exists():
        raise AssertionError("rejected checkout journal seeded external trusted state")

    lock_symlink_root = temp / "lock-symlink-root"
    lock_symlink_root.mkdir()
    lock_symlink_outside = temp / "lock-symlink-outside"
    lock_symlink_outside.mkdir()
    lock_symlink_sentinel = lock_symlink_outside / "owner.json"
    lock_symlink_sentinel.write_bytes(b"external sentinel\n")
    with checker.open_trusted_state(lock_symlink_root, create=True):
        pass
    trusted_lock_symlink = checker.trusted_state_path(lock_symlink_root) / checker.LOCK_DIRECTORY
    trusted_lock_symlink.symlink_to(lock_symlink_outside, target_is_directory=True)
    try:
        with checker.refresh_lock(lock_symlink_root):
            pass
    except checker.EvidenceError:
        pass
    else:
        raise AssertionError("trusted-state lock symlink was followed")
    if lock_symlink_sentinel.read_bytes() != b"external sentinel\n":
        raise AssertionError("lock symlink handling changed an external sentinel")
    trusted_lock_symlink.unlink()

    owner_swap_root = temp / "lock-owner-swap"
    owner_swap_root.mkdir()
    real_read_owned_file_at = checker.read_owned_file_at
    owner_swap_injected = [False]

    def replace_owner_after_read(
        directory_descriptor: int,
        name: str,
        label: str,
        expected_mode: int,
        **kwargs: object,
    ) -> tuple[bytes, object]:
        payload, metadata = real_read_owned_file_at(
            directory_descriptor,
            name,
            label,
            expected_mode,
            **kwargs,
        )
        if name == "owner.json" and not owner_swap_injected[0]:
            owner_swap_injected[0] = True
            checker.os.unlink(name, dir_fd=directory_descriptor)
            checker.write_new_fsynced_at(
                directory_descriptor,
                name,
                payload,
                0o600,
                label,
            )
        return payload, metadata

    try:
        with checker.refresh_lock(owner_swap_root):
            checker.read_owned_file_at = replace_owner_after_read
    except checker.EvidenceError as error:
        if "identity changed" not in str(error):
            raise AssertionError(f"unexpected owner-swap rejection: {error}") from error
    else:
        raise AssertionError("refresh lock released after owner inode replacement")
    finally:
        checker.read_owned_file_at = real_read_owned_file_at
    if not owner_swap_injected[0]:
        raise AssertionError("owner replacement fixture did not run")
    shutil.rmtree(checker.trusted_state_path(owner_swap_root) / checker.LOCK_DIRECTORY)

    directory_swap_root = temp / "lock-directory-swap"
    directory_swap_root.mkdir()
    real_retire_owned_directory = checker.retire_owned_directory
    directory_swap_injected = [False]

    def replace_lock_directory_before_retirement(
        state: object,
        name: str,
        descriptor: int,
        identity: tuple[int, int],
    ) -> None:
        if name == checker.LOCK_DIRECTORY and not directory_swap_injected[0]:
            directory_swap_injected[0] = True
            checker.os.rename(
                name,
                f"{name}.moved",
                src_dir_fd=state.descriptor,
                dst_dir_fd=state.descriptor,
            )
            checker.os.mkdir(name, 0o700, dir_fd=state.descriptor)
        real_retire_owned_directory(state, name, descriptor, identity)

    try:
        with checker.refresh_lock(directory_swap_root):
            checker.retire_owned_directory = replace_lock_directory_before_retirement
    except checker.EvidenceError as error:
        if "identity changed" not in str(error):
            raise AssertionError(f"unexpected directory-swap rejection: {error}") from error
    else:
        raise AssertionError("refresh lock deleted a replacement directory")
    finally:
        checker.retire_owned_directory = real_retire_owned_directory
    if not directory_swap_injected[0]:
        raise AssertionError("lock-directory replacement fixture did not run")
    directory_state = checker.trusted_state_path(directory_swap_root)
    if not (directory_state / checker.LOCK_DIRECTORY).is_dir():
        raise AssertionError("replacement lock directory was deleted")
    if not (directory_state / f"{checker.LOCK_DIRECTORY}.moved/owner.json").is_file():
        raise AssertionError("original lock owner was not preserved after a path swap")
    shutil.rmtree(directory_state / checker.LOCK_DIRECTORY)
    shutil.rmtree(directory_state / f"{checker.LOCK_DIRECTORY}.moved")

    promotion_crash_program = r'''
import importlib.util
import os
import signal
import sys
from pathlib import Path

module_path = Path(sys.argv[1])
root = Path(sys.argv[2])
kill_point = sys.argv[3]
spec = importlib.util.spec_from_file_location("promotion_crash_checker", module_path)
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)
outcome = root / "outcome.json"
case = root / "case.json"
manifest = root / "manifest.json"
real_replace = checker.os.replace
real_link = checker.os.link
real_unlink = checker.os.unlink
real_write_new_fsynced_at = checker.write_new_fsynced_at

def kill_after_replace(source, destination, *args, **kwargs):
    real_replace(source, destination, *args, **kwargs)
    destination_name = Path(str(destination)).name
    if (
        destination_name == kill_point
        or (
            kill_point == "outcome.marker"
            and destination_name == "published-0000.json"
        )
    ):
        os.kill(os.getpid(), signal.SIGKILL)

def kill_after_link(source, destination, *args, **kwargs):
    real_link(source, destination, *args, **kwargs)
    if kill_point == "outcome.link":
        os.kill(os.getpid(), signal.SIGKILL)

def kill_after_unlink(path, *args, **kwargs):
    real_unlink(path, *args, **kwargs)
    if (
        kill_point == "outcome.stage-unlink"
        and Path(str(path)).name == "replacement-0000.bin"
    ):
        os.kill(os.getpid(), signal.SIGKILL)

def kill_after_trusted_write(
    directory_descriptor, name, payload, mode, label
):
    real_write_new_fsynced_at(
        directory_descriptor, name, payload, mode, label
    )
    if kill_point == "outcome.marker.tmp" and name == "published-0000.json.tmp":
        os.kill(os.getpid(), signal.SIGKILL)

checker.os.replace = kill_after_replace
checker.os.link = kill_after_link
checker.os.unlink = kill_after_unlink
checker.write_new_fsynced_at = kill_after_trusted_write
checker.atomic_replace_many(
    [
        (outcome, b"new outcome\n"),
        (case, b"new case\n"),
        (manifest, b"new manifest\n"),
    ],
    {
        outcome: None,
        case: b"old case\n",
        manifest: b"old manifest\n",
    },
    journal_root=root,
)
'''
    for kill_point in (
        "prepared",
        "outcome.link",
        "outcome.marker.tmp",
        "outcome.marker",
        "outcome.stage-unlink",
        "case.json",
        "manifest.json",
    ):
        promotion_crash_root = temp / f"promotion-crash-{kill_point.replace('.', '-')}"
        promotion_crash_root.mkdir()
        promotion_case_path = promotion_crash_root / "case.json"
        promotion_manifest_path = promotion_crash_root / "manifest.json"
        promotion_outcome_path = promotion_crash_root / "outcome.json"
        promotion_state_path = checker.trusted_state_path(promotion_crash_root)
        promotion_state_path.mkdir(mode=0o700)
        promotion_state_before = promotion_state_path.lstat()
        checker.require_owned_directory_metadata(
            promotion_state_before, str(promotion_state_path)
        )
        if promotion_state_before.st_nlink not in (1, 2):
            raise AssertionError("precreated trusted state has unexpected link count")
        promotion_case_path.write_bytes(b"old case\n")
        promotion_manifest_path.write_bytes(b"old manifest\n")
        crashed = subprocess.run(
            [
                sys.executable,
                "-c",
                promotion_crash_program,
                str(root / "scripts/check-security-adversarial-evidence.py"),
                str(promotion_crash_root),
                kill_point,
            ],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if crashed.returncode != -signal.SIGKILL:
            raise AssertionError(
                f"promotion crash point {kill_point} did not terminate: {crashed.stdout}"
            )
        with checker.refresh_lock(promotion_crash_root):
            recovery = checker.recover_atomic_replace_journal(promotion_crash_root)
        promotion_state_after = promotion_state_path.lstat()
        checker.require_owned_directory_metadata(
            promotion_state_after, str(promotion_state_path)
        )
        if (
            checker.metadata_identity(promotion_state_after)
            != checker.metadata_identity(promotion_state_before)
            or promotion_state_after.st_nlink != promotion_state_before.st_nlink
        ):
            raise AssertionError("recovery replaced or relinked precreated trusted state")
        if kill_point == "manifest.json":
            if recovery != "committed":
                raise AssertionError(f"fully published promotion was not committed: {recovery}")
            expected_case = b"new case\n"
            expected_manifest = b"new manifest\n"
            expected_outcome = b"new outcome\n"
        else:
            if recovery != "rolled-back":
                raise AssertionError(f"partial promotion was not rolled back: {recovery}")
            expected_case = b"old case\n"
            expected_manifest = b"old manifest\n"
            expected_outcome = None
        if promotion_case_path.read_bytes() != expected_case:
            raise AssertionError(f"case split after promotion crash at {kill_point}")
        if promotion_manifest_path.read_bytes() != expected_manifest:
            raise AssertionError(f"manifest split after promotion crash at {kill_point}")
        if (
            None if not promotion_outcome_path.exists() else promotion_outcome_path.read_bytes()
        ) != expected_outcome:
            raise AssertionError(f"outcome split after promotion crash at {kill_point}")

    absent_unknown_root = temp / "promotion-unknown-edit"
    absent_unknown_root.mkdir()
    absent_unknown_outcome = absent_unknown_root / "outcome.json"
    absent_unknown_case = absent_unknown_root / "case.json"
    absent_unknown_case.write_bytes(b"old case\n")
    real_replace_below_root = checker.replace_below_root
    absent_publish_calls = [0]

    def inject_unknown_new_destination(
        journal_root: Path,
        source: Path,
        destination: Path,
        expected_destination: bytes | None,
    ) -> None:
        absent_publish_calls[0] += 1
        if absent_publish_calls[0] == 2:
            absent_unknown_outcome.write_bytes(b"unknown concurrent outcome\n")
            raise OSError("force absent-original rollback")
        real_replace_below_root(journal_root, source, destination, expected_destination)

    checker.replace_below_root = inject_unknown_new_destination
    try:
        checker.atomic_replace_many(
            [
                (absent_unknown_outcome, b"new outcome\n"),
                (absent_unknown_case, b"new case\n"),
            ],
            {
                absent_unknown_outcome: None,
                absent_unknown_case: b"old case\n",
            },
            journal_root=absent_unknown_root,
        )
    except checker.EvidenceError as error:
        if "rollback was incomplete" not in str(error):
            raise AssertionError(f"unexpected absent rollback rejection: {error}") from error
    else:
        raise AssertionError("absent rollback overwrote an unknown edit")
    finally:
        checker.replace_below_root = real_replace_below_root
    if absent_unknown_outcome.read_bytes() != b"unknown concurrent outcome\n":
        raise AssertionError("absent rollback destroyed an unknown destination edit")
    absent_unknown_journal = checker.transaction_directory(absent_unknown_root)
    if not absent_unknown_journal.is_dir():
        raise AssertionError("absent rollback discarded its forensic journal")
    try:
        checker.recover_atomic_replace_journal(absent_unknown_root)
    except checker.EvidenceError as error:
        if "differs from both journaled transaction states" not in str(error):
            raise AssertionError(f"unexpected absent recovery rejection: {error}") from error
    else:
        raise AssertionError("recovery overwrote an unknown new-destination edit")
    shutil.rmtree(absent_unknown_journal)

    parent_swap_root = temp / "promotion-parent-swap"
    parent_swap_root.mkdir()
    parent_swap_destination_parent = parent_swap_root / "evidence"
    parent_swap_destination_parent.mkdir()
    parent_swap_destination = parent_swap_destination_parent / "outcome.json"
    parent_swap_moved = parent_swap_root / "evidence-moved"
    parent_swap_external = temp / "promotion-parent-swap-external"
    parent_swap_external.mkdir()
    parent_swap_sentinel = parent_swap_external / "sentinel"
    parent_swap_sentinel.write_bytes(b"external path sentinel\n")
    real_link = checker.os.link
    parent_swap_injected = [False]

    def replace_parent_during_link(*args: object, **kwargs: object) -> None:
        if not parent_swap_injected[0]:
            parent_swap_injected[0] = True
            parent_swap_destination_parent.rename(parent_swap_moved)
            parent_swap_destination_parent.symlink_to(
                parent_swap_external, target_is_directory=True
            )
        real_link(*args, **kwargs)

    checker.os.link = replace_parent_during_link
    try:
        checker.atomic_replace_many(
            [(parent_swap_destination, b"transaction payload\n")],
            {parent_swap_destination: None},
            journal_root=parent_swap_root,
        )
    except checker.EvidenceError as error:
        if "rollback was incomplete" not in str(error):
            raise AssertionError(f"unexpected parent-swap rejection: {error}") from error
    else:
        raise AssertionError("transaction accepted a replaced destination parent")
    finally:
        checker.os.link = real_link
    if parent_swap_sentinel.read_bytes() != b"external path sentinel\n":
        raise AssertionError("destination-parent swap changed an external sentinel")
    if (parent_swap_external / "outcome.json").exists():
        raise AssertionError("destination-parent swap redirected publication outside root")
    if not checker.transaction_directory(parent_swap_root).is_dir():
        raise AssertionError("parent-swap failure discarded its forensic journal")

    checker.run_campaign = actual_run_campaign

    release_controls: list[str] = []
    release_campaigns: list[str] = []
    original_run_campaign = checker.run_campaign
    checker.run_control = lambda _root, control, _environment: release_controls.append(
        control["id"]
    )
    checker.run_campaign = (
        lambda _root, campaign, _control, _output, _environment: release_campaigns.append(
            campaign["id"]
        )
    )
    release_control = {
        "id": "fixture_control",
        "package": "fixture-package",
        "test_source": "crates/fixture-package/src/lib.rs",
        "target_kind": "lib",
        "target": None,
        "features": [],
        "required_target_os": None,
        "test_name": "fixture_test",
    }
    promoted_release_index = {
        "promoted_one": (
            None,
            {"id": "promoted_one", "outcomes": {"sha256": "1" * 64}},
            release_control,
        ),
        "promoted_two": (
            None,
            {"id": "promoted_two", "outcomes": {"sha256": "2" * 64}},
            release_control,
        ),
    }
    release_counts = checker.run_release_verification(
        promotion_root, promoted_release_index, {}
    )
    if release_counts != (2, 1, 0):
        raise AssertionError(f"all-promoted release accounting is wrong: {release_counts}")
    if release_controls != ["fixture_control"]:
        raise AssertionError(
            "all-promoted release did not execute its distinct current control exactly once"
        )
    if release_campaigns != ["promoted_one", "promoted_two"]:
        raise AssertionError(
            "all-promoted release did not rerun every promoted mutation against the current tree: "
            f"{release_campaigns}"
        )

    def reject_surviving_promoted_mutant(
        _root: Path,
        campaign: dict[str, object],
        _control: dict[str, object],
        _output: Path,
        _environment: dict[str, str],
    ) -> None:
        if campaign["id"] == "promoted_two":
            raise checker.EvidenceError(
                "promoted_two: promoted mutant survived the current tree"
            )

    checker.run_campaign = reject_surviving_promoted_mutant
    try:
        checker.run_release_verification(promotion_root, promoted_release_index, {})
    except checker.EvidenceError as error:
        if "promoted mutant survived the current tree" not in str(error):
            raise AssertionError(
                f"unexpected promoted-rerun rejection: {error}"
            ) from error
    else:
        raise AssertionError("release accepted a promoted mutant that survives the current tree")
    try:
        checker.run_release_verification(promotion_root, {}, {})
    except checker.EvidenceError as error:
        if "no mutation campaigns" not in str(error):
            raise AssertionError(f"unexpected empty release rejection: {error}") from error
    else:
        raise AssertionError("empty release evidence suite passed")
    checker.run_campaign = original_run_campaign

    escaped_function_outcome = copy.deepcopy(promotion_outcome)
    for outcome in escaped_function_outcome["outcomes"]:
        scenario = outcome.get("scenario")
        mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
        if isinstance(mutant, dict):
            mutant["function"]["function_name"] = "fixture_function_extra"
    escaped_function_path = temp / "escaped-function-outcome.json"
    write_json(escaped_function_path, escaped_function_outcome)
    try:
        checker.validate_outcomes(
            escaped_function_path,
            {
                "package": "fixture-package",
                "source": "crates/fixture-package/src/lib.rs",
                "function": "fixture_function",
                "minimum_caught": 1,
            },
            None,
            fixture_source,
        )
    except checker.EvidenceError as error:
        if "function binding" not in str(error):
            raise AssertionError(f"unexpected function-binding rejection: {error}") from error
    else:
        raise AssertionError("substring function binding accepted an escaped mutant")

    wrong_identity = copy.deepcopy(promotion_outcome)
    wrong_identity["outcomes"][1]["scenario"]["Mutant"]["replacement"] = "true"
    wrong_identity_path = temp / "wrong-identity-outcome.json"
    write_json(wrong_identity_path, wrong_identity)
    try:
        checker.validate_outcomes(
            wrong_identity_path,
            promotion_campaign,
            None,
            fixture_source,
        )
    except checker.EvidenceError as error:
        if "identity differs" not in str(error):
            raise AssertionError(f"unexpected identity rejection: {error}") from error
    else:
        raise AssertionError("outcome with a different replacement passed semantic binding")

    checker.run_control = lambda *_args, **_kwargs: None
    checker.validate_outcomes = lambda *_args, **_kwargs: None
    actual_cargo_mutants_executable = checker.cargo_mutants_executable
    actual_require_cargo_mutants_version = checker.require_cargo_mutants_version
    actual_validate_mutation_output_root = checker.validate_mutation_output_root
    actual_cargo_mutants_subprocess_options = (
        checker.cargo_mutants_subprocess_options
    )
    campaign_authentications: list[Path] = []
    campaign_version_checks: list[Path] = []
    campaign_execution_bindings: list[tuple[str, ...]] = []
    enterprise_campaign_environment = {"CHIO_ENTERPRISE_SECURITY_RUNNER": "1"}

    def authenticated_campaign_output(
        _output: Path, environment: dict[str, str]
    ) -> None:
        if environment.get("CHIO_ENTERPRISE_SECURITY_RUNNER") != "1":
            raise AssertionError("campaign output validation left enterprise mode")
        return None

    def authenticated_campaign_executable(
        _root: Path, cache: object, environment: dict[str, str] | None = None
    ) -> Path:
        if (
            environment is None
            or environment.get("CHIO_ENTERPRISE_SECURITY_RUNNER") != "1"
        ):
            raise AssertionError("campaign cargo-mutants authentication left enterprise mode")
        cache.executable = trusted_tool
        campaign_authentications.append(trusted_tool)
        return trusted_tool

    def authenticated_campaign_version(
        executable: Path,
        _root: Path,
        environment: dict[str, str] | None = None,
    ) -> tuple[int, int]:
        if executable != trusted_tool:
            raise AssertionError("campaign version check used an untrusted executable")
        if (
            environment is None
            or environment.get("CHIO_ENTERPRISE_SECURITY_RUNNER") != "1"
        ):
            raise AssertionError("campaign cargo-mutants version left enterprise mode")
        campaign_version_checks.append(executable)
        return (1, 1)

    @checker.contextmanager
    def authenticated_campaign_execution(
        _root: Path,
        command: list[str],
        environment: dict[str, str] | None,
        expected_identity: tuple[int, int] | None = None,
    ) -> object:
        if (
            environment is None
            or environment.get("CHIO_ENTERPRISE_SECURITY_RUNNER") != "1"
            or command[:2] != [str(trusted_tool), "mutants"]
            or expected_identity != (1, 1)
        ):
            raise AssertionError("campaign execution left its pinned enterprise engine")
        campaign_execution_bindings.append(tuple(command))
        yield (
            {
                "executable": "/proc/self/fd/97",
                "pass_fds": (97,),
            },
            (1, 1),
        )

    checker.validate_mutation_output_root = authenticated_campaign_output
    checker.cargo_mutants_executable = authenticated_campaign_executable
    checker.require_cargo_mutants_version = authenticated_campaign_version
    checker.cargo_mutants_subprocess_options = authenticated_campaign_execution

    campaign_root = temp / "campaign-root"
    campaign_source = campaign_root / "src/lib.rs"
    campaign_source.parent.mkdir(parents=True)
    campaign_source.write_text(
        "fn fixture_function() -> bool { true }\n", encoding="utf-8"
    )
    runner_campaign = {
        "id": "fixture_campaign",
        "package": "fixture-package",
        "source": "src/lib.rs",
        "function": "fixture_function",
        "minimum_caught": 1,
        "mutant": {"genre": "FnValue", "replacement": "false"},
    }
    runner_native = copy.deepcopy(fixture_mutant)
    runner_native["file"] = "src/lib.rs"

    def observe_preflight(
        command: list[str],
        *_args: object,
        **kwargs: object,
    ) -> object:
        if command[:2] != [str(trusted_tool), "mutants"]:
            raise AssertionError(f"preflight bypassed trusted cargo-mutants: {command}")
        if kwargs.get("execution_options") != {
            "executable": "/proc/self/fd/97",
            "pass_fds": (97,),
        }:
            raise AssertionError("preflight was not bound to its authenticated inode")
        for required in ("--no-config", "--list", "--json", "--no-shuffle"):
            if required not in command:
                raise AssertionError(f"missing mutation preflight option: {required}")
        for forbidden in ("--output", "--in-place", "--jobs"):
            if forbidden in command:
                raise AssertionError(f"unsafe mutation preflight option: {forbidden}")
        unrelated = copy.deepcopy(runner_native)
        unrelated["function"]["function_name"] = "other_function"
        unrelated["genre"] = "MatchArm"
        return [unrelated, copy.deepcopy(runner_native)]

    checker.run_json_checked = observe_preflight

    def observe_output_parent(
        command: list[str],
        *_args: object,
        **kwargs: object,
    ) -> str:
        if command[:2] != [str(trusted_tool), "mutants"]:
            raise AssertionError(f"campaign bypassed trusted cargo-mutants: {command}")
        if kwargs.get("execution_options") != {
            "executable": "/proc/self/fd/97",
            "pass_fds": (97,),
        }:
            raise AssertionError("campaign was not bound to its authenticated inode")
        output = Path(command[command.index("--output") + 1])
        if output != campaign_output:
            raise AssertionError(f"unexpected mutation output root: {output}")
        if "--baseline=skip" in command:
            raise AssertionError("native mutation evidence omitted its baseline")
        for required in (
            "--no-config",
            "--in-place",
            "--jobserver-tasks=1",
            "--line-col=true",
            "--no-shuffle",
        ):
            if required not in command:
                raise AssertionError(f"missing single-lane mutation option: {required}")
        if "--jobs" in command:
            raise AssertionError("cargo-mutants --jobs conflicts with in-place execution")
        selector = command[command.index("--re") + 1]
        native_name = (
            "src/lib.rs:1:33: replace fixture_function -> bool with false"
        )
        expected_selector = f"^{checker.re.escape(native_name)}$"
        if selector != expected_selector:
            raise AssertionError(
                f"mutation identity selector is not exact: {selector}"
            )
        if "--cargo-arg=--lib" not in command:
            raise AssertionError("mutation execution was not limited to the control target")
        if command[-4:] != ["--", "fixture_test", "--", "--exact"]:
            raise AssertionError(f"mutation execution was not exact: {command[-4:]}")
        if not output.is_dir():
            raise AssertionError("mutation output parent was not created")
        native_output = output / "mutants.out"
        native_output.mkdir()
        (native_output / "outcomes.json").write_text("{}\n", encoding="utf-8")
        return ""

    checker.run_checked = observe_output_parent
    campaign_output = temp / "new-campaign-output"
    returned = checker.run_campaign(
        campaign_root,
        runner_campaign,
        {
            "id": "fixture_control",
            "package": "fixture-package",
            "features": [],
            "target_kind": "lib",
            "target": "",
            "test_name": "fixture_test",
        },
        campaign_output,
        enterprise_campaign_environment,
    )
    if returned != campaign_output / "mutants.out/outcomes.json":
        raise AssertionError(f"unexpected campaign outcome path: {returned}")

    def observe_cross_package(
        command: list[str],
        *_args: object,
        **kwargs: object,
    ) -> str:
        if command[:2] != [str(trusted_tool), "mutants"]:
            raise AssertionError(f"campaign bypassed trusted cargo-mutants: {command}")
        if kwargs.get("execution_options") != {
            "executable": "/proc/self/fd/97",
            "pass_fds": (97,),
        }:
            raise AssertionError("campaign was not bound to its authenticated inode")
        if "--test-package" not in command:
            raise AssertionError("cross-package control omitted --test-package")
        test_package_index = command.index("--test-package")
        if command[test_package_index + 1] != "fixture-control-package":
            raise AssertionError(f"wrong cross-package control: {command}")
        if any(argument.startswith("--cargo-arg=") for argument in command):
            raise AssertionError(
                "cross-package control leaked a target selector into the mutated package"
            )
        if command[-4:] != ["--", "cross_package_test", "--", "--exact"]:
            raise AssertionError(f"cross-package execution was not exact: {command[-4:]}")
        output = Path(command[command.index("--output") + 1])
        native_output = output / "mutants.out"
        native_output.mkdir()
        (native_output / "outcomes.json").write_text("{}\n", encoding="utf-8")
        return ""

    checker.run_checked = observe_cross_package
    cross_package_output = temp / "cross-package-campaign-output"
    cross_package_returned = checker.run_campaign(
        campaign_root,
        runner_campaign,
        {
            "id": "cross_package_control",
            "package": "fixture-control-package",
            "features": [],
            "target_kind": "test",
            "target": "cross_package_target",
            "test_name": "cross_package_test",
        },
        cross_package_output,
        enterprise_campaign_environment,
    )
    if cross_package_returned != cross_package_output / "mutants.out/outcomes.json":
        raise AssertionError(
            f"unexpected cross-package outcome path: {cross_package_returned}"
        )

    duplicate_native = copy.deepcopy(runner_native)
    duplicate_native["span"]["start"]["line"] = 2
    duplicate_native["span"]["end"]["line"] = 2
    campaign_source_lines = checker.source_lines(
        campaign_source.read_bytes(), campaign_source
    )
    try:
        checker.select_native_mutant(
            [runner_native, duplicate_native],
            runner_campaign,
            campaign_source_lines,
            campaign_source,
        )
    except checker.EvidenceError as error:
        if "resolved to 2" not in str(error):
            raise AssertionError(f"unexpected ambiguity rejection: {error}") from error
    else:
        raise AssertionError("ambiguous semantic selector passed preflight")

    ordinal_campaign = copy.deepcopy(runner_campaign)
    ordinal_campaign["mutant"]["occurrence"] = 2
    selected = checker.select_native_mutant(
        [runner_native, duplicate_native],
        ordinal_campaign,
        campaign_source_lines,
        campaign_source,
    )
    if selected.native != duplicate_native:
        raise AssertionError("semantic occurrence did not select source-ordered mutant")

    fallback_campaign = copy.deepcopy(runner_campaign)
    fallback_campaign["mutant"]["replacement"] = "Ok(Default::default())"
    fallback_native = copy.deepcopy(runner_native)
    fallback_native["replacement"] = "Ok(Default::default())"
    fallback_native["function"]["return_type"] = (
        "-> Result<Digest32, StateMachineError>"
    )
    fallback = checker.select_native_mutant(
        [fallback_native],
        fallback_campaign,
        campaign_source_lines,
        campaign_source,
    )
    try:
        checker.require_statically_viable_mutant(fallback, fallback_campaign)
    except checker.EvidenceError as error:
        if "not statically viable" not in str(error):
            raise AssertionError(f"unexpected viability rejection: {error}") from error
    else:
        raise AssertionError("Default-based FnValue fallback passed preflight")

    campaign_output = temp / "corrupt-campaign-output"

    def leave_source_changed(
        command: list[str],
        *args: object,
        **kwargs: object,
    ) -> str:
        observed = observe_output_parent(command, *args, **kwargs)
        campaign_source.write_text("fn fixture_function() { panic!() }\n", encoding="utf-8")
        return observed

    checker.run_checked = leave_source_changed
    try:
        checker.run_campaign(
            campaign_root,
            runner_campaign,
            {
                "id": "fixture_control",
                "package": "fixture-package",
                "features": [],
                "target_kind": "lib",
                "target": "",
                "test_name": "fixture_test",
            },
            campaign_output,
            enterprise_campaign_environment,
        )
    except checker.EvidenceError as error:
        if "left the source changed" not in str(error):
            raise AssertionError(f"unexpected source-integrity rejection: {error}") from error
    else:
        raise AssertionError("in-place mutation left changed source without rejection")
    if (
        campaign_authentications != [trusted_tool, trusted_tool, trusted_tool]
        or campaign_version_checks != [trusted_tool, trusted_tool, trusted_tool]
        or len(campaign_execution_bindings) != 6
    ):
        raise AssertionError("campaign executions did not bind the pinned engine")
    checker.cargo_mutants_executable = actual_cargo_mutants_executable
    checker.require_cargo_mutants_version = actual_require_cargo_mutants_version
    checker.validate_mutation_output_root = actual_validate_mutation_output_root
    checker.cargo_mutants_subprocess_options = (
        actual_cargo_mutants_subprocess_options
    )

print("Security adversarial evidence gate contract passed")
PY
