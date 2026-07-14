#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

test -x scripts/check-security-adversarial-evidence.sh
bash -n scripts/check-security-adversarial-evidence.sh
python3 -m py_compile scripts/check-security-adversarial-evidence.py

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
import shutil
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
canary = root / (
    "crates/core/chio-adversarial-suite/cases/canary_evasion/"
    "canary-evasion-001.json"
)
native_outcome = root / (
    "audits/evidence/mutants/security/ingest_time_substitution/"
    "mutants.out/outcomes.json"
)


def write_json(path: Path, body: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def invoke(cases: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(gate),
            "--root",
            str(root),
            "--cases",
            str(cases),
            "--fixture",
            *extra,
        ],
        cwd=root,
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
    temp = Path(raw)

    valid_cases = temp / "valid"
    write_json(
        valid_cases / "temporal_evasion/temporal-evasion-001.json",
        json.loads(temporal.read_text(encoding="utf-8")),
    )
    valid = invoke(valid_cases)
    if valid.returncode != 0:
        raise AssertionError(valid.stdout)

    legacy_cases = temp / "legacy"
    legacy = json.loads(temporal.read_text(encoding="utf-8"))
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
    expect_rejected(invoke(legacy_cases), "artifact: field mismatch")

    unknown_cases = temp / "unknown"
    unknown = json.loads(temporal.read_text(encoding="utf-8"))
    unknown["artifact"]["unexpectedField"] = True
    write_json(
        unknown_cases / "temporal_evasion/temporal-evasion-001.json",
        unknown,
    )
    expect_rejected(invoke(unknown_cases), "unknown=['unexpectedField']")

    digest_cases = temp / "digest"
    digest = json.loads(temporal.read_text(encoding="utf-8"))
    digest["artifact"]["campaigns"][0]["outcomes"]["sha256"] = "0" * 64
    write_json(
        digest_cases / "temporal_evasion/temporal-evasion-001.json",
        digest,
    )
    expect_rejected(invoke(digest_cases), "digest mismatch")

    unbound_inputs_cases = temp / "unbound-inputs"
    unbound_inputs = json.loads(temporal.read_text(encoding="utf-8"))
    unbound_inputs["artifact"]["campaigns"][0]["outcomes"].pop(
        "inputs_sha256"
    )
    write_json(
        unbound_inputs_cases / "temporal_evasion/temporal-evasion-001.json",
        unbound_inputs,
    )
    expect_rejected(
        invoke(unbound_inputs_cases),
        "outcome and input digests must be bound together",
    )

    missing_cases = temp / "missing"
    missing = json.loads(canary.read_text(encoding="utf-8"))
    missing["pending"] = False
    missing["artifact"]["campaigns"][0]["outcomes"].pop("sha256", None)
    missing["artifact"]["campaigns"][0]["outcomes"].pop(
        "inputs_sha256", None
    )
    write_json(
        missing_cases / "canary_evasion/canary-evasion-001.json",
        missing,
    )
    expect_rejected(invoke(missing_cases), "outcome exists without a bound digest")

    base_outcome = json.loads(native_outcome.read_text(encoding="utf-8"))
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
        ),
        "missed, timed out, unviable, or surviving mutant",
    )

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
        ),
        encoding="utf-8",
    )
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
    canonical_outcome = promotion_root / promotion_campaign["outcomes"]["path"]
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

    module_spec = importlib.util.spec_from_file_location(
        "security_adversarial_evidence",
        root / "scripts/check-security-adversarial-evidence.py",
    )
    if module_spec is None or module_spec.loader is None:
        raise AssertionError("unable to load adversarial evidence checker")
    checker = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = checker
    module_spec.loader.exec_module(checker)

    refresh_root = temp / "refresh-root"
    shutil.copytree(promotion_root, refresh_root)
    refresh_root = refresh_root.resolve()
    refresh_case_path = refresh_root / promotion_case_path.relative_to(promotion_root)
    refresh_manifest_path = refresh_root / manifest_path.relative_to(promotion_root)
    refresh_source = refresh_root / fixture_source.relative_to(promotion_root)
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
    _multi_cases, multi_index = checker.load_cases(
        multi_refresh_root,
        multi_cases_path,
        False,
        True,
        refresh_campaign="sandbox_fd_leak",
    )
    untouched_outcome = multi_refresh_root / (
        multi_index["sandbox_env_leak"][1]["outcomes"]["path"]
    )
    untouched_outcome_bytes = untouched_outcome.read_bytes()
    checker.refresh_outcome(
        multi_refresh_root,
        checker.package_roots(multi_refresh_root),
        multi_index["sandbox_fd_leak"],
        {},
    )
    if untouched_outcome.read_bytes() != untouched_outcome_bytes:
        raise AssertionError("targeted refresh changed a different stale campaign outcome")
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

    def refresh_artifact_snapshot() -> tuple[bytes, bytes, bytes]:
        return (
            refreshed_path.read_bytes(),
            refresh_case_path.read_bytes(),
            refresh_manifest_path.read_bytes(),
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

    transaction_root = temp / "refresh-transaction"
    transaction_root.mkdir()
    transaction_paths = [transaction_root / f"artifact-{index}" for index in range(3)]
    transaction_originals = {
        path: f"original-{index}\n".encode()
        for index, path in enumerate(transaction_paths)
    }
    for path, payload in transaction_originals.items():
        path.write_bytes(payload)
    real_replace = checker.os.replace
    replace_calls = [0]

    def fail_third_transaction_replace(source: object, destination: object) -> None:
        replace_calls[0] += 1
        if replace_calls[0] == 3:
            raise OSError("fixture commit interruption")
        real_replace(source, destination)

    checker.os.replace = fail_third_transaction_replace
    try:
        checker.atomic_replace_many(
            [
                (path, f"replacement-{index}\n".encode())
                for index, path in enumerate(transaction_paths)
            ],
            transaction_originals,
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

    def observe_preflight(command: list[str], *_args: object) -> object:
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

    def observe_output_parent(command: list[str], *_args: object) -> str:
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
        {},
    )
    if returned != campaign_output / "mutants.out/outcomes.json":
        raise AssertionError(f"unexpected campaign outcome path: {returned}")

    def observe_cross_package(command: list[str], *_args: object) -> str:
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
        {},
    )
    if cross_package_returned != cross_package_output / "mutants.out/outcomes.json":
        raise AssertionError(
            f"unexpected cross-package outcome path: {cross_package_returned}"
        )

    duplicate_native = copy.deepcopy(runner_native)
    duplicate_native["span"]["start"]["line"] = 2
    duplicate_native["span"]["end"]["line"] = 2
    try:
        checker.select_native_mutant(
            [runner_native, duplicate_native], runner_campaign, campaign_source
        )
    except checker.EvidenceError as error:
        if "resolved to 2" not in str(error):
            raise AssertionError(f"unexpected ambiguity rejection: {error}") from error
    else:
        raise AssertionError("ambiguous semantic selector passed preflight")

    ordinal_campaign = copy.deepcopy(runner_campaign)
    ordinal_campaign["mutant"]["occurrence"] = 2
    selected = checker.select_native_mutant(
        [runner_native, duplicate_native], ordinal_campaign, campaign_source
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
        [fallback_native], fallback_campaign, campaign_source
    )
    try:
        checker.require_statically_viable_mutant(fallback, fallback_campaign)
    except checker.EvidenceError as error:
        if "not statically viable" not in str(error):
            raise AssertionError(f"unexpected viability rejection: {error}") from error
    else:
        raise AssertionError("Default-based FnValue fallback passed preflight")

    campaign_output = temp / "corrupt-campaign-output"

    def leave_source_changed(command: list[str], *args: object) -> str:
        observed = observe_output_parent(command, *args)
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
            {},
        )
    except checker.EvidenceError as error:
        if "left the source changed" not in str(error):
            raise AssertionError(f"unexpected source-integrity rejection: {error}") from error
    else:
        raise AssertionError("in-place mutation left changed source without rejection")

print("Security adversarial evidence gate contract passed")
PY
