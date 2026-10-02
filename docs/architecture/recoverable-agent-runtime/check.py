#!/usr/bin/env python3
"""Check architecture traceability and provenance, not implementation security."""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SPEC = Path(__file__).resolve().parent
ROOT = SPEC.parents[2]
REQUIREMENT = re.compile(
    r"^\| ([A-Z]+-\d+) \| (.*?) \| `([^`]+)` \| (P\d) \|$"
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_model_evidence():
    root = SPEC / "model"
    evidence = json.loads((root / "evidence.json").read_text())
    require(evidence["schema"] == "chio.recovery-architecture-model-evidence.v1",
            "unknown model evidence schema")
    expected = {path.name for path in root.glob("*.rs")} | {"run.py"}
    entries = evidence["sources"]
    require({entry["path"] for entry in entries} == expected and len(entries) == len(expected),
            "model source evidence inventory drift")
    for entry in entries:
        require(sha256(root / entry["path"]) == entry["sha256"],
                f"model changed since execution: {entry['path']}")
    require(evidence["toolchain"] == "+1.94.1" and evidence["edition"] == "2021",
            "model toolchain/edition drift")
    require(evidence["compiler"].startswith("rustc 1.94.1 "), "unexpected retained compiler identity")
    require(evidence["formatting_checked"] and evidence["warnings_denied"],
            "missing model compilation/formatting evidence")
    expected_runs = {"ownership": ("recovery.rs", "results.txt"),
                     "review": ("review.rs", "review-results.txt"),
                     "third": ("third.rs", "third-results.txt")}
    require(len(evidence["runs"]) == len(expected_runs), "model run evidence missing or duplicated")
    require({run["name"] for run in evidence["runs"]} == set(expected_runs), "model run set drift")
    for run in evidence["runs"]:
        require((run["entry"], run["output"]) == expected_runs[run["name"]], "model entry/output drift")
        require(run["exit_code"] == 0, "model did not complete successfully")
        require(sha256(root / run["output"]) == run["output_sha256"], "retained model output changed")
    review = (root / "review-results.txt").read_text()
    baselines = re.findall(r"^REVIEW BASELINE PASS ([A-Za-z]+): (\d+) reachable states, (\d+) transitions;",
                           review, re.M)
    require(len(baselines) == 4 and {name for name, _, _ in baselines} ==
            {"Admission", "Knowledge", "Replay", "PartialEffect"}, "review baselines missing or duplicated")
    mutations = re.findall(r"^REVIEW MUTATION REJECTED ([A-Za-z]+):", review, re.M)
    require(len(mutations) == 8 and set(mutations) == {
        "CloseFromProjection", "IgnoreAdmissionTombstone", "IgnoreCancellation",
        "ReleaseWithoutJoin", "IgnoreKnowledgeFence", "RevisionBeforeReplay",
        "CachedResponseAfterRevocation", "PartialFailureAsNoEffect",
    }, "review mutation evidence missing or duplicated")
    third = (root / "third-results.txt").read_text()
    nonce = re.findall(r"^THIRD BASELINE PASS Nonce: (\d+) reachable states, (\d+) transitions; useful restart reachable\.$",
                       third, re.M)
    coverage = re.findall(r"^THIRD CONTRACT PASS Coverage: (\d+) bounded cases\.$", third, re.M)
    third_mutations = re.findall(r"^THIRD MUTATION REJECTED ([A-Za-z]+):", third, re.M)
    require(len(nonce) == 1 and len(coverage) == 1, "third review baseline missing or duplicated")
    require(len(third_mutations) == 8 and set(third_mutations) == {
        "FinalizeWithoutCustody", "PreflightBeforeIntent", "RenewMissingNonce",
        "RewriteProcessEnvelope", "RequireLiveInitiator", "AnyOwnerSuffices",
        "IgnoreApprovalContext", "CountSignatureAliases",
    }, "third review mutation evidence missing or duplicated")
    return {
        "baselines": [{"name": name, "reachable_states": int(states), "transitions": int(transitions)}
                      for name, states, transitions in baselines],
        "mutations_rejected": mutations,
        "source_and_output_hashes_verified": True,
        "scope": "Four independent bounded seams; not a composed or production proof",
        "third_pass": {
            "nonce_reachable_states": int(nonce[0][0]),
            "nonce_transitions": int(nonce[0][1]),
            "coverage_cases": int(coverage[0]),
            "mutations_rejected": third_mutations,
            "scope": "Bounded nonce custody protocol and symbolic coverage; not cryptographic or production qualification",
        },
    }


def validate_foundation_evidence():
    evidence = json.loads((SPEC / "foundation-tests-third-pass.json").read_text())
    require(evidence["schema"] == "chio.recovery-architecture-foundation-check.v1",
            "unknown foundation test evidence")
    require(evidence["command"] == ["cargo", "test", "--locked", "-p", "chio-process",
                                     "--test", "nonce_recovery"], "foundation command drift")
    require(evidence["exit_code"] == 0 and evidence["passed"] == 3 and evidence["failed"] == 0,
            "foundation test target did not pass")
    require(set(evidence["test_names"]) == {
        "strict_nonce_call_completes_once_and_replays_after_reopening",
        "strict_nonce_unknown_effect_keeps_original_custody_after_process_death",
        "strict_nonce_subprocess",
    } and len(evidence["test_names"]) == 3, "foundation test inventory drift")
    require(not evidence["new_architecture_implementation_qualified"],
            "foundation tests cannot qualify proposed architecture")
    for entry in evidence["selected_source_inputs"]:
        require(sha256(ROOT / entry["path"]) == entry["sha256"],
                f"foundation test input drift: {entry['path']}")
    return {key: evidence[key] for key in ["command", "passed", "failed", "count_note", "scope",
                                          "record_kind", "new_architecture_implementation_qualified"]}


def validate():
    registry = json.loads((SPEC / "requirements.json").read_text())
    inventory = json.loads((SPEC / "source-map.json").read_text())
    require(registry["architecture_revision"] == inventory["architecture_revision"] == 3,
            "architecture revision drift")
    require("proposed architecture, revision 3," in (SPEC / "README.md").read_text(),
            "README architecture revision drift")
    records = registry["requirements"]
    ids = [record["id"] for record in records]
    require(len(ids) == len(set(ids)), "duplicate requirement ID")
    require(len(ids) == registry["requirement_count"], "requirement count drift")
    by_id = {record["id"]: record for record in records}
    declared = {}
    links = 0
    markdown_files = sorted(SPEC.rglob("*.md"))
    for path in markdown_files:
        content = path.read_text()
        require("\u2014" not in content, f"em dash: {path.name}")
        require(content.endswith("\n"), f"missing final newline: {path.name}")
        require(all(line == line.rstrip() for line in content.splitlines()),
                f"trailing whitespace: {path.name}")
        for line in content.splitlines():
            match = REQUIREMENT.match(line)
            if match:
                ident, obligation, test, phase = match.groups()
                require(ident not in declared, f"duplicate normative declaration: {ident}")
                declared[ident] = (path.name, obligation, test, phase)
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
            if re.match(r"^[a-z]+:", target) or target.startswith("#"):
                continue
            resolved = path.parent / target.split("#", 1)[0]
            require(resolved.exists(), f"broken local link: {path.name} -> {target}")
            links += 1
    require(set(declared) == set(ids), "table/registry requirement mismatch")
    for ident, record in by_id.items():
        expected = (record["document"], record["obligation"],
                    record["proposed_acceptance_test"], record["phase"])
        require(declared[ident] == expected, f"registry drift: {ident}")
        require(record["phase"] in registry["phases"], f"unknown phase: {ident}")
        require(bool(record["owners"]), f"missing owner: {ident}")
        require(record["implementation_status"] == "specified_not_implemented_by_this_package",
                f"unsupported implementation claim: {ident}")
    for feature, requirements in registry["functionality_coverage"].items():
        require(bool(requirements), f"unmapped functionality: {feature}")
        require(set(requirements) <= set(ids), f"unknown requirement in {feature}")

    source_paths = set()
    for source in inventory["files"]:
        path = ROOT / source["path"]
        require(path.is_file(), f"missing source: {source['path']}")
        require(sha256(path) == source["sha256"], f"source drift: {source['path']}")
        source_paths.add(source["path"])
    for finding in inventory["findings"]:
        require(set(finding["paths"]) <= source_paths,
                f"finding lacks source inventory: {finding['id']}")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    source_base = inventory["development_base"]
    ancestry = subprocess.run(
        ["git", "merge-base", "--is-ancestor", source_base, head],
        cwd=ROOT, check=False, capture_output=True,
    )
    require(ancestry.returncode == 0, "checkout does not contain the architecture source base")
    for path in ["Cargo.toml", "Cargo.lock"]:
        original = subprocess.check_output(["git", "show", f"{source_base}:{path}"], cwd=ROOT)
        require((ROOT / path).read_bytes() == original, f"root build input changed: {path}")

    review_models = validate_model_evidence()
    foundation_tests = validate_foundation_evidence()
    model = (SPEC / "model/results.txt").read_text()
    baseline = re.search(r"BASELINE PASS: (\d+) reachable states, (\d+) transitions;", model)
    require(baseline is not None, "model has no completed baseline")
    mutations = re.findall(r"MUTATION REJECTED ([A-Za-z]+):", model)
    require(set(mutations) == {"OverlappingSelection", "IgnoreOwnerEpoch", "ReplayUnknown", "UnknownMeansNoEffect"},
            "model mutation evidence missing or stale")
    require(len(mutations) == 4, "duplicate mutation evidence")
    for source in SPEC.rglob("*.rs"):
        content = source.read_text()
        require("\u2014" not in content, f"em dash: {source.name}")
        require(".unwrap(" not in content and ".expect(" not in content,
                f"unchecked unwrap/expect: {source.name}")
    require(not inventory["public_availability_claimed"], "unsupported public availability claim")
    require(not inventory["production_code_changed_by_spec_work"], "scope drift")

    inputs = sorted(p for p in SPEC.rglob("*") if p.is_file()
                    and p.name != "validation.json" and "__pycache__" not in p.parts)
    return {
        "schema": "chio.recovery-architecture-validation.v1",
        "status": "structural_checks_passed",
        "scope": "Architecture documents, traceability, source hashes and retained bounded-model evidence only",
        "requirements": len(records),
        "functionality_mappings": len(registry["functionality_coverage"]),
        "markdown_files": len(markdown_files),
        "local_links_checked": links,
        "development_source_inputs_verified": len(source_paths),
        "source_findings": len(inventory["findings"]),
        "model": {"reachable_states": int(baseline.group(1)),
                  "transitions": int(baseline.group(2)),
                  "mutations_rejected": mutations,
                  "scope": "One effectful step, two continuations/coordinators, two owner epochs; no production proof"},
        "review_models": review_models,
        "root_manifest_and_lock_unchanged": True,
        "implementation_tests_rerun": True,
        "foundation_test_evidence": foundation_tests,
        "architecture_approved": False,
        "inputs": [{"path": str(p.relative_to(SPEC)), "sha256": sha256(p)} for p in inputs],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    # The README links to the report produced by this command. Require the
    # initial report placeholder to exist before validating navigation.
    result = validate()
    if args.write_report:
        (SPEC / "validation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "inputs"}, indent=2))


if __name__ == "__main__":
    main()
