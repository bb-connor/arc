"""Recompute the complete phase exit from retained, current, owning evidence."""
import datetime
import json
import re

from catalog import GATES
from cohort_report import CAPABLE_COHORT, COHORTS, CORRECTED_COHORT, REVIEW_FIX_COHORT
from inventory import PHASE, ROOT, binding, phase_delta, qualification_sources, runtime_sources, sha
from package_audit import audit_final_qualification, audit_gate, refuse
from package_measurements import audit_adoption, audit_assurance, audit_performance, audit_performance_provenance
from package_sources import audit_archive, audit_predecessor

LINUX_GATES = {
    "native-recovery-full": ["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib", "recovery::tests::", "--", "--test-threads=1"],
    "store-full": ["cargo", "test", "--offline", "--locked", "-p", "chio-store-sqlite", "--lib", "--", "--test-threads=2"],
    "kernel-linux-full": ["cargo", "test", "--offline", "--locked", "-p", "chio-kernel", "--lib", "--", "--test-threads=2"],
    "cli-setup": ["cargo", "test", "--offline", "--locked", "-p", "chio-cli", "--test", "recovery_setup"],
}


def read(path):
    return json.loads(path.read_bytes())


def audit_local(runtime_binding):
    evidence = PHASE / "evidence"
    rows = read(evidence / "local-gates.json")
    refuse(len(rows) == len(GATES) == 33 and {row["gate"] for row in rows} == set(GATES), "gate_inventory")
    result = []
    for row in rows:
        command = GATES[row["gate"]]["command"]
        counts = audit_gate(row, GATES[row["gate"]], PHASE / row["log"], runtime_binding,
                            requires_tests=command[0] == "cargo" and "test" in command)
        text = (PHASE / row["log"]).read_text()
        if row["gate"] in {"python", "ts"}:
            pattern = r"(\d+) passed" if row["gate"] == "python" else r"Tests\s+(\d+) passed"
            match = re.search(pattern, text)
            refuse(match is not None and int(match.group(1)) > 0, "sdk_test_denominator")
            counts["sdk_passed"] = int(match.group(1))
        result.append({**row, "tests": counts})
    return result


def p5_linux_cases(text):
    cases = re.findall(r"^test .*::(p5_linux_[\w]+) \.\.\. ok$", text, re.MULTILINE)
    refuse(len(cases) == len(set(cases)) == 10, "linux_p5_denominator")
    return sorted(cases)


def audit_linux(runtime_binding):
    directory = PHASE / "evidence/final-linux-postfix"
    profile = read(directory / "profile.json")
    refuse(profile["host"]["system"] == "Linux" and profile["host"]["machine"] == "x86_64"
           and "release: 1.94.1" in profile["rustc"] and profile["build_profile"] == "debug"
           and profile["dev_debug"] == profile["test_debug"] == "0"
           and profile["default_stack"] is True and re.fullmatch(r"[a-f0-9]{64}", profile["cage_challenge"]),
           "linux_profile")
    predecessor = read(ROOT / "docs/architecture/recoverable-agent-runtime/implementation/p5/evidence/linux-acceptance.result.json")
    refuse(profile["measured_images"] == predecessor["measured_images"] and len(profile["measured_images"]) == 11
           and profile["cage_challenge"] != predecessor["cage_challenge"], "linux_images_challenge")
    rows = read(directory / "results.json")
    refuse(len(rows) == 4 and {row["gate"] for row in rows} == set(LINUX_GATES), "linux_gate_inventory")
    for row in rows:
        expected = {"command": LINUX_GATES[row["gate"]], "cwd": "."}
        counts = audit_gate(row, expected, directory / row["log"], runtime_binding, requires_tests=True)
        refuse(counts == {"passed": row["passed_tests"], "failed": row["failed_tests"], "ignored": row["ignored_tests"]},
               "linux_counts")
    native = (directory / "native-recovery-full.log").read_text()
    p5 = p5_linux_cases(native)
    original_log = ROOT / "docs/architecture/recoverable-agent-runtime/implementation/p5" / predecessor["log"]
    refuse(p5 == p5_linux_cases(original_log.read_text()), "linux_p5_case_identity")
    return {"profile": profile, "gates": rows, "p5_tests": sorted(p5),
            "tested_runtime_binding": runtime_binding, "current_runtime_binding": runtime_binding,
            "scope": "All four complete Linux suites rerun at the final runtime after the primary Rust fix, with default stack sizes and a fresh cage challenge. Earlier reviewed executions remain separately retained."}


def audit_coverage():
    coverage = read(PHASE / "requirements-coverage.json")
    architecture = read(ROOT / "docs/architecture/recoverable-agent-runtime/requirements.json")
    required = {row["id"] for row in architecture["requirements"] if row["phase"] == "P6"}
    refuse({row["id"] for row in coverage["requirements"]} == required and len(required) == 8,
           "requirement_inventory")
    for row in coverage["requirements"]:
        for entry in row["sources"] + row["acceptance_tests"]:
            refuse(entry["anchor"] in (ROOT / entry["path"]).read_text(), "requirement_anchor")
    return coverage


def audit_review(source_rows, delta):
    from review_acceptance import audit_primary_fix
    review = read(PHASE / "review-manifest.json")
    original = read(PHASE / "evidence/fresh-review-inputs.json")
    snapshot = read(PHASE / "source-snapshot.json")
    refuse(review["reviewed_sources"] == original["sources"] == snapshot["sources"]
           and review["reviewed_source_binding"] == binding(original["sources"])
           and review["reviewed_phase_delta"] == original["phase_delta"]
           and review["final_sources"] == source_rows
           and review["final_source_binding"] == binding(source_rows)
           and review["phase_delta"] == delta, "review_source_inventory")
    refuse(sha(PHASE / snapshot["archive"]) == snapshot["archive_sha256"], "original_review_archive")
    audit_archive(PHASE / snapshot["archive"], original["sources"])
    refuse(review["fresh_context"] is True and review["model"] == "gpt-6-astra"
           and review["open_p0"] == review["open_p1"] == 0
           and review["status"] == "reviewed_no_open_p0_p1", "review_gate")
    refuse(sha(PHASE / review["report"]) == review["report_sha256"], "review_report")
    refuse(sha(PHASE / review["original_report"]) == review["original_report_sha256"]
           and review["original_open_p0"] == 0 and review["original_open_p1"] == 2,
           "original_review_verdict")
    audit_primary_fix(review["primary_fix"], original["sources"], source_rows, PHASE, binding(runtime_sources()))
    return review


def build_record():
    predecessor = audit_predecessor()
    runtime = runtime_sources()
    runtime_binding = binding(runtime)
    manifest = read(PHASE / "evidence/live-manifest/manifest.json")
    capable_path = PHASE / "evidence/live-manifest-capable/manifest.json"
    capable = read(capable_path)
    corrected_path = PHASE / "evidence/live-manifest-corrected/manifest.json"
    corrected = read(corrected_path)
    fixed_path = PHASE / "evidence/live-manifest-final/manifest.json"
    fixed = read(fixed_path)
    refuse(runtime == fixed["sources"] and runtime_binding == fixed["source_binding"], "live_runtime_sources")
    archive = PHASE / "evidence/live-manifest/sources.tar.gz"
    audit_archive(archive, manifest["sources"])
    sources = qualification_sources()
    delta = phase_delta()
    snapshot = read(PHASE / "final-source-snapshot.json")
    refuse(snapshot["sources"] == sources and snapshot["source_binding"] == binding(sources), "source_snapshot")
    refuse(sha(PHASE / snapshot["archive"]) == snapshot["archive_sha256"], "source_archive_hash")
    audit_archive(PHASE / snapshot["archive"], sources)
    gates = audit_local(runtime_binding)
    linux = audit_linux(runtime_binding)
    names = COHORTS + (CAPABLE_COHORT, CORRECTED_COHORT, REVIEW_FIX_COHORT)
    rows = {name: [json.loads(line) for line in (PHASE / "evidence/live" / name / "results.jsonl").read_text().splitlines()]
            for name in names}
    exchanges = {name: PHASE / "evidence/live" / name for name in names}
    audit_archive(capable_path.parent / "sources.tar.gz", capable["sources"])
    audit_archive(corrected_path.parent / "sources.tar.gz", corrected["sources"])
    audit_archive(fixed_path.parent / "sources.tar.gz", runtime)
    report = audit_final_qualification(PHASE / "evidence/live-manifest/manifest.json", capable_path,
                        corrected_path, fixed_path, PHASE / "evidence/cohorts.json",
                        PHASE / "evidence/capable-cohort-declaration.json", PHASE / "evidence/corrected-cohort-declaration.json",
                        PHASE / "evidence/review-fix-cohort-declaration.json",
                        rows, exchanges, PHASE / "evidence/initial-interruption.json", PHASE / "evidence/prior-prompt-gaps.json")
    refuse(report == read(PHASE / "evidence/live-report.json"), "live_report_recomputation")
    interruption = read(PHASE / "evidence/initial-interruption.json")
    cohorts = read(PHASE / "evidence/cohorts.json")
    refuse(sha(PHASE / "evidence/live" / COHORTS[0] / "results.jsonl") == interruption["retained_rows_sha256"]
           and sha(PHASE / "evidence/cohorts-original-declaration.json") == cohorts["original_declaration_sha256"],
           "original_cohort_bytes")
    performance = audit_performance(read(PHASE / "evidence/performance.json"))
    performance_provenance = audit_performance_provenance(runtime)
    adoption = audit_adoption(read(PHASE / "adoption-metrics.json"))
    assurance = audit_assurance()
    coverage = audit_coverage()
    review = audit_review(sources, delta)
    from review_acceptance import audit_public_preflight
    preflight = audit_public_preflight(PHASE / "evidence/final-host-preflight", runtime_binding,
                                      fixed["authority_policy"])
    return {"schema": "chio.recovery-p6-verification.v1", "phase": "P6", "phase_accomplished": True,
            "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "locally_linux_and_finite_live_qualified", "runtime_source_binding": runtime_binding,
            "qualification_source_binding": binding(sources), "joined_sources": sources, "phase_delta": delta,
            "tasks_complete": [1, 2, 3, 4, 5], "requirements": coverage, "local_gates": gates,
            "linux": linux, "live": report, "performance": performance, "performance_provenance": performance_provenance,
            "adoption": adoption, "assurance": assurance,
            "review": review, "public_native_preflight":preflight, "preserved_p5": predecessor,
            "next_work": "Operational/release qualification or separately specified provider/platform expansion; the roadmap defines no P7.",
            "limits": manifest["unsupported"] + ["Three repetitions per stratum do not establish general utility superiority.",
                      "No production migration, supervisory code savings, or account-independent availability claim.",
                      "Interrupted unknown measurements cannot establish safety for all 480 planned trials."]}
