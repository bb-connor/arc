#!/usr/bin/env python3
"""Seal the locally verified P3 package only after every required gate passed."""
from __future__ import annotations

import datetime
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[6]
PHASE = Path(__file__).resolve().parent.parent
STATUS = "implemented_locally_verified_and_reviewed"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def row(path: str) -> dict:
    return {"path": path, "sha256": sha(ROOT / path)}


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def test_counts(text: str) -> dict:
    matches = re.findall(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", text)
    return {"rust_tests_passed": sum(int(m[0]) for m in matches),
            "rust_tests_failed": sum(int(m[1]) for m in matches),
            "rust_tests_ignored": sum(int(m[2]) for m in matches),
            "rust_test_binaries": len(matches)} if matches else {}


def main() -> None:
    spec = importlib.util.spec_from_file_location("p3_gates", PHASE / "evidence/run-gates.py")
    if spec is None or spec.loader is None:
        raise ValueError("gate runner absent")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    checks = []
    for name, (command, cwd, _) in module.GATES.items():
        result = PHASE / "evidence" / (name + ".result.json")
        check = json.loads(result.read_text())
        if (check["status"] != "passed" or check["exit_code"] != 0
                or check["actual_command"] != command or check["cwd"] != cwd
                or sha(PHASE / check["log"]) != check["log_sha256"]):
            raise ValueError("required gate incomplete or drifted: " + name)
        check.update(test_counts((PHASE / check["log"]).read_text()))
        checks.append(check)
    for result in sorted((PHASE / "evidence").glob("*.result.json")):
        check = json.loads(result.read_text())
        if check["id"] not in module.GATES:
            if check["required_for_local_phase_acceptance"]:
                raise ValueError("unregistered required gate")
            if sha(PHASE / check["log"]) != check["log_sha256"]:
                raise ValueError("diagnostic log drift")
            check.update(test_counts((PHASE / check["log"]).read_text()))
            checks.append(check)

    baseline = json.loads((PHASE / "source-baseline.json").read_text())
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if head != baseline["source_base"]:
        raise ValueError("source base changed")
    for old in baseline["baseline_phase_documents"]:
        if sha(ROOT / old["path"]) != old["sha256"]:
            raise ValueError("historical P2 artifact drift")
    changed = subprocess.check_output(["git", "diff", "--name-only", "HEAD", "--"], cwd=ROOT, text=True).splitlines()
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
    paths = sorted({p for p in changed + untracked if (ROOT / p).is_file()
                    and not p.startswith("docs/architecture/recoverable-agent-runtime/implementation/")
                    and "node_modules" not in Path(p).parts})
    old_hashes = {r["path"]: r["sha256"] for r in baseline["p2_sources"]}
    delta = [p for p in paths if old_hashes.get(p) != sha(ROOT / p)]
    authored = [p for p in delta if p.endswith(".rs") and "_generated" not in Path(p).parts]
    inputs = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
              "fixtures/recovery-portable-consumer/Cargo.toml", "fixtures/recovery-portable-consumer/Cargo.lock",
              "sdks/typescript/package.json", "sdks/typescript/package-lock.json",
              "sdks/typescript/scripts/package.json", "sdks/typescript/scripts/package-lock.json",
              "sdks/python/chio-sdk-python/pyproject.toml"]
    inventory = {"schema": "chio.recovery-p3-source-inventory.v1", "phase": "P3",
                 "source_base": head, "baseline_phase": "P2", "baseline_source_count": len(old_hashes),
                 "joined_changed_sources": [row(p) for p in paths],
                 "phase_changed_sources": [row(p) for p in delta],
                 "authored_rust_phase_sources": authored, "build_inputs": [row(p) for p in inputs]}
    inventory_path = PHASE / "source-inventory.json"
    write(inventory_path, inventory)

    archive_path = PHASE / "evidence/current-source.tar.gz"
    with archive_path.open("wb") as file, gzip.GzipFile(fileobj=file, mode="wb", mtime=0, filename="") as gz:
        with tarfile.open(fileobj=gz, mode="w") as archive:
            for name in sorted(set(paths + inputs + [str(inventory_path.relative_to(ROOT))])):
                data = (ROOT / name).read_bytes()
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(data))

    def artifacts(directory: Path, exclusions: set[str]) -> list[dict]:
        return [{"path": str(path.relative_to(PHASE)), "sha256": sha(path)}
                for path in sorted(directory.iterdir()) if path.is_file() and path.name not in exclusions]

    tasks = [
        ("P3-01", "Signed contracts, complete coverage, selectors and registry generations", ["CON-01", "CON-02", "CON-03", "CON-11"]),
        ("P3-02", "Scoped complete ACL evidence, annotator powers and influence", ["CON-04", "CON-05", "CON-06", "CON-07"]),
        ("P3-03", "Independent exact-action endorsement and native one-shot consumption", ["SEC-11", "CON-07"]),
        ("P3-04", "Exact native transformations, alternate destinations and withholding", ["CON-04", "CON-08", "CON-10", "REC-13", "REC-17"]),
        ("P3-05", "Bounded plans, materialization and historical/current/held prerequisites", ["REC-12", "REC-17", "CON-13"]),
        ("P3-06", "Fresh physical native capture, dispatch and release for support read and issue creation", ["SEC-11", "CON-02", "CON-04", "CON-05", "CON-08", "CON-10", "CON-11", "CON-13"]),
        ("P3-07", "Shared wire/native/refusal/restart/portability acceptance and complete source review", [r["id"] for r in json.loads((PHASE / "requirements-coverage.json").read_text())["requirements"]]),
    ]
    ids = [r["id"] for r in json.loads((PHASE / "requirements-coverage.json").read_text())["requirements"]]
    report = {
        "schema": "chio.recovery-p3-verification.v1", "phase": "P3", "title": "Semantic remedies", "status": STATUS,
        "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_base": head,
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
        "working_tree_changes_committed": False, "architecture_revision": 3,
        "scope": "Local sequential native support-read, issue-creation and field-projection semantic profiles, protected ACL/endorsement/prerequisite state and pure bounded contracts. Trusted gateway/host setup remains explicit. No live provider, hosted CI, production release or scale qualification.",
        "confidence": "high within the declared locally verified supported phase profile",
        "review": {"reviewer": "Codex", "review_kind": "complete source self-review", "independent_human_signoff": False,
                   "all_handwritten_changes_reviewed": True, "schemas_generated_boundaries_sdk_and_manifests_reviewed": True,
                   "handwritten_rust_sources": len(authored), "phase_changed_source_paths": len(delta),
                   "reviewed_rust_sources": [row(p) for p in authored], "open_p0_findings": 0, "open_p1_findings": 0,
                   "severity_scope": "Reviewed P3 changes and declared supported local profile; unrelated workspace and broader qualification are separate.", "report": "REVIEW.md"},
        "tasks": [{"id": id_, "title": title, "obligations": obligations, "status": STATUS} for id_, title, obligations in tasks],
        "requirements": {"count": 15, "ids": ids, "status": "all_implemented_and_local_phase_acceptance_passed", "coverage": "requirements-coverage.json"},
        "bounds": {"packages_operations_routes_steps_selectors": 16, "step_dependencies": 8,
                   "assertions_projection_fields": 8, "aggregate_observed_facts": 32, "shared_pure_work_units": 4096,
                   "semantic_lifetime_ms": 60000, "wire_provider_bytes": 65536, "protected_record_bytes": 262144,
                   "connector_owned_slots": 8, "http_total_timeout_secs": 10, "http_connect_timeout_secs": 3},
        "source": {"inventory": "source-inventory.json", "inventory_sha256": sha(inventory_path),
                   "archive": "evidence/current-source.tar.gz", "archive_sha256": sha(archive_path),
                   "baseline": "source-baseline.json", "baseline_sha256": sha(PHASE / "source-baseline.json"),
                   "p2_baseline_archive": baseline["archive"], "p2_baseline_archive_sha256": baseline["archive_sha256"],
                   "p2_verification": "../p2/verification.json", "p2_verification_sha256": baseline["p2_verification_sha256"],
                   "p1_verification": "../p1/verification.json", "p1_verification_sha256": baseline["p1_verification_sha256"]},
        "checks": checks,
        "qualification_limits": [
            "Broad conformance listener attempt: six tiny_http bind EPERM failures; separately retained as failed and not required local profile evidence.",
            "Broad owning kernel run: 1448 kernel library tests passed, 12 unchanged payment listener tests failed EPERM; required kernel-lib explicitly filters only those exact names. No unfiltered kernel green claim.",
            "Broad store run: 1786 passed, 45 failed, 4 ignored; 29 unavailable separate Linux /dev/shm anchor fixtures, 14 macOS path-alias failures and 2 generic native InvalidData egress failures. Unchanged isolated egress diagnostics passed. A corrected component passed 1802 supported store library tests with 4 ignored and 29 exact filters; its aggregate later failed 11 remote-delivery cases with socket EPERM and remains a failed attempt. Final required gates cover eight complete owning packages, focused store rollback regression and store doctests alongside native P3/P2 tests. No colocated anchor substitution, unfiltered-store, default-concurrency, remote-delivery or distinct-device qualification.",
            "Disk-exhaustion diagnostic runs are retained as failed. Clean required runs followed worktree-only incremental-cache cleanup and restored headroom.",
            "Prior exploratory clock/late-capture refusals were not promoted to passing evidence; final complete native P3/P2 gates qualify only the declared local profile.",
            "Historical broad P1 stress and Node HTTP socket failures remain in immutable P2 evidence; no full-workspace or all socket-suite green claim.",
            "Offline Vitest/esbuild cache versions differ from unchanged lock pins; exact clean-install and hosted CI qualification are unavailable.",
            "Trusted gateway must independently enforce its declared account/resource and atomic provider precondition contract; no live vendor or network qualification.",
            "No Linux confinement, Kani execution, comparative scale/performance or production release qualification.",
        ],
        "next_phase": {"id": "P4", "title": "Durable knowledge", "scope": "Mediated artifact publication/read, labeled checkpoints and model contexts, restore/export, retention, adoption and safe garbage collection."},
        "phase_documents": artifacts(PHASE, {"verification.json"}),
        "evidence_artifacts": artifacts(PHASE / "evidence", set()),
    }
    write(PHASE / "verification.json", report)
    print(f"Sealed P3: {len(module.GATES)} required passed gates, 7 tasks, 15 obligations, "
          f"{len(authored)} reviewed Rust sources, {len(paths)} joined sources")


if __name__ == "__main__":
    main()
