#!/usr/bin/env python3
"""Seal the locally verified P4 package only after every required gate passed."""
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
    counts = {"rust_tests_passed": sum(int(m[0]) for m in matches),
            "rust_tests_failed": sum(int(m[1]) for m in matches),
            "rust_tests_ignored": sum(int(m[2]) for m in matches),
            "rust_test_binaries": len(matches)} if matches else {}
    python = re.search(r"(?:^|\s)(\d+) passed in [\d.]+s", text)
    typescript = re.search(r"Tests\s+(\d+) passed", text)
    if python:
        counts["python_tests_passed"] = int(python[1])
    if typescript:
        counts["typescript_tests_passed"] = int(typescript[1])
    return counts


def main() -> None:
    spec = importlib.util.spec_from_file_location("p4_gates", PHASE / "evidence/run-gates.py")
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
        if name in {"native", "p1-native", "p2-native", "p3-native", "owning-tests",
                    "store-native", "store-ordering", "store-schema", "store-regression",
                    "conformance-lib", "kernel-lib"} and not check.get("rust_tests_passed", 0):
            raise ValueError("required filtered Rust gate ran no passing tests: " + name)
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
            raise ValueError("historical P3 artifact drift")
    if (sha(PHASE / baseline["archive"]) != baseline["archive_sha256"]
            or sha(PHASE.parent / "p3/source-inventory.json") != baseline["p3_source_inventory_sha256"]):
        raise ValueError("historical P3 source baseline drift")
    for overlay in ["sdks/typescript/node_modules", "sdks/typescript/scripts/node_modules",
                    "sdks/typescript/packages/node-http/node_modules",
                    "sdks/typescript/packages/conformance/node_modules"]:
        if (ROOT / overlay).exists() or (ROOT / overlay).is_symlink():
            raise ValueError("temporary tool overlay remains: " + overlay)
    coverage = json.loads((PHASE / "requirements-coverage.json").read_text())
    architecture = json.loads((ROOT / "docs/architecture/recoverable-agent-runtime/requirements.json").read_text())
    ids = {r["id"] for r in architecture["requirements"] if r["phase"] == "P4"}
    if coverage["count"] != 13 or {r["id"] for r in coverage["requirements"]} != ids:
        raise ValueError("P4 requirement coverage incomplete")
    for requirement in coverage["requirements"]:
        for entry in requirement["sources"] + requirement["acceptance_tests"]:
            if entry["anchor"] not in (ROOT / entry["path"]).read_text():
                raise ValueError("source acceptance anchor drift")
        if not all((PHASE / evidence).is_file() for evidence in requirement["evidence"]):
            raise ValueError("acceptance evidence absent")
    changed = subprocess.check_output(["git", "diff", "--name-only", "HEAD", "--"], cwd=ROOT, text=True).splitlines()
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
    paths = sorted({p for p in changed + untracked if (ROOT / p).is_file()
                    and not p.startswith("docs/architecture/recoverable-agent-runtime/implementation/")
                    and "node_modules" not in Path(p).parts})
    old_hashes = {r["path"]: r["sha256"] for r in baseline["p3_sources"]}
    delta = [p for p in paths if old_hashes.get(p) != sha(ROOT / p)]
    authored = [p for p in delta if p.endswith(".rs") and "_generated" not in Path(p).parts]
    inputs = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
              "fixtures/recovery-portable-consumer/Cargo.toml", "fixtures/recovery-portable-consumer/Cargo.lock",
              "sdks/typescript/package.json", "sdks/typescript/package-lock.json",
              "sdks/typescript/scripts/package.json", "sdks/typescript/scripts/package-lock.json",
              "sdks/python/chio-sdk-python/pyproject.toml"]
    inventory = {"schema": "chio.recovery-p4-source-inventory.v1", "phase": "P4",
                 "source_base": head, "baseline_phase": "P3", "baseline_source_count": len(old_hashes),
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
        ("P4-01", "Closed artifact, provenance, release, certificate and checkpoint contracts", ["ART-01", "CON-09"]),
        ("P4-02", "Durable publication, quarantine and exact reconciliation", ["ART-02", "ART-03", "ART-11"]),
        ("P4-03", "Audience-scoped opaque references and fresh mediated native reads", ["ART-04", "ART-10", "ART-12"]),
        ("P4-04", "Provenance-preserving copy, signed export/import and exact adoption", ["ART-05", "ART-06", "ART-08", "CON-09"]),
        ("P4-05", "Labeled checkpoint CAS, model context binding and monotone restore", ["ART-07", "ART-08", "ART-12"]),
        ("P4-06", "Retention, native live pins, generation-barrier GC and permanent tombstones", ["ART-09"]),
        ("P4-07", "Native faults/races/restart/refusal, portable acceptance and complete source review", [r["id"] for r in json.loads((PHASE / "requirements-coverage.json").read_text())["requirements"]]),
    ]
    ids = [r["id"] for r in json.loads((PHASE / "requirements-coverage.json").read_text())["requirements"]]
    report = {
        "schema": "chio.recovery-p4-verification.v1", "phase": "P4", "title": "Durable knowledge", "status": STATUS,
        "recorded_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_base": head,
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
        "working_tree_changes_committed": False, "architecture_revision": 3,
        "scope": "Local host-private Unix SQLite process artifacts, same-authority mediated release/restore, signed exact-content certificates/archives, permanent evidence retention and generation-safe collection. Trusted host/selected sink setup remains explicit. No filesystem/object-store streams, cross-process transfer, live provider, hosted CI, production release or scale qualification.",
        "confidence": "high within the declared locally verified supported phase profile",
        "review": {"reviewer": "Codex", "review_kind": "complete source self-review", "independent_human_signoff": False,
                   "all_handwritten_changes_reviewed": True, "schemas_generated_boundaries_sdk_and_manifests_reviewed": True,
                   "handwritten_rust_sources": len(authored), "phase_changed_source_paths": len(delta),
                   "reviewed_rust_sources": [row(p) for p in authored], "open_p0_findings": 0, "open_p1_findings": 0,
                   "severity_scope": "Reviewed P4 changes and declared supported local profile; unrelated workspace and broader qualification are separate.", "report": "REVIEW.md"},
        "tasks": [{"id": id_, "title": title, "obligations": obligations, "status": STATUS} for id_, title, obligations in tasks],
        "requirements": {"count": 13, "ids": ids, "status": "all_implemented_and_local_phase_acceptance_passed", "coverage": "requirements-coverage.json"},
        "bounds": {"artifact_bytes": 1048576, "direct_dependencies": 16,
                   "dependency_traversal_versions": 64, "archive_versions": 16,
                   "host_recipients": 16, "checkpoint_roots": 8, "model_contexts": 8,
                   "model_side_files": 8, "wire_bytes": 65536, "protected_record_bytes": 262144,
                   "shared_pure_work_units": 4096, "certificate_lifetime_ms": 60000,
                   "publication_versions": 512, "knowledge_history_events": 4096,
                   "combined_native_history_events": 65536, "combined_native_history_bytes": 67108864},
        "source": {"inventory": "source-inventory.json", "inventory_sha256": sha(inventory_path),
                   "archive": "evidence/current-source.tar.gz", "archive_sha256": sha(archive_path),
                   "baseline": "source-baseline.json", "baseline_sha256": sha(PHASE / "source-baseline.json"),
                   "p3_baseline_archive": baseline["archive"], "p3_baseline_archive_sha256": baseline["archive_sha256"],
                   "p3_verification": "../p3/verification.json", "p3_verification_sha256": baseline["p3_verification_sha256"],
                   "p3_source_inventory_sha256": baseline["p3_source_inventory_sha256"]},
        "checks": checks,
        "qualification_limits": [
            "Supported artifact backend is host-private Unix SQLite with bounded immutable blobs and buffered delivery. Arbitrary filesystem/object-store paths, writable aliases, non-Unix enforcement and chunked streams refuse or are absent.",
            "Archive import/restore is restricted to the same process, tenant, authority domain and exact retained native provenance. No cross-process/domain transfer qualification.",
            "All checkpoint revisions, evidence/native pins, receipt provenance and ownership tombstones are retained permanently. No history pruning/unpinning; bounded exhaustion refuses. No provider-copy recall or cryptographic erasure claim.",
            "Model contexts are retained local provider/account/conversation/cache/side-file envelopes. Outbound provider requests still need their native effect contract; no live provider/cache lifecycle qualification.",
            "Required store gates cover native participant state, global commit order, schema, focused restoring regression and doctests. Required kernel library excludes exactly the same 12 unchanged payment listener tests that fail socket EPERM in immutable P3 evidence. No unfiltered full-workspace/kernel/store green claim or substituted distinct-device Linux anchor.",
            "Failed exploratory API/lint/test-fixture/codegen/cache attempts are retained as diagnostics; only final actual required successful gates qualify P4. Immutable P3 broad-run failures remain preserved.",
            "Offline Node cache used Vitest 3.2.6 and esbuild 0.27.7, differing from unchanged Vitest 4.1.11/esbuild 0.28.1 lock pins. No exact clean-install or hosted CI qualification. TypeScript 5.7.3, AJV 8.20.0 and schema generator 15.0.4 used; current workspace SDK source was selected.",
            "Complete source self-review is source-bound; no independent human signoff, Kani run, Linux confinement, comparative scale/performance, hosted CI, live gateway/provider or production deployment qualification.",
        ],
        "next_phase": {"id": "P5", "title": "Confined returns", "scope": "Host-issued lineage boundaries, enforced cage/broker launch, bounded parent returns and mediation of every enabled return, error, log and stream channel."},
        "phase_documents": artifacts(PHASE, {"verification.json"}),
        "evidence_artifacts": artifacts(PHASE / "evidence", set()),
    }
    write(PHASE / "verification.json", report)
    print(f"Sealed P4: {len(module.GATES)} required passed gates, 7 tasks, 13 obligations, "
          f"{len(authored)} reviewed Rust sources, {len(paths)} joined sources")


if __name__ == "__main__":
    main()
