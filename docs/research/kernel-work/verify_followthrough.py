#!/usr/bin/env python3
"""Execute Tasks 5-6 checks, or verify their retained source-bound records."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "docs/research/kernel-work/results/followthrough"
BASE = "188031256600903676eb69bda3144b9e8a1660da"
FAMILY = "labs/kernel-work-families/Cargo.toml"
PROCESS_TEST = "crates/kernel/chio-process/tests/cross_owner_recovery.rs"
WAIVER_TEST = "crates/kernel/chio-kernel/tests/durable_admission_sqlite/contractual_resolution.rs"
COMMANDS = [
    ("native-process", ["cargo", "test", "--locked", "-p", "chio-process", "--features", "worker-server",
                        "--test", "crash_recovery", "--test", "nonce_recovery", "--test", "aggregate_family",
                        "--test", "cross_owner_recovery", "--", "--nocapture"]),
    ("native-admission", ["cargo", "test", "--locked", "-p", "chio-kernel", "--test", "durable_admission_sqlite"]),
    ("native-lint", ["cargo", "clippy", "--locked", "-p", "chio-process", "--features", "worker-server",
                     "--test", "cross_owner_recovery", "--", "-D", "warnings"]),
    ("admission-lint", ["cargo", "clippy", "--locked", "-p", "chio-kernel", "--test", "durable_admission_sqlite", "--", "-D", "warnings"]),
    ("native-format", ["rustfmt", "--check", "--edition", "2021", PROCESS_TEST, WAIVER_TEST]),
    ("family-tests", ["cargo", "test", "--locked", "--manifest-path", FAMILY]),
    ("family-comparison", ["cargo", "run", "--locked", "--manifest-path", FAMILY]),
    ("family-lint", ["cargo", "clippy", "--locked", "--manifest-path", FAMILY, "--all-targets", "--", "-D", "warnings"]),
    ("family-format", ["cargo", "fmt", "--manifest-path", FAMILY, "--", "--check"]),
    ("prior-model", [sys.executable, "labs/kernel-work-composition/verify.py", "--check"]),
    ("prior-provenance", [sys.executable, "docs/research/kernel-work/verify_task1.py"]),
]


def digest(path):
    return hashlib.sha256(os.readlink(path).encode() if path.is_symlink() else path.read_bytes()).hexdigest()


def sources():
    # Bind the actual native dependency tree, including vendored patches, not
    # just the integration test. Exclude generated evidence to avoid a hash cycle.
    raw = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard",
                                   "crates", "third_party", "spec", ".cargo", "Cargo.toml", "Cargo.lock",
                                   "rust-toolchain.toml"], cwd=ROOT)
    files = {Path(p.decode()) for p in raw.split(b"\0") if p}
    aggregate = hashlib.sha256()
    for path in sorted(files):
        aggregate.update(str(path).encode() + b"\0" + digest(ROOT / path).encode() + b"\n")
    lab_files = [p for p in (ROOT / "labs/kernel-work-families").rglob("*")
                 if p.is_file() and "target" not in p.parts]
    lab_files += [ROOT / "docs/research/kernel-work/verify_followthrough.py",
                  ROOT / "docs/research/kernel-work/test_followthrough.py"]
    lab_files += [p for p in (ROOT / "labs/kernel-work-composition/src").rglob("*.rs")]
    lab_files += [ROOT / "labs/kernel-work-composition/Cargo.toml", ROOT / "labs/kernel-work-composition/Cargo.lock",
                  ROOT / "docs/research/kernel-work/fixtures.json"]
    # A successful prerequisite-check log is not the prerequisite's evidence.
    # Bind its manifest and complete declared source/output closure as well.
    prior_manifest = ROOT / "docs/research/kernel-work/results/model/verification.json"
    prior = json.loads(prior_manifest.read_text())
    lab_files.append(prior_manifest)
    lab_files += [ROOT / path for path in prior["sources"]]
    lab_files += [ROOT / item[stream] for item in prior["commands"] for stream in ["stdout", "stderr"]]
    package = ROOT / "docs/research/kernel-work"
    lab_files += list(package.glob("*.md"))
    lab_files += [package / name for name in ["verify_task1.py", "claim-register.json", "task1-sources.json",
                                             "recovery-baseline.json"]]
    return {"native_tree_sha256": aggregate.hexdigest(), "native_file_count": len(files),
            "files": {str(p.relative_to(ROOT)): digest(p) for p in sorted(set(lab_files))}}


def write_manifest(manifest):
    temporary = OUT / "verification.tmp"
    temporary.write_text(json.dumps(manifest, indent=2) + "\n")
    temporary.replace(OUT / "verification.json")


def check():
    m = json.loads((OUT / "verification.json").read_text())
    if m.get("complete") is not True or len(m["commands"]) != len(COMMANDS):
        raise ValueError("incomplete verification record")
    if m["sources"] != sources():
        raise ValueError("source bytes differ from tested record")
    for item, (name, argv) in zip(m["commands"], COMMANDS, strict=True):
        if item["name"] != name or item["argv"] != argv or item.get("exit_code") != 0:
            raise ValueError(f"failed or unexpected command: {name}")
        for stream in ["stdout", "stderr"]:
            if item[f"{stream}_sha256"] != digest(OUT / f"{name}.{stream}"):
                raise ValueError(f"changed output: {name}.{stream}")
    # Revalidate the cheap structural predicates too, including the frozen
    # manuscript and current links. This does not rerun tests or benchmarks.
    for name, argv in COMMANDS[-2:]:
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise ValueError(f"prerequisite failed: {name}: {result.stderr.strip()}")
    print(json.dumps({"verified": True, "commands": len(COMMANDS), "scope": "local tested profile only"}))


def record():
    OUT.mkdir(parents=True, exist_ok=True)
    m = {"schema": "chio.research.followthrough-verification.v1", "complete": False,
         "base": BASE, "head_at_start": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
         "sources": sources(), "rustc": subprocess.check_output(["rustc", "-Vv"], cwd=ROOT, text=True), "commands": []}
    write_manifest(m)
    for name, argv in COMMANDS:
        env = dict(os.environ, CHIO_CHECKOUT_ROOT=str(ROOT), CARGO_BUILD_JOBS="4",
                   CARGO_TARGET_DIR="/tmp/chio-paper-tooling-target" if name.startswith("family") else "/tmp/chio-paper-target")
        item = {"name": name, "argv": argv, "exit_code": None,
                "environment": {key: env[key] for key in ["CHIO_CHECKOUT_ROOT", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR"]}}
        m["commands"].append(item)
        write_manifest(m)
        start = time.monotonic()
        with (OUT / f"{name}.stdout").open("w") as stdout, (OUT / f"{name}.stderr").open("w") as stderr:
            try:
                item["exit_code"] = subprocess.run(argv, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, timeout=1200).returncode
            except subprocess.TimeoutExpired:
                item["exit_code"] = 124
        item["elapsed_seconds"] = round(time.monotonic() - start, 3)
        for stream in ["stdout", "stderr"]:
            item[f"{stream}_sha256"] = digest(OUT / f"{name}.{stream}")
        write_manifest(m)
        print(f"{name}: exit {item['exit_code']}", flush=True)
        if item["exit_code"] != 0:
            return item["exit_code"]
    if m["sources"] != sources():
        raise ValueError("source changed during verification")
    m["complete"] = True
    write_manifest(m)
    check()
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--record", action="store_true")
    group.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.record:
        raise SystemExit(record())
    check()
