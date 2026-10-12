#!/usr/bin/env python3
"""Run authored, model-free probes without changing the upstream checkout."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time

PIN = "a96f87d1fec900caf890f14342a089a32b3bfaff"
HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=HERE.parent / "evidence")
    args = parser.parse_args()
    source, binary = args.source.resolve(), args.binary.resolve()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if head != PIN:
        raise SystemExit(f"Expected pinned source {PIN}, got {head}")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=source, text=True).strip():
        raise SystemExit("The upstream checkout must be clean for this pinned experiment")
    args.output.mkdir(parents=True, exist_ok=True)
    results = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "source": PIN,
        "source_clean": True,
        "binary_sha256": hashlib.file_digest(binary.open("rb"), "sha256").hexdigest(),
        "platform": platform.platform(),
        "build": "debug, debug information disabled; not a release benchmark",
        "limits": "No model calls, real external effects, live Claude/kagent session, or Linux confinement execution.",
        "runs": [],
    }

    def run(name, command, **kwargs):
        started = time.perf_counter()
        completed = subprocess.run(command, text=True, capture_output=True, **kwargs)
        elapsed = time.perf_counter() - started
        (args.output / f"{name}.log").write_text(completed.stdout + completed.stderr)
        results["runs"].append({"name": name, "command": command,
                               "exit_code": completed.returncode,
                               "elapsed_seconds": round(elapsed, 3)})
        if completed.returncode:
            raise RuntimeError(f"{name} failed; see {args.output / (name + '.log')}")
        return completed.stdout

    run("policy-description", [str(binary), "describe", "--check", "--config", str(HERE / "policy.toml")])
    run("authored-replay", [str(binary), "replay", "--verbose", "--config", str(HERE / "policy.toml"),
                           str(HERE / "confidentiality.appa"), str(HERE / "ordering.appa")])
    with tempfile.TemporaryDirectory(prefix="chio-appa-probe-") as scratch:
        root = Path(scratch)
        (root / "src").mkdir()
        shutil.copyfile(HERE / "file_restart.rs", root / "src/main.rs")
        # JSON string quoting is valid TOML basic-string quoting for these local paths.
        manifest = ('[package]\nname = "chio-appa-research-probe"\nversion = "0.1.0"\nedition = "2024"\n'
                    '[workspace]\n[dependencies]\n'
                    f'appa-engine = {{ path = {json.dumps(str(source / "appa-engine"))} }}\n'
                    f'appa-eventlog = {{ path = {json.dumps(str(source / "appa-eventlog"))} }}\n'
                    'serde_json = "1"\n')
        (root / "Cargo.toml").write_text(manifest)
        env = dict(os.environ, CARGO_TARGET_DIR=str(args.target.resolve()), CARGO_BUILD_JOBS="4",
                   CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0")
        output = run("file-ledger-recreation", ["cargo", "run", "--offline", "--manifest-path",
                     str(root / "Cargo.toml"), "--", str(root / "workspace")], env=env)
        shutil.copyfile(root / "Cargo.lock", args.output / "probe-Cargo.lock")
        results["file_ledger_probe"] = json.loads(output)
    (args.output / "experiments.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps({"passed": True, "runs": len(results["runs"]),
                      "evidence": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
