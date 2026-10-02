#!/usr/bin/env python3
"""Compile and run the bounded architecture models; retain source-bound evidence."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
TOOLCHAIN = "+1.94.1"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    if result.returncode != 0:
        raise SystemExit(f"Failed: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def main():
    sources = sorted(ROOT.glob("*.rs"))
    run(["rustfmt", TOOLCHAIN, "--edition", "2021", "--check", *map(str, sources)])
    compiler = run(["rustc", TOOLCHAIN, "-Vv"])
    outputs = []
    with tempfile.TemporaryDirectory(prefix="chio-architecture-model-") as directory:
        for name, entry, output in [
            ("ownership", "recovery.rs", "results.txt"),
            ("review", "review.rs", "review-results.txt"),
            ("third", "third.rs", "third-results.txt"),
        ]:
            binary = str(Path(directory) / name)
            run(["rustc", TOOLCHAIN, "--edition", "2021", "-D", "warnings", entry, "-o", binary])
            result = run([binary])
            outputs.append((name, entry, output, result))
    # Publish evidence only after every binary completes successfully.
    for _, _, output, result in outputs:
        (ROOT / output).write_text(result)
    evidence = {
        "schema": "chio.recovery-architecture-model-evidence.v1",
        "scope": "Bounded abstract protocols only; no production qualification",
        "compiler": compiler,
        "toolchain": TOOLCHAIN,
        "edition": "2021",
        "warnings_denied": True,
        "formatting_checked": True,
        "sources": [{"path": path.name, "sha256": sha256(path)}
                    for path in [*sources, ROOT / "run.py"]],
        "runs": [{"name": name, "entry": entry, "output": output,
                  "output_sha256": sha256(ROOT / output), "exit_code": 0}
                 for name, entry, output, _ in outputs],
    }
    (ROOT / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    for name, _, _, output in outputs:
        print(f"{name}: compiled and completed")
        for line in output.splitlines():
            if "BASELINE PASS" in line or "MUTATION REJECTED" in line or "CONTRACT PASS" in line:
                print(line)


if __name__ == "__main__":
    main()
