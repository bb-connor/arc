#!/usr/bin/env python3
"""Compile and run the bounded architecture models; retain source-bound evidence."""

import hashlib
import json
import argparse
import os
from pathlib import Path
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parent
TOOLCHAIN = "+1.94.1"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, output_root, name, commands, cwd=ROOT):
    started = time.monotonic()
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    log = output_root / (name + ".log")
    log.write_text(result.stdout + result.stderr)
    commands.append({"name":name,"command":command,"cwd":str(cwd),"exit_code":result.returncode,
                     "seconds":round(time.monotonic()-started, 6),"log":log.name,"log_sha256":sha256(log)})
    if result.returncode != 0:
        raise SystemExit(f"Failed: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def capture_inputs(paths, destination):
    """Hash and compile the same captured bytes, independently of later live edits."""
    destination.mkdir(mode=0o700)
    rows = []
    parent = os.open(ROOT,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for path in paths:
            descriptor = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("model input is not a regular file")
                with os.fdopen(os.dup(descriptor),"rb") as stream:
                    data = stream.read()
                after = os.fstat(descriptor)
                located = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                identity = lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
                if identity(before) != identity(after) or identity(after) != identity(located):
                    raise ValueError("model input changed during capture")
            finally:
                os.close(descriptor)
            captured = destination / path.name
            with captured.open("xb") as output:
                output.write(data)
            captured.chmod(0o444)
            rows.append({"path":path.name,"sha256":hashlib.sha256(data).hexdigest()})
    finally:
        os.close(parent)
    destination.chmod(0o500)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True, help="fresh directory below the candidate's target directory")
    args = parser.parse_args()
    repository = ROOT.parents[3].resolve(strict=True)
    output_root = args.output.absolute()
    if output_root.exists() or output_root.is_symlink():
        parser.error("output already exists; retained evidence must not be overwritten")
    if ".." in output_root.parts:
        parser.error("output contains parent traversal")
    if not output_root.is_relative_to(repository / "target") or output_root == repository / "target":
        parser.error("output must be a fresh directory below the candidate's target directory")
    if (repository / "target").is_symlink():
        parser.error("output target directory is symbolic")
    existing = output_root.parent
    while not existing.exists():
        existing = existing.parent
    located = existing.resolve(strict=True)
    if located != repository and not located.is_relative_to(repository / "target"):
        parser.error("output parent escapes the candidate")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    output_root = output_root.parent.resolve(strict=True) / output_root.name
    if not output_root.is_relative_to(repository / "target") or output_root == repository / "target":
        parser.error("output must be a fresh directory below the candidate's target directory")
    output_root.mkdir(mode=0o700)
    commands = []
    sources = sorted(ROOT.glob("*.rs"))
    captured = output_root / "inputs"
    source_rows = capture_inputs([*sources, ROOT / "run.py"],captured)
    run(["rustfmt", TOOLCHAIN, "--edition", "2021", "--check", *[path.name for path in sources]],
        output_root, "format", commands, cwd=captured)
    compiler = run(["rustc", TOOLCHAIN, "-Vv"], output_root, "compiler", commands)
    outputs = []
    for name, entry, output in [
        ("ownership", "recovery.rs", "results.txt"),
        ("review", "review.rs", "review-results.txt"),
        ("third", "third.rs", "third-results.txt"),
    ]:
        binary = output_root / name
        run(["rustc", TOOLCHAIN, "--edition", "2021", "-D", "warnings", entry, "-o", str(binary)],
            output_root, "compile-"+name, commands, cwd=captured)
        binary.chmod(0o500)
        executable_sha256 = sha256(binary)
        result = run([str(binary)], output_root, "execute-"+name, commands)
        if sha256(binary) != executable_sha256:
            raise SystemExit("model executable changed during execution")
        outputs.append((name, entry, output, result, executable_sha256))
    # Publish evidence only after every binary completes successfully.
    for _, _, output, result, _ in outputs:
        (output_root / output).write_text(result)
    evidence = {
        "schema": "chio.recovery-architecture-model-evidence.v1",
        "scope": "Bounded abstract protocols only; no production qualification",
        "compiler": compiler,
        "toolchain": TOOLCHAIN,
        "edition": "2021",
        "warnings_denied": True,
        "formatting_checked": True,
        "commands":commands,
        "sources": source_rows,
        "input_snapshot":"inputs",
        "runs": [{"name": name, "entry": entry, "output": output,
                  "output_sha256": sha256(output_root / output), "exit_code": 0,
                  "executable":name,"executable_sha256":executable_sha256}
                 for name, entry, output, _, executable_sha256 in outputs],
    }
    current_rows = [{"path":path.name, "sha256":sha256(path)} for path in [*sources, ROOT / "run.py"]]
    if current_rows != source_rows or sorted(ROOT.glob("*.rs")) != sources:
        raise SystemExit("model source changed during execution")
    (output_root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    for name, _, _, output, _ in outputs:
        print(f"{name}: compiled and completed")
        for line in output.splitlines():
            if "BASELINE PASS" in line or "MUTATION REJECTED" in line or "CONTRACT PASS" in line:
                print(line)


if __name__ == "__main__":
    main()
