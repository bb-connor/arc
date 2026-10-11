#!/usr/bin/env python3
"""Bound the instrumented retention workload and preserve incomplete evidence."""
import argparse
from contextlib import suppress
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

TEST = "retention_workload_commits_are_serialized_on_writer"


def completed_cases(text):
    return [int(value) for value in re.findall(
        r"^retention diagnostic case=(\d+) phase=complete$", text, re.MULTILINE)]


def qualified(text, code, timeout, cases):
    return (not timeout and code == 0 and completed_cases(text) == list(range(cases))
            and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", text,
                          re.MULTILINE) is not None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cases", type=int, default=24)
    parser.add_argument("--sync-delay-ms", type=int, default=3)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    if not 1 <= args.cases <= 256 or not 0 <= args.sync_delay_ms <= 1000:
        parser.error("cases must be 1..256 and sync delay 0..1000 ms")
    if not 1 <= args.timeout_seconds <= 1800:
        parser.error("timeout must be 1..1800 seconds")
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(CHIO_RETENTION_DIAGNOSTIC_CASES=str(args.cases),
               CHIO_RETENTION_SYNC_DELAY_MS=str(args.sync_delay_ms))
    command = [str(binary), "--exact", TEST, "--nocapture"]
    result = dict(command=command, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  cases=args.cases, sync_delay_ms=args.sync_delay_ms,
                  timeout_seconds=args.timeout_seconds, timed_out=False,
                  workload="public-API retention operation model; ChaCha seed [7;32]",
                  provenance="caller-supplied executable; hash is not a source-build attestation")
    started = time.monotonic()
    log_path = args.output / "workload.log"
    with log_path.open("w") as log:
        child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True)
        try:
            result["exit_code"] = child.wait(timeout=args.timeout_seconds)
        except subprocess.TimeoutExpired:
            result["timed_out"] = True
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            result["exit_code"] = child.returncode
    text = log_path.read_text()
    result.update(seconds=round(time.monotonic()-started, 3),
                  completed_cases=completed_cases(text),
                  passed=qualified(text, result["exit_code"], result["timed_out"], args.cases))
    (args.output / "summary.json").write_text(json.dumps(result, indent=2)+"\n")
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
