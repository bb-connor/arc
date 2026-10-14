#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
import os
import re
import signal
import subprocess
import time

PROBE_TIMEOUT_SECONDS = 30
DRAIN_TIMEOUT_SECONDS = 5


def stop_probe(process):
    deadline = time.monotonic() + DRAIN_TIMEOUT_SECONDS
    failure = None
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        failure = "Kani toolchain probe group termination failed"
    try:
        process.communicate(timeout=max(0, deadline - time.monotonic()))
    except BaseException:
        failure = "Kani toolchain probe group drain failed"
    finally:
        for stream in [process.stdout, process.stderr]:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    failure = "Kani toolchain probe group drain failed"
        if process.returncode is None:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except BaseException:
                failure = "Kani toolchain probe group drain failed"
    if failure is not None:
        raise SystemExit(failure) from None


def probe_version():
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    process = None
    cleanup_required = True
    try:
        try:
            process = subprocess.Popen(
                ["cargo", "kani", "--version", "--verbose"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True,
            )
            stdout, stderr = process.communicate(timeout=max(0, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            raise SystemExit("Kani toolchain version probe failed") from None
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            pass
        except OSError:
            raise SystemExit("Kani toolchain probe group state is unknown") from None
        else:
            raise SystemExit("Kani toolchain version probe left descendants")
        cleanup_required = False
        return process.returncode, stdout, stderr
    finally:
        if process is not None and cleanup_required:
            stop_probe(process)


def main():
    expected_version = "0.68.0"
    if os.environ.get("CHIO_KANI_VERSION", expected_version) != expected_version:
        raise SystemExit("Kani toolchain check requires CHIO_KANI_VERSION=0.68.0")
    returncode, stdout, stderr = probe_version()
    lines = stdout.splitlines()
    if returncode != 0 or stderr or len(lines) != 3:
        raise SystemExit("Kani toolchain version probe did not match the pinned release")
    if re.fullmatch(r"Kani Rust Verifier 0\.68\.0(?: \([^()\r\n]+\))? \(cargo plugin\)", lines[0]) is None:
        raise SystemExit("Kani toolchain check requires Kani 0.68.0")
    if re.fullmatch(
        r"using rustc 1\.100\.0-nightly \(8925ea358 2026-08-20\) "
        r"\(commit 8925ea35 2026-08-20\) with LLVM [0-9]+(?:\.[0-9]+)+",
        lines[1],
    ) is None:
        raise SystemExit("Kani toolchain check requires the nightly-2026-08-21 compiler")
    if lines[2] != "CBMC 6.11.0":
        raise SystemExit("Kani toolchain check requires CBMC 6.11.0")
    print(stdout, end="")


if __name__ == "__main__":
    main()
PY
