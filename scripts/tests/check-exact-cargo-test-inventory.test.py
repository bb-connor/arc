#!/usr/bin/env python3
"""Mutation self-test for the exact Rust inventory verifier."""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts/check-exact-cargo-test-inventory.py"


def invoke(
    listing: str,
    run: str,
    *,
    allow_filtered: bool = False,
    digest_mode: bool = False,
) -> int:
    with tempfile.TemporaryDirectory(prefix="chio-exact-inventory-") as directory:
        root = Path(directory)
        list_path = root / "list.out"
        run_path = root / "run.out"
        list_path.write_text(listing, encoding="utf-8")
        run_path.write_text(run, encoding="utf-8")
        command = [
            "python3",
            str(VERIFIER),
            "--label",
            "self-test",
            "--list-output",
            str(list_path),
            "--run-output",
            str(run_path),
        ]
        if allow_filtered:
            command.append("--allow-filtered")
        if digest_mode:
            digest = hashlib.sha256(b"alpha\nbeta\n").hexdigest()
            command.extend(["--expected-count", "2", "--expected-sha256", digest])
        else:
            command.extend(["alpha", "beta"])
        return subprocess.run(command, check=False).returncode


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


LISTING = "alpha: test\nbeta: test\n"
RUN = """running 2 tests
test alpha ... ok
test beta ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""


def main() -> int:
    require(invoke(LISTING, RUN) == 0, "verifier rejected the valid fixture")
    require(
        invoke(LISTING, RUN, digest_mode=True) == 0,
        "verifier rejected the valid committed-inventory fixture",
    )
    require(
        invoke("alpha: test\ngamma: test\n", RUN, digest_mode=True) != 0,
        "verifier accepted a renamed committed inventory",
    )
    require(
        invoke("alpha: test\n", RUN, digest_mode=True) != 0,
        "verifier accepted a short committed inventory",
    )
    require(
        invoke("", RUN.replace("running 2 tests", "running 0 tests"), digest_mode=True)
        != 0,
        "verifier accepted a zero committed inventory",
    )
    require(
        invoke("alpha: test\n", RUN) != 0,
        "verifier accepted an inventory with a missing test",
    )
    require(
        invoke(LISTING + "gamma: test\n", RUN) != 0,
        "verifier accepted an inventory with an extra test",
    )
    require(
        invoke(LISTING, RUN.replace("test beta ... ok", "test gamma ... ok")) != 0,
        "verifier accepted a renamed executed test",
    )
    require(
        invoke(LISTING, RUN.replace("0 ignored", "1 ignored")) != 0,
        "verifier accepted an ignored test",
    )
    filtered = RUN.replace("0 filtered out", "4 filtered out")
    require(
        invoke(LISTING, filtered) != 0,
        "verifier accepted filtered tests without an explicit allowance",
    )
    require(
        invoke(LISTING, filtered, allow_filtered=True) == 0,
        "verifier rejected filtered tests with an explicit allowance",
    )
    require(
        invoke("alpha: test\nalpha: test\nbeta: test\n", RUN) != 0,
        "verifier accepted a duplicate listed test",
    )
    print("exact Cargo test inventory verifier self-test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
