#!/usr/bin/env python3
"""Require one completed Kani proof after a successful compiler process.

This checks the pinned default text format. It is not proof replay or a
substitute for checking the actual cargo-kani exit status in the caller.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


ANSI_SGR = re.compile(r"\x1b\[[0-9;]*m")
SUMMARY = re.compile(
    r"^Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total\.$",
    re.MULTILINE,
)


def check_result(text: str, harness: str) -> None:
    """Reject empty, ambiguous, failed, or compiler-error output."""
    text = ANSI_SGR.sub("", text)
    if re.search(r"(?im)^.*(?:internal compiler error|unexpectedly panicked|"
                 r"VERIFICATION:-?\s*FAILED|^error:|^error\[)", text):
        raise ValueError("Kani output contains a compiler or verification failure")
    selected = re.findall(r"^(?:Thread [0-9]+: )?Checking harness (.+)\.\.\.$", text, re.MULTILINE)
    if selected != [harness]:
        raise ValueError("Kani did not check exactly the requested harness")
    if SUMMARY.findall(text) != [("1", "0", "1")]:
        raise ValueError("Kani did not complete exactly one successful proof")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", required=True)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        check_result(args.log.read_text(encoding="utf-8"), args.harness)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"check-kani-harness-result: {error}; proof remains unproved", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
