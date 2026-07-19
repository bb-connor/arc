#!/usr/bin/env python3
"""Verify one Rust test target's exact listed and executed inventory."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path


ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def lines(path: Path) -> list[str]:
    return [
        ANSI_ESCAPE.sub("", line).strip()
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--list-output", type=Path, required=True)
    parser.add_argument("--run-output", type=Path, required=True)
    parser.add_argument("--allow-filtered", action="store_true")
    parser.add_argument("--expected-count", type=int)
    parser.add_argument("--expected-sha256")
    parser.add_argument("expected", nargs="*")
    args = parser.parse_args()

    digest_mode = args.expected_count is not None or args.expected_sha256 is not None
    if digest_mode:
        if (
            args.expected
            or args.expected_count is None
            or args.expected_count < 1
            or args.expected_sha256 is None
            or re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256) is None
        ):
            parser.error(
                "digest mode requires --expected-count COUNT and "
                "--expected-sha256 HEX, with no positional test names"
            )
        expected: list[str] | None = None
        expected_count = args.expected_count
    else:
        if not args.expected:
            parser.error("at least one positional expected test name is required")
        expected = sorted(args.expected)
        expected_count = len(expected)

    listed = sorted(
        match.group(1)
        for line in lines(args.list_output)
        if (match := re.fullmatch(r"([A-Za-z0-9_:]+): test", line))
    )
    if expected is not None and listed != expected:
        missing = sorted(set(expected) - set(listed))
        unexpected = sorted(set(listed) - set(expected))
        raise SystemExit(
            f"{args.label} exact inventory mismatch: "
            f"missing={missing!r} unexpected={unexpected!r} listed={listed!r}"
        )
    if digest_mode:
        listed_bytes = ("\n".join(listed) + "\n").encode("utf-8")
        listed_sha256 = hashlib.sha256(listed_bytes).hexdigest()
        if len(listed) != expected_count or listed_sha256 != args.expected_sha256:
            raise SystemExit(
                f"{args.label} exact inventory commitment mismatch: "
                f"expected_count={expected_count} observed_count={len(listed)} "
                f"expected_sha256={args.expected_sha256} "
                f"observed_sha256={listed_sha256}"
            )

    run_lines = lines(args.run_output)
    passed = sorted(
        match.group(1)
        for line in run_lines
        if (match := re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\. ok", line))
    )
    if passed != listed:
        missing = sorted(set(listed) - set(passed))
        unexpected = sorted(set(passed) - set(listed))
        raise SystemExit(
            f"{args.label} execution inventory mismatch: "
            f"missing={missing!r} unexpected={unexpected!r} passed={passed!r}"
        )

    filtered = r"[0-9]+" if args.allow_filtered else "0"
    summary = re.compile(
        rf"test result: ok\. {expected_count} passed; 0 failed; 0 ignored; "
        rf"0 measured; {filtered} filtered out; finished in "
        r"[0-9]+(?:\.[0-9]+)?s"
    )
    matching_summaries = [line for line in run_lines if summary.fullmatch(line)]
    if len(matching_summaries) != 1:
        filtered_contract = (
            "a bounded filtered count" if args.allow_filtered else "zero filtered"
        )
        raise SystemExit(
            f"{args.label} requires one exact summary with {expected_count} passed, "
            f"zero failed/ignored/measured, and {filtered_contract} tests"
        )
    if args.allow_filtered and "; 0 filtered out;" in matching_summaries[0]:
        raise SystemExit(
            f"{args.label} was declared filtered but the command filtered no tests"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
