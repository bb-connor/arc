#!/usr/bin/env python3
"""Reject a successful Kani run without its required reachable witness."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from pathlib import Path

MAX_RESULT_BYTES = 64 * 1024 * 1024


class CoverError(ValueError):
    """The proof result does not establish the required witness."""


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CoverError(f"duplicate result member: {key}")
        result[key] = value
    return result


def refuse_constant(value: str) -> None:
    raise CoverError(f"non-JSON numeric constant: {value}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CoverError(message)


def verify(document: dict, harness: str) -> None:
    require(isinstance(document, dict), "result must be an object")
    verification = document.get("verification_results")
    require(isinstance(verification, dict), "missing verification results")
    summary = verification.get("summary")
    require(isinstance(summary, dict), "missing verification summary")
    for key, expected in {
        "total_harnesses": 1,
        "executed": 1,
        "successful": 1,
        "failed": 0,
    }.items():
        require(
            type(summary.get(key)) is int and summary[key] == expected,
            f"invalid summary {key}",
        )
    require(summary.get("status") == "completed", "verification is incomplete")
    results = verification.get("results")
    require(
        isinstance(results, list) and len(results) == 1,
        "expected exactly one harness result",
    )
    result = results[0]
    require(
        isinstance(result, dict) and result.get("harness_id") == harness,
        "result is for another harness",
    )
    require(result.get("status") == "Success", "harness verification did not succeed")
    checks = result.get("checks")
    require(isinstance(checks, list) and bool(checks), "missing proof checks")
    ids = set()
    covers = []
    for check in checks:
        require(isinstance(check, dict), "invalid proof check")
        identifier = check.get("id")
        require(
            type(identifier) is int and identifier > 0 and identifier not in ids,
            "invalid or duplicate check id",
        )
        ids.add(identifier)
        if check.get("category") == "cover":
            covers.append(check)
        else:
            require(
                check.get("status") in {"Success", "Unreachable"},
                "non-cover check did not succeed",
            )
    require(len(covers) == 1, "expected exactly one cover witness")
    witness = covers[0]
    require(witness.get("function") == harness, "cover belongs to another function")
    require(
        witness.get("description") == harness.rsplit("::", 1)[-1],
        "cover has another identity",
    )
    require(
        witness.get("status") == "Satisfied", "required cover witness is not reachable"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("harness")
    args = parser.parse_args()
    try:
        require(
            re.fullmatch(r"kani_public_harnesses::[A-Za-z_][A-Za-z0-9_]*", args.harness)
            is not None,
            "invalid harness name",
        )
        info = args.result.lstat()
        require(stat.S_ISREG(info.st_mode), "proof result must be a regular file")
        require(
            0 < info.st_size <= MAX_RESULT_BYTES, "proof result is empty or oversized"
        )
        with args.result.open("rb") as stream:
            raw = stream.read(MAX_RESULT_BYTES + 1)
        require(len(raw) <= MAX_RESULT_BYTES, "proof result exceeds size limit")
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=refuse_constant,
        )
        verify(document, args.harness)
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        print(f"Kani reachability refused: {error}", file=sys.stderr)
        return 1
    print(f"Kani reachable witness verified: {args.harness}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
