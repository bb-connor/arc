#!/usr/bin/env python3
"""Resolve a PublicKey function or the checked P256 encoding/SHA loop profile."""

from __future__ import annotations

import argparse
import re
import stat
import sys
from pathlib import Path

FUNCTIONS = {
    "public-key-eq": "<chio_core_types::PublicKey as core::cmp::PartialEq>::eq",
    "public-key-to-hex": "chio_core_types::PublicKey::to_hex",
}
MAX_DIAGNOSTIC_BYTES = 16 * 1024 * 1024
ENCODER = "chio_core_types::crypto::encoding::fill_prefixed_hex"
ENCODER_SOURCE = ("crates", "core", "chio-core-types", "src", "crypto", "encoding.rs")
ENCODER_BOUNDS = {67: 6, 70: 66}
SHA256 = "sha2::sha256::soft::compress"
SHA256_SOURCE = ("sha2-0.10.9", "src", "sha256", "soft.rs")
# Each 135-byte P256 key update passes at most two 64-byte blocks;
# finalization passes one block per call. Each block contains 16 words.
SHA256_BOUNDS = {211: 3, 212: 17}
SHA256_U64 = (
    "sha2::digest::typenum::UInt<" * 7
    + "sha2::digest::typenum::UTerm, sha2::digest::typenum::B1>"
    + ", sha2::digest::typenum::B0>" * 6
)
SHA256_PADDING = (
    f"sha2::digest::block_buffer::BlockBuffer::<{SHA256_U64}, "
    "sha2::digest::block_buffer::Eager>::digest_pad::<"
    "{closure@<sha2::Sha256VarCore as sha2::digest::core_api::"
    "VariableOutputCore>::finalize_variable_core::{closure#0}}>"
)
P256_LOOP_PROFILES = {
    ENCODER: ("fill_prefixed_hex", ENCODER_SOURCE, ENCODER_BOUNDS),
    SHA256: ("sha2564soft8compress", SHA256_SOURCE, SHA256_BOUNDS),
    # A successful delimiter write into U64 leaves at most 63 bytes to zero.
    SHA256_PADDING: (
        "10digest_pad",
        ("block-buffer-0.10.4", "src", "lib.rs"),
        {301: 65},
    ),
}


def p256_loop_bounds(diagnostic: str) -> str:
    roles = {function: {} for function in P256_LOOP_PROFILES}
    for block in re.split(r"(?m)^Loop ", diagnostic)[1:]:
        lines = block.splitlines()
        if not lines or not lines[0]:
            raise ValueError("loop record is empty")
        matches = [
            function
            for function, (marker, _, _) in P256_LOOP_PROFILES.items()
            if marker in lines[0] or any(function in line for line in lines[1:])
        ]
        if not matches:
            continue
        if len(matches) != 1:
            raise ValueError("P256 loop record matches multiple functions")
        expected_function = matches[0]
        _, expected_source, bounds = P256_LOOP_PROFILES[expected_function]
        sources = [line for line in lines[1:] if line.lstrip().startswith("file ")]
        source_record = (
            re.fullmatch(
                r"[ \t]+file (.+) line ([0-9]+)(?: column [0-9]+)? function (.+)",
                sources[0],
            )
            if len(sources) == 1
            else None
        )
        identifier = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_]*)\.(0|[1-9][0-9]{0,9}):", lines[0]
        )
        if (
            identifier is None
            or int(identifier.group(2)) > 2**32 - 1
            or source_record is None
        ):
            raise ValueError("P256 loop record is incomplete or invalid")
        source, line, function = source_record.groups()
        role = int(line)
        if (
            function != expected_function
            or Path(source).parts[-len(expected_source) :] != expected_source
            or role not in bounds
            or role in roles[function]
        ):
            raise ValueError("P256 loop source role is unknown or duplicated")
        roles[function][role] = lines[0][:-1]
    selected = []
    stems = set()
    for function, (_, _, bounds) in P256_LOOP_PROFILES.items():
        observed = roles[function]
        function_stems = {
            identifier.rsplit(".", 1)[0] for identifier in observed.values()
        }
        if (
            set(observed) != set(bounds)
            or len(set(observed.values())) != len(bounds)
            or len(function_stems) != 1
            or stems.intersection(function_stems)
        ):
            raise ValueError(f"expected {len(bounds)} distinct loops for {function}")
        stems.update(function_stems)
        selected.extend(
            f"{identifier}:{bounds[role]}"
            for role, identifier in sorted(observed.items(), key=lambda item: item[1])
        )
    return ",".join(selected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("diagnostic", type=Path)
    parser.add_argument("unwind", nargs="?")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--function", choices=FUNCTIONS)
    mode.add_argument("--p256-encoder-bounds", action="store_true")
    args = parser.parse_args()
    selected_function = args.function or "public-key-eq"
    function = FUNCTIONS[selected_function]
    try:
        minimum = 0 if selected_function == "public-key-to-hex" else 1
        if args.p256_encoder_bounds and args.unwind is not None:
            raise ValueError(
                "P256 encoder bounds are fixed; no unwind argument allowed"
            )
        if not args.p256_encoder_bounds and (
            args.unwind is None
            or re.fullmatch(r"0|[1-9][0-9]{0,9}", args.unwind) is None
            or not minimum <= int(args.unwind) <= 4294967295
        ):
            raise ValueError(
                f"bound must be an integer from {minimum} through 4294967295"
            )
        info = args.diagnostic.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("diagnostic must be a regular file")
        if not 0 < info.st_size <= MAX_DIAGNOSTIC_BYTES:
            raise ValueError("diagnostic is empty or oversized")
        with args.diagnostic.open("rb") as stream:
            raw = stream.read(MAX_DIAGNOSTIC_BYTES + 1)
        if len(raw) > MAX_DIAGNOSTIC_BYTES:
            raise ValueError("diagnostic exceeds size limit")
        if args.p256_encoder_bounds:
            print(p256_loop_bounds(raw.decode("utf-8")))
            return 0
        matches = [
            line
            for line in raw.decode("utf-8").splitlines()
            if line.startswith(function + " /* ")
        ]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one {selected_function} function")
        available = re.fullmatch(
            re.escape(function) + r" /\* ([A-Za-z_][A-Za-z0-9_]*) \*/", matches[0]
        )
        if available is None:
            raise ValueError("function is unavailable or its identifier is invalid")
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Kani function bound refused: {error}", file=sys.stderr)
        return 1
    print(f"{available.group(1)}:{args.unwind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
