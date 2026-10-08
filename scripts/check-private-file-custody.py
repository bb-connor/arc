#!/usr/bin/env python3
"""Keep private-file custody inside chio-secure-fs.

Unix permission bits chosen at creation (`OpenOptionsExt::mode`,
`DirBuilderExt::mode`), permission changes after creation
(`set_permissions`) and symlink refusal (`O_NOFOLLOW`, `OFlags::NOFOLLOW`)
are the raw materials of private-file custody. Every copy outside the shared
crate re-decides the owner, mode, link-count and symlink rules for itself,
and those copies have drifted apart. New production code uses
`crates/security/chio-secure-fs`, whose policies are explicit at each call
site.

The scan covers first-party Rust under `crates/`. Comments, strings and
test-only items are blanked by the lexer the accounting gate uses, and the
chio-secure-fs crate, the shared test-support crate and test-scoped files
(`tests/`, `benches/`, `*_tests.rs`, `tests.rs`) are skipped. A zero-argument
`.mode()` is a permission read and is not a site.

Baseline policy: `scripts/private-file-custody-baseline.txt` pins each
existing site as `count<TAB>rule<TAB>path`. More sites than the pin fail.
Fewer sites than the pin also fail until `--ratchet` lowers the pin, so the
recorded debt only shrinks as call sites move into chio-secure-fs.
`--ratchet` never raises a pin; with no baseline file present it records the
debt as it stands.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import sys

SCRIPTS = Path(__file__).resolve().parent
BASELINE_NAME = "private-file-custody-baseline.txt"
EXEMPT_PREFIXES = (
    "crates/security/chio-secure-fs/",
    "crates/tooling/chio-test-support/",
)
SKIPPED_DIRECTORIES = frozenset({"target", "examples"})
RULES = {
    "creation-mode": re.compile(r"\.\s*mode\s*\(\s*[^)\s]"),
    "set-permissions": re.compile(r"\bset_permissions\s*\("),
    "no-follow": re.compile(r"\b(?:O_)?NOFOLLOW\b"),
}

_spec = importlib.util.spec_from_file_location(
    "custody_lexer", SCRIPTS / "check-accounting-arithmetic.py"
)
if _spec is None or _spec.loader is None:
    raise SystemExit("cannot load scripts/check-accounting-arithmetic.py")
lexer = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = lexer
_spec.loader.exec_module(lexer)

Key = tuple[str, str]


def scanned_paths(root: Path) -> list[str]:
    crates = root / "crates"
    paths = []
    for path in crates.rglob("*.rs"):
        relative = path.relative_to(root)
        if any(
            part.startswith(".") or part in SKIPPED_DIRECTORIES
            for part in relative.parts[:-1]
        ):
            continue
        posix = relative.as_posix()
        if posix.startswith(EXEMPT_PREFIXES) or lexer.is_test_scope(posix):
            continue
        paths.append(posix)
    return sorted(paths)


def sites(root: Path) -> dict[Key, list[int]]:
    found: dict[Key, list[int]] = {}
    for path in scanned_paths(root):
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        code = lexer.blank_test_scoped_items(lexer.blank_rust_noise(text))
        for rule, pattern in RULES.items():
            lines = [code.count("\n", 0, match.start()) + 1 for match in pattern.finditer(code)]
            if lines:
                found[(rule, path)] = lines
    return found


def read_baseline(path: Path) -> dict[Key, int]:
    pins: dict[Key, int] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3 or not fields[0].isdigit() or fields[1] not in RULES:
            raise SystemExit(f"{path.name}:{number}: expected count<TAB>rule<TAB>path")
        key = (fields[1], fields[2])
        if key in pins:
            raise SystemExit(f"{path.name}:{number}: duplicate entry for {fields[2]} {fields[1]}")
        pins[key] = int(fields[0])
    return pins


def write_baseline(path: Path, pins: dict[Key, int]) -> None:
    lines = [
        "# Private-file custody sites outside chio-secure-fs, pinned by",
        "# scripts/check-private-file-custody.py. Entries only shrink; renew with --ratchet.",
    ]
    for (rule, source), count in sorted(pins.items(), key=lambda item: (item[0][1], item[0][0])):
        lines.append(f"{count}\t{rule}\t{source}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def growth(found: dict[Key, list[int]], pins: dict[Key, int]) -> list[str]:
    errors = []
    for (rule, path), lines in sorted(found.items(), key=lambda item: (item[0][1], item[0][0])):
        pinned = pins.get((rule, path), 0)
        if len(lines) > pinned:
            listed = ", ".join(str(line) for line in lines)
            errors.append(
                f"{path}: {len(lines) - pinned} new {rule} site(s) (lines {listed}); "
                "use chio-secure-fs for private-file custody"
            )
    return errors


def check(root: Path, baseline: Path) -> int:
    pins = read_baseline(baseline) if baseline.is_file() else {}
    found = sites(root)
    errors = growth(found, pins)
    for (rule, path), pinned in sorted(pins.items(), key=lambda item: (item[0][1], item[0][0])):
        remaining = len(found.get((rule, path), []))
        if remaining < pinned:
            errors.append(
                f"{path}: {rule} pin {pinned} exceeds the {remaining} remaining site(s); "
                "run --ratchet to record the burn-down"
            )
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if errors:
        return 1
    total = sum(len(lines) for lines in found.values())
    print(f"private-file custody: {total} pinned site(s) in {len({path for _, path in found})} file(s)")
    return 0


def ratchet(root: Path, baseline: Path) -> int:
    found = sites(root)
    if not baseline.is_file():
        write_baseline(baseline, {key: len(lines) for key, lines in found.items()})
        print(f"recorded {sum(len(lines) for lines in found.values())} site(s) in {baseline.name}")
        return 0
    pins = read_baseline(baseline)
    errors = growth(found, pins)
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        print("error: --ratchet never raises a pin", file=sys.stderr)
        return 1
    lowered = {key: len(lines) for key, lines in found.items() if key in pins}
    write_baseline(baseline, lowered)
    print(f"ratcheted {baseline.name}: {sum(lowered.values())} site(s) remain pinned")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=SCRIPTS.parent)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--ratchet", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    baseline = arguments.baseline or root / "scripts" / BASELINE_NAME
    if arguments.ratchet:
        return ratchet(root, baseline)
    return check(root, baseline)


if __name__ == "__main__":
    raise SystemExit(main())
