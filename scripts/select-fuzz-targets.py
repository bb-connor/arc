#!/usr/bin/env python3
"""Select the fuzz targets a pull request diff must exercise.

Reads the changed paths (one per line) and prints the selected fuzz targets,
sorted, one per line. A target is selected when a changed path matches one of
its trigger globs in fuzz/target-map.toml.

Every target is selected when the diff touches the fuzz build itself: the
ClusterFuzzLite builder, the cargo configuration, the root workspace manifest
that members inherit dependencies from, the fuzz workspace manifest or lock,
the target map, or this selector. A member crate manifest selects every target
when the crate belongs to the fuzz workspace dependency graph recorded in
fuzz/Cargo.lock, at either the head or the base revision, because feature and
dependency changes there change every fuzz build. Manifests of crates outside
that graph, and the root Cargo.lock, cannot change the fuzz build (the fuzz
workspace resolves against its own lock) and select nothing on their own. A
manifest whose package name cannot be read selects every target.

--classification names a file that receives one line: "targets-selected"
when targets were selected, "no-fuzz-relevant-change" when the diff cannot
reach any fuzz build, or "unclassified" when it can but no target is mapped. A
changed path is fuzz-relevant unless it is test, bench or example code, belongs
to a crate outside the fuzz dependency graph (owner found at the head or the
base revision), or is a non-Rust file owned by no crate outside spec/schemas/.
Paths under fuzz/, owned by fuzz-graph crates, Rust files with no owning
crate, and quoted (escaped) paths are fuzz-relevant.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

INVENTORY_CONTROL = re.compile(
    r"^(\.cargo/"
    r"|\.clusterfuzzlite/"
    r"|\.github/workflows/cflite_pr\.yml$"
    r"|Cargo\.toml$"
    r"|fuzz/Cargo\.(toml|lock)$"
    r"|fuzz/target-map\.toml$"
    r"|Makefile$"
    r"|scripts/(ci-pr-tier|spec-drift-check|check-review-slices)\.(sh|py)$"
    r"|scripts/select-fuzz-targets\.py$)"
)
MEMBER_MANIFEST = re.compile(r"^(.+/)?Cargo\.toml$")
NON_PRODUCTION = re.compile(r"(^|/)(tests|benches|examples)/|_tests(\.rs$|/)|(^|/)tests\.rs$")
ALWAYS_RELEVANT = re.compile(r"^(fuzz/|spec/schemas/)")
TARGETS_SELECTED = "targets-selected"
NO_FUZZ_RELEVANT_CHANGE = "no-fuzz-relevant-change"
UNCLASSIFIED = "unclassified"


class SelectionError(Exception):
    pass


def glob_regex(pattern: str) -> re.Pattern[str]:
    out = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("^" + "".join(out) + "$")


def load_targets(target_map: Path) -> dict[str, list[re.Pattern[str]]]:
    try:
        targets = tomllib.loads(target_map.read_text(encoding="utf-8"))["targets"]
    except (OSError, tomllib.TOMLDecodeError, KeyError) as error:
        raise SelectionError(f"cannot read target map {target_map}: {error}") from error
    if not isinstance(targets, dict) or not targets:
        raise SelectionError(f"target map {target_map} defines no targets")
    selected: dict[str, list[re.Pattern[str]]] = {}
    for name, spec in targets.items():
        triggers = spec.get("triggers") if isinstance(spec, dict) else None
        if not isinstance(triggers, list) or not triggers:
            raise SelectionError(f"target {name} has no triggers")
        if not all(isinstance(trigger, str) and trigger for trigger in triggers):
            raise SelectionError(f"target {name} has a non-string trigger")
        selected[name] = [glob_regex(trigger) for trigger in triggers]
    return selected


def fuzz_graph_packages(fuzz_lock: Path) -> set[str]:
    try:
        packages = tomllib.loads(fuzz_lock.read_text(encoding="utf-8"))["package"]
    except (OSError, tomllib.TOMLDecodeError, KeyError) as error:
        raise SelectionError(f"cannot read fuzz lock {fuzz_lock}: {error}") from error
    local = {package["name"] for package in packages if "source" not in package}
    if not local:
        raise SelectionError(f"fuzz lock {fuzz_lock} records no path packages")
    return local


def package_name(text: str) -> str | None:
    try:
        package = tomllib.loads(text).get("package")
    except tomllib.TOMLDecodeError:
        return None
    name = package.get("name") if isinstance(package, dict) else None
    return name if isinstance(name, str) and name else None


def manifest_names(root: Path, path: str, base: str | None) -> list[str | None]:
    names: list[str | None] = []
    head = root / path
    if head.is_file():
        names.append(package_name(head.read_text(encoding="utf-8")))
    if base is not None:
        shown = subprocess.run(
            ["git", "-C", str(root), "show", f"{base}:{path}"],
            capture_output=True,
            text=True,
            check=False,
        )
        if shown.returncode == 0:
            names.append(package_name(shown.stdout))
    return names


def owning_package(root: Path, path: str, base: str | None) -> str | None:
    """Name of the nearest enclosing package at the head or base revision."""
    parts = path.split("/")[:-1]
    while parts:
        manifest = "/".join(parts + ["Cargo.toml"])
        names = [name for name in manifest_names(root, manifest, base) if name is not None]
        if names:
            return names[0]
        parts.pop()
    return None


def fuzz_relevant(root: Path, path: str, graph: set[str], base: str | None) -> bool:
    if path.startswith('"'):
        return True
    if NON_PRODUCTION.search(path):
        return False
    if ALWAYS_RELEVANT.match(path):
        return True
    owner = owning_package(root, path, base)
    if owner is None:
        return path.endswith(".rs")
    return owner in graph


def classify(
    fired: list[str], changed: list[str], graph: set[str], root: Path, base: str | None
) -> tuple[str, list[str]]:
    if fired:
        return TARGETS_SELECTED, []
    relevant = [path for path in changed if fuzz_relevant(root, path, graph, base)]
    return (UNCLASSIFIED if relevant else NO_FUZZ_RELEVANT_CHANGE), relevant


def select(
    changed: list[str],
    targets: dict[str, list[re.Pattern[str]]],
    graph: set[str],
    root: Path,
    base: str | None,
) -> tuple[list[str], str | None]:
    for path in changed:
        if INVENTORY_CONTROL.match(path):
            return sorted(targets), f"fuzz build input changed: {path}"
    for path in changed:
        if not MEMBER_MANIFEST.match(path):
            continue
        names = manifest_names(root, path, base)
        if not names or None in names:
            return sorted(targets), f"unreadable crate manifest changed: {path}"
        if any(name in graph for name in names):
            return sorted(targets), f"fuzz dependency manifest changed: {path}"
    fired = {
        name
        for name, triggers in targets.items()
        if any(trigger.match(path) for trigger in triggers for path in changed)
    }
    return sorted(fired), None


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--changed", required=True, type=Path)
    parser.add_argument("--base", help="git revision the diff is taken against")
    parser.add_argument("--root", type=Path, default=root)
    parser.add_argument("--classification", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        changed = [
            line.strip()
            for line in args.changed.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        targets = load_targets(args.root / "fuzz/target-map.toml")
        graph = fuzz_graph_packages(args.root / "fuzz/Cargo.lock")
        fired, reason = select(changed, targets, graph, args.root, args.base)
        classification, relevant = classify(fired, changed, graph, args.root, args.base)
        args.classification.write_text(classification + "\n", encoding="utf-8")
    except (OSError, SelectionError) as error:
        print(f"select-fuzz-targets: {error}", file=sys.stderr)
        return 2
    if reason is not None:
        print(f"select-fuzz-targets: {reason}; selecting all {len(fired)} targets", file=sys.stderr)
    for path in relevant:
        print(
            f"select-fuzz-targets: fuzz-relevant change without a mapped target: {path}",
            file=sys.stderr,
        )
    for name in fired:
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
