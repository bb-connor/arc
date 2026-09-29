#!/usr/bin/env python3
"""Bound the normal dependency graph of each privileged binary package.

The standalone chio-cage-init package contains the confinement bootstrap and
shares its plan/status codec with the parent. It carries no async runtime,
network client, regex engine, or tracing framework. serde_json is required by
the sealed canonical plan and status wire format; its implementation remains
shared through chio-core-types instead of introducing another canonical codec.

Measure unique name/version pairs on x86_64-unknown-linux-musl with the release
feature set. This is the package graph, not linked artifact contents. An added
package or forbidden transitive dependency requires an explicit reviewed change;
artifact linkage is measured separately by the ELF packaging gate.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
import sys


TARGET = "x86_64-unknown-linux-musl"


@dataclass(frozen=True)
class Budget:
    manifest: str
    binary: str
    ceiling: int
    measured: str
    features: tuple[str, ...]
    deny: dict[str, str]


# Absent from both graphs at the measurement; a privileged program has no
# reason to acquire any of them.
COMMON_DENY: dict[str, str] = {
    "openssl": "a second TLS and crypto stack beside aws-lc-rs",
    "openssl-sys": "a second TLS and crypto stack beside aws-lc-rs",
    "native-tls": "platform TLS through the system library",
    "libloading": "runtime dynamic loading defeats the static-PIE guarantee",
    "dlopen2": "runtime dynamic loading defeats the static-PIE guarantee",
    "wasmtime": "a JIT in a privileged process",
    "cranelift-codegen": "a JIT in a privileged process",
    "git2": "a C version-control library with network reach",
    "curl": "a C HTTP client with network reach",
}

# Absent from the helper's graph at the measurement. A confinement helper that
# opens a database or runs the kernel is a different program.
HELPER_DENY: dict[str, str] = {
    **COMMON_DENY,
    "rusqlite": "the helper owns no database",
    "libsqlite3-sys": "the helper owns no database",
    "chio-store-sqlite": "the helper owns no database",
    "chio-kernel": "the helper enforces a plan; it does not evaluate policy",
    "rustls": "the helper opens no TLS connection",
    "ring": "a second crypto backend beside aws-lc-rs",
}

# Retired pending entries are now unconditional denials. JSON is required by
# the reviewed plan/status wire format; no other exception remains.
HELPER_DENY.update({
    name: "the confinement helper has no runtime, network, regex, or tracing role"
    for name in (
        "tokio", "hyper", "hyper-util", "reqwest", "tower-http", "rustls-webpki",
        "aws-lc-rs", "regex", "regex-automata", "fancy-regex", "tracing",
        "nono", "chio-core", "chio-manifest", "chio-cage",
    )
})

# Ceilings are the unique package counts measured on the release recipe:
# `--features real-linux-enforcement` for the helper, default features for the
# broker (`chio-broker-mcp` on musl, `chio-secret-brokerd` on glibc build the
# same graph).
BUDGETS: dict[str, Budget] = {
    "chio-cage-init": Budget(
        manifest="crates/security/chio-cage-init/Cargo.toml",
        binary="chio-cage-init",
        ceiling=72,
        measured="2026-09-29",
        features=("real-linux-enforcement",),
        deny=HELPER_DENY,
    ),
    "chio-secret-broker": Budget(
        manifest="crates/security/chio-secret-broker/Cargo.toml",
        binary="chio-secret-brokerd",
        # 480 -> 481: add cage-plan and cage-init, remove upstream nono.
        # Other shared platform dependencies remain in the broker's graph.
        ceiling=481,
        measured="2026-09-29",
        features=(),
        deny=COMMON_DENY,
    ),
}

TREE_LINE = re.compile(r"^(?P<depth>\d+)(?P<name>\S+) v(?P<version>\S+)")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def cargo_tree(root: Path, package: str, features: tuple[str, ...], *extra: str) -> list[str]:
    command = [
        "cargo",
        "tree",
        "--edges",
        "normal",
        "--locked",
        "--target",
        TARGET,
        "--prefix",
        "depth",
        "--package",
        package,
    ]
    for feature in features:
        command.extend(["--features", feature])
    command.extend(extra)
    result = subprocess.run(
        command, cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    return result.stdout.splitlines()


def packages(lines: list[str]) -> dict[str, set[str]]:
    """Package name to the set of versions in the graph."""
    graph: dict[str, set[str]] = {}
    for line in lines:
        match = TREE_LINE.match(line)
        if match is None:
            continue
        graph.setdefault(match.group("name"), set()).add(match.group("version"))
    return graph


def package_count(graph: dict[str, set[str]]) -> int:
    return sum(len(versions) for versions in graph.values())


def direct_carrier(root: Path, package: str, features: tuple[str, ...], denied: str) -> str | None:
    """The budgeted package's direct dependency through which `denied` arrives."""
    try:
        lines = cargo_tree(root, package, features, "--invert", denied)
    except subprocess.CalledProcessError:
        return None
    parsed = [match for match in (TREE_LINE.match(line) for line in lines) if match]
    for index, match in enumerate(parsed):
        if match.group("name") != package:
            continue
        depth = int(match.group("depth"))
        for previous in reversed(parsed[:index]):
            if int(previous.group("depth")) == depth - 1:
                return previous.group("name")
    return None


def manifest_line(root: Path, manifest: str, dependency: str | None) -> int:
    text = (root / manifest).read_text(encoding="utf-8")
    if dependency is not None:
        match = re.search(rf"^{re.escape(dependency)}\s*=", text, re.M)
        if match is not None:
            return text.count("\n", 0, match.start()) + 1
    match = re.search(r"^\[dependencies\]", text, re.M)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the privileged helpers' dependency budgets.")
    parser.add_argument("--root", type=Path, default=repo_root(), help="workspace root")
    args = parser.parse_args()
    root = args.root.resolve()

    failures: list[str] = []

    for package, budget in sorted(BUDGETS.items()):
        try:
            graph = packages(cargo_tree(root, package, budget.features))
        except subprocess.CalledProcessError as exc:
            failures.append(f"{budget.manifest}:1 cargo tree failed for {package}: {exc.stderr.strip()}")
            continue
        count = package_count(graph)
        denied = sorted(name for name in budget.deny if name in graph)
        print(
            f"{package} ({budget.binary}) on {TARGET}: {count} packages, ceiling {budget.ceiling} "
            f"(measured {budget.measured}); {len(denied)} denied"
        )
        if count > budget.ceiling:
            failures.append(
                f"{budget.manifest}:{manifest_line(root, budget.manifest, None)} {package} has "
                f"{count} packages in its {TARGET} graph, ceiling {budget.ceiling}; a new dependency "
                "of a privileged program is a reviewed change, not a side effect"
            )
        for name in denied:
            carrier = direct_carrier(root, package, budget.features, name)
            versions = ", ".join(sorted(graph[name]))
            failures.append(
                f"{budget.manifest}:{manifest_line(root, budget.manifest, carrier)} {package} carries "
                f"denied package {name} v{versions}"
                + (f" through {carrier}" if carrier and carrier != name else "")
                + f": {budget.deny[name]}"
            )

    if failures:
        print("\nDependency budget failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nDependency budget check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
