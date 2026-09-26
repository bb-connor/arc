#!/usr/bin/env python3
"""Bound the dependency graph of the privileged helpers.

`chio-cage-init` is the most privileged program in the runtime: it installs
the seccomp and Landlock confinement that everything else relies on, and it
runs before that confinement exists. `chio-secret-brokerd` holds credentials
no other process may see. Every crate in their dependency graphs is code that
can execute with that authority, and the graphs grow one convenient
`workspace = true` line at a time, with nothing that notices.

What this measures, exactly: the set of unique packages (name and version)
that `cargo tree --edges normal --locked --target x86_64-unknown-linux-musl`
reports for each budgeted package with its release feature set. That is a
package graph. It is not what the linker kept: dead-code elimination, LTO and
feature-gated modules mean the shipped binary contains less than the graph and
Cargo makes no promise about how much less. A package in the graph is a
package whose code was compiled into the build and whose maintainers are
trusted; whether any byte of it survived linking is a separate measurement of
the artifact, not of the graph. The musl target is the release target of the
helper and pins the target-specific dependencies so the count is the same on
every host.

The gate refuses, per budgeted package:

A graph above its ceiling. The ceiling is the count measured when the budget
was set, so any new package is an explicit edit to this file, reviewed as such.
Ceilings only move down without a reason recorded beside them.

A denied package anywhere in the graph. The deny list is derived from the
measurement: packages that a confinement helper or a credential broker has no
business carrying and that the graph does not carry today (a second TLS stack,
a dynamic loader, a JIT, C-library network clients), plus, for the helper only,
the database and kernel crates that make a program something other than a
helper.

A pending entry whose package has left the graph. The spec's deny candidates
for the helper (an async runtime, an HTTP stack, regex engines, a JSON codec,
a tracing framework) are all present today through `chio-core` and
`chio-manifest`, so they cannot be denied yet. They are recorded as pending
with an expiry and the change that retires them: moving the helper into its
own crate that depends only on the plan and envelope types, `seccompiler` and
`nono-chio`. When that lands and a pending package disappears, the entry is
stale and must be promoted to the deny list, which is how the ratchet closes.

Failures name the budgeted package's manifest and, for a denied package, the
direct dependency that carries it, found with `cargo tree --invert`.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import re
import subprocess
import sys


TARGET = "x86_64-unknown-linux-musl"


@dataclass(frozen=True)
class Pending:
    rationale: str
    expires: str


@dataclass(frozen=True)
class Budget:
    manifest: str
    binary: str
    ceiling: int
    measured: str
    features: tuple[str, ...]
    deny: dict[str, str]
    pending: dict[str, Pending]


def pending(expires: str, rationale: str) -> Pending:
    return Pending(rationale=rationale, expires=expires)


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

# Present in the helper's graph through chio-core and chio-manifest. Each
# retires when the helper depends only on the plan and envelope types,
# seccompiler and nono-chio; the entry then fails as stale and moves to
# HELPER_DENY.
HELPER_PENDING: dict[str, Pending] = {
    name: pending(
        "2026-12-31",
        "carried by chio-core and chio-manifest; retires with the helper's own crate",
    )
    for name in (
        "tokio",
        "hyper",
        "hyper-util",
        "reqwest",
        "tower-http",
        "rustls-webpki",
        "aws-lc-rs",
        "regex",
        "fancy-regex",
        "serde_json",
        "tracing",
    )
}

# Ceilings are the unique package counts measured on the release recipe:
# `--features real-linux-enforcement` for the helper, default features for the
# broker (`chio-broker-mcp` on musl, `chio-secret-brokerd` on glibc build the
# same graph).
BUDGETS: dict[str, Budget] = {
    "chio-cage": Budget(
        manifest="crates/security/chio-cage/Cargo.toml",
        binary="chio-cage-init",
        ceiling=260,
        measured="2026-09-26",
        features=("real-linux-enforcement",),
        deny=HELPER_DENY,
        pending=HELPER_PENDING,
    ),
    "chio-secret-broker": Budget(
        manifest="crates/security/chio-secret-broker/Cargo.toml",
        binary="chio-secret-brokerd",
        ceiling=478,
        measured="2026-09-26",
        features=(),
        deny=COMMON_DENY,
        pending={},
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


def validate_pending(failures: list[str]) -> None:
    for package, budget in sorted(BUDGETS.items()):
        for name, entry in sorted(budget.pending.items()):
            if name in budget.deny:
                failures.append(f"{budget.manifest}: {name} is both denied and pending for {package}")
            if not entry.rationale.strip():
                failures.append(f"{budget.manifest}: pending entry {name} has an empty rationale")
            try:
                expires_on = date.fromisoformat(entry.expires)
            except ValueError:
                failures.append(
                    f"{budget.manifest}: pending entry {name} expiry {entry.expires!r} is not an ISO date"
                )
                continue
            if expires_on < date.today():
                failures.append(f"{budget.manifest}: pending entry {name} expired on {entry.expires}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check the privileged helpers' dependency budgets.")
    parser.add_argument("--root", type=Path, default=repo_root(), help="workspace root")
    args = parser.parse_args()
    root = args.root.resolve()

    failures: list[str] = []
    validate_pending(failures)

    for package, budget in sorted(BUDGETS.items()):
        try:
            graph = packages(cargo_tree(root, package, budget.features))
        except subprocess.CalledProcessError as exc:
            failures.append(f"{budget.manifest}:1 cargo tree failed for {package}: {exc.stderr.strip()}")
            continue
        count = package_count(graph)
        denied = sorted(name for name in budget.deny if name in graph)
        present_pending = sorted(name for name in budget.pending if name in graph)
        stale_pending = sorted(name for name in budget.pending if name not in graph)
        print(
            f"{package} ({budget.binary}) on {TARGET}: {count} packages, ceiling {budget.ceiling} "
            f"(measured {budget.measured}); {len(denied)} denied, {len(present_pending)} pending"
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
        for name in stale_pending:
            failures.append(
                f"{budget.manifest}:{manifest_line(root, budget.manifest, None)} pending entry {name} "
                f"is no longer in the {package} graph; promote it to the deny list"
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
