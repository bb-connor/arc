#!/usr/bin/env python3
"""Keep every member crate under the workspace lint policy.

The workspace manifest declares the lint policy once, in `[workspace.lints]`,
and a member crate takes it with `[lints] workspace = true`. Cargo refuses to
combine that line with any local lint entry, so a crate that has to register a
`cfg` name for `unexpected_cfgs` (the Kani, loom, dhat and Creusot cfgs) cannot
inherit at all. It carries its own `[lints.rust]` and `[lints.clippy]` tables,
and those tables are copies that nothing keeps in step with the original.

That is the trap. The policy is intact today because each copy was written to
match. The next lint added to the workspace table reaches every inheriting
crate and silently misses every copying one, and the copying crates include
the kernel, the store and the core types, which is where the policy matters
most. `cargo clippy --workspace -- -D warnings` stays green on all of them and
says nothing.

The gate reads the workspace tables and every member manifest, and refuses:

A copying manifest that lacks a workspace lint, or carries it at a different
level or with a different configuration, in either table. Both tables are
compared, because a lint such as `unsafe_op_in_unsafe_fn` lives in the Rust
table and a Clippy-only comparison would never see it.

A manifest with no `[lints]` table at all. It inherits nothing and copies
nothing, so the policy does not reach it. The few that exist today are listed
as debt below, each with an expiry.

A copying manifest may declare lints the workspace does not; that is the reason
it copies. Nested workspace roots (the fuzz harnesses) are separate workspaces
and are outside the reach of `workspace = true`, so they are outside this gate.

Members are enumerated with `cargo metadata --no-deps`, which is the same list
Cargo builds from, including path dependencies it adds as members without a
`members` entry. Lint configurations are compared after normalisation, so
`"deny"` and `{ level = "deny" }` and `{ level = "deny", priority = 0 }` are
one value.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import date
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


LINT_TABLES = ("rust", "clippy")


@dataclass(frozen=True)
class UnreachedDebt:
    rationale: str
    expires: str


def allow(expires: str, rationale: str) -> UnreachedDebt:
    return UnreachedDebt(rationale=rationale, expires=expires)


# Manifests with no `[lints]` table. Each retires when its manifest adopts
# `[lints] workspace = true`; entries are removed, never renewed in place.
UNREACHED: dict[str, UnreachedDebt] = {
    "examples/hello-a2a/Cargo.toml": allow(
        "2026-12-31",
        "example binary with no lints table; retires when it inherits the workspace policy",
    ),
    "examples/hello-acp/Cargo.toml": allow(
        "2026-12-31",
        "example binary with no lints table; retires when it inherits the workspace policy",
    ),
    "examples/hello-mcp/Cargo.toml": allow(
        "2026-12-31",
        "example binary with no lints table; retires when it inherits the workspace policy",
    ),
    "examples/hello-tool/Cargo.toml": allow(
        "2026-12-31",
        "example binary with no lints table; retires when it inherits the workspace policy",
    ),
}


@dataclass(frozen=True)
class Manifest:
    path: str
    text: str
    data: dict


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def member_manifests(root: Path) -> list[str]:
    result = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    metadata = json.loads(result.stdout)
    members = set(metadata["workspace_members"])
    workspace_root = Path(metadata["workspace_root"]).resolve()
    paths = []
    for package in metadata["packages"]:
        if package["id"] not in members:
            continue
        manifest = Path(package["manifest_path"]).resolve()
        paths.append(manifest.relative_to(workspace_root).as_posix())
    return sorted(set(paths))


def load_manifest(root: Path, path: str) -> Manifest:
    text = (root / path).read_text(encoding="utf-8")
    return Manifest(path=path, text=text, data=tomllib.loads(text))


def normalise(config: object) -> tuple:
    """One comparable value for `"deny"` and its table spellings."""
    if isinstance(config, str):
        return (("level", config), ("priority", 0))
    if isinstance(config, dict):
        items = dict(config)
        items.setdefault("priority", 0)
        return tuple(
            (key, tuple(value) if isinstance(value, list) else value)
            for key, value in sorted(items.items())
        )
    return (("level", repr(config)), ("priority", 0))


def render(config: tuple) -> str:
    fields = dict(config)
    level = fields.pop("level", "?")
    if fields == {"priority": 0}:
        return f'"{level}"'
    rest = ", ".join(
        f"{key} = {json.dumps(list(value) if isinstance(value, tuple) else value)}"
        for key, value in fields.items()
    )
    return f'{{ level = "{level}", {rest} }}'


def line_of(text: str, pattern: str) -> int:
    match = re.search(pattern, text, re.M)
    if match is None:
        return 1
    return text.count("\n", 0, match.start()) + 1


def table_line(manifest: Manifest, table: str) -> int:
    return line_of(manifest.text, rf"^\[lints\.{re.escape(table)}\]")


def lint_line(manifest: Manifest, table: str, lint: str) -> int:
    header = re.search(rf"^\[lints\.{re.escape(table)}\]", manifest.text, re.M)
    if header is None:
        return 1
    body = manifest.text[header.end() :]
    key = re.search(rf"^{re.escape(lint)}\s*=", body, re.M)
    if key is None:
        return manifest.text.count("\n", 0, header.start()) + 1
    return manifest.text.count("\n", 0, header.end() + key.start()) + 1


def workspace_lints(root_manifest: Manifest) -> dict[str, dict[str, tuple]]:
    tables = root_manifest.data.get("workspace", {}).get("lints", {})
    return {
        table: {lint: normalise(config) for lint, config in tables.get(table, {}).items()}
        for table in LINT_TABLES
    }


def check_mirror(
    manifest: Manifest, policy: dict[str, dict[str, tuple]], failures: list[str]
) -> None:
    lints = manifest.data.get("lints", {})
    for table in LINT_TABLES:
        expected = policy[table]
        if not expected:
            continue
        local = lints.get(table)
        if local is None:
            names = ", ".join(sorted(expected))
            failures.append(
                f"{manifest.path}:{table_line(manifest, 'clippy' if table == 'rust' else 'rust')} "
                f"[lints.{table}] is absent; the workspace table sets {names}"
            )
            continue
        for lint, config in sorted(expected.items()):
            if lint not in local:
                failures.append(
                    f"{manifest.path}:{table_line(manifest, table)} "
                    f"[lints.{table}] lacks {lint}; the workspace sets it to {render(config)}"
                )
                continue
            actual = normalise(local[lint])
            if actual != config:
                failures.append(
                    f"{manifest.path}:{lint_line(manifest, table, lint)} "
                    f"[lints.{table}] {lint} = {render(actual)}; the workspace sets {render(config)}"
                )


def validate_debt(failures: list[str]) -> None:
    for path, entry in sorted(UNREACHED.items()):
        if not entry.rationale.strip():
            failures.append(f"{path}: debt entry has an empty rationale")
        try:
            expires_on = date.fromisoformat(entry.expires)
        except ValueError:
            failures.append(f"{path}: debt entry expiry {entry.expires!r} is not an ISO date")
            continue
        if expires_on < date.today():
            failures.append(f"{path}: debt entry expired on {entry.expires}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check that every member manifest carries the workspace lint policy."
    )
    parser.add_argument("--root", type=Path, default=repo_root(), help="workspace root")
    args = parser.parse_args()
    root = args.root.resolve()

    failures: list[str] = []
    validate_debt(failures)

    try:
        paths = member_manifests(root)
    except subprocess.CalledProcessError as exc:
        print(f"cargo metadata failed under {root}: {exc.stderr.strip()}", file=sys.stderr)
        return 1

    policy = workspace_lints(load_manifest(root, "Cargo.toml"))
    members = [path for path in paths if path != "Cargo.toml"]
    inheriting = mirroring = unreached = 0
    used: set[str] = set()
    for path in members:
        manifest = load_manifest(root, path)
        lints = manifest.data.get("lints")
        if lints is None:
            unreached += 1
            if path in UNREACHED:
                used.add(path)
                continue
            failures.append(
                f"{path}:1 no [lints] table; the workspace policy does not reach this crate "
                "(add `[lints] workspace = true`)"
            )
            continue
        if lints.get("workspace") is True:
            inheriting += 1
            continue
        mirroring += 1
        check_mirror(manifest, policy, failures)

    for path in sorted(set(UNREACHED) - used):
        if path in members:
            failures.append(
                f"{path}: debt entry no longer excuses a missing [lints] table; remove it"
            )

    lint_count = sum(len(table) for table in policy.values())
    print(
        f"Lint parity: {len(members)} member manifests, {inheriting} inherit, "
        f"{mirroring} mirror, {unreached} unreached; {lint_count} workspace lints "
        f"({len(policy['rust'])} rust, {len(policy['clippy'])} clippy)"
    )

    if failures:
        print("\nLint parity failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nLint parity check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
