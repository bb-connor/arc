#!/usr/bin/env python3
"""Fail when a Docker build context omits a path package its workspace resolves.

A Dockerfile stage that copies a Cargo workspace manifest must also copy the
directory of every path package that workspace resolves: vendored
`third_party` members, `[patch.crates-io]` replacements and sibling crates.
A missing directory fails only at image build time, after every Rust gate has
passed, so this check derives the requirement from `cargo metadata` for the
manifest each stage copies and compares it with the stage's own `COPY` lines.

A stage copies either the repository manifest (`COPY Cargo.toml Cargo.lock ./`)
or a generated product manifest (`COPY deploy/docker/<name>/Cargo.toml
./Cargo.toml`). Generated manifests are resolved in a scratch tree that links
every top-level repository entry, exactly as their regeneration scripts do.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

ROOT_MANIFEST_COPY = re.compile(r"^COPY\s+Cargo\.toml\s+Cargo\.lock\s+\./?$")
WORKSPACE_MANIFEST_COPY = re.compile(r"^COPY\s+(\S+)/Cargo\.toml\s+\./Cargo\.toml$")
CONTEXT_COPY = re.compile(r"^COPY\s+(?:--chown=\S+\s+)?(\S+)\s+\./(\S+?)/?$")
STAGE_START = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?\S+(?:\s+AS\s+(\S+))?$", re.IGNORECASE)
SCRATCH_EXCLUDED = frozenset({".git", "target", "Cargo.toml", "Cargo.lock"})


@dataclass
class Stage:
    """One build stage that copies a workspace manifest into its context."""

    dockerfile: Path
    name: str
    manifest_dir: str | None = None
    copied: list[str] = field(default_factory=list)

    def label(self) -> str:
        return f"{self.dockerfile} stage {self.name}"


def parse_stages(text: str, dockerfile: Path) -> list[Stage]:
    """Return the stages of `text` that copy a workspace manifest."""
    stages: list[Stage] = []
    current: Stage | None = None
    for raw in text.splitlines():
        line = raw.strip()
        stage_match = STAGE_START.match(line)
        if stage_match:
            current = Stage(dockerfile, stage_match.group(1) or str(len(stages)))
            stages.append(current)
            continue
        if current is None or not line.startswith("COPY") or "--from=" in line:
            continue
        if ROOT_MANIFEST_COPY.match(line):
            current.manifest_dir = ""
            continue
        manifest_match = WORKSPACE_MANIFEST_COPY.match(line)
        if manifest_match:
            current.manifest_dir = manifest_match.group(1)
            continue
        copy_match = CONTEXT_COPY.match(line)
        if copy_match:
            source, destination = copy_match.groups()
            if source.rstrip("/") == destination:
                current.copied.append(destination)
    return [stage for stage in stages if stage.manifest_dir is not None]


def cargo_metadata(workspace: Path) -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=workspace,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cargo metadata failed in {workspace}:\n{result.stderr.strip()}")
    return json.loads(result.stdout)


def relative_directory(directory: Path, roots: tuple[Path, ...]) -> str:
    for root in roots:
        try:
            return directory.relative_to(root).as_posix()
        except ValueError:
            continue
    raise RuntimeError(f"path package {directory} lies outside every build context root")


def reachable_path_packages(metadata: dict, roots: tuple[Path, ...], start_ids: list[str]) -> dict[str, str]:
    """Map the directory of every path package reachable from `start_ids` to its name."""
    packages = {package["id"]: package for package in metadata["packages"]}
    edges = {node["id"]: [dep["pkg"] for dep in node["deps"]] for node in metadata["resolve"]["nodes"]}
    seen = set(start_ids)
    queue = deque(start_ids)
    while queue:
        for dependency in edges.get(queue.popleft(), []):
            if dependency not in seen:
                seen.add(dependency)
                queue.append(dependency)
    required: dict[str, str] = {}
    for package_id in seen:
        package = packages[package_id]
        if package["source"] is not None:
            continue
        directory = Path(package["manifest_path"]).parent
        required[relative_directory(directory, roots)] = package["name"]
    return required


def workspace_requirements(repo_root: Path, manifest_dir: str) -> dict[str, str]:
    """Resolve the path packages a stage copying `manifest_dir` must carry."""
    if manifest_dir == "":
        metadata = cargo_metadata(repo_root)
        roots = (repo_root, repo_root.resolve())
        return reachable_path_packages(metadata, roots, metadata["workspace_members"])
    with tempfile.TemporaryDirectory(prefix="chio-docker-context.") as scratch:
        scratch_root = Path(scratch)
        for entry in repo_root.iterdir():
            if entry.name not in SCRATCH_EXCLUDED:
                (scratch_root / entry.name).symlink_to(entry)
        for name in ("Cargo.toml", "Cargo.lock"):
            (scratch_root / name).write_bytes((repo_root / manifest_dir / name).read_bytes())
        metadata = cargo_metadata(scratch_root)
        roots = (scratch_root, scratch_root.resolve(), repo_root, repo_root.resolve())
        return reachable_path_packages(metadata, roots, metadata["workspace_members"])


def missing_directories(required: dict[str, str], copied: list[str]) -> list[tuple[str, str]]:
    """Return the required (directory, package) pairs no copied source covers."""
    missing = []
    for directory, name in sorted(required.items()):
        if not any(directory == source or directory.startswith(f"{source}/") for source in copied):
            missing.append((directory, name))
    return missing


def tracked_dockerfiles(repo_root: Path) -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "--", "*Dockerfile*"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [repo_root / path for path in sorted(listed)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--dockerfile",
        action="append",
        type=Path,
        default=[],
        help="check only these Dockerfiles instead of every tracked one",
    )
    args = parser.parse_args(argv)
    repo_root = args.root.resolve()
    dockerfiles = [path.resolve() for path in args.dockerfile] or tracked_dockerfiles(repo_root)

    stages = [
        stage
        for dockerfile in dockerfiles
        for stage in parse_stages(dockerfile.read_text(encoding="utf-8"), dockerfile)
    ]
    requirements: dict[str, dict[str, str]] = {}
    failures: list[str] = []
    covered = 0
    for stage in stages:
        manifest_dir = stage.manifest_dir or ""
        if manifest_dir not in requirements:
            try:
                requirements[manifest_dir] = workspace_requirements(repo_root, manifest_dir)
            except RuntimeError as error:
                failures.append(f"{stage.label()}: {error}")
                requirements[manifest_dir] = {}
                continue
        required = requirements[manifest_dir]
        missing = missing_directories(required, stage.copied)
        covered += len(required) - len(missing)
        failures.extend(
            f"{stage.label()}: build context lacks {directory} (path package {name})"
            for directory, name in missing
        )

    for failure in failures:
        print(f"error: {failure}")
    if failures:
        print(f"{len(failures)} Docker build context failures", file=sys.stderr)
        return 1
    print(f"{len(stages)} Docker build stages cover {covered} resolved path packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
