#!/usr/bin/env python3
"""Fail when a Docker build context omits a source its workspace compiles.

A Dockerfile stage that copies a Cargo workspace manifest must also copy the
directory of every path package that workspace resolves: vendored
`third_party` members, `[patch.crates-io]` replacements and sibling crates.
It must also copy every file the packages it builds embed at compile time
through `include!`, `include_str!` or `include_bytes!` from outside their own
directory, such as formal models or shared fixtures. A missing directory or
embedded file fails only at image build time, after every Rust gate has
passed, so this check derives both requirements from `cargo metadata` and the
compiled sources of the manifest each stage copies, and compares them with
the stage's own `COPY` lines.

Directories are required for every path package the workspace resolves,
because Cargo loads every member manifest before it builds anything. Embedded
files are required only for the packages a stage names with `cargo build -p`
(every member when it names none) and only from sources an image build
compiles: the build script and `src`, without modules whose `cfg` cannot hold
in an image build (`test`, `windows`, a non-Linux target) and without the
`tests`, `benches` and `examples` targets.

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
BUILD_PACKAGE = re.compile(r"(?:^|\s)(?:-p|--package)(?:=|\s+)([A-Za-z0-9_.-]+)")
SCRATCH_EXCLUDED = frozenset({".git", "target", "Cargo.toml", "Cargo.lock"})
EMBED = re.compile(r"\binclude(?:_str|_bytes)?!\s*\(\s*\"([^\"]+)\"")
ATTRIBUTE = re.compile(r"^\s*#\[")
CFG_ATTRIBUTE = re.compile(r"^\s*#\[cfg\((.*)\)\]\s*$")
PATH_ATTRIBUTE = re.compile(r"^\s*#\[path\s*=\s*\"([^\"]+)\"\]\s*$")
MODULE_FILE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")
MODULE_INLINE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{")
CFG_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\"[^\"]*\"|[(),=]")


@dataclass
class Stage:
    """One build stage that copies a workspace manifest into its context."""

    dockerfile: Path
    name: str
    manifest_dir: str | None = None
    copied: list[str] = field(default_factory=list)
    packages: tuple[str, ...] = ()

    def label(self) -> str:
        return f"{self.dockerfile} stage {self.name}"


@dataclass
class Requirements:
    """What a build context must carry: package directories and embedded files."""

    directories: dict[str, str] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)


def logical_lines(text: str) -> list[str]:
    """Return Dockerfile lines with backslash continuations joined."""
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        lines.append((pending + stripped).strip())
        pending = ""
    if pending:
        lines.append(pending.strip())
    return lines


def parse_stages(text: str, dockerfile: Path) -> list[Stage]:
    """Return the stages of `text` that copy a workspace manifest."""
    stages: list[Stage] = []
    current: Stage | None = None
    for line in logical_lines(text):
        stage_match = STAGE_START.match(line)
        if stage_match:
            current = Stage(dockerfile, stage_match.group(1) or str(len(stages)))
            stages.append(current)
            continue
        if current is None:
            continue
        if line.startswith("RUN"):
            current.packages = tuple(sorted(set(current.packages) | set(BUILD_PACKAGE.findall(line))))
            continue
        if not line.startswith("COPY") or "--from=" in line:
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


def cfg_holds(expression: str) -> bool:
    """Evaluate a `cfg` expression for an image build: Linux, no test harness.

    Predicates the build cannot decide, such as features, are taken as true so
    the check stays conservative.
    """
    tokens = CFG_TOKEN.findall(expression)
    position = 0

    def predicate(name: str, value: str | None) -> bool:
        if name in {"test", "windows", "doc", "doctest", "miri"}:
            return False
        if name == "unix":
            return True
        if name == "target_os":
            return value == "linux"
        if name == "target_family":
            return value == "unix"
        return True

    def parse() -> bool:
        nonlocal position
        if position >= len(tokens):
            return True
        name = tokens[position]
        position += 1
        if position < len(tokens) and tokens[position] == "(":
            position += 1
            arguments: list[bool] = []
            while position < len(tokens) and tokens[position] != ")":
                arguments.append(parse())
                if position < len(tokens) and tokens[position] == ",":
                    position += 1
            position += 1
            if name == "not":
                return not all(arguments)
            if name == "all":
                return all(arguments)
            if name == "any":
                return any(arguments)
            return True
        value = None
        if position + 1 < len(tokens) and tokens[position] == "=":
            value = tokens[position + 1].strip('"')
            position += 2
        return predicate(name, value)

    return parse()


def attribute_block_holds(block: list[str]) -> bool:
    """Whether every `cfg` attribute in a block of attribute lines holds."""
    for line in block:
        cfg_match = CFG_ATTRIBUTE.match(line)
        if cfg_match and not cfg_holds(cfg_match.group(1)):
            return False
    return True


class PackageSources:
    """The `src` tree of one package, with the module declarations that compile it."""

    def __init__(self, package_dir: Path) -> None:
        self.package_dir = package_dir
        self.src_root = package_dir / "src"
        self.declarations: dict[Path, tuple[Path, list[str]]] = {}
        if self.src_root.is_dir():
            for source in sorted(self.src_root.rglob("*.rs")):
                self.index_declarations(source)

    def index_declarations(self, declaring: Path) -> None:
        lines = declaring.read_text(encoding="utf-8", errors="replace").splitlines()
        for index, line in enumerate(lines):
            module_match = MODULE_FILE.match(line)
            if not module_match:
                continue
            cursor = index - 1
            block: list[str] = []
            while cursor >= 0 and ATTRIBUTE.match(lines[cursor]):
                block.insert(0, lines[cursor])
                cursor -= 1
            declared = self.declared_file(declaring, module_match.group(1), block)
            if declared is not None:
                self.declarations.setdefault(declared, (declaring, block))

    @staticmethod
    def declared_file(declaring: Path, name: str, block: list[str]) -> Path | None:
        for line in block:
            path_match = PATH_ATTRIBUTE.match(line)
            if path_match:
                return (declaring.parent / path_match.group(1)).resolve()
        if declaring.name in {"mod.rs", "lib.rs", "main.rs"}:
            owned = declaring.parent
        else:
            owned = declaring.parent / declaring.stem
        for candidate in (owned / f"{name}.rs", owned / name / "mod.rs"):
            if candidate.is_file():
                return candidate.resolve()
        return None

    def compiles(self, source: Path, seen: frozenset[Path] = frozenset()) -> bool:
        """Whether an image build compiles `source`; undeclared files are assumed compiled."""
        resolved = source.resolve()
        if resolved in seen:
            return False
        declaration = self.declarations.get(resolved)
        if declaration is None:
            return True
        declaring, block = declaration
        return attribute_block_holds(block) and self.compiles(declaring, seen | {resolved})

    def compiled_sources(self) -> list[Path]:
        """Return the sources an image build compiles: the build script and `src`."""
        sources = []
        build_script = self.package_dir / "build.rs"
        if build_script.is_file():
            sources.append(build_script)
        if self.src_root.is_dir():
            sources.extend(
                source for source in sorted(self.src_root.rglob("*.rs")) if self.compiles(source)
            )
        return sources


def compiled_text(source: Path) -> str:
    """Return the source text without inline modules whose `cfg` cannot hold."""
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    kept: list[str] = []
    index = 0
    while index < len(lines):
        if ATTRIBUTE.match(lines[index]):
            block_end = index
            while block_end < len(lines) and ATTRIBUTE.match(lines[block_end]):
                block_end += 1
            block = lines[index:block_end]
            if block_end < len(lines) and MODULE_INLINE.match(lines[block_end]) and not attribute_block_holds(block):
                index = inline_module_end(lines, block_end)
                continue
        kept.append(lines[index])
        index += 1
    return "\n".join(kept)


def inline_module_end(lines: list[str], start: int) -> int:
    """Return the index after the inline module whose opening brace is on `start`."""
    depth = 0
    for index in range(start, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        if depth <= 0:
            return index + 1
    return len(lines)


def embedded_files(package_dir: Path, name: str, roots: tuple[Path, ...]) -> dict[str, str]:
    """Map every file `name` embeds from outside its directory to its embedding source."""
    package_root = package_dir.resolve()
    files: dict[str, str] = {}
    for source in PackageSources(package_dir).compiled_sources():
        for relative in EMBED.findall(compiled_text(source)):
            embedded = (source.parent / relative).resolve()
            if embedded == package_root or package_root in embedded.parents:
                continue
            origin = f"{name} {relative_directory(source.resolve(), roots)}"
            files[relative_directory(embedded, roots)] = origin
    return files


def reachable_packages(metadata: dict, start_ids: list[str]) -> list[dict]:
    """Return every path package reachable from `start_ids` through resolved dependencies."""
    packages = {package["id"]: package for package in metadata["packages"]}
    edges = {node["id"]: [dep["pkg"] for dep in node["deps"]] for node in metadata["resolve"]["nodes"]}
    seen = set(start_ids)
    queue = deque(start_ids)
    while queue:
        for dependency in edges.get(queue.popleft(), []):
            if dependency not in seen:
                seen.add(dependency)
                queue.append(dependency)
    return [packages[package_id] for package_id in seen if packages[package_id]["source"] is None]


def reachable_path_packages(metadata: dict, roots: tuple[Path, ...], start_ids: list[str]) -> dict[str, str]:
    """Map the directory of every path package reachable from `start_ids` to its name."""
    required: dict[str, str] = {}
    for package in reachable_packages(metadata, start_ids):
        directory = Path(package["manifest_path"]).parent
        required[relative_directory(directory, roots)] = package["name"]
    return required


def build_start_ids(metadata: dict, packages: tuple[str, ...]) -> list[str]:
    """Return the ids of the members a stage builds, or every member when it names none."""
    if not packages:
        return list(metadata["workspace_members"])
    by_name = {package["name"]: package["id"] for package in metadata["packages"] if package["source"] is None}
    missing = [name for name in packages if name not in by_name]
    if missing:
        raise RuntimeError(f"stage builds packages the workspace does not resolve: {', '.join(missing)}")
    return [by_name[name] for name in packages]


def context_requirements(
    metadata: dict, roots: tuple[Path, ...], context_root: Path, packages: tuple[str, ...]
) -> Requirements:
    requirements = Requirements(
        directories=reachable_path_packages(metadata, roots, metadata["workspace_members"])
    )
    for package in sorted(reachable_packages(metadata, build_start_ids(metadata, packages)), key=lambda p: p["name"]):
        directory = relative_directory(Path(package["manifest_path"]).parent, roots)
        requirements.files.update(embedded_files(context_root / directory, package["name"], roots))
    return requirements


def workspace_requirements(repo_root: Path, manifest_dir: str, packages: tuple[str, ...]) -> Requirements:
    """Resolve the packages and embedded files a stage copying `manifest_dir` must carry."""
    if manifest_dir == "":
        metadata = cargo_metadata(repo_root)
        roots = (repo_root, repo_root.resolve())
        return context_requirements(metadata, roots, repo_root, packages)
    with tempfile.TemporaryDirectory(prefix="chio-docker-context.") as scratch:
        scratch_root = Path(scratch)
        for entry in repo_root.iterdir():
            if entry.name not in SCRATCH_EXCLUDED:
                (scratch_root / entry.name).symlink_to(entry)
        for name in ("Cargo.toml", "Cargo.lock"):
            (scratch_root / name).write_bytes((repo_root / manifest_dir / name).read_bytes())
        metadata = cargo_metadata(scratch_root)
        roots = (scratch_root, scratch_root.resolve(), repo_root, repo_root.resolve())
        return context_requirements(metadata, roots, repo_root, packages)


def missing_entries(required: dict[str, str], copied: list[str]) -> list[tuple[str, str]]:
    """Return the required (path, origin) pairs no copied source covers."""
    missing = []
    for path, origin in sorted(required.items()):
        if not any(path == source or path.startswith(f"{source}/") for source in copied):
            missing.append((path, origin))
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
    requirements: dict[tuple[str, tuple[str, ...]], Requirements] = {}
    failures: list[str] = []
    covered_directories = 0
    covered_files = 0
    for stage in stages:
        key = (stage.manifest_dir or "", stage.packages)
        if key not in requirements:
            try:
                requirements[key] = workspace_requirements(repo_root, *key)
            except RuntimeError as error:
                failures.append(f"{stage.label()}: {error}")
                requirements[key] = Requirements()
                continue
        required = requirements[key]
        missing_directories = missing_entries(required.directories, stage.copied)
        missing_files = missing_entries(required.files, stage.copied)
        covered_directories += len(required.directories) - len(missing_directories)
        covered_files += len(required.files) - len(missing_files)
        failures.extend(
            f"{stage.label()}: build context lacks {directory} (path package {name})"
            for directory, name in missing_directories
        )
        failures.extend(
            f"{stage.label()}: build context lacks {path} (embedded by {origin})"
            for path, origin in missing_files
        )

    for failure in failures:
        print(f"error: {failure}")
    if failures:
        print(f"{len(failures)} Docker build context failures", file=sys.stderr)
        return 1
    print(
        f"{len(stages)} Docker build stages cover {covered_directories} resolved path packages"
        f" and {covered_files} embedded files"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
