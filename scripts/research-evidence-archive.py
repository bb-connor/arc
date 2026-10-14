#!/usr/bin/env python3
"""Build and verify the research evidence archive.

Raw run evidence (command output, logs and captured result documents) for the
papers and research notes is published as a release asset rather than kept in
the repository. The repository keeps `docs/research/evidence-archive.json`,
which binds every archived path to its sha256 and the archive to its own
digest. Extracting the archive at the repository root restores each file at
the path the documents cite.

  build   select raw evidence from a source commit, write a deterministic
          tar.gz and the manifest.
  verify  check an archive (and optionally an extracted tree) against the
          manifest.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from pathlib import Path

SCHEMA = "chio.research-evidence-archive.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / "docs/research/evidence-archive.json"

ROOTS = (
    "docs/papers",
    "docs/research",
    "docs/market/open-agent-work",
)
RAW_SUFFIXES = (".stdout", ".stderr", ".log", ".gz", ".ndjson", ".jsonl")
RAW_DIRECTORY = re.compile(r"(^|/)(evidence|[a-z0-9-]+-evidence|results|history)/")
RAW_DOCUMENT = re.compile(r"-(results|evidence)\.json$")
RAW_FILES = frozenset(
    {
        "docs/market/open-agent-work/08-workspace-inventory.json",
        "docs/market/open-agent-work/execution/00-source-inputs.json",
    }
)


class ArchiveError(RuntimeError):
    pass


def git(*args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args], check=True, capture_output=True
    ).stdout


TRACKED_PAPER_INPUTS = ("docs/papers/programmable-sovereignty/",)


def is_raw(path: str) -> bool:
    if "/supplementary/" in path or path.startswith(TRACKED_PAPER_INPUTS):
        return False
    return (
        path in RAW_FILES
        or path.endswith(RAW_SUFFIXES)
        or RAW_DIRECTORY.search(path) is not None
        or RAW_DOCUMENT.search(path) is not None
    )


def selected_paths(source: str, base: str) -> list[str]:
    """Raw paths that `source` adds or changes relative to `base`."""
    changed = git(
        "diff", "--name-only", "-z", "--diff-filter=AM", base, source, "--", *ROOTS
    )
    return sorted(p for p in changed.decode().split("\0") if p and is_raw(p))


def blob(source: str, path: str) -> bytes:
    return git("cat-file", "blob", f"{source}:{path}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_archive(out: Path, members: list[tuple[str, bytes]]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path, data in members:
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    payload = compressed.getvalue()
    out.write_bytes(payload)
    return payload


def build(args: argparse.Namespace) -> int:
    source = git("rev-parse", "--verify", f"{args.source}^{{commit}}").decode().strip()
    base = git("rev-parse", "--verify", f"{args.base}^{{commit}}").decode().strip()
    paths = selected_paths(source, base)
    if not paths:
        raise ArchiveError("no raw evidence selected")
    members = [(path, blob(source, path)) for path in paths]
    out = Path(args.out)
    payload = write_archive(out, members)
    manifest = {
        "schema": SCHEMA,
        "source_commit": source,
        "source_ref": args.source,
        "base_commit": base,
        "archive": {
            "name": out.name,
            "sha256": sha256(payload),
            "size": len(payload),
            "release_tag": args.release_tag,
        },
        "files": [
            {"path": path, "sha256": sha256(data), "size": len(data)}
            for path, data in members
        ],
    }
    Path(args.manifest).write_text(render_manifest(manifest))
    print(
        f"archived {len(members)} files, {sum(len(d) for _, d in members)} bytes "
        f"-> {out} ({len(payload)} bytes, sha256 {manifest['archive']['sha256']})"
    )
    return 0


def render_manifest(manifest: dict) -> str:
    """One file entry per line keeps the manifest reviewable as a diff."""
    head = {key: value for key, value in manifest.items() if key != "files"}
    lines = json.dumps(head, indent=2).splitlines()[:-1]
    lines[-1] += ","
    lines.append('  "files": [')
    entries = [json.dumps(entry, sort_keys=True) for entry in manifest["files"]]
    lines.extend(f"    {entry}," for entry in entries[:-1])
    lines.append(f"    {entries[-1]}")
    lines.extend(["  ]", "}"])
    return "\n".join(lines) + "\n"


def load_manifest(path: Path) -> dict:
    manifest = json.loads(path.read_text())
    if manifest.get("schema") != SCHEMA:
        raise ArchiveError(f"{path}: unsupported manifest schema")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ArchiveError(f"{path}: manifest lists no files")
    return manifest


def verify(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    expected = {entry["path"]: entry for entry in manifest["files"]}
    errors = []
    if args.archive:
        payload = Path(args.archive).read_bytes()
        if sha256(payload) != manifest["archive"]["sha256"]:
            errors.append("archive digest differs from the manifest")
        seen = set()
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile() or member.name not in expected:
                    errors.append(f"unexpected archive member: {member.name}")
                    continue
                data = tar.extractfile(member).read()
                if sha256(data) != expected[member.name]["sha256"]:
                    errors.append(f"digest mismatch: {member.name}")
                seen.add(member.name)
        errors.extend(f"missing from archive: {p}" for p in sorted(expected.keys() - seen))
    if args.tree:
        root = Path(args.tree).resolve()
        for path, entry in expected.items():
            file = (root / path).resolve()
            if not file.is_relative_to(root) or not file.is_file():
                errors.append(f"missing from tree: {path}")
            elif sha256(file.read_bytes()) != entry["sha256"]:
                errors.append(f"digest mismatch in tree: {path}")
    if not args.archive and not args.tree:
        raise ArchiveError("verify needs --archive, --tree or both")
    if errors:
        raise ArchiveError("\n  ".join(["evidence archive does not match:", *errors]))
    print(f"evidence archive matches the manifest ({len(expected)} files)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--source", required=True, help="commit or tag holding the evidence")
    b.add_argument("--base", required=True, help="commit the evidence is selected against")
    b.add_argument("--out", required=True, help="archive path (.tar.gz)")
    b.add_argument("--release-tag", required=True)
    b.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    b.set_defaults(run=build)
    v = sub.add_parser("verify")
    v.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    v.add_argument("--archive")
    v.add_argument("--tree", help="repository root holding the extracted files")
    v.set_defaults(run=verify)
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except (ArchiveError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"research-evidence-archive: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
