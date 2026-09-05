#!/usr/bin/env python3
"""Package verified installation artifacts without runtime state or credentials."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import tempfile


STATIC_FILES = {
    "install/bin/chio": "bin/chio",
    "requirements.txt": "python/requirements.txt",
    "LICENSE": "LICENSE",
    "NOTICE": "NOTICE",
    **{f"examples/{name}": f"examples/{name}" for name in (
        "mcp-adoption/check.py", "mcp-adoption/server.py",
        "mcp-adoption/claude_check.py", "mcp-adoption/policy.yaml",
        "langchain-kernel/run.py", "langchain-kernel/tools.py",
        "langchain-kernel/policy.yaml",
    )},
}
PACKAGES = {"chio-sdk", "chio-sdk-python", "chio-adapter-base", "chio-langchain"}
WHEEL = re.compile(r"(chio_sdk_python|chio_sdk|chio_adapter_base|chio_langchain)-([0-9][A-Za-z0-9_.+!]*)-py3-none-any\.whl")
MAX_BYTES = 768 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")


def unique_members(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate member in installation report")
        value[key] = item
    return value


def open_regular(root: Path, relative: str):
    parts = PurePosixPath(relative).parts
    if not parts or relative.startswith("/") or any(p in (".", "..") for p in parts):
        raise ValueError("invalid installation artifact path")
    parent = root
    for part in parts[:-1]:
        parent = parent / part
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError("installation artifact parent must be a regular directory")
    descriptor = os.open(parent / parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stream = os.fdopen(descriptor, "rb")
    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
        stream.close()
        raise ValueError("installation artifact must be a regular file")
    return stream


def read_report(root: Path) -> dict:
    with open_regular(root, "acceptance.json") as stream:
        contents = stream.read(2 * 1024 * 1024 + 1)
    if len(contents) > 2 * 1024 * 1024:
        raise ValueError("installation report exceeds 2 MiB")
    try:
        report = json.loads(contents, object_pairs_hook=unique_members)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("invalid installation report JSON") from error
    if not isinstance(report, dict) or (
        report.get("kind") != "chio.local-installation-acceptance.v1"
        or report.get("source_dirty") is not False
        or report.get("release_qualified") is not False
        or report.get("activation_restore_verified") is not True
        or report.get("build_profile") not in ("dev", "release")
        or not re.fullmatch(r"[0-9a-f]{40}", str(report.get("source_revision", "")))
        or report.get("mcp_adoption") != {"effects": 4, "verified_receipts": 6}
        or report.get("langchain") != {"effects": 2, "verified_receipts": 3}
    ):
        raise ValueError("requires a clean, successful installation acceptance with activation and restoration")
    return report


def select_artifacts(report: dict) -> dict[str, str]:
    hashes = report.get("sha256")
    packages = report.get("packages")
    if not isinstance(hashes, dict) or not isinstance(packages, dict) or set(packages) != PACKAGES:
        raise ValueError("invalid installation artifact or package inventory")
    selected = dict(STATIC_FILES)
    wheels = set()
    for path, digest in hashes.items():
        if str(PurePosixPath(path)) != path:
            raise ValueError("installation artifact path must be canonical")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError("invalid artifact checksum")
        if path in STATIC_FILES:
            continue
        parts = PurePosixPath(path).parts
        match = WHEEL.fullmatch(parts[-1]) if len(parts) == 2 and parts[0] == "wheels" else None
        if not match:
            raise ValueError("installation report contains an unexpected artifact")
        distribution = match[1].replace("_", "-")
        if distribution in wheels or packages.get(distribution) != match[2]:
            raise ValueError("wheel inventory does not match installed package versions")
        wheels.add(distribution)
        selected[path] = f"python/{path}"
    if wheels != PACKAGES or set(selected) != set(hashes):
        raise ValueError("installation report lacks required artifacts; rerun check-agent-install.sh")
    return selected


def native_architecture(stream) -> str:
    header = stream.read(64)
    stream.seek(0)
    if len(header) < 64 or header[:6] != b"\x7fELF\x02\x01" or header[7] not in (0, 3):
        raise ValueError("preview packaging currently supports native 64-bit Linux ELF binaries")
    kind, machine = struct.unpack_from("<HH", header, 16)
    if kind not in (2, 3) or machine not in (62, 183):
        raise ValueError("unsupported preview executable architecture")
    return {62: "x86_64", 183: "aarch64"}[machine]


class HashingReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()

    def read(self, size: int) -> bytes:
        data = self.stream.read(size)
        self.digest.update(data)
        return data


def add_file(archive: tarfile.TarFile, name: str, stream, size: int, executable: bool = False) -> None:
    entry = tarfile.TarInfo(name)
    entry.size = size
    entry.mode = 0o755 if executable else 0o644
    entry.mtime = 0
    archive.addfile(entry, stream)


def package(installation: Path, output: Path) -> dict:
    root = installation.resolve(strict=True)
    report = read_report(root)
    selected = select_artifacts(report)
    if output.exists() or output.is_symlink():
        raise ValueError("output already exists")
    if output.resolve().is_relative_to(root):
        raise ValueError("archive output must be outside the installation directory")
    readme = Path(__file__).with_name("agent-preview-readme.md").read_bytes()
    with ExitStack() as stack:
        sources = {name: stack.enter_context(open_regular(root, name)) for name in selected}
        sizes = {name: os.fstat(stream.fileno()).st_size for name, stream in sources.items()}
        if sum(sizes.values()) > MAX_BYTES:
            raise ValueError("preview artifacts exceed the 768 MiB bundle limit")
        architecture = native_architecture(sources["install/bin/chio"])
        checksums = {selected[name]: digest for name, digest in report["sha256"].items()}
        checksums["README.md"] = hashlib.sha256(readme).hexdigest()
        # Reconstruct public metadata. Never copy unknown report fields or the
        # report's Python environment, raw receipts, or local runtime state.
        manifest = {
            "kind": "chio.agent-preview.v1",
            "source_revision": report["source_revision"],
            "build_profile": report["build_profile"],
            "platform": "linux", "architecture": architecture,
            "packages": report["packages"], "sha256": checksums.copy(),
            "installation_acceptance": {
                "mcp_adoption": report["mcp_adoption"], "langchain": report["langchain"],
                "activation_restore_verified": True,
            },
            "release_qualified": False, "publisher_authenticated": False,
        }
        metadata = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        checksums["PREVIEW.json"] = hashlib.sha256(metadata).hexdigest()
        sums = "".join(f"{digest}  {name}\n" for name, digest in sorted(checksums.items())).encode()
        with tempfile.NamedTemporaryFile(dir=output.parent, prefix=".chio-preview-", suffix=".tmp") as temporary:
            with gzip.GzipFile(filename="", mode="wb", fileobj=temporary, mtime=0) as compressed:
                with tarfile.open(mode="w", fileobj=compressed, format=tarfile.USTAR_FORMAT) as archive:
                    for name, destination in sorted(selected.items(), key=lambda item: item[1]):
                        reader = HashingReader(sources[name])
                        add_file(archive, destination, reader, sizes[name], destination == "bin/chio")
                        if reader.digest.hexdigest() != report["sha256"][name]:
                            raise ValueError(f"artifact checksum mismatch: {name}")
                    for name, contents in (("README.md", readme), ("PREVIEW.json", metadata), ("SHA256SUMS", sums)):
                        add_file(archive, name, io.BytesIO(contents), len(contents))
            temporary.flush()
            os.fsync(temporary.fileno())
            # Publish only a complete archive, without overwriting an existing
            # output or following a destination symlink.
            os.link(temporary.name, output)
    with output.open("rb") as stream:
        archive_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"archive": str(output), "sha256": archive_hash,
            "source_revision": report["source_revision"], "architecture": architecture,
            "build_profile": report["build_profile"], "release_qualified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = package(args.installation, args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Cannot package preview: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
