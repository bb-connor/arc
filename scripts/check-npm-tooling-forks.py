#!/usr/bin/env python3
"""Authenticate repaired Node tooling packages and monitor their upstream bases.

The private package names identify modified source. They must never hide new
upstream advisories: query the original registry identities and reject every
advisory other than the two repairs bound to this inventory.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
RECORD = "supply-chain/npm-tooling-forks.json"
REPAIRS = {
    "braces": ("3.0.3", "GHSA-vfj7-8cjw-p6xm"),
    "node-forge": ("1.4.0", "GHSA-86w9-cpqp-85rv"),
}
MAX_ARCHIVE = 2 * 1024 * 1024
MAX_SOURCE = 8 * 1024 * 1024


def integrity(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def fetch(url: str, body: dict | None = None) -> bytes:
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        value = response.read(MAX_ARCHIVE + 1)
    if len(value) > MAX_ARCHIVE:
        raise ValueError("Upstream response exceeds the evidence bound")
    return value


def unpack(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE:
        raise ValueError("Package archive exceeds the compressed size bound")
    files = {}
    size = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for entry in archive:
            name = PurePosixPath(entry.name)
            if (
                not entry.isfile()
                or name.is_absolute()
                or ".." in name.parts
                or name.parts[0] != "package"
            ):
                raise ValueError("Package contains a non-regular or escaping member")
            relative = str(name.relative_to("package"))
            size += entry.size
            if relative in files or size > MAX_SOURCE:
                raise ValueError("Package contains duplicate or oversized source")
            with archive.extractfile(entry) as stream:
                files[relative] = stream.read()
    if not files:
        raise ValueError("Empty source archive")
    return files


def reviewed_path(root: Path, name: str) -> Path:
    path = root / name
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Fork input escapes the checkout")
    return path


def verify_fork(root: Path, record: dict, upstream: bytes) -> None:
    if integrity(upstream) != record["upstream_integrity"]:
        raise ValueError("Upstream registry source changed")
    packed = reviewed_path(root, record["archive"]).read_bytes()
    if integrity(packed) != record["integrity"]:
        raise ValueError("Private package archive changed")
    actual = unpack(packed)
    if {
        name: hashlib.sha256(data).hexdigest() for name, data in actual.items()
    } != record["files"]:
        raise ValueError("Private package source inventory changed")
    patch = reviewed_path(root, record["patch"]).read_bytes()
    if hashlib.sha256(patch).hexdigest() != record["patch_sha256"]:
        raise ValueError("Reviewed source repair changed")
    original = unpack(upstream)
    with tempfile.TemporaryDirectory(prefix="chio-npm-source-") as temporary:
        directory = Path(temporary)
        for name, data in original.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for name in record["removed"]:
            reviewed_path(directory, name).unlink()
        subprocess.run(
            ["git", "apply", "--whitespace=nowarn", "-"],
            cwd=directory,
            input=patch,
            check=True,
            capture_output=True,
        )
        reproduced = {
            p.relative_to(directory).as_posix(): p.read_bytes()
            for p in directory.rglob("*")
            if p.is_file()
        }
        if reproduced != actual:
            raise ValueError(
                "Registry source plus reviewed repair does not reproduce the package"
            )
    manifest = json.loads(actual["package.json"])
    if (
        manifest["name"] != record["name"]
        or manifest["version"] != record["version"]
        or manifest.get("private") is not True
        or manifest.get("scripts")
        or manifest.get("devDependencies")
    ):
        raise ValueError(
            "Private tooling package identity or installation behavior changed"
        )


def verify_resolution(root: Path, records: list[dict]) -> None:
    directory = root / "sdks/typescript"
    manifest = json.loads((directory / "package.json").read_text())
    packages = json.loads((directory / "package-lock.json").read_text())["packages"]
    for record in records:
        name = record["upstream_name"]
        spec = "file:../../" + record["archive"]
        if (
            manifest["overrides"].get(name) != "$" + name
            or manifest.get("devDependencies", {}).get(name) != spec
        ):
            raise ValueError(f"{name} does not select its authenticated repair")
        matches = [
            (key, value)
            for key, value in packages.items()
            if key.rsplit("node_modules/", 1)[-1] == name
        ]
        if not matches:
            raise ValueError(f"{name} peer tool is no longer installed")
        for _, package in matches:
            if (
                package.get("name") != record["name"]
                or package.get("version") != record["version"]
                or package.get("resolved") != spec
                or package.get("integrity") != record["integrity"]
            ):
                raise ValueError(
                    f"{name} resolves an unrepaired or unauthenticated copy"
                )


def verify_advisories(record: dict, response: dict) -> None:
    for vulnerability in response.get("vulns", []):
        identities = {vulnerability["id"], *vulnerability.get("aliases", [])}
        if record["fixed_advisory"] not in identities:
            raise ValueError(
                f"Unrepaired upstream advisory for {record['upstream_name']}: "
                f"{vulnerability['id']}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-archive-directory", type=Path)
    args = parser.parse_args()
    record = json.loads((ROOT / RECORD).read_text())
    if record.get("schema") != "chio.npm-tooling-forks.v1":
        raise ValueError("Unknown tooling source record")
    forks = record["forks"]
    if {
        p["upstream_name"]: (p["upstream_version"], p["fixed_advisory"]) for p in forks
    } != REPAIRS or len(forks) != len(REPAIRS):
        raise ValueError("Tooling repair inventory changed")
    for fork in forks:
        original = (
            (
                args.upstream_archive_directory / (fork["upstream_name"] + ".tgz")
            ).read_bytes()
            if args.upstream_archive_directory
            else fetch(fork["upstream_url"])
        )
        verify_fork(ROOT, fork, original)
        advisories = json.loads(
            fetch(
                "https://api.osv.dev/v1/query",
                {
                    "package": {"name": fork["upstream_name"], "ecosystem": "npm"},
                    "version": fork["upstream_version"],
                },
            )
        )
        verify_advisories(fork, advisories)
        print(
            f"Authenticated {fork['name']} source repair; "
            "upstream advisory monitor passed"
        )
    verify_resolution(ROOT, forks)
    print("Every installed peer-tooling resolution selects the authenticated repairs")


if __name__ == "__main__":
    main()
