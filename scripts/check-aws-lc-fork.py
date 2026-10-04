#!/usr/bin/env python3
"""Require the reviewed AWS-LC fork bytes and reject registry substitutions.

Cargo Vet certifies registry source, not the bytes of a path dependency. This
check complements the upstream review record; it never creates an audit.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
from pathlib import Path, PurePosixPath


FORK = Path("third_party/aws-lc-rs-chio")
RECORD = Path("supply-chain/aws-lc-rs-fork.json")
VERSION = "1.18.1"
REGISTRY_SHA256 = "b281d307588d634de920874890732659e2e7672f72b5e10e81badc1a8a83621e"
REGISTRY_URL = "https://static.crates.io/crates/aws-lc-rs/aws-lc-rs-1.18.1.crate"
UPSTREAM_COMMIT = "22e629d5c46276497a24ee3e575be4315940e7cb"
UPSTREAM_SHA256 = "43390fa01fc30a32873a6851bd1f5eda94443ae29e70f0272bfb3d47a3aeaadc"
UPSTREAM_URL = f"https://api.github.com/repos/aws/aws-lc-rs/tarball/{UPSTREAM_COMMIT}"
DEPLOYMENT_FEATURES = {
    "alloc", "aws-lc-sys", "aws-lc-fips-sys", "default", "bindgen",
    "fips", "non-fips", "prebuilt-nasm", "ring-io", "ring-sig-verify",
}
METADATA = {"CHIO-PATCH.md", "CHIO-PATCH.patch.json", "CHIO-RESTORED-FIXTURES.sha256"}
MANIFESTS = (
    Path("Cargo.toml"), Path("fuzz/Cargo.toml"),
    Path("sdks/lambda/chio-lambda-extension/Cargo.toml"),
    Path("crates/tooling/chio-conformance/verdict_matrix/Cargo.toml"),
)


class AuditError(ValueError):
    """The checked source is outside the recorded review."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_files(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        raise AuditError(f"fork root is not a real directory: {root}")
    result = {}
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise AuditError(f"non-regular fork input: {path}")
        result[path.relative_to(root).as_posix()] = path.read_bytes()
    return result


def verify_source_tree(root: Path, expected: dict[str, str]) -> None:
    actual = {name: digest(data) for name, data in tree_files(root).items()}
    if actual != expected:
        changed = sorted(name for name in actual.keys() | expected.keys()
                         if actual.get(name) != expected.get(name))
        raise AuditError(f"fork differs from its reviewed inventory: {changed}")


def verify_resolution(metadata: dict, fork: Path) -> None:
    packages = [p for p in metadata["packages"] if p["name"] == "aws-lc-rs"]
    if len(packages) != 1:
        raise AuditError("expected exactly one AWS-LC Rust package")
    package = packages[0]
    if (package["version"] != VERSION or package["source"] is not None
            or Path(package["manifest_path"]).resolve() != (fork / "Cargo.toml").resolve()):
        raise AuditError("Cargo resolved an unreviewed AWS-LC source")
    nodes = [n for n in metadata["resolve"]["nodes"] if n["id"] == package["id"]]
    if len(nodes) != 1 or not set(nodes[0]["features"]) <= DEPLOYMENT_FEATURES:
        raise AuditError("AWS-LC deployment features exceed the reviewed policy")


def verify_policy(root: Path) -> None:
    config = tomllib.loads((root / "supply-chain/config.toml").read_text())
    policy = config["policy"]["aws-lc-rs"]
    if policy.get("audit-as-crates-io") is not True:
        raise AuditError("upstream AWS-LC review enforcement is missing")
    if policy.get("criteria") != "aws-lc-upstream-reviewed":
        raise AuditError("published AWS-LC source must use the explicit review criterion")
    dependencies = {name: "safe-to-deploy" for name in
                    ("aws-lc-sys", "aws-lc-fips-sys", "untrusted", "zeroize")}
    if policy.get("dependency-criteria") != dependencies:
        raise AuditError("AWS-LC native/transitive dependencies require safe-to-deploy")
    crate = tomllib.loads((root / FORK / "Cargo.toml").read_text())
    if set(crate.get("dependencies", {})) != set(dependencies):
        raise AuditError("AWS-LC dependency set changed since review")
    audits = tomllib.loads((root / "supply-chain/audits.toml").read_text())
    criterion = audits["criteria"]["aws-lc-upstream-reviewed"]
    if criterion.get("implies"):
        raise AuditError("upstream review must not imply deployment approval")


def archive_bytes(path: Path | None, url: str, expected: str) -> bytes:
    if path is None:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(32 * 1024 * 1024 + 1)
    else:
        data = path.read_bytes()
    if len(data) > 32 * 1024 * 1024 or digest(data) != expected:
        raise AuditError(f"archive does not match reviewed SHA-256: {url}")
    return data


def archive_files(data: bytes, prefix: str) -> dict[str, bytes]:
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                raise AuditError("unsafe archive member path")
            if member.isdir():
                continue
            if not member.name.startswith(prefix):
                continue
            if not member.isfile():
                raise AuditError("archive contains a link or special file")
            if member.name.startswith(prefix):
                relative = member.name[len(prefix):]
                if not relative or relative in result:
                    raise AuditError("duplicate or empty archive path")
                reader = archive.extractfile(member)
                if reader is None:
                    raise AuditError("unreadable archive member")
                result[relative] = reader.read()
    if not result:
        raise AuditError("expected archive prefix is absent")
    return result


def reconstruct(fork: Path, registry: bytes, upstream: bytes) -> None:
    original = archive_files(registry, f"aws-lc-rs-{VERSION}/")
    fixtures = archive_files(upstream, "aws-aws-lc-rs-22e629d/aws-lc-rs/")
    patch_lines = json.loads((fork / "CHIO-PATCH.patch.json").read_text())
    if not isinstance(patch_lines, list) or not all(isinstance(s, str) for s in patch_lines):
        raise AuditError("patch must be a JSON array of text lines")
    patch = "".join(patch_lines).encode()
    with tempfile.TemporaryDirectory(prefix="chio-aws-lc-reconstruct-") as directory:
        target = Path(directory)
        for name, data in original.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        subprocess.run(["git", "apply", "--whitespace=nowarn", "-"], input=patch,
                       cwd=target, check=True, capture_output=True)
        for line in (fork / "CHIO-RESTORED-FIXTURES.sha256").read_text().splitlines():
            expected, name = line.split("  ", 1)
            if name not in fixtures or name in original:
                raise AuditError(f"invalid restored fixture: {name}")
            data = fixtures[name]
            if digest(data) != expected:
                # The documented normalization applies only to fixture data.
                data = b"\n".join(s.rstrip(b" \t") for s in
                                  data.replace(b"\r\n", b"\n").split(b"\n")).rstrip(b"\n") + b"\n"
            if digest(data) != expected:
                raise AuditError(f"restored fixture differs from upstream: {name}")
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        expected = {name: data for name, data in tree_files(fork).items() if name not in METADATA}
        if tree_files(target) != expected:
            raise AuditError("registry plus reviewed patch and fixtures does not reproduce fork")


def check(root: Path, args: argparse.Namespace) -> None:
    record = json.loads((root / RECORD).read_text())
    if record.get("schema") != "chio.aws-lc-fork-audit.v1" or record.get("status") != "approved":
        raise AuditError("fork audit is absent or incomplete")
    if record.get("registry_sha256") != REGISTRY_SHA256 or record.get("upstream_commit") != UPSTREAM_COMMIT:
        raise AuditError("fork audit refers to different upstream source")
    report = root / record["report"]["path"]
    if not report.resolve().is_relative_to(root) or digest(report.read_bytes()) != record["report"]["sha256"]:
        raise AuditError("fork audit report changed")
    fork = root / FORK
    verify_source_tree(fork, record["files"])
    verify_policy(root)
    for manifest in MANIFESTS:
        result = subprocess.run(["cargo", "metadata", "--locked", "--all-features",
                                 "--format-version", "1", "--manifest-path", str(root / manifest)],
                                check=True, capture_output=True)
        verify_resolution(json.loads(result.stdout), fork)
    for template in ("chio-workspace", "proof-room-workspace"):
        source = root / "deploy/docker" / template
        with tempfile.TemporaryDirectory(prefix="chio-aws-lc-docker-") as directory:
            target = Path(directory)
            for name in ("Cargo.toml", "Cargo.lock"):
                (target / name).write_bytes((source / name).read_bytes())
            for name in ("crates", "third_party", "fixtures", "spec", "wit"):
                (target / name).symlink_to(root / name, target_is_directory=True)
            result = subprocess.run(["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"],
                                    cwd=target, check=True, capture_output=True)
            verify_resolution(json.loads(result.stdout), fork)
    registry = archive_bytes(args.registry_archive, REGISTRY_URL, REGISTRY_SHA256)
    upstream = archive_bytes(args.upstream_archive, UPSTREAM_URL, UPSTREAM_SHA256)
    reconstruct(fork, registry, upstream)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--registry-archive", type=Path)
    parser.add_argument("--upstream-archive", type=Path)
    args = parser.parse_args()
    try:
        check(args.repo_root.resolve(), args)
    except (AuditError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"AWS-LC fork qualification failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr.decode(errors="replace"), file=sys.stderr)
        return 1
    print("Reviewed AWS-LC fork source, reconstruction, and deployment resolutions verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
