#!/usr/bin/env python3
"""Exercise an agent preview in a pinned Linux container without build tools."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import runpy
import shutil
import subprocess
import sys
import tarfile


PACKAGING = runpy.run_path(str(Path(__file__).with_name("package-agent-preview.py")))
IMAGE = "python@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534"
MAX_METADATA = 2 * 1024 * 1024
MAX_MEMBERS = len(PACKAGING["STATIC_FILES"]) + len(PACKAGING["WORKBENCH_FILES"]) + len(PACKAGING["PACKAGES"]) + 3
BUILD_TOOLS = ("cargo", "rustc", "cc", "gcc", "clang", "make", "cmake", "protoc", "uv")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(data: bytes) -> dict:
    if len(data) > MAX_METADATA:
        raise ValueError("preview metadata exceeds 2 MiB")
    value = json.loads(data, object_pairs_hook=PACKAGING["unique_members"])
    if not isinstance(value, dict):
        raise ValueError("preview metadata must be an object")
    return value


def inventory(manifest: dict) -> set[str]:
    if (
        manifest.get("kind") != "chio.agent-preview.v1"
        or manifest.get("platform") != "linux"
        or manifest.get("architecture") not in ("aarch64", "x86_64")
        or manifest.get("build_profile") not in ("dev", "release")
        or manifest.get("release_qualified") is not False
        or manifest.get("publisher_authenticated") is not False
        or not isinstance(manifest.get("source_revision"), str)
        or not re.fullmatch(r"[0-9a-f]{40}", manifest["source_revision"])
    ):
        raise ValueError("unsupported preview metadata")
    packages = manifest.get("packages")
    if not isinstance(packages, dict) or set(packages) != PACKAGING["PACKAGES"]:
        raise ValueError("unexpected preview package inventory")
    names = set(PACKAGING["STATIC_FILES"].values()) | {"README.md", "PREVIEW.json", "SHA256SUMS"}
    acceptance = manifest.get("installation_acceptance")
    if not isinstance(acceptance, dict):
        raise ValueError("missing preview installation acceptance")
    if "workbench" in acceptance:
        if acceptance["workbench"] != PACKAGING["WORKBENCH_ACCEPTANCE"]:
            raise ValueError("incomplete preview workbench acceptance")
        names.update(PACKAGING["WORKBENCH_FILES"].values())
    for name, version in packages.items():
        wheel = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        if not isinstance(version, str) or not PACKAGING["WHEEL"].fullmatch(wheel):
            raise ValueError("invalid preview wheel version")
        names.add(f"python/wheels/{wheel}")
    hashes = manifest.get("sha256")
    if not isinstance(hashes, dict) or set(hashes) != names - {"PREVIEW.json", "SHA256SUMS"}:
        raise ValueError("incomplete preview checksums")
    if any(not isinstance(value, str) or not PACKAGING["SHA256"].fullmatch(value) for value in hashes.values()):
        raise ValueError("invalid preview checksum")
    return names


def verify_bundle(root: Path) -> dict:
    manifest = read_json((root / "PREVIEW.json").read_bytes())
    names = inventory(manifest)
    expected_sums = dict(manifest["sha256"])
    expected_sums["PREVIEW.json"] = digest(root / "PREVIEW.json")
    expected_text = "".join(f"{checksum}  {name}\n" for name, checksum in sorted(expected_sums.items()))
    if (root / "SHA256SUMS").read_text() != expected_text:
        raise ValueError("checksum file does not match preview metadata")
    for name in names:
        with PACKAGING["open_regular"](root, name) as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if name in expected_sums and actual != expected_sums[name]:
            raise ValueError(f"preview checksum mismatch: {name}")
    return manifest


def extract_preview(archive_path: Path, expected_hash: str, destination: Path) -> dict:
    if digest(archive_path) != expected_hash:
        raise ValueError("archive checksum mismatch")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = {}
        total = 0
        for entry in archive:
            path = PurePosixPath(entry.name)
            if (
                not entry.isfile() or entry.name in members
                or str(path) != entry.name or path.is_absolute() or ".." in path.parts
                or entry.mode != (0o755 if entry.name in PACKAGING["EXECUTABLES"] else 0o644)
            ):
                raise ValueError("preview contains an unsafe archive member")
            members[entry.name] = entry
            total += entry.size
            if entry.name in ("PREVIEW.json", "SHA256SUMS", "README.md") and entry.size > MAX_METADATA:
                raise ValueError("preview metadata exceeds 2 MiB")
            if len(members) > MAX_MEMBERS or total > PACKAGING["MAX_BYTES"] + 3 * MAX_METADATA:
                raise ValueError("preview exceeds archive limits")
        if "PREVIEW.json" not in members:
            raise ValueError("preview metadata is missing")
        with archive.extractfile(members["PREVIEW.json"]) as stream:
            manifest = read_json(stream.read(MAX_METADATA + 1))
        if set(members) != inventory(manifest):
            raise ValueError("archive does not match the preview inventory")
        destination.mkdir(mode=0o700)
        archive.extractall(destination, members=members.values(), filter="data")
    return verify_bundle(destination)


def inside(phase: str, expected_hash: str) -> None:
    root = Path("/work/bundle")
    python = "/work/.venv/bin/python"
    if phase == "prepare":
        manifest = extract_preview(Path("/input/preview.tar.gz"), expected_hash, root)
        if manifest["architecture"] != platform.machine():
            raise ValueError("preview architecture does not match the runtime container")
        subprocess.run(["uv", "venv", "--python", sys.executable, "/work/.venv"], check=True)
        subprocess.run(["uv", "pip", "install", "--python", python, "--require-hashes",
                        "-r", str(root / "python/requirements.txt")], check=True)
        subprocess.run(["uv", "pip", "install", "--python", python, "--no-deps",
                        *map(str, sorted((root / "python/wheels").glob("*.whl")))], check=True)
        subprocess.run(["uv", "pip", "check", "--python", python], check=True)
        return
    manifest = verify_bundle(root)
    if set(os.listdir("/sys/class/net")) != {"lo"}:
        raise ValueError("runtime execution requires a container with networking disabled")
    if any(shutil.which(tool) for tool in BUILD_TOOLS):
        raise ValueError("runtime execution container unexpectedly contains build or installation tools")
    for name, version in manifest["packages"].items():
        distribution = importlib.metadata.distribution(name)
        direct = json.loads(distribution.read_text("direct_url.json") or "{}")
        if distribution.version != version or not direct.get("url", "").startswith((root / "python/wheels").as_uri() + "/"):
            raise ValueError("runtime package did not come from the bundled wheel")
    for example, script, state in (("mcp-adoption", "check.py", "mcp-state"),
                                    ("langchain-kernel", "run.py", "langchain-state")):
        subprocess.run([python, "-I", str(root / "examples" / example / script),
                        "--chio", str(root / "bin/chio"), "--state-dir", f"/work/{state}"], check=True)
    workbench = None
    if "workbench" in manifest["installation_acceptance"]:
        subprocess.run([python, "-I", str(root / "examples/workbench/check.py"),
                        "--workbench", str(root / "bin/chio-workbench"), "--state-dir", "/work/workbench-state"], check=True)
        evidence = read_json(Path("/work/workbench-state/evidence.json").read_bytes())
        workbench = {key: value for key, value in evidence.items() if key not in ("kind", "release_qualified")}
        if workbench != PACKAGING["WORKBENCH_ACCEPTANCE"]:
            raise ValueError("runtime workbench acceptance did not exercise the required repair")
    verify_bundle(root)
    mcp = json.loads(Path("/work/mcp-state/evidence.json").read_text())
    langchain = json.loads(Path("/work/langchain-state/evidence.json").read_text())
    if (
        (len(mcp["effects"]), len(mcp["receipts"])) != (4, 6)
        or (len(langchain["effects"]), len(langchain["receipts"])) != (2, 3)
        or mcp["activation"]["operation"] != "activate"
        or mcp["restoration"]["operation"] != "restore"
    ):
        raise ValueError("runtime acceptance did not exercise the required scenarios")
    report = {
        "kind": "chio.agent-preview-runtime-acceptance.v1",
        "source_revision": manifest["source_revision"], "archive_sha256": expected_hash,
        "architecture": platform.machine(), "distribution": platform.freedesktop_os_release()["PRETTY_NAME"],
        "libc": list(platform.libc_ver()), "python": platform.python_version(),
        "build_profile": manifest["build_profile"], "binary_sha256": manifest["sha256"]["bin/chio"],
        "mcp_adoption": {"effects": 4, "verified_receipts": 6},
        "langchain": {"effects": 2, "verified_receipts": 3},
        "activation_restore_verified": True, "checksums_verified_after_execution": True,
        "execution_network": "none", "build_tools_present": False, "build_tools_checked": list(BUILD_TOOLS),
        "release_qualified": False, "independent_machine_verified": False,
    }
    if workbench is not None:
        report["workbench"] = workbench
        report["workbench_binary_sha256"] = manifest["sha256"]["bin/chio-workbench"]
    Path("/work/runtime-result.json").write_text(json.dumps(report, indent=2) + "\n")


def drive(archive: Path, expected_hash: str, output: Path, image: str) -> None:
    archive = archive.resolve(strict=True)
    if output.exists() or output.is_symlink():
        raise ValueError("runtime output already exists")
    output = output.resolve()
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[0-9a-f]{64}", image):
        raise ValueError("runtime image must be pinned by digest")
    if output.is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError("runtime output must be outside the source checkout")
    if digest(archive) != expected_hash:
        raise ValueError("archive checksum mismatch")
    uv = shutil.which("uv")
    if not uv:
        raise ValueError("uv is required to prepare the runtime environment")
    output.mkdir(mode=0o700)
    subprocess.run(["docker", "pull", "--quiet", image], check=True)
    image_info = json.loads(subprocess.check_output(["docker", "image", "inspect", image], text=True))[0]
    common = ["docker", "run", "--rm", "--pull=never", "--user", f"{os.getuid()}:{os.getgid()}",
              "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
              "--tmpfs", "/tmp:rw,nosuid,nodev,size=536870912", "--workdir", "/work"]
    sources = ((archive, "/input/preview.tar.gz"), (output, "/work"),
               (Path(__file__).resolve(), "/tools/check-agent-preview-runtime.py"),
               (Path(__file__).with_name("package-agent-preview.py").resolve(), "/tools/package-agent-preview.py"))
    for source, target in sources:
        if "," in str(source):
            raise ValueError("Docker bind paths must not contain commas")
        common += ["--mount", f"type=bind,source={source},target={target}" + ("" if target == "/work" else ",readonly")]
    uv = Path(uv).resolve(strict=True)
    if "," in str(uv):
        raise ValueError("Docker bind paths must not contain commas")
    script = "/tools/check-agent-preview-runtime.py"
    subprocess.run([*common, "--env", "UV_CACHE_DIR=/work/uv-cache", "--mount",
                    f"type=bind,source={uv},target=/usr/local/bin/uv,readonly", image,
                    "python", "-I", script, "--inside", "prepare", "--sha256", expected_hash], check=True)
    subprocess.run([*common, "--network", "none", image, "/work/.venv/bin/python", "-I", script,
                    "--inside", "run", "--sha256", expected_hash], check=True)
    if digest(archive) != expected_hash:
        raise ValueError("archive changed during runtime acceptance")
    report = read_json((output / "runtime-result.json").read_bytes())
    report["runtime_image"] = image
    report["runtime_image_id"] = image_info["Id"]
    (output / "acceptance.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--inside", choices=("prepare", "run"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.sha256):
        parser.error("--sha256 requires the expected archive SHA-256")
    try:
        if args.inside:
            inside(args.inside, args.sha256)
        elif args.archive is None or args.output is None:
            parser.error("--archive and --output are required")
        else:
            drive(args.archive, args.sha256, args.output, args.image)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"Runtime acceptance failed: {error}\n")


if __name__ == "__main__":
    main()
