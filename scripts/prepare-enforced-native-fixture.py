#!/usr/bin/env python3
"""Create explicit native-consumer inputs after the enforcing-host probe passes."""

import argparse
import hashlib
import json
import os
import platform
import stat
import tempfile
from pathlib import Path


def validate_grants(paths: list[Path], protected: list[Path]) -> list[Path]:
    grants = sorted({path.resolve(strict=True) for path in paths})
    if not grants:
        raise ValueError("native fixture requires explicit read grants")
    for grant in grants:
        if not grant.is_absolute() or grant == Path("/"):
            raise ValueError("read grants must be absolute non-root paths")
        if any(
            secret == grant or grant in secret.parents or secret in grant.parents
            for secret in protected
        ):
            raise ValueError(
                "read grants include fixture authority or its independent anchor"
            )
        if "\n" in str(grant) or "\r" in str(grant):
            raise ValueError("read grants cannot contain line separators")
    return grants


def prepare(helper: Path, directory: Path, paths: list[Path], github_env: Path) -> None:
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        raise ValueError("native consumer fixture requires Linux x86_64")
    if os.getuid() == 0 or os.getgid() == 0:
        raise ValueError("native consumers must run as a non-root operator")
    groups = sorted(set(os.getgroups()) - {os.getgid()})
    if 0 in groups or len(groups) > 64:
        raise ValueError("invalid supplementary group set")
    helper = helper.resolve(strict=True)
    if not stat.S_ISREG(helper.stat().st_mode) or not os.access(helper, os.X_OK):
        raise ValueError("native helper must be an executable regular file")
    directory = directory.absolute()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    anchor = Path(tempfile.mkdtemp(prefix="chio-native-anchors-", dir="/dev/shm"))
    try:
        if anchor.stat().st_dev == directory.stat().st_dev:
            raise ValueError("receipt anchors require an independent filesystem")
        protected = [directory.resolve(), anchor]
        if workspace := os.environ.get("GITHUB_WORKSPACE"):
            protected.append((Path(workspace) / ".git").resolve())
        grants = validate_grants(paths, protected)
        grants_file = directory / "read-paths.txt"
        grants_file.write_text(
            "".join(f"{path}\n" for path in grants), encoding="utf-8"
        )
        grants_file.chmod(0o600)
        settings = {
            "CHIO_CAGE_INIT": str(helper),
            "CHIO_RECEIPT_ANCHOR_ROOT": str(anchor),
            "CHIO_CAGE_READ_PATHS_FILE": str(grants_file),
            "CHIO_CAGE_EXECUTION_UID": str(os.getuid()),
            "CHIO_CAGE_EXECUTION_GID": str(os.getgid()),
            "CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS": ",".join(
                str(group) for group in groups
            ),
        }
        if any("\n" in value or "\r" in value for value in settings.values()):
            raise ValueError("fixture settings cannot contain line separators")
        (directory / "fixture.json").write_text(
            json.dumps(
                {
                    "schema": "chio.native-consumer-fixture.v1",
                    "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
                    "source_sha": os.environ.get("GITHUB_SHA"),
                    "kernel": platform.release(),
                    "settings": settings,
                    "read_paths": [str(path) for path in grants],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        with github_env.open("a", encoding="utf-8") as handle:
            for name, value in settings.items():
                handle.write(f"{name}={value}\n")
    except BaseException:
        anchor.rmdir()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--read-path", action="append", default=[], type=Path)
    parser.add_argument("--github-env", required=True, type=Path)
    args = parser.parse_args()
    prepare(args.helper, args.directory, args.read_path, args.github_env)


if __name__ == "__main__":
    main()
