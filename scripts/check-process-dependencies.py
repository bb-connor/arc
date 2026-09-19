#!/usr/bin/env python3
"""Keep custody issuer dependencies out of default kernel and worker builds."""

import argparse
import json
import re
import subprocess
from pathlib import Path


def classify_dependency_tree(root: str, output: str) -> dict:
    """Parse complete Cargo tree output and classify the default dependency boundary."""
    number = r"(?:0|[1-9][0-9]*)"
    prerelease = rf"(?:{number}|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    version = rf"{number}\.{number}\.{number}(?:-{prerelease}(?:\.{prerelease})*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    package_line = re.compile(
        rf"(?P<package>[A-Za-z0-9_-]+ v{version})(?: \([^\r\n]+\))?(?: \(\*\))?"
    )
    packages = set()
    lines = output.splitlines()
    if not lines:
        raise ValueError("Cargo dependency tree is empty")
    for line_number, line in enumerate(lines, 1):
        match = package_line.fullmatch(line)
        if match is None:
            raise ValueError(
                f"Cargo dependency tree has a malformed line {line_number}"
            )
        packages.add(match.group("package"))
    names = {package.split()[0] for package in packages}
    # rustls-native-certs uses openssl-probe only to discover certificate
    # paths. It has no OpenSSL dependency or native-library binding.
    forbidden = sorted(
        name
        for name in names
        if name.startswith("webauthn")
        or (name.startswith("openssl") and name != "openssl-probe")
    )
    required = {
        root,
        "chio-kernel",
        "chio-kernel-core",
        "chio-core-types",
        "chio-custody-hw",
    }
    return {
        "packages": sorted(packages),
        "package_count": len(packages),
        "forbidden_issuer_dependencies": forbidden,
        "missing_kernel_dependencies": sorted(required - names),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "Cargo.toml",
    )
    arguments = parser.parse_args()
    report = {}
    for root in ("chio-kernel", "chio-process", "chio-cli"):
        output = subprocess.check_output(
            [
                "cargo",
                "tree",
                "--locked",
                "--manifest-path",
                str(arguments.manifest_path),
                "-p",
                root,
                "--edges",
                "normal,build",
                "--prefix",
                "none",
                "--format",
                "{p}",
            ],
            text=True,
            timeout=120,
        )
        try:
            report[root] = classify_dependency_tree(root, output)
        except ValueError as error:
            report[root] = {"parse_error": str(error)}
    print(json.dumps(report, indent=2))
    return int(
        any(
            row.get("parse_error")
            or row["forbidden_issuer_dependencies"]
            or row["missing_kernel_dependencies"]
            for row in report.values()
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
