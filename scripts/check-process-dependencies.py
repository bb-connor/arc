#!/usr/bin/env python3
"""Keep custody issuer dependencies out of default kernel and worker builds."""

import argparse
import json
import re
import subprocess
from pathlib import Path


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
        packages = sorted(set(re.findall(r"^([\w-]+ v\S+)", output, re.MULTILINE)))
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
        missing = sorted(required - names)
        report[root] = {
            "packages": packages,
            "package_count": len(packages),
            "forbidden_issuer_dependencies": forbidden,
            "missing_kernel_dependencies": missing,
        }
    print(json.dumps(report, indent=2))
    return int(
        any(
            row["forbidden_issuer_dependencies"] or row["missing_kernel_dependencies"]
            for row in report.values()
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
