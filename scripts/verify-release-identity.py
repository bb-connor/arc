#!/usr/bin/env python3
"""Pin Chio releases to the canonical repository, workflow and exact tag."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPOSITORY = "bb-connor/arc"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
COSIGN_VERSION = "v2.4.1"
WORKFLOWS = {"binaries": "release-binaries.yml", "pypi": "release-pypi.yml", "npm": "release-npm.yml"}
SEMVER = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"


def identity(channel, tag):
    prefix = {"binaries": "", "pypi": "py/", "npm": "ts/"}[channel]
    slug = "" if channel == "binaries" else r"(?:[a-z0-9]+(?:-[a-z0-9]+)*-)?"
    match = re.fullmatch(re.escape(prefix) + slug + "v" + SEMVER, tag, flags=re.ASCII)
    if not match:
        raise ValueError(f"invalid {channel} release tag: {tag!r}")
    prerelease = match.group(4)
    if prerelease and any(part.isdigit() and len(part) > 1 and part[0] == "0" for part in prerelease.split(".")):
        raise ValueError("numeric prerelease identifiers must not have leading zeros")
    return f"https://github.com/{REPOSITORY}/.github/workflows/{WORKFLOWS[channel]}@refs/tags/{tag}"


def check_context(channel):
    tag = os.environ.get("GITHUB_REF_NAME", "")
    expected = identity(channel, tag)
    requirements = {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF_TYPE": "tag",
                    "GITHUB_REF": "refs/tags/" + tag,
                    "GITHUB_WORKFLOW_REF": expected.removeprefix("https://github.com/")}
    for name, value in requirements.items():
        if os.environ.get(name) != value:
            raise ValueError(f"{name} must be {value!r}; refusing release signing context")
    return expected


def verify(channel, tag, artifact):
    expected = identity(channel, tag)
    artifact = artifact.resolve(strict=True)
    signature = Path(str(artifact) + ".sig")
    certificate = Path(str(artifact) + ".pem")
    for path in (artifact, signature, certificate):
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing or empty release verification input: {path}")
    version = subprocess.run(["cosign", "version", "--json"], check=True, capture_output=True, text=True)
    if json.loads(version.stdout).get("gitVersion") != COSIGN_VERSION:
        raise ValueError(f"this verification path requires cosign {COSIGN_VERSION}")
    # Literal identity comparison: caller input never becomes an identity regex.
    # Keep public Fulcio, SCT and Rekor verification enabled with cosign defaults.
    return subprocess.run(["cosign", "verify-blob", "--signature", str(signature),
                           "--certificate", str(certificate), "--certificate-identity", expected,
                           "--certificate-oidc-issuer", OIDC_ISSUER, str(artifact)], check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("identity", "verify", "check-context"):
        subparser = commands.add_parser(command)
        subparser.add_argument("--channel", choices=WORKFLOWS, required=True)
        if command != "check-context":
            subparser.add_argument("--tag", required=True)
        if command == "verify":
            subparser.add_argument("--artifact", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "identity":
            print(identity(args.channel, args.tag))
        elif args.command == "check-context":
            print(check_context(args.channel))
        else:
            return verify(args.channel, args.tag, args.artifact)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"release verification refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
