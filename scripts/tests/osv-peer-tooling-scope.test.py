#!/usr/bin/env python3
"""Exercise OSV's real directory and expiry boundaries with benign lock records."""

import argparse
import copy
import datetime
import json
import pathlib
import re
import shutil
import subprocess
import tempfile
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[2]
ADVISORIES = {"GHSA-vfj7-8cjw-p6xm", "GHSA-86w9-cpqp-85rv"}
DEADLINE = datetime.datetime(2026, 10, 18, tzinfo=datetime.timezone.utc)
REVIEWED_PARENTS = {
    "braces": {("node_modules/micromatch", "4.0.8", "^3.0.3")},
    "micromatch": {
        ("node_modules/metro-file-map", "0.84.4", "^4.0.4"),
        ("node_modules/@expo/metro-file-map", "57.0.0", "^4.0.4"),
    },
    "node-forge": {
        ("node_modules/@expo/cli", "57.0.4", "^1.3.3"),
        ("node_modules/@expo/code-signing-certificates", "0.0.6", "^1.3.3"),
    },
    "@expo/code-signing-certificates": {("node_modules/@expo/cli", "57.0.4", "^0.0.6")},
    "@expo/cli": {("node_modules/expo", "57.0.2", "^57.0.4")},
    "metro-file-map": {
        ("node_modules/@expo/metro", "56.0.0", "0.84.4"),
        ("node_modules/metro", "0.84.4", "0.84.4"),
    },
    "@expo/metro-file-map": {("node_modules/@expo/cli", "57.0.4", "^57.0.0")},
}


def validate_reviewed_tree(source: dict, directory: pathlib.Path) -> None:
    lockfiles = {
        path.name
        for path in directory.iterdir()
        if path.is_file() and ("lock" in path.name or path.name == "npm-shrinkwrap.json")
    }
    if lockfiles != {"package-lock.json"}:
        raise AssertionError(f"peer-tooling lock inventory changed: {lockfiles}; re-review required")
    packages = source["packages"]
    for name, version in (("braces", "3.0.3"), ("node-forge", "1.4.0")):
        matches = {key: package for key, package in packages.items() if key.rsplit("node_modules/", 1)[-1] == name}
        package = matches.get(f"node_modules/{name}", {})
        if len(matches) != 1 or package.get("version") != version or package.get("peer") is not True or package.get("dev") is True:
            raise AssertionError(f"{name} version or peer-tooling status changed; re-review required")
    for name, expected in REVIEWED_PARENTS.items():
        actual = {
            (key, package.get("version"), block[name])
            for key, package in packages.items()
            for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
            if name in (block := package.get(field, {}))
        }
        if actual != expected:
            raise AssertionError(f"{name} parent chain changed: {actual}; re-review required")


def expect_rejected(label: str, operation) -> None:
    try:
        operation()
    except AssertionError:
        print(f"PASS {label}: review guard rejected changed evidence")
    else:
        raise AssertionError(f"{label}: changed evidence was accepted")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scanner", default=shutil.which("osv-scanner"))
    args = parser.parse_args()
    if not args.scanner:
        parser.error("install osv-scanner or provide --scanner PATH")

    config_path = ROOT / "sdks/typescript/osv-scanner.toml"
    if not config_path.exists():
        raise AssertionError("directory-local peer-tooling advisory disposition is missing")
    config_text = config_path.read_text()
    config = tomllib.loads(config_text)
    entries = {entry["id"]: entry for entry in config.get("IgnoredVulns", [])}
    now = datetime.datetime.now(datetime.timezone.utc)
    for advisory in ADVISORIES:
        expiry = entries[advisory].get("ignoreUntil")
        if not isinstance(expiry, datetime.datetime) or expiry.tzinfo is None:
            raise AssertionError(f"{advisory} requires an explicit UTC expiry")
        if not now < expiry <= DEADLINE:
            raise AssertionError(f"{advisory} exception expired or exceeds reviewed deadline")

    # A --config override ignores directory-local configuration and could silently
    # extend an accepted advisory to unrelated lockfiles.
    workflow = (ROOT / ".github/workflows/cve-monitor.yml").read_text()
    marker = "      - name: osv-scanner Python and npm ecosystems\n"
    scan_step = workflow.partition(marker)[2].split("\n      - name:", 1)[0]
    if not scan_step or "--config" in scan_step:
        raise AssertionError("CVE scan must discover directory-local OSV configs")

    source = json.loads((ROOT / "sdks/typescript/package-lock.json").read_text())
    validate_reviewed_tree(source, config_path.parent)
    fixture = {
        "name": "chio-osv-scope-fixture",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "packages": {},
    }
    for package in ("braces", "node-forge"):
        key = f"node_modules/{package}"
        fixture["packages"][key] = source["packages"][key]

    with tempfile.TemporaryDirectory(prefix="chio-osv-peer-scope-") as temporary:
        root = pathlib.Path(temporary)
        inventory = root / "inventory"
        inventory.mkdir()
        (inventory / "package-lock.json").write_text("{}")
        changed = copy.deepcopy(source)
        changed["packages"]["node_modules/braces"]["version"] = "3.0.4"
        expect_rejected("version change", lambda: validate_reviewed_tree(changed, inventory))
        changed = copy.deepcopy(source)
        changed["packages"]["new-consumer"] = {"version": "1.0.0", "dependencies": {"node-forge": "1.4.0"}}
        expect_rejected("new consumer", lambda: validate_reviewed_tree(changed, inventory))
        (inventory / "yarn.lock").write_text("")
        expect_rejected("another same-directory lock", lambda: validate_reviewed_tree(source, inventory))
        shutil.rmtree(inventory)
        paths = ("scoped", "scoped/child", "outside")
        for path in paths:
            directory = root / path
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "package-lock.json").write_text(json.dumps(fixture))
        local_config = root / "scoped/osv-scanner.toml"

        def scan(label: str, expected: set[str], extra: set[str] | None = None) -> None:
            output = root / f"{label}.json"
            result = subprocess.run(
                [args.scanner, "--recursive", "--format", "json", "--output", str(output), str(root)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 1 or not output.exists():
                raise AssertionError(
                    f"{label}: expected a blocking scan, got {result.returncode}\n"
                    f"{result.stdout}\n{result.stderr}"
                )
            findings = {}
            for group in json.loads(output.read_text()).get("results", []):
                ids = {
                    vulnerability["id"]
                    for package in group.get("packages", [])
                    for vulnerability in package.get("vulnerabilities", [])
                }
                if ids:
                    path = pathlib.Path(group["source"]["path"]).parent.relative_to(root)
                    findings[path.as_posix()] = ids
            if extra is not None:
                scoped = findings.pop("scoped", set())
                if not extra.issubset(scoped) or scoped.intersection(ADVISORIES):
                    raise AssertionError(f"{label}: unrelated advisories were not kept blocking: {scoped}")
                print(f"PASS {label}: unrelated same-package advisories still block: {', '.join(sorted(scoped))}")
            if findings != {path: ADVISORIES for path in expected}:
                raise AssertionError(f"{label}: unexpected findings {findings}")
            if extra is None:
                print(f"PASS {label}: both advisories block in {', '.join(sorted(expected))}")

        scan("unaccepted", set(paths))
        local_config.write_text(config_text)
        scan("directory scope", {"scoped/child", "outside"})
        # Benign historical package records demonstrate that these exact-ID
        # entries do not suppress a different advisory on the same package.
        for package, version, advisory in (
            ("braces", "3.0.2", "GHSA-grv7-fg5c-xmjg"),
            ("node-forge", "1.3.3", "GHSA-q67f-28xg-22rw"),
        ):
            older = copy.deepcopy(fixture)
            older["packages"][f"node_modules/{package}"] = {"version": version}
            (root / "scoped/package-lock.json").write_text(json.dumps(older))
            scan(f"unrelated {package} advisory", {"scoped/child", "outside"}, {advisory})
        (root / "scoped/package-lock.json").write_text(json.dumps(fixture))
        local_config.write_text(
            re.sub(
                r"(?m)^ignoreUntil\s*=.*$",
                "ignoreUntil = 2000-01-01T00:00:00Z",
                config_text,
            )
        )
        scan("expired", set(paths))


if __name__ == "__main__":
    main()
