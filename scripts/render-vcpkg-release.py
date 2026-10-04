#!/usr/bin/env python3
"""Bind release ports to the repository, commit and archive that were qualified."""

import argparse
import pathlib
import re
import shutil

PORTS = ("chio-cpp", "chio-cpp-kernel", "chio-guard-cpp", "chio-drogon")


def render(template: str, repository: str, commit: str, archive_sha512: str) -> str:
    for value, pattern in (
        (repository, r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"),
        (commit, r"[0-9a-f]{40}"),
        (archive_sha512, r"[0-9a-f]{128}"),
    ):
        if re.fullmatch(pattern, value) is None:
            raise ValueError("release source requires an exact repository, commit and archive digest")
    for field, expected, replacement in (
        ("REPO", "backbay-labs/chio", f'"{repository}"'),
        ("REF", '"cpp/v${VERSION}"', f'"{commit}"'),
        ("SHA512", "0", archive_sha512),
    ):
        matches = list(re.finditer(rf"^    {field} (.+)$", template, re.MULTILINE))
        if len(matches) != 1 or matches[0][1] != expected:
            raise ValueError(f"unexpected {field} template; review release source binding")
        template = re.sub(rf"^    {field} .+$", f"    {field} {replacement}", template, flags=re.MULTILINE)
    # Published ports cannot select an unaudited moving branch via --head.
    head_refs = re.findall(r"^\s*HEAD_REF\b[^\n]*", template, re.MULTILINE)
    if head_refs != ["    HEAD_REF main"]:
        raise ValueError("unexpected moving branch template; review release source binding")
    template = template.replace("    HEAD_REF main\n", "")
    return template


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--archive-sha512", required=True)
    parser.add_argument("--ports", type=pathlib.Path, required=True)
    parser.add_argument("--registry", type=pathlib.Path, required=True)
    args = parser.parse_args()
    # Validate all templates before writing any publishable port.
    rendered = {
        port: render((args.ports / port / "portfile.cmake").read_text(),
                     args.source_repository, args.source_sha, args.archive_sha512)
        for port in PORTS
    }
    for port, content in rendered.items():
        destination = args.registry / "ports" / port
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.ports / port / "vcpkg.json", destination / "vcpkg.json")
        (destination / "portfile.cmake").write_text(content)


if __name__ == "__main__":
    main()
