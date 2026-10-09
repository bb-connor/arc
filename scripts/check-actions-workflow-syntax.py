#!/usr/bin/env python3
"""Validate known authority extensions, then lint remaining workflow syntax."""

from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import yaml

SPEC = importlib.util.spec_from_file_location(
    "trusted_queue_contract", Path(__file__).with_name("check-security-ci-contract.py")
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load trusted authority queue contracts")
CONTRACT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CONTRACT
SPEC.loader.exec_module(CONTRACT)


def mapping(node: yaml.Node) -> dict[str, yaml.Node]:
    if not isinstance(node, yaml.MappingNode):
        raise CONTRACT.ContractError("workflow mapping is malformed")
    result = {}
    for key, value in node.value:
        if not isinstance(key, yaml.ScalarNode) or key.value in result:
            raise CONTRACT.ContractError("duplicate or non-scalar workflow member")
        result[key.value] = value
    return result


def normalize_known_extensions(name: str, text: str) -> tuple[str, list[dict]]:
    tree = yaml.compose(text, Loader=yaml.BaseLoader)
    removed: set[int] = set()
    proofs: list[dict] = []
    lines = text.splitlines(keepends=True)

    def visit(node: yaml.Node, path: tuple[str, ...], ancestors: set[int]) -> None:
        if id(node) in ancestors:
            raise CONTRACT.ContractError("cyclic workflow alias")
        ancestors = ancestors | {id(node)}
        if isinstance(node, yaml.MappingNode):
            fields = mapping(node)
            if "cache-mode" in fields:
                # GitHub enforces this permission at the cache service. Keep
                # the exact lane contract while older actionlint parsers catch
                # every other syntax error. Job overrides are not permitted.
                # https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#cache-mode
                mode = fields["cache-mode"]
                if name != "lane-test.yml" or path:
                    raise CONTRACT.ContractError("cache compatibility is restricted to the lane workflow root")
                if not isinstance(mode, yaml.ScalarNode) or mode.value != "read":
                    raise CONTRACT.ContractError("lane workflow requires literal read-only cache authority")
                line = mode.start_mark.line
                if mode.end_mark.line != line or not re.fullmatch(r"cache-mode:\s*read\s*(?:#.*)?\n?", lines[line]):
                    raise CONTRACT.ContractError("unrecognized cache-mode source representation")
                removed.add(line)
                proofs.append({"workflow": name, "cache-mode": "read"})
            if path and path[-1] == "concurrency" and "queue" in fields:
                if len(path) != 3 or path[0] != "jobs":
                    raise CONTRACT.ContractError("queue compatibility is restricted to exact authority jobs")
                if any(not isinstance(value, yaml.ScalarNode) for value in fields.values()):
                    raise CONTRACT.ContractError("authority concurrency values must be literal scalars")
                values = {key: value.value for key, value in fields.items()}
                CONTRACT.validate_authority_queue(name, path[1], values)
                queue = fields["queue"]
                line = queue.start_mark.line
                if queue.end_mark.line != line or not re.fullmatch(r"\s*queue:\s*max\s*(?:#.*)?\n?", lines[line]):
                    raise CONTRACT.ContractError("unrecognized queue source representation")
                if line in removed:
                    raise CONTRACT.ContractError("shared authority queue alias is not supported")
                removed.add(line)
                proofs.append({"workflow": name, "job": path[1], "concurrency": values})
            for key, value in fields.items():
                visit(value, path + (key,), ancestors)
        elif isinstance(node, yaml.SequenceNode):
            for index, value in enumerate(node.value):
                visit(value, path + (str(index),), ancestors)

    if tree is None:
        raise CONTRACT.ContractError("empty workflow")
    visit(tree, (), set())
    if name == "lane-test.yml" and not any("cache-mode" in proof for proof in proofs):
        raise CONTRACT.ContractError("lane workflow requires explicit read-only cache authority")
    return "".join(line for index, line in enumerate(lines) if index not in removed), proofs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--actionlint", default="actionlint")
    parser.add_argument("files", type=Path, nargs="*")
    args = parser.parse_args()
    root = args.root.resolve()
    directory = root / ".github/workflows"
    files = args.files or sorted((*directory.glob("*.yml"), *directory.glob("*.yaml")))
    count = 0
    cache_count = 0
    result_code = 0
    try:
        for source in files:
            source = source if source.is_absolute() else root / source
            if source.is_symlink() or not source.is_file() or source.parent.resolve() != directory.resolve():
                raise CONTRACT.ContractError("workflow source is not an exact regular repository file")
            text, proofs = normalize_known_extensions(source.name, source.read_text(encoding="utf-8"))
            count += sum("concurrency" in proof for proof in proofs)
            cache_count += sum("cache-mode" in proof for proof in proofs)
            command = [args.actionlint, "-stdin-filename", str(source.relative_to(root))]
            config = root / ".github/actionlint.yaml"
            if config.is_file():
                command += ["-config-file", str(config)]
            checked = subprocess.run(command + ["-"], input=text, cwd=root, text=True,
                                     capture_output=True, check=False, timeout=120)
            sys.stdout.write(checked.stdout)
            sys.stderr.write(checked.stderr)
            if checked.returncode:
                result_code = checked.returncode
    except (CONTRACT.ContractError, OSError, ValueError, yaml.YAMLError, subprocess.TimeoutExpired) as error:
        print(f"workflow syntax validation failed: {error}", file=sys.stderr)
        return 1
    print(f"queue contracts verified: {count}; read-only cache contracts verified: {cache_count}; "
          f"remaining workflow syntax exit: {result_code}; "
          "hosted workflow acceptance remains unverified")
    return result_code


if __name__ == "__main__":
    raise SystemExit(main())
