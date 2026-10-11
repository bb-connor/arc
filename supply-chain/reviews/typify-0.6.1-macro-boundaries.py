#!/usr/bin/env python3
"""Check the reviewed macro's compilation boundaries in an extracted audit workspace."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(CARGO_BUILD_JOBS="1", CARGO_INCREMENTAL="0")
    results = []
    with tempfile.TemporaryDirectory(prefix="typify-macro-boundaries-") as temporary:
        root = Path(temporary)
        (root / "src").mkdir()
        (root / "Cargo.toml").write_text(
            '[package]\nname="typify-macro-boundaries"\nversion="0.0.0"\n'
            'edition="2021"\n[workspace]\n[dependencies]\n'
            f'typify={{path={json.dumps(str(workspace / "typify-0.6.1"))}}}\n'
            'serde={version="1",features=["derive"]}\n'
            '[patch.crates-io]\n'
            f'typify-impl={{path={json.dumps(str(workspace / "typify-impl-0.6.1"))}}}\n'
            f'typify-macro={{path={json.dumps(str(workspace / "typify-macro-0.6.1"))}}}\n'
        )
        (root / "Cargo.lock").write_bytes((workspace / "Cargo.lock").read_bytes())
        schema = {
            "title": "Fixture",
            "description": 'A quoted "description" with braces {}; and newlines\n',
            "type": "object",
            "additionalProperties": False,
            "required": ["value"],
            "properties": {"value": {"type": "string"}},
        }
        (root / "schema.json").write_text(json.dumps(schema))
        (root / "malformed.json").write_text('{"title":')
        cases = [
            ("relative-schema", 'typify::import_types!("schema.json");\n'
             'fn fixture() -> Fixture { Fixture { value: "ok".into() } }\n', True, None),
            ("absolute-schema", f'typify::import_types!({json.dumps(str(root / "schema.json"))});\n',
             True, None),
            ("missing-schema", 'typify::import_types!("absent.json");\n',
             False, "couldn't read file absent.json"),
            ("malformed-json", 'typify::import_types!("malformed.json");\n',
             False, "proc macro panicked"),
            ("malformed-setting", 'typify::import_types!(schema = 42);\n',
             False, "expected string literal"),
        ]
        for name, source, success, diagnostic in cases:
            (root / "src/lib.rs").write_text(source)
            command = ["cargo", "check", "--offline", "--manifest-path", str(root / "Cargo.toml")]
            result = subprocess.run(command, env=environment, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            log = evidence / f"macro-{name}.log"
            log.write_text(result.stdout)
            matched = (result.returncode == 0) == success
            if diagnostic:
                matched = matched and diagnostic in result.stdout
            results.append({"case": name, "command": command, "exit": result.returncode,
                            "expected_success": success, "diagnostic": diagnostic,
                            "passed": matched,
                            "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()})
    (evidence / "macro-boundaries.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))
    if not all(result["passed"] for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
