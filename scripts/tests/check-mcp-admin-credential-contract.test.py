#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_mcp_admin_credential_contract",
    ROOT / "scripts/check-mcp-admin-credential-contract.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load MCP admin credential checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

ADMIN_FLAG = re.compile(r"--admin-token(?:=|\s+)(?:\"[^\"]+\"|'[^']+'|[^\s\\]+)")
FIXTURE_PATHS = sorted(
    {
        *CHECKER.SHELL_CALLSITE_COUNTS,
        *CHECKER.PYTHON_CALLSITE_COUNTS,
        *CHECKER.RUST_CALLSITE_COUNTS,
        ".github/workflows/ci.yml",
    }
)


def seed_fixture(root: Path) -> None:
    for relative in FIXTURE_PATHS:
        source = ROOT / relative
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def replace_command_admin(body: str, replacement: str, occurrence: int) -> str:
    lines = body.splitlines(keepends=True)
    markers = [
        index
        for index, line in enumerate(lines)
        if CHECKER.SHELL_MARKER.search(line)
        and line.rstrip().endswith("\\")
        and not line.strip().startswith("#")
    ]
    if occurrence >= len(markers):
        raise AssertionError(
            f"command mutation index {occurrence} exceeds {len(markers)} matches"
        )
    start = markers[occurrence]
    while start > 0 and lines[start - 1].rstrip().endswith("\\"):
        start -= 1
    end = markers[occurrence]
    while end < len(lines) - 1 and lines[end].rstrip().endswith("\\"):
        end += 1
    command = "".join(lines[start : end + 1])
    mutated, count = ADMIN_FLAG.subn(replacement, command, count=1)
    if count != 1:
        raise AssertionError(
            "serve-http command did not contain exactly one admin flag"
        )
    return "".join(lines[:start]) + mutated + "".join(lines[end + 1 :])


def replace_once(old: str, new: str) -> Callable[[str], str]:
    return lambda body: body.replace(old, new, 1)


def assert_rejected(
    label: str,
    relative: str,
    mutate: Callable[[str], str],
    expected_error: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-mcp-admin-contract-") as raw:
        fixture = Path(raw)
        seed_fixture(fixture)
        path = fixture / relative
        original = path.read_text(encoding="utf-8")
        mutated = mutate(original)
        if mutated == original:
            raise AssertionError(f"{label}: mutation did not change its fixture")
        path.write_text(mutated, encoding="utf-8")
        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"credential contract accepted mutation: {label}")


CHECKER.validate(ROOT)

expected_total = sum(CHECKER.SHELL_CALLSITE_COUNTS.values())
actual_commands = CHECKER._discover_shell_commands(ROOT)
if len(actual_commands) != expected_total:
    raise AssertionError(
        f"callsite inventory expected {expected_total} commands, found {len(actual_commands)}"
    )

for relative, count in CHECKER.SHELL_CALLSITE_COUNTS.items():
    if relative in CHECKER.ENV_ADMIN_CALLSITES:
        continue
    for occurrence in range(count):
        assert_rejected(
            f"missing admin flag in {relative} occurrence {occurrence + 1}",
            relative,
            lambda body, occurrence=occurrence: replace_command_admin(
                body, "", occurrence
            ),
            "must pass exactly one explicit --admin-token",
        )
        assert_rejected(
            f"reused auth credential in {relative} occurrence {occurrence + 1}",
            relative,
            lambda body, occurrence=occurrence: replace_command_admin(
                body,
                '--admin-token "${CHIO_AUTH_TOKEN}"',
                occurrence,
            ),
            "dedicated admin credential",
        )

assert_rejected(
    "systemd unit omits admin credential declaration",
    "docs/release/systemd/chio-mcp-edge.service",
    replace_once(
        "Provide CHIO_AUTH_TOKEN, CHIO_ADMIN_TOKEN, CHIO_CONTROL_TOKEN",
        "Provide CHIO_AUTH_TOKEN and CHIO_CONTROL_TOKEN",
    ),
    "omits exact environment credential contract statements",
)
assert_rejected(
    "systemd unit exposes a reused admin credential in argv",
    "docs/release/systemd/chio-mcp-edge.service",
    replace_once(
        "  --listen 127.0.0.1:8931 \\\n",
        "  --listen 127.0.0.1:8931 \\\n  --admin-token ${CHIO_AUTH_TOKEN} \\\n",
    ),
    "must keep bearer credentials out of the process argv",
)

assert_rejected(
    "equality-prone default",
    "examples/internet-of-agents-incident-network/smoke.sh",
    replace_once(
        'CHIO_ADMIN_TOKEN="${CHIO_ADMIN_TOKEN:-demo-admin-token}"',
        'CHIO_ADMIN_TOKEN="${CHIO_ADMIN_TOKEN:-demo-token}"',
    ),
    "equality-prone admin/auth token default",
)

assert_rejected(
    "python launcher omits admin environment",
    "examples/docker/mcp_demo_entrypoint.py",
    replace_once('        "CHIO_ADMIN_TOKEN": admin_token,\n', ""),
    "omits exact admin credential separation statements",
)
assert_rejected(
    "python launcher reuses auth as admin",
    "examples/docker/mcp_demo_entrypoint.py",
    replace_once(
        '        "CHIO_ADMIN_TOKEN": admin_token,',
        '        "CHIO_ADMIN_TOKEN": auth_token,',
    ),
    "omits exact admin credential separation statements",
)

assert_rejected(
    "conformance launcher omits admin environment",
    "crates/tooling/chio-conformance/src/runner.rs",
    replace_once(
        '        .env("CHIO_ADMIN_TOKEN", &options.admin_token);',
        '        .env_remove("CHIO_ADMIN_TOKEN");',
    ),
    "omits exact child credential isolation statements",
)
assert_rejected(
    "conformance launcher reuses auth as admin",
    "crates/tooling/chio-conformance/src/runner.rs",
    replace_once(
        '.env("CHIO_ADMIN_TOKEN", &options.admin_token)',
        '.env("CHIO_ADMIN_TOKEN", &options.auth_token)',
    ),
    "omits exact child credential isolation statements",
)
assert_rejected(
    "conformance harness omits credential preflight",
    "crates/tooling/chio-conformance/src/runner.rs",
    replace_once("    validate_conformance_credentials(options)?;\n", ""),
    "omits exact child credential isolation statements",
)
assert_rejected(
    "conformance harness performs an effect before credential preflight",
    "crates/tooling/chio-conformance/src/runner.rs",
    replace_once(
        "    validate_conformance_credentials(options)?;\n",
        "    let _ = fs::metadata(&options.results_dir);\n"
        "    validate_conformance_credentials(options)?;\n",
    ),
    "must validate credentials before every filesystem or process effect",
)
assert_rejected(
    "conformance harness inverts credential separation",
    "crates/tooling/chio-conformance/src/runner.rs",
    replace_once(
        "    if options.auth_token == options.admin_token {",
        "    if options.auth_token != options.admin_token {",
    ),
    "omits exact child credential isolation statements",
)
assert_rejected(
    "conformance harness accepts a missing auth credential",
    "crates/tooling/chio-conformance/src/runner.rs",
    replace_once("    if options.auth_token.is_empty()", "    if false"),
    "omits exact child credential isolation statements",
)

assert_rejected(
    "CI omits the credential gate",
    ".github/workflows/ci.yml",
    replace_once(
        "          python3 ./scripts/check-mcp-admin-credential-contract.py\n",
        "",
    ),
    "CI must run exactly once",
)

assert_rejected(
    "terminal serve-http marker drops the remaining credential flags",
    "deploy/SIDECAR_BUILD_GUIDE.md",
    replace_once("chio mcp serve-http \\\n", "chio mcp serve-http\n"),
    "must pass exactly one explicit --admin-token",
)

with tempfile.TemporaryDirectory(prefix="chio-mcp-admin-contract-") as raw:
    fixture = Path(raw)
    seed_fixture(fixture)
    unexpected = fixture / "examples/unexpected-hosted-edge.sh"
    unexpected.write_text(
        "#!/usr/bin/env bash\n"
        'chio mcp serve-http --policy /etc/chio/policy.yaml --admin-token "${CHIO_ADMIN_TOKEN}" -- /usr/local/bin/tool-server\n',
        encoding="utf-8",
    )
    try:
        CHECKER.validate(fixture)
    except CHECKER.ContractError as error:
        if "callsite inventory drifted" not in str(error):
            raise AssertionError(f"unexpected callsite rejection: {error}") from error
    else:
        raise AssertionError("credential contract accepted a one-line callsite")

with tempfile.TemporaryDirectory(prefix="chio-mcp-admin-contract-") as raw:
    fixture = Path(raw)
    seed_fixture(fixture)
    unexpected = fixture / "examples/unexpected-split-hosted-edge.sh"
    unexpected.write_text(
        "#!/usr/bin/env bash\n"
        "chio \\\n"
        "  mcp \\\n"
        '  serve-http --admin-token "${CHIO_ADMIN_TOKEN}" -- /usr/local/bin/tool-server\n',
        encoding="utf-8",
    )
    try:
        CHECKER.validate(fixture)
    except CHECKER.ContractError as error:
        if "callsite inventory drifted" not in str(error):
            raise AssertionError(
                f"unexpected split-callsite rejection: {error}"
            ) from error
    else:
        raise AssertionError("credential contract accepted a split terminal callsite")

with tempfile.TemporaryDirectory(prefix="chio-mcp-admin-contract-") as raw:
    fixture = Path(raw)
    seed_fixture(fixture)
    unexpected = fixture / "examples/unexpected_hosted_edge.py"
    unexpected.write_text('ARGS = ["mcp", "serve-http"]\n', encoding="utf-8")
    try:
        CHECKER.validate(fixture)
    except CHECKER.ContractError as error:
        if "Python callsite inventory drifted" not in str(error):
            raise AssertionError(
                f"unexpected Python-callsite rejection: {error}"
            ) from error
    else:
        raise AssertionError(
            "credential contract accepted an unenumerated Python callsite"
        )

with tempfile.TemporaryDirectory(prefix="chio-mcp-admin-contract-") as raw:
    fixture = Path(raw)
    seed_fixture(fixture)
    unexpected = fixture / "crates/tooling/chio-conformance/src/unexpected.rs"
    unexpected.write_text(
        'fn launch(command: &mut std::process::Command) { command.arg("mcp").arg("serve-http"); }\n',
        encoding="utf-8",
    )
    try:
        CHECKER.validate(fixture)
    except CHECKER.ContractError as error:
        if "Rust callsite inventory drifted" not in str(error):
            raise AssertionError(
                f"unexpected Rust-callsite rejection: {error}"
            ) from error
    else:
        raise AssertionError(
            "credential contract accepted an unenumerated Rust callsite"
        )

with tempfile.TemporaryDirectory(prefix="chio-mcp-admin-contract-") as raw:
    fixture = Path(raw)
    seed_fixture(fixture)
    unexpected = fixture / "deploy/unexpected-hosted-edge.yaml"
    unexpected.parent.mkdir(parents=True, exist_ok=True)
    unexpected.write_text(
        'args:\n  - "mcp"\n  - "serve-http"\n',
        encoding="utf-8",
    )
    try:
        CHECKER.validate(fixture)
    except CHECKER.ContractError as error:
        if "structured callsite inventory drifted" not in str(error):
            raise AssertionError(
                f"unexpected YAML-callsite rejection: {error}"
            ) from error
    else:
        raise AssertionError(
            "credential contract accepted an unenumerated YAML callsite"
        )

print(
    "check-mcp-admin-credential-contract.test.py: "
    f"{(expected_total - len(CHECKER.ENV_ADMIN_CALLSITES)) * 2 + 18} credential mutations rejected"
)
