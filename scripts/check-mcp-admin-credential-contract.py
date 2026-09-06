#!/usr/bin/env python3
"""Enforce dedicated admin credentials at every shipped hosted-MCP launch."""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


class ContractError(RuntimeError):
    """A shipped serve-http launch weakens credential separation."""


SHELL_CALLSITE_COUNTS = {
    "deploy/SIDECAR_BUILD_GUIDE.md": 1,
    "docs/operator-runbook/onboarding.md": 1,
    "docs/operator-runbook/topology.md": 1,
    "docs/reference/IDENTITY_FEDERATION_GUIDE.md": 4,
    "docs/release/OPERATIONS_RUNBOOK.md": 1,
    "docs/release/systemd/chio-mcp-edge.service": 1,
    "docs/start-here/PROGRESSIVE_TUTORIAL.md": 1,
    "examples/agent-commerce-network/provider/run-edge.sh": 4,
    "examples/internet-of-agents-incident-network/scenario/lib.sh": 1,
    "examples/internet-of-agents-incident-network/smoke.sh": 1,
    "examples/internet-of-agents-web3-network/scenario/lib.sh": 3,
    "scripts/check-sdk-publication-examples.sh": 1,
}
PYTHON_CALLSITE_COUNTS = {
    "examples/docker/mcp_demo_entrypoint.py": 1,
}
RUST_CALLSITE_COUNTS = {
    "crates/tooling/chio-conformance/src/runner.rs": 1,
}
STRUCTURED_CALLSITE_COUNTS: dict[str, int] = {}
ENV_ADMIN_CALLSITES = {
    "docs/release/systemd/chio-mcp-edge.service",
}
MARKDOWN_NON_INVOCATIONS = {
    ("docs/operator-runbook/index.md", "chio mcp serve-http"),
}
EXECUTABLE_FENCE_LANGUAGES = {"bash", "console", "sh", "shell", "zsh"}
CI_GATE_COMMANDS = (
    "python3 ./scripts/check-mcp-admin-credential-contract.py",
    "python3 ./scripts/tests/check-mcp-admin-credential-contract.test.py",
)

SHELL_SUFFIXES = {".md", ".service", ".sh"}
SHELL_MARKER = re.compile(r"\bmcp\s+serve-http\b")
FENCE_MARKER = re.compile(r"^\s*```\s*([^`]*)$")
TOKEN_FLAG = re.compile(
    r"--(?P<role>admin|auth|control|service)-token(?:=|\s+)"
    r"(?P<value>\"[^\"]+\"|'[^']+'|[^\s\\]+)"
)
TOKEN_ASSIGNMENT = re.compile(
    r"(?m)^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*token)="
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s#]+)",
    re.IGNORECASE,
)
TOKEN_REFERENCE = re.compile(
    r"(?:\$\{?|\b)(?P<name>[A-Za-z_][A-Za-z0-9_]*token)\}?",
    re.IGNORECASE,
)
FALLBACK_VALUE = re.compile(r":-([^}]+)")
YAML_SERVE_HTTP_TOKEN = re.compile(
    r"(?m)^\s*-\s*(?:[\"'])?serve-http(?:[\"'])?\s*(?:#.*)?$"
)
DOCKER_SERVE_HTTP_TOKEN = re.compile(r"[\"']serve-http[\"']")


@dataclass(frozen=True)
class ShellCommand:
    path: str
    line: int
    body: str


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise ContractError(f"missing credential-contract input: {path}") from error


def _discover_shell_commands(root: Path) -> list[ShellCommand]:
    commands: list[ShellCommand] = []
    for directory in (
        root / "deploy",
        root / "docs",
        root / "examples",
        root / "scripts",
    ):
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if not path.is_file() or path.suffix not in SHELL_SUFFIXES:
                continue
            lines = _read(path).splitlines()
            executable_lines: list[int] = []
            if path.suffix == ".md":
                fence_language: str | None = None
                for index, line in enumerate(lines):
                    fence = FENCE_MARKER.match(line)
                    if fence is not None:
                        fence_language = (
                            fence.group(1).strip().lower()
                            if fence_language is None
                            else None
                        )
                        continue
                    if fence_language in EXECUTABLE_FENCE_LANGUAGES:
                        executable_lines.append(index)
            else:
                executable_lines = list(range(len(lines)))

            cursor = 0
            while cursor < len(executable_lines):
                start_position = cursor
                end_position = cursor
                while (
                    end_position < len(executable_lines) - 1
                    and executable_lines[end_position + 1]
                    == executable_lines[end_position] + 1
                    and lines[executable_lines[end_position]].rstrip().endswith("\\")
                ):
                    end_position += 1
                indexes = executable_lines[start_position : end_position + 1]
                cursor = end_position + 1
                if not indexes:
                    continue
                body_lines = lines[indexes[0] : indexes[-1] + 1]
                first_code_line = next(
                    (line.strip() for line in body_lines if line.strip()), ""
                )
                if first_code_line.startswith("#"):
                    continue
                logical = " ".join(
                    line.strip().removesuffix("\\").rstrip() for line in body_lines
                )
                logical = " ".join(logical.split())
                if not SHELL_MARKER.search(logical):
                    continue
                relative = _relative(path, root)
                if (relative, logical) in MARKDOWN_NON_INVOCATIONS:
                    continue
                marker_line = next(
                    (index + 1 for index in indexes if "serve-http" in lines[index]),
                    indexes[0] + 1,
                )
                commands.append(
                    ShellCommand(
                        path=relative,
                        line=marker_line,
                        body="\n".join(body_lines),
                    )
                )
    return commands


def _normalize_token_value(value: str) -> str:
    normalized = value.strip().strip("\"'").strip("<>")
    normalized = normalized.removeprefix("${").removesuffix("}")
    normalized = normalized.removeprefix("$")
    return normalized.strip().lower().replace("-", "_")


def _token_role(name: str) -> str | None:
    upper = name.upper()
    if "ADMIN" in upper:
        return "admin"
    if "AUTH" in upper or "EDGE" in upper:
        return "auth"
    if "CONTROL" in upper or "SERVICE" in upper:
        return "control"
    return None


def _validate_shell_command(command: ShellCommand) -> None:
    flags: dict[str, list[str]] = {}
    for match in TOKEN_FLAG.finditer(command.body):
        flags.setdefault(match.group("role"), []).append(match.group("value"))

    admins = flags.get("admin", [])
    location = f"{command.path}:{command.line}"
    if command.path in ENV_ADMIN_CALLSITES:
        if admins:
            raise ContractError(
                f"{location} must keep bearer credentials out of the process argv"
            )
        return
    if len(admins) != 1:
        raise ContractError(
            f"{location} must pass exactly one explicit --admin-token; found {len(admins)}"
        )

    admin = _normalize_token_value(admins[0])
    if "admin" not in admin or any(
        role in admin for role in ("auth", "edge", "control", "service")
    ):
        raise ContractError(
            f"{location} must source --admin-token from a dedicated admin credential"
        )

    for role in ("auth", "control", "service"):
        for value in flags.get(role, []):
            if _normalize_token_value(value) == admin:
                raise ContractError(
                    f"{location} reuses its {role} credential as --admin-token"
                )


def _literal_assignment_value(value: str) -> str | None:
    unquoted = value.strip().strip("\"'")
    fallback = FALLBACK_VALUE.search(unquoted)
    if fallback is not None:
        return fallback.group(1).strip().lower()
    if "$" not in unquoted and unquoted:
        return unquoted.lower()
    return None


def _validate_assignments(path: str, body: str) -> None:
    literals: dict[str, set[str]] = {}
    for match in TOKEN_ASSIGNMENT.finditer(body):
        name = match.group("name")
        role = _token_role(name)
        if role is None:
            continue
        value = match.group("value")
        for reference in TOKEN_REFERENCE.finditer(value):
            referenced_role = _token_role(reference.group("name"))
            if referenced_role is not None and referenced_role != role:
                raise ContractError(
                    f"{path} aliases {name} to a {referenced_role} credential"
                )
        literal = _literal_assignment_value(value)
        if literal is not None:
            literals.setdefault(role, set()).add(literal)

    for left, right in (("admin", "auth"), ("admin", "control"), ("auth", "control")):
        reused = literals.get(left, set()) & literals.get(right, set())
        if reused:
            value = sorted(reused)[0]
            raise ContractError(
                f"{path} uses equality-prone {left}/{right} token default {value!r}"
            )


def _validate_shell_surface(root: Path) -> None:
    commands = _discover_shell_commands(root)
    actual = Counter(command.path for command in commands)
    expected = Counter(SHELL_CALLSITE_COUNTS)
    if actual != expected:
        missing = sorted((expected - actual).elements())
        unexpected = sorted((actual - expected).elements())
        raise ContractError(
            "serve-http shell/documentation callsite inventory drifted: "
            f"missing={missing}, unexpected={unexpected}"
        )

    for command in commands:
        _validate_shell_command(command)
    for path in sorted(SHELL_CALLSITE_COUNTS):
        body = _read(root / path)
        _validate_assignments(path, body)
        if path in ENV_ADMIN_CALLSITES:
            required = (
                "EnvironmentFile=/etc/chio/chio-mcp-edge.env",
                "Provide CHIO_AUTH_TOKEN, CHIO_ADMIN_TOKEN, CHIO_CONTROL_TOKEN",
                "requires all three bearer tokens and rejects missing or reused credentials",
            )
            missing = [statement for statement in required if statement not in body]
            if missing:
                raise ContractError(
                    f"{path} omits exact environment credential contract statements: {missing}"
                )


def _validate_python_surface(root: Path) -> None:
    actual: Counter[str] = Counter()
    examples = root / "examples"
    if examples.is_dir():
        for path in sorted(examples.rglob("*.py")):
            if "tests" in path.parts or "__pycache__" in path.parts:
                continue
            count = len(re.findall(r'["\']serve-http["\']', _read(path)))
            if count:
                actual[_relative(path, root)] = count
    expected = Counter(PYTHON_CALLSITE_COUNTS)
    if actual != expected:
        missing = sorted((expected - actual).elements())
        unexpected = sorted((actual - expected).elements())
        raise ContractError(
            "serve-http Python callsite inventory drifted: "
            f"missing={missing}, unexpected={unexpected}"
        )
    for relative, expected_count in PYTHON_CALLSITE_COUNTS.items():
        body = _read(root / relative)
        actual_count = len(re.findall(r'(?m)^\s*"serve-http",\s*$', body))
        if actual_count != expected_count:
            raise ContractError(
                f"{relative} serve-http invocation count is {actual_count}, expected {expected_count}"
            )
        required = (
            'admin_token = os.environ.get("CHIO_ADMIN_TOKEN", "")',
            "if len({auth_token, admin_token, control_token}) != 3:",
            '"CHIO_AUTH_TOKEN": auth_token',
            '"CHIO_ADMIN_TOKEN": admin_token',
            '"CHIO_CONTROL_TOKEN": control_token',
        )
        missing = [statement for statement in required if statement not in body]
        if missing:
            raise ContractError(
                f"{relative} omits exact admin credential separation statements: {missing}"
            )


def _validate_rust_surface(root: Path) -> None:
    actual: Counter[str] = Counter()
    crates = root / "crates"
    if crates.is_dir():
        for path in sorted(crates.rglob("*.rs")):
            if "tests" in path.parts:
                continue
            count = _read(path).count('.arg("serve-http")')
            if count:
                actual[_relative(path, root)] = count
    expected = Counter(RUST_CALLSITE_COUNTS)
    if actual != expected:
        missing = sorted((expected - actual).elements())
        unexpected = sorted((actual - expected).elements())
        raise ContractError(
            "serve-http Rust callsite inventory drifted: "
            f"missing={missing}, unexpected={unexpected}"
        )
    for relative, expected_count in RUST_CALLSITE_COUNTS.items():
        body = _read(root / relative)
        actual_count = body.count('.arg("serve-http")')
        if actual_count != expected_count:
            raise ContractError(
                f"{relative} serve-http invocation count is {actual_count}, expected {expected_count}"
            )
        required = (
            '.env("CHIO_ADMIN_TOKEN", &options.admin_token)',
            '.env("CHIO_AUTH_TOKEN", &options.auth_token)',
            '.env_remove("CHIO_MCP_ADMIN_TOKEN")',
            "InvalidCredentials { reason: &'static str }",
            "validate_conformance_credentials(options)?;",
            "if options.auth_token.is_empty()",
            "options.auth_token.trim() != options.auth_token",
            "options.auth_token.chars().any(char::is_control)",
            "if options.admin_token.is_empty()",
            "options.admin_token.trim() != options.admin_token",
            "options.admin_token.chars().any(char::is_control)",
            "if options.auth_token == options.admin_token {",
            'reason: "admin token must differ from auth token"',
            "credential_preflight_rejects_missing_and_reused_tokens_before_effects",
            "credential_preflight_recovers_after_distinct_tokens_are_supplied",
        )
        missing = [statement for statement in required if statement not in body]
        if missing:
            raise ContractError(
                f"{relative} omits exact child credential isolation statements: {missing}"
            )
        if '.env("CHIO_ADMIN_TOKEN", &options.auth_token)' in body:
            raise ContractError(
                f"{relative} maps the admin environment to the auth credential"
            )
        exact_preflight = (
            "pub fn run_conformance_harness(\n"
            "    options: &ConformanceRunOptions,\n"
            ") -> Result<ConformanceRunSummary, RunnerError> {\n"
            "    validate_conformance_credentials(options)?;\n"
            "    if options.results_dir.exists() {"
        )
        if exact_preflight not in body:
            raise ContractError(
                f"{relative} must validate credentials before every filesystem or process effect"
            )


def _validate_structured_surface(root: Path) -> None:
    actual: Counter[str] = Counter()
    for directory in (root / ".github", root / "deploy", root / "examples"):
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix in {".yaml", ".yml"}:
                count = len(YAML_SERVE_HTTP_TOKEN.findall(_read(path)))
            elif path.name.startswith("Dockerfile"):
                count = len(DOCKER_SERVE_HTTP_TOKEN.findall(_read(path)))
            else:
                continue
            if count:
                actual[_relative(path, root)] = count
    expected = Counter(STRUCTURED_CALLSITE_COUNTS)
    if actual != expected:
        missing = sorted((expected - actual).elements())
        unexpected = sorted((actual - expected).elements())
        raise ContractError(
            "serve-http structured callsite inventory drifted: "
            f"missing={missing}, unexpected={unexpected}"
        )


def _validate_ci_gate(root: Path) -> None:
    body = _read(root / ".github/workflows/ci.yml")
    for command in CI_GATE_COMMANDS:
        if body.count(command) != 1:
            raise ContractError(f"CI must run exactly once: {command}")


def validate(root: Path) -> None:
    _validate_shell_surface(root)
    _validate_python_surface(root)
    _validate_rust_surface(root)
    _validate_structured_surface(root)
    _validate_ci_gate(root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    try:
        validate(args.root.resolve())
    except ContractError as error:
        print(f"check-mcp-admin-credential-contract.py: {error}", file=sys.stderr)
        return 1
    print("MCP hosted-edge admin credential contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
