#!/usr/bin/env python3
"""Mutation suite for the Docker and systemd security runtime contract."""

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
    "check_security_runtime_contract",
    ROOT / "scripts/check-security-runtime-contract.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load security runtime contract checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

CHECKED_PATHS = (
    CHECKER.COMPOSE_PATH,
    CHECKER.MAKEFILE_PATH,
    CHECKER.DOCKERFILE_PATH,
    CHECKER.DOCKER_EDGE_ENTRYPOINT_PATH,
    CHECKER.DOCKER_EDGE_HEALTHCHECK_PATH,
    CHECKER.DOCKER_TLS_ENTRYPOINT_PATH,
    CHECKER.DOCKER_TLS_PROXY_PATH,
    CHECKER.DOCKER_TLS_HEALTHCHECK_PATH,
    CHECKER.DOCKER_SMOKE_CLIENT_PATH,
    CHECKER.DOCKER_LAUNCHER_PATH,
    CHECKER.DOCKER_TOOLS_PATH,
    CHECKER.DOCKER_README_PATH,
    CHECKER.PROGRESSIVE_TUTORIAL_PATH,
    CHECKER.NATIVE_PROVISIONER_PATH,
    CHECKER.EDGE_UNIT_PATH,
    CHECKER.TRUST_UNIT_PATH,
)

Mutator = Callable[[str], str]
ASSERTION_COUNT = 0


def replace_once(old: str, new: str) -> Mutator:
    def mutate(body: str) -> str:
        count = body.count(old)
        if count != 1:
            raise AssertionError(
                f"mutation target {old!r} occurred {count} times instead of once"
            )
        return body.replace(old, new, 1)

    return mutate


def replace_all(old: str, new: str) -> Mutator:
    def mutate(body: str) -> str:
        count = body.count(old)
        if count == 0:
            raise AssertionError(f"mutation target {old!r} did not occur")
        return body.replace(old, new)

    return mutate


def chain(*mutators: Mutator) -> Mutator:
    def mutate(body: str) -> str:
        for item in mutators:
            body = item(body)
        return body

    return mutate


def replace_in_service(name: str, old: str, new: str) -> Mutator:
    def mutate(body: str) -> str:
        match = re.search(
            rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|^volumes:\n)",
            body,
        )
        if match is None:
            raise AssertionError(f"unable to find Compose service {name!r}")
        block = match.group(0)
        count = block.count(old)
        if count != 1:
            raise AssertionError(
                f"service {name!r} mutation target {old!r} occurred {count} times"
            )
        changed = block.replace(old, new, 1)
        return body[: match.start()] + changed + body[match.end() :]

    return mutate


def replace_in_network(name: str, old: str, new: str) -> Mutator:
    def mutate(body: str) -> str:
        match = re.search(
            rf"(?ms)^  {re.escape(name)}:\n.*?(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            body[body.index("\nnetworks:\n") + 1 :],
        )
        if match is None:
            raise AssertionError(f"unable to find Compose network {name!r}")
        offset = body.index("\nnetworks:\n") + 1
        block = match.group(0)
        count = block.count(old)
        if count != 1:
            raise AssertionError(
                f"network {name!r} mutation target {old!r} occurred {count} times"
            )
        changed = block.replace(old, new, 1)
        start = offset + match.start()
        end = offset + match.end()
        return body[:start] + changed + body[end:]

    return mutate


def copy_fixture(destination: Path) -> None:
    for relative in CHECKED_PATHS:
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def assert_rejected(
    label: str,
    relative: Path,
    mutate: Mutator,
    expected_error: str,
) -> None:
    global ASSERTION_COUNT
    with tempfile.TemporaryDirectory(prefix="chio-security-runtime-contract-") as raw:
        fixture = Path(raw)
        copy_fixture(fixture)
        target = fixture / relative
        original = target.read_text(encoding="utf-8")
        mutated = mutate(original)
        if mutated == original:
            raise AssertionError(f"{label}: mutation did not change the fixture")
        target.write_text(mutated, encoding="utf-8")
        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(
                f"security runtime contract accepted mutation: {label}"
            )
    ASSERTION_COUNT += 1


def assert_missing_file_rejected(
    label: str, relative: Path, expected_error: str
) -> None:
    global ASSERTION_COUNT
    with tempfile.TemporaryDirectory(prefix="chio-security-runtime-contract-") as raw:
        fixture = Path(raw)
        copy_fixture(fixture)
        (fixture / relative).unlink()
        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(
                f"security runtime contract accepted mutation: {label}"
            )
    ASSERTION_COUNT += 1


def main() -> int:
    CHECKER.validate(ROOT)

    compose = CHECKER.COMPOSE_PATH
    makefile = CHECKER.MAKEFILE_PATH
    dockerfile = CHECKER.DOCKERFILE_PATH
    edge_entrypoint = CHECKER.DOCKER_EDGE_ENTRYPOINT_PATH
    edge_healthcheck = CHECKER.DOCKER_EDGE_HEALTHCHECK_PATH
    tls_entrypoint = CHECKER.DOCKER_TLS_ENTRYPOINT_PATH
    tls_proxy = CHECKER.DOCKER_TLS_PROXY_PATH
    healthcheck = CHECKER.DOCKER_TLS_HEALTHCHECK_PATH
    smoke = CHECKER.DOCKER_SMOKE_CLIENT_PATH
    launcher = CHECKER.DOCKER_LAUNCHER_PATH
    tools = CHECKER.DOCKER_TOOLS_PATH
    docker_readme = CHECKER.DOCKER_README_PATH
    tutorial = CHECKER.PROGRESSIVE_TUTORIAL_PATH
    provisioner = CHECKER.NATIVE_PROVISIONER_PATH
    edge_unit = CHECKER.EDGE_UNIT_PATH
    trust_unit = CHECKER.TRUST_UNIT_PATH

    compose_mutations = (
        (
            "security init becomes restartable",
            replace_in_service(
                "chio-security-init", 'restart: "no"', 'restart: "always"'
            ),
            "one-shot",
        ),
        (
            "security init gains a network",
            replace_in_service(
                "chio-security-init", "network_mode: none", "network_mode: bridge"
            ),
            "network_mode none",
        ),
        (
            "security init publishes a host port",
            replace_in_service(
                "chio-security-init",
                "    volumes:\n",
                '    ports:\n      - "0.0.0.0:8999:8999"\n    volumes:\n',
            ),
            "must not publish host ports",
        ),
        (
            "provision output becomes persistent",
            replace_in_service(
                "chio-security-init",
                "--output-dir /run/chio-provision/security",
                "--output-dir /var/lib/chio/provision",
            ),
            "output path is not exact",
        ),
        (
            "runtime security path drifts",
            replace_in_service(
                "chio-security-init",
                "--runtime-security-dir /var/lib/chio/security",
                "--runtime-security-dir /var/lib/chio/unbound",
            ),
            "runtime security directory is not exact",
        ),
        (
            "digest-bound launcher is bypassed",
            replace_in_service(
                "chio-security-init",
                "--target /usr/local/bin/chio-demo-mcp-launcher",
                "--target /usr/bin/python3",
            ),
            "digest-bind the exact demo launcher",
        ),
        (
            "reviewed tools fixture is bypassed",
            replace_in_service(
                "chio-security-init",
                "--tools-fixture /opt/chio/examples/tools.json",
                "--tools-fixture /tmp/tools.json",
            ),
            "reviewed tools fixture",
        ),
        (
            "target execution UID drifts",
            replace_in_service(
                "chio-security-init",
                "--execution-uid 10002",
                "--execution-uid 10001",
            ),
            "exact execution-uid",
        ),
        (
            "target execution GID drifts",
            replace_in_service(
                "chio-security-init",
                "--execution-gid 10002",
                "--execution-gid 10001",
            ),
            "exact execution-gid",
        ),
        (
            "security init ignores provision failure",
            replace_in_service(
                "chio-security-init",
                "--server-version 1\n",
                "--server-version 1 || true\n",
            ),
            "not fail-closed",
        ),
        (
            "provision output tmpfs is weakened",
            replace_in_service(
                "chio-security-init",
                "noexec,nosuid,nodev,size=67108864",
                "size=67108864",
            ),
            "ephemeral hardened tmpfs",
        ),
        (
            "security init loses capability drop",
            replace_in_service("chio-security-init", "    - ALL\n", "    - NET_RAW\n"),
            "cap_drop",
        ),
        (
            "security init loses no-new-privileges",
            replace_in_service(
                "chio-security-init",
                "no-new-privileges:true",
                "no-new-privileges:false",
            ),
            "security_opt",
        ),
        (
            "security init root filesystem becomes writable",
            replace_in_service(
                "chio-security-init", "read_only: true", "read_only: false"
            ),
            "root filesystem must be read-only",
        ),
        (
            "security init pid bound is removed",
            replace_in_service(
                "chio-security-init", "pids_limit: 64", "pids_limit: 4096"
            ),
            "pids_limit",
        ),
        (
            "public artifacts include manifest signing seed",
            replace_in_service(
                "chio-security-init",
                "          signed-manifest.json \\\n",
                "          manifest-signer.seed \\\n          signed-manifest.json \\\n",
            ),
            "public runtime artifact allowlist",
        ),
        (
            "private artifacts include policy signing seed",
            replace_in_service(
                "chio-security-init",
                "          enterprise-migration.sqlite3 \\\n",
                "          cage-policy-signer.seed \\\n          enterprise-migration.sqlite3 \\\n",
            ),
            "edge-private artifact allowlist",
        ),
        (
            "manifest signing seed is copied directly to runtime",
            replace_in_service(
                "chio-security-init",
                "        cp /run/chio-provision/security/control-authority.seed /run/chio-trust/control-authority.seed\n",
                "        cp /run/chio-provision/security/manifest-signer.seed /run/chio-trust/manifest-signer.seed\n"
                "        cp /run/chio-provision/security/control-authority.seed /run/chio-trust/control-authority.seed\n",
            ),
            "copied to runtime state",
        ),
        (
            "forbidden signer inspection omits the trust volume",
            replace_in_service(
                "chio-security-init",
                "/run/chio-public /var/lib/chio /run/chio-trust -name",
                "/run/chio-public /var/lib/chio -name",
            ),
            "not exact and fail-closed",
        ),
        (
            "forbidden signer inspection ignores find failure",
            replace_in_service(
                "chio-security-init",
                'echo "failed to inspect runtime state for escaped signer: $${forbidden}" >&2\n'
                "            exit 1\n"
                "          }",
                'echo "failed to inspect runtime state for escaped signer: $${forbidden}" >&2\n'
                "            :\n"
                "          }",
            ),
            "not exact and fail-closed",
        ),
        (
            "forbidden signer inspection uses a masking pipeline",
            replace_in_service(
                "chio-security-init",
                '-name "$${forbidden}" -print -quit)" || {',
                '-name "$${forbidden}" -print -quit | grep -q .)" || {',
            ),
            "not exact and fail-closed",
        ),
        (
            "forbidden signer inspection runs after trust ownership handoff",
            replace_in_service(
                "chio-security-init",
                "        for forbidden in manifest-signer.seed cage-policy-signer.seed cage-migration-signer.seed; do\n",
                "        chown 10001:10001 /run/chio-trust/control-authority.seed /run/chio-trust\n"
                "        for forbidden in manifest-signer.seed cage-policy-signer.seed cage-migration-signer.seed; do\n",
            ),
            "must precede trust ownership handoff",
        ),
        (
            "runtime signer volume is shared with public artifacts",
            chain(
                replace_in_service(
                    "chio-security-init",
                    "chio_trust_secret:/run/chio-trust",
                    "chio_public_security:/run/chio-trust",
                ),
                replace_in_service(
                    "chio-trust-demo",
                    "chio_trust_secret:/run/chio-trust:ro",
                    "chio_public_security:/run/chio-trust:ro",
                ),
            ),
            "must mount 'chio_trust_secret'",
        ),
        (
            "trust secret becomes writable",
            replace_in_service(
                "chio-trust-demo",
                "chio_trust_secret:/run/chio-trust:ro",
                "chio_trust_secret:/run/chio-trust:rw",
            ),
            "read-only",
        ),
        (
            "trust receives edge private state",
            replace_in_service(
                "chio-trust-demo",
                "chio_demo_state:/var/lib/chio",
                "chio_edge_state:/var/lib/chio",
            ),
            "must mount 'chio_demo_state'",
        ),
        (
            "plaintext trust backend is published",
            replace_in_service(
                "chio-trust-demo",
                "    volumes:\n",
                '    ports:\n      - "127.0.0.1:8941:8940"\n    volumes:\n',
            ),
            "must not publish host ports",
        ),
        (
            "trust joins edge network",
            replace_in_service(
                "chio-trust-demo", "      - trust-backend\n", "      - edge-control\n"
            ),
            "attach only to trust-backend",
        ),
        (
            "trust healthcheck becomes unconditional",
            replace_in_service(
                "chio-trust-demo",
                'test: ["CMD-SHELL", "wget -q -O - http://127.0.0.1:8940/health >/dev/null 2>&1"]',
                'test: ["CMD", "true"]',
            ),
            "healthcheck command is not exact",
        ),
        (
            "trust service token regains a demo fallback",
            replace_in_service(
                "chio-trust-demo",
                "${CHIO_SERVICE_TOKEN:?set a dedicated CHIO_SERVICE_TOKEN}",
                "${CHIO_SERVICE_TOKEN:-demo-token}",
            ),
            "demo credential literal",
        ),
        (
            "trust service token is sourced from edge authentication",
            replace_in_service(
                "chio-trust-demo",
                "${CHIO_SERVICE_TOKEN:?set a dedicated CHIO_SERVICE_TOKEN}",
                "${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}",
            ),
            "dedicated service token",
        ),
        (
            "trust dashboard read token regains a demo fallback",
            replace_in_service(
                "chio-trust-demo",
                "${CHIO_DASHBOARD_READ_TOKEN:?set a dedicated CHIO_DASHBOARD_READ_TOKEN}",
                "${CHIO_DASHBOARD_READ_TOKEN:-demo-token}",
            ),
            "demo credential literal",
        ),
        (
            "trust dashboard read token is sourced from the service credential",
            replace_in_service(
                "chio-trust-demo",
                "${CHIO_DASHBOARD_READ_TOKEN:?set a dedicated CHIO_DASHBOARD_READ_TOKEN}",
                "${CHIO_SERVICE_TOKEN:?set a dedicated CHIO_SERVICE_TOKEN}",
            ),
            "dedicated dashboard read token",
        ),
        (
            "trust dashboard read token is omitted",
            replace_in_service(
                "chio-trust-demo",
                "      CHIO_TRUST_DASHBOARD_READ_TOKEN: ${CHIO_DASHBOARD_READ_TOKEN:?set a dedicated CHIO_DASHBOARD_READ_TOKEN}\n",
                "",
            ),
            "dedicated dashboard read token",
        ),
        (
            "trust receives a dashboard report relay credential",
            replace_in_service(
                "chio-trust-demo",
                "    environment:\n",
                "    environment:\n"
                "      CHIO_TRUST_DASHBOARD_REPORT_TOKEN: ${CHIO_DASHBOARD_REPORT_TOKEN:?set a dedicated CHIO_DASHBOARD_REPORT_TOKEN}\n",
            ),
            "dedicated dashboard read token",
        ),
        (
            "trust starts before security init succeeds",
            replace_in_service(
                "chio-trust-demo",
                "condition: service_completed_successfully",
                "condition: service_started",
            ),
            "service_completed_successfully",
        ),
        (
            "TLS init becomes restartable",
            replace_in_service("chio-tls-init", 'restart: "no"', 'restart: "always"'),
            "one-shot",
        ),
        (
            "TLS init gains a network",
            replace_in_service(
                "chio-tls-init", "network_mode: none", "network_mode: bridge"
            ),
            "network_mode none",
        ),
        (
            "TLS init working tmpfs loses noexec",
            replace_in_service(
                "chio-tls-init",
                "/run:rw,noexec,nosuid,nodev,size=33554432,mode=0755",
                "/run:rw,nosuid,nodev,size=33554432,mode=0755",
            ),
            "exact hardened /run tmpfs",
        ),
        (
            "CA and server private volumes collapse",
            replace_in_service(
                "chio-tls-init",
                "chio_tls_ca_private:/var/lib/chio-tls-ca",
                "chio_tls_private:/var/lib/chio-tls-ca",
            ),
            "must mount 'chio_tls_ca_private'",
        ),
        (
            "long-lived TLS proxy receives CA key volume",
            replace_in_service(
                "chio-trust-tls",
                "      - chio_tls_private:/var/lib/chio-tls-private:ro\n",
                "      - chio_tls_ca_private:/var/lib/chio-tls-ca:ro\n"
                "      - chio_tls_private:/var/lib/chio-tls-private:ro\n",
            ),
            "volume set is not exact",
        ),
        (
            "TLS server key volume becomes writable",
            replace_in_service(
                "chio-trust-tls",
                "chio_tls_private:/var/lib/chio-tls-private:ro",
                "chio_tls_private:/var/lib/chio-tls-private:rw",
            ),
            "read-only",
        ),
        (
            "TLS networks are flattened",
            replace_in_service(
                "chio-trust-tls",
                "      - trust-backend\n      - edge-control\n",
                "      - edge-control\n",
            ),
            "bridge exactly",
        ),
        (
            "TLS port binds every host interface",
            replace_in_service(
                "chio-trust-tls",
                "127.0.0.1:${CHIO_TRUST_PORT:-8940}:8940",
                "0.0.0.0:${CHIO_TRUST_PORT:-8940}:8940",
            ),
            "exact loopback port",
        ),
        (
            "TLS healthcheck becomes unconditional",
            replace_in_service(
                "chio-trust-tls",
                'test: ["CMD", "python3", "/opt/chio/tls_healthcheck.py"]',
                'test: ["CMD", "true"]',
            ),
            "healthcheck command is not exact",
        ),
        (
            "edge control URL is downgraded",
            replace_in_service(
                "chio-mcp-demo",
                "CHIO_CONTROL_URL: https://chio-trust-tls:8940",
                "CHIO_CONTROL_URL: http://chio-trust-demo:8940",
            ),
            "exact split security contract",
        ),
        (
            "edge authentication token regains a demo fallback",
            replace_in_service(
                "chio-mcp-demo",
                "${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}",
                "${CHIO_AUTH_TOKEN:-demo-token}",
            ),
            "demo credential literal",
        ),
        (
            "edge authentication token is sourced from service token",
            replace_in_service(
                "chio-mcp-demo",
                "CHIO_AUTH_TOKEN: ${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}",
                "CHIO_AUTH_TOKEN: ${CHIO_SERVICE_TOKEN:?set a dedicated CHIO_SERVICE_TOKEN}",
            ),
            "exact split security contract",
        ),
        (
            "edge admin token gains a fallback",
            replace_in_service(
                "chio-mcp-demo",
                "${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}",
                "${CHIO_ADMIN_TOKEN:-unsafe}",
            ),
            "default-value fallbacks",
        ),
        (
            "edge admin token is sourced from ordinary authentication",
            replace_in_service(
                "chio-mcp-demo",
                "CHIO_ADMIN_TOKEN: ${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}",
                "CHIO_ADMIN_TOKEN: ${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}",
            ),
            "exact split security contract",
        ),
        (
            "edge omits the dedicated admin token",
            replace_in_service(
                "chio-mcp-demo",
                "      CHIO_ADMIN_TOKEN: ${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}\n",
                "",
            ),
            "exact split security contract",
        ),
        (
            "trust service also receives the admin token",
            replace_in_service(
                "chio-trust-demo",
                "    environment:\n",
                "    environment:\n"
                "      CHIO_ADMIN_TOKEN: ${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}\n",
            ),
            "dedicated dashboard read token",
        ),
        (
            "edge control token is sourced from authentication token",
            replace_in_service(
                "chio-mcp-demo",
                "CHIO_CONTROL_TOKEN: ${CHIO_SERVICE_TOKEN:?set a dedicated CHIO_SERVICE_TOKEN}",
                "CHIO_CONTROL_TOKEN: ${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}",
            ),
            "exact split security contract",
        ),
        (
            "edge public artifacts become writable",
            replace_in_service(
                "chio-mcp-demo",
                "chio_public_security:/run/chio-public:ro",
                "chio_public_security:/run/chio-public:rw",
            ),
            "read-only",
        ),
        (
            "edge receives trust authority seed volume",
            replace_in_service(
                "chio-mcp-demo",
                "      - chio_public_security:/run/chio-public:ro\n",
                "      - chio_trust_secret:/run/chio-trust:ro\n"
                "      - chio_public_security:/run/chio-public:ro\n",
            ),
            "volume set is not exact",
        ),
        (
            "edge receives TLS server keys",
            replace_in_service(
                "chio-mcp-demo",
                "      - chio_tls_public:/var/lib/chio-tls-public:ro\n",
                "      - chio_tls_private:/var/lib/chio-tls-private:ro\n"
                "      - chio_tls_public:/var/lib/chio-tls-public:ro\n",
            ),
            "volume set is not exact",
        ),
        (
            "edge joins plaintext backend",
            replace_in_service(
                "chio-mcp-demo", "      - edge-control\n", "      - trust-backend\n"
            ),
            "attach only to edge-control",
        ),
        (
            "edge port binds every host interface",
            replace_in_service(
                "chio-mcp-demo",
                "127.0.0.1:${CHIO_EDGE_PORT:-8931}:8931",
                "0.0.0.0:${CHIO_EDGE_PORT:-8931}:8931",
            ),
            "exact loopback port",
        ),
        (
            "edge readiness healthcheck becomes unconditional",
            replace_in_service(
                "chio-mcp-demo",
                'test: ["CMD", "python3", "/opt/chio/examples/mcp_edge_healthcheck.py"]',
                'test: ["CMD", "true"]',
            ),
            "healthcheck command is not exact",
        ),
        (
            "edge readiness healthcheck uses the wrong client",
            replace_in_service(
                "chio-mcp-demo",
                "/opt/chio/examples/mcp_edge_healthcheck.py",
                "/opt/chio/tls_healthcheck.py",
            ),
            "healthcheck command is not exact",
        ),
        (
            "edge loses capability drop",
            replace_in_service(
                "chio-mcp-demo", "cap_add:\n", "cap_drop: []\n    cap_add:\n"
            ),
            "cap_drop",
        ),
        (
            "edge receives SYS_ADMIN",
            replace_in_service(
                "chio-mcp-demo",
                "      - SETGID\n",
                "      - SETGID\n      - SYS_ADMIN\n",
            ),
            "cap_add",
        ),
        (
            "edge loses SETUID",
            replace_in_service("chio-mcp-demo", "      - SETUID\n", ""),
            "cap_add",
        ),
        (
            "edge loses no-new-privileges",
            replace_once(
                "x-runtime-hardening: &runtime-hardening\n  read_only: true",
                "x-runtime-hardening: &runtime-hardening\n  read_only: true\n  security_opt: []",
            ),
            "security_opt",
        ),
        (
            "edge root filesystem becomes writable",
            replace_in_service(
                "chio-mcp-demo", 'user: "0:0"', 'user: "0:0"\n    read_only: false'
            ),
            "root filesystem must be read-only",
        ),
        (
            "edge pid bound is removed",
            replace_in_service(
                "chio-mcp-demo", "cap_add:\n", "pids_limit: 4096\n    cap_add:\n"
            ),
            "pids_limit",
        ),
        (
            "edge starts non-root before transition",
            replace_in_service("chio-mcp-demo", 'user: "0:0"', 'user: "10001:10001"'),
            "must begin as root",
        ),
        (
            "edge starts before provisioning succeeds",
            replace_in_service(
                "chio-mcp-demo",
                "condition: service_completed_successfully",
                "condition: service_started",
            ),
            "service_completed_successfully",
        ),
        (
            "control network is no longer internal",
            replace_in_network("edge-control", "internal: true", "internal: false"),
            "explicitly internal",
        ),
        (
            "proof-room loses its writable tmpfs",
            replace_in_service(
                "chio-proof-room",
                "    ports:\n",
                "    tmpfs: []\n    ports:\n",
            ),
            "bounded hardened /tmp tmpfs",
        ),
        (
            "proof-room tmpfs becomes read-only",
            replace_in_service(
                "chio-proof-room",
                "    ports:\n",
                "    tmpfs:\n"
                "      - /tmp:ro,noexec,nosuid,nodev,size=16777216,mode=1777\n"
                "    ports:\n",
            ),
            "bounded hardened /tmp tmpfs",
        ),
        (
            "proof-room immutable root is disabled",
            replace_in_service(
                "chio-proof-room",
                "    ports:\n",
                "    read_only: false\n    ports:\n",
            ),
            "root filesystem must be read-only",
        ),
        (
            "proof-room Compose override is removed",
            replace_in_service(
                "chio-proof-room",
                "    command:\n",
                "    x-disabled-command:\n",
            ),
            "must supply --doctor-report exactly once",
        ),
        (
            "proof-room Compose override writes immutable image root",
            replace_in_service(
                "chio-proof-room",
                "/tmp/chio-proof-doctor-report.json",
                "/opt/chio/proof-doctor-report.json",
            ),
            "not backed by an explicit writable mount or tmpfs",
        ),
        (
            "proof-room Compose override changes report filename",
            replace_in_service(
                "chio-proof-room",
                "/tmp/chio-proof-doctor-report.json",
                "/tmp/other-proof-doctor-report.json",
            ),
            "exactly match the canonical image command",
        ),
        (
            "proof-room Compose override drifts a non-output argument",
            replace_in_service(
                "chio-proof-room",
                "      - 0.0.0.0:7391\n",
                "      - 127.0.0.1:7391\n",
            ),
            "exactly match the canonical image command",
        ),
        (
            "proof-room Compose override omits doctor report flag",
            replace_in_service(
                "chio-proof-room",
                "      - --doctor-report\n",
                "      - --disabled-doctor-report\n",
            ),
            "must supply --doctor-report exactly once",
        ),
    )
    for label, mutate, error in compose_mutations:
        assert_rejected(label, compose, mutate, error)

    dockerfile_mutations = (
        (
            "edge security entrypoint is bypassed",
            replace_once(
                'ENTRYPOINT ["/sbin/tini", "--", "/opt/chio/examples/mcp_demo_entrypoint.py"]',
                'ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/chio"]',
            ),
            "does not execute the checked security entrypoint",
        ),
        (
            "launcher source is omitted",
            replace_once(
                "COPY examples/docker/mcp_demo_launcher.c ./examples/mcp_demo_launcher.c",
                "COPY examples/docker/mock_mcp_server.py ./examples/mcp_demo_launcher.c",
            ),
            "mcp_demo_launcher.c",
        ),
        (
            "edge healthcheck implementation is omitted",
            replace_once(
                "COPY examples/docker/mcp_edge_healthcheck.py ./examples/mcp_edge_healthcheck.py",
                "COPY examples/docker/mcp_edge_healthcheck.py ./examples/unchecked_health.py",
            ),
            "mcp_edge_healthcheck.py",
        ),
        (
            "launcher Python digest binding is removed",
            replace_once("-DCHIO_DEMO_PYTHON_SHA256", "-DCHIO_DEMO_PYTHON_UNCHECKED"),
            "CHIO_DEMO_PYTHON_SHA256",
        ),
        (
            "tool identity collapses into Chio identity",
            replace_once(
                "addgroup -S -g 10002 chio-mcp", "addgroup -S -g 10001 chio-mcp"
            ),
            "10002",
        ),
        (
            "reviewed assets become tool-owned",
            replace_once(
                "chown -R root:root /opt/chio /var/lib/chio",
                "chown -R chio-mcp:chio-mcp /opt/chio /var/lib/chio",
            ),
            "root:root",
        ),
        (
            "reviewed assets become writable",
            replace_once(
                "find /opt/chio -type f -exec chmod 0444",
                "find /opt/chio -type f -exec chmod 0644",
            ),
            "chmod 0444",
        ),
        (
            "edge image starts non-root",
            replace_once(
                "FROM chio AS chio-mcp-demo\nUSER root",
                "FROM chio AS chio-mcp-demo\nUSER chio",
            ),
            "must start the edge process as root",
        ),
        (
            "TLS healthcheck implementation is omitted",
            replace_once(
                "examples/docker/tls_healthcheck.py",
                "examples/docker/unchecked_health.py",
            ),
            "tls_healthcheck.py",
        ),
        (
            "trust image substitutes authority database",
            replace_once("--authority-seed-file", "--authority-db"),
            "trust-only seed exactly",
        ),
        (
            "proof-room canonical image report moves to tmpfs path",
            replace_once(
                "/opt/chio/proof-doctor-report.json",
                "/tmp/chio-proof-doctor-report.json",
            ),
            "preserve the canonical standalone doctor report path",
        ),
        (
            "proof-room canonical image report path drifts",
            replace_once(
                "/opt/chio/proof-doctor-report.json",
                "/opt/chio/other-proof-doctor-report.json",
            ),
            "preserve the canonical standalone doctor report path",
        ),
        (
            "trust receipt database targets immutable image root",
            replace_once(
                "--receipt-db /var/lib/chio/receipts.sqlite",
                "--receipt-db /opt/chio/receipts.sqlite",
            ),
            "not backed by an explicit writable mount or tmpfs",
        ),
    )
    for label, mutate, error in dockerfile_mutations:
        assert_rejected(label, dockerfile, mutate, error)

    entrypoint_mutations = (
        (
            "edge security reads follow symlinks",
            replace_once(' | getattr(os, "O_NOFOLLOW", 0)', ""),
            "O_NOFOLLOW",
        ),
        (
            "edge security ignores root ownership",
            replace_once("metadata.st_uid != 0 or ", ""),
            "metadata.st_uid != 0",
        ),
        (
            "public and private security directories collapse",
            replace_once(
                'os.environ.get("CHIO_PRIVATE_SECURITY_DIR", "/var/lib/chio/security")',
                'os.environ.get("CHIO_PRIVATE_SECURITY_DIR", "/run/chio-public")',
            ),
            "CHIO_PRIVATE_SECURITY_DIR",
        ),
        (
            "edge entrypoint gains HTTP control default",
            replace_once("https://chio-trust-tls:8940", "http://chio-trust-demo:8940"),
            "insecure HTTP default",
        ),
        (
            "edge inherits ambient environment",
            replace_once(
                "environment = {",
                "environment = os.environ.copy(); environment.update({",
            ),
            "invalid",
        ),
        (
            "edge omits signed manifest",
            replace_once('"signed-manifest.json"', '"unsigned-manifest.json"'),
            "signed manifest artifact",
        ),
        (
            "edge omits cage policy flag",
            replace_once('"--cage-policy"', '"--unchecked-cage-policy"'),
            "does not supply signed cage policy",
        ),
        (
            "edge target execution uses a shell",
            replace_once(
                "os.execve(executable, arguments, environment)",
                "os.system(' '.join(arguments))",
            ),
            "does not directly exec",
        ),
        (
            "edge omits control token from Chio",
            replace_once('"CHIO_CONTROL_TOKEN": control_token,\n', ""),
            "CHIO_CONTROL_TOKEN",
        ),
        (
            "edge omits admin token from Chio",
            replace_once('"CHIO_ADMIN_TOKEN": admin_token,\n', ""),
            "CHIO_ADMIN_TOKEN",
        ),
        (
            "edge disables the three-token distinction guard",
            replace_once(
                "if len({auth_token, admin_token, control_token}) != 3:",
                "if False:",
            ),
            "pairwise-distinct auth, admin, and control tokens before exec",
        ),
        (
            "edge distinction guard omits the admin token",
            replace_once(
                "{auth_token, admin_token, control_token}",
                "{auth_token, auth_token, control_token}",
            ),
            "pairwise-distinct auth, admin, and control tokens before exec",
        ),
        (
            "edge authentication token regains an entrypoint default",
            replace_once(
                'auth_token = os.environ.get("CHIO_AUTH_TOKEN", "")',
                'auth_token = os.environ.get("CHIO_AUTH_TOKEN", "demo-token")',
            ),
            "credential defaults",
        ),
        (
            "edge admin token regains an entrypoint default",
            replace_once(
                'admin_token = os.environ.get("CHIO_ADMIN_TOKEN", "")',
                'admin_token = os.environ.get("CHIO_ADMIN_TOKEN", "unsafe")',
            ),
            "CHIO_ADMIN_TOKEN",
        ),
        (
            "edge skips admin token grammar validation",
            replace_once('        ("CHIO_ADMIN_TOKEN", admin_token),\n', ""),
            '("CHIO_ADMIN_TOKEN", admin_token)',
        ),
        (
            "edge skips bearer grammar validation",
            replace_once("BEARER_TOKEN.fullmatch(value)", 'value == ""'),
            "BEARER_TOKEN.fullmatch(value)",
        ),
        (
            "edge forwards raw auth token instead of validated value",
            replace_once(
                '"CHIO_AUTH_TOKEN": auth_token,',
                '"CHIO_AUTH_TOKEN": os.environ["CHIO_AUTH_TOKEN"],',
            ),
            '"CHIO_AUTH_TOKEN": auth_token',
        ),
        (
            "edge forwards raw admin token instead of validated value",
            replace_once(
                '"CHIO_ADMIN_TOKEN": admin_token,',
                '"CHIO_ADMIN_TOKEN": os.environ["CHIO_ADMIN_TOKEN"],',
            ),
            '"CHIO_ADMIN_TOKEN": admin_token',
        ),
        (
            "edge validates but does not forward private CA path",
            replace_once('"CHIO_CONTROL_TLS_ROOT_CA_FILE": str(control_ca),\n', ""),
            "forward the private CA path",
        ),
        (
            "edge forwards an unvalidated private CA path",
            replace_once(
                '"CHIO_CONTROL_TLS_ROOT_CA_FILE": str(control_ca),',
                '"CHIO_CONTROL_TLS_ROOT_CA_FILE": os.environ["CHIO_CONTROL_TLS_ROOT_CA_FILE"],',
            ),
            "validated private CA path exactly",
        ),
    )
    for label, mutate, error in entrypoint_mutations:
        assert_rejected(label, edge_entrypoint, mutate, error)

    launcher_mutations = (
        (
            "launcher follows target symlinks",
            replace_once(" | O_NOFOLLOW", ""),
            "O_NOFOLLOW",
        ),
        (
            "launcher skips target ownership check",
            replace_once("|| metadata.st_uid != 0 ", ""),
            "metadata.st_uid != 0",
        ),
        (
            "launcher skips digest comparison",
            replace_once(
                "strcmp(encoded, expected_digest) != 0", "strcmp(encoded, encoded) != 0"
            ),
            "strcmp(encoded, expected_digest)",
        ),
        (
            "launcher does not scrub inherited tokens",
            replace_once("clearenv()", 'setenv("CHIO_CONTROL_TOKEN", "leaked", 1)'),
            "clearenv()",
        ),
        (
            "launcher forwards control token to tool",
            replace_once(
                '(char *)"HOME=/nonexistent",',
                '(char *)"CHIO_CONTROL_TOKEN=leaked",\n        (char *)"HOME=/nonexistent",',
            ),
            "leaks CHIO_CONTROL_TOKEN",
        ),
        (
            "launcher forwards admin token to tool",
            replace_once(
                '(char *)"HOME=/nonexistent",',
                '(char *)"CHIO_ADMIN_TOKEN=leaked",\n        (char *)"HOME=/nonexistent",',
            ),
            "leaks CHIO_ADMIN_TOKEN",
        ),
        (
            "launcher uses Chio UID for tool",
            replace_once(
                "#define CHIO_DEMO_UID ((uid_t)10002)",
                "#define CHIO_DEMO_UID ((uid_t)10001)",
            ),
            "10002",
        ),
        (
            "launcher skips UID transition",
            replace_once(
                "setresuid(CHIO_DEMO_UID, CHIO_DEMO_UID, CHIO_DEMO_UID)",
                "setresuid(0, 0, 0)",
            ),
            "setresuid",
        ),
        (
            "launcher omits the post-credential dumpability reset",
            replace_once(
                "if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 || chdir(\"/opt/chio\") != 0",
                "if (chdir(\"/opt/chio\") != 0",
            ),
            "reset dumpability after its optional root credential transition",
        ),
        (
            "launcher rejects pre-dropped exact identity",
            replace_once(
                "has_exact_empty_group_identity(CHIO_DEMO_UID, CHIO_DEMO_GID);",
                "0;",
            ),
            "has_exact_empty_group_identity(CHIO_DEMO_UID, CHIO_DEMO_GID)",
        ),
        (
            "launcher accepts a mismatched saved UID",
            replace_once(
                "saved_uid == expected_uid",
                "saved_uid != expected_uid",
            ),
            "saved_uid == expected_uid",
        ),
        (
            "launcher accepts supplementary groups",
            replace_once(
                "getgroups(0, NULL) != 0",
                "getgroups(0, NULL) < 0",
            ),
            "getgroups(0, NULL) != 0",
        ),
        (
            "launcher omits the launcher-interval dumpability check",
            replace_once(
                "\n        || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0",
                "",
            ),
            "verify nondumpable state within the launcher interval before exec",
        ),
        (
            "launcher accepts a dumpable launcher interval",
            replace_once(
                "prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0",
                "prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0",
            ),
            "verify nondumpable state within the launcher interval before exec",
        ),
        (
            "launcher restores the capped descriptor loop",
            replace_once(
                "close_descriptor_range(3, first - 1)",
                "for (int descriptor = 3; descriptor < 65536; ++descriptor) {\n"
                "        (void)close(descriptor);\n"
                "    }",
            ),
            "capped descriptor scrub surface",
        ),
        (
            "launcher ignores close_range errors",
            replace_once(
                "if (errno == ENOSYS || errno == EPERM) {",
                "if (errno != 0) {",
            ),
            "fall back only for ENOSYS or EPERM",
        ),
        (
            "launcher marks inherited descriptors close-on-exec instead of closing",
            replace_once(
                "syscall(SYS_close_range, first, last, 0)",
                "syscall(SYS_close_range, first, last, CLOSE_RANGE_CLOEXEC)",
            ),
            "fall back only for ENOSYS or EPERM",
        ),
        (
            "launcher broadens procfs fallback errors",
            replace_once(
                "if (errno == ENOSYS || errno == EPERM) {",
                "if (errno == ENOSYS || errno == EPERM || errno == EINVAL) {",
            ),
            "fall back only for ENOSYS or EPERM",
        ),
        (
            "launcher accepts aliased verified descriptors",
            replace_once("\n        || python_descriptor == script_descriptor", ""),
            "preserve only two validated descriptors",
        ),
        (
            "launcher does not sort preserved descriptors",
            replace_once("if (first > second) {", "if (false) {"),
            "complete close_range intervals",
        ),
        (
            "launcher leaves descriptor three inherited",
            replace_once(
                "close_descriptor_range(3, first - 1)",
                "close_descriptor_range(4, first - 1)",
            ),
            "complete close_range intervals",
        ),
        (
            "launcher leaves descriptors between verified targets inherited",
            replace_once("|| close_descriptor_range(first + 1, second - 1)\n", ""),
            "complete close_range intervals",
        ),
        (
            "launcher caps the final close_range interval",
            replace_once("second + 1, UINT_MAX", "second + 1, 65535"),
            "complete close_range intervals",
        ),
        (
            "launcher omits inherited descriptor scrubbing",
            replace_once(
                "close_unneeded_descriptors(python_descriptor, script_descriptor);",
                "",
            ),
            "scrub inherited descriptors exactly once",
        ),
        (
            "launcher procfs fallback closes its enumeration descriptor",
            replace_once("\n            || descriptor == directory_descriptor", ""),
            "procfs fallback must completely enumerate",
        ),
        (
            "launcher procfs fallback closes verified Python descriptor",
            replace_once(
                "\n        if (descriptor < 3 || descriptor == python_descriptor",
                "\n        if (descriptor < 3",
            ),
            "procfs fallback must completely enumerate",
        ),
        (
            "launcher procfs fallback ignores readdir errors",
            replace_once(
                "        if (entry == NULL) {\n"
                "            if (errno != 0) {\n"
                '                fail("cannot inspect inherited descriptors");\n'
                "            }\n"
                "            break;\n"
                "        }",
                "        if (entry == NULL) {\n            break;\n        }",
            ),
            "procfs fallback must completely enumerate",
        ),
        (
            "launcher procfs fallback accepts partial descriptor parses",
            replace_once(" || *end != '\\0'", ""),
            "procfs fallback must completely enumerate",
        ),
        (
            "launcher procfs fallback ignores close errors",
            replace_once(
                "        if (close(descriptor) != 0) {\n"
                '            fail("cannot close inherited descriptor");\n'
                "        }",
                "        (void)close(descriptor);",
            ),
            "procfs fallback must completely enumerate",
        ),
        (
            "launcher procfs fallback ignores closedir errors",
            replace_once(
                "    if (closedir(directory) != 0) {\n"
                '        fail("cannot close descriptor directory");\n'
                "    }",
                "    (void)closedir(directory);",
            ),
            "procfs fallback must completely enumerate",
        ),
        (
            "launcher procfs fallback ignores opendir errors",
            replace_once("if (directory == NULL) {", "if (false) {"),
            "procfs fallback must completely enumerate",
        ),
        (
            "launcher procfs fallback ignores dirfd errors",
            replace_once("if (directory_descriptor < 0) {", "if (false) {"),
            "procfs fallback must completely enumerate",
        ),
    )
    for label, mutate, error in launcher_mutations:
        assert_rejected(label, launcher, mutate, error)

    tls_entrypoint_mutations = (
        (
            "TLS CA directory collapses into server directory",
            replace_once(
                "ca_dir=/var/lib/chio-tls-ca", "ca_dir=/var/lib/chio-tls-private"
            ),
            "/var/lib/chio-tls-ca",
        ),
        (
            "TLS file checks follow symlinks",
            replace_once(
                '[ -f "${path}" ] || return 1\n  [ ! -L "${path}" ] || return 1',
                '[ -f "${path}" ] || return 1',
            ),
            "reject symlinked files and directories",
        ),
        (
            "TLS directory checks follow symlinks",
            replace_once(
                '[ -d "${path}" ] || return 1\n  [ ! -L "${path}" ] || return 1',
                '[ -d "${path}" ] || return 1',
            ),
            "reject symlinked files and directories",
        ),
        (
            "TLS ownership-mode check is removed",
            replace_all(
                '[ "$(stat -c \'%u:%g:%a\' "${path}")" = "${owner}:${mode_bits}" ]',
                "true",
            ),
            "stat -c",
        ),
        (
            "TLS private key mode becomes group-readable",
            replace_once(
                'require_file "${server_key}" "${key_owner}" 400',
                'require_file "${server_key}" "${key_owner}" 440',
            ),
            "server_key",
        ),
        (
            "TLS proxy no longer rejects CA key",
            replace_once(
                'if [ -e "${ca_key}" ] || [ -L "${ca_key}" ]; then', "if false; then"
            ),
            'if [ -e "${ca_key}" ]',
        ),
        (
            "TLS server key is not handed to proxy UID",
            replace_all(
                'chown 10001:10001 "${server_key}" "${server_dir}"',
                'chown 0:0 "${server_key}" "${server_dir}"',
            ),
            "chown 10001",
        ),
        (
            "TLS empty-directory probe masks find failure",
            replace_once(
                'first_entry="$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)" || return 1',
                'first_entry="$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)"',
            ),
            "first_entry",
        ),
        (
            "TLS provision accepts symlinked state directory",
            replace_once('[ ! -L "${directory}" ] || exit 1\n', ""),
            '[ ! -L "${directory}" ]',
        ),
        (
            "TLS certificate chain failure is masked",
            replace_once(
                'openssl verify -CAfile "${ca_cert}" "${server_cert}" >/dev/null 2>&1 || return 1',
                'openssl verify -CAfile "${ca_cert}" "${server_cert}" >/dev/null 2>&1',
            ),
            "certificate validation must fail closed",
        ),
        (
            "TLS persisted server key mismatch is masked",
            replace_once(
                '"$(openssl rsa -noout -modulus -in "${server_key}" 2>/dev/null)" ] || return 1',
                '"$(openssl rsa -noout -modulus -in "${server_key}" 2>/dev/null)" ] || true',
            ),
            "certificate validation must fail closed",
        ),
        (
            "TLS persisted server key mode validation is masked",
            replace_once(
                'require_file "${server_key}" "${key_owner}" 400 || return 1',
                'require_file "${server_key}" "${key_owner}" 400 || true',
            ),
            "certificate validation must fail closed",
        ),
        (
            "TLS certificate SAN read failure is masked",
            replace_once(
                'san="$(openssl x509 -noout -ext subjectAltName -in "${server_cert}")" || return 1',
                'san="$(openssl x509 -noout -ext subjectAltName -in "${server_cert}")"',
            ),
            "certificate validation must fail closed",
        ),
    )
    for label, mutate, error in tls_entrypoint_mutations:
        assert_rejected(label, tls_entrypoint, mutate, error)

    proxy_mutations = (
        (
            "proxy accepts Transfer-Encoding",
            replace_once('if self.headers.get_all("Transfer-Encoding"):', "if False:"),
            "Transfer-Encoding",
        ),
        (
            "proxy accepts inconsistent Content-Length",
            replace_once("if len(set(values)) != 1:", "if False:"),
            "len(set(values))",
        ),
        (
            "proxy loses request bound",
            replace_all("MAX_REQUEST_BYTES", "UNBOUNDED_REQUEST_BYTES"),
            "MAX_REQUEST_BYTES",
        ),
        (
            "proxy loses response bound",
            replace_all("MAX_RESPONSE_BYTES", "UNBOUNDED_RESPONSE_BYTES"),
            "MAX_RESPONSE_BYTES",
        ),
        (
            "proxy loses header deadline",
            replace_all("HEADER_TIMEOUT_SECONDS", "NO_HEADER_DEADLINE"),
            "HEADER_TIMEOUT_SECONDS",
        ),
        (
            "proxy loses upstream deadline",
            replace_all("SocketShutdownDeadline", "NoShutdownTimer"),
            "SocketShutdownDeadline",
        ),
        (
            "proxy re-resolves upstream per request",
            replace_all("ResolvedHTTPConnection", "DirectHostHTTPConnection"),
            "ResolvedHTTPConnection",
        ),
        (
            "proxy stops stripping transfer encoding",
            replace_once('    "transfer-encoding",\n', ""),
            '"transfer-encoding"',
        ),
        (
            "proxy accepts authority-form targets",
            replace_once('or self.path.startswith("//")', ""),
            'startswith("//")',
        ),
        (
            "proxy removes TLS certificate wrapping",
            replace_once("context.load_cert_chain", "context.load_verify_locations"),
            "load_cert_chain",
        ),
        (
            "proxy removes TLS minimum",
            replace_once(
                "context.minimum_version = ssl.TLSVersion.TLSv1_2",
                "context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED",
            ),
            "minimum TLS version",
        ),
        (
            "proxy introduces redirect-following client",
            replace_once(
                "import http.client\n", "import http.client\nimport urllib.request\n"
            ),
            "redirect-following HTTP client",
        ),
    )
    for label, mutate, error in proxy_mutations:
        assert_rejected(label, tls_proxy, mutate, error)

    health_mutations = (
        (
            "healthcheck follows redirects",
            replace_once("NoRedirect(),", "urllib.request.HTTPRedirectHandler(),"),
            "NoRedirect()",
        ),
        (
            "healthcheck follows CA symlinks",
            replace_once(" | os.O_NOFOLLOW", ""),
            "os.O_NOFOLLOW",
        ),
        (
            "healthcheck permits HTTP",
            replace_once(
                "https://localhost:8940/health", "http://localhost:8940/health"
            ),
            "pin exact HTTPS",
        ),
        (
            "healthcheck ignores private CA",
            replace_once("context.load_verify_locations", "context.load_default_certs"),
            "does not load the private CA",
        ),
        (
            "healthcheck uses ambient proxy",
            replace_once(
                "urllib.request.ProxyHandler({}),", "urllib.request.ProxyHandler(),"
            ),
            "ProxyHandler({})",
        ),
    )
    for label, mutate, error in health_mutations:
        assert_rejected(label, healthcheck, mutate, error)

    edge_health_mutations = (
        (
            "edge healthcheck loses its authenticated admin route",
            replace_once(
                "http://127.0.0.1:8931/admin/health",
                "http://127.0.0.1:8931/health",
            ),
            "admin/health",
        ),
        (
            "edge healthcheck reads the ordinary edge token",
            replace_once('os.environ.get("CHIO_ADMIN_TOKEN", "")', 'os.environ.get("CHIO_AUTH_TOKEN", "")'),
            "CHIO_ADMIN_TOKEN",
        ),
        (
            "edge healthcheck omits its authorization header",
            replace_once(
                'headers={"Authorization": f"Bearer {admin_token}"}',
                "headers={}",
            ),
            "Authorization",
        ),
        (
            "edge healthcheck uses ambient proxy state",
            replace_once(
                "urllib.request.ProxyHandler({})", "urllib.request.ProxyHandler()"
            ),
            "ProxyHandler({})",
        ),
        (
            "edge healthcheck response bound becomes oversized",
            replace_once(
                "MAX_HEALTH_BODY_BYTES = 64 * 1024",
                "MAX_HEALTH_BODY_BYTES = 64 * 1024 * 1024",
            ),
            "MAX_HEALTH_BODY_BYTES = 64 * 1024",
        ),
        (
            "edge healthcheck stops checking control token configuration",
            replace_once(
                'control.get("controlTokenConfigured") is not True',
                "False",
            ),
            "controlTokenConfigured",
        ),
    )
    for label, mutate, error in edge_health_mutations:
        assert_rejected(label, edge_healthcheck, mutate, error)

    smoke_mutations = (
        (
            "smoke client regains a demo token default",
            replace_once(
                'value = os.environ.get(name, "")',
                'value = os.environ.get(name, "demo-token")',
            ),
            "credential defaults",
        ),
        (
            "smoke client disables the four-token distinction guard",
            replace_once(
                "if len({EDGE_TOKEN, ADMIN_TOKEN, DASHBOARD_READ_TOKEN, SERVICE_TOKEN}) != 4:",
                "if False:",
            ),
            "pairwise-distinct edge, admin, dashboard read, and service tokens",
        ),
        (
            "smoke readiness loses its total deadline",
            replace_once(
                "deadline = time.monotonic() + EDGE_READY_TIMEOUT_SECONDS",
                "deadline = float('inf')",
            ),
            "deadline = time.monotonic",
        ),
        (
            "smoke readiness uses the ordinary edge token",
            replace_once(
                "wait_for_edge_ready(\n"
                "        edge_origin=edge_origin,\n"
                "        admin_token=admin_token,",
                "wait_for_edge_ready(\n"
                "        edge_origin=edge_origin,\n"
                "        admin_token=edge_token,",
            ),
            "validated admin token",
        ),
        (
            "smoke readiness request omits admin authentication",
            replace_once(
                'headers={"Authorization": f"Bearer {admin_token}"},\n'
                "    )\n"
                "    try:\n"
                "        with edge_opener.open",
                "headers={},\n"
                "    )\n"
                "    try:\n"
                "        with edge_opener.open",
            ),
            "admin-authenticated readiness probe",
        ),
        (
            "smoke signed tool identity drifts",
            replace_once(
                'EXPECTED_TOOL_NAME = "echo_text"',
                'EXPECTED_TOOL_NAME = "unchecked_tool"',
            ),
            "EXPECTED_TOOL_NAME",
        ),
        (
            "smoke tool inventory validation is bypassed",
            replace_once(
                "tools = validate_tools_response(read_sse_json(response))",
                "tools = read_sse_json(response)",
            ),
            "apply validate_tools_response exactly once",
        ),
        (
            "smoke exact tool-result assertion is disabled",
            replace_once("if result != EXPECTED_TOOL_RESULT:", "if False:"),
            "result != EXPECTED_TOOL_RESULT",
        ),
        (
            "smoke receipt query omits exact tool name",
            replace_once('            "toolName": EXPECTED_TOOL_NAME,\n', ""),
            "toolName",
        ),
        (
            "smoke receipt capability binding is disabled",
            replace_once(
                'or receipt.get("capability_id") != capability_id',
                "or False",
            ),
            "capability_id",
        ),
        (
            "smoke accepts a deny receipt",
            replace_once('or decision.get("verdict") != "allow"', "or False"),
            "decision.get",
        ),
        (
            "smoke distinction guard omits the admin token",
            replace_once(
                "{EDGE_TOKEN, ADMIN_TOKEN, DASHBOARD_READ_TOKEN, SERVICE_TOKEN}",
                "{EDGE_TOKEN, EDGE_TOKEN, DASHBOARD_READ_TOKEN, SERVICE_TOKEN}",
            ),
            "pairwise-distinct edge, admin, dashboard read, and service tokens",
        ),
        (
            "smoke admin token is sourced from edge token",
            replace_once(
                'ADMIN_TOKEN = require_token("CHIO_ADMIN_TOKEN")',
                'ADMIN_TOKEN = require_token("CHIO_EDGE_TOKEN")',
            ),
            "CHIO_ADMIN_TOKEN",
        ),
        (
            "smoke dashboard read token is sourced from edge token",
            replace_once(
                'DASHBOARD_READ_TOKEN = require_token("CHIO_DASHBOARD_READ_TOKEN")',
                'DASHBOARD_READ_TOKEN = require_token("CHIO_EDGE_TOKEN")',
            ),
            "CHIO_DASHBOARD_READ_TOKEN",
        ),
        (
            "smoke service token is sourced from edge token",
            replace_once(
                'SERVICE_TOKEN = require_token("CHIO_SERVICE_TOKEN")',
                'SERVICE_TOKEN = require_token("CHIO_EDGE_TOKEN")',
            ),
            "CHIO_SERVICE_TOKEN",
        ),
        (
            "smoke control opener omits the session cookie processor",
            replace_once(
                "handlers.append(urllib.request.HTTPCookieProcessor(cookie_jar))",
                "pass",
            ),
            "HTTPCookieProcessor",
        ),
        (
            "smoke dashboard login sends the service credential",
            replace_once(
                '{"token": dashboard_read_token}, separators=(",", ":")',
                '{"token": SERVICE_TOKEN}, separators=(",", ":")',
            ),
            "token\": dashboard_read_token",
        ),
        (
            "smoke dashboard login skips exact cookie validation",
            replace_once(
                "DASHBOARD_SESSION_COOKIE_PATTERN.fullmatch(set_cookies[0])",
                "re.fullmatch(r'.*', set_cookies[0])",
            ),
            "DASHBOARD_SESSION_COOKIE_PATTERN",
        ),
        (
            "smoke dashboard login accepts any success status",
            replace_once("if response.status != 200:", "if False:"),
            "response.status != 200",
        ),
        (
            "smoke client follows redirects",
            replace_all("NoRedirect()", "urllib.request.HTTPRedirectHandler()"),
            "NoRedirect()",
        ),
        (
            "smoke client uses ambient proxy",
            replace_all(
                "urllib.request.ProxyHandler({})", "urllib.request.ProxyHandler()"
            ),
            "ProxyHandler({})",
        ),
        (
            "smoke client follows CA symlinks",
            replace_once(" | os.O_NOFOLLOW", ""),
            "os.O_NOFOLLOW",
        ),
        (
            "smoke control origin permits HTTP",
            replace_once("if not allow_loopback_http:", "if False:"),
            "if not allow_loopback_http",
        ),
        (
            "smoke token grammar is removed",
            replace_once("BEARER_TOKEN.fullmatch(token)", "re.fullmatch(r'.*', token)"),
            "BEARER_TOKEN.fullmatch",
        ),
        (
            "smoke final-origin equality is removed",
            replace_once(
                "final_origin != expected_origin or final_url != expected_url", "False"
            ),
            "final_origin",
        ),
        (
            "smoke receipt query regains bearer authentication",
            replace_once(
                '        allow_loopback_http=False,\n        opener=control_opener,\n    )\n    receipts = payload.get',
                '        allow_loopback_http=False,\n        headers={"Authorization": f"Bearer {dashboard_read_token}"},\n        opener=control_opener,\n    )\n    receipts = payload.get',
            ),
            "session cookie for receipt reads",
        ),
        (
            "smoke dashboard login sends the credential as a bearer",
            replace_once(
                '            "Content-Type": "application/json",\n',
                '            "Content-Type": "application/json",\n'
                '            "Authorization": f"Bearer {dashboard_read_token}",\n',
            ),
            "never send the dashboard credential as a bearer",
        ),
        (
            "smoke dashboard logout accepts any success status",
            replace_once("if response.status != 204:", "if False:"),
            "response.status != 204",
        ),
        (
            "smoke dashboard logout omits the clear-cookie contract",
            replace_once(
                "DASHBOARD_SESSION_CLEAR_COOKIE\n            ]",
                "set_cookies[0]\n            ]",
            ),
            "DASHBOARD_SESSION_CLEAR_COOKIE",
        ),
        (
            "smoke dashboard logout accepts a live stale session",
            replace_once("if exc.code != 401", "if False"),
            "exc.code != 401",
        ),
        (
            "smoke admin request uses the edge token",
            replace_once(
                'headers={"Authorization": f"Bearer {admin_token}"},\n'
                "        opener=edge_opener,",
                'headers={"Authorization": f"Bearer {edge_token}"},\n'
                "        opener=edge_opener,",
            ),
            "only the validated admin token to /admin/",
        ),
        (
            "smoke passes the edge token into its admin request helper",
            replace_once(
                "session_capability_id(\n"
                "        session_id,\n"
                "        edge_origin=edge_origin,\n"
                "        admin_token=admin_token,\n"
                "        edge_opener=edge_opener,",
                "session_capability_id(\n"
                "        session_id,\n"
                "        edge_origin=edge_origin,\n"
                "        admin_token=edge_token,\n"
                "        edge_opener=edge_opener,",
            ),
            "only the validated admin token to /admin/",
        ),
        (
            "smoke passes the edge token into its admin flow",
            replace_once(
                "edge_token=edge_token,\n"
                "            admin_token=admin_token,\n"
                "            dashboard_read_token=dashboard_read_token,",
                "edge_token=edge_token,\n"
                "            admin_token=edge_token,\n"
                "            dashboard_read_token=dashboard_read_token,",
            ),
            "only the validated admin token to /admin/",
        ),
        (
            "smoke CA verification is replaced by ambient roots",
            replace_once(
                "context.load_verify_locations(cadata=ca_pem)",
                "context.load_default_certs()",
            ),
            "load_verify_locations",
        ),
    )
    for label, mutate, error in smoke_mutations:
        assert_rejected(label, smoke, mutate, error)

    makefile_mutations = (
        (
            "Make Docker up omits bounded readiness",
            replace_once(
                "docker compose up -d --build --wait --wait-timeout 180",
                "docker compose up -d --build",
            ),
        ),
        (
            "Make smoke maps edge access from the admin token",
            replace_once(
                'CHIO_EDGE_TOKEN="$${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}"',
                'CHIO_EDGE_TOKEN="$${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}"',
            ),
        ),
        (
            "Make smoke maps admin access from ordinary authentication",
            replace_once(
                'CHIO_ADMIN_TOKEN="$${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}"',
                'CHIO_ADMIN_TOKEN="$${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}"',
            ),
        ),
        (
            "Make smoke maps dashboard reads from ordinary authentication",
            replace_once(
                'CHIO_DASHBOARD_READ_TOKEN="$${CHIO_DASHBOARD_READ_TOKEN:?set a dedicated CHIO_DASHBOARD_READ_TOKEN}"',
                'CHIO_DASHBOARD_READ_TOKEN="$${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}"',
            ),
        ),
    )
    for label, mutate in makefile_mutations:
        assert_rejected(
            label,
            makefile,
            mutate,
            "bounded readiness and exact token mapping",
        )

    documentation_mutations = (
        (
            "Docker README reintroduces demo credential",
            docker_readme,
            replace_once(
                "# Docker Quickstart Example\n",
                "# Docker Quickstart Example\n\nDefault: `demo-token`.\n",
            ),
            "demo credential literal",
        ),
        (
            "Docker README reintroduces credential fallback",
            docker_readme,
            replace_once(
                'CHIO_EDGE_TOKEN="${CHIO_AUTH_TOKEN}"',
                'CHIO_EDGE_TOKEN="${CHIO_AUTH_TOKEN:-unsafe}"',
            ),
            "credential fallbacks",
        ),
        (
            "Docker README omits token distinction check",
            docker_readme,
            replace_once('test "${CHIO_AUTH_TOKEN}" != "${CHIO_SERVICE_TOKEN}"\n', ""),
            "explicit distinct credentials",
        ),
        (
            "Docker README omits explicit admin token generation",
            docker_readme,
            replace_once('export CHIO_ADMIN_TOKEN="$(openssl rand -hex 32)"\n', ""),
            "explicit distinct credentials",
        ),
        (
            "Docker README maps smoke admin access to the edge token",
            docker_readme,
            replace_once(
                'CHIO_ADMIN_TOKEN="${CHIO_ADMIN_TOKEN}"',
                'CHIO_ADMIN_TOKEN="${CHIO_AUTH_TOKEN}"',
            ),
            "explicit distinct credentials",
        ),
        (
            "Docker README omits admin-service distinction",
            docker_readme,
            replace_once('test "${CHIO_ADMIN_TOKEN}" != "${CHIO_SERVICE_TOKEN}"\n', ""),
            "explicit distinct credentials",
        ),
        (
            "Docker README omits bounded Compose readiness",
            docker_readme,
            replace_once(
                "docker compose up -d --build --wait --wait-timeout 180",
                "docker compose up -d --build",
            ),
            "bounded Docker Compose readiness waiting",
        ),
        (
            "tutorial reintroduces demo credential",
            tutorial,
            replace_once(
                "# Progressive Chio Tutorial\n",
                "# Progressive Chio Tutorial\n\nUse `demo-token`.\n",
            ),
            "demo credential literal",
        ),
        (
            "tutorial reintroduces credential fallback",
            tutorial,
            replace_once(
                'CHIO_ADMIN_TOKEN="${CHIO_ADMIN_TOKEN}"',
                'CHIO_ADMIN_TOKEN="${CHIO_ADMIN_TOKEN:-unsafe}"',
            ),
            "credential fallbacks",
        ),
        (
            "tutorial omits explicit service token generation",
            tutorial,
            replace_once('export CHIO_SERVICE_TOKEN="$(openssl rand -hex 32)"\n', ""),
            "explicit distinct credentials",
        ),
        (
            "tutorial uses the ordinary edge token for an admin route",
            tutorial,
            replace_once(
                '-H "Authorization: Bearer ${CHIO_ADMIN_TOKEN}" \\\n',
                '-H "Authorization: Bearer ${CHIO_AUTH_TOKEN}" \\\n',
            ),
            "use only the admin token for its /admin/ example",
        ),
        (
            "tutorial omits bounded Compose readiness",
            tutorial,
            replace_once(
                "docker compose -f examples/docker/compose.yaml up -d --build --wait --wait-timeout 180",
                "docker compose -f examples/docker/compose.yaml up -d --build",
            ),
            "bounded Docker Compose readiness waiting",
        ),
    )
    for label, path, mutate, error in documentation_mutations:
        assert_rejected(label, path, mutate, error)

    assert_rejected(
        "tool schema accepts unknown properties",
        tools,
        replace_once('"additionalProperties": false', '"additionalProperties": true'),
        "closed, and bounded",
    )
    assert_rejected(
        "tool message input becomes unbounded",
        tools,
        replace_once('"maxLength": 4096', '"maxLength": 1048576'),
        "closed, and bounded",
    )

    assert_rejected(
        "native provisioner omits migration ledger",
        provisioner,
        replace_once(
            'const MIGRATION_DATABASE_FILE: &str = "enterprise-migration.sqlite3";',
            'const MIGRATION_DATABASE_FILE: &str = "unchecked.sqlite3";',
        ),
        "exact cage migration ledger",
    )
    assert_rejected(
        "native provisioner replay validation is removed",
        provisioner,
        replace_once(
            "validate_existing_provision(&inputs)?", "build_unchecked_report(&inputs)?"
        ),
        "fail closed on one-shot replay",
    )
    assert_rejected(
        "systemd control URL is downgraded",
        edge_unit,
        replace_once(
            "--control-url https://trust-control.example.com",
            "--control-url http://trust-control.example.com",
        ),
        "one final literal HTTPS control URL",
    )
    assert_rejected(
        "systemd private CA is removed",
        edge_unit,
        replace_once(
            "CHIO_CONTROL_TLS_ROOT_CA_FILE=/etc/chio/control-root-ca.pem",
            "CHIO_CONTROL_TLS_ROOT_CA_FILE=/etc/ssl/certs/ca-certificates.crt",
        ),
        "pin the exact private CA root",
    )
    assert_rejected(
        "systemd trust authority seed becomes a database",
        trust_unit,
        replace_once(
            "--authority-seed-file /var/lib/chio-trust-control/authority.seed",
            "--authority-db /var/lib/chio-trust-control/authority.sqlite3",
        ),
        "must supply --authority-seed-file exactly once",
    )

    for label, path, expected in (
        ("security entrypoint removed", edge_entrypoint, "entrypoint is unreadable"),
        (
            "edge healthcheck removed",
            edge_healthcheck,
            "edge healthcheck is unreadable",
        ),
        ("launcher removed", launcher, "target launcher is unreadable"),
        ("TLS healthcheck removed", healthcheck, "healthcheck is unreadable"),
        ("smoke client removed", smoke, "smoke client is unreadable"),
        ("tools fixture removed", tools, "tools fixture is unreadable"),
        ("Docker README removed", docker_readme, "README is unreadable"),
        ("progressive tutorial removed", tutorial, "tutorial is unreadable"),
        ("Makefile removed", makefile, "Makefile is unreadable"),
    ):
        assert_missing_file_rejected(label, path, expected)

    print(
        "check-security-runtime-contract.test.py: "
        f"{ASSERTION_COUNT} mutation assertions passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
