#!/usr/bin/env python3
"""Fail-closed static contract for the Docker and systemd security runtimes."""

from __future__ import annotations

import argparse
import ast
import json
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping, Sequence
from urllib.parse import urlsplit

import yaml


COMPOSE_PATH = Path("examples/docker/compose.yaml")
MAKEFILE_PATH = Path("Makefile")
DOCKERFILE_PATH = Path("deploy/docker/Dockerfile")
DOCKER_EDGE_ENTRYPOINT_PATH = Path("examples/docker/mcp_demo_entrypoint.py")
DOCKER_EDGE_HEALTHCHECK_PATH = Path("examples/docker/mcp_edge_healthcheck.py")
DOCKER_TLS_ENTRYPOINT_PATH = Path("examples/docker/tls_demo_entrypoint.sh")
DOCKER_TLS_PROXY_PATH = Path("examples/docker/tls_reverse_proxy.py")
DOCKER_TLS_HEALTHCHECK_PATH = Path("examples/docker/tls_healthcheck.py")
DOCKER_SMOKE_CLIENT_PATH = Path("examples/docker/smoke_client.py")
DOCKER_LAUNCHER_PATH = Path("examples/docker/mcp_demo_launcher.c")
DOCKER_TOOLS_PATH = Path("examples/docker/tools.json")
DOCKER_README_PATH = Path("examples/docker/README.md")
PROGRESSIVE_TUTORIAL_PATH = Path("docs/start-here/PROGRESSIVE_TUTORIAL.md")
NATIVE_PROVISIONER_PATH = Path("crates/products/chio-cli/src/cli/mcp/provision.rs")
EDGE_UNIT_PATH = Path("docs/release/systemd/chio-mcp-edge.service")
TRUST_UNIT_PATH = Path("docs/release/systemd/chio-trust-control.service")

EDGE_SERVICE = "chio-mcp-demo"
TRUST_SERVICE = "chio-trust-demo"
EDGE_BUILD_TARGET = "chio-mcp-demo"
TRUST_BUILD_TARGET = "chio-trust-demo"
TLS_BUILD_TARGET = "chio-trust-tls-demo"
TLS_SERVICE = "chio-trust-tls"
TLS_INIT_SERVICE = "chio-tls-init"
PROOF_ROOM_SERVICE = "chio-proof-room"
PROOF_ROOM_BUILD_TARGET = "chio-proof-room-quickstart"
PROOF_ROOM_DOCTOR_REPORT = PurePosixPath("/tmp/chio-proof-doctor-report.json")
PROOF_ROOM_IMAGE_DOCTOR_REPORT = PurePosixPath("/opt/chio/proof-doctor-report.json")
PUBLIC_SECURITY_VOLUME = "chio_public_security"
EDGE_STATE_VOLUME = "chio_edge_state"
TRUST_SECRET_VOLUME = "chio_trust_secret"
TRUST_STATE_VOLUME = "chio_demo_state"
TLS_CA_VOLUME = "chio_tls_ca_private"
TLS_SERVER_VOLUME = "chio_tls_private"
TLS_PUBLIC_VOLUME = "chio_tls_public"
PUBLIC_SECURITY_TARGET = PurePosixPath("/run/chio-public")
EDGE_STATE_TARGET = PurePosixPath("/var/lib/chio")
TRUST_SECRET_TARGET = PurePosixPath("/run/chio-trust")
TLS_CA_TARGET = PurePosixPath("/var/lib/chio-tls-ca")
TLS_PRIVATE_TARGET = PurePosixPath("/var/lib/chio-tls-private")
TLS_PUBLIC_TARGET = PurePosixPath("/var/lib/chio-tls-public")
PROVISION_OUTPUT = PurePosixPath("/run/chio-provision/security")
RUNTIME_SECURITY_DIR = PurePosixPath("/var/lib/chio/security")
DEMO_LAUNCHER = "/usr/local/bin/chio-demo-mcp-launcher"
TLS_ROOT_CA_NAME = "demo-ca.pem"
TLS_PORT = 8940

PUBLIC_RUNTIME_ARTIFACTS = {
    "signed-manifest.json",
    "manifest-public-key",
    "cage-launch-policy.json",
    "cage-policy-signer",
    "cage-migration-public-key",
    "cage-receipt-public-key",
    "control-authority-public-key",
    "target-command",
}
EDGE_PRIVATE_ARTIFACTS = {
    "enterprise-migration.sqlite3",
    "cage-receipt-signer.seed",
    "control-authority.seed",
}
PROVISION_ONLY_SIGNER_SEEDS = {
    "manifest-signer.seed",
    "cage-policy-signer.seed",
    "cage-migration-signer.seed",
}

SECURITY_ARTIFACTS = {
    "signed manifest": "signed-manifest.json",
    "manifest verifier key": "manifest-public-key",
    "signed cage policy": "cage-launch-policy.json",
    "cage policy verifier key": "cage-policy-signer",
    "current authority pin": "control-authority-public-key",
    "local authority seed": "control-authority.seed",
    "canonical target command": "target-command",
}
EDGE_REQUIRED_FLAGS = {
    "local authority seed": "--authority-seed-file",
    "final control URL": "--control-url",
    "exact current authority pin": "--control-authority-public-key",
    "signed manifest": "--signed-manifest",
    "manifest verifier key": "--manifest-public-key",
    "signed cage policy": "--cage-policy",
    "cage policy verifier key": "--cage-policy-signer",
}
FORBIDDEN_EDGE_STORE_FLAGS = (
    "--receipt-db",
    "--revocation-db",
    "--budget-db",
    "--authority-db",
)
PROVISION_SUBCOMMAND = "provision-native-mcp-demo"


class ContractError(RuntimeError):
    """The checked deployment surface weakens the security contract."""


class UniqueKeyLoader(yaml.BaseLoader):
    """BaseLoader variant that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ContractError("YAML mapping contains a non-scalar key") from error
        if duplicate:
            raise ContractError(f"YAML mapping contains duplicate key {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


@dataclass(frozen=True)
class VolumeMount:
    source: str
    target: PurePosixPath
    read_only: bool


def _read_text(path: Path, label: str) -> str:
    try:
        body = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ContractError(f"{label} is unreadable: {path}: {error}") from error
    if not body.strip():
        raise ContractError(f"{label} is empty: {path}")
    return body


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ContractError(f"{label} must be a string-keyed mapping")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _load_compose(path: Path) -> dict[str, object]:
    body = _read_text(path, "Docker Compose file")
    try:
        loaded = yaml.load(body, Loader=UniqueKeyLoader)
    except ContractError:
        raise
    except yaml.YAMLError as error:
        raise ContractError(
            f"Docker Compose YAML is invalid: {path}: {error}"
        ) from error
    return _mapping(loaded, "Docker Compose root")


def _service(compose: Mapping[str, object], name: str) -> dict[str, object]:
    services = _mapping(compose.get("services"), "Docker Compose services")
    if name not in services:
        raise ContractError(f"Docker Compose is missing required service {name!r}")
    return _mapping(services[name], f"Docker Compose service {name!r}")


def _effective_service(service: Mapping[str, object], label: str) -> dict[str, object]:
    merged: dict[str, object] = {}
    inherited = service.get("<<")
    if inherited is not None:
        merged.update(_mapping(inherited, f"{label} inherited configuration"))
    merged.update((key, value) for key, value in service.items() if key != "<<")
    return merged


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ContractError(f"{label} must be a non-empty string list")
    return list(value)


def _require_exact_strings(value: object, expected: set[str], label: str) -> None:
    observed = _string_list(value, label)
    if len(observed) != len(set(observed)) or set(observed) != expected:
        raise ContractError(f"{label} must be exactly {sorted(expected)!r}")


def _require_hardening(
    service: Mapping[str, object],
    label: str,
    *,
    maximum_pids: int,
    cap_add: set[str] | None = None,
    require_tmp: bool = True,
) -> dict[str, object]:
    effective = _effective_service(service, label)
    if effective.get("read_only") != "true":
        raise ContractError(f"{label} root filesystem must be read-only")
    _require_exact_strings(effective.get("cap_drop"), {"ALL"}, f"{label} cap_drop")
    _require_exact_strings(
        effective.get("security_opt"),
        {"no-new-privileges:true"},
        f"{label} security_opt",
    )
    expected_additions = cap_add or set()
    observed_additions = effective.get("cap_add")
    if expected_additions:
        _require_exact_strings(
            observed_additions, expected_additions, f"{label} cap_add"
        )
    elif observed_additions not in (None, []):
        raise ContractError(f"{label} must not add Linux capabilities")
    raw_limit = effective.get("pids_limit")
    try:
        pid_limit = int(_string(raw_limit, f"{label} pids_limit"), 10)
    except ValueError as error:
        raise ContractError(f"{label} pids_limit must be an integer") from error
    if pid_limit < 1 or pid_limit > maximum_pids:
        raise ContractError(f"{label} pids_limit must be between 1 and {maximum_pids}")
    if require_tmp:
        tmpfs = _string_list(effective.get("tmpfs"), f"{label} tmpfs")
        if not any(
            item.startswith("/tmp:rw,")
            and all(
                option in item.split(",") for option in ("noexec", "nosuid", "nodev")
            )
            for item in tmpfs
        ):
            raise ContractError(f"{label} must use a bounded hardened /tmp tmpfs")
    return effective


def _service_networks(service: Mapping[str, object], label: str) -> set[str]:
    effective = _effective_service(service, label)
    networks = effective.get("networks")
    if isinstance(networks, list):
        values = _string_list(networks, f"{label} networks")
    elif isinstance(networks, dict):
        values = list(_mapping(networks, f"{label} networks"))
    else:
        raise ContractError(f"{label} must declare explicit networks")
    if len(values) != len(set(values)):
        raise ContractError(f"{label} contains duplicate networks")
    return set(values)


def _require_loopback_port(
    service: Mapping[str, object], label: str, variable: str, default: int, target: int
) -> None:
    effective = _effective_service(service, label)
    ports = _string_list(effective.get("ports"), f"{label} ports")
    expected = f"127.0.0.1:${{{variable}:-{default}}}:{target}"
    if ports != [expected]:
        raise ContractError(
            f"{label} must publish only the exact loopback port {expected!r}"
        )


def _require_no_ports(service: Mapping[str, object], label: str) -> None:
    effective = _effective_service(service, label)
    if effective.get("ports") not in (None, []):
        raise ContractError(f"{label} must not publish host ports")


def _require_healthcheck(
    service: Mapping[str, object], label: str, expected_test: list[str]
) -> None:
    effective = _effective_service(service, label)
    health = _mapping(effective.get("healthcheck"), f"{label} healthcheck")
    if health.get("test") != expected_test:
        raise ContractError(f"{label} healthcheck command is not exact")
    if any(word.strip().lower() in {"true", "/bin/true"} for word in expected_test):
        raise ContractError(f"{label} healthcheck cannot be unconditional")
    expected_timing = {
        "interval": "5s",
        "timeout": "3s" if label == "Docker trust-control" else "4s",
        "retries": "20",
        "start_period": "5s",
    }
    for key, expected in expected_timing.items():
        if health.get(key) != expected:
            raise ContractError(f"{label} healthcheck {key} must be {expected!r}")


def _assert_exact_mounts(
    service: Mapping[str, object],
    label: str,
    expected: Mapping[PurePosixPath, tuple[str, bool]],
) -> list[VolumeMount]:
    mounts = _volume_mounts(_effective_service(service, label), label)
    if len(mounts) != len(expected):
        raise ContractError(f"{label} volume set is not exact")
    for target, (source, read_only) in expected.items():
        mount = _mount_for_target(mounts, target, label)
        if mount.source != source or mount.read_only != read_only:
            mode = "read-only" if read_only else "writable"
            raise ContractError(f"{label} must mount {source!r} at {target} {mode}")
    return mounts


def _writable_container_roots(
    service: Mapping[str, object], label: str
) -> set[PurePosixPath]:
    effective = _effective_service(service, label)
    if effective.get("read_only") != "true":
        raise ContractError(f"{label} root filesystem must remain read-only")
    roots: set[PurePosixPath] = set()
    raw_volumes = effective.get("volumes")
    if raw_volumes is not None:
        for mount in _volume_mounts(effective, label):
            if not mount.read_only:
                roots.add(mount.target)
    raw_tmpfs = effective.get("tmpfs")
    if raw_tmpfs is not None:
        for index, item in enumerate(_string_list(raw_tmpfs, f"{label} tmpfs")):
            parts = item.split(":", 1)
            target = PurePosixPath(parts[0])
            options = set(parts[1].split(",")) if len(parts) == 2 else set()
            if not target.is_absolute() or ".." in target.parts:
                raise ContractError(
                    f"{label} tmpfs[{index}] target must be an absolute canonical path"
                )
            if "rw" in options and "ro" not in options:
                roots.add(target)
    return roots


def _require_write_target_backed(
    service: Mapping[str, object], target: PurePosixPath, label: str
) -> None:
    if not target.is_absolute() or ".." in target.parts:
        raise ContractError(f"{label} must be an absolute canonical path")
    for root in _writable_container_roots(service, label):
        try:
            target.relative_to(root)
        except ValueError:
            continue
        return
    raise ContractError(
        f"{label} configured write target {str(target)!r} is not backed by an explicit writable mount or tmpfs"
    )


def _dockerfile_json_instruction(stage: str, directive: str, label: str) -> list[str]:
    matches = re.findall(rf"(?im)^\s*{re.escape(directive)}\s+(\[[^\n]+\])\s*$", stage)
    if len(matches) != 1:
        raise ContractError(
            f"{label} must define {directive} exactly once in JSON form"
        )
    try:
        value = json.loads(matches[0])
    except json.JSONDecodeError as error:
        raise ContractError(f"{label} {directive} is invalid JSON: {error}") from error
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise ContractError(f"{label} {directive} must be a non-empty string list")
    return value


def _shell_artifact_loop(command: str, destination: str, label: str) -> set[str]:
    pattern = re.compile(
        rf"for\s+artifact\s+in\s+(?P<items>[^;]+);\s*do\s*"
        rf'cp\s+"/run/chio-provision/security/\$\$\{{artifact\}}"\s+'
        rf'"{re.escape(destination)}/\$\$\{{artifact\}}"',
        re.DOTALL,
    )
    matches = list(pattern.finditer(command))
    if len(matches) != 1:
        raise ContractError(
            f"native MCP provisioner must have one exact {label} copy loop"
        )
    try:
        words = shlex.split(matches[0].group("items").replace("\\\n", " "))
    except ValueError as error:
        raise ContractError(
            f"native MCP provisioner {label} list is invalid"
        ) from error
    if len(words) != len(set(words)):
        raise ContractError(f"native MCP provisioner {label} list has duplicates")
    return set(words)


def _build_target(service: Mapping[str, object], label: str) -> str:
    build = service.get("build")
    if isinstance(build, str):
        raise ContractError(f"{label} build must name its exact Dockerfile target")
    build_map = _mapping(build, f"{label} build")
    return _string(build_map.get("target"), f"{label} build target")


def _environment(service: Mapping[str, object], label: str) -> dict[str, str]:
    value = service.get("environment")
    if value is None:
        return {}
    if isinstance(value, dict):
        result: dict[str, str] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise ContractError(f"{label} environment contains an invalid key")
            if not isinstance(item, str) or not item:
                raise ContractError(f"{label} environment variable {key!r} is empty")
            result[key] = item
        return result
    if isinstance(value, list):
        result = {}
        for item in value:
            text = _string(item, f"{label} environment entry")
            if "=" not in text:
                raise ContractError(
                    f"{label} environment entry {text!r} inherits ambient state"
                )
            key, item_value = text.split("=", 1)
            if not key or not item_value or key in result:
                raise ContractError(f"{label} environment entry {text!r} is ambiguous")
            result[key] = item_value
        return result
    raise ContractError(f"{label} environment must be a mapping or explicit list")


def _parse_read_only(value: object, label: str) -> bool:
    if value in (True, "true", "yes", "1"):
        return True
    if value in (False, "false", "no", "0", None):
        return False
    raise ContractError(f"{label} read_only must be an explicit boolean")


def _volume_mounts(service: Mapping[str, object], label: str) -> list[VolumeMount]:
    raw = service.get("volumes")
    if not isinstance(raw, list) or not raw:
        raise ContractError(f"{label} must declare explicit volume mounts")
    mounts: list[VolumeMount] = []
    for index, item in enumerate(raw):
        item_label = f"{label} volume[{index}]"
        if isinstance(item, str):
            parts = item.split(":")
            if len(parts) not in (2, 3) or not parts[0] or not parts[1]:
                raise ContractError(
                    f"{item_label} must use explicit source:target syntax"
                )
            modes = set(parts[2].split(",")) if len(parts) == 3 else set()
            unknown_modes = modes - {"ro", "rw", "z", "Z", "nocopy"}
            if unknown_modes or ({"ro", "rw"} <= modes):
                raise ContractError(f"{item_label} has ambiguous mount modes")
            source, target = parts[0], parts[1]
            read_only = "ro" in modes
        else:
            item_map = _mapping(item, item_label)
            mount_type = item_map.get("type", "volume")
            if mount_type != "volume":
                raise ContractError(f"{item_label} must be a named volume")
            source = _string(item_map.get("source"), f"{item_label} source")
            target = _string(item_map.get("target"), f"{item_label} target")
            read_only = _parse_read_only(item_map.get("read_only"), item_label)
        target_path = PurePosixPath(target)
        if not target_path.is_absolute() or ".." in target_path.parts:
            raise ContractError(
                f"{item_label} target must be an absolute canonical path"
            )
        mounts.append(VolumeMount(source, target_path, read_only))
    duplicate_targets = sorted(
        str(target)
        for target in {mount.target for mount in mounts}
        if sum(mount.target == target for mount in mounts) > 1
    )
    if duplicate_targets:
        raise ContractError(
            f"{label} has duplicate volume targets: {duplicate_targets!r}"
        )
    return mounts


def _mount_for_target(
    mounts: Iterable[VolumeMount], target: PurePosixPath, label: str
) -> VolumeMount:
    matches = [mount for mount in mounts if mount.target == target]
    if len(matches) != 1:
        raise ContractError(f"{label} must mount exactly {target}")
    return matches[0]


def _mount_containing(
    mounts: Iterable[VolumeMount], path: PurePosixPath, label: str
) -> VolumeMount:
    matches = []
    for mount in mounts:
        try:
            path.relative_to(mount.target)
        except ValueError:
            continue
        matches.append(mount)
    if len(matches) != 1:
        raise ContractError(f"{label} must have one unambiguous backing volume")
    return matches[0]


def _command_words(service: Mapping[str, object], label: str) -> list[str]:
    entrypoint = service.get("entrypoint")
    command = service.get("command")

    def words(value: object, part: str) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            if not value or any(
                not isinstance(item, str) or not item for item in value
            ):
                raise ContractError(f"{label} {part} must be a non-empty string list")
            return list(value)
        text = _string(value, f"{label} {part}")
        try:
            return shlex.split(text, posix=True)
        except ValueError as error:
            raise ContractError(
                f"{label} {part} has invalid shell quoting: {error}"
            ) from error

    entrypoint_words = words(entrypoint, "entrypoint")
    command_words = words(command, "command")
    shell_names = {"sh", "/bin/sh", "bash", "/bin/bash"}
    if (
        entrypoint_words
        and entrypoint_words[0] in shell_names
        and any(
            "c" in option[1:]
            for option in entrypoint_words[1:]
            if option.startswith("-")
        )
        and isinstance(command, list)
        and len(command) == 1
        and isinstance(command[0], str)
    ):
        try:
            command_words = shlex.split(command[0], posix=True)
        except ValueError as error:
            raise ContractError(
                f"{label} shell command has invalid quoting: {error}"
            ) from error
    return entrypoint_words + command_words


def _command_text(service: Mapping[str, object]) -> str:
    parts = []
    for key in ("entrypoint", "command"):
        value = service.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(item for item in value if isinstance(item, str))
    return "\n".join(parts)


def _flag_value(words: Sequence[str], flag: str, label: str) -> str:
    positions = [index for index, word in enumerate(words) if word == flag]
    inline = [word.split("=", 1)[1] for word in words if word.startswith(f"{flag}=")]
    if len(positions) + len(inline) != 1:
        raise ContractError(f"{label} must supply {flag} exactly once")
    if inline:
        return _string(inline[0], f"{label} {flag} value")
    index = positions[0]
    if index + 1 >= len(words) or words[index + 1].startswith("--"):
        raise ContractError(f"{label} {flag} has no value")
    return words[index + 1]


def _depends_condition(
    service: Mapping[str, object], dependency: str, expected: str, label: str
) -> None:
    depends = _mapping(service.get("depends_on"), f"{label} depends_on")
    dependency_body = _mapping(
        depends.get(dependency), f"{label} dependency on {dependency!r}"
    )
    if dependency_body.get("condition") != expected:
        raise ContractError(
            f"{label} must depend on {dependency!r} with condition {expected!r}"
        )
    if dependency_body.get("required", "true") != "true":
        raise ContractError(f"{label} dependency on {dependency!r} must be required")


def _single_service_with_target(
    compose: Mapping[str, object], target: str, label: str
) -> tuple[str, dict[str, object]]:
    services = _mapping(compose.get("services"), "Docker Compose services")
    matches: list[tuple[str, dict[str, object]]] = []
    for name, raw_service in services.items():
        service = _mapping(raw_service, f"Docker Compose service {name!r}")
        build = service.get("build")
        if isinstance(build, dict) and build.get("target") == target:
            matches.append((name, service))
    if len(matches) != 1:
        raise ContractError(
            f"Docker Compose must define exactly one {label} using target {target!r}"
        )
    return matches[0]


def _provision_service(
    compose: Mapping[str, object], edge_service: Mapping[str, object]
) -> tuple[str, dict[str, object], list[str]]:
    services = _mapping(compose.get("services"), "Docker Compose services")
    matches = []
    for name, raw_service in services.items():
        if name == EDGE_SERVICE:
            continue
        service = _mapping(raw_service, f"Docker Compose service {name!r}")
        words = _command_words(service, f"Docker Compose service {name!r}")
        if PROVISION_SUBCOMMAND in words:
            matches.append((name, service, words))
    if len(matches) != 1:
        raise ContractError(
            "Docker Compose must define exactly one native MCP security provisioner"
        )
    name, service, words = matches[0]
    if service.get("restart") != "no":
        raise ContractError(
            "native MCP security provisioner must be one-shot (restart: no)"
        )
    if _build_target(service, "native MCP security provisioner") != EDGE_BUILD_TARGET:
        raise ContractError(
            "native MCP security provisioner must use the reviewed edge image"
        )
    edge_image = edge_service.get("image")
    if not isinstance(edge_image, str) or service.get("image") != edge_image:
        raise ContractError(
            "native MCP security provisioner and edge must use the same image"
        )
    return name, service, words


def _validate_https_url(value: str, expected_host: str, label: str) -> None:
    if any(marker in value for marker in ("${", "$(`", "$(", "{", "}")):
        raise ContractError(f"{label} must be a final literal HTTPS URL")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ContractError(f"{label} has an invalid port: {error}") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or port != TLS_PORT
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ContractError(
            f"{label} must be exactly the TLS proxy at https://{expected_host}:{TLS_PORT}"
        )


def _validate_compose(root: Path) -> None:
    compose_body = _read_text(root / COMPOSE_PATH, "Docker Compose file")
    if "demo-token" in compose_body:
        raise ContractError("Docker Compose must not contain a demo credential literal")
    if re.search(r"\$\{CHIO_(?:AUTH|ADMIN|SERVICE|EDGE|CONTROL)_TOKEN:-", compose_body):
        raise ContractError(
            "Docker Compose credentials must not use default-value fallbacks"
        )
    compose = _load_compose(root / COMPOSE_PATH)
    edge = _service(compose, EDGE_SERVICE)
    trust = _service(compose, TRUST_SERVICE)
    tls_init = _service(compose, TLS_INIT_SERVICE)
    tls_proxy = _service(compose, TLS_SERVICE)
    proof_room = _service(compose, PROOF_ROOM_SERVICE)
    if _build_target(edge, "Docker MCP edge") != EDGE_BUILD_TARGET:
        raise ContractError("Docker MCP edge uses the wrong image target")
    if _build_target(trust, "Docker trust-control") != TRUST_BUILD_TARGET:
        raise ContractError("Docker trust-control uses the wrong image target")
    if _build_target(tls_init, "Docker TLS provisioner") != TLS_BUILD_TARGET:
        raise ContractError("Docker TLS provisioner uses the wrong image target")
    if _build_target(tls_proxy, "Docker TLS control proxy") != TLS_BUILD_TARGET:
        raise ContractError("Docker TLS control proxy uses the wrong image target")
    if _build_target(proof_room, "Docker proof-room") != PROOF_ROOM_BUILD_TARGET:
        raise ContractError("Docker proof-room uses the wrong image target")

    declared_volumes = _mapping(compose.get("volumes"), "Docker Compose volumes")
    required_volumes = {
        PUBLIC_SECURITY_VOLUME,
        EDGE_STATE_VOLUME,
        TRUST_SECRET_VOLUME,
        TRUST_STATE_VOLUME,
        TLS_CA_VOLUME,
        TLS_SERVER_VOLUME,
        TLS_PUBLIC_VOLUME,
    }
    missing_volumes = sorted(required_volumes - set(declared_volumes))
    if missing_volumes:
        raise ContractError(f"Docker Compose omits runtime volumes {missing_volumes!r}")
    if len(required_volumes) != 7:
        raise ContractError("Docker runtime volumes must remain distinct")

    networks = _mapping(compose.get("networks"), "Docker Compose networks")
    for network_name in ("trust-backend", "edge-control", "proof-room"):
        network = _mapping(
            networks.get(network_name), f"Docker Compose network {network_name!r}"
        )
        if network != {"internal": "true"}:
            raise ContractError(
                f"Docker Compose network {network_name!r} must be explicitly internal"
            )

    provision_name, provision, provision_words = _provision_service(compose, edge)
    if provision_name != "chio-security-init":
        raise ContractError("native MCP security provisioner service name is not exact")
    if provision.get("entrypoint") != ["/bin/sh", "-ec"]:
        raise ContractError(
            "native MCP security provisioner must use the fail-closed shell entrypoint"
        )
    provision_command = provision.get("command")
    if (
        not isinstance(provision_command, list)
        or len(provision_command) != 1
        or not isinstance(provision_command[0], str)
        or "/usr/local/bin/chio security provision-native-mcp-demo"
        not in provision_command[0]
        or "|| true" in provision_command[0]
    ):
        raise ContractError(
            "native MCP security provisioner command is not fail-closed"
        )
    if provision.get("restart") != "no" or provision.get("network_mode") != "none":
        raise ContractError(
            "native MCP security provisioner must be one-shot with network_mode none"
        )
    if provision.get("user") != "0:0":
        raise ContractError("native MCP security provisioner must run as root")
    provision_effective = _require_hardening(
        provision,
        "native MCP security provisioner",
        maximum_pids=64,
        cap_add={"CHOWN"},
        require_tmp=False,
    )
    provision_tmpfs = _string_list(
        provision_effective.get("tmpfs"), "native MCP security provisioner tmpfs"
    )
    if (
        "/run/chio-provision:rw,noexec,nosuid,nodev,size=67108864,mode=0700"
        not in provision_tmpfs
    ):
        raise ContractError(
            "native MCP provision output must be an ephemeral hardened tmpfs"
        )
    _require_no_ports(provision, "native MCP security provisioner")
    provision_output = PurePosixPath(
        _flag_value(provision_words, "--output-dir", "native MCP security provisioner")
    )
    if provision_output != PROVISION_OUTPUT:
        raise ContractError("native MCP provision output path is not exact")
    runtime_security_dir = PurePosixPath(
        _flag_value(
            provision_words,
            "--runtime-security-dir",
            "native MCP security provisioner",
        )
    )
    if runtime_security_dir != RUNTIME_SECURITY_DIR:
        raise ContractError("native MCP runtime security directory is not exact")
    command_position = provision_words.index(PROVISION_SUBCOMMAND)
    if command_position == 0 or provision_words[command_position - 1] != "security":
        raise ContractError(
            "native MCP provisioner must invoke security provision-native-mcp-demo"
        )
    tools_fixture = _flag_value(
        provision_words, "--tools-fixture", "native MCP security provisioner"
    )
    if tools_fixture != "/opt/chio/examples/tools.json":
        raise ContractError(
            "native MCP provisioner must use the reviewed tools fixture"
        )
    target = _flag_value(provision_words, "--target", "native MCP security provisioner")
    if target != DEMO_LAUNCHER:
        raise ContractError(
            "native MCP provisioner must digest-bind the exact demo launcher"
        )
    required_provision_values = {
        "--working-directory": "/opt/chio",
        "--execution-uid": "10002",
        "--execution-gid": "10002",
        "--server-id": "docker-demo",
        "--server-name": "Docker demo MCP",
        "--server-version": "1",
    }
    for flag, expected in required_provision_values.items():
        if (
            _flag_value(provision_words, flag, "native MCP security provisioner")
            != expected
        ):
            raise ContractError(
                f"native MCP provisioner must pin the exact {flag.removeprefix('--')}"
            )
    provision_mounts = _assert_exact_mounts(
        provision,
        "native MCP security provisioner",
        {
            PUBLIC_SECURITY_TARGET: (PUBLIC_SECURITY_VOLUME, False),
            EDGE_STATE_TARGET: (EDGE_STATE_VOLUME, False),
            TRUST_SECRET_TARGET: (TRUST_SECRET_VOLUME, False),
        },
    )
    if any(
        mount.target == PurePosixPath("/run/chio-provision")
        for mount in provision_mounts
    ):
        raise ContractError("native MCP provision output must not persist in a volume")
    provision_text = provision_command[0]
    public_artifacts = _shell_artifact_loop(
        provision_text, str(PUBLIC_SECURITY_TARGET), "public artifact"
    )
    if public_artifacts != PUBLIC_RUNTIME_ARTIFACTS:
        raise ContractError("native MCP public runtime artifact allowlist is not exact")
    private_artifacts = _shell_artifact_loop(
        provision_text, str(RUNTIME_SECURITY_DIR), "edge-private artifact"
    )
    if private_artifacts != EDGE_PRIVATE_ARTIFACTS:
        raise ContractError("native MCP edge-private artifact allowlist is not exact")
    copied_runtime_artifacts = public_artifacts | private_artifacts
    if copied_runtime_artifacts & PROVISION_ONLY_SIGNER_SEEDS:
        raise ContractError("provisioning-only signer seed escaped into runtime state")
    for seed in PROVISION_ONLY_SIGNER_SEEDS:
        direct_copy = re.compile(
            rf"(?m)^\s*cp\s+[^\n]*{re.escape(seed)}[^\n]*"
            r"(/run/chio-public|/var/lib/chio|/run/chio-trust)"
        )
        if direct_copy.search(provision_text):
            raise ContractError(
                f"provisioning-only signer seed {seed!r} is copied to runtime state"
            )
    required_provision_fragments = (
        'if [ ! -d "$${directory}" ] || [ -L "$${directory}" ]; then',
        'chown 0:0 "$${directory}"',
        'chmod 0700 "$${directory}"',
        'first_entry="$$(find "$${directory}" -mindepth 1 -maxdepth 1 -print -quit)" || {',
        "cp /run/chio-provision/security/control-authority.seed /run/chio-trust/control-authority.seed",
        "chown 10001:10001 /run/chio-trust/control-authority.seed /run/chio-trust",
        "chmod 0400 /run/chio-trust/control-authority.seed",
        "chown -R 0:0 /run/chio-public /var/lib/chio/security",
        "chmod 0555 /run/chio-public",
        "chmod 0700 /var/lib/chio/security",
    )
    for fragment in required_provision_fragments:
        if fragment not in provision_text:
            raise ContractError(
                f"native MCP provisioner omits runtime ownership contract {fragment!r}"
            )
    forbidden_loop = re.search(
        r"(?ms)^\s*for forbidden in "
        r"manifest-signer\.seed cage-policy-signer\.seed cage-migration-signer\.seed; do\n"
        r"(?P<body>.*?)^\s*done\s*$",
        provision_text,
    )
    if forbidden_loop is None:
        raise ContractError(
            "native MCP provisioner omits the exact forbidden-signer inspection"
        )
    forbidden_body = forbidden_loop.group("body")
    required_inspection = (
        'escaped_path="$$(find /run/chio-public /var/lib/chio /run/chio-trust '
        '-name "$${forbidden}" -print -quit)" || {',
        'if [ -n "$${escaped_path}" ]; then',
        "failed to inspect runtime state for escaped signer",
        "provisioning-only signer escaped into runtime state",
    )
    if any(fragment not in forbidden_body for fragment in required_inspection):
        raise ContractError(
            "native MCP forbidden-signer inspection is not exact and fail-closed"
        )
    if not re.search(
        r'(?m)^\s*echo "failed to inspect runtime state for escaped signer: '
        r'\$\$\{forbidden\}" >&2\n\s*exit 1\n\s*\}$',
        forbidden_body,
    ):
        raise ContractError(
            "native MCP forbidden-signer inspection is not exact and fail-closed"
        )
    if re.search(r"(?<!\|)\|(?!\|)", forbidden_body):
        raise ContractError(
            "native MCP forbidden-signer inspection must not hide find failures in a pipeline"
        )
    trust_handoff = provision_text.index(
        "chown 10001:10001 /run/chio-trust/control-authority.seed /run/chio-trust"
    )
    if forbidden_loop.start() > trust_handoff:
        raise ContractError(
            "native MCP forbidden-signer inspection must precede trust ownership handoff"
        )

    trust_words = _command_words(trust, "Docker trust-control")
    required_service_token = "${CHIO_SERVICE_TOKEN:?set a dedicated CHIO_SERVICE_TOKEN}"
    required_dashboard_read_token = (
        "${CHIO_DASHBOARD_READ_TOKEN:?set a dedicated CHIO_DASHBOARD_READ_TOKEN}"
    )
    trust_environment = _environment(trust, "Docker trust-control")
    if trust_environment != {
        "CHIO_AUTHORITY_SEED_FILE": "/run/chio-trust/control-authority.seed",
        "CHIO_TRUST_DASHBOARD_READ_TOKEN": required_dashboard_read_token,
        "CHIO_TRUST_SERVICE_TOKEN": required_service_token,
    }:
        raise ContractError(
            "Docker trust-control must use only its trust seed, dedicated service token, and dedicated dashboard read token"
        )
    if any(flag in trust_words for flag in ("--authority-db", "--authority-seed")):
        raise ContractError(
            "Docker trust-control configures a conflicting authority store"
        )
    _require_hardening(trust, "Docker trust-control", maximum_pids=128)
    _require_no_ports(trust, "Docker trust-control")
    _assert_exact_mounts(
        trust,
        "Docker trust-control",
        {
            EDGE_STATE_TARGET: (TRUST_STATE_VOLUME, False),
            TRUST_SECRET_TARGET: (TRUST_SECRET_VOLUME, True),
        },
    )
    if _service_networks(trust, "Docker trust-control") != {"trust-backend"}:
        raise ContractError("Docker trust-control must attach only to trust-backend")
    _require_healthcheck(
        trust,
        "Docker trust-control",
        [
            "CMD-SHELL",
            "wget -q -O - http://127.0.0.1:8940/health >/dev/null 2>&1",
        ],
    )

    if tls_init.get("restart") != "no" or tls_init.get("network_mode") != "none":
        raise ContractError(
            "Docker TLS provisioner must be one-shot with network_mode none"
        )
    if tls_init.get("user") != "0:0":
        raise ContractError("Docker TLS provisioner must run as root")
    _require_hardening(
        tls_init,
        "Docker TLS provisioner",
        maximum_pids=32,
        cap_add={"CHOWN"},
        require_tmp=False,
    )
    tls_init_tmpfs = _string_list(
        _effective_service(tls_init, "Docker TLS provisioner").get("tmpfs"),
        "Docker TLS provisioner tmpfs",
    )
    if tls_init_tmpfs != ["/run:rw,noexec,nosuid,nodev,size=33554432,mode=0755"]:
        raise ContractError(
            "Docker TLS provisioner must use the exact hardened /run tmpfs"
        )
    _require_no_ports(tls_init, "Docker TLS provisioner")
    if _environment(tls_init, "Docker TLS provisioner") != {
        "CHIO_TLS_MODE": "provision"
    }:
        raise ContractError("Docker TLS provisioner must select provision mode exactly")
    _assert_exact_mounts(
        tls_init,
        "Docker TLS provisioner",
        {
            TLS_CA_TARGET: (TLS_CA_VOLUME, False),
            TLS_PRIVATE_TARGET: (TLS_SERVER_VOLUME, False),
            TLS_PUBLIC_TARGET: (TLS_PUBLIC_VOLUME, False),
        },
    )

    tls_environment = _environment(tls_proxy, "Docker TLS control proxy")
    if tls_environment.get("CHIO_TLS_MODE") != "serve":
        raise ContractError("Docker TLS proxy must select serve mode exactly")
    if tls_environment.get("CHIO_TLS_UPSTREAM_HOST") != TRUST_SERVICE:
        raise ContractError("Docker TLS proxy must target the trust-control service")
    if tls_environment.get("CHIO_TLS_UPSTREAM_PORT") != str(TLS_PORT):
        raise ContractError("Docker TLS proxy must target the exact trust-control port")
    _require_hardening(tls_proxy, "Docker TLS control proxy", maximum_pids=128)
    tls_mounts = _assert_exact_mounts(
        tls_proxy,
        "Docker TLS control proxy",
        {
            TLS_PRIVATE_TARGET: (TLS_SERVER_VOLUME, True),
            TLS_PUBLIC_TARGET: (TLS_PUBLIC_VOLUME, True),
        },
    )
    if any(mount.source == TLS_CA_VOLUME for mount in tls_mounts):
        raise ContractError("Docker TLS proxy must never receive the CA signing key")
    if _service_networks(tls_proxy, "Docker TLS control proxy") != {
        "trust-backend",
        "edge-control",
    }:
        raise ContractError(
            "Docker TLS proxy must bridge exactly trust-backend and edge-control"
        )
    _require_loopback_port(
        tls_proxy, "Docker TLS control proxy", "CHIO_TRUST_PORT", TLS_PORT, TLS_PORT
    )
    _require_healthcheck(
        tls_proxy,
        "Docker TLS control proxy",
        ["CMD", "python3", "/opt/chio/tls_healthcheck.py"],
    )

    edge_environment = _environment(edge, "Docker MCP edge")
    required_edge_environment = {
        "CHIO_AUTH_TOKEN": "${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}",
        "CHIO_ADMIN_TOKEN": "${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}",
        "CHIO_CONTROL_URL": "https://chio-trust-tls:8940",
        "CHIO_CONTROL_TOKEN": required_service_token,
        "CHIO_CONTROL_TLS_ROOT_CA_FILE": "/var/lib/chio-tls-public/demo-ca.pem",
        "CHIO_PUBLIC_SECURITY_DIR": str(PUBLIC_SECURITY_TARGET),
        "CHIO_PRIVATE_SECURITY_DIR": str(RUNTIME_SECURITY_DIR),
    }
    if edge_environment != required_edge_environment:
        raise ContractError(
            "Docker MCP edge environment must use the exact split security contract"
        )
    control_url = edge_environment.get("CHIO_CONTROL_URL")
    assert isinstance(control_url, str)
    _validate_https_url(control_url, TLS_SERVICE, "Docker MCP edge control URL")
    edge_effective = _require_hardening(
        edge,
        "Docker MCP edge",
        maximum_pids=128,
        cap_add={"SETUID", "SETGID"},
    )
    if edge_effective.get("user") != "0:0":
        raise ContractError(
            "Docker MCP edge must begin as root for identity transition"
        )
    edge_mounts = _assert_exact_mounts(
        edge,
        "Docker MCP edge",
        {
            PUBLIC_SECURITY_TARGET: (PUBLIC_SECURITY_VOLUME, True),
            EDGE_STATE_TARGET: (EDGE_STATE_VOLUME, False),
            TLS_PUBLIC_TARGET: (TLS_PUBLIC_VOLUME, True),
        },
    )
    forbidden_edge_sources = {TRUST_SECRET_VOLUME, TLS_CA_VOLUME, TLS_SERVER_VOLUME}
    if any(mount.source in forbidden_edge_sources for mount in edge_mounts):
        raise ContractError("Docker MCP edge receives a forbidden trust or TLS secret")
    if _service_networks(edge, "Docker MCP edge") != {"edge-control"}:
        raise ContractError("Docker MCP edge must attach only to edge-control")
    _require_loopback_port(edge, "Docker MCP edge", "CHIO_EDGE_PORT", 8931, 8931)
    _require_healthcheck(
        edge,
        "Docker MCP edge",
        ["CMD", "python3", "/opt/chio/examples/mcp_edge_healthcheck.py"],
    )

    _require_hardening(proof_room, "Docker proof-room", maximum_pids=128)
    if _service_networks(proof_room, "Docker proof-room") != {"proof-room"}:
        raise ContractError("Docker proof-room must attach only to proof-room")
    _require_loopback_port(
        proof_room,
        "Docker proof-room",
        "CHIO_PROOF_ROOM_PORT",
        7391,
        7391,
    )

    _depends_condition(
        trust,
        provision_name,
        "service_completed_successfully",
        "Docker trust-control",
    )
    _depends_condition(
        edge,
        provision_name,
        "service_completed_successfully",
        "Docker MCP edge",
    )
    _depends_condition(edge, TLS_SERVICE, "service_healthy", "Docker MCP edge")
    _depends_condition(
        tls_proxy,
        TLS_INIT_SERVICE,
        "service_completed_successfully",
        "Docker TLS proxy",
    )
    _depends_condition(tls_proxy, TRUST_SERVICE, "service_healthy", "Docker TLS proxy")

    edge_words = _command_words(edge, "Docker MCP edge")
    if any(flag in edge_words for flag in FORBIDDEN_EDGE_STORE_FLAGS):
        raise ContractError(
            "Docker MCP edge configures a conflicting local control store"
        )

    services = _mapping(compose.get("services"), "Docker Compose services")
    admin_token_consumers = {
        service_name
        for service_name, raw_service in services.items()
        if "CHIO_ADMIN_TOKEN"
        in _environment(
            _mapping(raw_service, f"Docker Compose service {service_name!r}"),
            f"Docker Compose service {service_name!r}",
        )
    }
    if admin_token_consumers != {EDGE_SERVICE}:
        raise ContractError(
            "Docker Compose must forward the dedicated admin token only to Chio"
        )
    allowed_mount_users = {
        PUBLIC_SECURITY_VOLUME: {"chio-security-init", EDGE_SERVICE},
        EDGE_STATE_VOLUME: {"chio-security-init", EDGE_SERVICE},
        TRUST_SECRET_VOLUME: {"chio-security-init", TRUST_SERVICE},
        TRUST_STATE_VOLUME: {TRUST_SERVICE},
        TLS_CA_VOLUME: {TLS_INIT_SERVICE},
        TLS_SERVER_VOLUME: {TLS_INIT_SERVICE, TLS_SERVICE},
        TLS_PUBLIC_VOLUME: {TLS_INIT_SERVICE, TLS_SERVICE, EDGE_SERVICE},
    }
    observed_mount_users = {source: set() for source in allowed_mount_users}
    for service_name, raw_service in services.items():
        service = _mapping(raw_service, f"Docker Compose service {service_name!r}")
        effective = _effective_service(
            service, f"Docker Compose service {service_name!r}"
        )
        if effective.get("volumes") is None:
            continue
        for mount in _volume_mounts(
            effective, f"Docker Compose service {service_name!r}"
        ):
            if mount.source in observed_mount_users:
                observed_mount_users[mount.source].add(service_name)
    for source, expected_users in allowed_mount_users.items():
        if observed_mount_users[source] != expected_users:
            raise ContractError(
                f"Docker volume {source!r} must be mounted only by {sorted(expected_users)!r}"
            )


def _dockerfile_stage(body: str, target: str) -> str:
    starts = list(
        re.finditer(rf"(?im)^\s*FROM\s+[^\n]+\s+AS\s+{re.escape(target)}\s*$", body)
    )
    if len(starts) != 1:
        raise ContractError(f"Dockerfile must define exactly one {target!r} stage")
    start = starts[0].start()
    following = re.search(r"(?im)^\s*FROM\s+", body[starts[0].end() :])
    end = starts[0].end() + following.start() if following else len(body)
    return body[start:end]


def _validate_dockerfile(root: Path) -> None:
    body = _read_text(root / DOCKERFILE_PATH, "Dockerfile")
    edge_stage = _dockerfile_stage(body, EDGE_BUILD_TARGET)
    for required in (
        "COPY examples/docker/mock_mcp_server.py ./examples/mock_mcp_server.py",
        "COPY examples/docker/policy.yaml ./examples/policy.yaml",
        "COPY examples/docker/tools.json ./examples/tools.json",
        "COPY examples/docker/mcp_demo_entrypoint.py ./examples/mcp_demo_entrypoint.py",
        "COPY examples/docker/mcp_edge_healthcheck.py ./examples/mcp_edge_healthcheck.py",
        "COPY examples/docker/mcp_demo_launcher.c ./examples/mcp_demo_launcher.c",
        "addgroup -S -g 10002 chio-mcp",
        "adduser -S -D -H -u 10002 -G chio-mcp -h /nonexistent -s /sbin/nologin chio-mcp",
        'python_digest="$(sha256sum "${python_path}" | cut -d \' \' -f 1)"',
        "script_digest=\"$(sha256sum /opt/chio/examples/mock_mcp_server.py | cut -d ' ' -f 1)\"",
        '-DCHIO_DEMO_PYTHON_SHA256="\\"${python_digest}\\""',
        '-DCHIO_DEMO_SCRIPT_SHA256="\\"${script_digest}\\""',
        "-o /usr/local/bin/chio-demo-mcp-launcher",
        "rm /opt/chio/examples/mcp_demo_launcher.c",
        "chown -R root:root /opt/chio /var/lib/chio",
        "chmod 0700 /var/lib/chio",
        "find /opt/chio -type d -exec chmod 0555 {} +",
        "find /opt/chio -type f -exec chmod 0444 {} +",
        "chmod 0555 /opt/chio/examples/mcp_demo_entrypoint.py",
        "/opt/chio/examples/mcp_edge_healthcheck.py",
        "/usr/local/bin/chio-demo-mcp-launcher",
    ):
        if required not in edge_stage:
            raise ContractError(f"Docker edge image is missing {required!r}")
    if not re.search(r"(?m)^USER root\s*$", edge_stage):
        raise ContractError("Docker edge image must start the edge process as root")
    executable_stage = re.sub(r"(?m)^\s*#.*$", "", edge_stage)
    entrypoint_matches = re.findall(
        r"(?im)^\s*ENTRYPOINT\s+\[[^\n]*mcp_demo_entrypoint\.py[^\n]*\]\s*$",
        executable_stage,
    )
    if len(entrypoint_matches) != 1:
        raise ContractError(
            "Docker edge image does not execute the checked security entrypoint"
        )
    if re.search(r"CHIO_CONTROL_URL[^\n]*:-\s*http://", edge_stage):
        raise ContractError(
            "Docker edge image contains an insecure HTTP control default"
        )
    if "http://chio-trust" in edge_stage:
        raise ContractError(
            "Docker edge image contains an insecure HTTP control endpoint"
        )
    if "--chown=chio" in edge_stage or "chown -R chio:chio /opt/chio" in edge_stage:
        raise ContractError("Docker edge reviewed assets must remain root-owned")

    trust_stage = _dockerfile_stage(body, TRUST_BUILD_TARGET)
    if "CHIO_AUTHORITY_SEED_FILE" not in trust_stage:
        raise ContractError(
            "Docker trust-control image ignores the trust-only provisioned authority seed"
        )
    if "--authority-seed-file" not in trust_stage or "--authority-db" in trust_stage:
        raise ContractError(
            "Docker trust-control image does not select the trust-only seed exactly"
        )

    tls_stage = _dockerfile_stage(body, TLS_BUILD_TARGET)
    for required in (
        "examples/docker/tls_demo_entrypoint.sh",
        "examples/docker/tls_reverse_proxy.py",
        "examples/docker/tls_healthcheck.py",
        "tls_demo_entrypoint.sh",
        "chown -R root:root /opt/chio",
        "chmod 0555 /opt/chio /opt/chio/tls_demo_entrypoint.sh",
        "chmod 0444 /opt/chio/tls_reverse_proxy.py /opt/chio/tls_healthcheck.py",
    ):
        if required not in tls_stage:
            raise ContractError(f"Docker TLS proxy stage is missing {required!r}")


def _validate_docker_write_targets(root: Path) -> None:
    compose = _load_compose(root / COMPOSE_PATH)
    provision = _service(compose, "chio-security-init")
    trust = _service(compose, TRUST_SERVICE)
    tls_init = _service(compose, TLS_INIT_SERVICE)
    edge = _service(compose, EDGE_SERVICE)
    proof_room = _service(compose, PROOF_ROOM_SERVICE)

    configured_targets = (
        (provision, PROVISION_OUTPUT, "Docker security provision output"),
        (provision, PUBLIC_SECURITY_TARGET, "Docker public security output"),
        (provision, RUNTIME_SECURITY_DIR, "Docker edge-private security output"),
        (provision, TRUST_SECRET_TARGET, "Docker trust-secret output"),
        (tls_init, TLS_CA_TARGET, "Docker TLS CA output"),
        (tls_init, TLS_PRIVATE_TARGET, "Docker TLS server-key output"),
        (tls_init, TLS_PUBLIC_TARGET, "Docker TLS public-CA output"),
        (
            tls_init,
            PurePosixPath("/run/chio-tls-provision"),
            "Docker TLS temporary provision output",
        ),
        (
            edge,
            RUNTIME_SECURITY_DIR / "mcp-sessions.sqlite3",
            "Docker MCP session database",
        ),
    )
    for service, target, label in configured_targets:
        _require_write_target_backed(service, target, label)

    dockerfile = _read_text(root / DOCKERFILE_PATH, "Dockerfile")
    trust_stage = _dockerfile_stage(dockerfile, TRUST_BUILD_TARGET)
    trust_command = _dockerfile_json_instruction(
        trust_stage, "CMD", "Docker trust-control image"
    )
    if trust_command[:2] != ["/bin/sh", "-ec"] or len(trust_command) != 3:
        raise ContractError(
            "Docker trust-control image CMD must use one fail-closed shell command"
        )
    try:
        trust_words = shlex.split(trust_command[2], posix=True)
    except ValueError as error:
        raise ContractError(
            f"Docker trust-control image CMD has invalid shell quoting: {error}"
        ) from error
    for flag, label in (
        ("--receipt-db", "Docker trust receipt database"),
        ("--revocation-db", "Docker trust revocation database"),
        ("--budget-db", "Docker trust budget database"),
    ):
        target = PurePosixPath(_flag_value(trust_words, flag, label))
        _require_write_target_backed(trust, target, label)

    proof_stage = _dockerfile_stage(dockerfile, PROOF_ROOM_BUILD_TARGET)
    proof_command = _dockerfile_json_instruction(
        proof_stage, "CMD", "Docker proof-room image"
    )
    image_doctor_report = PurePosixPath(
        _flag_value(proof_command, "--doctor-report", "Docker proof-room image")
    )
    if image_doctor_report != PROOF_ROOM_IMAGE_DOCTOR_REPORT:
        raise ContractError(
            "Docker proof-room image must preserve the canonical standalone doctor report path"
        )

    proof_override = _command_words(proof_room, "Docker proof-room")
    override_doctor_report = PurePosixPath(
        _flag_value(proof_override, "--doctor-report", "Docker proof-room override")
    )
    _require_write_target_backed(
        proof_room, override_doctor_report, "Docker proof-room doctor report"
    )
    expected_override = list(proof_command)
    image_report_index = expected_override.index(str(PROOF_ROOM_IMAGE_DOCTOR_REPORT))
    expected_override[image_report_index] = str(PROOF_ROOM_DOCTOR_REPORT)
    if proof_override != expected_override:
        raise ContractError(
            "Docker proof-room Compose command must exactly match the canonical image command except for its writable doctor report path"
        )


def _ast_calls(tree: ast.AST) -> list[str]:
    calls: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if isinstance(function, ast.Name):
            calls.append(function.id)
        elif isinstance(function, ast.Attribute):
            parts = [function.attr]
            value = function.value
            while isinstance(value, ast.Attribute):
                parts.append(value.attr)
                value = value.value
            if isinstance(value, ast.Name):
                parts.append(value.id)
            calls.append(".".join(reversed(parts)))
    return calls


def _ast_string_literals(tree: ast.AST) -> set[str]:
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def _is_token_distinction_guard(
    statement: ast.stmt, expected_names: set[str]
) -> bool:
    if not isinstance(statement, ast.If) or not isinstance(statement.test, ast.Compare):
        return False
    comparison = statement.test
    if (
        len(comparison.ops) != 1
        or not isinstance(comparison.ops[0], ast.NotEq)
        or len(comparison.comparators) != 1
        or not isinstance(comparison.comparators[0], ast.Constant)
        or comparison.comparators[0].value != len(expected_names)
        or not isinstance(comparison.left, ast.Call)
        or not isinstance(comparison.left.func, ast.Name)
        or comparison.left.func.id != "len"
        or len(comparison.left.args) != 1
        or comparison.left.keywords
        or not isinstance(comparison.left.args[0], ast.Set)
    ):
        return False
    elements = comparison.left.args[0].elts
    names = [element.id for element in elements if isinstance(element, ast.Name)]
    return (
        len(elements) == len(expected_names)
        and len(names) == len(expected_names)
        and set(names) == expected_names
        and any(isinstance(item, ast.Raise) for item in statement.body)
    )


def _function(tree: ast.Module, name: str, label: str) -> ast.FunctionDef:
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(matches) != 1:
        raise ContractError(f"{label} must define {name} exactly once")
    return matches[0]


def _named_calls(scope: ast.AST, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(scope)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == name
    ]


def _call_forwards_name(call: ast.Call, keyword: str, name: str) -> bool:
    matches = [item for item in call.keywords if item.arg == keyword]
    return (
        len(matches) == 1
        and isinstance(matches[0].value, ast.Name)
        and matches[0].value.id == name
    )


def _is_bearer_header(value: ast.expr, token_name: str) -> bool:
    if not isinstance(value, ast.Dict) or len(value.keys) != 1:
        return False
    key = value.keys[0]
    bearer = value.values[0]
    return (
        isinstance(key, ast.Constant)
        and key.value == "Authorization"
        and isinstance(bearer, ast.JoinedStr)
        and len(bearer.values) == 2
        and isinstance(bearer.values[0], ast.Constant)
        and bearer.values[0].value == "Bearer "
        and isinstance(bearer.values[1], ast.FormattedValue)
        and isinstance(bearer.values[1].value, ast.Name)
        and bearer.values[1].value.id == token_name
    )


def _validate_edge_entrypoint(root: Path) -> None:
    path = root / DOCKER_EDGE_ENTRYPOINT_PATH
    body = _read_text(path, "Docker MCP security entrypoint")
    try:
        tree = ast.parse(body, filename=str(path))
    except SyntaxError as error:
        raise ContractError(
            f"Docker MCP security entrypoint is invalid: {error}"
        ) from error
    literals = _ast_string_literals(tree)
    calls = _ast_calls(tree)
    if "demo-token" in body or re.search(
        r"CHIO_(?:AUTH|ADMIN|SERVICE|EDGE|CONTROL|DASHBOARD_READ)_TOKEN[^\n]{0,80}:-",
        body,
    ):
        raise ContractError(
            "Docker MCP edge entrypoint must not contain credential defaults"
        )

    public_artifact_labels = {
        label: artifact
        for label, artifact in SECURITY_ARTIFACTS.items()
        if label != "local authority seed"
    }
    for label, artifact in public_artifact_labels.items():
        if artifact not in literals:
            raise ContractError(
                f"Docker MCP edge does not require the {label} artifact"
            )
    for label, flag in EDGE_REQUIRED_FLAGS.items():
        if flag not in literals:
            raise ContractError(f"Docker MCP edge does not supply {label} ({flag})")
    if not any(call in calls for call in ("json.loads", "json.load")):
        raise ContractError(
            "Docker MCP edge does not parse canonical target-command JSON"
        )
    if not any(call in calls for call in ("os.execv", "os.execve")):
        raise ContractError(
            "Docker MCP edge does not directly exec the canonical target command"
        )
    forbidden_calls = {
        "eval",
        "exec",
        "os.system",
        "os.popen",
        "shlex.split",
        "subprocess.call",
        "subprocess.Popen",
        "subprocess.run",
    }
    observed_forbidden = sorted(forbidden_calls.intersection(calls))
    if observed_forbidden:
        raise ContractError(
            "Docker MCP edge target command uses a shell/eval surface: "
            f"{observed_forbidden!r}"
        )
    for flag in FORBIDDEN_EDGE_STORE_FLAGS:
        if flag in literals or flag in body:
            raise ContractError(
                f"Docker MCP edge configures conflicting local store flag {flag}"
            )
    if "http://" in body:
        raise ContractError(
            "Docker MCP edge entrypoint contains an insecure HTTP default"
        )
    if "CHIO_CONTROL_TLS_ROOT_CA_FILE" not in literals:
        raise ContractError(
            "Docker MCP edge does not require the configured private CA root"
        )
    required_fragments = (
        'os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)',
        "stat.S_ISREG(metadata.st_mode)",
        "if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != expected_mode:",
        "stat.S_IMODE(metadata.st_mode) != expected_mode",
        "public_security_directory, 0o555",
        "private_security_directory, 0o700",
        "directory.lstat()",
        "directory.is_symlink()",
        'os.environ.get("CHIO_PUBLIC_SECURITY_DIR", "/run/chio-public")',
        'os.environ.get("CHIO_PRIVATE_SECURITY_DIR", "/var/lib/chio/security")',
        'authority_seed = private_security_directory / "control-authority.seed"',
        'session_database = private_security_directory / "mcp-sessions.sqlite3"',
        'executable = "/usr/local/bin/chio"',
        'auth_token = os.environ.get("CHIO_AUTH_TOKEN", "")',
        'admin_token = os.environ.get("CHIO_ADMIN_TOKEN", "")',
        'control_token = os.environ.get("CHIO_CONTROL_TOKEN", "")',
        '("CHIO_ADMIN_TOKEN", admin_token)',
        "BEARER_TOKEN.fullmatch(value)",
        '"CHIO_AUTH_TOKEN": auth_token',
        '"CHIO_ADMIN_TOKEN": admin_token',
        '"CHIO_CONTROL_TOKEN": control_token',
        "os.execve(executable, arguments, environment)",
    )
    for fragment in required_fragments:
        if fragment not in body:
            raise ContractError(
                f"Docker MCP edge entrypoint is missing security contract {fragment!r}"
            )
    if "os.environ.copy()" in body:
        raise ContractError(
            "Docker MCP edge entrypoint must use a sanitized exec environment"
        )
    if "manifest-signer.seed" in body or "cage-policy-signer.seed" in body:
        raise ContractError(
            "Docker MCP edge entrypoint consumes a provisioning-only seed"
        )
    main_function = _function(tree, "main", "Docker MCP edge entrypoint")
    distinct_token_guards = [
        statement
        for statement in main_function.body
        if _is_token_distinction_guard(
            statement, {"auth_token", "admin_token", "control_token"}
        )
    ]
    exec_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.func.attr == "execve"
    ]
    if (
        len(distinct_token_guards) != 1
        or len(exec_calls) != 1
        or distinct_token_guards[0].lineno >= exec_calls[0].lineno
        or not any(
            isinstance(statement, ast.Raise)
            for statement in distinct_token_guards[0].body
        )
    ):
        raise ContractError(
            "Docker MCP edge must enforce pairwise-distinct auth, admin, and control tokens before exec"
        )
    environment_assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "environment"
            for target in node.targets
        )
    ]
    if len(environment_assignments) != 1 or not isinstance(
        environment_assignments[0].value, ast.Dict
    ):
        raise ContractError("Docker MCP edge must construct one fixed exec environment")
    environment_dict = environment_assignments[0].value
    environment_entries: dict[str, ast.expr] = {}
    for key, value in zip(environment_dict.keys, environment_dict.values, strict=True):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            raise ContractError(
                "Docker MCP edge exec environment keys must be literals"
            )
        if key.value in environment_entries:
            raise ContractError("Docker MCP edge exec environment has a duplicate key")
        environment_entries[key.value] = value
    expected_environment_keys = {
        "CHIO_AUTH_TOKEN",
        "CHIO_ADMIN_TOKEN",
        "CHIO_CONTROL_TOKEN",
        "CHIO_CONTROL_TLS_ROOT_CA_FILE",
        "HOME",
        "LANG",
        "PATH",
        "RUST_LOG",
    }
    if set(environment_entries) != expected_environment_keys:
        raise ContractError(
            "Docker MCP edge exec environment must be exact and forward the private CA path"
        )
    ca_value = environment_entries["CHIO_CONTROL_TLS_ROOT_CA_FILE"]
    if not (
        isinstance(ca_value, ast.Call)
        and isinstance(ca_value.func, ast.Name)
        and ca_value.func.id == "str"
        and len(ca_value.args) == 1
        and isinstance(ca_value.args[0], ast.Name)
        and ca_value.args[0].id == "control_ca"
        and not ca_value.keywords
    ):
        raise ContractError(
            "Docker MCP edge must forward the validated private CA path exactly"
        )
    for key, variable in (
        ("CHIO_AUTH_TOKEN", "auth_token"),
        ("CHIO_ADMIN_TOKEN", "admin_token"),
        ("CHIO_CONTROL_TOKEN", "control_token"),
    ):
        value = environment_entries[key]
        if not isinstance(value, ast.Name) or value.id != variable:
            raise ContractError(f"Docker MCP edge must forward validated {key} exactly")


def _validate_tls_runtime(root: Path) -> None:
    entrypoint = _read_text(root / DOCKER_TLS_ENTRYPOINT_PATH, "Docker TLS entrypoint")
    proxy_path = root / DOCKER_TLS_PROXY_PATH
    proxy = _read_text(proxy_path, "Docker TLS proxy")
    if not entrypoint.startswith("#!/bin/sh\nset -eu\n"):
        raise ContractError("Docker TLS entrypoint must enable fail-closed shell mode")
    for required in (
        str(TLS_CA_TARGET),
        str(TLS_PRIVATE_TARGET),
        str(TLS_PUBLIC_TARGET),
        TLS_ROOT_CA_NAME,
        "demo-ca-key.pem",
        "demo-server-key.pem",
        f"DNS:{TLS_SERVICE}",
        "DNS:localhost",
        "IP Address:127.0.0.1",
        'first_entry="$(find "$1" -mindepth 1 -maxdepth 1 -print -quit)" || return 1',
        '[ -z "${first_entry}" ] || return 1',
        '[ -d "${path}" ] || return 1',
        '[ ! -L "${path}" ] || return 1',
        '[ -f "${path}" ] || return 1',
        'stat -c \'%u:%g:%a\' "${path}")" = "${owner}:${mode_bits}" ] || return 1',
        '[ -d "${directory}" ] || exit 1',
        '[ ! -L "${directory}" ] || exit 1',
        'require_directory "${ca_dir}" 0:0 700',
        'require_directory "${server_dir}" 0:0 700',
        'require_directory "${server_dir}" 10001:10001 700',
        'require_directory "${public_dir}" 0:0 755',
        'require_file "${ca_key}" 0:0 400',
        'require_file "${server_key}" "${key_owner}" 400',
        'require_file "${server_cert}" 0:0 444',
        'require_file "${ca_cert}" 0:0 444',
        'if [ -e "${ca_key}" ] || [ -L "${ca_key}" ]; then',
        "verify_certificate_set 0:0",
        "verify_certificate_set 10001:10001",
        'chown 10001:10001 "${server_key}" "${server_dir}"',
        "openssl verify -CAfile",
        "openssl x509 -checkend 86400",
        "exec python3 /opt/chio/tls_reverse_proxy.py",
    ):
        if required not in entrypoint:
            raise ContractError(f"Docker TLS entrypoint is missing {required!r}")
    mode_check = '[ "$(stat -c \'%u:%g:%a\' "${path}")" = "${owner}:${mode_bits}" ]'
    if entrypoint.count(mode_check) != 2:
        raise ContractError(
            "Docker TLS entrypoint must check directory and file ownership-mode exactly"
        )
    symlink_guard = '[ ! -L "${path}" ] || return 1'
    if entrypoint.count(symlink_guard) != 2:
        raise ContractError(
            "Docker TLS entrypoint must reject symlinked files and directories"
        )
    guarded_certificate_steps = (
        'require_file "${ca_cert}" 0:0 444 || return 1',
        'require_file "${server_cert}" 0:0 444 || return 1',
        'require_file "${server_key}" "${key_owner}" 400 || return 1',
        'openssl verify -CAfile "${ca_cert}" "${server_cert}" >/dev/null 2>&1 || return 1',
        'openssl x509 -checkend 86400 -noout -in "${ca_cert}" >/dev/null 2>&1 || return 1',
        'openssl x509 -checkend 86400 -noout -in "${server_cert}" >/dev/null 2>&1 || return 1',
        '"$(openssl rsa -noout -modulus -in "${server_key}" 2>/dev/null)" ] || return 1',
        'san="$(openssl x509 -noout -ext subjectAltName -in "${server_cert}")" || return 1',
        "grep -F 'DNS:chio-trust-tls' >/dev/null || return 1",
        "grep -F 'DNS:localhost' >/dev/null || return 1",
        "grep -F 'IP Address:127.0.0.1' >/dev/null || return 1",
        "grep -F 'IP Address:0:0:0:0:0:0:0:1' >/dev/null || return 1",
    )
    for step in guarded_certificate_steps:
        if step not in entrypoint:
            raise ContractError(
                f"Docker TLS certificate validation must fail closed at {step!r}"
            )
    if "CHIO_TLS_MODE:-serve" not in entrypoint:
        raise ContractError(
            "Docker TLS entrypoint must fail closed between provision and serve"
        )
    if re.search(
        r"cp\s+[^\n]*ca-key[^\n]*(chio-tls-private|chio-tls-public)", entrypoint
    ):
        raise ContractError(
            "Docker TLS CA signing key escapes its provision-only volume"
        )
    try:
        proxy_tree = ast.parse(proxy, filename=str(proxy_path))
    except SyntaxError as error:
        raise ContractError(f"Docker TLS proxy is invalid: {error}") from error
    proxy_calls = _ast_calls(proxy_tree)
    proxy_literals = _ast_string_literals(proxy_tree)
    for required_call in ("ssl.SSLContext", "context.load_cert_chain"):
        if required_call not in proxy_calls:
            raise ContractError(f"Docker TLS proxy does not enforce {required_call}")
    if not ({"TLSv1_2", "TLSv1_3"} & proxy_literals) and "TLSv1_2" not in proxy:
        raise ContractError("Docker TLS proxy does not set a minimum TLS version")
    required_proxy_fragments = (
        'self.headers.get_all("Transfer-Encoding")',
        'self.headers.get_all("Content-Length")',
        "if len(set(values)) != 1:",
        '"transfer-encoding"',
        '"content-length"',
        'headers["Accept-Encoding"] = "identity"',
        "MAX_REQUEST_BYTES",
        "MAX_RESPONSE_BYTES",
        "MAX_CONCURRENT_REQUESTS",
        "TLS_HANDSHAKE_TIMEOUT_SECONDS",
        "HEADER_TIMEOUT_SECONDS",
        "BODY_TIMEOUT_SECONDS",
        "UPSTREAM_TIMEOUT_SECONDS",
        "CLIENT_WRITE_TIMEOUT_SECONDS",
        "DeadlineReader",
        "SocketShutdownDeadline",
        "threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)",
        "class ResolvedHTTPConnection(http.client.HTTPConnection):",
        "socket.getaddrinfo(",
        "endpoint=self.server.upstream_endpoint",
        "perform_tls_handshake(tls_request, TLS_HANDSHAKE_TIMEOUT_SECONDS)",
        'self.path.startswith("//")',
    )
    for fragment in required_proxy_fragments:
        if fragment not in proxy:
            raise ContractError(f"Docker TLS proxy is missing {fragment!r}")
    if "urllib.request" in proxy or "requests." in proxy:
        raise ContractError(
            "Docker TLS proxy must not use a redirect-following HTTP client"
        )


def _validate_launcher(root: Path) -> None:
    body = _read_text(root / DOCKER_LAUNCHER_PATH, "Docker MCP target launcher")
    required = (
        "#define CHIO_DEMO_UID ((uid_t)10002)",
        "#define CHIO_DEMO_GID ((gid_t)10002)",
        '#define CHIO_DEMO_SCRIPT_PATH "/opt/chio/examples/mock_mcp_server.py"',
        "O_RDONLY | O_CLOEXEC | O_NOFOLLOW",
        "S_ISREG(metadata.st_mode)",
        "metadata.st_uid != 0",
        "S_IWGRP | S_IWOTH",
        "EVP_sha256()",
        "strcmp(encoded, expected_digest) != 0",
        "open_verified_regular(CHIO_DEMO_PYTHON_PATH, CHIO_DEMO_PYTHON_SHA256)",
        "open_verified_regular(CHIO_DEMO_SCRIPT_PATH, CHIO_DEMO_SCRIPT_SHA256)",
        "has_exact_empty_group_identity(0, 0)",
        "has_exact_empty_group_identity(CHIO_DEMO_UID, CHIO_DEMO_GID)",
        "int starts_as_target =\n        has_exact_empty_group_identity(CHIO_DEMO_UID, CHIO_DEMO_GID);",
        "starts_as_root == starts_as_target",
        "getresuid(&real_uid, &effective_uid, &saved_uid)",
        "getresgid(&real_gid, &effective_gid, &saved_gid)",
        "getgroups(0, NULL) != 0",
        "saved_uid == expected_uid",
        "saved_gid == expected_gid",
        "clearenv()",
        "if (starts_as_root",
        "setgroups(0, NULL)",
        "setresgid(CHIO_DEMO_GID, CHIO_DEMO_GID, CHIO_DEMO_GID)",
        "setresuid(CHIO_DEMO_UID, CHIO_DEMO_UID, CHIO_DEMO_UID)",
        "prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)",
        '"PYTHONDONTWRITEBYTECODE=1"',
        "fexecve(python_descriptor, child_argv, child_environment)",
    )
    for fragment in required:
        if fragment not in body:
            raise ContractError(f"Docker MCP target launcher is missing {fragment!r}")
    dumpable_reset = "prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)"
    reset_positions = [
        match.start() for match in re.finditer(re.escape(dumpable_reset), body)
    ]
    setresuid_position = body.find(
        "setresuid(CHIO_DEMO_UID, CHIO_DEMO_UID, CHIO_DEMO_UID)"
    )
    dumpable_verify = "prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0"
    verify_position = body.find(dumpable_verify)
    exec_position = body.find(
        "fexecve(python_descriptor, child_argv, child_environment)"
    )
    if (
        len(reset_positions) != 2
        or setresuid_position < 0
        or reset_positions[0] >= setresuid_position
        or reset_positions[1] <= setresuid_position
    ):
        raise ContractError(
            "Docker MCP target launcher must reset dumpability after its optional root credential transition"
        )
    if (
        verify_position <= reset_positions[1]
        or exec_position <= verify_position
        or body.count(dumpable_verify) != 1
    ):
        raise ContractError(
            "Docker MCP target launcher must verify nondumpable state within the launcher interval before exec"
        )
    child_environment_match = re.search(
        r"char\s+\*const\s+child_environment\[\]\s*=\s*\{(?P<body>.*?)\};",
        body,
        re.DOTALL,
    )
    if child_environment_match is None:
        raise ContractError("Docker MCP target launcher has no fixed child environment")
    child_environment = child_environment_match.group("body")
    for secret_name in (
        "CHIO_ADMIN_TOKEN",
        "CHIO_CONTROL_TOKEN",
        "CHIO_AUTH_TOKEN",
    ):
        if secret_name in child_environment:
            raise ContractError(
                f"Docker MCP target launcher leaks {secret_name} into the tool child"
            )
    if "getenv(" in body or "extern char **environ" in body:
        raise ContractError("Docker MCP target launcher inherits ambient environment")
    for forbidden in (
        "getrlimit(",
        "RLIMIT_NOFILE",
        "rlim_t",
        "65536",
        "for (int descriptor = 3;",
    ):
        if forbidden in body:
            raise ContractError(
                f"Docker MCP target launcher retains capped descriptor scrub surface {forbidden!r}"
            )
    for required_include in (
        "#include <dirent.h>",
        "#include <limits.h>",
        "#include <sys/syscall.h>",
    ):
        if required_include not in body:
            raise ContractError(
                f"Docker MCP target launcher is missing {required_include!r}"
            )

    range_helper = re.search(
        r"(?ms)^static int close_descriptor_range\(unsigned int first, unsigned int last\) \{\n"
        r"(?P<body>.*?)^\}",
        body,
    )
    if range_helper is None:
        raise ContractError(
            "Docker MCP target launcher must define the fail-closed close_range helper"
        )
    normalized_range_helper = " ".join(range_helper.group("body").split())
    expected_range_helper = (
        "if (first > last || syscall(SYS_close_range, first, last, 0) == 0) { "
        "return 0; } if (errno == ENOSYS || errno == EPERM) { return 1; } "
        'fail("cannot close inherited descriptors"); return 1;'
    )
    if normalized_range_helper != expected_range_helper:
        raise ContractError(
            "Docker MCP target launcher close_range helper must fall back only for ENOSYS or EPERM and fail closed otherwise"
        )

    procfs_helper = re.search(
        r"(?ms)^static void close_unneeded_from_procfs\(\n"
        r"    int python_descriptor,\n"
        r"    int script_descriptor\n"
        r"\) \{\n(?P<body>.*?)^\}",
        body,
    )
    if procfs_helper is None:
        raise ContractError(
            "Docker MCP target launcher must define the complete procfs descriptor fallback"
        )
    normalized_procfs_helper = " ".join(procfs_helper.group("body").split())
    expected_procfs_helper = (
        'DIR *directory = opendir("/proc/self/fd"); if (directory == NULL) { '
        'fail("cannot close inherited descriptors"); } int directory_descriptor = '
        "dirfd(directory); if (directory_descriptor < 0) { "
        'fail("cannot inspect inherited descriptors"); } for (;;) { errno = 0; '
        "struct dirent *entry = readdir(directory); if (entry == NULL) { if (errno "
        '!= 0) { fail("cannot inspect inherited descriptors"); } break; } if '
        "(entry->d_name[0] < '0' || entry->d_name[0] > '9') { continue; } char "
        "*end = NULL; errno = 0; unsigned long value = strtoul(entry->d_name, "
        "&end, 10); if (errno != 0 || end == entry->d_name || *end != '\\0' || "
        'value > INT_MAX) { fail("inherited descriptor entry is invalid"); } '
        "int descriptor = (int)value; if (descriptor < 3 || descriptor == "
        "python_descriptor || descriptor == script_descriptor || descriptor == "
        "directory_descriptor) { continue; } if (close(descriptor) != 0) { "
        'fail("cannot close inherited descriptor"); } } if (closedir(directory) != '
        '0) { fail("cannot close descriptor directory"); }'
    )
    if normalized_procfs_helper != expected_procfs_helper:
        raise ContractError(
            "Docker MCP target launcher procfs fallback must completely enumerate, preserve required descriptors, parse exactly, and fail closed"
        )

    scrub_helper = re.search(
        r"(?ms)^static void close_unneeded_descriptors\(int python_descriptor, int script_descriptor\) \{\n"
        r"(?P<body>.*?)^\}",
        body,
    )
    if scrub_helper is None:
        raise ContractError(
            "Docker MCP target launcher must define complete inherited descriptor scrubbing"
        )
    normalized_scrub_helper = " ".join(scrub_helper.group("body").split())
    expected_scrub_helper = (
        "if (python_descriptor < 3 || script_descriptor < 3 || python_descriptor == "
        'script_descriptor) { fail("verified target descriptors are invalid"); } '
        "unsigned int first = (unsigned int)python_descriptor; unsigned int second = "
        "(unsigned int)script_descriptor; if (first > second) { unsigned int swap = "
        "first; first = second; second = swap; } if (close_descriptor_range(3, "
        "first - 1) || close_descriptor_range(first + 1, second - 1) || "
        "close_descriptor_range(second + 1, UINT_MAX)) { "
        "close_unneeded_from_procfs(python_descriptor, script_descriptor); }"
    )
    if normalized_scrub_helper != expected_scrub_helper:
        raise ContractError(
            "Docker MCP target launcher must preserve only two validated descriptors across complete close_range intervals"
        )
    invocation = "close_unneeded_descriptors(python_descriptor, script_descriptor);"
    if body.count(invocation) != 1:
        raise ContractError(
            "Docker MCP target launcher must scrub inherited descriptors exactly once"
        )


def _validate_edge_healthcheck(root: Path) -> None:
    path = root / DOCKER_EDGE_HEALTHCHECK_PATH
    body = _read_text(path, "Docker MCP edge healthcheck")
    try:
        tree = ast.parse(body, filename=str(path))
    except SyntaxError as error:
        raise ContractError(f"Docker MCP edge healthcheck is invalid: {error}") from error
    calls = _ast_calls(tree)
    required = (
        'HEALTH_URL = "http://127.0.0.1:8931/admin/health"',
        "REQUEST_TIMEOUT_SECONDS = 3",
        "MAX_HEALTH_BODY_BYTES = 64 * 1024\n",
        'token = os.environ.get("CHIO_ADMIN_TOKEN", "")',
        "BEARER_TOKEN.fullmatch(token)",
        'headers={"Authorization": f"Bearer {admin_token}"}',
        "urllib.request.ProxyHandler({})",
        "NoRedirect()",
        "REQUEST_TIMEOUT_SECONDS",
        "MAX_HEALTH_BODY_BYTES",
        "response.geturl() != HEALTH_URL",
        "response.status != 200",
        'payload.get("ok") is not True',
        'server.get("serverId") != "docker-demo"',
        'auth.get("adminTokenConfigured") is not True',
        'control.get("proxied") is not True',
        'control.get("controlTokenConfigured") is not True',
    )
    for fragment in required:
        if fragment not in body:
            raise ContractError(
                f"Docker MCP edge healthcheck is missing {fragment!r}"
            )
    if "urllib.request.build_opener" not in calls:
        raise ContractError("Docker MCP edge healthcheck does not isolate its HTTP client")


def _validate_healthcheck(root: Path) -> None:
    path = root / DOCKER_TLS_HEALTHCHECK_PATH
    body = _read_text(path, "Docker TLS healthcheck")
    try:
        tree = ast.parse(body, filename=str(path))
    except SyntaxError as error:
        raise ContractError(f"Docker TLS healthcheck is invalid: {error}") from error
    literals = _ast_string_literals(tree)
    calls = _ast_calls(tree)
    required_literals = {
        "https://localhost:8940/health",
        "/var/lib/chio-tls-public/demo-ca.pem",
        "https",
        "/health",
    }
    if not required_literals <= literals:
        raise ContractError("Docker TLS healthcheck does not pin exact HTTPS inputs")
    for required in (
        "os.O_NOFOLLOW",
        "stat.S_ISREG(metadata.st_mode)",
        "MAX_CA_BYTES",
        "ssl.TLSVersion.TLSv1_2",
        "NoRedirect()",
        "urllib.request.ProxyHandler({})",
        "response.geturl() != expected_url",
        "response.status != 200",
        "MAX_HEALTH_BODY_BYTES",
    ):
        if required not in body:
            raise ContractError(f"Docker TLS healthcheck is missing {required!r}")
    if "context.load_verify_locations" not in calls:
        raise ContractError("Docker TLS healthcheck does not load the private CA")


def _validate_smoke_client(root: Path) -> None:
    path = root / DOCKER_SMOKE_CLIENT_PATH
    body = _read_text(path, "Docker smoke client")
    try:
        tree = ast.parse(body, filename=str(path))
    except SyntaxError as error:
        raise ContractError(f"Docker smoke client is invalid: {error}") from error
    if "demo-token" in body or re.search(
        r"CHIO_(?:AUTH|ADMIN|SERVICE|EDGE|CONTROL|DASHBOARD_READ)_TOKEN[^\n]{0,80}:-",
        body,
    ):
        raise ContractError("Docker smoke client must not contain credential defaults")
    calls = _ast_calls(tree)
    required = (
        'BASE_URL = os.environ.get("CHIO_BASE_URL", "http://127.0.0.1:8931")',
        'CONTROL_URL = os.environ.get("CHIO_CONTROL_URL", "https://127.0.0.1:8940")',
        "ipaddress.ip_address(parsed.hostname)",
        "address.is_loopback",
        "if not allow_loopback_http:",
        "BEARER_TOKEN.fullmatch(token)",
        'value = os.environ.get(name, "")',
        "BEARER_TOKEN.fullmatch(value)",
        'EDGE_TOKEN = require_token("CHIO_EDGE_TOKEN")',
        'ADMIN_TOKEN = require_token("CHIO_ADMIN_TOKEN")',
        'DASHBOARD_READ_TOKEN = require_token("CHIO_DASHBOARD_READ_TOKEN")',
        'SERVICE_TOKEN = require_token("CHIO_SERVICE_TOKEN")',
        'admin_token = validate_token(ADMIN_TOKEN, name="admin")',
        'DASHBOARD_READ_TOKEN, name="dashboard read"',
        'EXPECTED_TOOL_SERVER = "docker-demo"',
        'EXPECTED_TOOL_NAME = "echo_text"',
        'EXPECTED_ECHO_MESSAGE = "hello from docker"',
        "EDGE_READY_TIMEOUT_SECONDS = 60.0",
        "deadline = time.monotonic() + EDGE_READY_TIMEOUT_SECONDS",
        "time.sleep(min(EDGE_READY_RETRY_SECONDS, remaining))",
        'url = f"{edge_origin}/admin/health"',
        "NoRedirect()",
        "urllib.request.ProxyHandler({})",
        "os.O_NOFOLLOW",
        "stat.S_ISREG(metadata.st_mode)",
        "MAX_CA_BYTES",
        "context.load_verify_locations(cadata=ca_pem)",
        "urllib.request.HTTPCookieProcessor(cookie_jar)",
        'DASHBOARD_SESSION_PATH = "/v1/dashboard/session"',
        'data=json.dumps(\n            {"token": dashboard_read_token}, separators=(",", ":")',
        'method="POST"',
        'response.status != 200',
        'response.headers.get_all("Set-Cookie", [])',
        'DASHBOARD_SESSION_COOKIE_PATTERN.fullmatch(set_cookies[0])',
        'response.headers.get("Cache-Control") != "no-store"',
        'method="DELETE"',
        'response.status != 204',
        'response.headers.get_all("Set-Cookie", []) != [\n                DASHBOARD_SESSION_CLEAR_COOKIE\n            ]',
        'headers={"Cookie": stale_cookie}',
        "exc.code != 401",
        "final_origin != expected_origin or final_url != expected_url",
        '"Authorization": f"Bearer {edge_token}"',
        'headers={"Authorization": f"Bearer {admin_token}"}',
        'result != {"tools": [EXPECTED_TOOL], "nextCursor": None}',
        "result != EXPECTED_TOOL_RESULT",
        'receipt.get("capability_id") != capability_id',
        'receipt.get("tool_server") != EXPECTED_TOOL_SERVER',
        'receipt.get("tool_name") != EXPECTED_TOOL_NAME',
        'decision.get("verdict") != "allow"',
        '"toolServer": EXPECTED_TOOL_SERVER',
        '"toolName": EXPECTED_TOOL_NAME',
        "len(receipts) != 1",
        "REQUEST_TIMEOUT_SECONDS",
    )
    for fragment in required:
        if fragment not in body:
            raise ContractError(f"Docker smoke client is missing {fragment!r}")
    if "urllib.request.build_opener" not in calls:
        raise ContractError("Docker smoke client does not build isolated URL openers")
    distinct_token_guards = [
        statement
        for statement in tree.body
        if _is_token_distinction_guard(
            statement,
            {"EDGE_TOKEN", "ADMIN_TOKEN", "DASHBOARD_READ_TOKEN", "SERVICE_TOKEN"},
        )
    ]
    if len(distinct_token_guards) != 1:
        raise ContractError(
            "Docker smoke client must enforce pairwise-distinct edge, admin, dashboard read, and service tokens"
        )

    session_function = _function(tree, "session_capability_id", "Docker smoke client")
    dashboard_create_function = _function(
        tree, "create_dashboard_session", "Docker smoke client"
    )
    dashboard_delete_function = _function(
        tree, "delete_dashboard_session", "Docker smoke client"
    )
    receipt_function = _function(tree, "query_receipts", "Docker smoke client")
    readiness_function = _function(tree, "probe_edge_health", "Docker smoke client")
    run_smoke_function = _function(tree, "run_smoke", "Docker smoke client")
    main_function = _function(tree, "main", "Docker smoke client")
    admin_path_literals = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "/admin/" in node.value
    ]
    admin_requests = [
        call
        for call in _named_calls(session_function, "request_json")
        if call.args
        and any(
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and "/admin/" in node.value
            for node in ast.walk(call.args[0])
        )
    ]
    if len(admin_path_literals) != 2 or len(admin_requests) != 1:
        raise ContractError(
            "Docker smoke client must issue exactly the reviewed readiness and session admin requests"
        )
    header_values = [
        keyword.value
        for keyword in admin_requests[0].keywords
        if keyword.arg == "headers"
    ]
    session_calls = _named_calls(run_smoke_function, "session_capability_id")
    readiness_calls = _named_calls(main_function, "wait_for_edge_ready")
    run_calls = _named_calls(main_function, "run_smoke")
    receipt_calls = _named_calls(run_smoke_function, "query_receipts")
    dashboard_create_calls = _named_calls(run_smoke_function, "create_dashboard_session")
    dashboard_delete_calls = _named_calls(run_smoke_function, "delete_dashboard_session")
    if (
        len(header_values) != 1
        or not _is_bearer_header(header_values[0], "admin_token")
        or len(session_calls) != 1
        or not _call_forwards_name(session_calls[0], "admin_token", "admin_token")
        or len(readiness_calls) != 1
        or not _call_forwards_name(readiness_calls[0], "admin_token", "admin_token")
        or len(run_calls) != 1
        or not _call_forwards_name(run_calls[0], "admin_token", "admin_token")
    ):
        raise ContractError(
            "Docker smoke client must route only the validated admin token to /admin/"
        )
    receipt_requests = _named_calls(receipt_function, "request_json")
    if (
        len(receipt_requests) != 1
        or any(item.arg == "headers" for item in receipt_requests[0].keywords)
        or len(receipt_calls) != 1
        or any(
            isinstance(node, ast.Constant) and node.value == "Authorization"
            for node in ast.walk(receipt_function)
        )
        or len(dashboard_create_calls) != 1
        or not _call_forwards_name(
            dashboard_create_calls[0], "dashboard_read_token", "dashboard_read_token"
        )
        or not _call_forwards_name(
            dashboard_create_calls[0], "cookie_jar", "control_cookie_jar"
        )
        or len(dashboard_delete_calls) != 1
        or not _call_forwards_name(
            dashboard_delete_calls[0], "cookie_jar", "control_cookie_jar"
        )
        or len(run_calls) != 1
        or not _call_forwards_name(
            run_calls[0], "dashboard_read_token", "dashboard_read_token"
        )
        or not _call_forwards_name(
            run_calls[0], "control_cookie_jar", "control_cookie_jar"
        )
    ):
        raise ContractError(
            "Docker smoke client must exchange the dashboard credential once and use only its session cookie for receipt reads"
        )
    create_status_calls = _named_calls(dashboard_create_function, "request_json")
    if (
        len(create_status_calls) != 1
        or any(
            item.arg == "headers" for item in create_status_calls[0].keywords
        )
        or any(
            isinstance(node, ast.Constant) and node.value == "Authorization"
            for node in ast.walk(dashboard_create_function)
        )
        or any(
            isinstance(node, ast.Constant) and node.value == "Authorization"
            for node in ast.walk(dashboard_delete_function)
        )
    ):
        raise ContractError(
            "Docker smoke dashboard session lifecycle must never send the dashboard credential as a bearer"
        )
    readiness_requests = [
        node
        for node in ast.walk(readiness_function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "Request"
    ]
    readiness_headers = (
        [item.value for item in readiness_requests[0].keywords if item.arg == "headers"]
        if len(readiness_requests) == 1
        else []
    )
    if (
        len(readiness_requests) != 1
        or len(readiness_headers) != 1
        or not _is_bearer_header(readiness_headers[0], "admin_token")
    ):
        raise ContractError(
            "Docker smoke client must issue exactly one bounded admin-authenticated readiness probe"
        )
    expected_validators = (
        "validate_initialize_response",
        "validate_tools_response",
        "validate_tool_call_response",
    )
    for validator in expected_validators:
        if len(_named_calls(run_smoke_function, validator)) != 1:
            raise ContractError(
                f"Docker smoke client must apply {validator} exactly once"
            )


def _validate_docker_credential_docs(root: Path) -> None:
    required_fragments = (
        'export CHIO_AUTH_TOKEN="$(openssl rand -hex 32)"',
        'export CHIO_ADMIN_TOKEN="$(openssl rand -hex 32)"',
        'export CHIO_SERVICE_TOKEN="$(openssl rand -hex 32)"',
        'export CHIO_DASHBOARD_READ_TOKEN="$(openssl rand -hex 32)"',
        'test "${CHIO_AUTH_TOKEN}" != "${CHIO_ADMIN_TOKEN}"',
        'test "${CHIO_AUTH_TOKEN}" != "${CHIO_SERVICE_TOKEN}"',
        'test "${CHIO_ADMIN_TOKEN}" != "${CHIO_SERVICE_TOKEN}"',
        'test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_AUTH_TOKEN}"',
        'test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_ADMIN_TOKEN}"',
        'test "${CHIO_DASHBOARD_READ_TOKEN}" != "${CHIO_SERVICE_TOKEN}"',
        'CHIO_EDGE_TOKEN="${CHIO_AUTH_TOKEN}"',
        'CHIO_ADMIN_TOKEN="${CHIO_ADMIN_TOKEN}"',
        'CHIO_DASHBOARD_READ_TOKEN="${CHIO_DASHBOARD_READ_TOKEN}"',
    )
    for relative, label in (
        (DOCKER_README_PATH, "Docker quickstart README"),
        (PROGRESSIVE_TUTORIAL_PATH, "progressive tutorial"),
    ):
        body = _read_text(root / relative, label)
        if "demo-token" in body:
            raise ContractError(f"{label} must not contain a demo credential literal")
        if re.search(
            r"CHIO_(?:AUTH|ADMIN|SERVICE|EDGE|CONTROL|DASHBOARD_READ)_TOKEN[^\n]{0,80}:-",
            body,
        ):
            raise ContractError(f"{label} must not contain credential fallbacks")
        for fragment in required_fragments:
            if fragment not in body:
                raise ContractError(
                    f"{label} must document explicit distinct credentials via {fragment!r}"
                )
        if relative == PROGRESSIVE_TUTORIAL_PATH and not re.search(
            r'-H "Authorization: Bearer \$\{CHIO_ADMIN_TOKEN\}" \\\n'
            r'\s+"http://127\.0\.0\.1:8931/admin/',
            body,
        ):
            raise ContractError(
                "progressive tutorial must use only the admin token for its /admin/ example"
            )
        required_up = (
            "docker compose up -d --build --wait --wait-timeout 180"
            if relative == DOCKER_README_PATH
            else "docker compose -f examples/docker/compose.yaml up -d --build --wait --wait-timeout 180"
        )
        if required_up not in body:
            raise ContractError(
                f"{label} must use bounded Docker Compose readiness waiting"
            )


def _validate_makefile(root: Path) -> None:
    body = _read_text(root / MAKEFILE_PATH, "Makefile")
    required = (
        "docker-demo-up:\n"
        "\tcd examples/docker && docker compose up -d --build --wait --wait-timeout 180",
        "docker-demo-smoke:\n"
        "\tcd examples/docker && \\\n"
        '\t\tCHIO_EDGE_TOKEN="$${CHIO_AUTH_TOKEN:?set a dedicated CHIO_AUTH_TOKEN}" \\\n'
        '\t\tCHIO_ADMIN_TOKEN="$${CHIO_ADMIN_TOKEN:?set a dedicated CHIO_ADMIN_TOKEN}" \\\n'
        '\t\tCHIO_DASHBOARD_READ_TOKEN="$${CHIO_DASHBOARD_READ_TOKEN:?set a dedicated CHIO_DASHBOARD_READ_TOKEN}" \\\n'
        "\t\tpython3 smoke_client.py",
    )
    for fragment in required:
        if fragment not in body:
            raise ContractError(
                "Makefile Docker quickstart must preserve bounded readiness and exact token mapping"
            )


def _validate_tools_schema(root: Path) -> None:
    path = root / DOCKER_TOOLS_PATH
    body = _read_text(path, "Docker tools fixture")
    try:
        document = json.loads(body)
    except json.JSONDecodeError as error:
        raise ContractError(f"Docker tools fixture is invalid JSON: {error}") from error
    expected = {
        "tools": [
            {
                "name": "echo_text",
                "title": "Echo Text",
                "description": "Return the provided message",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 4096,
                        }
                    },
                    "required": ["message"],
                    "additionalProperties": False,
                },
                "annotations": {"readOnlyHint": True},
            }
        ]
    }
    if document != expected:
        raise ContractError(
            "Docker tools fixture schema is not exact, closed, and bounded"
        )


def _validate_native_provisioner(root: Path) -> None:
    body = _read_text(root / NATIVE_PROVISIONER_PATH, "native MCP provisioner")
    required_constants = {
        "signed manifest": (
            "SIGNED_MANIFEST_FILE",
            "signed-manifest.json",
        ),
        "manifest verifier key": (
            "MANIFEST_PUBLIC_KEY_FILE",
            "manifest-public-key",
        ),
        "signed cage policy": (
            "CAGE_POLICY_FILE",
            "cage-launch-policy.json",
        ),
        "cage policy verifier key": (
            "CAGE_POLICY_PUBLIC_KEY_FILE",
            "cage-policy-signer",
        ),
        "cage migration ledger": (
            "MIGRATION_DATABASE_FILE",
            "enterprise-migration.sqlite3",
        ),
        "cage migration verifier": (
            "MIGRATION_PUBLIC_KEY_FILE",
            "cage-migration-public-key",
        ),
        "cage receipt signer": (
            "RECEIPT_SEED_FILE",
            "cage-receipt-signer.seed",
        ),
        "current authority pin": (
            "CONTROL_AUTHORITY_PUBLIC_KEY_FILE",
            "control-authority-public-key",
        ),
        "local authority seed": (
            "CONTROL_AUTHORITY_SEED_FILE",
            "control-authority.seed",
        ),
        "canonical target command": (
            "TARGET_COMMAND_FILE",
            "target-command",
        ),
    }
    for label, (constant, filename) in required_constants.items():
        declaration = re.compile(
            rf'(?m)^const\s+{re.escape(constant)}:\s*&str\s*=\s*"{re.escape(filename)}";\s*$'
        )
        if declaration.search(body) is None:
            raise ContractError(
                f"native MCP provisioner does not emit the exact {label}"
            )
    if "validate_existing_provision(&inputs)" not in body:
        raise ContractError(
            "native MCP provisioner does not fail closed on one-shot replay"
        )


def _parse_unit(path: Path, label: str) -> dict[str, dict[str, list[str]]]:
    body = _read_text(path, label)
    logical: list[str] = []
    pending = ""
    for raw_line in body.splitlines():
        stripped = raw_line.strip()
        if not pending and (not stripped or stripped.startswith(("#", ";"))):
            continue
        continued = raw_line.rstrip().endswith("\\")
        part = raw_line.rstrip()
        if continued:
            part = part[:-1]
        pending = f"{pending} {part.strip()}".strip()
        if not continued:
            logical.append(pending)
            pending = ""
    if pending:
        raise ContractError(f"{label} ends with an unterminated continuation")

    sections: dict[str, dict[str, list[str]]] = {}
    section: str | None = None
    for line in logical:
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            if not section or section in sections:
                raise ContractError(f"{label} contains an invalid/duplicate section")
            sections[section] = {}
            continue
        if section is None or "=" not in line:
            raise ContractError(f"{label} contains an invalid directive: {line!r}")
        key, value = line.split("=", 1)
        if not key or not value:
            raise ContractError(f"{label} contains an empty directive: {line!r}")
        sections[section].setdefault(key, []).append(value)
    return sections


def _unit_one(service: Mapping[str, list[str]], key: str, label: str) -> str:
    values = service.get(key)
    if not isinstance(values, list) or len(values) != 1 or not values[0]:
        raise ContractError(f"{label} must declare {key} exactly once")
    return values[0]


def _unit_exec_words(service: Mapping[str, list[str]], label: str) -> list[str]:
    command = _unit_one(service, "ExecStart", label)
    try:
        return shlex.split(command, posix=True)
    except ValueError as error:
        raise ContractError(
            f"{label} ExecStart has invalid quoting: {error}"
        ) from error


def _unit_environment(service: Mapping[str, list[str]], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for directive in service.get("Environment", []):
        try:
            entries = shlex.split(directive, posix=True)
        except ValueError as error:
            raise ContractError(
                f"{label} Environment has invalid quoting: {error}"
            ) from error
        for entry in entries:
            if "=" not in entry:
                raise ContractError(
                    f"{label} Environment inherits {entry!r} ambiguously"
                )
            key, value = entry.split("=", 1)
            if not key or not value or key in result:
                raise ContractError(f"{label} Environment has an ambiguous {key!r}")
            result[key] = value
    return result


def _validate_systemd(root: Path) -> None:
    edge_unit_path = root / EDGE_UNIT_PATH
    edge_unit_body = _read_text(edge_unit_path, "systemd MCP edge unit")
    edge_unit = _parse_unit(edge_unit_path, "systemd MCP edge unit")
    edge_service = _mapping(
        edge_unit.get("Service"), "systemd MCP edge Service section"
    )
    edge_words = _unit_exec_words(edge_service, "systemd MCP edge")
    if (
        _unit_one(edge_service, "EnvironmentFile", "systemd MCP edge")
        != "/etc/chio/chio-mcp-edge.env"
    ):
        raise ContractError(
            "systemd MCP edge must use the exact required environment file"
        )
    if _unit_one(edge_service, "ProtectSystem", "systemd MCP edge") != "strict":
        raise ContractError(
            "systemd MCP edge must keep the private CA filesystem read-only"
        )
    writable_paths = []
    for directive in edge_service.get("ReadWritePaths", []):
        try:
            writable_paths.extend(shlex.split(directive, posix=True))
        except ValueError as error:
            raise ContractError(
                f"systemd MCP edge ReadWritePaths has invalid quoting: {error}"
            ) from error
    root_ca_unit_path = PurePosixPath("/etc/chio/control-root-ca.pem")
    for raw_path in writable_paths:
        path = PurePosixPath(raw_path.lstrip("-+"))
        if not path.is_absolute() or ".." in path.parts:
            raise ContractError("systemd MCP edge has a noncanonical writable path")
        try:
            root_ca_unit_path.relative_to(path)
        except ValueError:
            continue
        raise ContractError("systemd MCP edge makes the private CA path writable")
    control_url = _flag_value(edge_words, "--control-url", "systemd MCP edge")
    parsed = urlsplit(control_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "," in control_url
        or any(marker in control_url for marker in ("${", "$("))
    ):
        raise ContractError(
            "systemd MCP edge must use one final literal HTTPS control URL"
        )

    environment = _unit_environment(edge_service, "systemd MCP edge")
    if environment.get("CHIO_CONTROL_TLS_ROOT_CA_FILE") != str(root_ca_unit_path):
        raise ContractError("systemd MCP edge must pin the exact private CA root")
    required_values = {
        "--authority-seed-file": "/etc/chio/mcp-edge-authority.seed",
        "--signed-manifest": "/etc/chio/mcp-edge-signed-manifest.json",
        "--manifest-public-key": "${CHIO_MANIFEST_PUBLIC_KEY}",
        "--cage-policy": "/etc/chio/mcp-edge-cage-policy.json",
        "--cage-policy-signer": "${CHIO_CAGE_POLICY_SIGNER}",
    }
    for flag, expected in required_values.items():
        observed = _flag_value(edge_words, flag, "systemd MCP edge")
        if observed != expected:
            raise ContractError(
                f"systemd MCP edge {flag} must be exactly {expected!r}, got {observed!r}"
            )
    authority_pin_flag = "--control-authority-public-key"
    if authority_pin_flag in edge_words:
        observed_pin = _flag_value(edge_words, authority_pin_flag, "systemd MCP edge")
        if observed_pin != "${CHIO_CONTROL_AUTHORITY_PUBLIC_KEY}":
            raise ContractError(
                "systemd MCP edge must bind the exact current authority pin"
            )
    elif any(word.startswith(authority_pin_flag) for word in edge_words):
        raise ContractError(
            "systemd MCP edge has a malformed current authority pin flag"
        )
    elif "CHIO_CONTROL_AUTHORITY_PUBLIC_KEY" not in edge_unit_body:
        raise ContractError(
            "systemd MCP edge operator contract omits the exact current authority pin"
        )
    if any(flag in edge_words for flag in FORBIDDEN_EDGE_STORE_FLAGS):
        raise ContractError(
            "systemd MCP edge configures a conflicting local control store"
        )
    if "--" not in edge_words:
        raise ContractError(
            "systemd MCP edge does not delimit the canonical target command"
        )
    delimiter = edge_words.index("--")
    if edge_words[delimiter + 1 :] != ["/usr/local/bin/chio-mcp-upstream"]:
        raise ContractError("systemd MCP edge target command is not exact")

    trust_unit = _parse_unit(root / TRUST_UNIT_PATH, "systemd trust-control unit")
    trust_service = _mapping(
        trust_unit.get("Service"), "systemd trust-control Service section"
    )
    trust_words = _unit_exec_words(trust_service, "systemd trust-control")
    if (
        _flag_value(trust_words, "--authority-seed-file", "systemd trust-control")
        != "/var/lib/chio-trust-control/authority.seed"
    ):
        raise ContractError(
            "systemd trust-control does not use the exact authority seed"
        )
    if "--authority-db" in trust_words:
        raise ContractError(
            "systemd trust-control configures a conflicting authority database"
        )


def validate(root: Path) -> None:
    root = root.resolve()
    _validate_compose(root)
    _validate_dockerfile(root)
    _validate_docker_write_targets(root)
    _validate_edge_entrypoint(root)
    _validate_tls_runtime(root)
    _validate_launcher(root)
    _validate_edge_healthcheck(root)
    _validate_healthcheck(root)
    _validate_smoke_client(root)
    _validate_docker_credential_docs(root)
    _validate_makefile(root)
    _validate_tools_schema(root)
    _validate_native_provisioner(root)
    _validate_systemd(root)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check Docker/systemd fail-closed security runtime wiring"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the checker's repository)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    try:
        validate(args.root)
    except ContractError as error:
        print(f"check-security-runtime-contract.py: {error}", file=sys.stderr)
        return 1
    print("security runtime contract passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
