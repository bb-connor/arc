#!/usr/bin/env python3
"""Read-only, self-contained audit of versioned current qualification records.

This executable imports only the standard library. Historical package auditors
remain historical; their mutable-tree imports are never used by this auditor.
"""
from __future__ import annotations

import argparse
from bisect import bisect_left
import errno
from contextlib import ExitStack, contextmanager
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import platform
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tomllib
import types
from types import SimpleNamespace
import unicodedata

SCHEMA = "chio.recovery-qualification-record.v1"
INVENTORY_VERSION = "chio.source-inventory.v4"
MATERIALIZATION_SCHEMA = "chio.confined-source-snapshot.v2"
SOURCE_ORIGIN_SCHEMA = "chio.rust-profile-source-origin.v2"
SOURCE_MANIFEST_NAME = "__declared_source_snapshot__.json"
COMPILED_IMAGE_MAX_BYTES = 512 * 1024**2
COMPILED_IMAGE_POOL_MAX_BYTES = 16 * 1024**3
COMPILED_DIMENSION_TOOL_SHA = "e0495799c3b23d00648843615785b9c4a87f5f76876f3de44e0e3358f883a8e8"
MATERIALIZATION_RUNNER = "scripts/run-confined-return-linux-acceptance.py"
MATERIALIZATION_CACHE_PARTS = frozenset({".cache", ".git", ".ignored-cache", ".mypy_cache", ".next",
    ".pytest_cache", ".ruff_cache", ".turbo", ".venv", "__pycache__", "node_modules", "venv"})
PROVIDER_ENDPOINT = "https://api.openai.com/v1"
COHORT_MODEL = "gpt-5.4-2026-03-05"
COHORT_HOSTS = {"crewai":"0.203.2", "langgraph":"1.2.12", "openai":"3.3.0", "httpx":"0.28.1"}
SOURCE_DIRECTORIES = frozenset({
    ".cargo", ".clusterfuzzlite", ".config", ".dst", ".github", ".kani", ".loom",
    "arena", "bench", "ci-gates", "config", "contracts", "crates", "deploy", "examples",
    "fixtures", "formal", "fuzz", "integrations", "labs", "packaging", "scripts", "sdks",
    "spec", "supply-chain", "tests", "third_party", "tools", "wit", "xtask",
})
SOURCE_FILES = frozenset({
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain", "rustfmt.toml",
    "Makefile", "deny.toml", "osv-scanner.toml", "package.json", "playwright.config.ts",
    ".gitignore", ".gitattributes",
})
BUILD_DIRECTORIES = frozenset({"node_modules", "target", "dist", ".venv", "__pycache__"})
SECRET_NAMES = frozenset({"credentials", "credentials.json", "credentials.toml", ".git-credentials", ".netrc",
    ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", ".aws", ".ssh",
    ".gnupg", ".secrets", ".auth", ".password-store"})
SECRET_SUFFIXES = frozenset({".key", ".pem", ".p12", ".pfx", ".keystore"})
ARCHIVE_SUFFIXES = (
    ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar.xz", ".txz",
    ".tar.zst", ".tzst", ".zip", ".7z",
)
ARTIFACT_PREFIXES = (
    "docs/integrations/acceptance",
    "docs/architecture/recoverable-agent-runtime/implementation/p0/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p1/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p2/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p3/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p4/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p5/evidence",
    "docs/architecture/recoverable-agent-runtime/implementation/p6/evidence",
    "sdks/python/chio-hermes/evidence", "audits/evidence",
    "docs/integrations/session-credentials/evidence", "docs/evidence",
    "docs/research/openappa-2026-10-01/evidence", "labs/openappa-recovery/evidence",
    "formal/mutation/evidence",
)
PYTHON_ENVIRONMENT = {"OTEL_SDK_DISABLED":"true", "CREWAI_DISABLE_TELEMETRY":"true",
                      "CREWAI_TELEMETRY_DISABLED":"true", "LITELLM_LOCAL_MODEL_COST_MAP":"True"}
PYTHON_SDK_COMMAND = (
    "import json,sys;from pathlib import Path;root=Path.cwd().resolve();"
    "sys.path[:0]=[str(root/p) for p in ['sdks/python/chio-sdk-python/src',"
    "'sdks/python/chio-adapter-base/src','sdks/python/chio-langgraph/src','sdks/python/chio-crewai/src']];"
    "import chio_sdk;origin=Path(chio_sdk.__file__).resolve();"
    "expected=root/'sdks/python/chio-sdk-python/src/chio_sdk/__init__.py';"
    "origin==expected or sys.exit('qualification.python_sdk_origin');"
    "print('QUALIFICATION_PYTHON_IMPORTS '+json.dumps({'chio_sdk':str(origin.relative_to(root)),"
    "'repository':str(root),'prefix':str(Path(sys.prefix).resolve()),"
    "'executable':str(Path(sys.executable).absolute()),'real_executable':str(Path(sys.executable).resolve())}),flush=True);"
    "import pytest;sys.exit(pytest.main(['-q','sdks/python/chio-sdk-python/tests']))"
)


def require(condition, reason):
    if not condition:
        raise ValueError("qualification." + reason)


def portable_path_key(name):
    return unicodedata.normalize("NFC", name).casefold()


def secret_source(name):
    return any(part in SECRET_NAMES or part == ".env" or part.startswith(".env.")
        or part == "secrets" or part.startswith("secrets.") or part.startswith("private-key")
        or Path(part).suffix in SECRET_SUFFIXES for part in (part.lower() for part in relative_path(name).parts))


def source_exclusion(name):
    """Classify excluded metadata without reading original contents or links."""
    path = relative_path(name)
    if secret_source(name):
        return "secret-path-policy"
    if any(path.is_relative_to(prefix) for prefix in ARTIFACT_PREFIXES):
        return "artifact-tree-policy"
    if path.name.lower().endswith(ARCHIVE_SUFFIXES):
        return "archive-file-policy"
    return None


def source_metadata(root, relative):
    """Record excluded shape through no-follow parents without reading content."""
    exclusion = source_exclusion(relative.as_posix())
    require(exclusion is not None,"source_exclusion")
    row = {"path":relative.as_posix(),"content_coverage":"metadata-only","exclusion_reason":exclusion}
    parent = os.open(root,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptors = [parent]
    parents = []
    def finish(value):
        locations = [(os.fstat(descriptors[0]),root.stat(follow_symlinks=False))]
        locations += [(os.fstat(child),os.stat(part,dir_fd=held,follow_symlinks=False))
                      for held,part,child in parents]
        require(all((held.st_dev,held.st_ino,held.st_mode) == (named.st_dev,named.st_ino,named.st_mode)
                    for held,named in locations),"source_changed_during_read")
        return value
    try:
        for part in relative.parts[:-1]:
            try:
                child = os.open(part,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
            except OSError as error:
                if error.errno in {errno.ENOENT,errno.ENOTDIR,errno.ELOOP}:
                    return finish({**row,"state":"unreachable","reason":"missing-or-nondirectory-parent"})
                raise
            parents.append((parent,part,child))
            descriptors.append(child)
            parent = child
        try:
            before = os.stat(relative.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:
            return finish({**row,"state":"missing"})
        after = os.stat(relative.name,dir_fd=parent,follow_symlinks=False)
        require((before.st_dev,before.st_ino,before.st_mode) == (after.st_dev,after.st_ino,after.st_mode),
                "source_changed_during_read")
        state = "file" if stat.S_ISREG(before.st_mode) else "symlink" if stat.S_ISLNK(before.st_mode) else \
                "directory" if stat.S_ISDIR(before.st_mode) else "special"
        return finish({**row,"state":state,"mode":stat.S_IMODE(before.st_mode)})
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def validate_source_rows(sources):
    require(isinstance(sources,list) and sources and sources == sorted(sources,key=lambda row:row["path"])
            and len({portable_path_key(row["path"]) for row in sources}) == len(sources),"source_inventory")
    for row in sources:
        relative_path(row["path"])
        if "sha256" in row:
            require(set(row) == {"path","sha256"} and source_exclusion(row["path"]) is None
                    and re.fullmatch(r"[a-f0-9]{64}",row["sha256"]),"source_inventory")
        else:
            state = row.get("state")
            fields = {"path","content_coverage","exclusion_reason","state"}
            if state == "unreachable":
                fields.add("reason")
                require(row.get("reason") == "missing-or-nondirectory-parent","source_inventory")
            elif state != "missing":
                fields.add("mode")
                require(state in {"file","symlink","directory","special"}
                        and type(row.get("mode")) is int and 0 <= row["mode"] <= 0o7777,"source_inventory")
            exclusion = source_exclusion(row["path"])
            require(set(row) == fields and exclusion is not None
                    and row.get("content_coverage") == "metadata-only"
                    and row.get("exclusion_reason") == exclusion,"source_inventory")


def gate_catalog():
    """Commands are owned by the auditor, not declared by successful records."""
    commands = {
        "format":["cargo", "fmt", "--all", "--", "--check"],
        "workspace-build":["cargo", "build", "--offline", "--locked", "--workspace"],
        "workspace-msrv":["cargo", "+1.95.0", "check", "--offline", "--locked", "--workspace", "--all-targets"],
        "workspace-test":["cargo", "test", "--offline", "--locked", "--workspace"],
        "workspace-clippy":["cargo", "clippy", "--offline", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"],
        "contracts":["cargo", "test", "--offline", "--locked", "-p", "chio-core-types", "-p", "chio-security-types"],
        "native-recovery":["cargo", "test", "--offline", "--locked", "-p", "chio-control-plane", "--lib", "--features", "pq", "recovery::", "--", "--test-threads=1"],
        "store":["cargo", "test", "--offline", "--locked", "-p", "chio-store-sqlite", "--lib", "--", "--test-threads=1"],
        "kernel":["cargo", "test", "--offline", "--locked", "-p", "chio-kernel", "--lib"],
        "cli":["cargo", "test", "--offline", "--locked", "-p", "chio-cli", "--test", "recovery_egress", "--test", "recovery_setup"],
        "python-sdk":["target/recovery-qualification-venv/bin/python", "-I", "-B", "-c", PYTHON_SDK_COMMAND],
        "python-fixtures":["target/recovery-qualification-venv/bin/python", "-B", "-m", "unittest", "discover", "-s", "fixtures/recovery-product", "-p", "test_*.py"],
        "typescript":["node", "node_modules/vitest/vitest.mjs", "run"],
        "go-sdk":["go", "test", "-json", "./..."],
        "allocator":["cargo", "check", "--offline", "--locked", "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml"],
        "standard":["cargo", "check", "--offline", "--locked", "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml", "--features", "std"],
        "allocator-msrv":["cargo", "+1.93.0", "check", "--offline", "--locked", "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml"],
        "standard-msrv":["cargo", "+1.93.0", "check", "--offline", "--locked", "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml", "--features", "std"],
        "wasm":["cargo", "check", "--offline", "--locked", "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml", "--target", "wasm32-unknown-unknown"],
        "recovery-boundaries":["python3", "scripts/check-recovery-boundaries.py", "--offline"],
        "domain-separation":["python3", "scripts/check-domain-separation.py"],
        "wire-schemas":["python3", "scripts/check-wire-schemas.py"],
        "source-names":["python3", "scripts/check-source-names.py"],
        "rust-hygiene":["python3", "scripts/check-rust-file-hygiene.py"],
        "workspace-layering":["bash", "scripts/check-workspace-layering.sh"],
        "rust-codegen":["target/debug/xtask", "codegen", "rust", "--check"],
        "typescript-codegen":["target/debug/xtask", "codegen", "ts", "--check"],
        "python-codegen":["target/debug/xtask", "codegen", "python", "--check"],
        "go-codegen":["target/debug/xtask", "codegen", "go", "--check"],
        "formal-differential":["cargo", "test", "--offline", "--locked", "-p", "chio-formal-diff-tests"],
        "native-performance":["cargo", "test", "--offline", "--locked", "-p", "chio-process", "--test", "recovery_baseline",
                              "measured_native_baseline", "--", "--ignored", "--nocapture", "--test-threads=1"],
        "pure-performance":["cargo", "run", "--offline", "--locked", "-p", "chio-recovery", "--example", "pure_baseline"],
    }
    tests = {"workspace-test", "contracts", "native-recovery", "store", "kernel", "cli",
             "python-sdk", "python-fixtures", "typescript", "go-sdk", "formal-differential", "native-performance"}
    catalog = {name:{"command":command, "cwd":".", "environment":{}, "requires_tests":name in tests}
               for name, command in commands.items()}
    catalog["python-sdk"]["environment"] = dict(PYTHON_ENVIRONMENT)
    catalog["python-fixtures"]["environment"] = {**PYTHON_ENVIRONMENT,
        "PYTHONPATH":"fixtures/recovery-product:sdks/python/chio-sdk-python/src:sdks/python/chio-adapter-base/src:sdks/python/chio-langgraph/src:sdks/python/chio-crewai/src"}
    catalog["typescript"]["cwd"] = "sdks/typescript/packages/conformance"
    catalog["go-sdk"]["cwd"] = "sdks/go/chio-go-http"
    return catalog


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def binding(sources, base_commit):
    return hashlib.sha256(canonical({"source_inventory_version":INVENTORY_VERSION,
                                    "base_commit":base_commit, "sources":sources})).hexdigest()


def resolve_public_source(root, relative):
    """Inspect public links only; excluded intermediate paths are never followed."""
    pending = list(relative.parts)
    resolved = []
    links = set()
    while pending:
        part = pending.pop(0)
        if part in {"","."}:
            continue
        if part == "..":
            require(resolved,"source_alias_boundary")
            resolved.pop()
            continue
        candidate = Path(*resolved,part)
        exclusion = source_exclusion(candidate.as_posix())
        require(exclusion not in {"secret-path-policy","artifact-tree-policy"},"source_alias_boundary")
        try:
            metadata = (root/candidate).lstat()
        except FileNotFoundError:
            require(not links,"source_alias_boundary")
            return None
        require(exclusion is None or stat.S_ISDIR(metadata.st_mode),"source_alias_boundary")
        if stat.S_ISLNK(metadata.st_mode):
            require(candidate not in links and len(links) < 64,"source_alias_cycle")
            links.add(candidate)
            target = os.readlink(root/candidate)
            if target.startswith("/"):
                prefix = root.as_posix()
                require(target == prefix or target.startswith(prefix+"/"),"source_alias_boundary")
                target = target[len(prefix):].lstrip("/")
                resolved = []
            pending = target.split("/")+pending
        else:
            require(not pending or stat.S_ISDIR(metadata.st_mode),"source_alias_boundary")
            resolved.append(part)
    return root/Path(*resolved)


def current_source_inventory(root):
    """Recompute the named inventory version without importing mutable helpers."""
    root = Path(root).resolve(strict=True)
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root).decode().split("\0")
    declared = set()
    folded = set()
    for name in sorted(set(names) - {""}):
        path = relative_path(name)
        if not source_selected(name) and source_exclusion(name) is None:
            continue
        require(portable_path_key(name) not in folded, "source_case_collision")
        folded.add(portable_path_key(name))
        declared.add(path)
    files = {}
    metadata = {path.as_posix():source_metadata(root,path) for path in declared
                if source_exclusion(path.as_posix()) is not None}
    declared = {path for path in declared if source_exclusion(path.as_posix()) is None}
    def collect(path, ancestors=frozenset(), expected_target=None):
        logical = root / path
        resolved = resolve_public_source(root,path)
        if resolved is None:
            return
        require(expected_target is None or expected_target == resolved,"source_changed_during_read")
        target = resolved.relative_to(root)
        if resolved.is_file():
            require(target in declared, "source_alias_boundary")
            digest = sha(resolved)
            require(resolve_public_source(root,path) == resolved, "source_changed_during_read")
            files[path.as_posix()] = digest
        elif logical.is_symlink() and resolved.is_dir():
            require(resolved not in ancestors and not path.is_relative_to(target), "source_alias_cycle")
            members = sorted(member for member in declared if member != target and member.is_relative_to(target))
            require(members, "source_alias_boundary")
            for member in members:
                suffix = member.relative_to(target)
                collect(path / suffix, ancestors | {resolved}, resolve_public_source(root,member))
            require(resolve_public_source(root,path) == resolved,"source_changed_during_read")
        else:
            require(False, "source_regular_file")
    for path in sorted(declared):
        collect(path)
    require(len({portable_path_key(name) for name in files}) == len(files), "source_case_collision")
    rows = {name:{"path":name,"sha256":digest} for name,digest in files.items()}
    rows.update(metadata)
    require(len({portable_path_key(name) for name in rows}) == len(rows),"source_case_collision")
    return [row for _,row in sorted(rows.items())]


def relative_path(value):
    require(isinstance(value, str) and value and "\\" not in value
            and all(ord(character) >= 32 and ord(character) != 127 for character in value), "artifact_path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and str(path) == value, "artifact_path")
    return Path(value)


@contextmanager
def regular_input(path):
    """Hold directory components and a regular file through the complete read."""
    absolute = Path(path).absolute()
    require(".." not in absolute.parts, "artifact_path")
    descriptors = []
    parents = []
    try:
        parent = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(parent)
        for component in absolute.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append(child)
            parents.append((parent, component, child))
            parent = child
        descriptor = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), "artifact_regular_file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            yield stream
        after = os.fstat(descriptor)
        located = os.stat(absolute.name, dir_fd=parent, follow_symlinks=False)
        identity = lambda item:(item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(identity(before) == identity(after) == identity(located), "artifact_changed_during_read")
        for parent_fd, component, child in parents:
            held = os.fstat(child)
            located = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            require((held.st_dev, held.st_ino, held.st_mode) == (located.st_dev, located.st_ino, located.st_mode),
                    "artifact_parent_changed")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def read_bytes(path, limit=64*1024*1024):
    with regular_input(path) as stream:
        data = stream.read(limit + 1)
        require(len(data) <= limit, "artifact_size")
        return data


def sha(path):
    digest = hashlib.sha256()
    with regular_input(path) as stream:
        for chunk in iter(lambda:stream.read(1024*1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def closed_pairs(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate_json_field")
        result[name] = value
    return result


def read_json(path):
    return json.loads(read_bytes(path), object_pairs_hook=closed_pairs,
                      parse_constant=lambda _:require(False, "nonfinite_json_number"))


def audit_samples(measurement):
    samples = measurement.get("samples_ns")
    require(isinstance(samples, list) and 0 < len(samples) <= 100000
            and all(type(item) is int and 0 <= item <= 2**64-1 for item in samples)
            and type(measurement.get("samples")) is int and measurement["samples"] == len(samples),
            "performance_raw_samples")
    ordered = sorted(samples)
    expected = {"p50_ns":ordered[math.ceil(.5*len(ordered))-1],
                "p95_ns":ordered[math.ceil(.95*len(ordered))-1],
                "p99_ns":ordered[math.ceil(.99*len(ordered))-1], "max_ns":ordered[-1]}
    require(all(type(measurement.get(key)) is int and measurement[key] == value
                for key, value in expected.items()), "performance_recomputation")


def top_level_rust_counts(text):
    totals = {"passed":0, "failed":0, "ignored":0}
    for section in re.split(r"^\s*(?:Running |Doc-tests )", text, flags=re.MULTILINE):
        summaries = re.findall(r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", section, re.MULTILINE)
        if summaries:
            for name, value in zip(totals, summaries[-1]):
                totals[name] += int(value)
    return totals


def positive_test_count(text):
    rust = top_level_rust_counts(text)
    if rust["passed"] or rust["failed"]:
        require(rust["failed"] == 0, "gate_test_denominator")
        return rust["passed"]
    pytest = re.findall(r"\b(\d+) passed\b", text)
    unittest = re.findall(r"^Ran (\d+) tests?\b", text, re.MULTILINE)
    vitest = re.findall(r"^\s*Tests\s+(\d+) passed", text, re.MULTILINE)
    go = []
    for line in text.splitlines():
        if line.startswith("{"):
            try:
                item = json.loads(line)
                if item.get("Action") == "pass" and item.get("Test"):
                    go.append(item)
            except ValueError:
                continue
    if unittest:
        require(re.search(r"^OK$", text, re.MULTILINE) is not None, "gate_test_denominator")
    return max([0, *(int(value) for value in pytest + unittest + vitest), len(go)])


def audit_gate(root, row, source_binding):
    expected = gate_catalog().get(row.get("id"))
    require(expected is not None, "gate_inventory")
    require(row.get("command") == expected["command"] and row.get("cwd", ".") == expected["cwd"], "gate_command")
    environment = row.get("environment", {})
    require(isinstance(environment, dict) and all(environment.get(name) == value
            for name, value in expected["environment"].items()), "gate_environment")
    require(type(row.get("exit_code")) is int and row["exit_code"] == 0 and row.get("source_stable") is True, "gate_failed")
    require(row.get("source_binding") == source_binding, "gate_source")
    log = read_bytes(root / relative_path(row["log"]["path"]))
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", log.decode("utf-8"))
    if row["id"] == "python-sdk":
        origins = re.findall(r"^QUALIFICATION_PYTHON_IMPORTS (.+)$", text, re.MULTILINE)
        require(len(origins) == 1, "python_sdk_origin")
        origin = json.loads(origins[0])
        require(origin.get("chio_sdk") == "sdks/python/chio-sdk-python/src/chio_sdk/__init__.py"
                and str(origin.get("prefix", "")).endswith("/target/recovery-qualification-venv"), "python_sdk_origin")
    count = positive_test_count(text) if expected["requires_tests"] else None
    if expected["requires_tests"]:
        require(count > 0, "gate_test_denominator")
    require(hashlib.sha256(log).hexdigest() == row["log"]["sha256"], "gate_log_hash")
    return {"id":row["id"], "tests":count, "rust":top_level_rust_counts(text)}


def audit_attempts(declaration, attempts, root=None, candidate=None):
    require(isinstance(declaration, list) and isinstance(attempts, list), "cohort_inventory")
    expected = [row["id"] for row in declaration]
    require(expected == [row.get("id") for row in attempts] and len(set(expected)) == len(expected), "cohort_inventory")
    for planned, attempt in zip(declaration, attempts):
        total = planned["planned_trials"]
        counters = [attempt.get(key) for key in ["planned_trials", "measured_trials", "unknown_trials",
                                                "positive_strata", "positive_strata_passed"]]
        require(type(total) is int and total == 96
                and all(type(value) is int and value >= 0 for value in counters)
                and total == counters[0] == counters[1] + counters[2]
                and counters[3] > 0 and counters[4] <= counters[3], "cohort_denominator")
        qualified = counters[2] == 0 and counters[3] == counters[4]
        if root is not None and candidate is not None:
            require(isinstance(attempt.get("primary"),dict),"cohort_primary_evidence")
            measured = audit_live_cohort(root,attempt["primary"],candidate)
            require(all(attempt.get(key) == measured[key] for key in ["planned_trials","measured_trials",
                "unknown_trials","positive_strata","positive_strata_passed"]),"cohort_report_recomputation")
            qualified = measured["qualified"]
        require(type(attempt.get("qualified")) is bool and attempt["qualified"] == qualified, "cohort_qualification")
        if qualified and root is None:
            require(root is not None and candidate is not None and isinstance(attempt.get("primary"), dict),
                    "cohort_primary_evidence")


def artifact_json(root, reference):
    path = root / relative_path(reference["path"])
    data = read_bytes(path)
    require(hashlib.sha256(data).hexdigest() == reference["sha256"], "evidence_reference_hash")
    return json.loads(data, object_pairs_hook=closed_pairs,
                      parse_constant=lambda _:require(False, "nonfinite_json_number"))


def source_selected(name):
    path = relative_path(name)
    docs_input = path.parts[0] == "docs" and not any(path.is_relative_to(prefix) for prefix in [
        "docs/plans", "docs/planning", "docs/architecture/recoverable-agent-runtime/implementation"])
    return source_exclusion(name) is None and not BUILD_DIRECTORIES.intersection(path.parts) and (path.parts[0] in SOURCE_DIRECTORIES
        or name in SOURCE_FILES or docs_input)


def audited_source_manifest(snapshot):
    """Recompute the provenance writer's ASCII canonical manifest, excluding timings."""
    require(snapshot.get("format") == "chio.local-command-provenance.v1"
            and isinstance(snapshot.get("git"), dict) and isinstance(snapshot.get("entries"), dict)
            and isinstance(snapshot.get("explicit_file_pins"), list), "gate_source_manifest")
    manifest = {key:snapshot[key] for key in ["git", "entries", "explicit_file_pins"]}
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True, ensure_ascii=True,
                                      separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    require(digest == snapshot.get("content_manifest_sha256"), "gate_source_manifest")
    names = list(snapshot["entries"])
    require(len(names) == len({portable_path_key(name) for name in names}), "source_case_collision")
    for name in names:
        relative_path(name)
    return digest


def snapshot_target(name, entries, repository):
    """Resolve captured link text inside the captured repository, without live reads."""
    pending = list(PurePosixPath(name).parts)
    resolved = []
    visited = set()
    while pending:
        part = pending.pop(0)
        if part in {"","."}:
            continue
        if part == "..":
            require(resolved,"source_alias_boundary")
            resolved.pop()
            continue
        prefix = PurePosixPath(*resolved,part).as_posix()
        exclusion = source_exclusion(prefix)
        entry = entries.get(prefix,{})
        require(exclusion is None or exclusion == "archive-file-policy"
                and entry.get("state") in {None,"directory"},"source_alias_boundary")
        if entry.get("state") == "symlink":
            require(prefix not in visited and len(visited) < 64,"source_alias_cycle")
            visited.add(prefix)
            target = entry.get("target")
            require(isinstance(target, str) and entry.get("content_coverage") == "link-text-only"
                    and hashlib.sha256(os.fsencode(target)).hexdigest() == entry.get("target_sha256"),
                    "gate_source_bracket")
            if target.startswith("/"):
                base = repository.as_posix()
                require(target == base or target.startswith(base+"/"),"source_alias_boundary")
                target = target[len(base):].lstrip("/")
                resolved = []
            pending = target.split("/")+pending
        else:
            require(entry.get("state") not in {"missing","unreachable","special"}
                    and (not pending or entry.get("state") != "file"),"source_alias_boundary")
            resolved.append(part)
    target = PurePosixPath(*resolved).as_posix()
    relative_path(target)
    return target


def audit_snapshot_sources(snapshot, sources, repository):
    """Every runtime row must be a declared input whose captured bytes match."""
    entries = snapshot["entries"]
    declared = {name for name, entry in entries.items() if (source_selected(name) or source_exclusion(name) is not None)
                and entry.get("membership") in {"tracked", "nonignored-untracked"}
                and (entry.get("state") not in {"missing","unreachable"} or source_exclusion(name) is not None)}
    byte_declared = {name for name in declared if source_exclusion(name) is None}
    expected = set()
    def collect(name, ancestors=frozenset()):
        if source_exclusion(name) is not None:
            expected.add(name)
            return
        target = snapshot_target(name, entries, repository)
        entry = entries.get(target, {})
        if entry.get("state") == "file":
            require(target in byte_declared, "source_alias_boundary")
            expected.add(name)
        elif name != target:
            members = [path for path in byte_declared if path != target and PurePosixPath(path).is_relative_to(target)]
            require(members and target not in ancestors and not PurePosixPath(name).is_relative_to(target),
                    "source_alias_boundary")
            for member in members:
                collect(str(PurePosixPath(name)/PurePosixPath(member).relative_to(target)),ancestors | {target})
        else:
            require(False, "gate_source_bracket")
    for name in sorted(declared):
        collect(name)
    require(expected == {row["path"] for row in sources}, "gate_source_membership")
    for row in sources:
        if row.get("content_coverage") == "metadata-only":
            entry = entries.get(row["path"],{})
            absent = row["state"] in {"missing","unreachable"}
            exclusion = source_exclusion(row["path"])
            require(exclusion is not None and entry.get("state") == row["state"]
                    and all(entry.get(key) == row[key] for key in ["mode","reason"] if key in row)
                    and entry.get("content_coverage") in ({None,"metadata-only"} if absent else {"metadata-only"})
                    and entry.get("exclusion_reason") in ({None,exclusion} if absent else {exclusion})
                    and not {"sha256","target","target_sha256","link_text","size_bytes"}.intersection(entry),
                    "gate_source_bracket")
            continue
        target = snapshot_target(row["path"], entries, repository)
        entry = entries.get(target, {})
        require(entry.get("state") == "file" and entry.get("content_coverage") == "sha256-bytes"
                and entry.get("sha256") == row["sha256"], "gate_source_bracket")


def materialized_entries(inputs, memberships):
    require(isinstance(inputs,list) and 0 < len(inputs) <= 100000
            and len({portable_path_key(item["path"]) for item in inputs}) == len(inputs),
            "materialization_source_inventory")
    require(isinstance(memberships,dict) and set(memberships) == {item["path"] for item in inputs},
            "materialization_source_membership")
    entries = {}
    for item in inputs:
        name = item["path"]
        relative_path(name)
        require(memberships[name] in {"tracked","nonignored-untracked"},"materialization_source_membership")
        if "sha256" in item:
            require(not secret_source(name),"materialization_secret_bytes")
            entry = {"state":"file","content_coverage":"sha256-bytes","sha256":item["sha256"]}
        elif item.get("content_coverage") == "metadata-only":
            entry = {key:value for key,value in item.items() if key != "path"}
        elif "target" in item and "link_text" in item:
            require(not secret_source(name),"materialization_secret_bytes")
            entry = {"state":"symlink","content_coverage":"link-text-only","target":item["link_text"],
                     "target_sha256":hashlib.sha256(os.fsencode(item["link_text"])).hexdigest()}
        elif item.get("deleted") is True:
            entry = {"state":"missing"}
        else:
            require(False,"materialization_source_inventory")
        entries[name] = {**entry,"membership":memberships[name]}
    return entries


def materialization_binding(policy, inputs):
    return hashlib.sha256(json.dumps({"policy":policy,"inputs":inputs},sort_keys=True,
                                     separators=(",",":"),allow_nan=False).encode()).hexdigest()


def materialization_path(name):
    require(isinstance(name,str) and name and "\\" not in name
            and not any(ord(character) < 32 or ord(character) == 127 for character in name),
            "materialization_source_path")
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts and path.as_posix() == name
            and path.parts[0] != ".git" and name != SOURCE_MANIFEST_NAME,"materialization_source_path")
    return path


def materialization_policy(policy):
    """The pinned Rust profile's policy, independently owned by this auditor."""
    expected = {"schema":"chio.confined-return-source-inventory.v2","profile":"rust-confined-return-linux",
        "coverage":"Overinclusive Git-visible candidate inputs with declared metadata-only secret, archive and artifact exclusions; not a resolved dependency graph or Python/TypeScript SDK dependency qualification.",
        "discovery":"Cached and nonignored untracked Git paths; ignored untracked inputs are not discovered.",
        "excluded_cache_parts":sorted(MATERIALIZATION_CACHE_PARTS),"excluded_secret_names":sorted(SECRET_NAMES),
        "excluded_secret_suffixes":sorted(SECRET_SUFFIXES),
        "excluded_secret_patterns":[".env",".env.*","secrets","secrets.*","private-key*"],
        "excluded_archive_suffixes":sorted(ARCHIVE_SUFFIXES),
        "excluded_artifact_prefixes":sorted(ARTIFACT_PREFIXES),
        "excluded_target_parts":["target"],"excluded_ignored_tracked_inputs":"metadata-only",
        "excluded_link_coverage":"Secret, archive and artifact exclusions have metadata-only coverage without link text or referent reads. Other excluded nonsecret links retain text only; referents are never traversed or hashed.",
        "source_link_coverage":"Relative internal links only, with exact text and independently hashed Git-visible target files."}
    require(policy == expected,"materialization_policy")


def materialization_exclusion(name):
    exclusion = source_exclusion(name)
    if exclusion is not None:
        return exclusion
    parts = {part.lower() for part in materialization_path(name).parts}
    if "target" in parts:
        return "target-tree-policy"
    if MATERIALIZATION_CACHE_PARTS.intersection(parts):
        return "cache-tree-policy"
    return None


def materialization_location(location):
    require(isinstance(location,dict) and set(location) == {"schema","repository","host","root"}
            and location.get("schema") == "chio.source-location.v1","materialization_source_location")
    repository = location["repository"]
    require(isinstance(repository,str) and repository and PurePosixPath(repository).is_absolute()
            and PurePosixPath(repository).as_posix() == repository and ".." not in PurePosixPath(repository).parts
            and not any(ord(value) < 32 or ord(value) == 127 for value in repository),
            "materialization_source_location")
    host = location["host"]
    require(isinstance(host,dict) and set(host) == {"system","machine","node"}
            and all(isinstance(value,str) and value
                    and not any(ord(character) < 32 or ord(character) == 127 for character in value)
                    for value in host.values()),"materialization_source_location")
    identity = location["root"]
    require(isinstance(identity,dict) and set(identity) == {"device","inode","uid","mode"}
            and all(type(value) is int and value >= 0 for value in identity.values())
            and identity["mode"] <= 0o777,"materialization_source_location")
    return {key:host[key] for key in ["system","machine"]}


def validate_materialization_inputs(manifest, memberships):
    """Admit only states the pinned no-follow source helper can reproduce."""
    inputs,details = manifest.get("inputs"),manifest.get("file_details")
    require(isinstance(inputs,list) and 0 < len(inputs) <= 100000
            and all(isinstance(item,dict) and isinstance(item.get("path"),str) for item in inputs),
            "materialization_source_inventory")
    paths = [item["path"] for item in inputs]
    require(paths == sorted(paths) and len({portable_path_key(name) for name in paths}) == len(paths),
            "materialization_source_inventory")
    require(isinstance(memberships,dict) and set(memberships) == set(paths)
            and all(value in {"tracked","nonignored-untracked"} for value in memberships.values()),
            "materialization_source_membership")
    require(isinstance(details,dict) and set(details) == {item["path"] for item in inputs if "sha256" in item},
            "materialization_file_details")
    links = []
    for item in inputs:
        name = item["path"]
        materialization_path(name)
        exclusion = materialization_exclusion(name)
        if "sha256" in item:
            require(not secret_source(name),"materialization_secret_bytes")
            require(set(item) == {"path","sha256"} and isinstance(item["sha256"],str)
                    and re.fullmatch(r"[a-f0-9]{64}",item["sha256"]),"materialization_source_inventory")
            require(exclusion is None,"materialization_source_policy")
            detail = details[name]
            require(isinstance(detail,dict) and set(detail) == {"mode","size"}
                    and type(detail["mode"]) is int and 0 <= detail["mode"] <= 0o777
                    and type(detail["size"]) is int and 0 <= detail["size"] <= 12*1024**3,
                    "materialization_file_details")
        elif item.get("content_coverage") == "metadata-only":
            state = item.get("state")
            fields = {"path","content_coverage","exclusion_reason","state"}
            require(state in {"file","directory","symlink","missing"},"materialization_source_inventory")
            if state != "missing":
                fields.add("mode")
                require(type(item.get("mode")) is int and 0 <= item["mode"] <= 0o777,
                        "materialization_source_inventory")
            if state == "symlink":
                if source_exclusion(name) is None:
                    fields.add("link_text")
                    require(isinstance(item.get("link_text"),str) and item["link_text"]
                            and "\0" not in item["link_text"],"materialization_source_inventory")
                    links.append(name)
            require(set(item) == fields,"materialization_source_inventory")
            reason = item["exclusion_reason"]
            require(reason == exclusion and exclusion is not None
                    or reason == "ignored-but-tracked" and memberships[name] == "tracked"
                       and source_exclusion(name) is None,"materialization_source_policy")
        elif "target" in item:
            require(set(item) == {"path","target","link_text"} and isinstance(item["target"],str)
                    and isinstance(item["link_text"],str) and item["link_text"]
                    and not PurePosixPath(item["link_text"]).is_absolute()
                    and "\\" not in item["link_text"]
                    and not any(ord(value) < 32 or ord(value) == 127 for value in item["link_text"])
                    and exclusion is None,"materialization_source_alias")
            materialization_path(item["target"])
            require(materialization_exclusion(item["target"]) is None,"materialization_source_alias")
            links.append(name)
        else:
            require(set(item) == {"path","deleted"} and item.get("deleted") is True
                    and exclusion is None,"materialization_source_inventory")
    for name in links:
        prefix = name+"/"
        index = bisect_left(paths,prefix)
        require(index == len(paths) or not paths[index].startswith(prefix),"materialization_source_alias")
    entries = materialized_entries(inputs,memberships)
    byte_names = {item["path"] for item in inputs if "sha256" in item}
    for item in inputs:
        if "target" not in item:
            continue
        try:
            target = snapshot_target(item["path"],entries,Path(manifest["source_location"]["repository"]))
        except ValueError as error:
            raise ValueError("qualification.materialization_source_alias") from error
        require(target == item["target"] and (target in byte_names
                or any(name.startswith(target+"/") for name in byte_names)),"materialization_source_alias")
    return entries


def audit_materialization_archive(root, reference, manifest):
    """Check a source-transfer payload without reading excluded original files."""
    expected = {item["path"]:item for item in manifest["inputs"] if "sha256" in item
                or "target" in item and "link_text" in item}
    require(not any(secret_source(name) for name in expected),"materialization_secret_bytes")
    details = manifest["file_details"]
    require(set(details) == {name for name,item in expected.items() if "sha256" in item},
            "materialization_file_details")
    manifest_name = SOURCE_MANIFEST_NAME
    seen = set()
    total = 0
    with regular_input(root/relative_path(reference["path"])) as stream:
        archive_bytes = os.fstat(stream.fileno()).st_size
        require(archive_bytes <= 12*1024**3,"materialization_archive_size")
        with tarfile.open(fileobj=stream,mode="r|") as archive:
            members = iter(archive)
            first = next(members,None)
            require(first is not None and first.name == manifest_name
                    and first.type in {tarfile.REGTYPE,tarfile.AREGTYPE}
                    and 0 < first.size <= 64*1024**2,"materialization_archive_manifest")
            metadata = archive.extractfile(first)
            require(metadata is not None,"materialization_archive_manifest")
            require(json.loads(metadata.read(),object_pairs_hook=closed_pairs,
                    parse_constant=lambda _:require(False,"nonfinite_json_number")) == manifest,
                    "materialization_archive_manifest")
            seen.add(manifest_name)
            for member in members:
                name = str(materialization_path(member.name))
                require(name not in seen and len(seen) <= 100000,"materialization_archive_inventory")
                seen.add(name)
                require(name in expected,"materialization_archive_inventory")
                item = expected[name]
                if "sha256" in item:
                    detail = details[name]
                    require(member.type in {tarfile.REGTYPE,tarfile.AREGTYPE}
                            and member.size == detail.get("size") and member.mode == detail.get("mode"),
                            "materialization_file_details")
                    total += member.size
                    require(total <= 12*1024**3,"materialization_archive_size")
                    digest = hashlib.sha256()
                    data = archive.extractfile(member)
                    require(data is not None,"materialization_archive_inventory")
                    for chunk in iter(lambda:data.read(1024*1024),b""):
                        digest.update(chunk)
                    require(digest.hexdigest() == item["sha256"],"materialization_archive_bytes")
                else:
                    require(member.type == tarfile.SYMTYPE and member.linkname == item["link_text"]
                            and member.size == 0,"materialization_archive_link")
        require(seen == {manifest_name,*expected},"materialization_archive_inventory")
        stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda:stream.read(1024*1024),b""):
            digest.update(chunk)
        require(digest.hexdigest() == reference["sha256"],"materialization_archive_bytes")
    return archive_bytes


def audit_source_origin(root, origin, sources, base_commit, candidate):
    """Join the original Git identity to actual private materialization receipts."""
    require(isinstance(origin,dict) and origin.get("base_commit") == base_commit
            and origin.get("source_binding") == candidate
            and isinstance(origin.get("original_repository"),str)
            and PurePosixPath(origin["original_repository"]).is_absolute()
            and PurePosixPath(origin["original_repository"]).as_posix() == origin["original_repository"]
            and ".." not in PurePosixPath(origin["original_repository"]).parts,
            "materialization_origin")
    stages = origin.get("stages")
    require(isinstance(stages,list) and 0 < len(stages) <= 4,"materialization_stage_inventory")
    # A late receiver success never replaces a failed or timed-out transport.
    for stage in stages:
        require(isinstance(stage,dict),"materialization_stage_inventory")
        if "transport" in stage:
            transport = artifact_json(root,stage["transport"])
            require(transport.get("schema") in {"chio.confined-source-snapshot.v1",MATERIALIZATION_SCHEMA}
                    and transport.get("status") == "transferred"
                    and type(transport.get("exit_code")) is int and transport["exit_code"] == 0
                    and type(transport.get("actual_transport_exit")) is int and transport["actual_transport_exit"] == 0,
                    "materialization_transport_exit")
    # Historical failed attempts remain failures; successful v1 records cannot
    # acquire physical source-location evidence by changing their envelope.
    require(origin.get("schema") == SOURCE_ORIGIN_SCHEMA,"materialization_origin")
    previous_guest = previous_location = None
    receipt = None
    for index,stage in enumerate(stages):
        before,after = (artifact_json(root,stage[key]) for key in ["host_before","host_after"])
        require(before == after,"materialization_source_bracket")
        source_platform = materialization_location(before.get("source_location"))
        if index == 0:
            require(before.get("git_identity",{}).get("head") == base_commit,"materialization_base_commit")
            require(before["source_location"]["repository"] == origin["original_repository"],
                    "materialization_source_location")
        else:
            require(before.get("git_identity",{}).get("head") is None
                    and before.get("inputs") == previous_guest,"materialization_source_chain")
            require(before["source_location"] == previous_location,"materialization_source_location")
        manifest = artifact_json(root,stage["manifest"])
        snapshot = artifact_json(root,stage["snapshot_result"])
        receipt = artifact_json(root,stage["receipt"])
        guest = artifact_json(root,stage["guest_inventory"])
        require(manifest.get("schema") == snapshot.get("schema") == receipt.get("schema")
                == MATERIALIZATION_SCHEMA,"materialization_record")
        require(snapshot.get("status") == "snapshotted" and snapshot.get("exit_code") == 0
                and type(snapshot.get("exit_code")) is int
                and receipt.get("status") == "received" and receipt.get("exit_code") == 0
                and type(receipt.get("exit_code")) is int,
                "materialization_exit")
        delivery = stage.get("delivery")
        require(delivery in {"local","transport"}
                and ("transport" in stage) is (delivery == "transport"),
                "materialization_delivery")
        require(isinstance(receipt.get("host"),dict) and set(receipt["host"]) == {"system","machine"}
                and all(isinstance(value,str) and value for value in receipt["host"].values())
                and type(receipt.get("uid")) is int and receipt["uid"] >= 0
                and type(receipt.get("native_profile_checked")) is bool,"materialization_receiver_identity")
        if delivery == "transport":
            require(receipt["host"] == {"system":"Linux","machine":"x86_64"}
                    and receipt["uid"] == 501 and receipt["native_profile_checked"] is True,
                    "materialization_receiver_identity")
        else:
            require(manifest.get("host_platform") == receipt["host"] == source_platform,
                    "materialization_receiver_identity")
        receipt_platform = materialization_location(receipt.get("location"))
        require(receipt_platform == receipt["host"]
                and receipt["location"]["repository"] == receipt.get("candidate")
                and receipt["location"]["root"]["uid"] == receipt["uid"]
                and receipt["location"]["root"]["mode"] == 0o700,"materialization_receiver_identity")
        require(manifest.get("source_location") == before["source_location"]
                and manifest.get("host_platform") == source_platform,"materialization_source_location")
        policy = manifest.get("policy")
        materialization_policy(policy)
        require(manifest.get("inputs") == before.get("inputs") and policy == before.get("policy")
                and manifest.get("file_details") == before.get("file_details"),"materialization_source_bracket")
        entries = validate_materialization_inputs(manifest,before.get("memberships"))
        source_digest = materialization_binding(policy,manifest["inputs"])
        require(source_digest == manifest.get("host_binding") == before.get("source_binding")
                == snapshot.get("host_binding") == receipt.get("host_binding")
                == receipt.get("normalized_guest_binding"),"materialization_source_bracket")
        for key in ["snapshot_id","runner_sha256","utility_sha256"]:
            require(manifest.get(key) == receipt.get(key),"materialization_receipt")
        require(snapshot.get("snapshot_id") == manifest.get("snapshot_id")
                and snapshot.get("payload_manifest_sha256") == stage["manifest"]["sha256"],"materialization_receipt")
        archive = stage["archive"]
        require(archive["sha256"] == snapshot.get("archive_sha256") == receipt.get("archive_sha256")
                and snapshot.get("archive_bytes") == receipt.get("archive_bytes"),"materialization_archive_bytes")
        for key in ["runner","utility"]:
            require(stage["tools"][key]["sha256"] == manifest[key+"_sha256"]
                    == sha(root/relative_path(stage["tools"][key]["path"])),"materialization_tool_binding")
        require(entries.get(MATERIALIZATION_RUNNER,{}).get("state") == "file"
                and entries[MATERIALIZATION_RUNNER]["sha256"] == manifest["runner_sha256"],
                "materialization_tool_binding")
        if delivery == "transport":
            transport = artifact_json(root,stage["transport"])
            require(transport.get("schema") == MATERIALIZATION_SCHEMA
                    and transport.get("archive_sha256") == archive["sha256"]
                    and transport.get("snapshot_id") == manifest["snapshot_id"]
                    and transport.get("host_binding") == manifest["host_binding"]
                    and transport.get("candidate") == receipt["candidate"],"materialization_transport_binding")
            require(transport.get("host_before_captured") is True and transport.get("host_after_captured") is True
                    and {"send_host_before","send_host_after","transport_stdout"} <= set(stage),
                    "materialization_transport_bracket")
            send_before,send_after = (artifact_json(root,stage[key]) for key in ["send_host_before","send_host_after"])
            require(send_before == send_after == before
                    and transport.get("source_location") == before["source_location"],"materialization_transport_bracket")
            require(artifact_json(root,stage["transport_stdout"]) == receipt,"materialization_transport_receipt")
        else:
            require(not {"send_host_before","send_host_after","transport_stdout"}.intersection(stage),
                    "materialization_delivery")
        archive_bytes = audit_materialization_archive(root,archive,manifest)
        require(type(snapshot.get("archive_bytes")) is int
                and archive_bytes == snapshot["archive_bytes"],"materialization_archive_bytes")
        require(isinstance(guest,list) and all(isinstance(item,dict) and isinstance(item.get("path"),str) for item in guest)
                and materialization_binding(policy,guest) == receipt.get("guest_binding")
                and type(receipt.get("input_paths")) is int and receipt["input_paths"] == len(guest),
                "materialization_guest_inventory")
        require([item["path"] for item in guest] == [item["path"] for item in manifest["inputs"]],
                "materialization_guest_inventory")
        adjustments = receipt.get("mode_adjustments")
        require(isinstance(adjustments,list) and all(isinstance(item,dict) and isinstance(item.get("path"),str)
                for item in adjustments) and len({item["path"] for item in adjustments}) == len(adjustments),
                "materialization_mode_adjustments")
        normalized = [dict(item) for item in guest]
        by_path = {item["path"]:item for item in normalized}
        for adjustment in adjustments:
            item = by_path.get(adjustment.get("path"),{})
            require(adjustment == {"path":item.get("path"),"field":"mode","host":0o755,"guest":0o777,
                    "reason":"Darwin/Linux metadata-only cache symlink mode"}
                    and item.get("mode") == 0o777 and item.get("content_coverage") == "metadata-only"
                    and item.get("state") == "symlink"
                    # Ignored tracked metadata retains its original exclusion
                    # reason. Cache eligibility is independently path-based.
                    and materialization_exclusion(item.get("path")) == "cache-tree-policy"
                    and manifest.get("host_platform",{}).get("system") == "Darwin"
                    and receipt.get("host",{}).get("system") == "Linux","materialization_mode_adjustments")
            item["mode"] = 0o755
        require(normalized == manifest["inputs"],"materialization_guest_inventory")
        audit_snapshot_sources({"entries":entries},sources,Path(origin["original_repository"]))
        previous_guest,previous_location = guest,receipt["location"]
    require(receipt is not None and Path(receipt["candidate"]).is_absolute(),"materialization_candidate")
    return receipt


def audit_materialized_capture(root, stage, snapshot):
    """Bind the complete received denominator, separately from the v3 projection."""
    guest = artifact_json(root,stage["guest_inventory"])
    manifest = artifact_json(root,stage["manifest"])
    actual = snapshot["entries"]
    require(set(actual) == {item["path"] for item in guest},"gate_materialized_sources")
    empty_blob = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    for item in guest:
        name = item["path"]
        entry = actual[name]
        require(isinstance(entry,dict) and entry.get("membership") == "tracked",
                "gate_materialized_sources")
        expected_index = [{"mode":"100644","stage":0}]
        excluded = item.get("content_coverage") == "metadata-only"
        if not excluded:
            expected_index[0]["object"] = empty_blob
        require(entry.get("index") == expected_index
                and (not excluded or entry.get("index_object_coverage") == "redacted-by-content-policy"),
                "gate_materialized_sources")
        if "sha256" in item:
            detail = manifest["file_details"][name]
            require(entry.get("state") == "file" and entry.get("content_coverage") == "sha256-bytes"
                    and entry.get("sha256") == item["sha256"] and type(entry.get("mode")) is int
                    and entry["mode"] == detail["mode"] and type(entry.get("size_bytes")) is int
                    and entry["size_bytes"] == detail["size"],"gate_materialized_sources")
        elif excluded:
            require(entry.get("state") == item["state"]
                    and (item["state"] == "missing" or entry.get("content_coverage") == "metadata-only"
                        and entry.get("exclusion_reason") == item["exclusion_reason"]
                        and type(entry.get("mode")) is int and entry["mode"] == item["mode"])
                    and not {"sha256","target","target_sha256","size_bytes"}.intersection(entry),
                    "gate_materialized_sources")
        elif "target" in item:
            require(entry.get("state") == "symlink" and entry.get("content_coverage") == "link-text-only"
                    and entry.get("target") == item["link_text"]
                    and entry.get("target_sha256") == hashlib.sha256(os.fsencode(item["link_text"])).hexdigest(),
                    "gate_materialized_sources")
        else:
            require(entry.get("state") == "missing"
                    and not {"sha256","target","target_sha256","size_bytes"}.intersection(entry),
                    "gate_materialized_sources")


@contextmanager
def compiler_namespace_directory(path):
    """Hold every directory component while checking one recorder namespace."""
    name = os.fspath(path)
    require(os.path.isabs(name) and ".." not in PurePosixPath(name).parts
            and PurePosixPath(name).as_posix() == name,"compiler_namespace")
    descriptors,parents = [],[]
    key = lambda value:(value.st_dev,value.st_ino,value.st_mode)
    try:
        descriptor = os.open("/",os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(descriptor)
        for component in PurePosixPath(name).parts[1:]:
            observed = os.stat(component,dir_fd=descriptor,follow_symlinks=False)
            child = os.open(component,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
                            dir_fd=descriptor)
            descriptors.append(child)
            require(key(observed) == key(os.fstat(child)),"compiler_namespace_changed")
            parents.append((descriptor,component,child,key(observed)))
            descriptor = child
        yield descriptor
        for parent,component,child,before in parents:
            require(key(os.fstat(child)) == before
                    == key(os.stat(component,dir_fd=parent,follow_symlinks=False)),"compiler_namespace_changed")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def compiler_json(stream):
    metadata = os.fstat(stream.fileno())
    require(metadata.st_nlink == 1 and 0 < metadata.st_size <= 16*1024**2,"compiler_publication")
    raw = stream.read(16*1024**2+1)
    require(len(raw) == metadata.st_size,"compiler_publication")
    value = json.loads(raw,object_pairs_hook=closed_pairs,
                       parse_constant=lambda _:require(False,"nonfinite_json_number"))
    require(isinstance(value,dict),"compiler_publication")
    return value,raw,{"device":metadata.st_dev,"inode":metadata.st_ino}


def compiler_metadata_identity(value):
    return (value.st_dev,value.st_ino,value.st_mode,value.st_size,
            value.st_mtime_ns,value.st_ctime_ns,value.st_nlink)


def audit_legacy_compiler_publications(namespace, source_binding):
    """Verify original physical publication, without claiming compiled closure.

    This independent consumer reads only retained rows/markers/artifacts. It
    never imports or executes the recorder and never reads named original
    compiler/source paths from a row. Copied evidence needs separate custody.
    """
    require(isinstance(source_binding,str) and re.fullmatch(r"[a-f0-9]{64}",source_binding),
            "compiler_source_binding")
    namespace = Path(namespace)
    verified,images,statuses,kinds = [],{}, {},{}
    artifact_bytes = 0
    record_metadata,marker_metadata,image_metadata = {},{},{}
    with compiler_namespace_directory(namespace) as _root, \
            compiler_namespace_directory(namespace/"records") as records, \
            compiler_namespace_directory(namespace/"completions") as completions, \
            compiler_namespace_directory(namespace/"artifacts") as artifacts:
        record_names,marker_names,artifact_names = (sorted(os.listdir(descriptor))
                                                    for descriptor in [records,completions,artifacts])
        names = [name for name in record_names if re.fullmatch(r"[a-f0-9]{32}\.json",name)]
        require(0 < len(names) <= 100000 and set(marker_names) == set(names),"compiler_publication_inventory")
        incomplete = [name for name in record_names if name.startswith(".incomplete-")]
        require(set(record_names) == {*names,*incomplete} and len(record_names) <= 100000
                and len(artifact_names) <= 100000 and all(re.fullmatch(r"[a-f0-9]{64}",name) for name in artifact_names),
                "compiler_publication_inventory")
        for name in names:
            with regular_input(namespace/"records"/name) as record_stream:
                row,raw,record_identity = compiler_json(record_stream)
                record_metadata[name] = compiler_metadata_identity(os.fstat(record_stream.fileno()))
                identifier = name[:-5]
                require(row.get("schema") == "chio.rust-compilation.v3"
                        and row.get("invocation_id") == identifier
                        and row.get("source_binding") == source_binding,"compiler_publication_binding")
                publication = row.get("publication")
                marker_path = "completions/"+name
                require(isinstance(publication,dict) and set(publication) == {"completion","marker_identity"}
                        and publication.get("completion") == marker_path,"compiler_publication_binding")
                with regular_input(namespace/marker_path) as marker_stream:
                    marker,marker_raw,marker_identity = compiler_json(marker_stream)
                    marker_metadata[name] = compiler_metadata_identity(os.fstat(marker_stream.fileno()))
                    for identity in [publication.get("marker_identity"),marker.get("record_identity")]:
                        require(isinstance(identity,dict) and set(identity) == {"device","inode"}
                                and all(type(value) is int and value >= 0 for value in identity.values()),
                                "compiler_publication_identity")
                    require(publication["marker_identity"] == marker_identity
                            and marker["record_identity"] == record_identity,"compiler_publication_identity")
                    expected = {"schema":"chio.rust-compilation-completion.v2","invocation_id":identifier,
                        "source_binding":source_binding,"record_sha256":hashlib.sha256(raw).hexdigest(),
                        "size":len(raw),"record_identity":record_identity}
                    require(marker == expected,"compiler_publication_binding")
                    kind,status = row.get("kind"),row.get("status")
                    require(kind in {"compilation","probe"} and status in
                            {"success","refused","compiler_failed","instrumentation_failed"},"compiler_record_outcome")
                    if status == "success":
                        require(type(row.get("compiler_exit")) is int and row["compiler_exit"] == 0
                                and row.get("refusal") is None,"compiler_record_outcome")
                    elif status == "compiler_failed":
                        require(type(row.get("compiler_exit")) is int and row["compiler_exit"] != 0,
                                "compiler_record_outcome")
                    inputs,outputs = row.get("inputs"),row.get("outputs")
                    require(isinstance(inputs,list) and isinstance(outputs,list)
                            and len(inputs)+len(outputs) <= 100000,"compiler_artifact_binding")
                    compiler = row.get("compiler")
                    for image in [*inputs,*outputs,*([compiler] if compiler is not None else [])]:
                        require(isinstance(image,dict) and isinstance(image.get("sha256"),str)
                                and re.fullmatch(r"[a-f0-9]{64}",image["sha256"])
                                and image.get("artifact") == "artifacts/"+image["sha256"]
                                and type(image.get("size")) is int and 0 <= image["size"] <= 512*1024**2,
                                "compiler_artifact_binding")
                        artifact = image["sha256"]
                        if artifact not in images:
                            with regular_input(namespace/image["artifact"]) as image_stream:
                                metadata = os.fstat(image_stream.fileno())
                                require(metadata.st_nlink == 1 and metadata.st_size <= 512*1024**2,
                                        "compiler_artifact_binding")
                                digest = hashlib.sha256()
                                count = 0
                                for chunk in iter(lambda:image_stream.read(1024*1024),b""):
                                    count += len(chunk)
                                    require(count <= metadata.st_size,"compiler_namespace_changed")
                                    digest.update(chunk)
                                require(count == metadata.st_size,"compiler_namespace_changed")
                                images[artifact] = {"sha256":digest.hexdigest(),"size":metadata.st_size}
                                image_metadata[artifact] = compiler_metadata_identity(metadata)
                                artifact_bytes += metadata.st_size
                                require(artifact_bytes <= 16*1024**3,
                                        "compiler_artifact_budget")
                        require(images[artifact] == {"sha256":artifact,"size":image["size"]},"compiler_artifact_binding")
                    statuses[status] = statuses.get(status,0)+1
                    kinds[kind] = kinds.get(kind,0)+1
                    verified.append({"invocation_id":identifier,"kind":kind,"status":status,
                        "record_sha256":expected["record_sha256"],"record_identity":record_identity,
                        "completion_sha256":hashlib.sha256(marker_raw).hexdigest(),"marker_identity":marker_identity})
        require(record_names == sorted(os.listdir(records)) and marker_names == sorted(os.listdir(completions))
                and artifact_names == sorted(os.listdir(artifacts)),"compiler_namespace_changed")
        for descriptor,observed in [(records,record_metadata),(completions,marker_metadata),(artifacts,image_metadata)]:
            for name,before in observed.items():
                require(compiler_metadata_identity(os.stat(name,dir_fd=descriptor,follow_symlinks=False)) == before,
                        "compiler_namespace_changed")
    return {"schema":"chio.compiler-publication-verification.v1","source_binding":source_binding,
        "coverage":"original-recorder-filesystem-namespace-only","verified_records":len(verified),
        "records":verified,"status_counts":statuses,"kind_counts":kinds,"incomplete_records":len(incomplete),
        "incomplete_records_coverage":"records-directory incomplete-prefix entries only; missing completion markers refuse verification",
        "verified_artifacts":len(images),"verified_artifact_bytes":artifact_bytes,
        "unreferenced_artifacts":len(set(artifact_names)-set(images)),
        "unreferenced_artifact_coverage":"names only; unreferenced content and file types are not verified",
        "compiled_closure_status":"not-established"}


def same_compilation_json(left, right):
    """Preserve JSON types when joining physically observed projections."""
    return compilation_canonical(left) == compilation_canonical(right)


COMPILER_CUSTODY_DESCRIPTOR_BUDGET = 32768
COMPILER_CUSTODY_DESCRIPTOR_RESERVE = 128


def original_compiler_descriptor_capacity(namespace):
    """Require measured capacity before retained-byte reads; never raise a limit."""
    try:
        import resource
    except ImportError:
        require(False,"compiler_descriptor_capacity")
    namespace = Path(namespace)
    require(namespace.is_absolute() and ".." not in namespace.parts, "compiler_descriptor_namespace")
    leaves = 0
    with ExitStack() as stack:
        stack.enter_context(compiler_namespace_directory(namespace))
        for name in ["artifacts", "records", "completions", "batches"]:
            descriptor = stack.enter_context(compiler_namespace_directory(namespace/name))
            names = os.listdir(descriptor)
            require(len(names) <= 200000, "compiler_descriptor_namespace")
            for leaf in names:
                metadata = os.stat(leaf,dir_fd=descriptor,follow_symlinks=False)
                require(stat.S_ISREG(metadata.st_mode), "compiler_descriptor_namespace")
            leaves += len(names)
    # Compiler readers share original ancestor descriptors and retain one
    # original regular-file descriptor per live image. Reserve covers the
    # fixed input/configuration/log joins around that closed namespace.
    ancestry = len(namespace.parts) + 4
    descriptor_directory = Path("/proc/self/fd") if platform.system() == "Linux" else Path("/dev/fd")
    open_names = os.listdir(descriptor_directory)
    require(all(name.isdecimal() for name in open_names), "compiler_descriptor_capacity")
    existing = len(open_names)
    needed = existing + leaves + ancestry + COMPILER_CUSTODY_DESCRIPTOR_RESERVE
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    require(type(soft) is int and type(hard) is int and soft > 0 and hard >= soft
            and needed <= COMPILER_CUSTODY_DESCRIPTOR_BUDGET and needed <= soft,
            "compiler_descriptor_capacity")
    return {"schema":"chio.original-compiler-descriptor-capacity.v1",
            "namespace":str(namespace), "regular_namespace_leaves":leaves,
            "observed_open_descriptors":existing,
            "ancestry_descriptors":ancestry, "reserved_descriptors":COMPILER_CUSTODY_DESCRIPTOR_RESERVE,
            "required_descriptors":needed, "descriptor_budget":COMPILER_CUSTODY_DESCRIPTOR_BUDGET,
            "observed_soft_limit":soft, "observed_hard_limit":hard, "limit_changed":False}


@contextmanager
def compiler_input_custody():
    """Share held no-follow ancestors while preserving every held regular leaf."""
    directories = {}
    ancestry = []
    opened = []
    def directory(path):
        path = Path(path)
        if path in directories:
            return directories[path]
        if path == Path("/"):
            descriptor = os.open("/",os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            opened.append(descriptor)
            directories[path] = descriptor
            return descriptor
        parent = directory(path.parent)
        located = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        descriptor = os.open(path.name,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=parent)
        opened.append(descriptor)
        identity = compiler_metadata_identity(os.fstat(descriptor))[:3]
        require(identity == compiler_metadata_identity(located)[:3], "compiler_namespace_changed")
        directories[path] = descriptor
        ancestry.append((parent,path.name,descriptor,identity))
        return descriptor
    @contextmanager
    def regular(path):
        path = Path(path)
        require(path.is_absolute() and ".." not in path.parts, "compiler_namespace")
        parent = directory(path.parent)
        located = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        descriptor = os.open(path.name,os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,dir_fd=parent)
        stream = os.fdopen(descriptor,"rb")
        try:
            actual = os.fstat(descriptor)
            identity = compiler_metadata_identity(actual)
            require(stat.S_ISREG(actual.st_mode) and actual.st_nlink == 1
                    and identity == compiler_metadata_identity(located), "compiler_namespace_changed")
            yield stream
            require(compiler_metadata_identity(os.fstat(descriptor)) == identity
                    == compiler_metadata_identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),
                    "compiler_namespace_changed")
        finally:
            stream.close()
    try:
        yield regular
        for parent,name,descriptor,identity in ancestry:
            require(compiler_metadata_identity(os.fstat(descriptor))[:3] == identity
                    == compiler_metadata_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))[:3],
                    "compiler_namespace_changed")
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def current_compiler_publications(base, namespace, source_binding):
    """Read original v4/v3 pairs and batches without claiming past fsync success."""
    require(type(source_binding) is str and re.fullmatch(r"[a-f0-9]{64}", source_binding), "compiler_source_binding")
    namespace = Path(namespace)
    with ExitStack() as stack:
        directories = {name: stack.enter_context(base.compiler_namespace_directory(namespace/name))
                       for name in ["records", "completions", "artifacts", "batches"]}
        stack.enter_context(base.compiler_namespace_directory(namespace))
        names = {name: sorted(os.listdir(descriptor)) for name, descriptor in directories.items()}
        records = [name for name in names["records"] if re.fullmatch(r"[a-f0-9]{32}\.json", name)]
        incomplete = [name for name in names["records"] if name.startswith(".incomplete-")]
        require(0 <= len(records) <= 100000 and set(names["records"]) == {*records, *incomplete}
                and len(names["records"]) <= 100000 and names["completions"] == records,
                "compiler_publication_inventory")
        require(len(names["artifacts"]) <= 100000
                and all(re.fullmatch(r"[a-f0-9]{64}", name) for name in names["artifacts"]),
                "compiler_publication_inventory")
        require(len(names["batches"]) <= 200000 and all(
            re.fullmatch(r"[a-f0-9]{32}\.(?:start|complete)\.json", name) for name in names["batches"]),
            "compiler_retention_batch")
        observed, decoded, images = {}, {}, {}
        total_bytes = 0

        def read_json(relative):
            if relative in decoded:
                return decoded[relative]
            stream = stack.enter_context(base.regular_input(namespace/relative))
            value, raw, identity = base.compiler_json(stream)
            metadata = base.compiler_metadata_identity(os.fstat(stream.fileno()))
            require(metadata[-1] == 1, "compiler_publication_identity")
            reference = {"path": relative, "sha256": hashlib.sha256(raw).hexdigest(),
                         "size": len(raw), "identity": identity}
            observed[relative] = (stream, metadata, reference["sha256"])
            decoded[relative] = value, reference
            return decoded[relative]

        def read_image(image):
            nonlocal total_bytes
            require(type(image) is dict and type(image.get("sha256")) is str
                    and re.fullmatch(r"[a-f0-9]{64}", image["sha256"])
                    and image.get("artifact") == "artifacts/"+image["sha256"]
                    and type(image.get("size")) is int and 0 <= image["size"] <= 512*1024**2,
                    "compiler_artifact_binding")
            relative = image["artifact"]
            if relative not in images:
                stream = stack.enter_context(base.regular_input(namespace/relative))
                info = os.fstat(stream.fileno())
                require(info.st_nlink == 1 and info.st_size == image["size"], "compiler_artifact_binding")
                total_bytes += info.st_size
                require(total_bytes <= 16*1024**3, "compiler_artifact_budget")
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024*1024), b""):
                    digest.update(chunk)
                require(digest.hexdigest() == image["sha256"], "compiler_artifact_binding")
                identity = base.compiler_metadata_identity(info)
                observed[relative] = (stream, identity, image["sha256"])
                images[relative] = {"sha256": image["sha256"], "size": info.st_size, "identity": list(identity)}
            require(images[relative]["sha256"] == image["sha256"] and images[relative]["size"] == image["size"],
                    "compiler_artifact_binding")
            return images[relative]

        # Retained batches describe earlier snapshots, not the whole live CAS.
        # Every original namespace member contributes to custody and quotas.
        for name in names["artifacts"]:
            info = os.stat(name, dir_fd=directories["artifacts"], follow_symlinks=False)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and 0 <= info.st_size <= 512*1024**2, "compiler_artifact_binding")
            read_image({"artifact": "artifacts/"+name, "sha256": name, "size": info.st_size})

        def snapshot(value):
            require(type(value) is dict and set(value) == {"artifacts", "content_bytes", "record_count"}
                    and type(value["content_bytes"]) is int and 0 <= value["content_bytes"] <= 16*1024**3
                    and type(value["record_count"]) is int and 0 <= value["record_count"] <= len(records)
                    and type(value["artifacts"]) is list and len(value["artifacts"]) <= 100000,
                    "compiler_retention_batch")
            hashes = []
            for image in value["artifacts"]:
                require(type(image) is dict and set(image) == {"artifact", "sha256", "size", "identity"}
                        and type(image["identity"]) is list and len(image["identity"]) == 7
                        and all(type(part) is int and part >= 0 for part in image["identity"]),
                        "compiler_retention_batch")
                require(read_image(image)["identity"] == image["identity"], "compiler_retention_batch_identity")
                hashes.append(image["sha256"])
            require(hashes == sorted(set(hashes)) and sum(image["size"] for image in value["artifacts"])
                    == value["content_bytes"], "compiler_retention_batch")
            return {image["sha256"]: image for image in value["artifacts"]}

        batches = {}
        identifiers = sorted({name.split(".")[0] for name in names["batches"]})
        require(len(names["batches"]) == 2*len(identifiers), "compiler_retention_batch")
        for identifier in identifiers:
            start_path, complete_path = "batches/"+identifier+".start.json", "batches/"+identifier+".complete.json"
            require(Path(start_path).name in names["batches"] and Path(complete_path).name in names["batches"],
                    "compiler_retention_batch")
            start, start_ref = read_json(start_path)
            complete, complete_ref = read_json(complete_path)
            require(type(start) is dict and set(start) == {"schema", "batch_id", "source_binding", "before", "completion_identity"}
                    and start["schema"] == "chio.compiler-retention-batch-start.v1"
                    and type(complete) is dict and set(complete) == {"schema", "batch_id", "source_binding", "start", "before_sha256", "after", "retained"}
                    and complete["schema"] == "chio.compiler-retention-batch-complete.v1"
                    and start["batch_id"] == complete["batch_id"] == identifier
                    and start["source_binding"] == complete["source_binding"] == source_binding
                    and same_compilation_json(start["completion_identity"], complete_ref["identity"])
                    and same_compilation_json(complete["start"], start_ref)
                    and complete["before_sha256"] == hashlib.sha256(compilation_canonical(start["before"])).hexdigest(),
                    "compiler_retention_batch")
            before, after = snapshot(start["before"]), snapshot(complete["after"])
            require(start["before"]["record_count"] == complete["after"]["record_count"]
                    and all(same_compilation_json(after.get(key), value) for key, value in before.items())
                    and same_compilation_json(complete["retained"], [after[key] for key in sorted(set(after)-set(before))]),
                    "compiler_retention_batch")
            batches[identifier] = {"batch_id": identifier, "source_binding": source_binding,
                                   "start": start_ref, "complete": complete_ref}

        verified, units, statuses, kinds = [], {}, {}, {}
        for name in records:
            row, reference = read_json("records/"+name)
            marker, marker_reference = read_json("completions/"+name)
            identifier = name[:-5]
            require(type(row) is dict and row.get("schema") == "chio.rust-compilation.v4"
                    and row.get("invocation_id") == identifier and row.get("source_binding") == source_binding,
                    "compiler_publication_binding")
            publication = row.get("publication")
            require(type(publication) is dict and same_compilation_json(publication, {
                "completion": marker_reference["path"], "marker_identity": marker_reference["identity"]}),
                "compiler_publication_identity")
            require(same_compilation_json(marker, {"schema": "chio.rust-compilation-completion.v3", "invocation_id": identifier,
                "source_binding": source_binding, "record_sha256": reference["sha256"], "size": reference["size"],
                "record_identity": reference["identity"]}), "compiler_publication_binding")
            retained = row.get("retention_batches")
            require(type(retained) is list and len(retained) <= 100000
                    and all(type(value) is dict and type(value.get("batch_id")) is str
                            and same_compilation_json(batches.get(value["batch_id"]), value) for value in retained)
                    and [value["batch_id"] for value in retained] == sorted({value["batch_id"] for value in retained}),
                    "compiler_retention_batch")
            kind, status = row.get("kind"), row.get("status")
            require(type(kind) is str and type(status) is str
                    and kind in {"compilation", "probe"} and status in
                    {"success", "refused", "compiler_failed", "instrumentation_failed"}
                    and (row.get("compiler_exit") is None or type(row.get("compiler_exit")) is int),
                    "compiler_record_outcome")
            if status == "success":
                require(type(row.get("compiler_exit")) is int and row["compiler_exit"] == 0
                        and row.get("refusal") is None, "compiler_record_outcome")
            if status == "compiler_failed":
                require(type(row.get("compiler_exit")) is int and row["compiler_exit"] != 0, "compiler_record_outcome")
            inputs, outputs, depfiles = (row.get(key) for key in ["inputs", "outputs", "depfiles"])
            require(type(inputs) is list and type(outputs) is list and type(depfiles) is list
                    and len(inputs)+len(outputs)+len(depfiles) <= 100000, "compiler_artifact_binding")
            for image in [*inputs, *outputs, *([row["compiler"]] if row.get("compiler") is not None else [])]:
                read_image(image)
            units[identifier] = {"schema": "chio.rust-unit-publication-outcome.v1", "source_binding": source_binding,
                "invocation_id": identifier, "kind": kind, "record_status": status, "compiler_exit": row.get("compiler_exit"),
                "record": reference, "completion": marker_reference,
                "unit_images_sha256": hashlib.sha256(compilation_canonical({key: row[key]
                    for key in ["compiler", "inputs", "outputs", "depfiles"]})).hexdigest(),
                "physical_status": "complete"}
            statuses[status], kinds[kind] = statuses.get(status, 0)+1, kinds.get(kind, 0)+1
            verified.append({"invocation_id": identifier, "kind": kind, "status": status,
                "record_sha256": reference["sha256"], "record_identity": reference["identity"],
                "completion_sha256": marker_reference["sha256"], "marker_identity": marker_reference["identity"]})
        for name, descriptor in directories.items():
            require(names[name] == sorted(os.listdir(descriptor)), "compiler_namespace_changed")
        for relative, (stream, identity, expected) in observed.items():
            require(base.compiler_metadata_identity(os.fstat(stream.fileno())) == identity
                    and base.compiler_metadata_identity(os.stat(namespace/relative, follow_symlinks=False)) == identity,
                    "compiler_namespace_changed")
            stream.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024*1024), b""):
                digest.update(chunk)
            require(digest.hexdigest() == expected, "compiler_namespace_changed")
    return {"schema": "chio.compiler-publication-verification.v2", "source_binding": source_binding,
            "coverage": "original-recorder-filesystem-namespace-only", "verified_records": len(verified),
            "records": verified, "status_counts": statuses, "kind_counts": kinds, "incomplete_records": len(incomplete),
            "verified_artifacts": len(images), "verified_artifact_bytes": total_bytes,
            "retention_batches": [batches[key] for key in sorted(batches)], "unit_publications": units,
            "durability_coverage": "physical-only-durability-unknown; actual outside required-sync observations mandatory",
            "compiled_closure_status": "not-established"}


def current_required_sync_observations(publication, stderr):
    """Join actual outside stream bytes; this pure join alone is not authority."""
    require(type(stderr) is bytes and len(stderr) <= 64*1024**2, "compiler_outer_observation")
    prefixes = {b"compilation_recorder.retention_batch_outcome=": "batch",
                b"compilation_recorder.unit_publication_outcome=": "unit"}
    batches, units = {}, {}
    for line in stderr.splitlines():
        prefix = next((prefix for prefix in prefixes if line.startswith(prefix)), None)
        if prefix is None:
            continue
        def closed_pairs(pairs):
            value = {}
            for key, item in pairs:
                require(key not in value, "compiler_outer_observation")
                value[key] = item
            return value
        value = json.loads(line[len(prefix):], object_pairs_hook=closed_pairs,
                           parse_constant=lambda _: require(False, "compiler_outer_observation"))
        require(compilation_canonical(value) == line[len(prefix):] and type(value) is dict
                and value.get("source_binding") == publication["source_binding"]
                and value.get("physical_status") == "complete"
                and value.get("durability") == {"status": "confirmed", "phase": "completion-directory-fsync", "errno": None},
                "compiler_required_sync_observation")
        if prefixes[prefix] == "batch":
            require(set(value) == {"schema", "source_binding", "batch_id", "start", "complete", "physical_status", "durability", "declaration_emitted"}
                    and value["schema"] == "chio.compiler-retention-batch-outcome.v1" and value["declaration_emitted"] is False,
                    "compiler_required_sync_observation")
            expected = next((batch for batch in publication["retention_batches"] if batch["batch_id"] == value["batch_id"]), None)
            require(expected is not None and same_compilation_json({key: value[key] for key in expected}, expected)
                    and value["batch_id"] not in batches, "compiler_required_sync_observation")
            batches[value["batch_id"]] = value
        else:
            expected = publication["unit_publications"].get(value.get("invocation_id"))
            require(expected is not None and set(value) == set(expected) | {"durability"}
                    and same_compilation_json({key: value[key] for key in expected}, expected)
                    and value["invocation_id"] not in units, "compiler_required_sync_observation")
            units[value["invocation_id"]] = value
    require(set(units) == set(publication["unit_publications"])
            and set(batches) == {batch["batch_id"] for batch in publication["retention_batches"]},
            "compiler_required_sync_observation")
    return {"batch_outcomes": batches, "unit_outcomes": units,
            "scope": "Decoded required-sync joins only; actual enclosing argv/source/image/exit and original stream custody required."}


def checked_public_compilation_count(publications, name):
    """Count actual parser units; metadata probes cannot replace compiled units."""
    records = publications.get("records") if type(publications) is dict else None
    units = publications.get("unit_publications") if type(publications) is dict else None
    require(type(records) is list and type(units) is dict
            and all(type(row) is dict and type(row.get("invocation_id")) is str
                    and type(row.get("kind")) is str and row["kind"] in {"compilation","probe"}
                    and type(row.get("status")) is str
                    and row["status"] in {"success","refused","compiler_failed","instrumentation_failed"}
                    for row in records), "micro_primary_compilations")
    identifiers = [row["invocation_id"] for row in records]
    require(len(set(identifiers)) == len(identifiers) and set(identifiers) == set(units),
            "micro_primary_compilations")
    compiled = 0
    for row in records:
        unit = units[row["invocation_id"]]
        require(type(unit) is dict and unit.get("kind") == row["kind"]
                and unit.get("record_status") == row["status"]
                and (unit.get("compiler_exit") is None or type(unit["compiler_exit"]) is int),
                "micro_primary_compilations")
        if row["status"] == "success":
            require(type(unit.get("compiler_exit")) is int and unit["compiler_exit"] == 0,
                    "micro_primary_compilations")
            compiled += row["kind"] == "compilation"
        elif row["status"] == "compiler_failed":
            require(type(unit.get("compiler_exit")) is int and unit["compiler_exit"] != 0,
                    "micro_primary_compilations")
    require(name in PRIMARY_COMPILER_PROBES and (name not in {"gnu-native","musl-static-pie"}
            or compiled >= (2 if name == "gnu-native" else 1)), "micro_primary_compilations")
    return compiled


def audit_compiler_publications(namespace, source_binding):
    """Current physical observations and explicit historical format handling."""
    namespace = Path(namespace)
    try:
        metadata = os.stat(namespace/"batches",follow_symlinks=False)
    except FileNotFoundError:
        return audit_legacy_compiler_publications(namespace,source_binding)
    require(stat.S_ISDIR(metadata.st_mode),"compiler_namespace")
    original_compiler_descriptor_capacity(namespace)
    with compiler_input_custody() as inputs:
        primitives = SimpleNamespace(compiler_namespace_directory=compiler_namespace_directory,
            regular_input=inputs,compiler_json=compiler_json,compiler_metadata_identity=compiler_metadata_identity)
        return current_compiler_publications(primitives,namespace,source_binding)


def compiler_graph_image(image):
    require(isinstance(image,dict) and isinstance(image.get("path"),str),"compiler_graph_image")
    name = image["path"]
    require(name.startswith("/") and not name.startswith("//")
            and ".." not in PurePosixPath(name).parts and PurePosixPath(name).as_posix() == name
            and re.fullmatch(r"[a-f0-9]{64}",image.get("sha256",""))
            and type(image.get("size")) is int and 0 <= image["size"] <= COMPILED_IMAGE_MAX_BYTES,
            "compiler_graph_image")
    return name,image["sha256"],image["size"]


def compilation_canonical(value):
    """Match the retained compiler-record encoding, independently of its tool."""
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode()


def compilation_json_image(value):
    raw = compilation_canonical(value)+b"\n"
    digest = hashlib.sha256(raw).hexdigest()
    return {"sha256":digest,"size":len(raw),"artifact":"artifacts/"+digest}


def compilation_absolute_path(value):
    require(isinstance(value,str) and value.startswith("/") and not value.startswith("//")
            and "\x00" not in value and ".." not in PurePosixPath(value).parts
            and str(PurePosixPath(value)) == value,"compilation_scope_path")
    return PurePosixPath(value)


def compilation_image_path(name, aliases):
    path = compilation_absolute_path(name)
    seen = set()
    for _ in range(128):
        match = next((alias for alias in aliases if path == Path(alias["path"])
                      or path.is_relative_to(Path(alias["path"]))), None)
        if match is None:
            return str(path)
        key = (str(path), match["path"])
        require(key not in seen, "micro_alias_cycle")
        seen.add(key)
        path = Path(match["target"]) / path.relative_to(Path(match["path"]))
    require(False, "micro_alias_cycle")

def audit_compilation_aliases(configuration, readonly):
    aliases = configuration["aliases"]
    require(type(aliases) is list and len(aliases) <= 128, "micro_aliases")
    paths = set()
    roots = [compilation_absolute_path(scope["root"]) for scope in configuration["scopes"]]
    denied = [compilation_absolute_path(path) for path in configuration["write_roots"]
              + [configuration["records"], configuration["evidence"]]]
    for alias in aliases:
        require(type(alias) is dict and set(alias) in [{"path","text","target"},
                {"path","text","target","purpose"}] and type(alias["text"]) is str,
                "micro_aliases")
        path, target = map(compilation_absolute_path, [alias["path"],alias["target"]])
        require(str(path) not in paths and not any(path.is_relative_to(root)
                or target.is_relative_to(root) for root in denied)
                and any(target.is_relative_to(root) or root.is_relative_to(target) for root in roots),
                "micro_aliases")
        paths.add(str(path))
        if "purpose" in alias:
            require(alias["purpose"] == "public-system-elf-loader", "micro_loader_alias")
            if path.name == "lib64":
                require(alias["text"] == "usr/lib64" and target == path.parent/"usr/lib64",
                        "micro_loader_alias")
            else:
                require(path.parts[-3:] == ("usr","lib64","ld-linux-x86-64.so.2")
                        and alias["text"] == "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
                        and target == path.parent.parent/"lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                        "micro_loader_alias")
                require({"path":str(path.parent.parent.parent/"lib64"), "text":"usr/lib64",
                         "target":str(path.parent), "purpose":alias["purpose"]} in aliases,
                        "micro_loader_alias_pair")
        else:
            text = alias["text"]
            require(text and "\x00" not in text and ".." not in PurePosixPath(text).parts,
                    "micro_aliases")
            require(compilation_absolute_path(str(path.parent/text) if not text.startswith("/") else text)
                    == target, "micro_aliases")
    return sorted(aliases, key=lambda row:len(PurePosixPath(row["path"]).parts), reverse=True)

def audit_compilation_alias_chains(configuration, declaration, readonly, aliases):
    declared = configuration["aliases"]
    chains = declaration.get("alias_chains", [])
    require(type(chains) is list and len(chains) == len(declared), "micro_loader_chains")
    for alias, chain in zip(declared, chains):
        require(type(chain) is dict and set(chain) == {"path","immediate_target","resolved","purpose","hops"}
                and chain["path"] == alias["path"] and chain["immediate_target"] == alias["target"]
                and chain["resolved"] == compilation_image_path(alias["path"], aliases)
                and chain["purpose"] == alias.get("purpose","declared-alias") and type(chain["hops"]) is list
                and 1 <= len(chain["hops"]) <= 256, "micro_loader_chains")
        require(any(hop.get("kind") == "link" and hop.get("path") == alias["path"]
                    and hop.get("text") == alias["text"] for hop in chain["hops"] if type(hop) is dict),
                "micro_loader_chain_hop")
        for hop in chain["hops"]:
            require(type(hop) is dict and hop.get("kind") in {"directory","regular","link"},
                    "micro_loader_chains")
            kind = hop["kind"]
            require(set(hop) == {"path","kind","identity"} | ({"text"} if kind == "link" else set()),
                    "micro_loader_chains")
            compilation_absolute_path(hop["path"])
            identity = hop["identity"]
            require(type(identity) is list and len(identity) == (3 if kind == "directory" else 7)
                    and all(type(value) is int and value >= 0 for value in identity), "micro_loader_chains")
            if kind == "link":
                require(any(entry["path"] == hop["path"] and entry["text"] == hop["text"]
                            for entry in declared), "micro_loader_chain_hop")
        terminal = chain["hops"][-1]
        require(terminal["path"] == chain["resolved"] and terminal["kind"] in {"directory","regular"},
                "micro_loader_chains")
        if terminal["kind"] == "regular":
            require(terminal["path"] in readonly, "micro_loader_terminal")
    return chains

def audit_compilation_targets(configuration, declaration, readonly, aliases):
    targets = configuration.get("supported_targets", [])
    retained = declaration.get("targets")
    require(type(targets) is list and type(retained) is list and len(targets) == len(retained) <= 2,
            "micro_targets")
    selected = configuration.get("linker_selection")
    if selected is not None:
        require(type(selected) is dict and set(selected) == {"schema","mode","profile","targets"}
                and selected["schema"] == "chio.compiler-linker-selection.v1"
                and selected["mode"] == "declared-driver-if-missing"
                and selected["profile"] == "explicit-instrumented-compiler"
                and type(selected["targets"]) is list and 0 < len(selected["targets"]) == len(targets),
                "micro_linker_selection")
    for target, observed in zip(targets, retained):
        require(type(target) is dict and set(target) == {"triple","sysroot","library_root","crt_members"}
                and target["triple"] in {"x86_64-unknown-linux-gnu","x86_64-unknown-linux-musl"}
                and type(observed) is dict and set(observed) == {"triple","sysroot","library_root","crt_members","libraries"}
                    | ({"linker_driver"} if selected is not None else set())
                and all(target[key] == observed[key] for key in ["triple","sysroot","library_root"]), "micro_targets")
        library = compilation_absolute_path(target["library_root"])
        require(library == compilation_absolute_path(target["sysroot"])/"lib/rustlib"/target["triple"]/"lib",
                "micro_targets")
        def ref(member):
            return {key:member[key] for key in ["path","sha256","size","artifact"]}
        expected_libraries = [ref(value) for path,value in sorted(readonly.items()) if Path(path).is_relative_to(library)]
        require(bool(expected_libraries) and observed["libraries"] == expected_libraries
                and type(target["crt_members"]) is list and bool(target["crt_members"])
                and len(target["crt_members"]) == len(set(target["crt_members"]))
                and all(path in readonly and path.endswith((".a",".o")) for path in target["crt_members"])
                and observed["crt_members"] == [ref(readonly[path]) for path in target["crt_members"]], "micro_targets")
        if selected is not None:
            entry = next((item for item in selected["targets"] if item.get("triple") == target["triple"]), None)
            require(type(entry) is dict and set(entry) == set(target) | {"driver"}
                    and all(entry[key] == target[key] for key in target)
                    and type(entry["driver"]) is dict and set(entry["driver"]) == {"path","sha256"}, "micro_linker_selection")
            driver = compilation_image_path(entry["driver"]["path"], aliases)
            require(driver in readonly and readonly[driver]["sha256"] == entry["driver"]["sha256"]
                    and observed["linker_driver"] == ref(readonly[driver]), "micro_linker_selection")

def compilation_target(arguments):
    target = None
    consumed = {"--crate-name","--edition","--emit","--crate-type","--out-dir","--sysroot","--extern",
                "-L","-l","-C","-o","--cfg","--check-cfg","--cap-lints","--error-format","--json",
                "--color","--remap-path-prefix","--print","--target"}
    index = 1
    while index < len(arguments):
        option = arguments[index]
        if option in consumed:
            require(index+1 < len(arguments), "micro_compiler_arguments")
            value = arguments[index+1]
            if option == "--target":
                require(target is None, "micro_compiler_arguments")
                target = value
            index += 2
        else:
            if option.startswith("--target="):
                require(target is None, "micro_compiler_arguments")
                target = option[len("--target="):]
            index += 1
    return target or "x86_64-unknown-linux-gnu"

def compilation_explicit_linkers(arguments):
    """Read only actual consumed codegen flags, never option-value substrings."""
    consumed = {"--crate-name","--edition","--emit","--crate-type","--out-dir","--sysroot","--extern",
                "-L","-l","-C","-o","--cfg","--check-cfg","--cap-lints","--error-format","--json",
                "--color","--remap-path-prefix","--print","--target"}
    linkers = []
    index = 1
    while index < len(arguments):
        option = arguments[index]
        codegen = None
        if option in consumed:
            require(index+1 < len(arguments), "micro_compiler_arguments")
            if option == "-C":
                codegen = arguments[index+1]
            index += 2
        else:
            if option.startswith("-C"):
                codegen = option[2:]
            index += 1
        if codegen is not None and codegen.split("=",1)[0] == "linker":
            require(codegen.startswith("linker=") and bool(codegen[len("linker="):]),
                    "micro_compiler_driver")
            linkers.append(codegen[len("linker="):])
    require(len(linkers) <= 1, "micro_compiler_driver")
    return linkers

def audit_native_compiler_output(output, read_raw):
    """Join complete bounded output bytes to an outside-owned native dispatch."""
    require(type(output) is dict and set(output) == {"schema","status","refusal","observed_bytes","eof",
            "elapsed_seconds","cleanup","policy","stdout","stderr"}
            and output["schema"] == "chio.native-compiler-output.v1"
            and output["status"] == "complete" and output["refusal"] is None and output["cleanup"] is None
            and type(output["elapsed_seconds"]) in {int,float} and 0 <= output["elapsed_seconds"] <= 180
            and type(output["policy"]) is dict
            and set(output["policy"]) == {"maximum_bytes_per_stream","execution_and_cleanup_seconds",
                                         "cleanup_reserve_seconds","raw_diagnostics_forwarded"}
            and type(output["policy"]["maximum_bytes_per_stream"]) is int
            and output["policy"]["maximum_bytes_per_stream"] == 16*1024**2
            and type(output["policy"]["execution_and_cleanup_seconds"]) is int
            and output["policy"]["execution_and_cleanup_seconds"] == 180
            and type(output["policy"]["cleanup_reserve_seconds"]) is int
            and output["policy"]["cleanup_reserve_seconds"] == 1
            and output["policy"]["raw_diagnostics_forwarded"] is False
            and type(output["observed_bytes"]) is dict and set(output["observed_bytes"]) == {"stdout","stderr"}
            and type(output["eof"]) is dict and set(output["eof"]) == {"stdout","stderr"}
            and callable(read_raw), "micro_compiler_output")
    for name in ["stdout","stderr"]:
        reference = output[name]
        require(type(reference) is dict and set(reference) == {"artifact","sha256","size"}
                and type(reference["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}",reference["sha256"])
                and reference["artifact"] == "artifacts/"+reference["sha256"]
                and type(reference["size"]) is int and 0 <= reference["size"] <= 16*1024**2
                and type(output["observed_bytes"][name]) is int
                and output["observed_bytes"][name] == reference["size"] and output["eof"][name] is True,
                "micro_compiler_output")
        raw = read_raw(reference)
        require(type(raw) is bytes and len(raw) == reference["size"]
                and hashlib.sha256(raw).hexdigest() == reference["sha256"], "micro_compiler_output_bytes")


def audit_compilation_dispatches(namespace, configuration, declaration, events, publications, read, retained,
                                read_raw=None, retained_raw=None):
    require(type(events) is dict and set(events) == {"schema","events"}
            and type(events["schema"]) is str
            and events["schema"] in {"chio.compilation-supervisor-events.v1","chio.compilation-supervisor-events.v2"},
            "micro_supervisor_events")
    require(type(events["events"]) is list and len(events["events"]) <= 100000, "micro_supervisor_events")
    captured = events["schema"] == "chio.compilation-supervisor-events.v2"
    available = {row["invocation_id"]:row for row in publications["records"]}
    joined = set()
    verified = 0
    candidate = compilation_absolute_path(configuration["candidate"])
    aliases = sorted(configuration["aliases"], key=lambda row:len(PurePosixPath(row["path"]).parts), reverse=True)
    for event in events["events"]:
        require(type(event) is dict and set(event) == {"request_sha256","id","exit","recorder_exit",
                "response","refusal","dispatches","records"}
                and re.fullmatch(r"[a-f0-9]{64}",event.get("request_sha256",""))
                and type(event["id"]) is str and (event["id"] == "" or re.fullmatch(r"[a-f0-9]{32}",event["id"]))
                and type(event["exit"]) is int and 0 <= event["exit"] <= 255
                and (event["recorder_exit"] is None or type(event["recorder_exit"]) is int and 0 <= event["recorder_exit"] <= 255)
                and event["response"] in {"encoded","refused"}
                and (event["refusal"] is None or type(event["refusal"]) is str
                     and re.fullmatch(r"[a-z][a-z0-9_]{0,127}",event["refusal"]))
                and type(event["records"]) is list and len(event["records"]) <= 100000
                and type(event["dispatches"]) is list and len(event["dispatches"]) <= 100000,
                "micro_supervisor_events")
        if event["exit"] == 0:
            require(event["recorder_exit"] == 0 and event["refusal"] is None and event["response"] == "encoded",
                    "micro_supervisor_outcome")
        if event["response"] == "refused":
            require(event["exit"] == 86 and event["refusal"] == "compilation_response_limit",
                    "micro_supervisor_outcome")
        for dispatch in event["dispatches"]:
            fields = {"kind","invocation_sha256","environment_sha256","cwd","compiler_exit"}
            if captured:
                fields |= {"schema","output"}
            require(type(dispatch) is dict and set(dispatch) == fields
                    and type(dispatch["kind"]) is str
                    and dispatch["kind"] in {"compiler-probe","compiler-unit"}
                    and all(re.fullmatch(r"[a-f0-9]{64}",dispatch.get(key,"")) for key in ["invocation_sha256","environment_sha256"])
                    and type(dispatch["compiler_exit"]) is int, "micro_dispatch")
            if captured:
                require(dispatch["schema"] == "chio.native-compiler-dispatch.v2", "micro_dispatch")
                audit_native_compiler_output(dispatch["output"], retained_raw)
            cwd = compilation_absolute_path(dispatch["cwd"])
            require(cwd.is_relative_to(candidate)
                    and not any(cwd.is_relative_to(compilation_absolute_path(configuration[key]))
                                for key in ["records","evidence"]), "micro_dispatch")
        matched_dispatches = set()
        for reference in event["records"]:
            require(type(reference) is dict and set(reference) == {"invocation_id","path","sha256","size"},
                    "micro_dispatch_publication")
            identifier = reference["invocation_id"]
            require(identifier in available and identifier not in joined
                    and reference["path"] == "records/"+identifier+".json"
                    and reference["sha256"] == available[identifier]["record_sha256"]
                    and type(reference["size"]) is int and 0 < reference["size"] <= 16*1024**2,
                    "micro_dispatch_publication")
            path = namespace/reference["path"]
            row = read(path)
            raw_record = (read_bytes if read_raw is None else read_raw)(path)
            require(hashlib.sha256(raw_record).hexdigest() == reference["sha256"]
                    and len(raw_record) == reference["size"],
                    "micro_dispatch_publication")
            joined.add(identifier)
            require(row["kind"] in {"probe","compilation"}
                    and type(row.get("environment_sha256")) is str
                    and re.fullmatch(r"[a-f0-9]{64}",row["environment_sha256"]), "micro_actual_dispatch")
            matches = [(index,dispatch) for index,dispatch in enumerate(event["dispatches"])
                       if dispatch["invocation_sha256"] == row["invocation_sha256"]]
            if row["compiler_exit"] is None:
                require(row["status"] != "success" and not matches, "micro_actual_dispatch")
            else:
                require(type(row["compiler_exit"]) is int and len(matches) == 1
                        and matches[0][0] not in matched_dispatches
                        and matches[0][1]["compiler_exit"] == row["compiler_exit"]
                        and matches[0][1]["environment_sha256"] == row["environment_sha256"]
                        and matches[0][1]["kind"] == ("compiler-probe" if row["kind"] == "probe" else "compiler-unit"),
                        "micro_actual_dispatch")
                if row["kind"] == "compilation":
                    require(type(row.get("semantics")) is dict
                            and row["semantics"].get("cwd") == matches[0][1]["cwd"], "micro_actual_dispatch")
                matched_dispatches.add(matches[0][0])
            if row["status"] != "success":
                continue
            require(type(row["compiler_exit"]) is int and row["compiler_exit"] == 0,
                    "micro_actual_dispatch")
            semantics = row.get("semantics")
            require(type(semantics) is dict and type(semantics.get("native_scope")) is dict,
                    "micro_unit_native_scope")
            native = semantics["native_scope"]
            native_fields = {"scope_id","scope_record","coverage","platform","linker","input_attribution","generated_attribution"}
            current = declaration.get("schema") == "chio.linux-compilation-scope-declaration.v2"
            require(current or declaration.get("schema") == "chio.linux-compilation-scope-declaration.v1",
                    "micro_unit_native_scope")
            if current:
                native_fields |= {"retention_batch","retention_outcome_sha256"}
            require(set(native) == native_fields
                    and native["scope_id"] == declaration["scope_id"] and native["platform"] == "linux-gnu"
                    and native["coverage"] == "conservative-read-scope"
                    and native["input_attribution"] == "direct-source-and-extern-plus-conservative-allowed-scope"
                    and native["generated_attribution"] == "campaign-produced"
                    and same_compilation_json(retained(namespace,native["scope_record"]),declaration), "micro_unit_native_scope")
            if current:
                require(same_compilation_json(native["retention_batch"],declaration["retention_batch"])
                        and native["retention_outcome_sha256"] == declaration["retention_outcome_sha256"], "micro_unit_native_scope")
            if "compiler_dispatch" not in semantics:
                # The trusted recorder issues these metadata calls internally.
                # They have no wrapper-selected compiler invocation to retain.
                internal_arguments = {"version":["-vV"],"sysroot":["--print","sysroot"]}
                name = semantics.get("probe")
                require(current and set(semantics) == {"probe","native_scope"}
                        and row.get("schema") == "chio.rust-compilation.v4" and row["kind"] == "probe"
                        and type(name) is str and name in internal_arguments
                        and row.get("inputs") == [] and row.get("outputs") == [] and row.get("depfiles") == [],
                        "micro_internal_probe")
                compiler = declaration["images"]["rustc"]
                require(type(row.get("compiler")) is dict
                        and compiler_graph_image(row["compiler"]) == compiler_graph_image(compiler)
                        and row["invocation_sha256"] == hashlib.sha256(compilation_canonical(
                            [compiler["path"],*internal_arguments[name]])).hexdigest(), "micro_internal_probe")
                require(any(same_compilation_json(native["linker"],driver) for driver in
                        [declaration["images"]["linker"],*[target["linker_driver"] for target in declaration["targets"]
                                                         if "linker_driver" in target]]), "micro_internal_probe")
                verified += 1
                continue
            selection = semantics["compiler_dispatch"]
            require(type(selection) is dict and set(selection) == {"raw_wrapper_argv","effective_argv","raw_wrapper_sha256","raw_compiler_sha256",
                    "effective_invocation_sha256","reason","target","driver","profile"}, "micro_compiler_dispatch")
            raw = retained(namespace,selection["raw_wrapper_argv"])
            effective = retained(namespace,selection["effective_argv"])
            require(type(raw) is list and type(effective) is list and 2 <= len(raw) <= 8192 and 1 <= len(effective) <= 8192
                    and all(type(value) is str and "\x00" not in value for value in [*raw,*effective])
                    and raw[0] == declaration["images"]["recorder"]["path"]
                    and raw[1] == declaration["images"]["rustc"]["path"]
                    and effective[0] == declaration["images"]["rustc"]["path"], "micro_compiler_dispatch")
            digest = lambda value:hashlib.sha256(compilation_canonical(value)).hexdigest()
            require(selection["raw_wrapper_sha256"] == digest(raw)
                    and selection["raw_compiler_sha256"] == digest(raw[1:])
                    and selection["effective_invocation_sha256"] == digest(effective) == row["invocation_sha256"],
                    "micro_compiler_dispatch")
            reason = selection["reason"]
            require(reason in {"missing-linker-declared-driver-opt-in","matching-explicit-linker","probe-unchanged","not-linking-unit"},
                    "micro_compiler_dispatch")
            target = selection["target"]
            require(target in {"x86_64-unknown-linux-gnu","x86_64-unknown-linux-musl"}
                    and compilation_target(raw[1:]) == target, "micro_compiler_target")
            if row["kind"] == "compilation":
                require((semantics.get("target") or "x86_64-unknown-linux-gnu") == target, "micro_compiler_target")
            driver = selection["driver"]
            configured = next((entry for entry in declaration["targets"] if entry["triple"] == target), None)
            expected = declaration["images"]["linker"] if configured is None else configured.get("linker_driver",declaration["images"]["linker"])
            raw_linkers = compilation_explicit_linkers(raw[1:])
            effective_linkers = compilation_explicit_linkers(effective)
            require(all(compilation_image_path(linker,aliases) == expected["path"]
                        for linker in [*raw_linkers,*effective_linkers]), "micro_compiler_driver")
            if reason in {"probe-unchanged","not-linking-unit"}:
                require(driver is None and effective == raw[1:]
                        and (row["kind"] == "probe") == (reason == "probe-unchanged"), "micro_compiler_dispatch")
            else:
                require(row["kind"] == "compilation" and same_compilation_json(driver,expected)
                        and same_compilation_json(driver,native["linker"]), "micro_compiler_driver")
                if reason == "missing-linker-declared-driver-opt-in":
                    require("linker_selection" in configuration
                            and selection["profile"] == "explicit-instrumented-compiler"
                            and not raw_linkers and effective_linkers == [driver["path"]]
                            and effective == raw[1:]+["-C","linker="+driver["path"]], "micro_compiler_dispatch")
                else:
                    require(len(raw_linkers) == 1 and effective_linkers == raw_linkers
                            and effective == raw[1:], "micro_compiler_dispatch")
            verified += 1
        require(matched_dispatches == set(range(len(event["dispatches"]))), "micro_actual_dispatch")
    require(joined == set(available), "micro_dispatch_publication")
    return verified

def check_compilation_alias_physical(declaration):
    for chain in declaration.get("alias_chains", []):
        for hop in chain["hops"]:
            info = os.stat(hop["path"], follow_symlinks=False)
            identity = [info.st_dev, info.st_ino, info.st_mode, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns, info.st_nlink]
            require((identity[:3] if hop["kind"] == "directory" else identity) == hop["identity"],
                    "micro_physical_alias")
            if hop["kind"] == "link":
                require(stat.S_ISLNK(info.st_mode) and os.readlink(hop["path"]) == hop["text"],
                        "micro_physical_alias")
            elif hop["kind"] == "directory":
                require(stat.S_ISDIR(info.st_mode), "micro_physical_alias")
            else:
                require(stat.S_ISREG(info.st_mode), "micro_physical_alias")

def audit_legacy_linux_compilation_scope_records(configuration, declaration, scope, inventories,
                                         source_binding, command, declaration_path):
    """Join already decoded records; this does not prove kernel enforcement.

    Callers must verify retained bytes, original publication/export custody,
    source origin and primary probes separately. No original path is opened.
    """
    config_fields = {"schema","candidate","source_binding","profile","package_root","runtime_inventory",
        "source_origin","scopes","images","aliases","write_roots","environment_metadata","environment","records","evidence"}
    require(type(configuration) is dict and config_fields <= set(configuration)
            <= config_fields | {"loader_paths","supported_targets","public_arguments","linker_selection"}
            and configuration["schema"] == "chio.linux-compilation-launch.v1","compilation_scope_configuration")
    require(isinstance(source_binding,str) and re.fullmatch(r"[a-f0-9]{64}",source_binding)
            and configuration["source_binding"] == source_binding,"compilation_scope_binding")
    candidate = compilation_absolute_path(configuration["candidate"])
    compilation_absolute_path(configuration["package_root"])
    writes = configuration["write_roots"]
    require(type(writes) is list and 0 < len(writes) <= 64 and len(set(writes)) == len(writes),"compilation_scope_configuration")
    writes = [compilation_absolute_path(value) for value in writes]
    protected = [compilation_absolute_path(configuration[key]) for key in ["records","evidence"]]
    require(all(path.is_relative_to(candidate/"target") for path in [*writes,*protected])
            and protected[0] != protected[1]
            and not any(left != right and left.is_relative_to(right) for left in writes for right in writes)
            and not any(left.is_relative_to(right) for left in protected for right in protected if left != right)
            and not any(path.is_relative_to(write) or write.is_relative_to(path) for path in protected for write in writes),
            "compilation_protected_namespace")
    profile = configuration["profile"]
    require(type(profile) is dict and profile.get("name") in {"dev","test","release"}
            and set(profile) <= {"name","CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG"}
            and all(value in {"0","1","2"} for key,value in profile.items() if key != "name"),"compilation_scope_profile")
    environment = configuration["environment"]
    allowed_environment = {"PATH","HOME","CARGO_HOME","RUSTUP_HOME","RUSTUP_TOOLCHAIN","LANG","LC_ALL","TMPDIR",
        "CARGO_TARGET_DIR","CARGO_INCREMENTAL","CARGO_BUILD_JOBS","CARGO_NET_OFFLINE","CARGO_TERM_COLOR",
        "CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","CHIO_CONFINED_CANARY_MODE"}
    require(type(environment) is dict and set(environment) <= allowed_environment
            and all(type(value) is str and "\x00" not in value for value in environment.values())
            and environment.get("CARGO_INCREMENTAL") == "0" and environment.get("CARGO_NET_OFFLINE") == "true"
            and environment.get("CARGO_TERM_COLOR") == "never","compilation_scope_environment")
    path_entries = environment.get("PATH","").split(":")
    require(0 < len(path_entries) <= 128 and all(path_entries),"compilation_scope_environment")
    for value in path_entries:
        compilation_absolute_path(value)
    for name in ["CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG"]:
        require(environment.get(name) == profile.get(name),"compilation_scope_profile")
    require(type(inventories) is list and type(configuration["scopes"]) is list
            and 1 <= len(inventories) == len(configuration["scopes"]) <= 64,"compilation_scope_inventory")
    required_roles = {"candidate","vendor","toolchain","native-runtime"}
    readonly,scope_roots = {},[]
    expected_references = []
    total_members = 0
    for configured,inventory in zip(configuration["scopes"],inventories):
        require(type(configured) is dict and set(configured) == {"role","root","selection","members"}
                and type(inventory) is dict and set(inventory) == {"schema","role","root","selection","directories","members"}
                and inventory["schema"] == "chio.compilation-read-scope.v1"
                and inventory["role"] in required_roles and inventory["role"] == configured["role"]
                and inventory["root"] == configured["root"] and inventory["selection"] == configured["selection"]
                and inventory["selection"] in {"complete-tree","explicit-members"},"compilation_scope_inventory")
        root = compilation_absolute_path(inventory["root"])
        require(str(root) != "/" and not any(root.is_relative_to(path) for path in protected)
                and (inventory["role"] == "candidate" or not any(root.is_relative_to(write)
                    or write.is_relative_to(root) for write in writes)),"compilation_protected_namespace")
        scope_roots.append(root)
        require(type(inventory["directories"]) is list and type(inventory["members"]) is list
                and len(inventory["directories"])+len(inventory["members"]) <= 100000,"compilation_scope_inventory")
        total_members += len(inventory["members"])
        require(total_members <= 2000000,"compilation_scope_inventory")
        names = [member.get("path") for member in inventory["members"] if type(member) is dict]
        require(len(names) == len(inventory["members"]) and all(type(name) is str for name in names)
                and names == sorted(set(names)) and len({portable_path_key(name) for name in names}) == len(names),"compilation_scope_inventory")
        for member in inventory["members"]:
            name = str(relative_path(member["path"]))
            path = str(root/name)
            kind = member.get("kind")
            if kind == "regular":
                require(set(member) == {"path","kind","sha256","size","mode","artifact"}
                        and type(member["mode"]) is int and 0 <= member["mode"] <= 0o7777
                        and member["artifact"] == "artifacts/"+member.get("sha256","")
                        and not any(PurePosixPath(path).is_relative_to(selected) for selected in [*writes,*protected]),
                        "compilation_scope_inventory")
                compiler_graph_image({**member,"path":path})
                require(path not in readonly,"compilation_scope_inventory")
                readonly[path] = {"role":inventory["role"],**member,"path":path}
            elif kind in {"trusted-recorder-namespace","campaign-produced-namespace"}:
                allowed = protected if kind == "trusted-recorder-namespace" else writes
                require(set(member) == {"path","kind"} and any(PurePosixPath(path).is_relative_to(selected)
                        for selected in allowed),"compilation_scope_inventory")
            elif kind == "excluded":
                require(set(member) == {"path","kind","reason"} and member["reason"] in
                        {"secret-shaped-original","discovery-metadata"},"compilation_scope_inventory")
            else:
                require(kind == "link" and set(member) == {"path","kind","text","target"}
                        and type(member["text"]) is str,"compilation_scope_inventory")
                compilation_absolute_path(member["target"])
        reference = compilation_json_image(inventory)
        expected_references.append({"role":inventory["role"],"root":str(root),"coverage":"conservative-read-scope",
                                    "inventory":{"path":reference["artifact"],**reference}})
    require(len(set(scope_roots)) == len(scope_roots)
            and {inventory["role"] for inventory in inventories} == required_roles
            and any(inventory["role"] == "candidate" and inventory["root"] == str(candidate) for inventory in inventories),
            "compilation_scope_inventory")
    aliases = audit_compilation_aliases(configuration, readonly)
    chains = audit_compilation_alias_chains(configuration, declaration, readonly, aliases)
    audit_compilation_targets(configuration, declaration, readonly, aliases)
    declaration_fields = {"schema","source_binding","scope_id","candidate","profile","scopes","runtime_inventory",
        "source_origin","policy","images","targets","environment","generated_attribution"}
    if chains:
        declaration_fields.add("alias_chains")
    require(type(declaration) is dict and set(declaration) == declaration_fields
            and declaration["schema"] == "chio.linux-compilation-scope-declaration.v1"
            and declaration["source_binding"] == source_binding and declaration["candidate"] == str(candidate)
            and declaration["profile"] == profile and declaration["environment"] == environment
            and declaration["scopes"] == expected_references and declaration["generated_attribution"] == "campaign-produced",
            "compilation_scope_declaration")
    scope_inputs = {"configuration":configuration,"inventories":inventories}
    if chains:
        scope_inputs["alias_chains"] = chains
    scope_id = hashlib.sha256(compilation_canonical(scope_inputs)).hexdigest()
    require(declaration["scope_id"] == scope_id,"compilation_scope_binding")
    for key in ["runtime_inventory","source_origin"]:
        original,retained = configuration[key],declaration[key]
        require(type(original) is dict and set(original) == {"path","sha256"} and type(retained) is dict
                and set(retained) == {"path","sha256","size","artifact"} and retained["path"] == str(relative_path(original["path"]))
                and retained["sha256"] == original["sha256"] and re.fullmatch(r"[a-f0-9]{64}",retained["sha256"])
                and type(retained["size"]) is int and 0 < retained["size"] <= 16*1024**2
                and retained["artifact"] == "artifacts/"+retained["sha256"],"compilation_scope_origin")
    require(type(configuration["images"]) is dict and set(configuration["images"]) == {"cargo","rustc","linker","python","recorder"}
            and type(declaration["images"]) is dict and set(declaration["images"]) == set(configuration["images"]),"compilation_scope_images")
    for name,configured in configuration["images"].items():
        retained = declaration["images"][name]
        require(type(configured) is dict and set(configured) == {"path","sha256"}
                and type(retained) is dict and set(retained) == {"path","sha256","size","artifact"},"compilation_scope_images")
        compiler_graph_image(retained)
        require(retained["path"] == compilation_image_path(configured["path"], aliases) and retained["sha256"] == configured["sha256"]
                and retained["path"] in readonly and all(retained[key] == readonly[retained["path"]][key]
                    for key in ["sha256","size","artifact"]),"compilation_scope_images")
    expected_policy = {"configuration":compilation_json_image(configuration),"launcher":declaration["images"]["recorder"],
        "implementation":"outside-supervisor-landlock-regular-leaves-seccomp-v2","minimum_landlock_abi":3,
        "write_roots":configuration["write_roots"],"environment_metadata":configuration["environment_metadata"],
        "protected_namespaces":[configuration["records"],configuration["evidence"]],
        "publication_authority":"outside-supervisor-actual-dispatch-original-namespace",
        "descendant_completion":"subreaper-wait-all-no-process-group-escape",
        "path_metadata":"stat-readlink-access-unrestricted; no regular-byte or observed-read claim",
        "descriptor_inheritance":"cargo-predeclared-anonymous-pipes; compiler-stdin-null-stdout-stderr-nonsocket-close-above-two"}
    require(declaration["policy"] == expected_policy,"compilation_scope_policy")
    require(type(scope) is dict and set(scope) == declaration_fields | {"declaration","execution"}
            and scope["schema"] == "chio.linux-compilation-scope.v1"
            and all(scope[key] == declaration[key] for key in declaration_fields-{"schema"})
            and scope["declaration"] == compilation_json_image(declaration),"compilation_scope_declaration")
    execution = scope["execution"]
    execution_fields = {"kind","command_sha256","environment_sha256","started_unix_seconds","ended_unix_seconds",
        "command_exit","runner_exit","source_drift","linux_architecture","landlock_abi","ipc","reaped_descendants",
        "generated_before","generated_after","logs","supervisor_events"}
    require(type(execution) is dict and set(execution) == execution_fields and execution["kind"] in {"cargo","scope-enforcement-probe"}
            and type(execution["command_exit"]) is int and execution["command_exit"] == 0
            and type(execution["runner_exit"]) is int and execution["runner_exit"] == 0 and execution["source_drift"] is False
            and execution["linux_architecture"] == "x86_64" and type(execution["landlock_abi"]) is int
            and execution["landlock_abi"] >= 3,"compilation_scope_execution")
    times = [execution[key] for key in ["started_unix_seconds","ended_unix_seconds"]]
    require(all(type(value) in {int,float} and math.isfinite(value) and value >= 0 for value in times)
            and times[1] >= times[0],"compilation_scope_execution")
    require(type(command) is list and 0 < len(command) <= 8192 and all(type(value) is str and "\x00" not in value for value in command)
            and execution["command_sha256"] == hashlib.sha256(compilation_canonical(command)).hexdigest(),"compilation_scope_command")
    path = compilation_absolute_path(declaration_path)
    require(path.parent.parent == protected[1] and path.name == "declaration.json"
            and re.fullmatch(r"[a-f0-9]{32}",path.parent.name),"compilation_scope_environment")
    ipc = execution["ipc"]
    require(type(ipc) is dict and set(ipc) == {"schema","lease","channels"} and ipc["schema"] == "chio.rust-compilation-pipes.v1"
            and type(ipc["lease"]) is list and len(ipc["lease"]) == 2 and type(ipc["channels"]) is list
            and len(ipc["channels"]) == 4 and all(type(pair) is list and len(pair) == 2 for pair in ipc["channels"]),"compilation_scope_environment")
    descriptors = ipc["lease"]+[value for pair in ipc["channels"] for value in pair]
    require(all(type(value) is int and value >= 3 for value in descriptors) and len(set(descriptors)) == 10,"compilation_scope_environment")
    effective_environment = {**environment,"RUSTC":declaration["images"]["rustc"]["path"],
        "RUSTC_WRAPPER":declaration["images"]["recorder"]["path"],"PYTHONDONTWRITEBYTECODE":"1",
        "CHIO_COMPILATION_SOURCE_ROOT":str(candidate),"CHIO_COMPILATION_RECORDS":configuration["records"],
        "CHIO_COMPILATION_SOURCE_BINDING":source_binding,"CHIO_COMPILATION_SCOPE_DECLARATION":declaration_path,
        "CHIO_COMPILATION_SCOPE_ID":scope_id,"CHIO_COMPILATION_IPC":compilation_canonical(ipc).decode("ascii")}
    require(execution["environment_sha256"] == hashlib.sha256(compilation_canonical(effective_environment)).hexdigest(),
            "compilation_scope_environment")
    reaped = execution["reaped_descendants"]
    require(type(reaped) is list and len(reaped) <= 100000 and all(type(row) is dict and set(row) == {"pid","wait_status"}
            and type(row["pid"]) is int and row["pid"] > 0 and type(row["wait_status"]) is int and row["wait_status"] >= 0
            for row in reaped) and len({row["pid"] for row in reaped}) == len(reaped),"compilation_scope_execution")
    return {"schema":"chio.completed-compilation-scope-record-verification.v1","scope_id":scope_id,
        "source_binding":source_binding,"declared_regular_inputs":len(readonly),
        "coverage":"completed-scope-record-integrity-only","compiled_closure_status":"not-established"}

def checked_current_retention(declaration, execution, source_binding):
    """Validate decoded batch composition; original physical and stream joins follow."""
    batch = declaration["retention_batch"]
    require(type(batch) is dict and set(batch) == {"batch_id","source_binding","start","complete"}
            and type(batch["batch_id"]) is str and re.fullmatch(r"[a-f0-9]{32}",batch["batch_id"])
            and batch["source_binding"] == source_binding,"compilation_scope_retention")
    for phase in ["start","complete"]:
        reference = batch[phase]
        require(type(reference) is dict and set(reference) == {"path","sha256","size","identity"}
                and reference["path"] == "batches/"+batch["batch_id"]+"."+phase+".json"
                and type(reference["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}",reference["sha256"])
                and type(reference["size"]) is int and 0 < reference["size"] <= 16*1024**2
                and type(reference["identity"]) is dict and set(reference["identity"]) == {"device","inode"}
                and all(type(value) is int and value >= 0 for value in reference["identity"].values()),
                "compilation_scope_retention")
    outcomes = execution["retention_outcomes"]
    require(type(outcomes) is list and len(outcomes) == 1,"compilation_scope_retention")
    outcome = outcomes[0]
    require(type(outcome) is dict and set(outcome) == {"schema","source_binding","batch_id","start","complete",
            "physical_status","durability","declaration_emitted"}
            and outcome["schema"] == "chio.compiler-retention-batch-outcome.v1"
            and outcome["physical_status"] == "complete" and outcome["declaration_emitted"] is False
            and same_compilation_json(outcome["durability"],{"status":"confirmed","phase":"completion-directory-fsync","errno":None})
            and same_compilation_json({key:outcome[key] for key in batch},batch)
            and type(declaration["retention_outcome_sha256"]) is str
            and declaration["retention_outcome_sha256"] == hashlib.sha256(compilation_canonical(outcome)).hexdigest(),
            "compilation_scope_retention")

def audit_compilation_directory_inventory(configured, inventory):
    """Recompute READ_DIR metadata from the finite approved regular byte leaves."""
    fields = {"schema","role","root","selection","directories","members"}
    version = inventory.get("schema") if type(inventory) is dict else None
    require(type(version) is str and version in {"chio.compilation-read-scope.v1","chio.compilation-read-scope.v2"}
            and set(inventory) == fields | ({"directory_metadata"} if version.endswith(".v2") else set())
            and type(inventory.get("directories")) is list and type(inventory.get("members")) is list,
            "compilation_scope_directories")
    directories = inventory["directories"]
    require(all(type(name) is str and name and (name == "." or not secret_source(name)) for name in directories)
            and directories == sorted(set(directories))
            and len({portable_path_key(name) for name in directories}) == len(directories),
            "compilation_scope_directories")
    for name in directories:
        require(name == "." or str(relative_path(name)) == name,"compilation_scope_directories")
    if configured["selection"] == "explicit-members":
        members = inventory["members"]
        require(type(configured["members"]) is list
                and all(type(member) is dict and type(member.get("path")) is str for member in members)
                and [member["path"] for member in members] == sorted(configured["members"]),
                "compilation_scope_directories")
        expected = sorted({str(PurePosixPath(member["path"]).parent) for member in members
                           if member.get("kind") == "regular"})
        require(directories == (expected if version.endswith(".v2") else []),
                "compilation_scope_directories")
    else:
        require(version == "chio.compilation-read-scope.v1", "compilation_scope_directories")
    if version.endswith(".v2"):
        metadata = inventory["directory_metadata"]
        require(type(metadata) is list and bool(metadata) and len(metadata) == len(directories)
                and all(type(row) is dict and set(row) == {"path","identity"}
                        and type(row.get("identity")) is list and len(row["identity"]) == 3
                        and all(type(value) is int and value >= 0 for value in row["identity"])
                        and stat.S_ISDIR(row["identity"][2]) for row in metadata)
                and [row["path"] for row in metadata] == directories,
                "compilation_scope_directories")


def hold_compilation_directory_metadata(inventories, descriptors, observed):
    """Join retained READ_DIR metadata to original no-follow directory objects."""
    for inventory in inventories:
        if inventory["schema"] != "chio.compilation-read-scope.v2":
            continue
        root = Path(compilation_absolute_path(inventory["root"]))
        for row in inventory["directory_metadata"]:
            path = root/row["path"]
            require(not secret_source(path.as_posix().lstrip("/")), "compilation_scope_directories_physical")
            if path not in observed:
                descriptor = descriptors.enter_context(compiler_namespace_directory(path))
                info = os.fstat(descriptor)
                observed[path] = [info.st_dev,info.st_ino,info.st_mode]
            require(same_compilation_json(observed[path],row["identity"]),
                    "compilation_scope_directories_physical")


def audit_current_linux_compilation_scope_records(configuration, declaration, scope, inventories,
                                         source_binding, command, declaration_path):
    """Join already decoded records; this does not prove kernel enforcement.

    Callers must verify retained bytes, original publication/export custody,
    source origin and primary probes separately. No original path is opened.
    """
    config_fields = {"schema","candidate","source_binding","profile","package_root","runtime_inventory",
        "source_origin","scopes","images","aliases","write_roots","environment_metadata","environment","records","evidence"}
    require(type(configuration) is dict and config_fields <= set(configuration)
            <= config_fields | {"loader_paths","supported_targets","public_arguments","linker_selection"}
            and configuration["schema"] == "chio.linux-compilation-launch.v1","compilation_scope_configuration")
    require(isinstance(source_binding,str) and re.fullmatch(r"[a-f0-9]{64}",source_binding)
            and configuration["source_binding"] == source_binding,"compilation_scope_binding")
    candidate = compilation_absolute_path(configuration["candidate"])
    compilation_absolute_path(configuration["package_root"])
    writes = configuration["write_roots"]
    require(type(writes) is list and 0 < len(writes) <= 64 and len(set(writes)) == len(writes),"compilation_scope_configuration")
    writes = [compilation_absolute_path(value) for value in writes]
    protected = [compilation_absolute_path(configuration[key]) for key in ["records","evidence"]]
    require(all(path.is_relative_to(candidate/"target") for path in [*writes,*protected])
            and protected[0] != protected[1]
            and not any(left != right and left.is_relative_to(right) for left in writes for right in writes)
            and not any(left.is_relative_to(right) for left in protected for right in protected if left != right)
            and not any(path.is_relative_to(write) or write.is_relative_to(path) for path in protected for write in writes),
            "compilation_protected_namespace")
    profile = configuration["profile"]
    require(type(profile) is dict and profile.get("name") in {"dev","test","release"}
            and set(profile) <= {"name","CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG"}
            and all(value in {"0","1","2"} for key,value in profile.items() if key != "name"),"compilation_scope_profile")
    environment = configuration["environment"]
    allowed_environment = {"PATH","HOME","CARGO_HOME","RUSTUP_HOME","RUSTUP_TOOLCHAIN","LANG","LC_ALL","TMPDIR",
        "CARGO_TARGET_DIR","CARGO_INCREMENTAL","CARGO_BUILD_JOBS","CARGO_NET_OFFLINE","CARGO_TERM_COLOR",
        "CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG","CHIO_CONFINED_CANARY_MODE"}
    require(type(environment) is dict and set(environment) <= allowed_environment
            and all(type(value) is str and "\x00" not in value for value in environment.values())
            and environment.get("CARGO_INCREMENTAL") == "0" and environment.get("CARGO_NET_OFFLINE") == "true"
            and environment.get("CARGO_TERM_COLOR") == "never","compilation_scope_environment")
    path_entries = environment.get("PATH","").split(":")
    require(0 < len(path_entries) <= 128 and all(path_entries),"compilation_scope_environment")
    for value in path_entries:
        compilation_absolute_path(value)
    for name in ["CARGO_PROFILE_DEV_DEBUG","CARGO_PROFILE_TEST_DEBUG"]:
        require(environment.get(name) == profile.get(name),"compilation_scope_profile")
    require(type(inventories) is list and type(configuration["scopes"]) is list
            and 1 <= len(inventories) == len(configuration["scopes"]) <= 64,"compilation_scope_inventory")
    required_roles = {"candidate","vendor","toolchain","native-runtime"}
    readonly,scope_roots = {},[]
    expected_references = []
    total_members = 0
    for configured,inventory in zip(configuration["scopes"],inventories):
        require(type(configured) is dict and set(configured) == {"role","root","selection","members"}
                and type(inventory) is dict
                and inventory.get("schema") in {"chio.compilation-read-scope.v1","chio.compilation-read-scope.v2"}
                and inventory["role"] in required_roles and inventory["role"] == configured["role"]
                and inventory["root"] == configured["root"] and inventory["selection"] == configured["selection"]
                and inventory["selection"] in {"complete-tree","explicit-members"},"compilation_scope_inventory")
        audit_compilation_directory_inventory(configured,inventory)
        root = compilation_absolute_path(inventory["root"])
        require(str(root) != "/" and not any(root.is_relative_to(path) for path in protected)
                and (inventory["role"] == "candidate" or not any(root.is_relative_to(write)
                    or write.is_relative_to(root) for write in writes)),"compilation_protected_namespace")
        scope_roots.append(root)
        require(type(inventory["directories"]) is list and type(inventory["members"]) is list
                and len(inventory["directories"])+len(inventory["members"]) <= 100000,"compilation_scope_inventory")
        total_members += len(inventory["members"])
        require(total_members <= 2000000,"compilation_scope_inventory")
        names = [member.get("path") for member in inventory["members"] if type(member) is dict]
        require(len(names) == len(inventory["members"]) and all(type(name) is str for name in names)
                and names == sorted(set(names)) and len({portable_path_key(name) for name in names}) == len(names),"compilation_scope_inventory")
        for member in inventory["members"]:
            name = str(relative_path(member["path"]))
            path = str(root/name)
            kind = member.get("kind")
            if kind == "regular":
                require(set(member) == {"path","kind","sha256","size","mode","artifact"}
                        and type(member["mode"]) is int and 0 <= member["mode"] <= 0o7777
                        and member["artifact"] == "artifacts/"+member.get("sha256","")
                        and not any(PurePosixPath(path).is_relative_to(selected) for selected in [*writes,*protected]),
                        "compilation_scope_inventory")
                compiler_graph_image({**member,"path":path})
                require(path not in readonly,"compilation_scope_inventory")
                readonly[path] = {"role":inventory["role"],**member,"path":path}
            elif kind in {"trusted-recorder-namespace","campaign-produced-namespace"}:
                allowed = protected if kind == "trusted-recorder-namespace" else writes
                require(set(member) == {"path","kind"} and any(PurePosixPath(path).is_relative_to(selected)
                        for selected in allowed),"compilation_scope_inventory")
            elif kind == "excluded":
                require(set(member) == {"path","kind","reason"} and member["reason"] in
                        {"secret-shaped-original","discovery-metadata"},"compilation_scope_inventory")
            else:
                require(kind == "link" and set(member) == {"path","kind","text","target"}
                        and type(member["text"]) is str,"compilation_scope_inventory")
                compilation_absolute_path(member["target"])
        reference = compilation_json_image(inventory)
        expected_references.append({"role":inventory["role"],"root":str(root),"coverage":"conservative-read-scope",
                                    "inventory":{"path":reference["artifact"],**reference}})
    require(len(set(scope_roots)) == len(scope_roots)
            and {inventory["role"] for inventory in inventories} == required_roles
            and any(inventory["role"] == "candidate" and inventory["root"] == str(candidate) for inventory in inventories),
            "compilation_scope_inventory")
    aliases = audit_compilation_aliases(configuration, readonly)
    chains = audit_compilation_alias_chains(configuration, declaration, readonly, aliases)
    audit_compilation_targets(configuration, declaration, readonly, aliases)
    declaration_fields = {"schema","source_binding","scope_id","candidate","profile","scopes","runtime_inventory",
        "source_origin","policy","images","targets","environment","generated_attribution",
        "retention_batch","retention_outcome_sha256"}
    if chains:
        declaration_fields.add("alias_chains")
    require(type(declaration) is dict and set(declaration) == declaration_fields
            and declaration["schema"] == "chio.linux-compilation-scope-declaration.v2"
            and declaration["source_binding"] == source_binding and declaration["candidate"] == str(candidate)
            and declaration["profile"] == profile and declaration["environment"] == environment
            and declaration["scopes"] == expected_references and declaration["generated_attribution"] == "campaign-produced",
            "compilation_scope_declaration")
    scope_inputs = {"configuration":configuration,"inventories":inventories}
    if chains:
        scope_inputs["alias_chains"] = chains
    scope_id = hashlib.sha256(compilation_canonical(scope_inputs)).hexdigest()
    require(declaration["scope_id"] == scope_id,"compilation_scope_binding")
    for key in ["runtime_inventory","source_origin"]:
        original,retained = configuration[key],declaration[key]
        require(type(original) is dict and set(original) == {"path","sha256"} and type(retained) is dict
                and set(retained) == {"path","sha256","size","artifact"} and retained["path"] == str(relative_path(original["path"]))
                and retained["sha256"] == original["sha256"] and re.fullmatch(r"[a-f0-9]{64}",retained["sha256"])
                and type(retained["size"]) is int and 0 < retained["size"] <= 16*1024**2
                and retained["artifact"] == "artifacts/"+retained["sha256"],"compilation_scope_origin")
    require(type(configuration["images"]) is dict and set(configuration["images"]) == {"cargo","rustc","linker","python","recorder"}
            and type(declaration["images"]) is dict and set(declaration["images"]) == set(configuration["images"]),"compilation_scope_images")
    for name,configured in configuration["images"].items():
        retained = declaration["images"][name]
        require(type(configured) is dict and set(configured) == {"path","sha256"}
                and type(retained) is dict and set(retained) == {"path","sha256","size","artifact"},"compilation_scope_images")
        compiler_graph_image(retained)
        require(retained["path"] == compilation_image_path(configured["path"], aliases) and retained["sha256"] == configured["sha256"]
                and retained["path"] in readonly and all(retained[key] == readonly[retained["path"]][key]
                    for key in ["sha256","size","artifact"]),"compilation_scope_images")
    expected_policy = {"configuration":compilation_json_image(configuration),"launcher":declaration["images"]["recorder"],
        "implementation":"outside-supervisor-landlock-regular-leaves-seccomp-v2","minimum_landlock_abi":3,
        "write_roots":configuration["write_roots"],"environment_metadata":configuration["environment_metadata"],
        "protected_namespaces":[configuration["records"],configuration["evidence"]],
        "publication_authority":"outside-supervisor-actual-dispatch-original-namespace",
        "descendant_completion":"subreaper-wait-all-no-process-group-escape",
        "path_metadata":"stat-readlink-access-unrestricted; no regular-byte or observed-read claim",
        "descriptor_inheritance":"cargo-predeclared-anonymous-pipes; compiler-stdin-null-stdout-stderr-nonsocket-close-above-two"}
    require(same_compilation_json(declaration["policy"],expected_policy),"compilation_scope_policy")
    require(type(scope) is dict and set(scope) == declaration_fields | {"declaration","execution"}
            and scope["schema"] == "chio.linux-compilation-scope.v2"
            and same_compilation_json({key:scope[key] for key in declaration_fields-{"schema"}},
                {key:declaration[key] for key in declaration_fields-{"schema"}})
            and same_compilation_json(scope["declaration"],compilation_json_image(declaration)),"compilation_scope_declaration")
    execution = scope["execution"]
    execution_fields = {"kind","command_sha256","environment_sha256","started_unix_seconds","ended_unix_seconds",
        "command_exit","runner_exit","source_drift","linux_architecture","landlock_abi","ipc","reaped_descendants",
        "generated_before","generated_after","logs","supervisor_events","retention_outcomes"}
    require(type(execution) is dict and set(execution) == execution_fields and execution["kind"] in {"cargo","scope-enforcement-probe"}
            and type(execution["command_exit"]) is int and execution["command_exit"] == 0
            and type(execution["runner_exit"]) is int and execution["runner_exit"] == 0 and execution["source_drift"] is False
            and execution["linux_architecture"] == "x86_64" and type(execution["landlock_abi"]) is int
            and execution["landlock_abi"] >= 3,"compilation_scope_execution")
    checked_current_retention(declaration,execution,source_binding)
    times = [execution[key] for key in ["started_unix_seconds","ended_unix_seconds"]]
    require(all(type(value) in {int,float} and math.isfinite(value) and value >= 0 for value in times)
            and times[1] >= times[0],"compilation_scope_execution")
    require(type(command) is list and 0 < len(command) <= 8192 and all(type(value) is str and "\x00" not in value for value in command)
            and execution["command_sha256"] == hashlib.sha256(compilation_canonical(command)).hexdigest(),"compilation_scope_command")
    path = compilation_absolute_path(declaration_path)
    require(path.parent.parent == protected[1] and path.name == "declaration.json"
            and re.fullmatch(r"[a-f0-9]{32}",path.parent.name),"compilation_scope_environment")
    ipc = execution["ipc"]
    require(type(ipc) is dict and set(ipc) == {"schema","lease","channels"} and ipc["schema"] == "chio.rust-compilation-pipes.v1"
            and type(ipc["lease"]) is list and len(ipc["lease"]) == 2 and type(ipc["channels"]) is list
            and len(ipc["channels"]) == 4 and all(type(pair) is list and len(pair) == 2 for pair in ipc["channels"]),"compilation_scope_environment")
    descriptors = ipc["lease"]+[value for pair in ipc["channels"] for value in pair]
    require(all(type(value) is int and value >= 3 for value in descriptors) and len(set(descriptors)) == 10,"compilation_scope_environment")
    effective_environment = {**environment,"RUSTC":declaration["images"]["rustc"]["path"],
        "RUSTC_WRAPPER":declaration["images"]["recorder"]["path"],"PYTHONDONTWRITEBYTECODE":"1",
        "CHIO_COMPILATION_SOURCE_ROOT":str(candidate),"CHIO_COMPILATION_RECORDS":configuration["records"],
        "CHIO_COMPILATION_SOURCE_BINDING":source_binding,"CHIO_COMPILATION_SCOPE_DECLARATION":declaration_path,
        "CHIO_COMPILATION_SCOPE_ID":scope_id,"CHIO_COMPILATION_IPC":compilation_canonical(ipc).decode("ascii")}
    require(execution["environment_sha256"] == hashlib.sha256(compilation_canonical(effective_environment)).hexdigest(),
            "compilation_scope_environment")
    reaped = execution["reaped_descendants"]
    require(type(reaped) is list and len(reaped) <= 100000 and all(type(row) is dict and set(row) == {"pid","wait_status"}
            and type(row["pid"]) is int and row["pid"] > 0 and type(row["wait_status"]) is int and row["wait_status"] >= 0
            for row in reaped) and len({row["pid"] for row in reaped}) == len(reaped),"compilation_scope_execution")
    return {"schema":"chio.completed-compilation-scope-record-verification.v2","scope_id":scope_id,
        "source_binding":source_binding,"declared_regular_inputs":len(readonly),
        "coverage":"completed-scope-record-integrity-only","compiled_closure_status":"not-established"}


def audit_linux_compilation_scope_records(configuration,declaration,scope,inventories,source_binding,command,declaration_path):
    """Versioned decoded joins; current qualification requires the v2 branch."""
    if declaration.get("schema") == "chio.linux-compilation-scope-declaration.v1":
        return audit_legacy_linux_compilation_scope_records(configuration,declaration,scope,inventories,
            source_binding,command,declaration_path)
    return audit_current_linux_compilation_scope_records(configuration,declaration,scope,inventories,
        source_binding,command,declaration_path)


def audit_compiler_unit_graph(rows, sources, roots, immutable_images=None):
    """Join checked publication rows to independently checked input declarations.

    Callers must first verify row publication, retained image bytes, the source
    inventory and immutable image declarations. This pure graph check never
    reads original paths and does not establish native scope or execution.
    """
    immutable_images = [] if immutable_images is None else immutable_images
    require(isinstance(rows,list) and 0 < len(rows) <= 100000
            and isinstance(sources,list) and len(sources) <= 200000
            and isinstance(roots,list) and 0 < len(roots) <= 100000
            and isinstance(immutable_images,list) and len(immutable_images) <= 200000,"compiler_graph_inventory")
    source_members = {compiler_graph_image(source):source for source in sources}
    require(len(source_members) == len(sources) and all(source.get("role") in
            {"candidate","vendor","toolchain","native-runtime","campaign-produced"} for source in sources),
            "compiler_graph_inventory")
    require(len({source["path"] for source in sources}) == len(sources),"compiler_graph_inventory")
    immutable = {compiler_graph_image(image) for image in immutable_images}
    require(len(immutable) == len(immutable_images)
            and len({image["path"] for image in immutable_images}) == len(immutable_images),"compiler_graph_inventory")
    identifiers = [row.get("invocation_id") for row in rows if isinstance(row,dict)]
    require(len(identifiers) == len(rows) and all(isinstance(identifier,str)
            and re.fullmatch(r"[a-f0-9]{32}",identifier) for identifier in identifiers)
            and len(set(identifiers)) == len(identifiers),"compiler_graph_inventory")
    units,producers,total_images = {},{},0
    for row in rows:
        if row.get("kind") != "compilation" or row.get("status") != "success":
            continue
        require(type(row.get("compiler_exit")) is int and row["compiler_exit"] == 0,"compiler_record_outcome")
        inputs,outputs,semantics = row.get("inputs"),row.get("outputs"),row.get("semantics")
        require(isinstance(inputs,list) and isinstance(outputs,list) and isinstance(semantics,dict)
                and len(inputs)+len(outputs) <= 100000
                and all(isinstance(image,dict) for image in [*inputs,*outputs]),"compiler_graph_inventory")
        total_images += len(inputs)+len(outputs)
        require(total_images <= 2000000,"compiler_graph_inventory")
        direct = [image for image in inputs if image.get("role") == "source"]
        require(direct and all(compiler_graph_image(image) in source_members for image in direct)
                and any(image["path"] == semantics.get("source") and source_members[compiler_graph_image(image)]["role"]
                    in {"candidate","vendor","campaign-produced"} for image in direct),"compiler_unit_source")
        identifier = row["invocation_id"]
        units[identifier] = row
        for image in outputs:
            if image.get("role") == "unit":
                key = compiler_graph_image(image)
                require(key not in producers,"compiler_unit_producer")
                producers[key] = identifier
    root_units = []
    root_images = {compiler_graph_image(image) for image in roots}
    for image in sorted(root_images):
        producer = producers.get(image)
        require(producer is not None,"compiler_root_producer")
        root_units.append(producer)
    edges,immutable_edges = {},{}
    for identifier,row in units.items():
        edges[identifier],immutable_edges[identifier] = [],0
        for image in row["inputs"]:
            if image.get("role") != "extern":
                continue
            key = compiler_graph_image(image)
            producer = producers.get(key)
            if producer is not None:
                edges[identifier].append(producer)
            else:
                require(key in immutable,"compiler_extern_producer")
                immutable_edges[identifier] += 1
    reached,pending = set(),list(root_units)
    while pending:
        identifier = pending.pop()
        if identifier not in reached:
            reached.add(identifier)
            pending.extend(edges[identifier])
    remaining = {identifier:len(set(edges[identifier])) for identifier in reached}
    consumers = {identifier:set() for identifier in reached}
    for identifier in reached:
        for dependency in set(edges[identifier]):
            consumers[dependency].add(identifier)
    ready = [identifier for identifier in reached if remaining[identifier] == 0]
    visited = 0
    while ready:
        identifier = ready.pop()
        visited += 1
        for consumer in consumers[identifier]:
            remaining[consumer] -= 1
            if remaining[consumer] == 0:
                ready.append(consumer)
    require(visited == len(reached),"compiler_unit_cycle")
    return {"schema":"chio.compiler-unit-graph-verification.v1","verified_roots":len(root_images),
        "root_declarations":len(roots),
        "reachable_units":len(reached),"extern_edges":sum(len(edges[identifier]) for identifier in reached),
        "immutable_extern_edges":sum(immutable_edges[identifier] for identifier in reached),
        "unit_ids":sorted(reached),"coverage":"declared-source-and-extern-unit-edges",
        "compiled_closure_status":"not-established"}


def compiler_immutable_externs(rows, additional_inputs, verified_native_inputs=None):
    """A role label cannot turn an old cached crate into immutable tooling."""
    verified_native_inputs = {} if verified_native_inputs is None else verified_native_inputs
    require(type(verified_native_inputs) is dict, "compiled_profile_immutable_producer")
    produced = {compiler_graph_image(image) for row in rows if row.get("kind") == "compilation"
        and row.get("status") == "success" and row.get("compiler_exit") == 0 for image in row.get("outputs",[])}
    needed, evidenced = set(), set()
    for row in rows:
        native = row.get("semantics",{}).get("native_scope")
        for image in row.get("inputs",[]):
            key = compiler_graph_image(image)
            if image.get("role") == "toolchain" and image.get("coverage") == "conservative-toolchain-scope":
                evidenced.add(key)
            if image.get("role") != "extern" or key in produced:
                continue
            needed.add(key)
            scope = image.get("immutable_scope")
            if type(native) is dict and type(scope) is dict and set(scope) == {"scope_id","path","sha256"} \
                    and image.get("origin") == "declared-immutable-scope" \
                    and scope == {"scope_id":native.get("scope_id"),"path":key[0],"sha256":key[1]} \
                    and re.fullmatch(r"[a-f0-9]{64}",scope.get("scope_id","")) \
                    and key in verified_native_inputs.get(scope["scope_id"],set()):
                evidenced.add(key)
    immutable = [image for image in additional_inputs if image.get("role") in {"toolchain","native-runtime"}
                 and compiler_graph_image(image) in needed]
    require(all(compiler_graph_image(image) in evidenced for image in immutable), "compiled_profile_immutable_producer")
    return immutable


def audit_ordinary_host_tool_image(namespace, image, completed_images):
    """Require actual tooling bytes in the reconciled original batch inventory."""
    require((image["sha256"], image["size"]) in completed_images and image["size"] <= 512*1024**2,
            "compiled_host_tool_batch")
    with regular_input(namespace/"artifacts"/image["sha256"]) as stream:
        require(os.fstat(stream.fileno()).st_size == image["size"], "compiled_host_tool_image")
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024*1024), b""):
            digest.update(chunk)
        require(digest.hexdigest() == image["sha256"], "compiled_host_tool_image")


def audit_ordinary_host_metadata(rows, repository, namespace, source_binding, retained, tooling_image):
    """Check versioned host observations without treating OS metadata as bytes."""
    checked_tooling = set()
    for row in rows:
        observation = (row.get("semantics") or {}).get("host_execution")
        if observation is None:
            continue
        require(type(observation) is dict and set(observation) == {"schema", "declaration", "loader_paths", "tooling_checks"}
                and observation["schema"] == "chio.ordinary-host-invocation.v1"
                and (row.get("semantics") or {}).get("native_scope") is None, "compiled_host_metadata")
        reference = observation["declaration"]
        require(reference in row["inputs"] and reference.get("role") == "host-execution-declaration", "compiled_host_metadata")
        host = json.loads(retained(reference), object_pairs_hook=closed_pairs)
        fields = {"schema", "repository", "namespace", "source_binding", "target_directory", "target", "machine",
                  "compiler", "cargo", "linker", "sdk", "toolchain", "images", "aliases", "runtime_metadata", "vendor_roots", "runtime_inventory"}
        require(type(host) is dict and set(host) == fields and host["schema"] == "chio.ordinary-host-execution.v1"
                and host["repository"] == str(repository) and host["namespace"] == str(namespace)
                and host["source_binding"] == source_binding
                and host["target"] == {"arm64": "aarch64-apple-darwin", "x86_64": "x86_64-apple-darwin"}.get(host["machine"]),
                "compiled_host_metadata")
        runtime_reference = host["runtime_inventory"]
        compiler_graph_image(runtime_reference)
        runtime_image = next((item for item in row["inputs"] if item.get("role") == "host-source-inventory"
                              and all(item.get(key) == runtime_reference.get(key) for key in ["path", "sha256", "size"])), None)
        require(runtime_image is not None, "compiled_host_metadata")
        runtime = json.loads(retained(runtime_image), object_pairs_hook=closed_pairs)
        require(type(runtime) is dict and set(runtime) == {"source_inventory_version", "base_commit", "sources", "source_binding"}
                and runtime["source_inventory_version"] == INVENTORY_VERSION
                and runtime["source_binding"] == source_binding
                and binding(runtime["sources"], runtime["base_commit"]) == source_binding, "compiled_host_metadata")
        validate_source_rows(runtime["sources"])
        target = compilation_absolute_path(host["target_directory"])
        require(target.is_relative_to(repository/"target") and target != repository/"target", "compiled_host_metadata")
        for key in ["compiler", "cargo", "linker", "sdk", "toolchain"]:
            require(not compilation_absolute_path(host[key]).is_relative_to(repository), "compiled_host_metadata")
        metadata = host["runtime_metadata"]
        require(type(metadata) is dict and set(metadata) == {"coverage", "system", "release", "version", "macos_version", "shared_cache_file_metadata"}
                and metadata["coverage"] == "ordinary-host-observation-no-retained-os-image-coverage"
                and metadata["system"] == "Darwin" and type(metadata["shared_cache_file_metadata"]) is list
                and len(metadata["shared_cache_file_metadata"]) <= 128, "compiled_host_metadata")
        for item in metadata["shared_cache_file_metadata"]:
            require(type(item) is dict and set(item) == {"path", "size", "mtime_ns"}
                    and compilation_absolute_path(item["path"]).is_relative_to("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld")
                    and type(item["size"]) is int and item["size"] >= 0
                    and type(item["mtime_ns"]) is int and item["mtime_ns"] >= 0, "compiled_host_metadata")
        allowed = {str(target/"debug/deps"), str(Path(host["toolchain"])/"lib"),
                   str(Path(host["toolchain"])/"lib/rustlib"/host["target"]/"lib")}
        require(type(observation["loader_paths"]) is dict and set(observation["loader_paths"]) <= {"LD_LIBRARY_PATH", "DYLD_FALLBACK_LIBRARY_PATH"}
                and all(type(paths) is list and paths and all(path in allowed for path in paths)
                        for paths in observation["loader_paths"].values()), "compiled_host_metadata")
        require(type(host["images"]) is list and 0 < len(host["images"]) <= 10000
                and type(host["aliases"]) is list and len(host["aliases"]) <= 10000, "compiled_host_metadata")
        tooling = set()
        tooling_paths = set()
        for image in host["images"]:
            require(type(image) is dict and set(image) == {"path", "sha256", "size", "purpose"}
                    and image["purpose"] in {"cargo", "linker", "linker-support", "sdk", "loader"}, "compiled_host_metadata")
            key = compiler_graph_image(image)
            require(key not in tooling and key[0] not in tooling_paths
                    and not Path(key[0]).is_relative_to(repository), "compiled_host_metadata")
            tooling.add(key)
            tooling_paths.add(key[0])
            if image["purpose"] == "sdk":
                require(Path(key[0]).is_relative_to(Path(host["sdk"])), "compiled_host_metadata")
        for alias in host["aliases"]:
            require(type(alias) is dict and set(alias) == {"path", "text"}
                    and compilation_absolute_path(alias["path"]).is_relative_to(Path(host["sdk"]))
                    and type(alias["text"]) is str and "\x00" not in alias["text"], "compiled_host_metadata")
        if row["kind"] == "compilation" and row["status"] == "success":
            checks = observation["tooling_checks"]
            require(type(checks) is dict and set(checks) == {"before", "after"}
                    and checks["before"] == checks["after"] and checks["before"] in row["inputs"]
                    and checks["before"].get("role") == "host-tool-observation", "compiled_host_tool_checks")
            state = json.loads(retained(checks["before"]), object_pairs_hook=closed_pairs)
            require(type(state) is dict and set(state) == {"schema", "declaration_sha256", "images"}
                    and state["schema"] == "chio.ordinary-host-tool-observation.v1"
                    and state["declaration_sha256"] == reference["sha256"] and type(state["images"]) is list
                    and len(state["images"]) == len(tooling), "compiled_host_tool_checks")
            actual = set()
            for image in state["images"]:
                key = compiler_graph_image(image)
                require(type(image) is dict and set(image) == {"path", "sha256", "size", "identity"}
                        and type(image["identity"]) is list and len(image["identity"]) == 7
                        and all(type(value) is int and value >= 0 for value in image["identity"])
                        and image["identity"][3] == image["size"] and image["identity"][-1] == 1
                        and stat.S_ISREG(image["identity"][2]), "compiled_host_tool_checks")
                actual.add(key)
                if key not in checked_tooling:
                    tooling_image(image)
                    checked_tooling.add(key)
            require(actual == tooling and row["compiler"]["path"] == host["compiler"]
                    and row["compiler"]["version"]["fields"]["host"] == host["target"], "compiled_host_metadata")
            for image in row["inputs"]:
                if image.get("role") == "extern":
                    require(image.get("origin") == "recorded-producing-unit" and type(image.get("producer")) is dict
                            and Path(image["path"]).is_relative_to(target), "compiled_host_extern_producer")


def audit_compiler_profile_namespace(namespace, repository, inventory, source_binding, roots,
                                     additional_inputs=None, selected_ids=None, verified_native_inputs=None):
    """Join an original publication namespace to a checked source inventory.

    Additional external/generated declarations require independent custody.
    This original-namespace check is not an export receipt or native probe.
    """
    repository = compilation_absolute_path(str(repository))
    require(type(inventory) is dict and set(inventory) == {"source_inventory_version","base_commit","sources","source_binding"}
            and inventory["source_inventory_version"] == INVENTORY_VERSION,"compiler_profile_inventory")
    validate_source_rows(inventory["sources"])
    base = inventory["base_commit"]
    require(base is None or type(base) is str and re.fullmatch(r"[a-f0-9]{40}",base),"compiler_profile_inventory")
    require(inventory["source_binding"] == binding(inventory["sources"],base),"compiler_profile_inventory")
    publication = audit_compiler_publications(namespace,source_binding)
    available = {row["invocation_id"]:row for row in publication["records"]}
    selected_ids = sorted(available) if selected_ids is None else selected_ids
    require(type(selected_ids) is list and 0 < len(selected_ids) <= 100000
            and all(type(identifier) is str for identifier in selected_ids)
            and len(set(selected_ids)) == len(selected_ids) and set(selected_ids) <= set(available),"compiler_profile_records")
    current = {str(repository/row["path"]):row["sha256"] for row in inventory["sources"] if "sha256" in row}
    additional_inputs = [] if additional_inputs is None else additional_inputs
    require(type(additional_inputs) is list and len(additional_inputs) <= 200000,"compiler_profile_inputs")
    extra = {}
    for image in additional_inputs:
        key = compiler_graph_image(image)
        require(key not in extra and image.get("role") in {"vendor","toolchain","native-runtime","campaign-produced"},"compiler_profile_inputs")
        path = PurePosixPath(key[0])
        require(key[0] not in current and (path.is_relative_to(repository/"target") if image["role"] == "campaign-produced"
                else not path.is_relative_to(repository)),"compiler_profile_inputs")
        extra[key] = image
    rows,inputs = [],{}
    for identifier in selected_ids:
        path = Path(namespace)/"records"/(identifier+".json")
        with regular_input(path) as stream:
            row,raw,identity = compiler_json(stream)
            require(hashlib.sha256(raw).hexdigest() == available[identifier]["record_sha256"]
                    and identity == available[identifier]["record_identity"],"compiler_namespace_changed")
        rows.append(row)
        for image in row.get("inputs",[]):
            if image.get("role") != "source":
                continue
            key = compiler_graph_image(image)
            if key[0] in current:
                require(key[1] == current[key[0]],"compiler_profile_source")
                inputs[key] = {"path":key[0],"sha256":key[1],"size":key[2],"role":"candidate"}
            else:
                require(key in extra,"compiler_profile_source")
                inputs[key] = extra[key]
    immutable = compiler_immutable_externs(rows,additional_inputs,verified_native_inputs)
    def retained_host_image(image):
        path = Path(namespace)/image["artifact"]
        with regular_input(path) as stream:
            raw = stream.read(16*1024**2+1)
        require(len(raw) == image["size"] <= 16*1024**2 and hashlib.sha256(raw).hexdigest() == image["sha256"], "compiled_host_metadata")
        return raw
    completed_host_images = None
    def original_host_tooling(image):
        nonlocal completed_host_images
        if completed_host_images is None:
            completed_host_images = set()
            for batch in publication.get("retention_batches", []):
                reference = batch["complete"]
                body = read_bytes(Path(namespace)/relative_path(reference["path"]))
                require(hashlib.sha256(body).hexdigest() == reference["sha256"], "compiled_host_tool_batch")
                complete = json.loads(body, object_pairs_hook=closed_pairs)
                completed_host_images.update((item["sha256"], item["size"]) for item in complete["after"]["artifacts"])
        audit_ordinary_host_tool_image(Path(namespace), image, completed_host_images)
    audit_ordinary_host_metadata(rows, repository, Path(namespace), source_binding, retained_host_image, original_host_tooling)
    graph = audit_compiler_unit_graph(rows,list(inputs.values()),roots,immutable)
    require(audit_compiler_publications(namespace,source_binding) == publication,"compiler_namespace_changed")
    return {"schema":"chio.original-compiler-profile-verification.v1","source_binding":source_binding,
        "runtime_inventory_binding":inventory["source_binding"],"repository":str(repository),
        "publication":publication,"unit_graph":graph,"selected_invocation_ids":sorted(selected_ids),
        "coverage":"original-publication-and-current-declared-source-unit-graph",
        "compiled_closure_status":"not-established"}


def audit_compiler_launch(root, reference, actual_command, repository, expected, sources, source_binding):
    """Validate the instrumented outer launch and the unchanged Cargo argv."""
    launch = artifact_json(root,reference)
    fields = {"schema","source_binding","launcher","configuration","configuration_path","command"}
    require(type(launch) is dict and set(launch) == fields and launch["schema"] == "chio.compiler-command-launch.v1",
            "compiler_launch_record")
    repository = compilation_absolute_path(str(repository))
    config = artifact_json(root,launch["configuration"])
    recorder = {"path":str(repository/"scripts/record-rust-compilation.py"),"sha256":next((source.get("sha256")
        for source in sources if source["path"] == "scripts/record-rust-compilation.py"),None)}
    require(recorder["sha256"] is not None and launch["launcher"] == recorder
            and config.get("schema") == "chio.linux-compilation-launch.v1"
            and config.get("candidate") == str(repository)
            and config.get("source_binding") == launch["source_binding"] == source_binding
            and config.get("images",{}).get("recorder") == recorder, "compiler_launch_source")
    path = compilation_absolute_path(launch["configuration_path"])
    require(path.is_relative_to(repository/"target/metadata"), "compiler_launch_configuration")
    cargo = compilation_absolute_path(config["images"]["cargo"]["path"])
    python = compilation_absolute_path(config["images"]["python"]["path"])
    command = launch["command"]
    require(type(command) is list and 0 < len(command) <= 8192
            and all(type(value) is str and "\x00" not in value for value in command)
            and command[0] == str(cargo) and expected["command"][0] == "cargo", "compiler_launch_command")
    normalized = ["cargo",*[str(Path(argument).relative_to(repository)) if Path(argument).is_absolute()
        and Path(argument).is_relative_to(repository) else argument for argument in command[1:]]]
    require(normalized == expected["command"] and actual_command == [str(python),"-B",recorder["path"],
            "--launch-scope",str(path),"--",*command], "compiler_launch_command")
    return {"command":normalized,"launch":launch,"configuration":config}


def audit_execution_provenance(root, row, sources, base_commit, expected=None):
    """A row's stable flag cannot substitute for its before/after byte manifests."""
    proof = row.get("provenance")
    required = {"start", "result", "before", "after", "runtime_sources_before", "runtime_sources_after"}
    require(isinstance(proof, dict) and required <= set(proof)
            and not set(proof)-required-{"source_origin","compiler_launch"}, "gate_provenance")
    start = artifact_json(root, proof["start"])
    result = artifact_json(root, proof["result"])
    before = artifact_json(root, proof["before"])
    after = artifact_json(root, proof["after"])
    before_digest = audited_source_manifest(before)
    after_digest = audited_source_manifest(after)
    require(result.get("format") == "chio.local-command-provenance.v1"
            and type(result.get("actual_command_exit")) is int and result["actual_command_exit"] == 0
            and result.get("runner_exit") == 0 and result.get("inventories_complete") is True
            and result.get("output_pipe_completed") is True and result.get("provenance_error") is None
            and result.get("source_drift", {}).get("detected") is False, "gate_execution_provenance")
    receipt = None
    origin = None
    if "source_origin" in proof:
        origin = artifact_json(root,proof["source_origin"])
        receipt = audit_source_origin(root,origin,sources,base_commit,binding(sources,base_commit))
        require(start.get("repository") == receipt.get("candidate"),"gate_executed_repository")
    discovered_base = None if receipt is not None else base_commit
    require(before.get("git", {}).get("head") == after.get("git", {}).get("head") == discovered_base,
            "gate_base_commit")
    require(before_digest == after_digest
            == result.get("before_manifest_sha256") == result.get("after_manifest_sha256"), "gate_source_bracket")
    for key in ["runtime_sources_before", "runtime_sources_after"]:
        snapshot = artifact_json(root, proof[key])
        require(snapshot.get("source_inventory_version") == INVENTORY_VERSION
                and snapshot.get("base_commit") == discovered_base and snapshot.get("sources") == sources
                and snapshot.get("source_binding") == binding(sources, discovered_base), "gate_source_bracket")
    repository = Path(start["repository"])
    require(repository.is_absolute() and ".." not in repository.parts, "gate_executed_repository")
    for snapshot in [before, after]:
        if origin is not None:
            audit_materialized_capture(root,origin["stages"][-1],snapshot)
        audit_snapshot_sources(snapshot, sources, PurePosixPath(repository.as_posix()))
    command = [str(Path(argument).relative_to(repository)) if Path(argument).is_absolute()
               and Path(argument).is_relative_to(repository) else argument for argument in start["command"]]
    expected = gate_catalog().get(row.get("id")) if expected is None else expected
    if "compiler_launch" in proof:
        require(expected is not None, "compiler_launch_command")
        launch = audit_compiler_launch(root,proof["compiler_launch"],start["command"],repository,
                                      expected,sources,binding(sources,discovered_base))
        command = launch["command"]
        for snapshot in [before,after]:
            require(any(pin.get("purpose") == "compiler-launch-configuration"
                    and pin.get("path") == launch["launch"]["configuration_path"]
                    and pin.get("observed",{}).get("sha256") == launch["launch"]["configuration"]["sha256"]
                    for pin in snapshot.get("explicit_file_pins",[])), "compiler_launch_configuration")
    require(expected is not None and row["command"] == expected["command"]
            and command == row["command"] and row.get("cwd", ".") == expected["cwd"]
            and Path(start["cwd"]) == repository / expected["cwd"], "gate_executed_command")
    require(all(start.get("environment", {}).get(name) == value
                for name, value in expected["environment"].items()), "gate_executed_environment")
    require(result.get("log", {}).get("sha256") == row["log"]["sha256"], "gate_executed_log")
    if row.get("id") == "python-sdk":
        text = checked_log(root,row["log"])
        origins = re.findall(r"^QUALIFICATION_PYTHON_IMPORTS (.+)$",text,re.MULTILINE)
        require(len(origins) == 1,"python_sdk_origin")
        origin = json.loads(origins[0],object_pairs_hook=closed_pairs)
        prefix = repository / "target/recovery-qualification-venv"
        require(origin.get("repository") == str(repository) and origin.get("prefix") == str(prefix)
                and origin.get("executable") == str(prefix / "bin/python")
                and origin.get("chio_sdk") == "sdks/python/chio-sdk-python/src/chio_sdk/__init__.py",
                "python_sdk_origin")
        interpreter = row.get("interpreter")
        require(isinstance(interpreter,dict),"python_interpreter_binding")
        checked_executable(root,interpreter)
        for snapshot in [before,after]:
            selected = [pin for pin in snapshot["explicit_file_pins"] if pin.get("purpose") == "interpreter"]
            require(len(selected) == 1 and selected[0].get("path") == origin.get("real_executable")
                    and selected[0].get("observed",{}).get("sha256") == interpreter["sha256"],
                    "python_interpreter_binding")


def checked_log(root, reference):
    raw = read_bytes(root / relative_path(reference["path"]))
    require(hashlib.sha256(raw).hexdigest() == reference["sha256"], "evidence_reference_hash")
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw.decode("utf-8"))


def checked_executable(root, reference, *, linux=False, static_pie=False, mode=None):
    """Verify retained executable bytes, including the confined canary's mode."""
    path = root / relative_path(reference["path"])
    with regular_input(path) as stream:
        digest = hashlib.sha256()
        modes = set()
        marker = b"CHIO-CONFINED-CANARY-MODE-V1:"
        tail = b""
        for chunk in iter(lambda:stream.read(1024*1024), b""):
            digest.update(chunk)
            if mode is not None:
                data = tail + chunk
                offset = 0
                while (position := data.find(marker, offset)) >= 0:
                    field = data[position+len(marker):position+len(marker)+32]
                    text, separator, padding = field.partition(b"\0")
                    if len(field) == 32 and separator and not padding.strip(b"\0") and re.fullmatch(rb"[a-z-]+", text):
                        modes.add(text.decode("ascii"))
                    offset = position+len(marker)
                tail = data[-(len(marker)+31):]
        require(digest.hexdigest() == reference["sha256"], "dimension_executable")
        stream.seek(0)
        header = stream.read(64)
        if linux or static_pie:
            require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01"
                    and struct.unpack_from("<H",header,18)[0] == 62, "linux_executable")
        else:
            require(header[:4] in {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                                  b"\xca\xfe\xba\xbe", b"MZ\x90\x00"}, "dimension_executable_format")
        if static_pie:
            require(struct.unpack_from("<H",header,16)[0] == 3, "linux_static_pie")
            offset = struct.unpack_from("<Q",header,32)[0]
            entry_size, count = struct.unpack_from("<HH",header,54)
            require(entry_size == 56 and 0 < count <= 4096, "linux_static_pie")
            stream.seek(0,2)
            size = stream.tell()
            require(offset + entry_size*count <= size, "linux_static_pie")
            for index in range(count):
                stream.seek(offset+entry_size*index)
                fields = struct.unpack("<IIQQQQQQ",stream.read(56))
                require(fields[0] != 3, "linux_static_pie")
                if fields[0] == 2:
                    require(fields[2]+fields[5] <= size and fields[5] % 16 == 0 and fields[5] <= 1024*1024,
                            "linux_static_pie")
                    stream.seek(fields[2])
                    tags = [struct.unpack("<qQ",stream.read(16))[0] for _ in range(fields[5]//16)]
                    require(not {1,15,29}.intersection(tags), "linux_static_pie")
        if mode is not None:
            require(modes == {mode}, "linux_canary_mode")


LINUX_CASE_PREFIX = "recovery::tests::knowledge::confinement::linux::"
LINUX_CASES = tuple(LINUX_CASE_PREFIX+name for name in (
    "linux_absolute_deadline_kills_a_held_handle_without_parent_io",
    "linux_acknowledgement_retains_delivery_after_cancel_and_authority_change",
    "linux_cancellation_reports_an_already_ordered_parent_return",
    "linux_channel_canaries_never_reach_parent_or_bypass_projection",
    "linux_duplicate_launch_and_cancel_preserve_the_observation_and_consumed_slot",
    "linux_fixed_environment_rejects_parent_controlled_channels",
    "linux_launch_cutpoints_never_duplicate_measurement_or_reset_observation",
    "linux_parent_cancellation_withholds_returns_before_and_after_native_join",
    "linux_rejected_projection_leaves_no_candidate_blob_or_extra_charge",
    "linux_return_cutpoints_reopen_the_native_writer_without_second_disclosure",
    "linux_sink_attempt_is_durably_uncertain_before_first_byte",
    "linux_staged_return_survives_execution_deadline",
    "linux_staging_receipt_and_return_preparation_enforce_source_audience",
    "linux_terminal_dispositions_survive_cancellation",
    "linux_true_and_false_returns_preserve_identical_parent_storage_availability",
    "linux_unknown_input_provenance_withholds_a_correct_projection",
    "linux_useful_decision_exact_authority_and_parent_join_before_first_byte",
    "linux_valid_signatures_cannot_authorize_cross_parent_epoch_or_stale_returns",
))


def audit_linux(root, evidence, candidate, sources, base_commit):
    require(evidence.get("schema") == "chio.recovery-linux-evidence.v1", "linux_record")
    require(sources is not None and base_commit is not None, "linux_source_origin")
    primary = artifact_json(root,evidence["acceptance"])
    require(primary.get("schema") == "chio.confined-return-linux-acceptance.v1"
            and primary.get("status") == "passed" and type(primary.get("exit_code")) is int
            and primary["exit_code"] == 0 and primary.get("expected_tests") == list(LINUX_CASES)
            and primary.get("host") == {"system":"Linux","machine":"x86_64"}, "linux_acceptance")
    inputs = artifact_json(root,evidence["source_inputs"])
    require(isinstance(inputs,list) and len({item["path"] for item in inputs}) == len(inputs), "linux_source_inventory")
    policy = primary.get("source_inventory_policy",{})
    materialization_policy(policy)
    digest = hashlib.sha256(json.dumps({"policy":policy,"inputs":inputs},sort_keys=True,separators=(",",":")).encode()).hexdigest()
    require(digest == primary.get("source_binding") == primary.get("source_binding_after"), "linux_source_bracket")
    indexed = {item["path"]:item for item in inputs}
    links = {path:{"state":"symlink","target":item["link_text"],"content_coverage":"link-text-only",
                   "target_sha256":hashlib.sha256(os.fsencode(item["link_text"])).hexdigest()}
             for path,item in indexed.items() if "link_text" in item}
    for source in sources:
        if source.get("content_coverage") == "metadata-only":
            require(source["path"] in indexed,"linux_candidate_metadata")
            observed = indexed.get(source["path"],{})
            try:
                validate_source_rows([observed])
            except ValueError as error:
                raise ValueError("qualification.linux_candidate_metadata") from error
            require(observed == source,"linux_candidate_metadata")
            continue
        target = snapshot_target(source["path"],links,PurePosixPath("/candidate"))
        require(indexed.get(target,{}).get("sha256") == source["sha256"], "linux_candidate_source")
    commands = primary.get("commands",[])
    base = relative_path(evidence["acceptance"]["path"]).parent
    by_log = {}
    for command in commands:
        require(type(command.get("exit_code")) is int and command["exit_code"] == 0
                and command.get("cwd") == "." and command["log"] not in by_log, "linux_command")
        reference = {"path":str(base/relative_path(command["log"])), "sha256":command["log_sha256"]}
        by_log[command["log"]] = (command["command"],checked_log(root,reference))
    expected_command = ["cargo","test","--offline","--locked","-p","chio-control-plane","--lib",LINUX_CASE_PREFIX,"--"]
    require(by_log.get("recovery-list.log",(None,))[0] == [*expected_command,"--list"]
            and by_log.get("recovery-run.log",(None,))[0] == [*expected_command,"--test-threads=1"]
            and by_log.get("cage-enforcement.log",(None,))[0] == ["bash","crates/security/chio-cage/scripts/check-linux-enforcement.sh"],
            "linux_command")
    listed = re.findall(r"^\s*([A-Za-z0-9_:]+): test$",by_log["recovery-list.log"][1],re.MULTILINE)
    require(sorted(listed) == sorted(LINUX_CASES), "linux_list_denominator")
    run = by_log["recovery-run.log"][1]
    completed = []
    pending = None
    for line in (line.strip() for line in run.splitlines()):
        match = re.fullmatch(r"test ([A-Za-z0-9_:]+) \.\.\. ?(ok)?",line)
        if match:
            require(pending is None,"linux_execution_denominator")
            if match[2]: completed.append(match[1])
            else: pending = match[1]
        elif line == "ok" and pending is not None:
            completed.append(pending)
            pending = None
    require(pending is None and sorted(completed) == sorted(LINUX_CASES)
            and re.findall(r"^running (\d+) tests$",run,re.MULTILINE) == [str(len(LINUX_CASES))]
            and top_level_rust_counts(run) == {"passed":len(LINUX_CASES),"failed":0,"ignored":0}, "linux_execution_denominator")
    challenge = primary.get("cage_challenge","")
    require(re.fullmatch(r"[a-f0-9]{64}",challenge) is not None
            and re.findall(r"^CHIO_CAGE_REAL_LINUX_EVIDENCE .+$",by_log["cage-enforcement.log"][1],re.MULTILINE)
            == ["CHIO_CAGE_REAL_LINUX_EVIDENCE challenge="+challenge+" all_targets=72 probes=27 mutations=10"],"linux_cage_evidence")
    images = primary.get("measured_images",[])
    modes = {"error","log","progress","stream","file","callback","wrong-predicate","overflow","hang"}
    require(len(images) == 11 and {image.get("mode") for image in images if "mode" in image} == modes,
            "linux_image_inventory")
    retained = evidence["executables"]
    require(set(retained) == {image["path"] for image in [*images,primary["native_test_executable"]]},"linux_image_inventory")
    for image in [*images,primary["native_test_executable"]]:
        reference = retained[image["path"]]
        require(reference["sha256"] == image["sha256"], "linux_image_binding")
        checked_executable(root,reference,linux=True,static_pie=image in images,mode=image.get("mode"))
    store = evidence["store_gate"]
    require(store.get("id") == "store","linux_store")
    audit_gate(root,store,candidate)
    audit_execution_provenance(root,store,sources,base_commit)
    return True


def audit_model_output(name, output):
    """A marker is insufficient; every declared fault must fail for its invariant."""
    ownership = {
        "OverlappingSelection":"more than one unresolved continuation owns the step",
        "IgnoreOwnerEpoch":"a stale coordinator epoch captured live ownership",
        "ReplayUnknown":"the one modeled effectful step executed more than once",
        "UnknownMeansNoEffect":"an actual effect was classified as closed without effect",
    }
    review = {
        "CloseFromProjection":"missing projection closed a potentially effective native operation",
        "IgnoreAdmissionTombstone":"late submission reopened a closed admission intent",
        "IgnoreCancellation":"capture followed an earlier committed cancellation",
        "ReleaseWithoutJoin":"bytes escaped before native knowledge joined",
        "IgnoreKnowledgeFence":"stale public preparation captured after restricted observation",
        "RevisionBeforeReplay":"committed command replay incorrectly conflicted on its old revision",
        "CachedResponseAfterRevocation":"cached protected response escaped after read revocation",
        "PartialFailureAsNoEffect":"partial failure caused a second external effect for the same step",
    }
    nonce = {
        "FinalizeWithoutCustody":"process finalized without durable exact request custody",
        "PreflightBeforeIntent":"native preflight preceded durable admission intent",
        "RenewMissingNonce":"missing process acknowledgement minted another native nonce",
        "RewriteProcessEnvelope":"native attachment rewrote the frozen process envelope",
        "RequireLiveInitiator":"expired initiator blocked authorized historical settlement",
        "AnyOwnerSuffices":"partial owner or power coverage authorized the complete release",
        "IgnoreApprovalContext":"approval from another action target challenge or source satisfied coverage",
        "CountSignatureAliases":"two aliases of one principal satisfied a two-principal obligation",
    }
    require(name in {"ownership","review","third"},"formal_model_inventory")
    expected = {"ownership":ownership,"review":review,"third":nonce}[name]
    prefix = {"ownership":"","review":"REVIEW ","third":"THIRD "}[name]
    faults = re.findall(r"^"+prefix+r"MUTATION REJECTED ([A-Za-z]+): (.+)$",output,re.MULTILINE)
    require(len(faults) == len(expected) and dict(faults) == expected,
            "formal_model_mutation_inventory")
    if name == "ownership":
        baselines = re.findall(r"^BASELINE PASS: ([1-9]\d*) reachable states, ([1-9]\d*) transitions; "
                              r"exhaustive within the stated bounds\.$",output,re.MULTILINE)
        require(len(baselines) == 1,"formal_model_baseline_inventory")
    elif name == "review":
        baselines = re.findall(r"^REVIEW BASELINE PASS ([A-Za-z]+): ([1-9]\d*) reachable states, "
                              r"([1-9]\d*) transitions; exhaustive within stated bounds\.$",output,re.MULTILINE)
        require(len(baselines) == 4 and {row[0] for row in baselines}
                == {"Admission","Knowledge","Replay","PartialEffect"},"formal_model_baseline_inventory")
    else:
        baselines = re.findall(r"^THIRD BASELINE PASS Nonce: ([1-9]\d*) reachable states, "
                              r"([1-9]\d*) transitions; useful restart reachable\.$",output,re.MULTILINE)
        coverage = re.findall(r"^THIRD CONTRACT PASS Coverage: ([1-9]\d*) bounded cases\.$",output,re.MULTILINE)
        require(len(baselines) == len(coverage) == 1,"formal_model_baseline_inventory")


def audit_kani_tool_version(version):
    require(re.fullmatch(r"Kani Rust Verifier 0\.68\.0 \(cargo plugin\)\nCBMC 6\.11\.0\n?",version) is not None,
            "formal_tool_version")


def audit_formal(root, evidence, candidate, sources, base_commit):
    require(evidence.get("schema") == "chio.recovery-formal-evidence.v1", "formal_record")
    require(sources is not None and base_commit is not None and evidence.get("full_system_proof") is False,
            "formal_scope")
    architecture = artifact_json(root,evidence["architecture"])
    require(architecture.get("schema") in {"chio.recovery-architecture-model-evidence.v1","chio.recovery-architecture-model-evidence.v2"}
            and architecture.get("toolchain") == "+1.94.1" and architecture.get("edition") == "2021",
            "formal_architecture_record")
    prefix = "docs/architecture/recoverable-agent-runtime/model/"
    expected = {row["path"][len(prefix):]:row["sha256"] for row in sources
                if row["path"].startswith(prefix) and (row["path"].endswith(".rs") or row["path"] == prefix+"run.py")}
    require({row["path"]:row["sha256"] for row in architecture["sources"]} == expected,
            "formal_model_sources")
    runs = architecture.get("runs",[])
    require({run.get("name"):run.get("entry") for run in runs}
            == {"ownership":"recovery.rs","review":"review.rs","third":"third.rs"} and len(runs) == 3,
            "formal_model_inventory")
    base = relative_path(evidence["architecture"]["path"]).parent
    commands = architecture.get("commands",[])
    by_name = {command["name"]:command for command in commands}
    require(len(by_name) == len(commands) and set(by_name) == {"format","compiler", *(
        phase+name for name in ["ownership","review","third"] for phase in ["compile-","execute-"])},
        "formal_command_inventory")
    for command in commands:
        require(type(command.get("exit_code")) is int and command["exit_code"] == 0,"formal_command")
        checked_log(root,{"path":str(base/relative_path(command["log"])),"sha256":command["log_sha256"]})
    require(by_name["compiler"]["command"] == ["rustc","+1.94.1","-Vv"],"formal_command")
    for run in runs:
        name = run["name"]
        compile_row, execute = by_name["compile-"+name],by_name["execute-"+name]
        capture = architecture["schema"] == "chio.recovery-architecture-model-evidence.v2"
        expected_compile = ["rustc","+1.94.1","--edition","2021","-D","warnings",run["entry"],
                            *(["--emit","dep-info,link"] if capture else []),"-o"]
        require(compile_row["command"][:-1] == expected_compile
                and execute["command"] == [compile_row["command"][-1]],"formal_command")
        if capture:
            producer = artifact_json(root,compile_row["compiled_capture"])
            require(producer.get("schema") == "chio.compiled-dimension-command-production.v2"
                    and producer.get("dimension") == "formal" and producer.get("label") == name
                    and producer.get("contract") == {"command":compile_row["command"],"cwd":compile_row["cwd"],
                        "environment":{},"caller_source":"docs/architecture/recoverable-agent-runtime/model/run.py",
                        "entry_source":prefix+run["entry"]}
                    and type(producer.get("actual_exit")) is int and producer["actual_exit"] == 0
                    and producer.get("completed") is True and producer.get("qualified") is False,
                    "formal_compilation_producer")
        executable = evidence["executables"][name]
        require(executable["sha256"] == run["executable_sha256"],"formal_executable_binding")
        if capture:require(type(run.get("executable_size")) is int and run["executable_size"] == executable.get("size"),"formal_executable_binding")
        checked_executable(root,executable)
        output = checked_log(root,{"path":str(base/relative_path(run["output"])),"sha256":run["output_sha256"]})
        logged = checked_log(root,{"path":str(base/relative_path(execute["log"])),"sha256":execute["log_sha256"]})
        require(output == logged,"formal_model_verdict")
        audit_model_output(name,output)
        snapshot = relative_path(architecture["input_snapshot"])
        for source in architecture["sources"]:
            require(sha(root/base/snapshot/relative_path(source["path"])) == source["sha256"],"formal_input_snapshot")
        require(Path(compile_row["cwd"]).name == str(snapshot) and compile_row["cwd"] == by_name["format"]["cwd"],
                "formal_input_snapshot")
    tools = evidence.get("tools",[])
    require(len(tools) == 2 and {tool.get("tool") for tool in tools} == {"kani","lean"},
            "formal_tool_inventory")
    for tool in tools:
        primary = artifact_json(root,tool["primary"])
        require(primary.get("schema") == "chio.formal-tool-execution.v1"
                and primary.get("tool") == tool["tool"] and primary.get("source_binding") == candidate,
                "formal_tool_record")
        row = primary["execution"]
        command = row["command"]
        sources_used = primary.get("source_inputs",[])
        require(sources_used and all(source in sources for source in sources_used),"formal_tool_sources")
        expected_command = formal_lane_command(tool["tool"])
        require(command == expected_command and row.get("cwd") == ".","formal_tool_command")
        require(type(row.get("exit_code")) is int and row["exit_code"] == 0,"formal_tool_execution")
        audit_execution_provenance(root,row,sources,base_commit,expected={"command":expected_command,"cwd":".","environment":{}})
        text = checked_log(root,row["log"])
        contract = ".kani/harnesses.toml" if tool["tool"] == "kani" else "formal/lean4/Chio/lean-toolchain"
        retained = primary.get("lane_contract")
        require(isinstance(retained,dict) and retained.get("sha256") == next(
            (source.get("sha256") for source in sources_used if source.get("path") == contract),None),
            "formal_lane_source")
        data = read_bytes(root/relative_path(retained["path"]))
        require(hashlib.sha256(data).hexdigest() == retained["sha256"],"formal_lane_source")
        audit_formal_lane_verdict(tool["tool"],text,data)
        version = checked_log(root,primary["version_log"])
        if tool["tool"] == "kani":
            audit_kani_tool_version(version)
        else:
            required_version = data.decode("utf-8").strip().removeprefix("leanprover/lean4:v")
            require(re.search(r"\bLean \(version "+re.escape(required_version)+r",",version) is not None,
                    "formal_tool_version")
        require(primary.get("executables"),"formal_tool_executable")
        for executable in primary["executables"]:
            checked_executable(root,executable)
    return True


def formal_lane_command(tool):
    require(tool in {"kani","lean"},"formal_tool_inventory")
    return ["bash","scripts/run-kani-manifest.sh","--lane","pr"] if tool == "kani" else \
           ["bash","scripts/check-formal-proofs.sh"]


def audit_formal_lane_verdict(tool, text, contract):
    if tool == "kani":
        manifest = tomllib.loads(contract.decode("utf-8"))
        entries = manifest.get("harness")
        require(manifest.get("schema") == "chio.kani.multi-crate.v1" and isinstance(entries,list)
                and entries,"formal_lane_contract")
        pairs = set()
        selected = []
        for entry in entries:
            pair = (entry.get("crate"),entry.get("harness"))
            require(all(isinstance(value,str) and re.fullmatch(r"[A-Za-z0-9_-]+",value) for value in pair)
                    and pair not in pairs and entry.get("lane") in {"pr","nightly"}
                    and type(entry.get("default_unwind")) is int and entry["default_unwind"] > 0
                    and type(entry.get("timeout_secs")) is int and entry["timeout_secs"] > 0,
                    "formal_lane_contract")
            pairs.add(pair)
            if entry["lane"] == "pr":
                selected.append(entry)
        require(selected,"formal_lane_contract")
        groups = re.findall(r"^::group::cargo kani ([A-Za-z0-9_-]+)::kani_public_harnesses::([A-Za-z0-9_]+) "
                            r"\(unwind=(\d+) timeout=(\d+)s\)$",text,re.MULTILINE)
        expected = [(entry["crate"],entry["harness"],str(entry["default_unwind"]),str(entry["timeout_secs"]))
                    for entry in selected]
        require(groups == expected,"formal_harness_inventory")
        chunks = re.split(r"^::group::cargo kani .+$",text,flags=re.MULTILINE)[1:]
        require(len(chunks) == len(selected) and all(re.findall(
            r"Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total\.",chunk)
            == [("1","0","1")] and len(re.findall(r"^::endgroup::$",chunk,re.MULTILINE)) == 1
            for chunk in chunks),"formal_tool_verdict")
        require(re.findall(r"^run-kani-manifest\.sh: (\d+) harnesses passed \(lane=pr\)$",text,re.MULTILINE)
                == [str(len(selected))],"formal_tool_verdict")
    else:
        require(tool == "lean" and re.fullmatch(rb"leanprover/lean4:v[0-9]+\.[0-9]+\.[0-9]+\n?",contract),
                "formal_lane_contract")
        phases = ["Canonical JSON Lean fixture drift","Lean 4 proof build","Lean 4 placeholder scan",
                  "Elaborated Lean assumption audit regressions","Proof manifest and theorem inventory sanity"]
        require(re.findall(r"^==> (.+)$",text,re.MULTILINE) == phases
                and "Build completed successfully" in text
                and re.findall(r"^PASS: elaborated Lean assumptions include public, private, and generated declarations$",
                               text,re.MULTILINE)
                and re.findall(r"^formal proof check passed$",text,re.MULTILINE) == ["formal proof check passed"],
                "formal_tool_verdict")


def audit_hosted_ci(root, evidence, candidate, sources, base_commit):
    require(evidence.get("schema") == "chio.recovery-hosted-ci.v2", "hosted_ci_record")
    require(sources is not None and base_commit is not None,"hosted_ci_source")
    commit = evidence.get("commit","")
    repository = evidence.get("repository","")
    require(re.fullmatch(r"[a-f0-9]{40}",commit) is not None
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repository) is not None,"hosted_ci_commit")
    primary = artifact_json(root,evidence["check_runs"])
    checks = primary.get("check_runs",[])
    require(type(primary.get("total_count")) is int and primary["total_count"] == len(checks)
            and len({check.get("id") for check in checks}) == len(checks),"hosted_ci_check_inventory")
    expected = {"Build, lint, test","MSRV build and test","cargo-vet (locked supply-chain audit)",
                "cargo-deny (supply-chain bans/advisories/licenses)"}
    selected = [check for check in checks if check.get("name") in expected]
    require(len(selected) == len(expected) and {check["name"] for check in selected} == expected
            and all(type(check.get("id")) is int and check["id"] > 0
                    and check.get("head_sha") == commit and check.get("status") == "completed"
                    and check.get("conclusion") == "success"
                    and check.get("url") == f"https://api.github.com/repos/{repository}/check-runs/{check['id']}"
                    and isinstance(check.get("details_url"),str)
                    and re.fullmatch(r"https://github\.com/"+re.escape(repository)+r"/actions/runs/[0-9]+/job/[0-9]+",check["details_url"])
                    and check.get("app",{}).get("slug") == "github-actions" for check in selected),"hosted_ci_checks")
    inventory = artifact_json(root,evidence["executed_source_inventory"])
    require(inventory.get("source_inventory_version") == INVENTORY_VERSION and inventory.get("base_commit") == commit
            and inventory.get("sources") == sources and inventory.get("source_binding") == binding(sources,commit),
            "hosted_ci_source")
    receipt = artifact_json(root,evidence["workflow_artifact"])
    require(receipt.get("schema") == "chio.hosted-workflow-artifact.v1" and receipt.get("repository") == repository
            and receipt.get("commit") == commit and type(receipt.get("run_id")) is int and receipt["run_id"] > 0
            and receipt.get("source_inventory") == evidence["executed_source_inventory"],"hosted_ci_artifact")
    require(all(f"/actions/runs/{receipt['run_id']}/" in check["details_url"] for check in selected),"hosted_ci_artifact")
    return True


def audit_review(root, evidence, candidate, sources, base_commit):
    require(evidence.get("schema") == "chio.recovery-review-closure.v2", "review_record")
    require(sources is not None and base_commit is not None,"review_source")
    catalogue = artifact_json(root,evidence["finding_catalogue"])
    dispositions = artifact_json(root,evidence["dispositions"])
    require(catalogue.get("format") == "recovery-findings-inventory.v1"
            and catalogue.get("findings"),"review_finding_inventory")
    original = {row["id"]:row for row in catalogue["findings"]}
    require(len(original) == len(catalogue["findings"]) and isinstance(dispositions,list)
            and len(dispositions) == len(original) and {row["id"] for row in dispositions} == set(original),
            "review_disposition_inventory")
    reviewers = evidence.get("reviews",[])
    require(reviewers and len({review["reviewer"] for review in reviewers}) == len(reviewers),"review_inventory")
    reviewed = set()
    approved = set()
    source_index = {row["path"]:row["sha256"] for row in sources if "sha256" in row}
    for review in reviewers:
        primary = artifact_json(root,review["primary"])
        require(primary.get("schema") == "chio.independent-source-review.v1"
                and primary.get("source_binding") == candidate and primary.get("base_commit") == base_commit
                and primary.get("reviewer") == review["reviewer"] and primary.get("independent") is True,
                "review_source")
        require(primary.get("sources") and all(source_index.get(row["path"]) == row["sha256"] for row in primary["sources"]),
                "review_source")
        log = checked_log(root,primary["report"])
        require(log.strip() and isinstance(primary.get("findings"),list),"review_report")
        require(not [finding for finding in primary["findings"] if finding.get("status") != "closed"],"review_open_findings")
        reviewed.update(row["path"] for row in primary["sources"])
        approved.update(primary.get("verified_disposition_ids",[]))
    required_scope = artifact_json(root,evidence["required_source_scope"])
    require(required_scope.get("schema") == "chio.recovery-review-source-scope.v1"
            and required_scope.get("source_binding") == candidate and required_scope.get("base_commit") == base_commit
            and required_scope.get("sources") and all(source_index.get(row["path"]) == row["sha256"]
                for row in required_scope["sources"]),"review_scope")
    require(reviewed >= {row["path"] for row in required_scope["sources"]},"review_scope")
    for disposition in dispositions:
        require(disposition.get("status") in {"fixed","verified_preexisting_fix","verified_alias","verified_not_applicable"}
                and disposition["id"] in approved and disposition.get("rationale")
                and disposition.get("evidence"),"review_open_findings")
        for reference in disposition["evidence"]:
            artifact_json(root,reference)
    return True


def audit_live_provider(root, evidence, candidate, sources, base_commit):
    require(evidence.get("schema") == "chio.recovery-live-provider-evidence.v1", "live_provider_record")
    require(sources is not None and base_commit is not None,"live_provider_source")
    declaration = artifact_json(root,evidence["cohort_declaration"])
    attempts = artifact_json(root,evidence["cohort_attempts"])
    audit_attempts(declaration,attempts,root,candidate)
    require(attempts and attempts[-1]["qualified"],"live_provider_qualification")
    return True


def audit_live_cohort(root, reference, candidate):
    """Recount the sealed matrix and independently retained native observations."""
    evidence = artifact_json(root,reference)
    require(evidence.get("schema") == "chio.recovery-live-cohort-evidence.v1"
            and evidence.get("source_binding") == candidate,"cohort_primary_evidence")
    manifest = artifact_json(root,evidence["manifest"])
    require(manifest.get("schema") == "chio.recovery-live-corpus.v2"
            and manifest.get("source_inventory_version") == INVENTORY_VERSION
            and manifest.get("provider_endpoint") == PROVIDER_ENDPOINT
            and manifest.get("source_binding") == candidate
            and binding(manifest["sources"],manifest["base_commit"]) == candidate,"cohort_manifest")
    require(manifest.get("model") == COHORT_MODEL and manifest.get("hosts") == COHORT_HOSTS,
            "cohort_profile")
    expected = [{"id":f"{host}-{workflow}-{arm}-{case}-r{repeat}","host":host,"workflow":workflow,
                 "arm":arm,"case":case,"repetition":repeat}
                for host in ["langgraph","crewai"] for workflow in ["support","artifact"]
                for arm in ["baseline","product"]
                for case in ["authorized","lost_ack_restart","wrong_authority","conflicting_basis"]
                for repeat in range(1,4)]
    require(manifest.get("trials") == expected,"cohort_matrix")
    budgets = {"model_calls":4,"tool_actions":8,"prompt_bytes":16384,"output_tokens":512,"output_bytes":8192,
               "provider_seconds":45,"native_http_seconds":120,"native_preparation_seconds":240,
               "native_shutdown_seconds":120,"host_start_deadline_seconds":240,"trial_seconds":720,
               "concurrent_trials":2,"transport_retries":0}
    require(manifest.get("budgets") == budgets and isinstance(manifest.get("model"),str)
            and manifest["model"] and re.fullmatch(r"[a-f0-9]{64}",manifest.get("authority_policy","")),
            "cohort_policy")
    raw = read_bytes(root/relative_path(evidence["rows"]["path"]))
    require(hashlib.sha256(raw).hexdigest() == evidence["rows"]["sha256"],"evidence_reference_hash")
    rows = [json.loads(line,object_pairs_hook=closed_pairs,
            parse_constant=lambda _:require(False,"nonfinite_json_number")) for line in raw.splitlines() if line.strip()]
    planned = {trial["id"]:trial for trial in expected}
    require(len(rows) <= 96 and len({row.get("id") for row in rows}) == len(rows)
            and {row.get("id") for row in rows} <= set(planned),"cohort_row_inventory")
    retained = evidence.get("trials",{})
    require(set(retained) == {row["id"] for row in rows},"cohort_trial_inventory")
    positive = {(host,workflow,arm,case):0 for host in ["langgraph","crewai"]
                for workflow in ["support","artifact"] for arm in ["baseline","product"]
                for case in ["authorized","lost_ack_restart"]}
    native_unknown = 0
    failures = 0
    unknown_tokens = 0
    for row in rows:
        require(all(row.get(key) == value for key,value in planned[row["id"]].items()),"cohort_trial_identity")
        require(all(row.get(key) == manifest[key] for key in ["source_binding","base_commit","provider_endpoint",
                    "source_inventory_version","authority_policy"])
                and row.get("requested_model") == manifest["model"],"cohort_trial_source")
        require(type(row.get("hidden_retries")) is int and row["hidden_retries"] == 0
                and type(row.get("tool_actions")) is int and 0 <= row["tool_actions"] <= 8,"cohort_budget")
        require(row.get("outcome") in ["complete", "completed_with_effects", "waiting_for_approval",
                    "waiting_for_outcome", "reconciliation_required", "closed_without_effect", "withheld",
                    "quarantined", "cancel_requested", "cancelled", "refused", "unavailable",
                    "restart_required", "conflict", "unsupported_profile", "uncovered_mediation",
                    "probe_expired", "origin_refused", "busy", "projection_too_large",
                    "invalid_choice", "skipped_tool", "parser_error", "provider_error",
                    "budget_exhausted", "framework_error", "native_error"],"cohort_outcome")
        attempts = row.get("model_attempts")
        require(isinstance(attempts,list) and len(attempts) <= 4,"cohort_budget")
        elapsed = row.get("elapsed_seconds")
        require(type(elapsed) in [int,float] and math.isfinite(elapsed) and elapsed >= 0,"cohort_latency")
        provider_seconds = 0
        successful_provider_response = False
        for attempt in attempts:
            require(attempt.get("provider_endpoint") == PROVIDER_ENDPOINT
                    and attempt.get("model") in [None,manifest["model"]],"cohort_provider")
            error = attempt.get("error")
            require(error in [None,"provider_unavailable","model_budget_exhausted","prompt_budget_exhausted",
                             "response_budget_exhausted","response_invalid"],"cohort_provider")
            if error is None:
                require(attempt.get("model") == manifest["model"] and isinstance(attempt.get("request_id"),str)
                        and attempt["request_id"],"cohort_provider")
            messages = attempt.get("messages")
            require(isinstance(messages,list),"cohort_prompt")
            encoded = json.dumps(messages,ensure_ascii=False,separators=(",",":"),allow_nan=False).encode()
            require(type(attempt.get("prompt_bytes")) is int and len(encoded) == attempt["prompt_bytes"] <= 16384
                    and hashlib.sha256(encoded).hexdigest() == attempt.get("prompt_sha256"),"cohort_prompt")
            for key in ["input_tokens","output_tokens"]:
                value = attempt.get(key)
                require(type(value) is int and 0 <= value <= 1000000 or error is not None and value is None,
                        "cohort_token_usage")
            unknown_tokens += int(attempt.get("input_tokens") is None or attempt.get("output_tokens") is None)
            seconds = attempt.get("seconds")
            require(type(seconds) in [int,float] and math.isfinite(seconds) and seconds >= 0,"cohort_latency")
            # Provider calls are serial. Allow only the public six-place timing
            # rounding error when joining them to the containing trial.
            require(seconds <= elapsed + 0.00001,"cohort_latency")
            provider_seconds += seconds
            require(math.isfinite(provider_seconds) and provider_seconds <= elapsed + 0.00001,
                    "cohort_latency")
            if error is None:
                completion = attempt.get("completion")
                require(type(completion) is str
                        and attempt["output_tokens"] <= budgets["output_tokens"],"cohort_provider_completion")
                try:
                    completion_bytes = completion.encode("utf-8")
                except UnicodeEncodeError:
                    require(False,"cohort_provider_completion")
                require(len(completion_bytes) <= budgets["output_bytes"],"cohort_provider_completion")
                successful_provider_response = successful_provider_response or bool(completion.strip())
        references = retained[row["id"]]
        require(artifact_json(root,references["result"]) == row,"cohort_result_join")
        native = row.get("native")
        if native is None:
            require(row.get("native_observation") == "unknown","cohort_native_unknown")
            native_unknown += 1
            continue
        require(type(native) is dict and row.get("native_observation") == "observed",
                "cohort_native_observation")
        require(artifact_json(root,references["native"]) == native,"cohort_native_join")
        log = checked_log(root,references["native_log"])
        native_exit = row.get("native_exit_code")
        require(native_exit is None or type(native_exit) is int,"cohort_native_execution")
        native_passed = native_exit == 0 and top_level_rust_counts(log) == {"passed":1,"failed":0,"ignored":0} \
            and "live_comparative_native_host" in log
        if native_passed:
            checked_executable(root,references["native_executable"])
            require(row.get("native_executable",{}).get("sha256") == references["native_executable"]["sha256"],
                    "cohort_native_executable")
        else:
            require(row.get("native_execution_error") is True,"cohort_native_execution")
        for key in ["effects","charges","unauthorized_effects","duplicate_effects","unresolved","unresolved_age_ms","extra_approvals"]:
            require(type(native.get(key)) is int and 0 <= native[key] <= 1000000,"cohort_native_counters")
        require(type(native.get("source_label_retained")) is bool and type(native.get("useful_completion")) is bool,
                "cohort_native_counters")
        require(not native["useful_completion"] or row["tool_actions"] > 0,"cohort_completion_without_action")
        if row.get("outcome") == "complete":
            require(successful_provider_response and native["useful_completion"],"cohort_trial_completion")
        failures += int(native["unauthorized_effects"] != 0 or native["duplicate_effects"] != 0
                        or native["source_label_retained"] is not True or not attempts or not native_passed
                        or row.get("native_execution_error") or row.get("native_shutdown_error")
                        or row.get("native_evidence_error") or row.get("native_executable_error") or elapsed > 720)
        key = tuple(row[field] for field in ["host","workflow","arm","case"])
        if key in positive and row.get("outcome") == "complete" and native["useful_completion"]:
            positive[key] += 1
    passed = sum(value >= 1 for value in positive.values())
    measured = {"planned_trials":96,"measured_trials":len(rows),"unknown_trials":96-len(rows),
                "native_unknown_trials":native_unknown,"unknown_token_usage_attempts":unknown_tokens,
                "positive_strata":16,"positive_strata_passed":passed,
                "qualified":len(rows) == 96 and native_unknown == failures == 0 and passed == 16}
    require(evidence.get("recomputed") == measured,"cohort_report_recomputation")
    return measured


def audit_dimensions(root, references, candidate, sources=None, base_commit=None):
    """External dimensions require retained, source-bound records, never flags."""
    dimensions = {name:False for name in ["linux", "formal", "live_provider", "hosted_ci", "complete_review"]}
    require(isinstance(references, dict) and not set(references) - set(dimensions), "dimension_inventory")
    for name, reference in references.items():
        evidence = artifact_json(root, reference)
        require(evidence.get("source_binding") == candidate, "dimension_source")
        adapters = {"linux":audit_linux,"formal":audit_formal,"live_provider":audit_live_provider,
                    "hosted_ci":audit_hosted_ci,"complete_review":audit_review}
        dimensions[name] = adapters[name](root,evidence,candidate,sources,base_commit)
    return dimensions


def audit_performance(root, performance, candidate=None, sources=None, base_commit=None):
    require(candidate is not None and sources is not None and base_commit is not None,
            "performance_execution_provenance")
    executions = performance.get("executions")
    require(isinstance(executions,dict) and set(executions) == {"native","pure"},"performance_execution_provenance")
    for name in ["native","pure"]:
        row = executions[name]
        require(row.get("id") == name+"-performance", "performance_command")
        audit_gate(root,row,candidate)
        audit_execution_provenance(root,row,sources,base_commit)
        require(row["log"] == performance["logs"][name],"performance_log_binding")
        require(row.get("executables"),"performance_executable_binding")
        for executable in row["executables"]:
            checked_executable(root,executable)
    native = performance["native"]
    pure = performance["pure"]
    audit_samples(native)
    require(performance.get("native_p95_ceiling_ns") == 220683049, "performance_ceiling")
    require(native.get("profile") == "debug" and native.get("errors") == 0
            and native.get("samples") == 64 and native.get("warmups") == native.get("replays") == 8
            and native.get("effect_count") == native.get("logical_call_charges") == 72, "performance_denominator")
    require(0 < native["p95_ns"] <= 220683049, "performance_ceiling_exceeded")
    require(pure.get("profile") == "debug" and pure.get("errors") == 0, "pure_profile")
    ceilings = {"intake":5000000, "digest":250000, "reduction":250000, "graph_16_steps":1000000}
    require(set(pure) == {"profile", "errors", *ceilings}, "performance_inventory")
    for name, ceiling in ceilings.items():
        item = pure[name]
        audit_samples(item)
        require(item.get("samples") == 1000 and item.get("warmups") == 100
                and item.get("p95_ceiling_ns") == ceiling and 0 < item["p95_ns"] <= ceiling, "pure_ceiling")
    for name, prefix, value in [("native", "NATIVE_RECOVERY_BASELINE ", native),
                                ("pure", "PURE_RECOVERY_BASELINE ", pure)]:
        reference = performance["logs"][name]
        raw = read_bytes(root / relative_path(reference["path"]))
        rows = [json.loads(line[len(prefix):], object_pairs_hook=closed_pairs)
                for line in raw.decode().splitlines() if line.startswith(prefix)]
        require(rows == [value], "performance_log_recomputation")
        require(hashlib.sha256(raw).hexdigest() == reference["sha256"], "performance_log_hash")


def audit_archive(path, sources):
    expected = {row["path"]:row["sha256"] for row in sources if "sha256" in row}
    require(len({row["path"] for row in sources}) == len(sources), "source_duplicates")
    seen = set()
    folded = set()
    with regular_input(path) as stream:
        with tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                name = str(relative_path(member.name))
                require(member.isfile() and name in expected and name not in seen
                        and portable_path_key(name) not in folded, "source_archive_inventory")
                data = archive.extractfile(member)
                require(data is not None, "source_archive_member")
                digest = hashlib.sha256()
                for chunk in iter(lambda:data.read(1024*1024), b""):
                    digest.update(chunk)
                require(digest.hexdigest() == expected[name], "source_archive_hash")
                seen.add(name)
                folded.add(portable_path_key(name))
    require(seen == set(expected), "source_archive_inventory")


def compiled_subjects(root, record):
    """Identify Rust commands and every explicitly claimed native image."""
    subjects = {}
    for row in record.get("gates", []):
        command = row.get("command", [])
        if command and (command[0] == "target/debug/xtask"
                or command[0] == "cargo" and "fmt" not in command[:3]):
            subjects["gate/"+row["id"]] = row.get("executables", [])
    performance = record.get("performance") or {}
    for name, row in performance.get("executions", {}).items():
        subjects["performance/"+name] = row.get("executables", [])
    for name, reference in record.get("dimension_records", {}).items():
        if name not in {"linux", "formal", "live_provider"}:
            continue
        evidence = artifact_json(root, reference)
        images = evidence.get("executables", {})
        if type(images) is dict:
            for label, image in images.items():
                subjects["dimension/"+name+"/"+label] = [image]
        if name == "linux" and "acceptance" in evidence:
            primary = artifact_json(root,evidence["acceptance"])
            require(type(images) is dict,"compiled_profile_subjects")
            for image in [*primary.get("measured_images",[]),primary.get("native_test_executable")]:
                require(type(image) is dict and type(image.get("path")) is str
                        and image["path"] in images,"compiled_profile_subjects")
                retained = images[image["path"]]
                require(retained.get("sha256") == image.get("sha256")
                        and retained.get("size") == image.get("size"),"compiled_profile_subjects")
                subjects["dimension/linux/"+image["path"]] = [{**retained,"original_relative_path":image["path"]}]
        elif name == "formal" and "architecture" in evidence:
            architecture = artifact_json(root,evidence["architecture"])
            commands = {row["name"]:row for row in architecture.get("commands",[])}
            for run in architecture.get("runs",[]):
                label = run.get("name")
                require(type(label) is str and label in images and "compile-"+label in commands,"compiled_profile_subjects")
                command = commands["compile-"+label]["command"]
                require(type(command) is list and bool(command) and type(command[-1]) is str,"compiled_profile_subjects")
                subjects["dimension/formal/"+label] = [{**images[label],"original_path":command[-1]}]
        elif name == "live_provider" and "cohort_attempts" in evidence:
            attempts = artifact_json(root,evidence["cohort_attempts"])
            require(type(attempts) is list and bool(attempts),"compiled_profile_subjects")
            cohort = artifact_json(root,attempts[-1]["primary"])
            raw = read_bytes(root/relative_path(cohort["rows"]["path"]))
            require(hashlib.sha256(raw).hexdigest() == cohort["rows"]["sha256"],"evidence_reference_hash")
            rows = [json.loads(line,object_pairs_hook=closed_pairs) for line in raw.splitlines() if line.strip()]
            require(len(rows) == 96 and type(cohort.get("trials")) is dict,"compiled_profile_subjects")
            native = {}
            for row in rows:
                require(type(row) is dict and type(row.get("id")) is str and row["id"] in cohort["trials"]
                        and type(row.get("native_executable")) is dict,"compiled_profile_subjects")
                image = cohort["trials"][row["id"]]["native_executable"]
                observed = row["native_executable"]
                require(type(observed.get("path")) is str and observed.get("sha256") == image.get("sha256")
                        and observed.get("size") == image.get("size"),"compiled_profile_subjects")
                key = (observed["path"],image["sha256"],image["size"])
                native[key] = {**image,"original_relative_path":observed["path"]}
            subjects["dimension/live_provider/native-host-library"] = list(native.values())
    return subjects


def checked_compiled_blob(root, image):
    """Bind retained ordinary image bytes without interpreting copied inodes."""
    require(type(image) is dict and set(image) == {"path", "sha256", "size"}
            and re.fullmatch(r"[a-f0-9]{64}", image.get("sha256", ""))
            and type(image.get("size")) is int and 0 <= image["size"] <= 512*1024**2,
            "compiled_profile_image")
    path = root/relative_path(image["path"])
    with regular_input(path) as stream:
        metadata = os.fstat(stream.fileno())
        require(metadata.st_nlink == 1 and metadata.st_size == image["size"], "compiled_profile_image")
        digest = hashlib.sha256()
        for chunk in iter(lambda:stream.read(1024*1024), b""):
            digest.update(chunk)
        require(digest.hexdigest() == image["sha256"], "compiled_profile_image")


@contextmanager
def compiled_image_custody(root):
    """Keep each retained image and its parents bound through aggregate return."""
    with ExitStack() as descriptors:
        inputs = descriptors.enter_context(compiler_input_custody())
        originals = {}
        total_bytes = 0
        def hold(image):
            nonlocal total_bytes
            require(type(image) is dict and set(image) == {"path","sha256","size"}
                    and type(image.get("sha256")) is str
                    and re.fullmatch(r"[a-f0-9]{64}",image["sha256"])
                    and type(image.get("size")) is int
                    and 0 <= image["size"] <= COMPILED_IMAGE_MAX_BYTES,
                    "compiled_profile_image")
            path = root/relative_path(image["path"])
            expected = image["sha256"],image["size"]
            if path in originals:
                require(originals[path][0] == expected, "compiled_profile_image")
                return
            stream = descriptors.enter_context(inputs(path))
            identity = compiler_metadata_identity(os.fstat(stream.fileno()))
            require(identity[3] == image["size"] and identity[-1] == 1, "compiled_profile_image")
            total_bytes += image["size"]
            require(total_bytes <= COMPILED_IMAGE_POOL_MAX_BYTES, "compiled_profile_image_budget")
            originals[path] = (expected,identity,stream)
        yield hold
        for path,(expected,identity,stream) in originals.items():
            require(compiler_metadata_identity(os.fstat(stream.fileno())) == identity
                    and compiler_metadata_identity(os.stat(path,follow_symlinks=False)) == identity,
                    "compiled_profile_image")
            stream.seek(0)
            digest = hashlib.sha256()
            for chunk in iter(lambda:stream.read(1024*1024),b""):
                digest.update(chunk)
            require(digest.hexdigest() == expected[0], "compiled_profile_image")


def hold_compiled_profile_references(root, profile, image_custody):
    """Bind direct portable references, including tools and process records."""
    pending,visited = [profile],0
    while pending:
        value = pending.pop()
        visited += 1
        require(visited <= 2000000, "compiled_profile_images")
        if type(value) is dict:
            if {"path","sha256"} <= set(value) and type(value["path"]) is str \
                    and not value["path"].startswith("/"):
                path = relative_path(value["path"])
                require(type(value.get("sha256")) is str
                        and re.fullmatch(r"[a-f0-9]{64}",value["sha256"]) is not None
                        and not secret_source(path.as_posix()), "compiled_profile_image")
                info = os.stat(root/path,follow_symlinks=False)
                image_custody({"path":path.as_posix(),"sha256":value["sha256"],"size":info.st_size})
            pending.extend(value.values())
        elif type(value) is list:
            pending.extend(value)


def audit_compilation_scope_data(data, source_binding, repository, namespace, publications, retained, retained_raw=None):
    """Join decoded scope data to checked CAS bytes and completed publications."""
    fields = {"schema","scope_path","scope_sha256","configuration","declaration","scope","inventories",
              "command","events","runtime_inventory","source_origin","rows"}
    require(type(data) is dict and set(data) == fields
            and data["schema"] == "chio.original-linux-compilation-data.v1", "compiled_profile_linux_scope")
    scope_path = compilation_absolute_path(data["scope_path"])
    config, declaration, scope = (data[key] for key in ["configuration","declaration","scope"])
    require(config.get("candidate") == str(repository) and config.get("records") == str(namespace),
            "compiled_profile_linux_scope")
    require(retained(scope["policy"]["configuration"]) == config
            and retained(scope["declaration"]) == declaration
            and [retained(row["inventory"]) for row in declaration["scopes"]] == data["inventories"]
            and retained(declaration["runtime_inventory"]) == data["runtime_inventory"]
            and retained(declaration["source_origin"]) == data["source_origin"]
            and retained(scope["execution"]["supervisor_events"]) == data["events"], "compiled_profile_linux_scope")
    require(data["runtime_inventory"].get("source_binding") == source_binding,
            "compiled_profile_linux_source")
    result = audit_linux_compilation_scope_records(config, declaration, scope, data["inventories"],
        source_binding, data["command"], str(scope_path.with_name("declaration.json")))
    events = data["events"]
    require(type(events) is dict and set(events) == {"schema","events"}
            and type(events["schema"]) is str
            and events["schema"] in {"chio.compilation-supervisor-events.v1","chio.compilation-supervisor-events.v2"}
            and type(events["events"]) is list and len(events["events"]) <= 100000, "compiled_profile_linux_dispatch")
    rows = data["rows"]
    require(type(rows) is list and len(rows) <= 100000, "compiled_profile_rows")
    selected = {row.get("invocation_id"):row for row in rows}
    available = {row["invocation_id"]:row for row in publications["records"]}
    require(len(selected) == len(rows) and set(selected) <= set(available), "compiled_profile_rows")
    for identifier, row in selected.items():
        require(hashlib.sha256(compilation_canonical(row)+b"\n").hexdigest()
                == available[identifier]["record_sha256"], "compiled_profile_rows")
    subset = {"records":[available[identifier] for identifier in selected]}
    def read_record(path):
        require(path.parent == Path(namespace)/"records" and path.suffix == ".json"
                and path.stem in selected, "compiled_profile_rows")
        return selected[path.stem]
    joins = audit_compilation_dispatches(Path(namespace),config,declaration,events,subset,read_record,
        lambda _namespace, image:retained(image),
        lambda path:compilation_canonical(read_record(path))+b"\n", retained_raw)
    readonly = {}
    for inventory in data["inventories"]:
        for member in inventory["members"]:
            if member["kind"] == "regular":
                key = str(compilation_absolute_path(inventory["root"])/member["path"])
                readonly[key] = {**member,"path":key,"role":inventory["role"]}
    compiler = declaration["images"]["rustc"]
    for row in rows:
        require(row.get("compiler") is None or compiler_graph_image(row["compiler"])
                == compiler_graph_image(compiler), "compiled_profile_linux_compiler")
    return {"scope_id":result["scope_id"],"verified_dispatches":joins,"unit_ids":sorted(selected),
            "readonly":readonly,"configuration":config,"declaration":declaration}


def inspect_linux_compiled_profile(linux, request, profile, verified_native_inputs=None):
    """Observe completed native scopes in the actual protected namespace."""
    require(type(linux) is dict and set(linux) == {"schema","source_location","scopes"}
            and linux["schema"] == "chio.linux-compiler-custody-request.v1"
            and type(linux["scopes"]) is list and 0 < len(linux["scopes"]) <= 512,
            "compiled_profile_linux_required")
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "compiled_profile_mode")
    repository, namespace = (Path(request[key]) for key in ["repository","namespace"])
    location = linux["source_location"]
    with compiler_namespace_directory(repository) as root_descriptor, ExitStack() as held:
        info = os.fstat(root_descriptor)
        expected_location = {"schema":"chio.source-location.v1","repository":str(repository),
            "host":{"system":platform.system(),"machine":platform.machine(),"node":platform.node()},
            "root":{"device":info.st_dev,"inode":info.st_ino,"mode":info.st_mode & 0o7777,"uid":info.st_uid}}
        require(location == expected_location, "compiled_profile_linux_location")
        observed, retained_bytes = {}, 0
        output_originals = {}
        observed_directories = {}
        def read_original(path):
            path = Path(compilation_absolute_path(str(path)))
            if path in observed and observed[path][1] is not None:
                return observed[path][0]
            stream = observed[path][3] if path in observed else held.enter_context(regular_input(path))
            metadata = compiler_metadata_identity(os.fstat(stream.fileno()))
            require(metadata[3] <= 16*1024**2 and metadata[-1] == 1, "compiled_profile_linux_scope")
            stream.seek(0)
            raw = stream.read(16*1024**2+1)
            value = json.loads(raw, object_pairs_hook=closed_pairs,
                parse_constant=lambda _:require(False,"nonfinite_json_number"))
            observed[path] = (value,raw,metadata,stream)
            return value
        def retained(image):
            require(type(image) is dict and type(image.get("sha256")) is str
                    and re.fullmatch(r"[a-f0-9]{64}",image["sha256"])
                    and image.get("artifact") == "artifacts/"+image["sha256"]
                    and type(image.get("size")) is int and 0 <= image["size"] <= 16*1024**2,
                    "compiled_profile_linux_image")
            path = namespace/image["artifact"]
            value = read_original(path)
            raw = observed[path][1]
            require(len(raw) == image["size"] and hashlib.sha256(raw).hexdigest() == image["sha256"],
                    "compiled_profile_linux_image")
            return value
        def retained_output_raw(image):
            nonlocal retained_bytes
            path = namespace/image["artifact"]
            if path in output_originals:
                raw, _identity, _stream = output_originals[path]
                require(len(raw) == image["size"] and hashlib.sha256(raw).hexdigest() == image["sha256"],
                        "compiled_profile_linux_image")
                return raw
            stream = held.enter_context(regular_input(path))
            identity = compiler_metadata_identity(os.fstat(stream.fileno()))
            require(identity[3] == image["size"] <= 16*1024**2 and identity[-1] == 1,
                    "compiled_profile_linux_image")
            retained_bytes += image["size"]
            require(retained_bytes <= 16*1024**3, "compiled_profile_linux_image")
            raw = stream.read(16*1024**2+1)
            require(len(raw) == image["size"] and hashlib.sha256(raw).hexdigest() == image["sha256"],
                    "compiled_profile_linux_image")
            output_originals[path] = (raw,identity,stream)
            return raw
        scope_reports, covered, seen_scopes = [], set(), set()
        publications = profile["publication"]
        require(publications["incomplete_records"] == 0, "compiled_profile_linux_publication")
        for reference in linux["scopes"]:
            require(type(reference) is dict and set(reference) == {"scope","command"}, "compiled_profile_linux_scope")
            scope_reference, command_reference = reference["scope"], reference["command"]
            for value in [scope_reference,command_reference]:
                require(type(value) is dict and set(value) == {"path","sha256"}
                        and re.fullmatch(r"[a-f0-9]{64}",value.get("sha256","")), "compiled_profile_linux_scope")
            scope_path = Path(compilation_absolute_path(scope_reference["path"]))
            require(scope_path.name == "scope.json" and scope_path not in seen_scopes, "compiled_profile_linux_scope")
            seen_scopes.add(scope_path)
            scope = read_original(scope_path)
            require(hashlib.sha256(observed[scope_path][1]).hexdigest() == scope_reference["sha256"],
                    "compiled_profile_linux_scope")
            declaration = read_original(scope_path.with_name("declaration.json"))
            command_path = Path(compilation_absolute_path(command_reference["path"]))
            command = read_original(command_path)
            require(hashlib.sha256(observed[command_path][1]).hexdigest() == command_reference["sha256"],
                    "compiled_profile_linux_scope")
            config = retained(scope["policy"]["configuration"])
            require(scope_path.parent.parent == Path(config["evidence"]), "compiled_profile_linux_scope")
            events = retained(scope["execution"]["supervisor_events"])
            ids = [row["invocation_id"] for event in events["events"] for row in event["records"]]
            require(len(ids) == len(set(ids)), "compiled_profile_linux_dispatch")
            rows = [read_original(namespace/"records"/(identifier+".json")) for identifier in ids]
            data = {"schema":"chio.original-linux-compilation-data.v1","scope_path":str(scope_path),
                "scope_sha256":scope_reference["sha256"],"configuration":config,"declaration":declaration,
                "scope":scope,"inventories":[retained(row["inventory"]) for row in declaration["scopes"]],
                "command":command,"events":events,"runtime_inventory":retained(declaration["runtime_inventory"]),
                "source_origin":retained(declaration["source_origin"]),"rows":rows}
            joined = audit_compilation_scope_data(data,request["source_binding"],repository,namespace,publications,retained,
                                                 retained_output_raw)
            hold_compilation_directory_metadata(data["inventories"],held,observed_directories)
            check_compilation_alias_physical(declaration)
            recorder = config["images"]["recorder"]
            current = {str(repository/source["path"]):source.get("sha256") for source in
                       current_source_inventory(repository)}
            require(current.get(recorder["path"]) == recorder["sha256"] and data["runtime_inventory"]["sources"]
                    == current_source_inventory(repository), "compiled_profile_linux_source")
            for image in request["additional_inputs"]:
                key = compiler_graph_image(image)
                if image["role"] != "campaign-produced":
                    require(key[0] in joined["readonly"] and compiler_graph_image(joined["readonly"][key[0]]) == key
                            and joined["readonly"][key[0]]["role"] == image["role"], "compiled_profile_linux_source")
            for image in joined["readonly"].values():
                path = namespace/image["artifact"]
                if path in observed:
                    require(len(observed[path][1]) == image["size"]
                            and hashlib.sha256(observed[path][1]).hexdigest() == image["sha256"],
                            "compiled_profile_linux_image")
                    continue
                stream = held.enter_context(regular_input(path))
                metadata = compiler_metadata_identity(os.fstat(stream.fileno()))
                retained_bytes += image["size"]
                require(metadata[3] == image["size"] <= 512*1024**2 and metadata[-1] == 1
                        and retained_bytes <= 16*1024**3, "compiled_profile_linux_image")
                digest = hashlib.sha256()
                for chunk in iter(lambda:stream.read(1024*1024),b""):
                    digest.update(chunk)
                require(digest.hexdigest() == image["sha256"], "compiled_profile_linux_image")
                observed[path] = (None,None,metadata,stream)
            require(not covered.intersection(ids), "compiled_profile_linux_dispatch")
            covered.update(ids)
            if verified_native_inputs is not None:
                verified_native_inputs.setdefault(joined["scope_id"],set()).update(
                    compiler_graph_image(image) for image in joined["readonly"].values()
                    if image["role"] in {"toolchain","native-runtime"})
            scope_reports.append({"scope_path":str(scope_path),"scope_sha256":scope_reference["sha256"],
                "data_sha256":hashlib.sha256(compilation_canonical(data)+b"\n").hexdigest(),
                "scope_id":joined["scope_id"],"unit_ids":joined["unit_ids"],
                "verified_dispatches":joined["verified_dispatches"]})
        require(set(profile["selected_invocation_ids"]) <= covered, "compiled_profile_linux_dispatch")
        for path, (_value,_raw,identity,stream) in observed.items():
            require(compiler_metadata_identity(os.fstat(stream.fileno())) == identity
                    and compiler_metadata_identity(os.stat(path,follow_symlinks=False)) == identity,
                    "compiled_profile_linux_changed")
        for path,(raw,identity,stream) in output_originals.items():
            require(compiler_metadata_identity(os.fstat(stream.fileno())) == identity
                    and compiler_metadata_identity(os.stat(path,follow_symlinks=False)) == identity,
                    "compiled_profile_linux_changed")
            stream.seek(0)
            require(stream.read(len(raw)+1) == raw, "compiled_profile_linux_changed")
        require(audit_compiler_publications(namespace,request["source_binding"]) == publications,
                "compiled_profile_linux_changed")
    return {"schema":"chio.original-linux-compiler-custody-observation.v1","source_location":location,
        "source_binding":request["source_binding"],"original_namespace":str(namespace),"scope_reports":scope_reports,
        "coverage":"completed-original-scope-and-dispatch-record-joins","qualified":False,
        "compiled_closure_status":"not-established"}


def audit_linux_compiled_profile(root, linux, request, report, candidate, sources, base_commit, rows,
                                  images=None, producer=None, runtime=None, dimension_context=None):
    require(type(linux) is dict and set(linux) == {"schema","scopes","primary_probes"}
            and linux["schema"] == "chio.linux-compiled-profile-evidence.v1"
            and type(linux["scopes"]) is list and bool(linux["scopes"])
            and type(request) is dict and set(request) == {"schema","source_location","scopes"}
            and request["schema"] == "chio.linux-compiler-custody-request.v1"
            and type(report) is dict and set(report) == {"schema","source_location","source_binding",
                "original_namespace","scope_reports","coverage","qualified","compiled_closure_status"}
            and report["schema"] == "chio.original-linux-compiler-custody-observation.v1"
            and report["qualified"] is False and report["source_location"] == request["source_location"]
            and report["coverage"] == "completed-original-scope-and-dispatch-record-joins"
            and report["compiled_closure_status"] == "not-established", "compiled_profile_linux_required")
    require(type(images) is dict and producer is not None and runtime is not None, "compiled_profile_linux_required")
    repository = compilation_absolute_path(request["source_location"]["repository"] if dimension_context is not None
        else artifact_json(root,producer["provenance"]["start"])["repository"])
    namespace = compilation_absolute_path(report["original_namespace"])
    require(report["source_binding"] == runtime["source_binding"] and request["source_location"]["repository"] == str(repository)
            and request["source_location"]["host"].get("system") == "Linux"
            and request["source_location"]["host"].get("machine") == "x86_64", "compiled_profile_linux_location")
    require(len(linux["scopes"]) == len(request["scopes"]) == len(report["scope_reports"]) <= 512,
            "compiled_profile_linux_scope")
    publications = {"records":[{"invocation_id":row["invocation_id"],
        "record_sha256":hashlib.sha256(compilation_canonical(row)+b"\n").hexdigest()} for row in rows]}
    if dimension_context is None:
        producer_start = artifact_json(root,producer["provenance"]["start"])
        launch = audit_compiler_launch(root,producer["provenance"]["compiler_launch"],producer_start["command"],repository,
            gate_catalog()[producer["id"]],sources,runtime["source_binding"])
        source_origin = artifact_json(root,producer["provenance"]["source_origin"])
    else:
        configuration = artifact_json(root,portable_original_compiler_reference(producer["launch_configuration"],repository))
        require(configuration.get("candidate") == str(repository) and configuration.get("records") == producer["namespace"]
                and configuration.get("source_binding") == runtime["source_binding"]
                and configuration.get("environment") == dimension_context["environment"]
                and all(configuration.get("images",{}).get(name) == {key:producer["tools"][name][key] for key in ["path","sha256"]}
                        for name in ["cargo","rustc","python","recorder"]),"compiled_dimension_compiler_context")
        launch = {"configuration":configuration,"launch":{"command":dimension_context["inner_command"]}}
        source_origin = artifact_json(root,portable_original_compiler_reference(producer["source_origin"],repository))
    def retained(image):
        require(type(image) is dict and image.get("artifact") == "artifacts/"+image.get("sha256","")
                and (image.get("sha256"),image.get("size")) in images, "compiled_profile_linux_image")
        return artifact_json(root, images[(image["sha256"],image["size"])])
    def retained_output_raw(image):
        require((image["sha256"],image["size"]) in images, "compiled_profile_linux_image")
        reference = images[(image["sha256"],image["size"])]
        name = relative_path(reference["path"]).as_posix()
        require(not secret_source(name), "compiled_profile_linux_image")
        with regular_input(root/name) as stream:
            require(os.fstat(stream.fileno()).st_size == image["size"] <= 16*1024**2,
                    "compiled_profile_linux_image")
            return stream.read(16*1024**2+1)
    covered,verified_native_inputs = set(),{}
    for reference, original, observed in zip(linux["scopes"],request["scopes"],report["scope_reports"]):
        data = artifact_json(root,reference)
        require(data.get("scope",{}).get("schema") == "chio.linux-compilation-scope.v2"
                and data.get("declaration",{}).get("schema") == "chio.linux-compilation-scope-declaration.v2",
                "compiled_profile_current_scope")
        require(reference["sha256"] == observed["data_sha256"]
                and data["scope_path"] == observed["scope_path"] == original["scope"]["path"]
                and data["scope_sha256"] == observed["scope_sha256"] == original["scope"]["sha256"],
                "compiled_profile_linux_scope")
        joined = audit_compilation_scope_data(data,runtime["source_binding"],repository,namespace,publications,retained,
                                             retained_output_raw)
        require(joined["configuration"] == launch["configuration"] and data["command"] == launch["launch"]["command"],
                "compiled_profile_compiler_context")
        require(joined["scope_id"] == observed["scope_id"] and joined["unit_ids"] == observed["unit_ids"]
                and joined["verified_dispatches"] == observed["verified_dispatches"]
                and not covered.intersection(joined["unit_ids"]), "compiled_profile_linux_dispatch")
        covered.update(joined["unit_ids"])
        verified_native_inputs.setdefault(joined["scope_id"],set()).update(
            compiler_graph_image(image) for image in joined["readonly"].values()
            if image["role"] in {"toolchain","native-runtime"})
        require(data["runtime_inventory"] == runtime and data["source_origin"] == source_origin,
                "compiled_profile_linux_source")
        recorder = joined["configuration"]["images"]["recorder"]
        require(recorder["path"] == str(repository/"scripts/record-rust-compilation.py")
                and recorder["sha256"] == next((source.get("sha256") for source in sources
                    if source["path"] == "scripts/record-rust-compilation.py"),None), "compiled_profile_linux_source")
    require({row["invocation_id"] for row in rows} <= covered, "compiled_profile_linux_dispatch")
    audit_primary_compiler_probes(root,linux["primary_probes"],sources)
    return verified_native_inputs


PRIMARY_COMPILER_PROBES = ("allowed-read","outside-read","outside-write","evidence-read","evidence-write",
                         "network","forged-ipc","gnu-native","musl-static-pie")
PRIMARY_COMPILER_TOOLS = {
    "consumer/verify_public_compilation_probes.py":"c2c218095e11f6abbd862a08a2e9a0f493fd9704fec0079f2d8c5abc09c4707b",
    "consumer/scope-record-functions.py":"fba31e53940e6d37f0170e89fce687a58f7b4fb4a5adf40b8f8b2f06743f3e38",
    "inventory-collector.py":"6004b9a4aa2b2acbb7aaee8c5cbfb56e597b54c94e9e2c6716baf11b26601359",
    "run-public-compiler-campaign-current.py":"bf4b1085c5c5f246fff3130d66b8b26f2417c3b30376ac4ef2b93ca928b0374b",
}


CURRENT_PRIMARY_COMPILER_TOOLS = {
    'consumer/verify_public_compilation_probes.py':'21f92a7d36cf5a4709addda7e3394c8e4cd0a1f919c8895a7fd8e43b42acc60e',
    'consumer/scope-record-functions.py':'f92309385f1eba536d88cd9adbd4eb02943a02a1be84efc808e8d0e29b724471',
    'consumer/physical_publication_functions.py':'35274dde491ca572e22d5d44d787f52aaa8f1f13a9d9d40a714fa5cfe6799564',
    'consumer/probe-observation-functions.py':'8ac9b9822c09e629c81d458207cf8f1b0af8a3161bf81dd045dc9b098172403e',
    'inventory-collector.py':'1f35d0a4c6462d30fecc995e68b55e8a7ef4db10dac44ced9023974d4b3c279d',
    'run-public-compiler-campaign-current.py':'35735f7d03fa1030155b076cad5fe5e0d66ac653a2458708750aaf09a3a4d26a',
}

DIRECTORY_PRIMARY_COMPILER_TOOLS = {
    "consumer/verify_public_compilation_probes.py":"17fb2e3e1d18e7d4733b606095dd454c32d9530d7509d9f07954c4d9654cef9a",
    "consumer/scope-record-functions.py":"39f6e1477b63751a5730305d75035aa97ba3a8cf8c7f8fcb7c2cfa888afeb94b",
    "consumer/physical_publication_functions.py":"35274dde491ca572e22d5d44d787f52aaa8f1f13a9d9d40a714fa5cfe6799564",
    "consumer/probe-observation-functions.py":"8ac9b9822c09e629c81d458207cf8f1b0af8a3161bf81dd045dc9b098172403e",
    "inventory-collector.py":"0e58111416e15594d7009c77b6a0ae26c24c6e1510f6ccb06603a7901be7adde",
    "run-public-compiler-campaign-current.py":"35735f7d03fa1030155b076cad5fe5e0d66ac653a2458708750aaf09a3a4d26a",
}

DESCRIPTOR_CUSTODY_PRIMARY_COMPILER_TOOLS = {
    "consumer/verify_public_compilation_probes.py":"1733d055922b83c4228646b1e7bc4426d89e425f663c3ea5e0fb3279b88696da",
    "consumer/scope-record-functions.py":"39f6e1477b63751a5730305d75035aa97ba3a8cf8c7f8fcb7c2cfa888afeb94b",
    "consumer/physical_publication_functions.py":"35274dde491ca572e22d5d44d787f52aaa8f1f13a9d9d40a714fa5cfe6799564",
    "consumer/probe-observation-functions.py":"8ac9b9822c09e629c81d458207cf8f1b0af8a3161bf81dd045dc9b098172403e",
    "inventory-collector.py":"e5cfc57485dcc268d45fba83e588e66c40b6f1386020204106b2a0df9bb9610c",
    "run-public-compiler-campaign-current.py":"35735f7d03fa1030155b076cad5fe5e0d66ac653a2458708750aaf09a3a4d26a",
}

SCOPE_DEPENDENCY_PRIMARY_COMPILER_TOOLS = {
    **DESCRIPTOR_CUSTODY_PRIMARY_COMPILER_TOOLS,
    "consumer/verify_public_compilation_probes.py":"4cfecc814d8077069efac6e052005ba506d43c9ce2f47fce4f930dcbd1bf5122",
    "consumer/scope-record-functions.py":"cd1da76e46982c7f8846cb5e3f5526e4dbc2a54afb486a7361a485676f25b1e6",
}


PUBLIC_PAYLOAD_PRIMARY_AUTHORIZATION_SHA = "0658e3dfa7e8a5ecd58a11ccc4842e76275fd055bd57052e063bf238f6908f21"
PUBLIC_PAYLOAD_PRIMARY_COMPILER_TOOLS = {
    "consumer/verify_public_compilation_probes.py":"47deea10c5be41a12dd2b4528677623c01999f4a81ae8a50c80d1f25099c0f31",
    "consumer/scope-record-functions.py":"cd1da76e46982c7f8846cb5e3f5526e4dbc2a54afb486a7361a485676f25b1e6",
    "consumer/physical_publication_functions.py":"35274dde491ca572e22d5d44d787f52aaa8f1f13a9d9d40a714fa5cfe6799564",
    "consumer/probe-observation-functions.py":"6137af233bdbbedc245eb5105a8fe381a6981576a81b582c5c5ae8ce73aaa027",
    "inventory-collector.py":"0ec77f139132a449270a96baf188a49efad057d3d8be3214e118efcb7d34f410",
    "run-public-compiler-campaign-current.py":"e3b2cca44d42b0487ca604061a30486fdf35402d4bf6bf8f47802c90079fb5cf",
}


def audit_primary_compiler_tools(plan):
    candidate = compilation_absolute_path(plan["candidate"])
    if plan.get("schema") == "chio.public-linux-primary-plan.v2":
        authorization = plan.get("authorization_sha256",PRIMARY_AUTHORIZATION_SHA)
        require(type(authorization) is str and authorization in {PRIMARY_AUTHORIZATION_SHA,
            PUBLIC_PAYLOAD_PRIMARY_AUTHORIZATION_SHA},"compiled_profile_primary_authorization")
        if authorization == PUBLIC_PAYLOAD_PRIMARY_AUTHORIZATION_SHA:
            selected = [PUBLIC_PAYLOAD_PRIMARY_COMPILER_TOOLS]
        else:
            selected = [CURRENT_PRIMARY_COMPILER_TOOLS,DIRECTORY_PRIMARY_COMPILER_TOOLS,
                        DESCRIPTOR_CUSTODY_PRIMARY_COMPILER_TOOLS,SCOPE_DEPENDENCY_PRIMARY_COMPILER_TOOLS]
    else:selected = [PRIMARY_COMPILER_TOOLS]
    expected = [{str(candidate/"target/metadata"/name):digest for name,digest in roster.items()} for roster in selected]
    tools = plan.get("tools")
    require(type(tools) is list and len(tools) == len(expected[0])
            and all(type(tool) is dict and set(tool) == {"path","sha256"}
                    and type(tool["path"]) is str and type(tool["sha256"]) is str
                    and re.fullmatch(r"[a-f0-9]{64}",tool["sha256"]) for tool in tools),
            "compiled_profile_primary_tool")
    declared = {tool["path"]:tool["sha256"] for tool in tools}
    require(len(declared) == len(tools) and any(declared == roster for roster in expected), "compiled_profile_primary_tool")
    return declared


def checked_primary_compiler_contract(plan, summary, authorization_raw):
    """Pair exact approved payload bytes with their reviewed producer tools."""
    authorization = checked_public_authorization(authorization_raw)
    authorization_sha = hashlib.sha256(authorization_raw).hexdigest()
    require(type(plan) is dict and type(summary) is dict
            and plan.get("schema") == "chio.public-linux-primary-plan.v2"
            and summary.get("schema") == "chio.public-linux-primary-result.v2"
            and plan.get("authorization_sha256") == summary.get("authorization_sha256") == authorization_sha,
            "compiled_profile_primary_authorization")
    return authorization,audit_primary_compiler_tools(plan),authorization_sha


def audit_legacy_primary_compiler_probes(root, reference, sources):
    """Require the actual finite native campaign, including its failures."""
    evidence = artifact_json(root,reference)
    require(type(evidence) is dict and set(evidence) == {"schema","plan","summary","dispatch_start",
            "execution","controller","cases"} and evidence["schema"] == "chio.linux-compiler-primary-probes.v1",
            "compiled_profile_primary_record")
    plan, summary, dispatch = (artifact_json(root,evidence[key]) for key in ["plan","summary","dispatch_start"])
    tools = audit_primary_compiler_tools(plan)
    caps = {"total_seconds":900,"ordinary_seconds":120,"compiler_seconds":180,"retry":False}
    require(plan.get("caps") == summary.get("caps") == dispatch.get("caps") == caps
            and summary.get("status") == "passed-public-microprobes"
            and summary.get("qualified") is False and summary.get("compiled_closure_status") == "not-established"
            and type(summary.get("elapsed_from_first_dispatch_seconds")) in {int,float}
            and math.isfinite(summary["elapsed_from_first_dispatch_seconds"])
            and 0 < summary["elapsed_from_first_dispatch_seconds"] <= 900,
            "compiled_profile_primary_execution")
    candidate = compilation_absolute_path(plan["candidate"])
    recorder_sha = next((source.get("sha256") for source in sources
                         if source["path"] == "scripts/record-rust-compilation.py"),None)
    micro_sources = [{"path":"scripts/record-rust-compilation.py","sha256":recorder_sha}]
    micro_binding = binding(micro_sources,None)
    require(recorder_sha is not None and summary.get("candidate") == dispatch.get("candidate") == str(candidate)
            and plan.get("source_binding") == summary.get("source_binding") == dispatch.get("source_binding") == micro_binding
            and dispatch.get("schema") == "chio.public-probe-dispatch-start.v1"
            and dispatch.get("plan_sha256") == evidence["plan"]["sha256"], "compiled_profile_primary_source")
    cases = evidence["cases"]
    configs = plan.get("configs")
    require(type(cases) is list and type(configs) is list
            and [case.get("name") for case in cases] == [config.get("name") for config in configs] == list(PRIMARY_COMPILER_PROBES)
            and type(summary.get("results")) is list and len(summary["results"]) == len(cases),
            "compiled_profile_primary_denominator")
    controller = evidence["controller"]
    require(type(controller) is dict and set(controller) == {"path","sha256","size","original_path"},
            "compiled_profile_primary_controller")
    checked_compiled_blob(root,{key:controller[key] for key in ["path","sha256","size"]})
    original_controller = compilation_absolute_path(controller["original_path"])
    require(tools.get(str(original_controller)) == controller["sha256"], "compiled_profile_primary_controller")
    original_plan = compilation_absolute_path(evidence["plan"].get("original_path",""))
    require(original_plan.is_relative_to(candidate/"target/metadata"), "compiled_profile_primary_controller")
    execution = evidence["execution"]
    expected = {"command":["python3","-I","-B",str(original_controller.relative_to(candidate)),
        str(original_plan.relative_to(candidate)),evidence["plan"]["sha256"]],"cwd":".","environment":{}}
    # The provenance decoder normalizes contained absolute command paths.
    audit_execution_provenance(root,execution,micro_sources,None,expected)
    start = artifact_json(root,execution["provenance"]["start"])
    require(start["repository"] == str(candidate), "compiled_profile_primary_controller")
    for key in ["before","after"]:
        pins = artifact_json(root,execution["provenance"][key]).get("explicit_file_pins",[])
        require(any(pin.get("purpose") == "compiler-primary-controller" and pin.get("path") == str(original_controller)
                    and pin.get("observed",{}).get("sha256") == controller["sha256"] for pin in pins)
                and any(pin.get("purpose") == "compiler-primary-plan" and pin.get("path")
                    == str(original_plan)
                    and pin.get("observed",{}).get("sha256") == evidence["plan"]["sha256"] for pin in pins),
                "compiled_profile_primary_controller")
        require(all(any(pin.get("purpose") == "compiler-primary-tool" and pin.get("path") == path
                        and pin.get("observed",{}).get("sha256") == digest for pin in pins)
                    for path,digest in tools.items()), "compiled_profile_primary_tool")
    logged = [json.loads(line,object_pairs_hook=closed_pairs) for line in checked_log(root,execution["log"]).splitlines()
              if line.startswith("{")]
    for case, config, result in zip(cases,configs,summary["results"]):
        fields = {"name","result","runtime_before","runtime_after","command","original_audit_stdout",
                  "original_audit_stderr","launcher_stdout","launcher_stderr"}
        require(type(case) is dict and set(case) == fields, "compiled_profile_primary_case")
        observed = artifact_json(root,case["result"])
        require(observed == result and observed in logged and observed.get("name") == case["name"]
                and observed.get("command") == config.get("command")
                and type(observed.get("actual_exit")) is int and observed["actual_exit"] == 0
                and observed.get("status") == "passed-command-and-original-namespace-audit"
                and "observation_error" not in observed and "timeout_seconds" not in observed,
                "compiled_profile_primary_case")
        cap = 180 if case["name"] in {"gnu-native","musl-static-pie"} else 120
        require(type(observed.get("command_timeout_seconds")) in {int,float}
                and 0 < observed["command_timeout_seconds"] <= cap
                and type(observed.get("elapsed_seconds")) in {int,float}
                and 0 < observed["elapsed_seconds"] <= observed["command_timeout_seconds"]
                and type(observed.get("pid")) is int and observed["pid"] > 0
                and observed.get("process_group") == observed["pid"], "compiled_profile_primary_case")
        runtime = artifact_json(root,case["runtime_before"])
        require(runtime == artifact_json(root,case["runtime_after"]) == {"source_inventory_version":INVENTORY_VERSION,
                "base_commit":None,"sources":micro_sources,"source_binding":micro_binding}, "compiled_profile_primary_source")
        for key in ["runtime_before","runtime_after"]:
            require(observed[key]["actual_exit"] == 0 and observed[key]["sha256"] == case[key]["sha256"],
                    "compiled_profile_primary_source")
        command = artifact_json(root,case["command"])
        require(command == observed["command"][observed["command"].index("--")+1:], "compiled_profile_primary_case")
        audit = observed.get("original_namespace_audit")
        require(type(audit) is dict and set(audit) == {"command","actual_exit","stdout_sha256","stderr_sha256","scope"}
                and type(audit["actual_exit"]) is int and audit["actual_exit"] == 0
                and audit["stdout_sha256"] == case["original_audit_stdout"]["sha256"]
                and audit["stderr_sha256"] == case["original_audit_stderr"]["sha256"], "compiled_profile_primary_custody")
        case_root = candidate/"target/metadata/primary-observations"/case["name"]
        scope_path = compilation_absolute_path(audit["scope"])
        require(scope_path.name == "scope.json" and scope_path.parent.parent == candidate/"target/evidence"/case["name"]
                and re.fullmatch(r"[a-f0-9]{32}",scope_path.parent.name)
                and observed["runtime_before"]["path"] == str(case_root/"runtime-before.json")
                and observed["runtime_after"]["path"] == str(case_root/"runtime-after.json")
                and audit["command"] == ["/usr/bin/python3.12","-I","-B",
                    str(candidate/"target/metadata/consumer/verify_public_compilation_probes.py"),"--auditor",
                    str(candidate/"target/metadata/inventory-collector.py"),"--scope",str(scope_path),
                    "--runtime-before",str(case_root/"runtime-before.json"),"--runtime-after",
                    str(case_root/"runtime-after.json"),"--command",str(case_root/"command.json")],
                "compiled_profile_primary_custody")
        original = artifact_json(root,case["original_audit_stdout"])
        require(original.get("schema") == "chio.original-public-compilation-probe-verification.v1"
                and original.get("qualified") is False and original.get("source_binding") == micro_binding
                and original.get("scope_path") == audit["scope"]
                and original.get("coverage") == "original-namespace-public-microprobe-record-joins-only",
                "compiled_profile_primary_custody")
        output = checked_log(root,case["launcher_stdout"])
        checked_log(root,case["launcher_stderr"])
        checked_log(root,case["original_audit_stderr"])
        samples = [json.loads(line,object_pairs_hook=closed_pairs) for line in output.splitlines() if line.startswith("{")]
        samples = [sample for sample in samples if sample.get("schema") == "chio.public-linux-compilation-probe.v1"]
        require(len(samples) == 1 and samples[0].get("mode") == case["name"], "compiled_profile_primary_observation")
        value = samples[0].get("result",{})
        name = case["name"]
        if name == "allowed-read":
            require(value == {"public_bytes":20}, "compiled_profile_primary_observation")
        elif name in {"outside-read","outside-write","evidence-read","evidence-write"}:
            require(value.get("expected_denial") is True and type(value.get("observed_errno")) is int
                    and value["observed_errno"] in {errno.EACCES,errno.EPERM}, "compiled_profile_primary_observation")
        elif name == "network":
            require(set(value) == {"1","2"} and all(item.get("expected_denial") is True
                and type(item.get("observed_errno")) is int and item["observed_errno"] in {errno.EACCES,errno.EPERM}
                for item in value.values()), "compiled_profile_primary_observation")
        elif name == "forged-ipc":
            require(value == {"observed_refusal_exit":86}, "compiled_profile_primary_observation")
        elif name == "gnu-native":
            require(value.get("program_exit") == 0 and value.get("public_stdout") == "14"
                    and type(value.get("commands")) is list and len(value["commands"]) == 2
                    and original.get("verified_dispatches",0) >= 2
                    and value.get("compiler_child_ipc",{}).get("observation")
                        == "proc-macro-checked-original-pipe-identities-not-inherited", "compiled_profile_primary_observation")
        else:
            require(value.get("program_exit") == 0 and value.get("target") == "x86_64-unknown-linux-musl"
                    and value.get("elf_machine") == 62 and value.get("elf_type") == 3
                    and value.get("interpreter_present") is False and original.get("verified_dispatches",0) >= 1,
                    "compiled_profile_primary_observation")
    return {"case_count":len(cases),"coverage":"actual-primary-public-native-probe-executions"}


def audit_current_compiled_publication(root,publication,runtime,producer):
    """Historical physical records cannot supply current required-sync proof."""
    require(type(publication) is dict and publication.get("schema") == "chio.compiler-publication-verification.v2"
            and publication.get("source_binding") == runtime["source_binding"]
            and type(publication.get("verified_records")) is int and publication["verified_records"] > 0
            and type(publication.get("incomplete_records")) is int and publication["incomplete_records"] == 0,
            "compiled_profile_current_publication")
    return current_required_sync_observations(publication,checked_log(root,producer["log"]).encode("utf-8"))


def load_compiled_dimension_support(root, reference, sources):
    """Execute only the maintained, literal-pinned standard-library helper."""
    expected = next((row.get("sha256") for row in sources
                     if row.get("path") == "scripts/compiled-dimension-profiles.py"),None)
    require(type(reference) is dict and set(reference) == {"path","sha256","size"}
            and type(COMPILED_DIMENSION_TOOL_SHA) is str
            and re.fullmatch(r"[a-f0-9]{64}",COMPILED_DIMENSION_TOOL_SHA)
            and reference["sha256"] == expected == COMPILED_DIMENSION_TOOL_SHA
            and type(reference["size"]) is int and 0 < reference["size"] <= 1024*1024,
            "compiled_dimension_tool")
    path = root/relative_path(reference["path"])
    with regular_input(path) as stream:
        raw = stream.read(1024*1024+1)
        require(len(raw) == reference["size"] and hashlib.sha256(raw).hexdigest() == expected,
                "compiled_dimension_tool")
        module = types.ModuleType("literal_pinned_compiled_dimension_support")
        module.__file__ = str(path)
        exec(compile(raw,str(path),"exec"),module.__dict__)
    return module


def portable_original_compiler_reference(reference, repository):
    """Map an original input image to the same path in the retained package."""
    require(type(reference) is dict and set(reference) == {"path","sha256","size"},"compiled_dimension_reference")
    path,digest,size = compiler_graph_image(reference)
    path,repository = Path(path),Path(repository)
    require(path.is_relative_to(repository) and path != repository,"compiled_dimension_reference")
    return {"path":str(path.relative_to(repository)),"sha256":digest,"size":size}


def audit_dimension_compiled_profile(root, profile, candidate, sources, base_commit, image_custody, dimension_records):
    """Version two joins an owned action to observed and actually used images."""
    fields = {"schema","source_binding","mode","subjects","producer","runtime_inventory","custody_request",
        "custody_report","custody_execution","custody_tool","rows","inputs","roots","images","linux",
        "dimension_binding","subject_export","source_projections","producer_tool"}
    require(type(profile) is dict and set(profile) == fields and profile["schema"] == "chio.compiled-profile-evidence.v2"
            and profile["source_binding"] == candidate and type(dimension_records) is dict,
            "compiled_dimension_profile")
    hold_compiled_profile_references(root,profile,image_custody)
    support = load_compiled_dimension_support(root,profile["producer_tool"],sources)
    owner = profile["dimension_binding"]
    require(type(owner) is dict and type(owner.get("dimension")) is str
            and owner["dimension"] in dimension_records,"compiled_dimension_binding")
    reference = dimension_records[owner["dimension"]]
    dimension,label = support.checked_dimension_binding(owner,reference)
    artifact_json(root,reference)
    producer = artifact_json(root,profile["producer"])
    require(type(producer) is dict and producer.get("dimension") == dimension and producer.get("label") == label,
            "compiled_dimension_producer")
    runtime = artifact_json(root,profile["runtime_inventory"])
    require(type(runtime) is dict and set(runtime) == {"source_inventory_version","base_commit","sources","source_binding"}
            and runtime["source_inventory_version"] == INVENTORY_VERSION and runtime["sources"] == sources
            and runtime["source_binding"] == binding(sources,runtime["base_commit"]),"compiled_profile_source")
    request = artifact_json(root,profile["custody_request"])
    require(type(request) is dict and set(request) == {"schema","namespace","repository","runtime_inventory",
        "source_binding","roots","additional_inputs","selected_invocation_ids","mode","linux","producer",
        "subject_observation","source_projections"}
        and request["schema"] == "chio.compiler-profile-custody-request.v2","compiled_profile_custody_request")
    repository = Path(compilation_absolute_path(request["repository"]))
    options_ref = portable_original_compiler_reference(producer["options"],repository)
    options = artifact_json(root,options_ref)
    context = support.checked_producer_record(producer,runtime,repository,options,
        checked_log(root,producer["toolchain_probe"]["stdout"]))
    require(profile["mode"] == request["mode"] == context["mode"]
            and request["namespace"] == producer["namespace"] and request["source_binding"] == runtime["source_binding"]
            and profile["runtime_inventory"] == producer["runtime_inventory_before"]
            and artifact_json(root,producer["runtime_inventory_before"]) == runtime
            and artifact_json(root,producer["runtime_inventory_after"]) == runtime,"compiled_dimension_source")
    if producer["source_origin"] is not None:
        origin = artifact_json(root,portable_original_compiler_reference(producer["source_origin"],repository))
        receipt = audit_source_origin(root,origin,sources,base_commit,candidate)
        require(receipt["candidate"] == str(repository) and runtime["base_commit"] is None,"compiled_dimension_source")
    else:require(runtime["base_commit"] == base_commit,"compiled_dimension_source")
    for name,path in {"helper":"scripts/compiled-dimension-profiles.py","inspector":"scripts/verify-recovery-qualification.py",
                      "recorder":"scripts/record-rust-compilation.py"}.items():
        tool = producer["tools"][name]
        expected = next((row.get("sha256") for row in sources if row["path"] == path),None)
        require(tool["path"] == str(repository/path) and tool["sha256"] == expected,"compiled_dimension_tool")
    require(request["producer"] == {**profile["producer"],"path":str(repository/relative_path(profile["producer"]["path"]))},
            "compiled_dimension_producer")
    report = artifact_json(root,profile["custody_report"])
    report_fields = {"schema","request_sha256","request_path","namespace","repository","source_binding",
        "runtime_inventory_binding","mode","profile","linux","host","qualified","producer_sha256",
        "subject_observation","source_projections"}
    require(type(report) is dict and set(report) == report_fields
            and report["schema"] == "chio.compiler-profile-custody-observation.v2" and report["qualified"] is False
            and report["request_sha256"] == profile["custody_request"]["sha256"]
            and report["request_path"] == str(repository/relative_path(profile["custody_request"]["path"]))
            and report["producer_sha256"] == profile["producer"]["sha256"]
            and report["namespace"] == request["namespace"] and report["repository"] == str(repository)
            and report["source_binding"] == report["runtime_inventory_binding"] == runtime["source_binding"]
            and report["mode"] == profile["mode"] and report["subject_observation"] == request["subject_observation"]
            and report["source_projections"] == request["source_projections"] == profile["source_projections"],
            "compiled_dimension_custody")
    execution = artifact_json(root,profile["custody_execution"])
    require(type(execution) is dict and set(execution) == {"schema","command","cwd","actual_exit","stdout","stderr",
        "runtime_inventory_before","runtime_inventory_after","tool","request","qualified"}
        and execution["schema"] == "chio.compiled-dimension-inspector-execution.v2"
        and type(execution["actual_exit"]) is int and execution["actual_exit"] == 0 and execution["qualified"] is False
        and execution["cwd"] == str(repository) and execution["tool"] == producer["tools"]["inspector"]
        and execution["request"] == profile["custody_request"]
        and execution["command"] == [producer["tools"]["python"]["path"],"-I","-B",
            producer["tools"]["inspector"]["path"],"--compiler-profile-request",report["request_path"]]
        and artifact_json(root,execution["runtime_inventory_before"]) == runtime
        and artifact_json(root,execution["runtime_inventory_after"]) == runtime,"compiled_dimension_custody_execution")
    output = checked_log(root,execution["stdout"]);checked_log(root,execution["stderr"])
    prefix = "COMPILER_PROFILE_CUSTODY "
    observations = [json.loads(line[len(prefix):],object_pairs_hook=closed_pairs)
                    for line in output.splitlines() if line.startswith(prefix)]
    require(observations == [report],"compiled_dimension_custody_execution")
    tool = profile["custody_tool"]
    require(tool["sha256"] == producer["tools"]["inspector"]["sha256"] == sha(Path(__file__)),"compiled_profile_inspector")
    rows = artifact_json(root,profile["rows"])
    subject = support.checked_subject_observation(request["subject_observation"],rows)
    require(request["subject_observation"]["dimension"] == dimension and request["subject_observation"]["label"] == label
            and profile["subjects"] == request["subject_observation"]["produced_subjects"],"compiled_dimension_subjects")
    exported = support.export_dimension_bindings(owner,reference,rows,profile["subjects"],
        request["subject_observation"]["executed_subjects"],request["subject_observation"]["copy_custody"])
    require(profile["subject_export"] == exported,"compiled_dimension_subjects")
    observed = report["profile"]
    require(observed.get("schema") == "chio.original-compiler-profile-verification.v1"
            and observed.get("coverage") == "original-publication-and-current-declared-source-unit-graph"
            and observed.get("source_binding") == runtime["source_binding"]
            and observed.get("runtime_inventory_binding") == runtime["source_binding"]
            and observed.get("repository") == str(repository),"compiled_dimension_custody")
    publication = observed["publication"]
    require(type(publication) is dict and type(publication.get("records")) is list,"compiled_profile_rows")
    published = {row["invocation_id"]:row for row in publication["records"]}
    identifiers = [row["invocation_id"] for row in rows]
    require(len(published) == len(publication["records"]) and identifiers == request["selected_invocation_ids"]
            == observed["selected_invocation_ids"] and len(set(identifiers)) == len(identifiers)
            and set(identifiers) == set(published),"compiled_profile_rows")
    by_image = {}
    require(type(profile["images"]) is list and 0 < len(profile["images"]) <= 200000,"compiled_profile_images")
    for image in profile["images"]:
        checked_compiled_blob(root,image);image_custody(image)
        key = image["sha256"],image["size"]
        require(key not in by_image,"compiled_profile_images");by_image[key] = image
    for row in rows:
        require(row.get("source_binding") == runtime["source_binding"] and hashlib.sha256(compilation_canonical(row)+b"\n").hexdigest()
                == published[row["invocation_id"]]["record_sha256"],"compiled_profile_rows")
        for image in [*row["inputs"],*row["outputs"],row["compiler"]]:
            require((image.get("sha256"),image.get("size")) in by_image,"compiled_profile_images")
        require(row["compiler"]["sha256"] == producer["tools"]["rustc"]["sha256"],"compiled_dimension_toolchain")
    inputs,roots = profile["inputs"],profile["roots"]
    require(type(inputs) is list and len(inputs) <= 200000 and type(roots) is list and bool(roots)
            and roots == request["roots"] and request["additional_inputs"] == [image for image in inputs if image["role"] != "candidate"],
            "compiled_profile_inputs")
    if dimension == "formal":
        projection_inputs = support.checked_source_projections(profile["source_projections"],sources,repository,producer["contract"]["cwd"])
        require(all(image in inputs for image in projection_inputs),"compiled_dimension_projection")
    else:require(profile["source_projections"] == [],"compiled_dimension_projection")
    current = {str(repository/source["path"]):source["sha256"] for source in sources if "sha256" in source}
    for image in inputs:
        name,digest,size = compiler_graph_image(image)
        require((digest,size) in by_image,"compiled_profile_images")
        if image["role"] == "candidate":require(current.get(name) == digest,"compiled_profile_source")
        elif image["role"] == "campaign-produced":
            require(Path(name).is_relative_to(repository/"target"),"compiled_profile_inputs")
        else:require(image["role"] in {"vendor","toolchain","native-runtime"},"compiled_profile_inputs")
    if profile["mode"] == "host-trusted-fresh":
        require(profile["linux"] is None and request["linux"] is None and report["linux"] is None
                and report["host"].get("system") != "Linux","compiled_profile_mode")
        native = None
    else:
        # Native version two uses its own finite command producer. The gate
        # catalogue cannot supply a surrogate dimension action.
        native = audit_linux_compiled_profile(root,profile["linux"],request["linux"],report["linux"],candidate,
            sources,base_commit,rows,by_image,producer,runtime,dimension_context=context)
    graph = audit_compiler_unit_graph(rows,inputs,roots,compiler_immutable_externs(rows,inputs,native))
    require(graph == observed["unit_graph"],"compiled_profile_graph")
    require(all(compiler_graph_image(image) in {compiler_graph_image(root) for root in roots}
                for images in profile["subjects"].values() for image in images),"compiled_profile_roots")
    audit_current_compiled_publication(root,publication,runtime,producer)
    return {"subjects":request["subject_observation"]["executed_subjects"],"roots":{compiler_graph_image(image) for image in roots},
        "graph":graph,"mode":profile["mode"],"dimension":dimension,"repository":str(repository),
        "coverage":"owning-dimension-action-and-original-produced-to-executed-image-custody"}


def audit_compiled_profile(root, profile, candidate, sources, base_commit, image_custody=None, dimension_records=None):
    """Recompute exported graph and joins to actual original custody execution.

    Physical namespace checks occur in the pinned inspector's retained actual
    execution. This archive decoder does not assign physical authority to
    copied marker/record inode numbers and does not accept qualification flags.
    """
    if image_custody is None:
        with compiled_image_custody(root) as hold:
            return audit_compiled_profile(root,profile,candidate,sources,base_commit,hold,dimension_records)
    if type(profile) is dict and profile.get("schema") == "chio.compiled-profile-evidence.v2":
        return audit_dimension_compiled_profile(root,profile,candidate,sources,base_commit,image_custody,dimension_records)
    fields = {"schema", "source_binding", "mode", "subjects", "producer", "runtime_inventory",
              "custody_request", "custody_report", "custody_execution", "custody_tool", "rows",
              "inputs", "roots", "images", "linux"}
    require(type(profile) is dict and set(profile) == fields
            and profile["schema"] == "chio.compiled-profile-evidence.v1"
            and profile["source_binding"] == candidate
            and profile["mode"] in {"host-trusted-fresh", "linux-enforced"}, "compiled_profile_record")
    hold_compiled_profile_references(root,profile,image_custody)
    producer = profile["producer"]
    require(type(producer) is dict and producer.get("id") in gate_catalog()
            and producer.get("command", [None])[0] == "cargo", "compiled_profile_producer")
    subjects = profile["subjects"]
    require(type(subjects) is dict and bool(subjects), "compiled_profile_subjects")
    for name in subjects:
        require(type(name) is str, "compiled_profile_subjects")
        if name.startswith("gate/"):
            require(name == "gate/"+producer["id"], "compiled_profile_producer_subject")
        elif name.startswith("performance/"):
            require(name in {"performance/native","performance/pure"}
                    and producer["id"] == name.removeprefix("performance/")+"-performance",
                    "compiled_profile_producer_subject")
        else:
            # This version records one supported Cargo producer. Dimension
            # runners do not yet supply that producer contract, so a gate's
            # compilation cannot manufacture their independent image custody.
            require(False,"compiled_profile_producer_subject")
    audit_gate(root, producer, candidate)
    audit_execution_provenance(root, producer, sources, base_commit)
    producer_start = artifact_json(root, producer["provenance"]["start"])
    repository = compilation_absolute_path(producer_start["repository"])
    runtime = artifact_json(root, profile["runtime_inventory"])
    discovered_base = None if "source_origin" in producer["provenance"] else base_commit
    require(type(runtime) is dict and set(runtime) == {"source_inventory_version", "base_commit", "sources", "source_binding"}
            and runtime["source_inventory_version"] == INVENTORY_VERSION
            and runtime["base_commit"] == discovered_base and runtime["sources"] == sources
            and runtime["source_binding"] == binding(sources, discovered_base), "compiled_profile_source")
    request = artifact_json(root, profile["custody_request"])
    report = artifact_json(root, profile["custody_report"])
    request_fields = {"schema", "namespace", "repository", "runtime_inventory", "source_binding", "roots",
                      "additional_inputs", "selected_invocation_ids", "mode", "linux"}
    require(type(request) is dict and set(request) == request_fields
            and request["schema"] == "chio.compiler-profile-custody-request.v1"
            and request["repository"] == str(repository) and request["mode"] == profile["mode"]
            and request["source_binding"] == runtime["source_binding"], "compiled_profile_custody_request")
    namespace = compilation_absolute_path(request["namespace"])
    require(namespace.is_relative_to(repository/"target"), "compiled_profile_custody_request")
    recorder_path = str(repository/"scripts/record-rust-compilation.py")
    recorder_sha = next((source.get("sha256") for source in sources
                        if source["path"] == "scripts/record-rust-compilation.py"),None)
    if profile["mode"] == "host-trusted-fresh":
        environment = producer_start.get("environment",{})
        expected_environment = {"RUSTC_WRAPPER":recorder_path,"CHIO_COMPILATION_RECORDS":str(namespace),
            "CHIO_COMPILATION_SOURCE_ROOT":str(repository),"CHIO_COMPILATION_SOURCE_BINDING":runtime["source_binding"]}
        require(recorder_sha is not None and type(environment) is dict
                and all(environment.get(key) == value for key,value in expected_environment.items())
                and environment.get("RUSTC_WORKSPACE_WRAPPER") is None, "compiled_profile_compiler_context")
    else:
        launch = producer["provenance"].get("compiler_launch")
        require(type(launch) is dict, "compiled_profile_compiler_context")
        verified_launch = audit_compiler_launch(root,launch,producer_start["command"],repository,
            gate_catalog()[producer["id"]],sources,runtime["source_binding"])
        require(verified_launch["configuration"]["records"] == str(namespace), "compiled_profile_compiler_context")
    require(type(report) is dict and set(report) == {"schema", "request_sha256", "request_path", "namespace",
            "repository", "source_binding", "runtime_inventory_binding", "mode", "profile", "linux", "host", "qualified"}
            and report["schema"] == "chio.compiler-profile-custody-observation.v1"
            and report["qualified"] is False and report["namespace"] == str(namespace)
            and report["repository"] == str(repository) and report["source_binding"] == request["source_binding"]
            and report["runtime_inventory_binding"] == runtime["source_binding"]
            and report["mode"] == profile["mode"]
            and report["request_sha256"] == profile["custody_request"]["sha256"], "compiled_profile_custody")
    require(type(report["host"]) is dict and set(report["host"]) == {"system","machine","node"}
            and all(type(value) is str and 0 < len(value) <= 255 and "\x00" not in value
                    for value in report["host"].values()), "compiled_profile_custody")
    require(type(request["runtime_inventory"]) is dict and set(request["runtime_inventory"]) == {"path","sha256"}
            and request["runtime_inventory"]["sha256"] == profile["runtime_inventory"]["sha256"],
            "compiled_profile_source")
    compilation_absolute_path(request["runtime_inventory"]["path"])
    tool = profile["custody_tool"]
    require(type(tool) is dict and tool.get("sha256") == next((source.get("sha256") for source in sources
            if source["path"] == "scripts/verify-recovery-qualification.py"), None), "compiled_profile_inspector")
    require(sha(root/relative_path(tool["path"])) == tool["sha256"] == sha(Path(__file__)), "compiled_profile_inspector")
    execution = profile["custody_execution"]
    expected = {"command":["python3", "-I", "-B", "scripts/verify-recovery-qualification.py",
                           "--compiler-profile-request", report["request_path"]],
                "cwd":".", "environment":{}}
    audit_execution_provenance(root, execution, sources, base_commit, expected=expected)
    log = checked_log(root, execution["log"])
    observations = [json.loads(line[len("COMPILER_PROFILE_CUSTODY "):], object_pairs_hook=closed_pairs)
                    for line in log.splitlines() if line.startswith("COMPILER_PROFILE_CUSTODY ")]
    require(observations == [report], "compiled_profile_custody_execution")
    start = artifact_json(root, execution["provenance"]["start"])
    require(start["repository"] == str(repository), "compiled_profile_custody_execution")
    for key in ["before", "after"]:
        snapshot = artifact_json(root, execution["provenance"][key])
        pins = snapshot.get("explicit_file_pins", [])
        require(any(pin.get("purpose") == "compiler-profile-request" and pin.get("path") == report["request_path"]
                    and pin.get("observed", {}).get("sha256") == report["request_sha256"] for pin in pins)
                and any(pin.get("purpose") == "compiler-profile-inspector" and pin.get("path") == str(repository/"scripts/verify-recovery-qualification.py")
                    and pin.get("observed", {}).get("sha256") == tool["sha256"] for pin in pins),
                "compiled_profile_custody_execution")
    rows = artifact_json(root, profile["rows"])
    require(type(rows) is list and 0 < len(rows) <= 100000, "compiled_profile_rows")
    observed = report["profile"]
    require(observed.get("schema") == "chio.original-compiler-profile-verification.v1"
            and observed.get("coverage") == "original-publication-and-current-declared-source-unit-graph"
            and observed.get("source_binding") == runtime["source_binding"]
            and observed.get("runtime_inventory_binding") == runtime["source_binding"]
            and observed.get("repository") == str(repository), "compiled_profile_custody")
    publication = observed["publication"]
    publications = publication["records"]
    by_id = {row["invocation_id"]:row for row in publications}
    require(len(by_id) == len(publications), "compiled_profile_rows")
    identifiers = [row.get("invocation_id") for row in rows]
    require(identifiers == request["selected_invocation_ids"] == observed["selected_invocation_ids"]
            and len(set(identifiers)) == len(identifiers) and set(identifiers) <= set(by_id), "compiled_profile_rows")
    images = profile["images"]
    require(type(images) is list and 0 < len(images) <= 200000, "compiled_profile_images")
    by_image = {}
    for image in images:
        checked_compiled_blob(root, image)
        image_custody(image)
        key = image["sha256"], image["size"]
        require(key not in by_image, "compiled_profile_images")
        by_image[key] = image
    for row in rows:
        identifier = row["invocation_id"]
        body = compilation_canonical(row)+b"\n"
        require(row.get("source_binding") == runtime["source_binding"]
                and hashlib.sha256(body).hexdigest() == by_id[identifier]["record_sha256"], "compiled_profile_rows")
        for image in [*row.get("inputs", []), *row.get("outputs", []), *([row["compiler"]] if row.get("compiler") else [])]:
            require((image.get("sha256"), image.get("size")) in by_image, "compiled_profile_images")
    inputs = profile["inputs"]
    require(type(inputs) is list and len(inputs) <= 200000, "compiled_profile_inputs")
    current = {str(repository/source["path"]):source["sha256"] for source in sources if "sha256" in source}
    for image in inputs:
        name, digest, size = compiler_graph_image(image)
        require((digest,size) in by_image, "compiled_profile_images")
        if image.get("role") == "candidate":
            require(current.get(name) == digest, "compiled_profile_source")
        else:
            require(image.get("role") in {"vendor","toolchain","native-runtime","campaign-produced"}, "compiled_profile_inputs")
            require(name not in current and (Path(name).is_relative_to(repository/"target")
                    if image["role"] == "campaign-produced" else not Path(name).is_relative_to(repository)), "compiled_profile_inputs")
    roots = profile["roots"]
    require(type(roots) is list and bool(roots) and roots == request["roots"], "compiled_profile_roots")
    if profile["mode"] == "host-trusted-fresh":
        require(profile["linux"] is None and request["linux"] is None and report["linux"] is None,
                "compiled_profile_mode")
        require(report["host"].get("system") != "Linux", "compiled_profile_mode")
        verified_native_inputs = None
        def retained_host_image(image):
            exported = by_image[(image["sha256"], image["size"])]
            raw = read_bytes(root/relative_path(exported["path"]))
            require(len(raw) == image["size"] <= 16*1024**2 and hashlib.sha256(raw).hexdigest() == image["sha256"], "compiled_host_metadata")
            return raw
        def portable_host_tooling(image):
            require((image["sha256"], image["size"]) in by_image, "compiled_host_tool_image")
        audit_ordinary_host_metadata(rows, repository, namespace, runtime["source_binding"], retained_host_image, portable_host_tooling)
    else:
        verified_native_inputs = audit_linux_compiled_profile(root, profile["linux"], request["linux"], report["linux"],
                                     candidate, sources, base_commit, rows, by_image, producer, runtime)
    immutable = compiler_immutable_externs(rows,inputs,verified_native_inputs)
    graph = audit_compiler_unit_graph(rows, inputs, roots, immutable)
    require(graph == observed["unit_graph"], "compiled_profile_graph")
    require(request["additional_inputs"] == [image for image in inputs if image["role"] != "candidate"],
            "compiled_profile_inputs")
    root_images = {compiler_graph_image(image) for image in roots}
    for name, claimed in subjects.items():
        require(type(name) is str and type(claimed) is list and bool(claimed)
                and all(compiler_graph_image(image) in root_images for image in claimed), "compiled_profile_roots")
    audit_current_compiled_publication(root,publication,runtime,producer)
    return {"subjects":subjects, "roots":root_images, "graph":graph, "mode":profile["mode"],
            "coverage":"current-source-unit-graph-and-retained-original-custody-execution"}


def audit_compiled_profiles(root, record, candidate, sources, base_commit, image_custody=None):
    if image_custody is None:
        with compiled_image_custody(root) as hold:
            return audit_compiled_profiles(root,record,candidate,sources,base_commit,hold)
    references = record.get("compiled_profiles")
    require(type(references) is list and 0 < len(references) <= 512, "compiled_profile_required")
    expected = compiled_subjects(root, record)
    claimed = {}
    reports = []
    for reference in references:
        hold_compiled_profile_references(root,reference,image_custody)
        report = audit_compiled_profile(root, artifact_json(root,reference), candidate, sources, base_commit,image_custody,
                                        record.get("dimension_records",{}))
        for name, images in report["subjects"].items():
            require(name in expected and name not in claimed, "compiled_profile_subjects")
            required = expected[name]
            require(type(required) is list, "compiled_profile_subjects")
            subject_images = {compiler_graph_image(image) for image in images}
            for image in required:
                require(type(image) is dict and type(image.get("size")) is int
                        and any(root[1:] == (image.get("sha256"),image["size"])
                                for root in subject_images), "compiled_profile_roots")
                if "dimension" in report:
                    original = image.get("original_path")
                    if original is None and "original_relative_path" in image:
                        original = str(Path(report["repository"])/relative_path(image["original_relative_path"]))
                    require(type(original) is str and any(observed[0] == original
                            and observed[1:] == (image["sha256"],image["size"]) for observed in subject_images),
                            "compiled_dimension_executed_subject")
            claimed[name] = images
        reports.append(report)
    require(bool(expected) and set(claimed) == set(expected), "compiled_profile_subjects")
    return {"profile_count":len(reports), "subject_ids":sorted(claimed), "verified_root_count":sum(len(row["roots"]) for row in reports)}


def inspect_compiler_profile_request(request_path):
    """Observe the actual original namespace before portable evidence export.

    This read-only observation is deliberately unqualified. It provides the
    archive decoder's source/producer/physical-custody witness, not a substitute
    for actual product, platform, provider, performance or formal execution.
    """
    request_path = compilation_absolute_path(str(request_path))
    with regular_input(request_path) as stream, ExitStack() as originals:
        metadata = compiler_metadata_identity(os.fstat(stream.fileno()))
        raw = stream.read(16*1024**2+1)
        require(0 < len(raw) <= 16*1024**2, "compiled_profile_custody_request")
        request = json.loads(raw, object_pairs_hook=closed_pairs)
        fields = {"schema", "namespace", "repository", "runtime_inventory", "source_binding", "roots",
                  "additional_inputs", "selected_invocation_ids", "mode", "linux"}
        dimension_request = type(request) is dict and request.get("schema") == "chio.compiler-profile-custody-request.v2"
        if dimension_request:fields |= {"producer","subject_observation","source_projections"}
        require(type(request) is dict and set(request) == fields
                and request["schema"] in {"chio.compiler-profile-custody-request.v1","chio.compiler-profile-custody-request.v2"}
                and request["mode"] in {"host-trusted-fresh", "linux-enforced"}, "compiled_profile_custody_request")
        repository = compilation_absolute_path(request["repository"])
        namespace = compilation_absolute_path(request["namespace"])
        require(namespace.is_relative_to(repository/"target"), "compiled_profile_custody_request")
        host = {"system":platform.system(), "machine":platform.machine(), "node":platform.node()}
        require(request["mode"] != "host-trusted-fresh" or host["system"] != "Linux", "compiled_profile_mode")
        require(request["mode"] != "linux-enforced" or host["system"] == "Linux"
                and host["machine"] == "x86_64", "compiled_profile_mode")
        inventory_reference = request["runtime_inventory"]
        require(type(inventory_reference) is dict and set(inventory_reference) == {"path", "sha256"}, "compiled_profile_source")
        inventory_path = compilation_absolute_path(inventory_reference["path"])
        inventory = read_json(inventory_path)
        require(sha(inventory_path) == inventory_reference["sha256"]
                and inventory.get("sources") == current_source_inventory(repository), "compiled_profile_source")
        actual = subprocess.run(["git", "-C", str(repository), "rev-parse", "--verify", "HEAD"],
            env={"PATH":"/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM":"1"}, capture_output=True, timeout=10)
        discovered = actual.stdout.decode().strip() if actual.returncode == 0 else None
        require(inventory.get("base_commit") == discovered
                and request["source_binding"] == inventory.get("source_binding"), "compiled_profile_source")
        extra = request["additional_inputs"]
        require(type(extra) is list and len(extra) <= 200000, "compiled_profile_inputs")
        retained_originals = []
        producer_sha = None
        if dimension_request:
            own_sources = inventory["sources"]
            helper_path = repository/"scripts/compiled-dimension-profiles.py"
            helper_sha = next((row.get("sha256") for row in own_sources
                               if row["path"] == "scripts/compiled-dimension-profiles.py"),None)
            require(helper_sha == COMPILED_DIMENSION_TOOL_SHA and re.fullmatch(r"[a-f0-9]{64}",helper_sha or ""),
                    "compiled_dimension_tool")
            helper_stream = originals.enter_context(regular_input(helper_path))
            helper_identity = compiler_metadata_identity(os.fstat(helper_stream.fileno()))
            helper_raw = helper_stream.read(1024*1024+1)
            require(0 < len(helper_raw) <= 1024*1024 and hashlib.sha256(helper_raw).hexdigest() == helper_sha,
                    "compiled_dimension_tool")
            support = types.ModuleType("original_literal_pinned_dimension_support")
            support.__file__ = str(helper_path)
            exec(compile(helper_raw,str(helper_path),"exec"),support.__dict__)
            retained_originals.append((helper_path,helper_identity,helper_stream))
            def original_image(reference):
                path,digest,size = compiler_graph_image(reference)
                require(not secret_source(path.lstrip("/")),"compiled_profile_input_policy")
                stream = originals.enter_context(regular_input(Path(path)))
                identity = compiler_metadata_identity(os.fstat(stream.fileno()))
                require(identity[3] == size <= 16*1024**2 and identity[-1] == 1,"compiled_dimension_input")
                body = stream.read(16*1024**2+1)
                require(len(body) == size and hashlib.sha256(body).hexdigest() == digest,"compiled_dimension_input")
                retained_originals.append((Path(path),identity,stream))
                return body
            producer_raw = original_image(request["producer"])
            producer_sha = hashlib.sha256(producer_raw).hexdigest()
            producer = json.loads(producer_raw,object_pairs_hook=closed_pairs,
                parse_constant=lambda _:require(False,"nonfinite_json_number"))
            options = json.loads(original_image(producer["options"]),object_pairs_hook=closed_pairs,
                parse_constant=lambda _:require(False,"nonfinite_json_number"))
            version_reference = producer["toolchain_probe"]["stdout"]
            version = original_image({**version_reference,"path":str(repository/relative_path(version_reference["path"]))})
            context = support.checked_producer_record(producer,inventory,repository,options,version.decode("ascii"))
            require(context["mode"] == request["mode"] and producer["namespace"] == str(namespace),"compiled_dimension_producer")
            for key in ["runtime_inventory_before","runtime_inventory_after"]:
                reference = producer[key]
                actual_inventory = json.loads(original_image({**reference,"path":str(repository/relative_path(reference["path"]))}),
                    object_pairs_hook=closed_pairs,parse_constant=lambda _:require(False,"nonfinite_json_number"))
                require(actual_inventory == inventory,"compiled_dimension_source")
            for key in ["helper","inspector","recorder","cargo","rustc","python"]:
                image = producer["tools"][key]
                name,digest,size = compiler_graph_image(image)
                require(not secret_source(name.lstrip("/")),"compiled_profile_input_policy")
                held = originals.enter_context(regular_input(Path(name)))
                before = compiler_metadata_identity(os.fstat(held.fileno()))
                require(before[3] == size and before[-1] == 1,"compiled_dimension_tool")
                tool_digest = hashlib.sha256()
                for block in iter(lambda:held.read(1024*1024),b""):tool_digest.update(block)
                require(tool_digest.hexdigest() == digest,"compiled_dimension_tool")
                retained_originals.append((Path(name),before,held))
            if producer["dimension"] == "formal":
                projection_inputs = support.checked_source_projections(request["source_projections"],inventory["sources"],
                    repository,producer["contract"]["cwd"])
                require(all(image in request["additional_inputs"] for image in projection_inputs),"compiled_dimension_projection")
                for receipt in request["source_projections"]:
                    for key in ["source","captured"]:
                        original_image(receipt[key])
                        require(compiler_metadata_identity(os.stat(receipt[key]["path"],follow_symlinks=False))
                                == tuple(receipt[key+"_identity"]),"compiled_dimension_projection")
            else:require(request["source_projections"] == [],"compiled_dimension_projection")
        for image in extra:
            name, digest, size = compiler_graph_image(image)
            require(not secret_source(name.lstrip("/")), "compiled_profile_input_policy")
            observed = originals.enter_context(regular_input(Path(name)))
            before = compiler_metadata_identity(os.fstat(observed.fileno()))
            require(before[3] == size, "compiled_profile_inputs")
            actual_digest = hashlib.sha256()
            for chunk in iter(lambda:observed.read(1024*1024), b""):
                actual_digest.update(chunk)
            require(actual_digest.hexdigest() == digest, "compiled_profile_inputs")
            retained_originals.append((Path(name),before,observed))
        if request["mode"] == "linux-enforced":
            verified_native_inputs = {}
            preliminary = {"publication":audit_compiler_publications(namespace,request["source_binding"]),
                           "selected_invocation_ids":request["selected_invocation_ids"]}
            linux = inspect_linux_compiled_profile(request["linux"],request,preliminary,verified_native_inputs)
        else:
            require(request["linux"] is None, "compiled_profile_mode")
            verified_native_inputs,linux = None,None
        profile = audit_compiler_profile_namespace(namespace, repository, inventory, request["source_binding"],
            request["roots"], extra, request["selected_invocation_ids"],verified_native_inputs)
        if dimension_request:
            require(set(request["selected_invocation_ids"]) == {row["invocation_id"] for row in profile["publication"]["records"]},
                    "compiled_dimension_rows")
            rows = [read_json(Path(namespace)/"records"/(identifier+".json")) for identifier in profile["selected_invocation_ids"]]
            support.checked_subject_observation(request["subject_observation"],rows)
            require(request["subject_observation"]["dimension"] == producer["dimension"]
                    and request["subject_observation"]["label"] == producer["label"],"compiled_dimension_subjects")
            for images in request["subject_observation"]["executed_subjects"].values():
                for image in images:
                    path,digest,size = compiler_graph_image(image)
                    require(Path(path).is_relative_to(repository/"target") and not Path(path).is_relative_to(namespace),
                            "compiled_dimension_subjects")
                    held = originals.enter_context(regular_input(Path(path)))
                    identity = compiler_metadata_identity(os.fstat(held.fileno()))
                    require(identity[3] == size and identity[-1] == 1 and identity[2] & 0o111,"compiled_dimension_subjects")
                    actual_digest = hashlib.sha256()
                    for block in iter(lambda:held.read(1024*1024),b""):actual_digest.update(block)
                    require(actual_digest.hexdigest() == digest,"compiled_dimension_subjects")
                    retained_originals.append((Path(path),identity,held))
            for receipt in request["subject_observation"]["copy_custody"]:
                for key in ["source","destination"]:
                    path = receipt[key]["path"]
                    require(compiler_metadata_identity(os.stat(path,follow_symlinks=False)) == tuple(receipt[key+"_identity"]),
                            "compiled_dimension_copy")
        for image in request["roots"]:
            name, digest, size = compiler_graph_image(image)
            require(not secret_source(name.lstrip("/")), "compiled_profile_input_policy")
            require(Path(name).is_relative_to(repository/"target")
                    and not Path(name).is_relative_to(namespace), "compiled_profile_roots")
            observed = originals.enter_context(regular_input(Path(name)))
            before = compiler_metadata_identity(os.fstat(observed.fileno()))
            require(before[3] == size, "compiled_profile_roots")
            actual_digest = hashlib.sha256()
            for chunk in iter(lambda:observed.read(1024*1024), b""):
                actual_digest.update(chunk)
            require(actual_digest.hexdigest() == digest, "compiled_profile_roots")
            retained_originals.append((Path(name),before,observed))
        require(current_source_inventory(repository) == inventory["sources"]
                and sha(inventory_path) == inventory_reference["sha256"], "compiled_profile_source")
        for path,identity,observed in retained_originals:
            require(compiler_metadata_identity(os.fstat(observed.fileno())) == identity
                    and compiler_metadata_identity(os.stat(path,follow_symlinks=False)) == identity,
                    "compiled_profile_inputs")
        require(compiler_metadata_identity(os.fstat(stream.fileno())) == metadata
                and compiler_metadata_identity(os.stat(request_path,follow_symlinks=False)) == metadata,
                "compiled_profile_custody_request")
    observation = {"schema":"chio.compiler-profile-custody-observation.v2" if dimension_request else "chio.compiler-profile-custody-observation.v1", "request_path":str(request_path),
        "request_sha256":hashlib.sha256(raw).hexdigest(), "namespace":str(namespace), "repository":str(repository),
        "source_binding":request["source_binding"], "runtime_inventory_binding":inventory["source_binding"],
        "mode":request["mode"], "profile":profile, "linux":linux, "host":host, "qualified":False}
    if dimension_request:
        observation.update(producer_sha256=producer_sha,subject_observation=request["subject_observation"],
                           source_projections=request["source_projections"])
    return observation


def audit_record(root, record, expected_seal=None, source_root=None):
    require(record.get("schema") == SCHEMA and record.get("source_inventory_version") == INVENTORY_VERSION,
            "record_version")
    require(re.fullmatch(r"[a-f0-9]{40}", record.get("base_commit", "")) is not None, "base_commit")
    sources = record["sources"]
    validate_source_rows(sources)
    candidate = binding(sources, record["base_commit"])
    require(candidate == record.get("source_binding"), "source_binding")
    if source_root is not None:
        current_commit = subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], cwd=source_root).decode().strip()
        require(current_commit == record["base_commit"] and current_source_inventory(source_root) == sources,
                "current_source_inventory")
    gates = record.get("gates", [])
    require(len({row["id"] for row in gates}) == len(gates), "gate_inventory")
    results = [audit_gate(root, row, candidate) for row in gates]
    for row in gates:
        audit_execution_provenance(root, row, sources, record["base_commit"])
    missing = sorted(set(gate_catalog()) - {row["id"] for row in gates})
    performance = record.get("performance")
    if performance is not None:
        audit_performance(root, performance, candidate, sources, record["base_commit"])
    declarations = record.get("cohort_declaration", [])
    attempts = record.get("cohort_attempts", [])
    audit_attempts(declarations, attempts, root, candidate)
    archive = record.get("source_archive")
    if archive is not None:
        audit_archive(root / relative_path(archive["path"]), sources)
        require(sha(root / relative_path(archive["path"])) == archive["sha256"], "archive_integrity")
    artifacts = record["artifacts"]
    require(len({item["path"] for item in artifacts}) == len(artifacts), "artifact_inventory")
    artifact_paths = {item["path"] for item in artifacts}
    auditor = record.get("auditor")
    require(isinstance(auditor, dict) and auditor.get("path") in artifact_paths
            and auditor.get("sha256") == next(item["sha256"] for item in artifacts if item["path"] == auditor["path"])
            == sha(root/relative_path(auditor["path"])) == sha(Path(__file__)), "auditor_binding")
    require(all(reference["path"] in artifact_paths for row in gates
                for reference in [row["log"], *row["provenance"].values()]), "artifact_inventory")
    require(all(reference["path"] in artifact_paths for reference in record.get("dimension_records", {}).values()),
            "artifact_inventory")
    for item in artifacts:
        require(sha(root / relative_path(item["path"])) == item["sha256"], "artifact_integrity")
    if expected_seal is not None:
        require(hashlib.sha256(canonical(record)).hexdigest() == expected_seal, "record_integrity")
    dimensions = audit_dimensions(root, record.get("dimension_records", {}), candidate, sources, record["base_commit"])
    ready = not missing and performance is not None and archive is not None \
        and attempts and attempts[-1]["qualified"] and all(dimensions.get(name) is True
            for name in ["linux", "formal", "live_provider", "hosted_ci", "complete_review"])
    compiled = None
    if ready or record.get("compiled_profiles") is not None:
        compiled = audit_compiled_profiles(root, record, candidate, sources, record["base_commit"])
    require(record.get("qualified") is bool(ready), "qualification_claim")
    if ready:
        require(expected_seal is not None, "out_of_band_seal_required")
    return {"schema":SCHEMA, "qualified":bool(ready), "source_binding":candidate,
            "gate_results":results, "missing_gate_ids":missing,
            "compiled_profiles":compiled,
            "dimensions":dimensions, "cohort_attempts":attempts,
            "current_tree_checked":source_root is not None,
            "scope":"Source-bound records only. Dimension evidence must be independently reviewed; no complete-system theorem."}


def audit_historical_package(root, expected_integrity=None, source_root=None):
    """Check frozen package bytes without loading any historical executable code."""
    integrity_path = root / "package-integrity.json"
    raw = read_bytes(integrity_path)
    if expected_integrity is not None:
        require(hashlib.sha256(raw).hexdigest() == expected_integrity, "historical_integrity_anchor")
    integrity = json.loads(raw, object_pairs_hook=closed_pairs)
    artifacts = integrity["artifacts"]
    names = [str(relative_path(row["path"])) for row in artifacts]
    require(names == sorted(names) and len(set(names)) == len(names)
            and len({portable_path_key(name) for name in names}) == len(names), "historical_artifact_inventory")
    observed = sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()
                      and path.name != "package-integrity.json" and "__pycache__" not in path.parts)
    require(names == observed, "historical_artifact_inventory")
    for artifact in artifacts:
        require(sha(root / relative_path(artifact["path"])) == artifact["sha256"], "historical_artifact_hash")
    verification = read_json(root / "verification.json")
    sources = verification.get("joined_sources", verification.get("sources", []))
    require(isinstance(sources, list) and sources, "historical_source_inventory")
    drift = []
    if source_root is not None:
        source_root = source_root.resolve(strict=True)
        for row in sources:
            path = source_root / relative_path(row["path"])
            try:
                observed = sha(path)
            except OSError:
                observed = None
            if observed != row["sha256"]:
                drift.append({"path":row["path"], "sealed_sha256":row["sha256"], "current_sha256":observed})
    return {"schema":"chio.historical-qualification-integrity.v1", "artifacts_verified":len(artifacts),
            "sealed_source_count":len(sources), "integrity_sha256":hashlib.sha256(raw).hexdigest(),
            "current_source_drift":drift if source_root is not None else None,
            "current_qualified":False,
            "scope":"Historical byte integrity only; mutable-tree auditors are not executed and no current acceptance is inferred."}


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--record", type=Path)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--expected-seal-sha256")
    parser.add_argument("--source-root", type=Path, help="optional current Git checkout; omitted for portable archived evidence")
    modes.add_argument("--historical-package", type=Path)
    modes.add_argument("--catalog", action="store_true")
    modes.add_argument("--inventory", action="store_true")
    modes.add_argument("--compiler-publications", type=Path,
                       help="original recorder filesystem namespace; copied evidence is not authoritative")
    modes.add_argument("--compiler-profile-request", type=Path,
                       help="inspect original current-source unit graph and physical publication before export")
    parser.add_argument("--source-binding", help="independently verified runtime source binding for compiler publications")
    args = parser.parse_args()
    if args.compiler_profile_request is not None:
        if args.source_binding is not None:
            parser.error("profile request carries its independently checked runtime source binding")
        print("COMPILER_PROFILE_CUSTODY "+json.dumps(inspect_compiler_profile_request(args.compiler_profile_request),
              sort_keys=True,separators=(",",":")),flush=True)
        return
    if args.compiler_publications is not None:
        if args.source_binding is None:
            parser.error("--source-binding is required with --compiler-publications")
        print(json.dumps(audit_compiler_publications(args.compiler_publications,args.source_binding),
                         indent=2,sort_keys=True))
        return
    if args.source_binding is not None:
        parser.error("--source-binding requires --compiler-publications")
    if args.catalog:
        print(json.dumps(gate_catalog(), indent=2, sort_keys=True))
        return
    if args.inventory:
        root = (args.source_root or Path.cwd()).resolve(strict=True)
        observed = subprocess.run(["git","rev-parse","--verify","HEAD"],cwd=root,capture_output=True)
        require(observed.returncode in {0,128},"inventory_base_commit")
        base_commit = observed.stdout.decode().strip() if observed.returncode == 0 else None
        sources = current_source_inventory(root)
        print(json.dumps({"source_inventory_version":INVENTORY_VERSION, "base_commit":base_commit,
                          "sources":sources, "source_binding":binding(sources, base_commit)}, indent=2))
        return
    if args.historical_package is not None:
        print(json.dumps(audit_historical_package(args.historical_package.resolve(strict=True),
                         args.expected_seal_sha256, args.source_root), indent=2, sort_keys=True))
        return
    record = read_json(args.record)
    report = audit_record(args.root.resolve(strict=True), record, args.expected_seal_sha256,
                          args.source_root.resolve(strict=True) if args.source_root else None)
    print(json.dumps(report, indent=2, sort_keys=True))


compilation_json_same = same_compilation_json

"""Closed fixed-input and actual stream joins for public native microprobes."""
AUTHORIZATION_SHA = "90659258cf73681a01780b0e83018bd418b1cbf3207fa29c2e0454af0a5bac41"


def checked_public_authorization(raw):
    require(type(raw) is bytes and len(raw) <= 16*1024
            and hashlib.sha256(raw).hexdigest() in {AUTHORIZATION_SHA,PUBLIC_PAYLOAD_PRIMARY_AUTHORIZATION_SHA},
            "micro_primary_authorization")
    value = json.loads(raw, object_pairs_hook=closed_pairs,
                       parse_constant=lambda _:require(False,"micro_primary_authorization"))
    require(value["schema"] == "chio.public-linux-primary-authorization.v1", "micro_primary_authorization")
    return value


def checked_public_launcher_observation(value, authorization, configuration, command, read_blob):
    fields = {"schema","candidate","source_binding","name","command","actual_exit",
              "command_timeout_seconds","elapsed_seconds","pid","process_group","launcher_capture"}
    require(type(value) is dict and set(value) == fields
            and value["schema"] == "chio.public-linux-launcher-observation.v1"
            and value["candidate"] == configuration["candidate"]
            and value["source_binding"] == configuration["source_binding"]
            and type(value["actual_exit"]) is int and value["actual_exit"] == 0
            and type(value["pid"]) is int and value["pid"] > 0
            and type(value["process_group"]) is int and value["process_group"] == value["pid"],
            "micro_primary_observation")
    candidate = compilation_absolute_path(value["candidate"])
    case = next((row for row in authorization["cases"] if row["name"] == value["name"]), None)
    require(case is not None,"micro_primary_observation")
    configuration_path = str(candidate / case["configuration_relative_path"])
    expected = [argument.format(candidate=str(candidate),configuration=configuration_path)
                for argument in case["command_template"]]
    require(value["command"] == expected and command == expected[expected.index("--")+1:],
            "micro_primary_command")
    times = [value["command_timeout_seconds"],value["elapsed_seconds"]]
    require(all(type(time) in {int,float} and math.isfinite(time) and time > 0 for time in times)
            and times[1] <= times[0] <= case["timeout_seconds"], "micro_primary_observation")
    captures = value["launcher_capture"]
    require(type(captures) is dict and set(captures) == {"stdout","stderr"}, "micro_primary_capture")
    result = {}
    for name in ["stdout","stderr"]:
        reference = captures[name]
        expected_path = candidate / "target/metadata/primary-observations" / value["name"] / ("launcher."+name+".log")
        require(type(reference) is dict and set(reference) == {"path","sha256","size"}
                and reference["path"] == str(expected_path)
                and type(reference["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}",reference["sha256"])
                and type(reference["size"]) is int and 0 <= reference["size"] <= 64*1024**2,
                "micro_primary_capture")
        raw = read_blob(expected_path)
        require(type(raw) is bytes and len(raw) == reference["size"]
                and hashlib.sha256(raw).hexdigest() == reference["sha256"], "micro_primary_capture")
        result[name] = raw
    return result


def checked_public_probe_observation(raw, name, dispatches):
    """Interpret the actual inner scope log, separately from outer sync evidence."""
    require(type(raw) is bytes and len(raw) <= 64*1024**2
            and type(dispatches) is int and dispatches >= 0,"micro_primary_probe")
    samples = []
    for line in raw.splitlines():
        if not line.startswith(b"{"):
            continue
        value = json.loads(line, object_pairs_hook=closed_pairs,
                           parse_constant=lambda _:require(False,"micro_primary_probe"))
        if type(value) is dict and value.get("schema") == "chio.public-linux-compilation-probe.v1":
            samples.append(value)
    require(len(samples) == 1 and set(samples[0]) == {"schema","mode","result"}
            and samples[0]["mode"] == name and type(samples[0]["result"]) is dict,"micro_primary_probe")
    value = samples[0]["result"]
    if name == "allowed-read":
        require(compilation_json_same(value,{"public_bytes":20}),"micro_primary_probe")
    elif name in {"outside-read","outside-write","evidence-read","evidence-write"}:
        require(set(value) == {"expected_denial","observed_errno"} and value["expected_denial"] is True
                and type(value["observed_errno"]) is int and value["observed_errno"] in {1,13},"micro_primary_probe")
    elif name == "network":
        require(set(value) == {"1","2"} and all(type(item) is dict and set(item) == {"expected_denial","observed_errno"}
                and item["expected_denial"] is True and type(item["observed_errno"]) is int
                and item["observed_errno"] in {1,13} for item in value.values()),"micro_primary_probe")
    elif name == "forged-ipc":
        require(compilation_json_same(value,{"observed_refusal_exit":86}),"micro_primary_probe")
    elif name == "gnu-native":
        require(set(value) == {"commands","program_exit","public_stdout","compiler_child_ipc"}
                and type(value["program_exit"]) is int and value["program_exit"] == 0
                and value["public_stdout"] == "14" and type(value["commands"]) is list and len(value["commands"]) == 2
                and type(value["compiler_child_ipc"]) is dict and value["compiler_child_ipc"].get("observation")
                    == "proc-macro-checked-original-pipe-identities-not-inherited"
                and dispatches >= 2,"micro_primary_probe")
    else:
        require(name == "musl-static-pie" and set(value) == {"command","program_exit","elf_machine","elf_type","interpreter_present","target"}
                and all(type(value[key]) is int for key in ["program_exit","elf_machine","elf_type"])
                and value["program_exit"] == 0 and value["elf_machine"] == 62 and value["elf_type"] == 3
                and value["interpreter_present"] is False and value["target"] == "x86_64-unknown-linux-musl"
                and dispatches >= 1,"micro_primary_probe")
    return samples[0]

"""Decode the fixed current campaign; original execution remains a separate join."""
PRIMARY_AUTHORIZATION_SHA = "90659258cf73681a01780b0e83018bd418b1cbf3207fa29c2e0454af0a5bac41"


def current_primary_bytes(root, reference, original=None):
    require(type(reference) is dict and {"path","sha256"} <= set(reference)
            <= {"path","sha256","size","original_path"}
            and type(reference["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}",reference["sha256"]),
            "compiled_profile_primary_capture")
    if original is not None:
        require(reference.get("original_path") == original["path"]
                and reference["sha256"] == original["sha256"] and type(original["size"]) is int
                and 0 <= original["size"] <= 64*1024**2, "compiled_profile_primary_capture")
    path = root/relative_path(reference["path"])
    with regular_input(path) as stream:
        body = stream.read(64*1024**2+1)
    require(len(body) <= 64*1024**2 and hashlib.sha256(body).hexdigest() == reference["sha256"],
            "compiled_profile_primary_capture")
    if original is not None:
        require(len(body) == original["size"], "compiled_profile_primary_capture")
    if "size" in reference:
        require(type(reference["size"]) is int and reference["size"] == len(body), "compiled_profile_primary_capture")
    return body


def current_primary_sync(stderr, source_binding, count):
    """Recompute the outside outcomes already checked in the original namespace.

    This archive projection supplies no new physical authority. Its digest must
    equal the actual pinned consumer report from the original execution.
    """
    prefixes = {b"compilation_recorder.retention_batch_outcome=":"batch",
                b"compilation_recorder.unit_publication_outcome=":"unit"}
    batches,units = {},{}
    def physical_reference(reference,path):
        require(type(reference) is dict and set(reference) == {"path","sha256","size","identity"}
                and reference["path"] == path and type(reference["sha256"]) is str
                and re.fullmatch(r"[a-f0-9]{64}",reference["sha256"])
                and type(reference["size"]) is int and 0 < reference["size"] <= 16*1024**2
                and type(reference["identity"]) is dict and set(reference["identity"]) == {"device","inode"}
                and all(type(part) is int and part >= 0 for part in reference["identity"].values()),
                "compiled_profile_primary_sync")
    for line in stderr.splitlines():
        prefix = next((value for value in prefixes if line.startswith(value)),None)
        if prefix is None:
            continue
        value = json.loads(line[len(prefix):],object_pairs_hook=closed_pairs,
                           parse_constant=lambda _:require(False,"compiled_profile_primary_sync"))
        require(type(value) is dict,"compiled_profile_primary_sync")
        if prefixes[prefix] == "batch":
            identifier = value.get("batch_id")
            require(type(identifier) is str and re.fullmatch(r"[a-f0-9]{32}",identifier)
                    and identifier not in batches,"compiled_profile_primary_sync")
            require(set(value) == {"schema","source_binding","batch_id","start","complete","physical_status","durability","declaration_emitted"},
                    "compiled_profile_primary_sync")
            physical_reference(value["start"],"batches/"+identifier+".start.json")
            physical_reference(value["complete"],"batches/"+identifier+".complete.json")
            batches[identifier] = {key:value.get(key) for key in ["batch_id","source_binding","start","complete"]}
        else:
            identifier = value.get("invocation_id")
            require(type(identifier) is str and re.fullmatch(r"[a-f0-9]{32}",identifier)
                    and identifier not in units,"compiled_profile_primary_sync")
            require(set(value) == {"schema","source_binding","invocation_id","kind","record_status","compiler_exit",
                        "record","completion","unit_images_sha256","physical_status","durability"}
                    and value["schema"] == "chio.rust-unit-publication-outcome.v1"
                    and type(value["kind"]) is str and value["kind"] in {"compilation","probe"}
                    and type(value["record_status"]) is str
                    and value["record_status"] in {"success","refused","compiler_failed","instrumentation_failed"}
                    and (value["compiler_exit"] is None or type(value["compiler_exit"]) is int)
                    and type(value["unit_images_sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}",value["unit_images_sha256"]),
                    "compiled_profile_primary_sync")
            if value["record_status"] == "success":
                require(type(value["compiler_exit"]) is int and value["compiler_exit"] == 0,
                        "compiled_profile_primary_sync")
            if value["record_status"] == "compiler_failed":
                require(type(value["compiler_exit"]) is int and value["compiler_exit"] != 0,
                        "compiled_profile_primary_sync")
            physical_reference(value["record"],"records/"+identifier+".json")
            physical_reference(value["completion"],"completions/"+identifier+".json")
            units[identifier] = {key:item for key,item in value.items() if key != "durability"}
    require(len(units) == count and len(batches) <= 100000,"compiled_profile_primary_sync")
    publication = {"source_binding":source_binding,"retention_batches":list(batches.values()),
                   "unit_publications":units}
    return current_required_sync_observations(publication,stderr)


def audit_current_primary_compiler_probes(root, reference, sources):
    """Recompute current records and require the independently recorded execution."""
    evidence = artifact_json(root,reference)
    fields = {"schema","plan","summary","dispatch_start","execution","controller","authorization","cases"}
    require(type(evidence) is dict and set(evidence) == fields
            and evidence["schema"] == "chio.linux-compiler-primary-probes.v2", "compiled_profile_primary_record")
    plan,summary,dispatch = (artifact_json(root,evidence[key]) for key in ["plan","summary","dispatch_start"])
    require(all(type(value) is dict for value in [plan,summary,dispatch]),"compiled_profile_primary_record")
    authorization_raw = current_primary_bytes(root,evidence["authorization"])
    authorization,tools,authorization_sha = checked_primary_compiler_contract(plan,summary,authorization_raw)
    caps = {"total_seconds":900,"ordinary_seconds":120,"compiler_seconds":180,"retry":False}
    elapsed = summary.get("elapsed_from_first_dispatch_seconds")
    require(same_compilation_json(plan.get("caps"),caps) and same_compilation_json(summary.get("caps"),caps)
            and same_compilation_json(dispatch.get("caps"),caps)
            and summary.get("status") == "passed-public-microprobes" and summary.get("qualified") is False
            and summary.get("compiled_closure_status") == "not-established"
            and type(elapsed) in {int,float} and 0 < elapsed <= 900,
            "compiled_profile_primary_execution")
    candidate = compilation_absolute_path(plan["candidate"])
    require(candidate.parent == Path("/var/tmp"),"compiled_profile_primary_source")
    recorder_sha = next((row.get("sha256") for row in sources if row["path"] == "scripts/record-rust-compilation.py"),None)
    micro_sources = [{"path":"scripts/record-rust-compilation.py","sha256":recorder_sha}]
    micro_binding = binding(micro_sources,None)
    require(recorder_sha is not None and summary.get("candidate") == dispatch.get("candidate") == str(candidate)
            and plan.get("source_binding") == summary.get("source_binding") == dispatch.get("source_binding") == micro_binding
            and dispatch.get("schema") == "chio.public-probe-dispatch-start.v1"
            and dispatch.get("plan_sha256") == evidence["plan"]["sha256"], "compiled_profile_primary_source")
    uid = plan.get("expected_uid")
    require(type(uid) is int and uid >= 0 and type(summary.get("expected_uid")) is int
            and summary["expected_uid"] == uid, "compiled_profile_primary_source")
    location = plan.get("source_location")
    try:
        materialization_location(location)
    except ValueError:
        require(False,"compiled_profile_primary_source")
    require(location["repository"] == str(candidate)
            and location["host"]["system"] == "Linux" and location["host"]["machine"] == "x86_64"
            and location["root"]["uid"] == uid and location["root"]["mode"] == 0o700,
            "compiled_profile_primary_source")
    cases,configs,results = evidence["cases"],plan.get("configs"),summary.get("results")
    require(type(cases) is list and type(configs) is list and type(results) is list
            and all(type(row) is dict for rows in [cases,configs,results] for row in rows)
            and [case.get("name") for case in cases] == [config.get("name") for config in configs]
                == [row["name"] for row in authorization["cases"]] == list(PRIMARY_COMPILER_PROBES)
            and len(results) == len(cases), "compiled_profile_primary_denominator")
    for config,approved in zip(configs,authorization["cases"]):
        require(config.get("guest_path") == str(candidate/approved["configuration_relative_path"])
                and type(config.get("sha256")) is str and re.fullmatch(r"[a-f0-9]{64}",config["sha256"]),
                "compiled_profile_primary_source")
    times = [row.get("elapsed_seconds") for row in results]
    # Range checks precede float conversion or summation. At most nine positive
    # durations bounded by the fixed campaign limit cannot overflow fsum.
    require(all(type(value) in {int,float} and 0 < value <= elapsed for value in times),
            "compiled_profile_primary_execution")
    total = math.fsum(times)
    require(total <= elapsed <= 900,"compiled_profile_primary_execution")
    prior = []
    for observed,approved in zip(results,authorization["cases"]):
        timeout = observed.get("command_timeout_seconds")
        require(type(timeout) in {int,float} and timeout > 0
                and timeout <= min(approved["timeout_seconds"],900-math.fsum(prior)),
                "compiled_profile_primary_execution")
        prior.append(observed["elapsed_seconds"])
    controller = evidence["controller"]
    require(type(controller) is dict and set(controller) == {"path","sha256","size","original_path"},
            "compiled_profile_primary_controller")
    checked_compiled_blob(root,{key:controller[key] for key in ["path","sha256","size"]})
    original_controller = compilation_absolute_path(controller["original_path"])
    require(tools.get(str(original_controller)) == controller["sha256"], "compiled_profile_primary_controller")
    original_plan = compilation_absolute_path(evidence["plan"].get("original_path",""))
    original_authorization = candidate/"target/metadata/public-probe-authorization.json"
    require(original_plan.is_relative_to(candidate/"target/metadata")
            and evidence["authorization"].get("original_path") == str(original_authorization),
            "compiled_profile_primary_controller")
    execution = evidence["execution"]
    expected = {"command":["/usr/bin/python3.12","-I","-B",str(original_controller.relative_to(candidate)),
        str(original_plan.relative_to(candidate)),evidence["plan"]["sha256"],str(original_authorization.relative_to(candidate))],
        "cwd":".","environment":{}}
    audit_execution_provenance(root,execution,micro_sources,None,expected)
    start = artifact_json(root,execution["provenance"]["start"])
    require(start["repository"] == str(candidate), "compiled_profile_primary_controller")
    expected_pins = [("compiler-primary-controller",str(original_controller),controller["sha256"]),
        ("compiler-primary-plan",str(original_plan),evidence["plan"]["sha256"]),
        ("compiler-primary-authorization",str(original_authorization),authorization_sha),
        *(("compiler-primary-tool",path,digest) for path,digest in tools.items())]
    for name in ["before","after"]:
        pins = artifact_json(root,execution["provenance"][name]).get("explicit_file_pins",[])
        require(all(any(pin.get("purpose") == purpose and pin.get("path") == path
                        and pin.get("observed",{}).get("sha256") == sha for pin in pins)
                    for purpose,path,sha in expected_pins), "compiled_profile_primary_tool")
    logged = [json.loads(line,object_pairs_hook=closed_pairs) for line in checked_log(root,execution["log"]).splitlines()
              if line.startswith("{")]
    for case,config,result in zip(cases,configs,results):
        fields = {"name","result","runtime_before","runtime_after","command","original_audit_stdout",
                  "original_audit_stderr","launcher_stdout","launcher_stderr","launcher_observation","scope_stdout","scope_stderr"}
        require(type(case) is dict and set(case) == fields, "compiled_profile_primary_case")
        require(all(type(case[key]) is dict and set(case[key]) == {"path","sha256","size","original_path"}
                    for key in ["launcher_stdout","launcher_stderr","scope_stdout","scope_stderr","launcher_observation"]),
                "compiled_profile_primary_capture")
        observed = artifact_json(root,case["result"])
        require(same_compilation_json(observed,result) and any(same_compilation_json(observed,line) for line in logged)
                and observed.get("name") == case["name"] and same_compilation_json(observed.get("command"),config.get("command"))
                and type(observed.get("actual_exit")) is int and observed["actual_exit"] == 0
                and observed.get("status") == "passed-command-and-original-namespace-audit"
                and observed.get("qualified") is False and observed.get("compiled_closure_status") == "not-established"
                and "observation_error" not in observed and "timeout_seconds" not in observed
                and "cleanup_failure" not in observed, "compiled_profile_primary_case")
        runtime = artifact_json(root,case["runtime_before"])
        require(same_compilation_json(runtime,artifact_json(root,case["runtime_after"]))
                and same_compilation_json(runtime,{"source_inventory_version":INVENTORY_VERSION,"base_commit":None,
                    "sources":micro_sources,"source_binding":micro_binding}), "compiled_profile_primary_source")
        case_root = candidate/"target/metadata/primary-observations"/case["name"]
        for key,suffix in [("runtime_before","runtime-before.json"),("runtime_after","runtime-after.json")]:
            captured = observed.get(key)
            require(type(captured) is dict and set(captured) == {"command","actual_exit","path","sha256"}
                    and type(captured["actual_exit"]) is int and captured["actual_exit"] == 0
                    and captured["sha256"] == case[key]["sha256"]
                    and captured["path"] == str(case_root/suffix)
                    and captured["command"] == ["/usr/bin/python3.12","-I","-B",
                        str(candidate/"target/metadata/inventory-collector.py"),"--inventory","--source-root",str(candidate)],
                    "compiled_profile_primary_source")
        observation = artifact_json(root,case["launcher_observation"])
        ref = observed.get("launcher_observation")
        require(type(ref) is dict and set(ref) == {"path","sha256","size"}
                and ref["path"] == str(case_root/"launcher-observation.json")
                and ref["sha256"] == case["launcher_observation"]["sha256"]
                and same_compilation_json(observation,{key:observed[key] for key in
                    ["name","command","actual_exit","command_timeout_seconds","elapsed_seconds","pid","process_group","launcher_capture"]}
                    | {"schema":"chio.public-linux-launcher-observation.v1","candidate":str(candidate),"source_binding":micro_binding}),
                "compiled_profile_primary_observation")
        current_primary_bytes(root,case["launcher_observation"],ref)
        command = artifact_json(root,case["command"])
        streams = {}
        def read_stream(path):
            name = "stdout" if str(path).endswith("launcher.stdout.log") else "stderr"
            streams[name] = current_primary_bytes(root,case["launcher_"+name],observation["launcher_capture"][name])
            return streams[name]
        checked_public_launcher_observation(observation,authorization,
            {"candidate":str(candidate),"source_binding":micro_binding},command,read_stream)
        audit = observed.get("original_namespace_audit")
        require(type(audit) is dict and set(audit) == {"command","actual_exit","stdout_sha256","stderr_sha256","scope"}
                and type(audit["actual_exit"]) is int and audit["actual_exit"] == 0
                and audit["stdout_sha256"] == case["original_audit_stdout"]["sha256"]
                and audit["stderr_sha256"] == case["original_audit_stderr"]["sha256"], "compiled_profile_primary_custody")
        scope_path = compilation_absolute_path(audit["scope"])
        require(scope_path.name == "scope.json" and scope_path.parent.parent == candidate/"target/evidence"/case["name"]
                and re.fullmatch(r"[a-f0-9]{32}",scope_path.parent.name)
                and audit["command"] == ["/usr/bin/python3.12","-I","-B",str(candidate/"target/metadata/consumer/verify_public_compilation_probes.py"),
                    "--auditor",str(candidate/"target/metadata/inventory-collector.py"),"--scope",str(scope_path),
                    "--runtime-before",str(case_root/"runtime-before.json"),"--runtime-after",str(case_root/"runtime-after.json"),
                    "--command",str(case_root/"command.json"),"--launcher-observation",str(case_root/"launcher-observation.json"),
                    "--authorization",str(original_authorization)], "compiled_profile_primary_custody")
        original = artifact_json(root,case["original_audit_stdout"])
        report_fields = {"schema","source_binding","scope_id","original_namespace","scope_path",
            "verified_publications","verified_dispatches","verified_compilations","verified_inventory_images",
            "coverage","qualified","compiled_closure_status","primary_probe_result_coverage","authorization_sha256",
            "launcher_observation","launcher_capture","scope_stdout_capture","scope_stderr_capture","probe_observation",
            "required_sync_observation_sha256"}
        require(type(original) is dict and set(original) == report_fields
                and original.get("schema") == "chio.original-public-compilation-probe-verification.v2"
                and original.get("qualified") is False and original.get("compiled_closure_status") == "not-established"
                and original.get("source_binding") == micro_binding and original.get("scope_path") == str(scope_path)
                and original.get("original_namespace") == str(candidate/"target/records"/case["name"])
                and type(original["scope_id"]) is str and re.fullmatch(r"[a-f0-9]{64}",original["scope_id"])
                and original.get("authorization_sha256") == authorization_sha
                and original.get("coverage") == "original-namespace-public-microprobe-record-joins-only"
                and original["primary_probe_result_coverage"] == "separate actual whole controller execution required"
                and same_compilation_json(original.get("launcher_observation"),ref)
                and same_compilation_json(original.get("launcher_capture"),observed["launcher_capture"]),
                "compiled_profile_primary_custody")
        inner = {name:current_primary_bytes(root,case["scope_"+name],original["scope_"+name+"_capture"])
                 for name in ["stdout","stderr"]}
        for name in ["stdout","stderr"]:
            require(original["scope_"+name+"_capture"]["path"] == str(scope_path.with_name(name+".log")),
                    "compiled_profile_primary_capture")
        require(all(type(original[key]) is int and 0 <= original[key] <= 1000000 for key in
                    ["verified_publications","verified_dispatches","verified_compilations","verified_inventory_images"])
                and original["verified_compilations"] <= original["verified_dispatches"]
                    <= original["verified_publications"], "compiled_profile_primary_observation")
        compiled = original["verified_compilations"]
        require(case["name"] not in {"gnu-native","musl-static-pie"}
                or compiled >= (2 if case["name"] == "gnu-native" else 1), "compiled_profile_primary_observation")
        sample = checked_public_probe_observation(inner["stdout"],case["name"],original["verified_dispatches"])
        require(same_compilation_json(sample,original.get("probe_observation")), "compiled_profile_primary_observation")
        sync = current_primary_sync(streams["stderr"],micro_binding,original["verified_publications"])
        require(hashlib.sha256(compilation_canonical(sync)).hexdigest() == original["required_sync_observation_sha256"],
                "compiled_profile_primary_sync")
        successful = [value for value in sync["unit_outcomes"].values()
                      if value["record_status"] == "success" and type(value["compiler_exit"]) is int
                         and value["compiler_exit"] == 0]
        compiled_from_units = checked_public_compilation_count({
            "records":[{"invocation_id":identifier,"kind":value["kind"],"status":value["record_status"]}
                       for identifier,value in sync["unit_outcomes"].items()],
            "unit_publications":sync["unit_outcomes"]},case["name"])
        require(original["verified_dispatches"] == len(successful)
                and original["verified_compilations"] == compiled_from_units,
                "compiled_profile_primary_observation")
        checked_log(root,case["original_audit_stderr"])
    return {"case_count":len(cases),"coverage":"actual-primary-public-native-probe-executions"}

def audit_primary_compiler_probes(root, reference, sources):
    return audit_current_primary_compiler_probes(root,reference,sources)

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError) as error:
        category = str(error) if isinstance(error, ValueError) and str(error).startswith("qualification.") else "qualification.invalid_record"
        print(category, file=sys.stderr)
        raise SystemExit(1) from None
