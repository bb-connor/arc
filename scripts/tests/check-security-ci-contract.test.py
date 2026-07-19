#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_security_ci_contract", ROOT / "scripts/check-security-ci-contract.py"
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("unable to load security CI checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

ZERO_BOOTSTRAP_SHA = "0" * 40
NONZERO_BOOTSTRAP_SHA = "0123456789abcdef0123456789abcdef01234567"
MISMATCHED_BOOTSTRAP_SHA = "1111111111111111111111111111111111111111"
BOOTSTRAP_CALL_PATTERN = re.compile(
    r"(uses: bb-connor/arc/\.github/workflows/enterprise-hardening\.yml@)[0-9a-f]{40}"
)
BOOTSTRAP_SENTINEL_PATTERN = re.compile(
    r"(# CHIO_ENTERPRISE_HARDENING_BOOTSTRAP_SHA=)[0-9a-f]{40}"
)

WORKFLOWS = (
    "ci.yml",
    "enterprise-hardening.yml",
    "enterprise-evidence-controller.yml",
    "enterprise-linux-capture.yml",
    "enterprise-evidence-finalizer.yml",
    "security-contract-revocation.yml",
    "apalache-safety.yml",
    "threat-model-coverage.yml",
    "admin-override-audit.yml",
)
CONTRACT_DOCUMENT = Path("docs/security/committed-linux-evidence.md")
ACTIONLINT_CONFIG = Path(".github/actionlint.yaml")
SECURITY_EXECUTION_BOUNDARY_FILES = (
    Path("deploy/docker/Dockerfile.security-evidence-runner"),
    Path("deploy/docker/security-evidence-apk.lock"),
    Path("deploy/docker/security-evidence-seccomp.json"),
    Path("crates/security/chio-cage/scripts/check-linux-enforcement.sh"),
    Path("scripts/check-cage-all-target-inventory.py"),
    Path("scripts/check-cage-enforcement.sh"),
    Path("scripts/check-exact-cargo-test-inventory.py"),
    Path("scripts/check-keyring-transparency.sh"),
    Path("scripts/check-linux-enforcement-stack.py"),
    Path("scripts/check-secret-broker-boundary.sh"),
    Path("scripts/check-security-adversarial-evidence.py"),
    Path("scripts/run-security-execution-container.py"),
    Path("scripts/security-execution-command-client.py"),
    Path("scripts/security-execution-container-entrypoint.py"),
    Path("scripts/tests/run-security-execution-container.test.py"),
)


def set_bootstrap_sha(body: str, sha: str) -> str:
    body, call_count = BOOTSTRAP_CALL_PATTERN.subn(rf"\g<1>{sha}", body, count=1)
    body, sentinel_count = BOOTSTRAP_SENTINEL_PATTERN.subn(
        rf"\g<1>{sha}", body, count=1
    )
    if call_count != 1 or sentinel_count != 1:
        raise AssertionError("bootstrap SHA fixture could not be normalized")
    return body


def populate_fixture(fixture: Path) -> None:
    workflows = fixture / ".github/workflows"
    workflows.mkdir(parents=True)
    for name in WORKFLOWS:
        shutil.copy2(ROOT / ".github/workflows" / name, workflows / name)
    ci_path = workflows / "ci.yml"
    ci_path.write_text(
        set_bootstrap_sha(ci_path.read_text(encoding="utf-8"), NONZERO_BOOTSTRAP_SHA),
        encoding="utf-8",
    )
    shutil.copy2(ROOT / ACTIONLINT_CONFIG, fixture / ACTIONLINT_CONFIG)
    document = fixture / CONTRACT_DOCUMENT
    document.parent.mkdir(parents=True)
    shutil.copy2(ROOT / CONTRACT_DOCUMENT, document)
    for relative in (Path("Cargo.lock"), Path("rust-toolchain.toml")):
        shutil.copy2(ROOT / relative, fixture / relative)
    for relative in SECURITY_EXECUTION_BOUNDARY_FILES:
        destination = fixture / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)


def replace_once(old: str, new: str) -> Callable[[str], str]:
    return lambda body: body.replace(old, new, 1)


def named_step_bounds(body: str, name: str) -> tuple[int, int]:
    marker = f"      - name: {name}\n"
    start = body.index(marker)
    search_start = start + len(marker)
    next_step = body.find("\n      - ", search_start)
    job_match = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", body[search_start:])
    next_job = search_start + job_match.start() if job_match else -1
    candidates = [position for position in (next_step, next_job) if position >= 0]
    if not candidates:
        return start, len(body)
    return start, min(candidates)


def named_job_bounds(body: str, identifier: str) -> tuple[int, int]:
    marker = f"  {identifier}:\n"
    start = body.index(marker)
    search_start = start + len(marker)
    next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", body[search_start:])
    if next_job is None:
        return start, len(body)
    return start, search_start + next_job.start()


def replace_in_named_job(identifier: str, old: str, new: str) -> Callable[[str], str]:
    def mutate(body: str) -> str:
        start, end = named_job_bounds(body, identifier)
        block = body[start:end]
        replaced = block.replace(old, new, 1)
        if replaced == block:
            raise AssertionError(f"mutation did not change workflow job: {identifier}")
        return body[:start] + replaced + body[end:]

    return mutate


def replace_in_named_step(name: str, old: str, new: str) -> Callable[[str], str]:
    def mutate(body: str) -> str:
        start, end = named_step_bounds(body, name)
        block = body[start:end]
        replaced = block.replace(old, new, 1)
        if replaced == block:
            raise AssertionError(f"mutation did not change workflow step: {name}")
        return body[:start] + replaced + body[end:]

    return mutate


def swap_named_steps(first: str, second: str) -> Callable[[str], str]:
    def mutate(body: str) -> str:
        first_start, first_end = named_step_bounds(body, first)
        second_start, second_end = named_step_bounds(body, second)
        if second_start < first_start:
            first_start, second_start = second_start, first_start
            first_end, second_end = second_end, first_end
        first_block = body[first_start:first_end]
        second_block = body[second_start:second_end]
        middle = body[first_end:second_start]
        return (
            body[:first_start] + second_block + middle + first_block + body[second_end:]
        )

    return mutate


def assert_rejected(
    label: str,
    workflow_name: str,
    mutate: Callable[[str], str],
    expected_error: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-ci-contract-") as raw:
        fixture = Path(raw)
        populate_fixture(fixture)
        workflows = fixture / ".github/workflows"

        workflow_path = workflows / workflow_name
        original = workflow_path.read_text(encoding="utf-8")
        mutated = mutate(original)
        if mutated == original:
            raise AssertionError(f"{label}: mutation did not change its fixture")
        workflow_path.write_text(mutated, encoding="utf-8")

        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"security CI accepted mutation: {label}")


def assert_nonzero_bootstrap_accepted() -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-ci-contract-") as raw:
        fixture = Path(raw)
        populate_fixture(fixture)
        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            raise AssertionError(
                f"security CI rejected matching nonzero bootstrap SHA: {error}"
            ) from error


def assert_added_workflow_rejected(label: str, body: str, expected_error: str) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-ci-contract-") as raw:
        fixture = Path(raw)
        populate_fixture(fixture)
        workflows = fixture / ".github/workflows"
        (workflows / "unreviewed.yml").write_text(body, encoding="utf-8")

        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"security CI accepted added workflow: {label}")


def assert_removed_workflow_rejected(
    label: str, workflow_name: str, expected_error: str
) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-ci-contract-") as raw:
        fixture = Path(raw)
        populate_fixture(fixture)
        (fixture / ".github/workflows" / workflow_name).unlink()

        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"security CI accepted removed workflow: {label}")


def assert_document_rejected(
    label: str, mutate: Callable[[str], str], expected_error: str
) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-ci-contract-") as raw:
        fixture = Path(raw)
        populate_fixture(fixture)
        document = fixture / CONTRACT_DOCUMENT
        original = document.read_text(encoding="utf-8")
        mutated = mutate(original)
        if mutated == original:
            raise AssertionError(f"{label}: mutation did not change its fixture")
        document.write_text(mutated, encoding="utf-8")

        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"security CI accepted document mutation: {label}")


def assert_actionlint_config_rejected(
    label: str, mutate: Callable[[str], str], expected_error: str
) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-ci-contract-") as raw:
        fixture = Path(raw)
        populate_fixture(fixture)
        config = fixture / ACTIONLINT_CONFIG
        original = config.read_text(encoding="utf-8")
        mutated = mutate(original)
        if mutated == original:
            raise AssertionError(f"{label}: mutation did not change its fixture")
        config.write_text(mutated, encoding="utf-8")

        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"security CI accepted actionlint mutation: {label}")


def assert_boundary_file_rejected(
    label: str,
    relative: Path,
    mutate: Callable[[str], str],
    expected_error: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-ci-contract-") as raw:
        fixture = Path(raw)
        populate_fixture(fixture)
        target = fixture / relative
        original = target.read_text(encoding="utf-8")
        mutated = mutate(original)
        if mutated == original:
            raise AssertionError(f"{label}: mutation did not change its fixture")
        target.write_text(mutated, encoding="utf-8")
        try:
            CHECKER.validate(fixture)
        except CHECKER.ContractError as error:
            if expected_error not in str(error):
                raise AssertionError(
                    f"{label}: unexpected rejection: {error}"
                ) from error
        else:
            raise AssertionError(f"security CI accepted boundary mutation: {label}")


def extraction_program() -> str:
    workflow = CHECKER.load_workflow(
        ROOT / ".github/workflows/enterprise-evidence-finalizer.yml"
    )
    validate_job = CHECKER.job(workflow, "validate-capture")
    run = CHECKER.named_step(
        validate_job, "Safely extract exact bounded capture files"
    )["run"]
    marker = "/usr/bin/python3 - <<'PY'\n"
    if (
        not isinstance(run, str)
        or marker not in run
        or not run.rstrip("\n").endswith("\nPY")
    ):
        raise AssertionError("unable to isolate bounded extraction program")
    return run.split(marker, 1)[1].rstrip("\n").rsplit("\nPY", 1)[0]


EXTRACTION_PROGRAM = extraction_program()
EXTRACTION_NAMES = (
    "artifact-files.sha256",
    "broker-boundary.log",
    "cage-enforcement.log",
    "capture-summary.json",
    "committed-adversarial-evidence.log",
    "key-log-transparency.log",
    "linux-adversarial-controls.log",
    "migration-state-store.log",
    "runner-contract.log",
)


def regular_zip_info(name: str, mode: int = 0o600) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def build_extraction_archive(
    path: Path,
    entries: list[tuple[zipfile.ZipInfo, bytes]],
    *,
    encrypted_index: int | None = None,
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as archive:
            for info, data in entries:
                archive.writestr(info, data)
    if encrypted_index is None:
        return
    body = bytearray(path.read_bytes())
    local_positions = [match.start() for match in re.finditer(b"PK\\x03\\x04", body)]
    central_positions = [match.start() for match in re.finditer(b"PK\\x01\\x02", body)]
    if encrypted_index >= len(local_positions) or encrypted_index >= len(
        central_positions
    ):
        raise AssertionError("unable to locate ZIP member headers")
    for position, offset in (
        (local_positions[encrypted_index], 6),
        (central_positions[encrypted_index], 8),
    ):
        flags = struct.unpack_from("<H", body, position + offset)[0]
        struct.pack_into("<H", body, position + offset, flags | 0x1)
    path.write_bytes(body)


def run_extraction_fixture(
    label: str,
    entries: list[tuple[zipfile.ZipInfo, bytes]],
    *,
    accepted: bool,
    encrypted_index: int | None = None,
) -> None:
    with tempfile.TemporaryDirectory(prefix="chio-security-extraction-") as raw:
        fixture = Path(raw)
        archive = fixture / "capture.zip"
        output = fixture / "output"
        program = fixture / "extract.py"
        build_extraction_archive(archive, entries, encrypted_index=encrypted_index)
        program.write_text(EXTRACTION_PROGRAM, encoding="utf-8")
        environment = os.environ.copy()
        environment.update({"ARCHIVE": str(archive), "OUTPUT_DIRECTORY": str(output)})
        result = subprocess.run(
            [sys.executable, str(program)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if accepted and result.returncode != 0:
            raise AssertionError(
                f"{label}: valid extraction failed: {result.stderr or result.stdout}"
            )
        if not accepted and result.returncode == 0:
            raise AssertionError(f"{label}: unsafe extraction was accepted")


assert_nonzero_bootstrap_accepted()
assert_rejected(
    "all-zero enterprise workflow bootstrap placeholder",
    "ci.yml",
    lambda body: set_bootstrap_sha(body, ZERO_BOOTSTRAP_SHA),
    "bootstrap SHA cannot be all zero",
)
assert_rejected(
    "substituted enterprise workflow",
    "ci.yml",
    replace_once(
        "uses: bb-connor/arc/.github/workflows/enterprise-hardening.yml@"
        + NONZERO_BOOTSTRAP_SHA,
        "uses: bb-connor/arc/.github/workflows/nightly.yml@"
        + NONZERO_BOOTSTRAP_SHA,
    ),
    "immutable full SHA",
)
assert_rejected(
    "enterprise workflow call falls back to mutable local bytes",
    "ci.yml",
    replace_once(
        "uses: bb-connor/arc/.github/workflows/enterprise-hardening.yml@"
        + NONZERO_BOOTSTRAP_SHA,
        "uses: ./.github/workflows/enterprise-hardening.yml",
    ),
    "immutable full SHA",
)
assert_rejected(
    "enterprise workflow bootstrap sentinel diverges from call",
    "ci.yml",
    replace_once(
        "# CHIO_ENTERPRISE_HARDENING_BOOTSTRAP_SHA=" + NONZERO_BOOTSTRAP_SHA,
        "# CHIO_ENTERPRISE_HARDENING_BOOTSTRAP_SHA=" + MISMATCHED_BOOTSTRAP_SHA,
    ),
    "bootstrap SHA sentinel is not exact",
)
assert_rejected(
    "enterprise caller uses synthetic merge instead of reviewed head",
    "ci.yml",
    replace_once(
        "source_sha: ${{ github.event.pull_request.head.sha || github.sha }}",
        "source_sha: ${{ github.sha }}",
    ),
    "immutable full SHA",
)
assert_rejected(
    "enterprise caller substitutes authorized S for current source C",
    "ci.yml",
    replace_once(
        "source_sha: ${{ github.event.pull_request.head.sha || github.sha }}",
        "source_sha: ${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
    ),
    "immutable full SHA",
)
assert_rejected(
    "candidate workflow receives signing seed",
    "ci.yml",
    replace_once(
        "      source_sha: ${{ github.event.pull_request.head.sha || github.sha }}\n",
        "      source_sha: ${{ github.event.pull_request.head.sha || github.sha }}\n"
        "    secrets:\n"
        "      CANARY: ${{ secrets.CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX }}\n",
    ),
    "exposes a repository secret to candidate work",
)
for assertion in sorted(CHECKER.REQUIRED_AGGREGATE_ASSERTIONS):
    assert_rejected(
        f"missing aggregate assertion: {assertion}",
        "ci.yml",
        replace_once(f"          {assertion}\n", ""),
        "omits exact dependency assertions",
    )
assert_rejected(
    "security context rename",
    "ci.yml",
    replace_once("    name: Security contract\n", "    name: Security Contract\n"),
    "planned main ruleset context changed",
)
assert_rejected(
    "refresh-label recovery removed",
    "ci.yml",
    replace_once(
        "    types: [opened, synchronize, reopened, unlabeled]\n",
        "    types: [opened, synchronize, reopened]\n",
    ),
    "does not rerun after Linux refresh label removal",
)
assert_rejected(
    "CI top-level contents permission becomes write",
    "ci.yml",
    replace_once(
        "permissions:\n  contents: read\n",
        "permissions:\n  contents: write\n",
    ),
    "required CI permissions changed",
)
assert_rejected(
    "candidate CI workflow grants Actions write",
    "ci.yml",
    replace_once(
        "permissions:\n  contents: read\n",
        "permissions:\n  actions: write\n  contents: read\n",
    ),
    "Actions write permission escapes its exact trusted dispatcher declarations",
)
assert_rejected(
    "candidate CI job grants Actions write",
    "ci.yml",
    replace_in_named_job(
        "check",
        "    name: Build, lint, test\n",
        "    name: Build, lint, test\n"
        "    permissions:\n"
        "      actions: write\n"
        "      contents: read\n",
    ),
    "Actions write permission escapes its exact trusted dispatcher declarations",
)
assert_rejected(
    "Cargo serialization removed",
    "ci.yml",
    replace_once('  CARGO_BUILD_JOBS: "1"\n', '  CARGO_BUILD_JOBS: "2"\n'),
    "does not enforce serialized nonincremental Cargo",
)
assert_rejected(
    "formal mapping removed",
    "ci.yml",
    replace_in_named_step(
        "Formal traceability gate", "bash scripts/check-mapping.sh", "true"
    ),
    "omits the exact formal traceability gate",
)
assert_rejected(
    "workspace clippy narrowed",
    "ci.yml",
    replace_once(
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo clippy --workspace -- -D warnings",
    ),
    "required CI omits exact command",
)
assert_rejected(
    "Loom gate disabled",
    "ci.yml",
    replace_in_named_step(
        "Protocol-primitives production Loom gate",
        "./scripts/check-protocol-primitives-concurrency.sh",
        "true",
    ),
    "changes mandatory step body",
)
assert_rejected(
    "Kani manifest narrowed",
    "ci.yml",
    replace_in_named_step(
        "Verify all PR Kani harnesses",
        "./scripts/run-kani-manifest.sh --lane pr",
        "./scripts/run-kani-manifest.sh --lane pr --crate chio-kernel-core",
    ),
    "Kani PR manifest evidence changes mandatory step body",
)

assert_rejected(
    "enterprise direct PR trigger",
    "enterprise-hardening.yml",
    replace_once("on:\n  workflow_call:\n", "on:\n  pull_request:\n  workflow_call:\n"),
    "source input contract changed",
)
assert_rejected(
    "enterprise source input removed",
    "enterprise-hardening.yml",
    replace_once(
        "      source_repository:\n",
        "      renamed_source_repository:\n",
    ),
    "source input contract changed",
)
assert_rejected(
    "enterprise source concurrency widened",
    "enterprise-hardening.yml",
    replace_once(
        "group: enterprise-security-source-${{ github.repository }}-${{ github.event.pull_request.head.sha || github.sha }}",
        "group: enterprise-security-${{ github.ref }}",
    ),
    "concurrency does not isolate",
)
assert_rejected(
    "enterprise job inventory drift",
    "enterprise-hardening.yml",
    replace_once(
        "  active-defense-security:\n", "  renamed-active-defense-security:\n"
    ),
    "enterprise job inventory changed",
)
assert_rejected(
    "required enterprise persistent runner",
    "enterprise-hardening.yml",
    replace_once("    runs-on: ubuntu-24.04\n", "    runs-on: [self-hosted, linux]\n"),
    "persistent runner",
)
assert_rejected(
    "required enterprise secret injection",
    "enterprise-hardening.yml",
    replace_once(
        'env:\n  CARGO_INCREMENTAL: "0"\n',
        'env:\n  CANARY: ${{ secrets.CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX }}\n  CARGO_INCREMENTAL: "0"\n',
    ),
    "exposes a repository secret to candidate work",
)
assert_rejected(
    "enterprise bind-source gains checkout",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Build canonical exact merge binding",
        "          set -euo pipefail\n",
        "          set -euo pipefail\n          git checkout main\n",
    ),
    "enterprise-hardening bind-source normalized job contract changed",
)
assert_rejected(
    "enterprise bind-source trusts caller repository",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Build canonical exact merge binding",
        'test "${INPUT_SOURCE_REPOSITORY}" = "${TESTED_REPOSITORY}"',
        "true",
    ),
    "does not attest the exact event merge",
)
assert_rejected(
    "enterprise bind-source trusts caller PR SHA",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Build canonical exact merge binding",
        'test "${INPUT_SOURCE_SHA}" = "${EVENT_PR_HEAD_SHA}"',
        "true",
    ),
    "does not attest the exact event merge",
)
assert_rejected(
    "enterprise bind-source conflates PR head and synthetic merge",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Build canonical exact merge binding",
        "TESTED_SHA: ${{ github.sha }}",
        "TESTED_SHA: ${{ inputs.source_sha }}",
    ),
    "event inputs changed",
)
assert_rejected(
    "enterprise bind-source accepts forged push SHA",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Bind exact pushed commit",
        'test "${INPUT_SOURCE_SHA}" = "${TESTED_SHA}"',
        "true",
    ),
    "enterprise-hardening bind-source normalized job contract changed",
)
assert_rejected(
    "enterprise candidate bypasses bind-source",
    "enterprise-hardening.yml",
    replace_once("    needs: [bind-source]\n", ""),
    "bypasses bound event source",
)
assert_rejected(
    "enterprise tested checkout retargeted to reviewed head",
    "enterprise-hardening.yml",
    replace_once(
        "          ref: ${{ needs.bind-source.outputs.tested_sha }}\n",
        "          ref: ${{ needs.bind-source.outputs.source_sha }}\n",
    ),
    "exact source without credentials",
)
assert_rejected(
    "enterprise source credentials persisted",
    "enterprise-hardening.yml",
    replace_once(
        "          persist-credentials: false\n",
        "          persist-credentials: true\n",
    ),
    "enterprise bind-source exact merge checkout changed",
)
assert_rejected(
    "enterprise tested identity check removed",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Verify exact event test checkout",
        'test "$(git rev-parse HEAD)" = "${{ needs.bind-source.outputs.tested_sha }}"',
        "true",
    ),
    "validate the exact source checkout",
)
assert_rejected(
    "enterprise Linux gate conditional",
    "enterprise-hardening.yml",
    replace_once(
        "  linux-enforcement:\n    name: enterprise real Linux enforcement\n",
        "  linux-enforcement:\n    name: enterprise real Linux enforcement\n    if: false\n",
    ),
    "required enterprise job is conditional",
)
assert_rejected(
    "enterprise Linux trusted checkout retargeted to candidate",
    "enterprise-hardening.yml",
    replace_in_named_job(
        "linux-enforcement",
        "          ref: ${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}\n",
        "          ref: ${{ needs.bind-source.outputs.tested_sha }}\n",
    ),
    "tooling is not pinned to authorized source",
)
assert_rejected(
    "enterprise Linux image builds candidate context",
    "enterprise-hardening.yml",
    replace_in_named_job(
        "linux-enforcement",
        "            authorized-security\n",
        "            candidate\n",
    ),
    "builds an image from candidate-controlled tooling",
)
assert_rejected(
    "enterprise Linux runner uses candidate bytes",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Run isolated Linux evidence and cage campaigns",
        "authorized-security/scripts/run-security-execution-container.py",
        "candidate/scripts/run-security-execution-container.py",
    ),
    "bypasses the trusted execution runner",
)
assert_rejected(
    "enterprise Linux executes Cargo on host",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Run isolated Linux evidence and cage campaigns",
        "          /usr/bin/python3 \\\n",
        "          cargo test --workspace\n          /usr/bin/python3 \\\n",
    ),
    "executes candidate tooling on the host",
)
assert_rejected(
    "enterprise schema gate removed",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Schema registry and generated bindings",
        "./scripts/check-chio-schema-registry.sh",
        "true",
    ),
    "changes mandatory step body",
)
assert_rejected(
    "enterprise native inventory narrowed",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Native security conformance",
        "            native_standards_artifacts_cover_required_categories_and_references\n",
        "",
    ),
    "changes mandatory step body",
)
assert_rejected(
    "enterprise Rust generated vector inventory narrowed",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Native security conformance",
        "            protocol_schema_and_generated_types_cover_exact_negative_corpus\n",
        "",
    ),
    "changes mandatory step body",
)
assert_rejected(
    "enterprise Go generated vector inventory narrowed",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Go generated security conformance",
        "\\nTestProtocolSchemaAndGeneratedTypesCoverExactNegativeCorpus'",
        "'",
    ),
    "changes mandatory step body",
)
assert_rejected(
    "enterprise active-defense gate removed",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Active defense acceptance behavior",
        "./scripts/check-active-defense-conformance.sh",
        "true",
    ),
    "changes mandatory step body",
)
assert_rejected(
    "enterprise adversarial gate removed",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Verify freshness-bound mutation evidence",
        "--operation adversarial-release",
        "--operation hostile-probe",
    ),
    "bypasses the trusted execution runner",
)
assert_rejected(
    "enterprise adversarial hostile probes removed",
    "enterprise-hardening.yml",
    replace_in_named_job(
        "adversarial-evidence",
        "      - name: Verify trusted execution boundary hostile probes\n",
        "      - name: Untrusted substitute probes\n",
    ),
    "step inventory changed",
)
assert_boundary_file_rejected(
    "security image loses digest-pinned Rust base",
    Path("deploy/docker/Dockerfile.security-evidence-runner"),
    replace_once(
        "rust:1.93.0-alpine3.22@sha256:efc08a6cc70a6ad8bdcf24176e3e0bdbbc7b984e7471fabf78b90de33b136f51",
        "rust:1.93.0-alpine3.22",
    ),
    "image has an unpinned build stage",
)
assert_boundary_file_rejected(
    "security image ignores a commented pinned-base decoy",
    Path("deploy/docker/Dockerfile.security-evidence-runner"),
    replace_once(
        "FROM --platform=linux/amd64 rust:1.93.0-alpine3.22@sha256:efc08a6cc70a6ad8bdcf24176e3e0bdbbc7b984e7471fabf78b90de33b136f51",
        "# FROM --platform=linux/amd64 rust:1.93.0-alpine3.22@sha256:efc08a6cc70a6ad8bdcf24176e3e0bdbbc7b984e7471fabf78b90de33b136f51\n"
        "FROM --platform=linux/amd64 rust:1.93.0-alpine3.22",
    ),
    "image has an unpinned build stage",
)
assert_boundary_file_rejected(
    "security image rejects reordered APK closure",
    Path("deploy/docker/Dockerfile.security-evidence-runner"),
    replace_once(
        "      bash=5.2.37-r0 \\\n      build-base=0.5-r3 \\\n",
        "      build-base=0.5-r3 \\\n      bash=5.2.37-r0 \\\n",
    ),
    "image APK closure changed",
)
assert_boundary_file_rejected(
    "security image omits installed seccomp authority",
    Path("deploy/docker/Dockerfile.security-evidence-runner"),
    replace_once(
        " && install -m 0444 deploy/docker/security-evidence-seccomp.json "
        "/opt/chio-security/security-evidence-seccomp.json \\\n",
        "",
    ),
    "image authority graph changed",
)
assert_boundary_file_rejected(
    "security seccomp permits namespace creation",
    Path("deploy/docker/security-evidence-seccomp.json"),
    replace_once('"unshare"', '"chio-unshare"'),
    "seccomp syscall contract changed",
)
assert_boundary_file_rejected(
    "security seccomp blocks ptrace proof syscall",
    Path("deploy/docker/security-evidence-seccomp.json"),
    replace_once('"bpf",', '"bpf", "ptrace",'),
    "seccomp syscall contract changed",
)
assert_boundary_file_rejected(
    "security seccomp changes the default action",
    Path("deploy/docker/security-evidence-seccomp.json"),
    replace_once(
        '"defaultAction": "SCMP_ACT_ALLOW"', '"defaultAction": "SCMP_ACT_LOG"'
    ),
    "seccomp syscall contract changed",
)
assert_boundary_file_rejected(
    "security seccomp changes the architecture map",
    Path("deploy/docker/security-evidence-seccomp.json"),
    replace_once('"SCMP_ARCH_X32"', '"SCMP_ARCH_AARCH64"'),
    "seccomp syscall contract changed",
)
assert_boundary_file_rejected(
    "security seccomp weakens a clone namespace mask",
    Path("deploy/docker/security-evidence-seccomp.json"),
    replace_once('"valueTwo": 268435456', '"valueTwo": 0'),
    "seccomp syscall contract changed",
)
assert_boundary_file_rejected(
    "security runner enables candidate network",
    Path("scripts/run-security-execution-container.py"),
    replace_once('"--network",\n        "none"', '"--network",\n        "bridge"'),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner appends a later host-network override",
    Path("scripts/run-security-execution-container.py"),
    replace_once(
        '"--network",\n        "none",',
        '"--network",\n        "none",\n        "--network",\n        "host",',
    ),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner appends an extra host mount",
    Path("scripts/run-security-execution-container.py"),
    replace_once(
        '"--mount",\n        f"type=bind,src={output},dst=/output",',
        '"--mount",\n'
        '        f"type=bind,src={output},dst=/output",\n'
        '        "--mount",\n'
        '        "type=bind,src=/,dst=/host,readonly",',
    ),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner removes the process limit value",
    Path("scripts/run-security-execution-container.py"),
    replace_once('"512",', '"0",'),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner disables the custom seccomp profile",
    Path("scripts/run-security-execution-container.py"),
    replace_once('f"seccomp={seccomp_profile}"', '"seccomp=unconfined"'),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner loses state identity labels",
    Path("scripts/run-security-execution-container.py"),
    replace_once(
        'STATE_LABEL = "org.chio.security-execution.state"',
        'STATE_LABEL = "org.chio.security-execution.unscoped"',
    ),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner follows lock symlinks",
    Path("scripts/run-security-execution-container.py"),
    replace_once(
        "def open_private_lock(path: Path) -> int:\n"
        '    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)\n'
        '    if hasattr(os, "O_NOFOLLOW"):\n'
        "        flags |= os.O_NOFOLLOW",
        "def open_private_lock(path: Path) -> int:\n"
        '    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)',
    ),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner keeps post-publication output after source race",
    Path("scripts/run-security-execution-container.py"),
    replace_once(
        "reject_published_outputs(output_dir, set(payloads))",
        "pass",
    ),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner restores debug-heavy candidate profiles",
    Path("scripts/run-security-execution-container.py"),
    replace_once('"CARGO_PROFILE_DEV_DEBUG": "0"', '"CARGO_PROFILE_DEV_DEBUG": "1"'),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner removes the file-size resource bound",
    Path("scripts/run-security-execution-container.py"),
    replace_once('"fsize=1073741824:1073741824"', '"fsize=-1:-1"'),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner restores container capabilities",
    Path("scripts/run-security-execution-container.py"),
    replace_once('"--cap-drop",\n        "ALL"', '"--cap-add",\n        "ALL"'),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security runner drops authority revalidation",
    Path("scripts/run-security-execution-container.py"),
    replace_once(
        "revalidate_repository(candidate)\n",
        "pass\n",
    ),
    "trusted security container runner contract changed",
)
assert_boundary_file_rejected(
    "security entrypoint executes candidate checker",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        "/opt/chio-security/check-security-adversarial-evidence.py",
        "/workspace/scripts/check-security-adversarial-evidence.py",
    ),
    "entrypoint authority paths changed",
)
assert_boundary_file_rejected(
    "security entrypoint runs candidate work as root",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once("CANDIDATE_UID = 65532", "CANDIDATE_UID = 0"),
    "entrypoint identity inventory changed",
)
assert_boundary_file_rejected(
    "security entrypoint gives candidate a mutable Git baseline",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once('"GIT_DIR": "/baseline/git"', '"GIT_DIR": "/private/candidate/.git"'),
    "entrypoint environment boundary changed",
)
assert_boundary_file_rejected(
    "security entrypoint rejects a dead finally quiescence decoy",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        "    try:\n"
        "        return collect_bounded_process(\n"
        "            process, timeout_seconds, terminate=terminate_group\n"
        "        )\n"
        "    finally:\n"
        "        quiesce_process_namespace()\n",
        "    try:\n"
        "        return collect_bounded_process(\n"
        "            process, timeout_seconds, terminate=terminate_group\n"
        "        )\n"
        "    finally:\n"
        "        if False:\n"
        "            quiesce_process_namespace()\n",
    ),
    "candidate command supervision control flow changed",
)
assert_boundary_file_rejected(
    "security entrypoint rejects a later candidate-env mutation",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        "    return environment\n\n\ndef verifier_environment",
        "    environment[\"CARGO_NET_OFFLINE\"] = \"false\"\n"
        "    return environment\n\n\ndef verifier_environment",
    ),
    "candidate environment forwarding changed",
)
assert_boundary_file_rejected(
    "security entrypoint rejects protected function rebinding",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        '\nif __name__ == "__main__":\n',
        "\nrun_candidate_capture = lambda *arguments, **keywords: (0, b\"\")\n"
        'if __name__ == "__main__":\n',
    ),
    "protected authority binding changed",
)
assert_boundary_file_rejected(
    "security entrypoint rejects protected function class rebinding",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        '\nif __name__ == "__main__":\n',
        "\nclass run_candidate_capture:\n"
        "    pass\n\n"
        'if __name__ == "__main__":\n',
    ),
    "protected authority binding changed",
)
assert_boundary_file_rejected(
    "security entrypoint rejects protected function import rebinding",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        '\nif __name__ == "__main__":\n',
        "\nimport os as run_candidate_capture\n"
        'if __name__ == "__main__":\n',
    ),
    "protected authority binding changed",
)
assert_boundary_file_rejected(
    "security entrypoint rejects protected function async rebinding",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        '\nif __name__ == "__main__":\n',
        "\nasync def run_candidate_capture(*arguments, **keywords):\n"
        "    return 0, b\"\"\n\n"
        'if __name__ == "__main__":\n',
    ),
    "protected authority binding changed",
)
assert_boundary_file_rejected(
    "security entrypoint rejects protected function decoration",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        "def run_candidate_capture(\n",
        "@staticmethod\ndef run_candidate_capture(\n",
    ),
    "protected authority binding changed",
)
assert_boundary_file_rejected(
    "security entrypoint rejects protected function exception rebinding",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        '\nif __name__ == "__main__":\n',
        "\ntry:\n"
        "    raise RuntimeError\n"
        "except RuntimeError as run_candidate_capture:\n"
        "    pass\n\n"
        'if __name__ == "__main__":\n',
    ),
    "protected authority binding changed",
)
assert_boundary_file_rejected(
    "security entrypoint stops validating installed seccomp mode",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        "        TRUSTED_SECCOMP_PROFILE,\n"
        "        expected_mode=0o444,\n",
        "        TRUSTED_SECCOMP_PROFILE,\n"
        "        expected_mode=0o555,\n",
    ),
    "entrypoint file modes changed",
)
assert_boundary_file_rejected(
    "security entrypoint omits the post-clippy repository inventory check",
    Path("scripts/security-execution-container-entrypoint.py"),
    replace_once(
        "    require_clean_repository(timeout_seconds)\n"
        "    for name, payload in (\n",
        "    for name, payload in (\n",
    ),
    "candidate repository publication graph changed",
)
assert_boundary_file_rejected(
    "security cage gate routes through candidate helper",
    Path("scripts/check-cage-enforcement.sh"),
    replace_once(
        "/opt/chio-security/gates/check-linux-enforcement-stack.py",
        "/private/candidate/scripts/check-linux-enforcement-stack.py",
    ),
    "trusted gate helper routing changed",
)
assert_rejected(
    "committed evidence bypasses bind-source",
    "enterprise-hardening.yml",
    replace_once(
        "    needs: [bind-source, linux-enforcement]\n",
        "    needs: [linux-enforcement]\n",
    ),
    "committed Linux evidence job protection changed",
)
assert_rejected(
    "committed evidence bootstrap trusts raw caller input",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Bind committed evidence or authorize narrow bootstrap",
        "SOURCE_SHA: ${{ needs.bind-source.outputs.source_sha }}",
        "SOURCE_SHA: ${{ inputs.source_sha }}",
    ),
    "bootstrap bindings changed",
)
assert_rejected(
    "committed evidence bootstrap widened past authorized S",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Bind committed evidence or authorize narrow bootstrap",
        'test "${SOURCE_SHA}" = "${AUTHORIZED_SOURCE_SHA}"',
        "true",
    ),
    "bootstrap is wider",
)
assert_rejected(
    "committed evidence E replaced with current C",
    "enterprise-hardening.yml",
    replace_once(
        "          ref: ${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}\n",
        "          ref: ${{ needs.bind-source.outputs.source_sha }}\n",
    ),
    "not bound to detached E",
)
assert_rejected(
    "committed evidence checker uses candidate bytes",
    "enterprise-hardening.yml",
    replace_in_named_job(
        "committed-linux-evidence",
        "          ref: ${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}\n",
        "          ref: ${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}\n",
    ),
    "checker is not pinned to authorized S",
)
assert_rejected(
    "committed evidence executes candidate checker",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Verify committed Linux evidence descendant",
        "/usr/bin/python3 authorized-checker/scripts/check-committed-linux-evidence.py",
        "/usr/bin/python3 committed-evidence/scripts/check-committed-linux-evidence.py",
    ),
    "does not use pinned checker bytes",
)
assert_rejected(
    "committed evidence verifies current source as E",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Verify committed Linux evidence descendant",
        '--evidence-commit "${EVIDENCE_SHA}"',
        '--evidence-commit "${{ needs.bind-source.outputs.source_sha }}"',
    ),
    "does not use pinned checker bytes",
)

assert_rejected(
    "controller candidate-context trigger",
    "enterprise-evidence-controller.yml",
    replace_once("  pull_request_target:\n", "  pull_request:\n"),
    "not base-defined on PR target",
)
assert_rejected(
    "controller dispatch permission removed",
    "enterprise-evidence-controller.yml",
    replace_once("  actions: write\n", "  actions: read\n"),
    "Actions write permission escapes its exact trusted dispatcher declarations",
)
assert_rejected(
    "controller source concurrency weakened",
    "enterprise-evidence-controller.yml",
    replace_once(
        "enterprise-security-controller-source-${{ github.event.pull_request.head.sha }}",
        "enterprise-security-controller-${{ github.ref }}",
    ),
    "source-SHA serialized",
)
assert_rejected(
    "controller checkout injection",
    "enterprise-evidence-controller.yml",
    replace_once(
        "    steps:\n",
        "    steps:\n      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n",
    ),
    "action inventory changed",
)
assert_rejected(
    "controller owner restriction removed",
    "enterprise-evidence-controller.yml",
    replace_once(
        "      github.event.pull_request.author_association == 'OWNER' &&\n",
        "      true &&\n",
    ),
    "does not restrict dispatch identity",
)
for label, old, new in (
    ("controller triggering actor unbound", ".triggering_actor.login", ".actor.login"),
    ("controller merge parent unbound", ".parents[1].sha", ".parents[0].sha"),
    (
        "controller source allowlist widened",
        '(.status == "added" or .status == "modified")',
        '(.status != "removed")',
    ),
    ("controller evidence mode widened", '.mode == "100644"', '.mode == "100755"'),
):
    assert_rejected(
        label,
        "enterprise-evidence-controller.yml",
        replace_in_named_step(
            "Authorize exact source and controller context", old, new
        ),
        "does not bind live workflow, PR, merge, and source authorization",
    )
assert_rejected(
    "controller omits authorized runner inventory",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Authorize exact source and controller context",
        "          100755:scripts/run-security-execution-container.py\n",
        "",
    ),
    "does not bind live workflow, PR, merge, and source authorization",
)
assert_rejected(
    "controller dispatches candidate workflow definition",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Dispatch exact default-branch capture definition",
        '--arg ref "${default_branch}"',
        '--arg ref "${HEAD_SHA}"',
    ),
    "does not bind exact capture inputs",
)
assert_rejected(
    "controller omits merge tree input",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Dispatch exact default-branch capture definition",
        '            --arg merge_tree_sha "${MERGE_TREE_SHA}" \\\n',
        "",
    ),
    "does not bind exact capture inputs",
)
assert_rejected(
    "controller omits capture dispatch nonce input",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Dispatch exact default-branch capture definition",
        '            --arg controller_dispatch_nonce "${dispatch_nonce}" \\\n',
        "",
    ),
    "does not bind exact capture inputs",
)
assert_rejected(
    "controller accepts a capture workflow rerun",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Dispatch exact default-branch capture definition",
        'test "$(jq -r \'.run_attempt\' <<< "${dispatched_run}")" = "1"',
        "true",
    ),
    "does not bind exact capture inputs",
)
assert_rejected(
    "controller weakens the capture intent schema",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Dispatch exact default-branch capture definition",
        'schema: "chio.enterprise-capture-dispatch-intent.v1"',
        'schema: "chio.enterprise-capture-dispatch-intent.v2"',
    ),
    "does not bind exact capture inputs",
)
assert_rejected(
    "controller upload loses exact capture run binding",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Upload exact capture dispatch intent",
        "enterprise-capture-intent-${{ github.run_id }}-${{ github.run_attempt }}-${{ steps.dispatch.outputs.capture_run_id }}",
        "enterprise-capture-intent-${{ github.run_id }}",
    ),
    "controller intent upload changed",
)

assert_rejected(
    "capture gains PR trigger",
    "enterprise-linux-capture.yml",
    replace_once("  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n"),
    "manual fixed-input contract",
)
assert_rejected(
    "capture source input removed",
    "enterprise-linux-capture.yml",
    replace_once(
        "      authorized_source_sha:\n", "      renamed_authorized_source_sha:\n"
    ),
    "manual fixed-input contract",
)
assert_rejected(
    "capture controller nonce input removed",
    "enterprise-linux-capture.yml",
    replace_once(
        "      controller_dispatch_nonce:\n",
        "      renamed_controller_dispatch_nonce:\n",
    ),
    "manual fixed-input contract",
)
assert_rejected(
    "capture authenticated controller title loses nonce",
    "enterprise-linux-capture.yml",
    replace_once(
        "run-name: Enterprise Linux capture N=${{ inputs.pr_number }} E=${{ inputs.source_sha }} M=${{ inputs.merge_commit_sha }} S=${{ inputs.authorized_source_sha }} K=${{ inputs.controller_dispatch_nonce }}",
        "run-name: Enterprise Linux capture N=${{ inputs.pr_number }} E=${{ inputs.source_sha }}",
    ),
    "authenticated title changed",
)
assert_rejected(
    "capture accepts a rerun before controller intent authentication",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Revalidate controller source and merge authorization",
        'test "${CAPTURE_RUN_ATTEMPT}" = "1"',
        "true",
    ),
    "does not revalidate controller, run, merge, source, and freshness bindings",
)
assert_rejected(
    "capture skips controller intent archive digest verification",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Revalidate controller source and merge authorization",
        'test "$(sha256sum "${intent_partial}" | cut -d\' \' -f1)" = "${intent_artifact_digest#sha256:}"',
        "true",
    ),
    "does not revalidate controller, run, merge, source, and freshness bindings",
)
assert_rejected(
    "capture permits multiple controller intent archive members",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Revalidate controller source and merge authorization",
        "if len(infos) != 1:",
        "if False:",
    ),
    "authorize-capture normalized job contract changed",
)
assert_rejected(
    "capture accepts a mismatched controller dispatch nonce",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Revalidate controller source and merge authorization",
        'test "$(jq -r \'.dispatch_nonce\' <<< "${intent}")" = "${INPUT_CONTROLLER_DISPATCH_NONCE}"',
        "true",
    ),
    "does not revalidate controller, run, merge, source, and freshness bindings",
)
assert_rejected(
    "capture gains write permission",
    "enterprise-linux-capture.yml",
    replace_once("  actions: read\n", "  actions: write\n"),
    "Actions write permission escapes its exact trusted dispatcher declarations",
)
assert_rejected(
    "capture source concurrency weakened",
    "enterprise-linux-capture.yml",
    replace_once(
        "group: enterprise-security-source-${{ inputs.source_sha }}",
        "group: enterprise-security-${{ github.ref }}",
    ),
    "source-SHA serialized",
)
assert_rejected(
    "capture receives signing seed",
    "enterprise-linux-capture.yml",
    replace_once(
        'env:\n  CARGO_INCREMENTAL: "0"\n',
        'env:\n  CANARY: ${{ secrets.CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX }}\n  CARGO_INCREMENTAL: "0"\n',
    ),
    "exposes a repository secret to candidate work",
)
assert_rejected(
    "capture uses persistent runner",
    "enterprise-linux-capture.yml",
    replace_once("    runs-on: ubuntu-24.04\n", "    runs-on: [self-hosted, linux]\n"),
    "persistent runner",
)
assert_rejected(
    "capture persists checkout credentials",
    "enterprise-linux-capture.yml",
    replace_once(
        "          persist-credentials: false\n",
        "          persist-credentials: true\n",
    ),
    "candidate checkout is not isolated and exact",
)
assert_rejected(
    "capture bypasses authorization need",
    "enterprise-linux-capture.yml",
    replace_once("    needs: [authorize-capture]\n", "    needs: []\n"),
    "bypasses authorization",
)
assert_rejected(
    "capture enforcement mode widened",
    "enterprise-linux-capture.yml",
    replace_once(
        "    if: needs.authorize-capture.outputs.mode == 'enforcement'\n",
        "    if: needs.authorize-capture.outputs.mode != 'refresh'\n",
    ),
    "capture mode is not exact",
)
for label, old, new in (
    (
        "capture controller success unbound",
        'test "$(jq -r \'.conclusion\' <<< "${controller_run}")" = "success"',
        "true",
    ),
    (
        "capture controller trigger actor unbound",
        ".triggering_actor.login",
        ".actor.login",
    ),
    (
        "capture workflow blob unbound",
        "contents/.github/workflows/enterprise-linux-capture.yml?ref=",
        "contents/.github/workflows/enterprise-hardening.yml?ref=",
    ),
    (
        "capture merge tree unbound",
        '.tree.sha\' <<< "${merge_commit}")" = "${INPUT_MERGE_TREE_SHA}"',
        '.tree.sha\' <<< "${merge_commit}")" != ""',
    ),
    (
        "capture source allowlist widened",
        '(.status == "added" or .status == "modified")',
        '(.status != "removed")',
    ),
    ("capture evidence mode widened", '.mode == "100644"', '.mode == "100755"'),
):
    assert_rejected(
        label,
        "enterprise-linux-capture.yml",
        replace_in_named_step(
            "Revalidate controller source and merge authorization", old, new
        ),
        "does not revalidate controller, run, merge, source, and freshness bindings",
    )
assert_rejected(
    "capture trusted input binding removed",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Revalidate controller source and merge authorization",
        "          INPUT_SOURCE_SHA: ${{ inputs.source_sha }}\n",
        "",
    ),
    "trusted input bindings changed",
)
assert_rejected(
    "capture interpolates raw dispatch input into trusted shell",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Revalidate controller source and merge authorization",
        '[[ "${INPUT_SOURCE_SHA}" =~ ${commit_pattern} ]]',
        '[[ "${{ inputs.source_sha }}" =~ ${commit_pattern} ]]',
    ),
    "interpolates untrusted dispatch inputs",
)
assert_rejected(
    "capture run actor treated as owner",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Revalidate controller source and merge authorization",
        'test "${CAPTURE_ACTOR}" = "github-actions[bot]"',
        'test "${CAPTURE_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"',
    ),
    "does not revalidate controller, run, merge, source, and freshness bindings",
)
assert_rejected(
    "capture enforcement checks out head not merge",
    "enterprise-linux-capture.yml",
    replace_once(
        "          ref: ${{ needs.authorize-capture.outputs.merge_commit_sha }}\n",
        "          ref: ${{ needs.authorize-capture.outputs.source_sha }}\n",
    ),
    "candidate checkout is not isolated and exact",
)
assert_rejected(
    "capture trusted checkout retargeted to candidate merge",
    "enterprise-linux-capture.yml",
    replace_in_named_job(
        "capture-linux-enforcement",
        "          ref: ${{ needs.authorize-capture.outputs.authorized_source_sha }}\n",
        "          ref: ${{ needs.authorize-capture.outputs.merge_commit_sha }}\n",
    ),
    "tooling is not pinned to authorized source",
)
assert_rejected(
    "capture image builds candidate context",
    "enterprise-linux-capture.yml",
    replace_in_named_job(
        "capture-linux-enforcement",
        "            authorized-security\n",
        "            candidate\n",
    ),
    "builds an image from candidate-controlled tooling",
)
assert_rejected(
    "capture executes candidate checker on host",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Run candidate enforcement inside trusted execution boundary",
        "          /usr/bin/python3 \\\n",
        "          /usr/bin/python3 candidate/scripts/check-security-adversarial-evidence.py --release\n          /usr/bin/python3 \\\n",
    ),
    "executes candidate tooling on the host",
)
assert_rejected(
    "capture drops network-none runner operation",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Run candidate enforcement inside trusted execution boundary",
        "--operation linux-enforcement",
        "--operation hostile-probe",
    ),
    "bypasses the trusted execution runner",
)
assert_rejected(
    "capture refresh downgrades to the partial campaign set",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Refresh all evidence inside trusted execution boundary",
        "--operation refresh-all-evidence",
        "--operation refresh-linux-evidence",
    ),
    "bypasses the trusted execution runner",
)
assert_rejected(
    "capture image build loses the linux amd64 platform binding",
    "enterprise-linux-capture.yml",
    replace_in_named_job(
        "capture-linux-enforcement",
        "--platform linux/amd64",
        "--platform linux/arm64",
    ),
    "does not build a digest-addressed trusted image",
)
assert_rejected(
    "capture marks unsigned data signed",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Build unsigned fixed-schema capture", '"signed": False', '"signed": True'
    ),
    "changes its unsigned summary contract",
)
assert_rejected(
    "capture omits security execution image provenance",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Build unsigned fixed-schema capture",
        '"security_execution_image": os.environ["SECURITY_EXECUTION_IMAGE"],',
        '"security_execution_image": "unbound",',
    ),
    "changes its unsigned summary contract",
)
assert_rejected(
    "capture omits security execution seccomp provenance",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Build unsigned fixed-schema capture",
        '"security_execution_seccomp_sha256": os.environ["SECURITY_EXECUTION_SECCOMP_SHA256"],',
        '"security_execution_seccomp_sha256": "unbound",',
    ),
    "changes its unsigned summary contract",
)
assert_rejected(
    "capture drops controller workflow binding",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Build unsigned fixed-schema capture",
        '"controller_workflow_id": os.environ["CONTROLLER_WORKFLOW_ID"],',
        '"controller_workflow_id": "1",',
    ),
    "changes its unsigned summary contract",
)
assert_rejected(
    "capture upload loses run binding",
    "enterprise-linux-capture.yml",
    replace_once(
        "name: enterprise-linux-capture-${{ needs.authorize-capture.outputs.source_sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
        "name: enterprise-linux-capture",
    ),
    "fixed unsigned artifact",
)
assert_rejected(
    "capture refresh uploads pre-boundary host path",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Upload unsigned evidence patch",
        "${{ runner.temp }}/linux-evidence-artifact/all-evidence.patch",
        "${{ github.workspace }}/candidate/all-evidence.patch",
    ),
    "refresh upload changed",
)
assert_rejected(
    "capture finalizer dispatch permission removed",
    "enterprise-linux-capture.yml",
    replace_once("      actions: write\n", "      actions: read\n"),
    "Actions write permission escapes its exact trusted dispatcher declarations",
)
assert_rejected(
    "capture finalizer dispatch bypasses enforcement",
    "enterprise-linux-capture.yml",
    replace_once("      - capture-linux-enforcement\n", ""),
    "finalizer dispatch job protection changed",
)
assert_rejected(
    "capture finalizer dispatch gains checkout",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        "          set -euo pipefail\n",
        "          set -euo pipefail\n          git checkout main\n",
    ),
    "must not checkout candidate",
)
assert_rejected(
    "capture finalizer definition retargeted to candidate",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        '--arg ref "${default_branch}"',
        '--arg ref "${SOURCE_SHA}"',
    ),
    "finalizer dispatch",
)
assert_rejected(
    "capture finalizer source input omitted",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        '              --arg source_sha "${SOURCE_SHA}" \\\n',
        "",
    ),
    "finalizer dispatch",
)
assert_rejected(
    "capture finalizer dispatch actor treated as owner",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        'test "${GITHUB_ACTOR}" = "github-actions[bot]"',
        'test "${GITHUB_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"',
    ),
    "trusted finalizer dispatch",
)
assert_rejected(
    "capture finalizer dispatch drops nonce input",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        '              --arg dispatch_nonce "${dispatch_nonce}" \\\n',
        "",
    ),
    "trusted finalizer dispatch",
)
assert_rejected(
    "capture finalizer dispatch accepts duplicate nonce runs",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        'test "${match_count}" -le 1',
        "true",
    ),
    "trusted finalizer dispatch",
)
assert_rejected(
    "capture finalizer dispatch skips paginated run handshake",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        "                --paginate \\\n",
        "",
    ),
    "trusted finalizer dispatch",
)
assert_rejected(
    "capture finalizer dispatch weakens run-start wait",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        "for _ in $(seq 1 120); do",
        "for _ in $(seq 1 1); do",
    ),
    "trusted finalizer dispatch",
)
assert_rejected(
    "capture finalizer dispatch accepts a merely queued run",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        "                in_progress)\n",
        "                queued|in_progress)\n",
    ),
    "trusted finalizer dispatch",
)
assert_rejected(
    "capture accepts a finalizer workflow rerun",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        'test "$(jq -r \'.run_attempt\' <<< "${dispatched_run}")" = "1"',
        "true",
    ),
    "trusted finalizer dispatch",
)
assert_rejected(
    "capture weakens the finalizer intent schema",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Dispatch exact default-branch finalizer definition",
        'schema: "chio.enterprise-finalizer-dispatch-intent.v1"',
        'schema: "chio.enterprise-finalizer-dispatch-intent.v2"',
    ),
    "trusted finalizer dispatch",
)
assert_rejected(
    "capture upload loses exact finalizer run binding",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Upload exact finalizer dispatch intent",
        "enterprise-finalizer-intent-${{ github.run_id }}-${{ github.run_attempt }}-${{ steps.dispatch.outputs.finalizer_run_id }}",
        "enterprise-finalizer-intent-${{ github.run_id }}",
    ),
    "finalizer dispatch intent upload changed",
)

assert_rejected(
    "finalizer workflow-run trigger restored",
    "enterprise-evidence-finalizer.yml",
    replace_once("  workflow_dispatch:\n", "  workflow_run:\n"),
    "explicit dispatch contract",
)
assert_rejected(
    "finalizer capture attempt input removed",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "      capture_run_attempt:\n", "      renamed_capture_run_attempt:\n"
    ),
    "explicit dispatch contract",
)
assert_rejected(
    "finalizer dispatch nonce input removed",
    "enterprise-evidence-finalizer.yml",
    replace_once("      dispatch_nonce:\n", "      renamed_dispatch_nonce:\n"),
    "explicit dispatch contract",
)
assert_rejected(
    "finalizer dispatch nonce title removed",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "run-name: Enterprise evidence finalizer N=${{ inputs.pr_number }} E=${{ inputs.source_sha }} M=${{ inputs.merge_commit_sha }} S=${{ inputs.authorized_source_sha }} K=${{ inputs.dispatch_nonce }}",
        "run-name: Enterprise evidence finalizer",
    ),
    "authenticated title changed",
)
assert_rejected(
    "finalizer accepts a rerun before dispatch intent authentication",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        'test "${FINALIZER_RUN_ATTEMPT}" = "1"',
        "true",
    ),
    "enterprise evidence finalizer validate-capture normalized job contract changed",
)
assert_rejected(
    "finalizer skips dispatch intent archive digest verification",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        'test "$(sha256sum "${intent_partial}" | cut -d\' \' -f1)" = "${intent_artifact_digest#sha256:}"',
        "true",
    ),
    "enterprise evidence finalizer validate-capture normalized job contract changed",
)
assert_rejected(
    "finalizer permits multiple dispatch intent archive members",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        "if len(infos) != 1:",
        "if False:",
    ),
    "validate-capture normalized job contract changed",
)
assert_rejected(
    "finalizer accepts a mismatched dispatch intent nonce",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        'test "$(jq -r \'.dispatch_nonce\' <<< "${intent}")" = "${DISPATCH_NONCE}"',
        "true",
    ),
    "enterprise evidence finalizer validate-capture normalized job contract changed",
)
assert_rejected(
    "finalizer authenticated intent upload loses attempt binding",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Upload authenticated finalizer dispatch intent",
        "authenticated-finalizer-intent-${{ github.run_id }}-${{ github.run_attempt }}",
        "authenticated-finalizer-intent-${{ github.run_id }}",
    ),
    "validate-capture normalized job contract changed",
)
assert_rejected(
    "finalizer capture completion poll returns to thirty seconds",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        "for _ in $(seq 1 120); do",
        "for _ in $(seq 1 30); do",
    ),
    "does not bind exact workflow",
)
assert_rejected(
    "finalizer gains write permission",
    "enterprise-evidence-finalizer.yml",
    replace_once("  actions: read\n", "  actions: write\n"),
    "Actions write permission escapes its exact trusted dispatcher declarations",
)
assert_rejected(
    "finalizer checkout injection",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "    steps:\n",
        "    steps:\n      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5\n",
    ),
    "action inventory changed",
)
assert_rejected(
    "finalizer run actor treated as owner",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        'test "${FINALIZER_ACTOR}" = "github-actions[bot]"',
        'test "${FINALIZER_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"',
    ),
    "does not bind exact workflow",
)
assert_rejected(
    "validation receives signing seed",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "      GH_TOKEN: ${{ github.token }}\n",
        "      CANARY: ${{ secrets.CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX }}\n      GH_TOKEN: ${{ github.token }}\n",
    ),
    "validation receives a signing secret",
)
assert_rejected(
    "finalizer seed secret drift",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "${{ secrets.CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX }}",
        "${{ secrets.CHIO_ENTERPRISE_CANARY_SIGNING_SEED }}",
    ),
    "secret inventory changed",
)
assert_rejected(
    "finalizer signing environment removed",
    "enterprise-evidence-finalizer.yml",
    replace_once("    environment: enterprise-evidence-signing\n", ""),
    "signing job protection changed",
)
assert_rejected(
    "finalizer source concurrency weakened",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "group: enterprise-security-source-${{ needs.validate-capture.outputs.source_sha }}",
        "group: enterprise-security-${{ github.ref }}",
    ),
    "signing job protection changed",
)
assert_rejected(
    "finalizer artifact selection regresses to a global rerun singleton",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        '          attempt_artifacts="$(\n',
        '          test "$(jq -r \'length\' <<< "${artifacts}")" = "1"\n'
        '          attempt_artifacts="$(\n',
    ),
    "global artifact singleton across rerun attempts",
)
assert_rejected(
    "finalizer artifact attempt name binding removed",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        ".name == $artifact_name and",
        "true and",
    ),
    "validate-capture normalized job contract changed",
)
assert_rejected(
    "finalizer canary window is computed before protected signing",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "      inventory_digest: ${{ steps.validate.outputs.inventory_digest }}\n",
        "      generated_at_not_before_unix_ms: ${{ steps.revalidate.outputs.generated_at_not_before_unix_ms }}\n"
        "      inventory_digest: ${{ steps.validate.outputs.inventory_digest }}\n",
    ),
    "computes the canary window before protected signing",
)
for label, step, old, new, error in (
    (
        "finalizer triggering actor unbound",
        "Bind finalizer capture job and artifact identities",
        ".triggering_actor.login",
        ".actor.login",
        "does not bind exact workflow",
    ),
    (
        "capture workflow path unbound",
        "Bind finalizer capture job and artifact identities",
        ".github/workflows/enterprise-linux-capture.yml",
        ".github/workflows/nightly.yml",
        "does not bind exact workflow",
    ),
    (
        "capture artifact run unbound",
        "Bind finalizer capture job and artifact identities",
        ".workflow_run.id",
        ".workflow_run.repository_id",
        "validate-capture normalized job contract changed",
    ),
    (
        "capture artifact freshness widened",
        "Bind finalizer capture job and artifact identities",
        "-le 600",
        "-le 60000",
        "does not bind exact workflow",
    ),
    (
        "capture runner group id weakened",
        "Bind finalizer capture job and artifact identities",
        'test "$(jq -r \'.runner_group_id\' <<< "${capture_job}")" = "0"',
        "true",
        "does not bind exact workflow",
    ),
    (
        "capture runner group name weakened",
        "Bind finalizer capture job and artifact identities",
        'test "$(jq -r \'.runner_group_name\' <<< "${capture_job}")" = "GitHub Actions"',
        "true",
        "does not bind exact workflow",
    ),
    (
        "capture runner labels widened",
        "Bind finalizer capture job and artifact identities",
        'test "${runner_labels}" = \'["ubuntu-24.04"]\'',
        'test "$(jq -r \'index("ubuntu-24.04") != null\' <<< "${runner_labels}")" = "true"',
        "does not bind exact workflow",
    ),
    (
        "capture runner name widened",
        "Bind finalizer capture job and artifact identities",
        '[[ "${runner_name}" =~ ^GitHub\\ Actions\\ [1-9][0-9]*$ ]]',
        '[[ "${runner_name}" =~ ^[[:print:]]+$ ]]',
        "does not bind exact workflow",
    ),
    (
        "artifact digest check removed",
        "Download bounded unsigned capture archive",
        'test "$(sha256sum "${partial}" | cut -d\' \' -f1)" = "${ARTIFACT_DIGEST}"',
        "true",
        "prebind the downloaded artifact",
    ),
    (
        "archive traversal check removed",
        "Safely extract exact bounded capture files",
        "or path.is_absolute()",
        "or False",
        "weakens safe bounded extraction",
    ),
    (
        "archive duplicate check removed",
        "Safely extract exact bounded capture files",
        "or name in observed",
        "or False",
        "weakens safe bounded extraction",
    ),
    (
        "archive regular mode check removed",
        "Safely extract exact bounded capture files",
        "not stat.S_ISREG(mode)",
        "False",
        "weakens safe bounded extraction",
    ),
    (
        "archive size bound removed",
        "Safely extract exact bounded capture files",
        "info.file_size > expected[name]",
        "False",
        "weakens safe bounded extraction",
    ),
    (
        "archive compression ratio removed",
        "Safely extract exact bounded capture files",
        "info.file_size > (info.compress_size * 100) + 1_048_576",
        "False",
        "weakens safe bounded extraction",
    ),
    (
        "canonical summary check removed",
        "Validate canonical fixed-schema capture data",
        "if summary_bytes != canonical_summary:",
        "if False:",
        "weakens fixed-schema validation",
    ),
    (
        "security execution image boundary equality removed",
        "Validate canonical fixed-schema capture data",
        'boundary["image_id"] != summary["security_execution_image"]',
        "False",
        "weakens fixed-schema validation",
    ),
    (
        "security execution seccomp boundary equality removed",
        "Validate canonical fixed-schema capture data",
        'boundary["seccomp_profile_sha256"]',
        'boundary["unbound_seccomp_profile_sha256"]',
        "weakens fixed-schema validation",
    ),
    (
        "security execution trusted tool hash inventory removed",
        "Validate canonical fixed-schema capture data",
        'set(boundary["trusted_file_sha256"]) != expected_trusted_files',
        "False",
        "weakens fixed-schema validation",
    ),
    (
        "capture actor equality removed",
        "Validate canonical fixed-schema capture data",
        'summary["capture_actor"] != os.environ["EXPECTED_CAPTURE_ACTOR"]',
        "False",
        "weakens fixed-schema validation",
    ),
    (
        "capture workflow equality removed",
        "Validate canonical fixed-schema capture data",
        'summary["capture_workflow_id"] != os.environ["EXPECTED_CAPTURE_WORKFLOW_ID"]',
        "False",
        "weakens fixed-schema validation",
    ),
    (
        "capture base ref output binding removed",
        "Validate canonical fixed-schema capture data",
        'summary["base_ref"] != os.environ["EXPECTED_BASE_REF"]',
        "False",
        "weakens fixed-schema validation",
    ),
    (
        "capture repository output binding removed",
        "Validate canonical fixed-schema capture data",
        'summary["source_repository"] != os.environ["EXPECTED_REPOSITORY"]',
        "False",
        "weakens fixed-schema validation",
    ),
    (
        "controller actor output binding removed",
        "Validate canonical fixed-schema capture data",
        'summary["controller_actor"] != os.environ["EXPECTED_CONTROLLER_ACTOR"]',
        "False",
        "weakens fixed-schema validation",
    ),
    (
        "controller workflow identity removed",
        "Revalidate live authorization and issuance freshness",
        'test "${CONTROLLER_WORKFLOW_ID}" = "${expected_controller_workflow_id}"',
        "true",
        "does not revalidate live source",
    ),
    (
        "controller definition blob removed",
        "Revalidate live authorization and issuance freshness",
        'test "${controller_blob_sha}" = "${CONTROLLER_DEFINITION_BLOB}"',
        "true",
        "does not revalidate live source",
    ),
    (
        "live merge parent removed",
        "Revalidate live authorization and issuance freshness",
        ".parents[1].sha",
        ".parents[0].sha",
        "does not revalidate live source",
    ),
    (
        "final source allowlist widened",
        "Revalidate live authorization and issuance freshness",
        '(.status == "added" or .status == "modified")',
        '(.status != "removed")',
        "does not revalidate live source",
    ),
    (
        "final source mode widened",
        "Revalidate live authorization and issuance freshness",
        '.mode == "100644"',
        '.mode == "100755"',
        "does not revalidate live source",
    ),
    (
        "verifier TLS pin removed",
        "Acquire pinned trusted evidence verifier",
        "--proto '=https'",
        "--proto '=all'",
        "hash-pinned verifier",
    ),
    (
        "seed not unset",
        "Create and verify committed migration canary",
        "unset CANARY_SIGNING_SEED_HEX",
        "true",
        "strict three-file canary",
    ),
    (
        "canary binding verification removed",
        "Create and verify committed migration canary",
        '--expected-binding-digest "${binding_digest}"',
        "",
        "strict three-file canary",
    ),
    (
        "signing-time current clock binding removed",
        "Create and verify committed migration canary",
        'signing_now_unix_ms="$(( $(date +%s) * 1000 ))"',
        'signing_now_unix_ms="${CAPTURE_ISSUED_AT_UNIX_MS}"',
        "strict three-file canary",
    ),
    (
        "signing-time capture freshness removed",
        "Create and verify committed migration canary",
        'test "$((signing_now_unix_ms - CAPTURE_ISSUED_AT_UNIX_MS))" -le 14400000',
        "true",
        "strict three-file canary",
    ),
):
    assert_rejected(
        label,
        "enterprise-evidence-finalizer.yml",
        replace_in_named_step(step, old, new),
        error,
    )
assert_rejected(
    "verifier hash variable removed",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Acquire pinned trusted evidence verifier",
        "          VERIFIER_SHA256: ${{ vars.CHIO_ENTERPRISE_EVIDENCE_VERIFIER_SHA256 }}\n",
        "",
    ),
    "verifier inputs changed",
)
assert_rejected(
    "policy reuses a pre-signing canary window",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Publish committed evidence verification policy",
        "${{ steps.sign.outputs.generated_at_not_before_unix_ms }}",
        "${{ needs.validate-capture.outputs.generated_at_not_before_unix_ms }}",
    ),
    "policy does not consume the exact signing-time window",
)
assert_rejected(
    "seed moved to job scope",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "    steps:\n      - name: Acquire pinned trusted evidence verifier\n",
        "    env:\n      CANARY: ${{ secrets.CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX }}\n    steps:\n      - name: Acquire pinned trusted evidence verifier\n",
    ),
    "secret inventory changed",
)
assert_rejected(
    "committed evidence upload widened",
    "enterprise-evidence-finalizer.yml",
    replace_once(
        "          path: ${{ runner.temp }}/committed-enterprise-linux-evidence/\n",
        "          path: ${{ runner.temp }}/\n",
    ),
    "committed evidence upload changed",
)
assert_rejected(
    "finalizer executes Cargo",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Create and verify committed migration canary",
        "          set -euo pipefail\n",
        "          set -euo pipefail\n          cargo run\n",
    ),
    "executes candidate artifacts",
)

assert_rejected(
    "publication omits committed E equality with current captured PR head",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind live committed evidence head and CI definition",
        'test "${COMMITTED_EVIDENCE_SHA}" = "${EVIDENCE_SHA}"',
        "true",
    ),
    "does not bind E to the current PR head",
)
assert_rejected(
    "publication accepts a live PR head different from E",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind live committed evidence head and CI definition",
        'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${EVIDENCE_SHA}"',
        'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${BASE_SHA}"',
    ),
    "does not bind E to the current PR head",
)
assert_rejected(
    "publication checks candidate E out as trusted S",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Checkout exact committed evidence without credentials",
        "          ref: ${{ steps.bind.outputs.evidence_sha }}\n",
        "          ref: ${{ steps.bind.outputs.authorized_source_sha }}\n",
    ),
    "does not isolate committed evidence and trusted checker source",
)
assert_rejected(
    "publication checks trusted S out as candidate E",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Checkout exact authorized checker source without credentials",
        "          ref: ${{ steps.bind.outputs.authorized_source_sha }}\n",
        "          ref: ${{ steps.bind.outputs.evidence_sha }}\n",
    ),
    "does not isolate committed evidence and trusted checker source",
)
assert_rejected(
    "publication skips strict checker from S against E",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Verify committed evidence with exact trusted checker",
        "/usr/bin/python3 authorized-checker/scripts/check-committed-linux-evidence.py",
        "/usr/bin/python3 committed-evidence/scripts/check-committed-linux-evidence.py",
    ),
    "skips the exact trusted checker from S against E",
)
for required_name in CHECKER.EXPECTED_PUBLICATION_REQUIRED_NAMES:
    assert_rejected(
        f"publication omits intended CI job or Actions aggregate: {required_name}",
        "enterprise-evidence-finalizer.yml",
        replace_in_named_step(
            "Authenticate exact successful current CI run",
            f'            "{required_name}"\n',
            "",
        ),
        "omits an intended CI job or Actions aggregate",
    )

for label, old, new in (
    (
        "publication authenticates the wrong CI run",
        "repos/${GITHUB_REPOSITORY}/actions/runs/${ci_run_id}",
        "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}",
    ),
    (
        "publication authenticates the wrong CI head",
        'test "$(jq -r \'.head_sha\' <<< "${ci_run}")" = "${EVIDENCE_SHA}"',
        'test "$(jq -r \'.head_sha\' <<< "${ci_run}")" = "${AUTHORIZED_SOURCE_SHA}"',
    ),
    (
        "publication authenticates the wrong CI workflow",
        'test "$(jq -r \'.workflow_id\' <<< "${ci_run}")" = "${CI_WORKFLOW_ID}"',
        'test "$(jq -r \'.workflow_id\' <<< "${ci_run}")" = "${GITHUB_WORKFLOW_REF}"',
    ),
    (
        "publication authenticates the wrong CI attempt",
        "actions/runs/${ci_run_id}/attempts/${ci_run_attempt}/jobs?filter=all&per_page=100",
        "actions/runs/${ci_run_id}/attempts/${GITHUB_RUN_ATTEMPT}/jobs?filter=all&per_page=100",
    ),
    (
        "publication accepts a source job attached to M instead of E",
        'test "$(jq -r \'.head_sha\' <<< "${required_job}")" = "${EVIDENCE_SHA}"',
        'test "$(jq -r \'.head_sha\' <<< "${required_job}")" = "${MERGE_COMMIT_SHA}"',
    ),
    (
        "publication accepts a source Check Run attached to M instead of E",
        'test "$(jq -r \'.head_sha\' <<< "${check_run}")" = "${EVIDENCE_SHA}"',
        'test "$(jq -r \'.head_sha\' <<< "${check_run}")" = "${MERGE_COMMIT_SHA}"',
    ),
    (
        "publication accepts non-Actions CI check runs",
        'test "$(jq -r \'.app.id\' <<< "${check_run}")" = "15368"',
        'test "$(jq -r \'.app.id\' <<< "${check_run}")" = "15369"',
    ),
):
    assert_rejected(
        label,
        "enterprise-evidence-finalizer.yml",
        replace_in_named_step("Authenticate exact successful current CI run", old, new),
        "does not authenticate the exact CI run",
    )
assert_rejected(
    "publication final live PR rebind accepts a changed head after CI",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Authenticate exact successful current CI run",
        'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${EVIDENCE_SHA}"',
        "true",
    ),
    "does not authenticate the exact CI run",
)
assert_rejected(
    "publication final live PR rebind accepts a changed merge tree after CI",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Authenticate exact successful current CI run",
        'test "$(jq -r \'.tree.sha\' <<< "${merge_commit}")" = "${MERGE_TREE_SHA}"',
        "true",
    ),
    "does not authenticate the exact CI run",
)

assert_added_workflow_rejected(
    "added workflow reuses the protected publisher environment",
    """name: unreviewed publisher
on: workflow_dispatch
jobs:
  publish:
    runs-on: ubuntu-24.04
    environment: security-check-publisher
    steps:
      - run: echo "${{ secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM }}"
""",
    "unreviewed workflow environment",
)
assert_added_workflow_rejected(
    "added workflow computes a protected environment name",
    """name: unreviewed dynamic environment
on: workflow_dispatch
jobs:
  publish:
    runs-on: ubuntu-24.04
    environment: ${{ 'security-check-publisher' }}
    steps:
      - run: true
""",
    "unreviewed workflow environment",
)
assert_added_workflow_rejected(
    "added workflow references the publisher key outside its environment",
    """name: unreviewed key reference
on: workflow_dispatch
jobs:
  publish:
    runs-on: ubuntu-24.04
    steps:
      - env:
          KEY: ${{ secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM }}
        run: true
""",
    "publisher private key reference escapes",
)
assert_added_workflow_rejected(
    "added workflow grants write-all token permissions",
    """name: unreviewed workflow writer
on: workflow_dispatch
permissions: write-all
jobs:
  dispatch:
    runs-on: ubuntu-24.04
    steps:
      - run: true
""",
    "Actions write permission escapes its exact trusted dispatcher declarations",
)
assert_rejected(
    "controller adds another job inheriting Actions write",
    "enterprise-evidence-controller.yml",
    replace_once(
        "jobs:\n  dispatch-isolated-capture:\n",
        "jobs:\n"
        "  hostile-dispatch:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - run: true\n"
        "  dispatch-isolated-capture:\n",
    ),
    "Actions write permission escapes its exact trusted dispatcher jobs",
)
assert_actionlint_config_rejected(
    "actionlint loses the enterprise runner label",
    replace_once(
        "chio-enterprise-security",
        "untrusted-enterprise-runner",
    ),
    "actionlint configuration changed",
)
assert_rejected(
    "controller accepts trusted-definition variable drift",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Authorize exact source and controller context",
        'test "${SECURITY_DEFINITION_SHA}" = "${ENTERPRISE_SECURITY_DEFINITION_SHA}"',
        "true",
    ),
    "enterprise evidence controller does not bind live workflow, PR, merge, and source authorization",
)
assert_rejected(
    "capture accepts trusted-definition variable drift",
    "enterprise-linux-capture.yml",
    replace_in_named_step(
        "Revalidate controller source and merge authorization",
        'test "${INPUT_SECURITY_DEFINITION_SHA}" = "${ENTERPRISE_SECURITY_DEFINITION_SHA}"',
        "true",
    ),
    "isolated capture does not revalidate controller, run, merge, source, and freshness bindings",
)
assert_rejected(
    "finalizer accepts trusted-definition variable drift",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind finalizer capture job and artifact identities",
        'test "${SECURITY_DEFINITION_SHA}" = "${ENTERPRISE_SECURITY_DEFINITION_SHA}"',
        "true",
    ),
    "enterprise evidence finalizer does not bind exact workflow, job, actor, run, artifact, and freshness identities",
)
assert_rejected(
    "workflow-run revoker accepts trusted-definition variable drift",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'test "${running_listener_blob_sha}" = "${authorized_listener_blob_sha}"',
        "true",
    ),
    "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
)
assert_rejected(
    "later-CI revoker substitutes the listener attempt for the completed event attempt",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        "EVENT_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}",
        "EVENT_RUN_ATTEMPT: ${{ github.run_attempt }}",
    ),
    "later-CI revocation binding inputs changed",
)
assert_rejected(
    "later-CI revoker rebinds a failed event attempt to the mutable latest run",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        "actions/runs/${EVENT_RUN_ID}/attempts/${EVENT_RUN_ATTEMPT}",
        "actions/runs/${EVENT_RUN_ID}",
    ),
    "later-CI revocation loses failure-only",
)
assert_rejected(
    "later-CI revoker fetches the listener attempt instead of the completed event attempt",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        "actions/runs/${EVENT_RUN_ID}/attempts/${EVENT_RUN_ATTEMPT}",
        "actions/runs/${EVENT_RUN_ID}/attempts/${LISTENER_RUN_ATTEMPT}",
    ),
    "later-CI revocation loses failure-only",
)
assert_rejected(
    "later-CI revoker stops proving the historical endpoint returned the event attempt",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'test "$(jq -r \'.run_attempt\' <<< "${upstream}")" = "${run_attempt}"',
        "true",
    ),
    "later-CI revocation loses failure-only",
)
assert_rejected(
    "revoker unsubscribes from failed finalizer runs",
    "security-contract-revocation.yml",
    replace_once(
        "    workflows: [CI, Enterprise evidence finalizer]\n",
        "    workflows: [CI]\n",
    ),
    "security check revocation workflow identity changed",
)
assert_rejected(
    "failed-finalizer revoker substitutes the listener attempt for the completed event attempt",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        "EVENT_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}",
        "EVENT_RUN_ATTEMPT: ${{ github.run_attempt }}",
    ),
    "failed-finalizer revocation binding inputs changed",
)
assert_rejected(
    "failed-finalizer revoker rebinds the failed event attempt to the mutable latest run",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        "actions/runs/${EVENT_RUN_ID}/attempts/${EVENT_RUN_ATTEMPT}",
        "actions/runs/${EVENT_RUN_ID}",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revoker fetches the listener attempt instead of the completed event attempt",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        "actions/runs/${EVENT_RUN_ID}/attempts/${EVENT_RUN_ATTEMPT}",
        "actions/runs/${EVENT_RUN_ID}/attempts/${LISTENER_RUN_ATTEMPT}",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revoker stops proving the historical endpoint returned the event attempt",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        'test "$(jq -r \'.run_attempt\' <<< "${upstream}")" = "${run_attempt}"',
        "true",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation accepts a rerun",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        'test "${run_attempt}" = "1"',
        "true",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation accepts a partial job inventory",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        'test "$(jq -r \'length\' <<< "${finalizer_jobs}")" = 4',
        'test "$(jq -r \'length\' <<< "${finalizer_jobs}")" -ge 3',
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation ignores publisher start and failure",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        'test "$(jq -r \'.conclusion // ""\' <<< "${publisher_job}")" != success',
        "true",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation skips authenticated intent digest",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        'test "$(sha256sum "${intent_partial}" | cut -d\' \' -f1)" = "${intent_artifact_digest#sha256:}"',
        "true",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation permits multiple intent members",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        "if len(infos) != 1:",
        "if False:",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation authenticates against mutable current definition",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        "?ref=${historical_security_definition_sha}",
        "?ref=${SECURITY_DEFINITION_SHA}",
    ),
    "failed-finalizer revocation loses workflow, definition, N/E/M/S, or existing-authority binding",
)
assert_rejected(
    "failed-finalizer revocation accepts an Actions mirror as authority",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        "(.app.id | tostring) == $app_id",
        ".app.id == 15368",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation ignores finalizer details URL",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        ".details_url == $details_url",
        "true",
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation accepts duplicate dedicated checks",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        'test "${relevant_count}" -le 1',
        'test "${relevant_count}" -ge 1',
    ),
    "failed-finalizer revocation loses workflow",
)
assert_rejected(
    "failed-finalizer revocation creates a missing authority namespace",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind failed finalizer to existing authority",
        'echo "create_missing=false"',
        'echo "create_missing=true"',
    ),
    "failed-finalizer revocation loses workflow",
)
assert_removed_workflow_rejected(
    "security check revocation workflow is removed",
    "security-contract-revocation.yml",
    "publisher private key reference escapes",
)
assert_rejected(
    "revocation does not enforce the publication freeze",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'test "${LIVE_COMMITTED_EVIDENCE_SHA}" = "0000000000000000000000000000000000000000"',
        "true",
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
assert_rejected(
    "failed-finalizer revocation is blocked by rotated live source authority",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'if test "${REASON}" != "finalizer-failure"; then',
        "if true; then",
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
assert_rejected(
    "revocation permits a non-owner actor",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind frozen manual revocation",
        'test "${REVOKER_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"',
        "true",
    ),
    "manual revocation loses owner, main, or exact M binding",
)
assert_rejected(
    "revocation permits a non-owner rerun actor",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind frozen manual revocation",
        'test "${REVOKER_TRIGGERING_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"',
        "true",
    ),
    "manual revocation loses owner, main, or exact M binding",
)
assert_rejected(
    "manual revocation permits workflow reruns",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind frozen manual revocation",
        'test "${RUN_ATTEMPT}" = "1"',
        "true",
    ),
    "manual revocation loses owner, main, or exact M binding",
)
assert_rejected(
    "revocation permits a candidate workflow ref",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'test "${REVOKER_REF}" = "refs/heads/main"',
        'test "${REVOKER_REF}" = "refs/pull/${PR_NUMBER}/merge"',
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
assert_rejected(
    "failure projector accepts a successful CI run",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'test "${EVENT_CONCLUSION}" != success',
        'test -n "${EVENT_CONCLUSION}"',
    ),
    "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
)
assert_rejected(
    "failure projector ignores the current committed evidence authority",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'test "${COMMITTED_EVIDENCE_SHA}" = "${evidence_sha}"',
        "true",
    ),
    "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
)
assert_rejected(
    "failure projector crosses pull-request heads",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${evidence_sha}"',
        "true",
    ),
    "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
)
assert_rejected(
    "failure projector creates new tombstones after pull-request drift",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        "          create_missing=false\n",
        "          create_missing=true\n",
    ),
    "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
)
assert_rejected(
    "failure projector derives source authority from an App variable",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
        "${{ vars.CHIO_SECURITY_APP_ID }}",
    ),
    "later-CI revocation binding inputs changed",
)
assert_rejected(
    "revocation preserves a successful conclusion",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'conclusion: "failure"',
        'conclusion: "success"',
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
assert_rejected(
    "revocation removes absent-namespace tombstone creation",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'created="$(curl --proto \'=https\' --tlsv1.2 --fail --silent --show-error --request POST',
        'created="$(curl --proto \'=https\' --tlsv1.2 --fail --silent --show-error --request GET',
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
for label, old, new in (
    (
        "revocation tombstone proof accepts a wrong external ID",
        'test "$(jq -r \'.check_runs[0].external_id\' <<< "${verified}")" = "${required_external_id}"',
        'test "$(jq -r \'.check_runs[0].external_id\' <<< "${verified}")" != "${required_external_id}"',
    ),
    (
        "revocation tombstone proof accepts the wrong App",
        ".app.slug == $app_slug)' <<< \"${verified}\"",
        ".app.slug == \"github-actions\")' <<< \"${verified}\"",
    ),
    (
        "revocation tombstone proof accepts the wrong name",
        ".name == $name and .head_sha == $head_sha and .status",
        ".name != $name and .head_sha == $head_sha and .status",
    ),
    (
        "revocation tombstone proof accepts the wrong head",
        ".name == $name and .head_sha == $head_sha and .status",
        ".name == $name and .head_sha != $head_sha and .status",
    ),
    (
        "revocation tombstone proof accepts a queued status",
        '.status == "completed" and .conclusion == "failure"',
        '.status == "queued" and .conclusion == "failure"',
    ),
    (
        "revocation tombstone proof accepts a success conclusion",
        '.status == "completed" and .conclusion == "failure"',
        '.status == "completed" and .conclusion == "success"',
    ),
):
    assert_rejected(
        label,
        "security-contract-revocation.yml",
        replace_in_named_step(
            "Revoke exact Actions mirrors and dedicated App namespace", old, new
        ),
        "security check revocation weakens event, owner, App, binding, or failure verification",
    )
assert_rejected(
    "revocation stops preserving existing external IDs and source metadata",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'test "${verified_metadata}" = "${preserved_metadata}"',
        "true",
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
assert_rejected(
    "revocation drops exact singleton proof",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'test "$(jq -r \'.total_count\' <<< "${verified}")" = "1"',
        "true",
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
assert_rejected(
    "revocation leaves duplicate authority names in the protected namespace",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'target_name="${check_name} / superseded ${check_run_id}"',
        'target_name="${check_name}"',
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
assert_rejected(
    "revocation omits an Actions mirror namespace",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Revoke exact Actions mirrors and dedicated App namespace",
        'normalize_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / Build, lint, test" "${external_id}:actions:build"',
        "true",
    ),
    "security check revocation weakens event, owner, App, binding, or failure verification",
)
assert_rejected(
    "revocation drops workflow-token Checks write",
    "security-contract-revocation.yml",
    replace_in_named_job(
        "revoke-security-contract",
        "      checks: write\n",
        "      checks: read\n",
    ),
    "security check revocation job identity changed",
)
for label, workflow_name, job_name, old, new, expected_error in (
    (
        "publisher changes its M-scoped serialization key",
        "enterprise-evidence-finalizer.yml",
        "publish-security-contract",
        "group: security-check-authority-${{ needs.authorize-security-check-publication.outputs.merge_commit_sha }}",
        "group: security-check-publisher-${{ needs.authorize-security-check-publication.outputs.merge_commit_sha }}",
        "dedicated Security contract publisher identity changed",
    ),
    (
        "publisher cancels an in-flight publisher",
        "enterprise-evidence-finalizer.yml",
        "publish-security-contract",
        "cancel-in-progress: false",
        "cancel-in-progress: true",
        "dedicated Security contract publisher identity changed",
    ),
    (
        "publisher restores single-pending replacement semantics",
        "enterprise-evidence-finalizer.yml",
        "publish-security-contract",
        "      queue: max\n",
        "",
        "dedicated Security contract publisher identity changed",
    ),
    (
        "revoker changes its M-scoped serialization key",
        "security-contract-revocation.yml",
        "revoke-security-contract",
        "group: security-check-authority-${{ needs.bind-revocation.outputs.merge_commit_sha }}",
        "group: security-check-revocation-global",
        "security check revocation job identity changed",
    ),
    (
        "revoker cancels an in-flight revocation",
        "security-contract-revocation.yml",
        "revoke-security-contract",
        "cancel-in-progress: false",
        "cancel-in-progress: true",
        "security check revocation job identity changed",
    ),
    (
        "revoker restores single-pending replacement semantics",
        "security-contract-revocation.yml",
        "revoke-security-contract",
        "      queue: max\n",
        "",
        "security check revocation job identity changed",
    ),
):
    assert_rejected(
        label,
        workflow_name,
        replace_in_named_job(job_name, old, new),
        expected_error,
    )
assert_rejected(
    "revocation step inventory widens",
    "security-contract-revocation.yml",
    replace_in_named_job(
        "revoke-security-contract",
        '          echo "Normalized all five authority namespaces to sticky failure on ${MERGE_COMMIT_SHA}." >> "${GITHUB_STEP_SUMMARY}"\n',
        '          echo "Normalized all five authority namespaces to sticky failure on ${MERGE_COMMIT_SHA}." >> "${GITHUB_STEP_SUMMARY}"\n'
        "      - name: Unsealed postrevocation action\n        run: true\n",
    ),
    "security check revocation step inventory changed",
)
for label, old, new in (
    (
        "signing environment path is renamed",
        "repos/bb-connor/arc/environments/enterprise-evidence-signing \\\n",
        "repos/bb-connor/arc/environments/enterprise-evidence-signing-pr \\\n",
    ),
    (
        "signing environment admits a pull-request branch",
        "  -f name=main \\\n",
        "  -f name='codex/**' \\\n",
    ),
    (
        "signing environment permits administrator bypass",
        "Disable administrator bypass for `enterprise-evidence-signing` in the\n",
        "Permit administrator bypass for `enterprise-evidence-signing` in the\n",
    ),
    (
        "signing seed becomes a repository secret",
        "repository UI. Set only the environment secret\n"
        "`CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX`.",
        "repository UI. Set the repository secret\n"
        "`CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX`.",
    ),
):
    assert_document_rejected(
        label,
        replace_once(old, new),
        "signing environment provisioning contract changed",
    )

for label, old, new in (
    (
        "revocation contract does not freeze future publication",
        "  --body '0000000000000000000000000000000000000000'",
        "  --body '<E>'",
    ),
    (
        "revocation contract disables the App before revoking",
        "Keep the App, installation, publisher environment, and private\n"
        "key available until revocation verifies:",
        "Disable the App, installation, publisher environment, and private\n"
        "key before revocation:",
    ),
    (
        "revocation contract does not fail the authority check",
        "absent namespace receives an exact completed-failure tombstone.",
        "deletes each successful run.\n",
    ),
    (
        "revocation contract permits restoration for the same merge",
        "Never\nrestore authority for the same test merge.",
        "Authority may be restored for the same test merge.",
    ),
    (
        "revocation contract separates publisher and revoker locks",
        "Publication and revocation use the same non-cancelling maximum-queue\n"
        "`security-check-authority-<M>` concurrency group.",
        "Publication and revocation use separate locks.",
    ),
    (
        "revocation contract restores single-pending replacement semantics",
        "Both jobs set `queue: max`,\n"
        "so a later authority mutation cannot replace an earlier pending member.",
        "The latest pending authority mutation replaces older pending work.",
    ),
    (
        "revocation contract permits a successful rerun to restore a tuple",
        "This is deliberately conservative: any completed non-success CI\n"
        "completion for the current `E` and `M` can permanently tombstone\n"
        "that tuple",
        "a later successful rerun restores the tuple",
    ),
    (
        "revocation contract documents the listener attempt instead of the immutable event attempt",
        "Both paths\nbind the immutable `workflow_run.run_attempt` carried by the event, retrieve the\nexact historical attempt endpoint, and require the returned run and attempt\nidentity to match. They never substitute the mutable current-run projection.",
        "Both paths use the listener attempt and current-run projection.",
    ),
    (
        "revocation contract drops all-attempt reconciliation and max-advance fail closure",
        "For every matching run it reads the current\nmaximum attempt, retrieves every exact historical attempt from one through that\nmaximum, and fails closed before GitHub's 1,000-result filtered-search ceiling.",
        "For every matching run it reads only the latest attempt and permits truncated search results.",
    ),
):
    assert_document_rejected(
        label,
        replace_once(old, new),
        "publisher environment provisioning contract changed",
    )

for label, old, new in (
    (
        "definition contract drops the explicit trusted SHA variable",
        "`CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA=B`",
        "the current default branch",
    ),
    (
        "definition contract permits privileged workflow drift",
        "Each authenticates its actual execution head from the Actions run API\n"
        "and requires the workflow blob at that head to equal the blob at `B`.",
        "Privileged workflows use whichever default-branch definition is current.",
    ),
    (
        "definition contract does not pin the reusable workflow to B",
        "The `ci.yml` caller must separately pin\n"
        "the reusable workflow to the same immutable full `B` SHA.",
        "The reusable workflow may use a branch ref.",
    ),
    (
        "definition contract moves the public App ID out of repository scope",
        "Also set\n`CHIO_SECURITY_APP_ID` as a repository variable.",
        "Set `CHIO_SECURITY_APP_ID` only in the protected publisher environment.",
    ),
):
    assert_document_rejected(
        label,
        replace_once(old, new),
        "trusted security definition variable contract changed",
    )

for label, old, new in (
    (
        "publisher environment moves its installation ID to repository scope",
        "Set only the environment variable `CHIO_SECURITY_APP_INSTALLATION_ID` and\n"
        "the environment secret `CHIO_SECURITY_APP_PRIVATE_KEY_PEM`.",
        "Set the repository variable `CHIO_SECURITY_APP_INSTALLATION_ID` and\n"
        "the environment secret `CHIO_SECURITY_APP_PRIVATE_KEY_PEM`.",
    ),
    (
        "publisher environment shadows the repository App ID",
        "Keep\n`CHIO_SECURITY_APP_ID` at repository scope and do not shadow it with an\n"
        "environment variable.",
        "Copy `CHIO_SECURITY_APP_ID` into the publisher environment.",
    ),
):
    assert_document_rejected(
        label,
        replace_once(old, new),
        "publisher environment provisioning contract changed",
    )

for label, old, new in (
    (
        "ruleset reuses the colliding source Build context",
        '{context: "Security mirror / Build, lint, test", integration_id: 15368}',
        '{context: "Build, lint, test", integration_id: 15368}',
    ),
    (
        "ruleset leaves MSRV mirror integration unbound",
        '{context: "Security mirror / MSRV build and test", integration_id: 15368}',
        '{context: "Security mirror / MSRV build and test"}',
    ),
    (
        "ruleset leaves the dedicated authority integration unbound",
        '{context: "Security contract", integration_id: $security_app_id}',
        '{context: "Security contract"}',
    ),
):
    assert_document_rejected(
        label,
        replace_once(old, new),
        "publisher environment provisioning contract changed",
    )

assert_rejected(
    "publisher private key leaks into authorization",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind live committed evidence head and CI definition",
        "          AUTHORIZED_SOURCE_SHA: ${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}\n",
        "          AUTHORIZED_SOURCE_SHA: ${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}\n"
        "          PUBLISHER_PRIVATE_KEY_COPY: ${{ secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM }}\n",
    ),
    "publisher private key reference escapes",
)
assert_rejected(
    "publisher mirrors use an untrusted token",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "          GH_TOKEN: ${{ github.token }}\n",
        "          GH_TOKEN: ${{ vars.CHIO_UNTRUSTED_TOKEN }}\n",
    ),
    "publisher App variables or sealed inputs changed",
)
assert_rejected(
    "publisher reuses an original CI name and collides with the source check",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        '["Security mirror / Build, lint, test", "build", "Build, lint, test", .ci.required_check_run_ids.build]',
        '["Build, lint, test", "build", "Build, lint, test", .ci.required_check_run_ids.build]',
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
for label, old, new in (
    (
        "publisher uses the wrong App ID variable",
        "${{ vars.CHIO_SECURITY_APP_ID }}",
        "${{ vars.CHIO_SECURITY_APP_ID_UNTRUSTED }}",
    ),
    (
        "publisher uses the wrong App installation variable",
        "${{ vars.CHIO_SECURITY_APP_INSTALLATION_ID }}",
        "${{ vars.CHIO_SECURITY_APP_INSTALLATION_ID_UNTRUSTED }}",
    ),
):
    assert_rejected(
        label,
        "enterprise-evidence-finalizer.yml",
        replace_in_named_step("Reconcile exact five-context merge authority", old, new),
        "publisher App variables or sealed inputs changed",
    )
assert_rejected(
    "publisher accepts GitHub Actions App ID 15368",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'test "${SECURITY_APP_ID}" != "15368"',
        'test "${SECURITY_APP_ID}" = "15368"',
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
for label, old, new in (
    (
        "publisher ignores older revoked authority checks",
        "check_name=Security%20contract&filter=all&per_page=100",
        "check_name=Security%20contract&filter=latest&per_page=100",
    ),
    (
        "publisher permits duplicate authority checks",
        'test "${existing_authority_match_count}" -le 1',
        "true",
    ),
    (
        "publisher accepts another tuple in the same ruleset namespace",
        'test "$(jq -r \'.[0].external_id\' <<< "${existing_authority_matches}")" = "${EXTERNAL_ID}"',
        "true",
    ),
    (
        "publisher replaces a sticky revoked check",
        'test "$(jq -r \'.[0].conclusion\' <<< "${existing_authority_matches}")" = "success"',
        "true",
    ),
    (
        "publisher fails to reuse an identical successful check",
        'check_run="$(jq -cS \'.[0]\' <<< "${existing_authority_matches}")"',
        'check_run=""',
    ),
):
    assert_rejected(
        label,
        "enterprise-evidence-finalizer.yml",
        replace_in_named_step("Reconcile exact five-context merge authority", old, new),
        "weakens App, main-ref, binding, or check payload authentication",
    )
assert_rejected(
    "publisher attempts to restore a revoked namespace member",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "          unset installation_token\n",
        '          curl --request PATCH "https://api.github.com/repos/${GITHUB_REPOSITORY}/check-runs/${check_run_id}"\n'
        "          unset installation_token\n",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher drops under-lock bad-CI conclusion authentication",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if test "${attempt_conclusion}" != success; then',
        'if test "${attempt_conclusion}" = failure; then',
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher leaves duplicate authority names in the protected namespace",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'target_name="${check_name} / superseded ${existing_check_id}"',
        'target_name="${check_name}"',
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher disables errexit inheritance inside authenticated paginators",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "shopt -s inherit_errexit",
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher disables the uncapped workflow-run fallback",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if test "${total_count}" -ge 1000; then',
        "if false; then",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publication authorization disables the uncapped workflow-run fallback",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Authenticate exact successful current CI run",
        'if test "${total_count}" -ge 1000; then',
        "if false; then",
    ),
    "security check publication does not authenticate the exact CI run, head, workflow, attempt, and Actions App",
)
assert_rejected(
    "publisher commits a drifting workflow-run enumeration",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if ! matching_ci_runs="$(list_matching_ci_runs)"; then',
        'if matching_ci_runs="$(list_matching_ci_runs)"; then',
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher forgets a failed historical attempt after a later successful rerun",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "for ((run_attempt = 1; run_attempt <= max_attempt; run_attempt++)); do",
        "for ((run_attempt = max_attempt; run_attempt <= max_attempt; run_attempt++)); do",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher replaces immutable attempt history with the mutable latest run",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "actions/runs/${run_id}/attempts/${run_attempt}",
        "actions/runs/${run_id}",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher stops proving each historical response has the requested attempt number",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'test "$(jq -r \'.run_attempt\' <<< "${exact_attempt}")" = "${run_attempt}"',
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher drops conclusion from the maximum-attempt stability fingerprint",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        '{conclusion: (.conclusion // ""), run_attempt: .run_attempt, status: .status}',
        '{run_attempt: .run_attempt, status: .status}',
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher accepts current and exact maximum-attempt divergence during a concurrent rerun",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if test "${current_max_fingerprint}" != "${exact_max_fingerprint}" ||',
        "if false ||",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher misses a concurrent maximum-attempt advance after exact history enumeration",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if test "${stable_max_attempt}" != "${max_attempt}"; then',
        "if false; then",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher ignores a new matching CI run created during the history scan",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if test "${stable_matching_ci_ids}" != "${matching_ci_ids}"; then',
        "if false; then",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher ignores an earlier CI run advancing while later runs are scanned",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if test "${revalidated_fingerprint}" != "${expected_fingerprint}"; then',
        "if false; then",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher accepts retry exhaustion while the maximum attempt keeps advancing",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'test "${scan_stable}" = true',
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher treats an in-progress exact attempt as publishable history",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "scan_incomplete=true",
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher lets an incomplete newer attempt suppress a completed failure",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if test "$(jq -r \'length\' <<< "${scanned_bad_ci_runs}")" -gt 0; then',
        "if false; then",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher deduplicates historical failures by run ID and hides distinct attempts",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        '[.[] | "\\(.id):\\(.run_attempt)"] | unique | length',
        "[.[].id] | unique | length",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher displaced revoker does not reconcile every authority namespace",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'normalize_bad_ci_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / Build, lint, test" "${EXTERNAL_ID}:actions:build"',
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher omits immediate bad-CI revalidation after a success POST",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "            fi\n            require_publishable_ci\n            [[ \"$(jq -r '.id' <<< \"${mirror_check}\")\" =~ ^[1-9][0-9]*$ ]]",
        "            fi\n            [[ \"$(jq -r '.id' <<< \"${mirror_check}\")\" =~ ^[1-9][0-9]*$ ]]",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher late-CI routine can restore success",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'conclusion: "failure"',
        'conclusion: "success"',
    ),
    "late-CI branch is not monotone failure-only",
)
for label, old, new in (
    (
        "publisher App drops ruleset-required commit-status permission",
        'test "$(jq -cS \'.permissions\' <<< "${app}")" = \'{"checks":"write","metadata":"read","statuses":"write"}\'',
        'test "$(jq -cS \'.permissions\' <<< "${app}")" = \'{"checks":"write","metadata":"read"}\'',
    ),
    (
        "publisher accepts excess App permissions",
        'test "$(jq -cS \'.permissions\' <<< "${app}")" = \'{"checks":"write","metadata":"read","statuses":"write"}\'',
        'test "$(jq -cS \'.permissions\' <<< "${app}")" = \'{"checks":"write","contents":"read","metadata":"read","statuses":"write"}\'',
    ),
    (
        "publisher requests legacy commit-status permission",
        'token_request=\'{"permissions":{"checks":"write"}}\'',
        'token_request=\'{"permissions":{"checks":"write","statuses":"write"}}\'',
    ),
    (
        "publisher requests an unauthorized installation token permission",
        'token_request=\'{"permissions":{"checks":"write"}}\'',
        'token_request=\'{"permissions":{"checks":"write","contents":"read"}}\'',
    ),
    (
        "publisher weakens installation token key format",
        '[[ "${installation_token}" =~ ^ghs_[A-Za-z0-9_.-]{16,4096}$ ]]',
        '[[ "${installation_token}" =~ ^[A-Za-z0-9_.-]+$ ]]',
    ),
    (
        "publisher accepts legacy commit-status token permission",
        '\'{"checks":"write"}\'|\'{"checks":"write","metadata":"read"}\') ;;',
        '\'{"checks":"write"}\'|\'{"checks":"write","metadata":"read","statuses":"write"}\') ;;',
    ),
    (
        "publisher accepts excess installation token permissions",
        '\'{"checks":"write"}\'|\'{"checks":"write","metadata":"read"}\') ;;',
        '\'{"checks":"write"}\'|\'{"checks":"write","contents":"read","metadata":"read"}\') ;;',
    ),
    (
        "publisher installation drops ruleset-required commit-status permission",
        'test "$(jq -cS \'.permissions\' <<< "${installation}")" = \'{"checks":"write","metadata":"read","statuses":"write"}\'',
        'test "$(jq -cS \'.permissions\' <<< "${installation}")" = \'{"checks":"write","metadata":"read"}\'',
    ),
    (
        "publisher accepts excess installation permissions",
        'test "$(jq -cS \'.permissions\' <<< "${installation}")" = \'{"checks":"write","metadata":"read","statuses":"write"}\'',
        'test "$(jq -cS \'.permissions\' <<< "${installation}")" = \'{"checks":"write","contents":"read","metadata":"read","statuses":"write"}\'',
    ),
):
    assert_rejected(
        label,
        "enterprise-evidence-finalizer.yml",
        replace_in_named_step("Reconcile exact five-context merge authority", old, new),
        "weakens App, main-ref, binding, or check payload authentication",
    )
assert_rejected(
    "publisher drops the authenticated finalizer attempt URL",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'publication_details_url="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${FINALIZER_RUN_ID}/attempts/${FINALIZER_RUN_ATTEMPT}"',
        'publication_details_url="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${CI_RUN_ID}"',
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher omits a check payload details URL",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "details_url: $details_url",
        "details_url: null",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)

for label, old, new in (
    (
        "publisher payload uses the wrong head SHA",
        "head_sha: $head_sha",
        "head_sha: $authorized_source_sha",
    ),
    (
        "publisher payload uses the wrong check name",
        'name: "Security contract"',
        'name: "Security Contract"',
    ),
    (
        "publisher payload uses the wrong status",
        'status: "completed"',
        'status: "queued"',
    ),
    (
        "publisher payload uses the wrong conclusion",
        'conclusion: "success"',
        'conclusion: "neutral"',
    ),
    (
        "publisher payload uses the wrong external ID",
        "external_id: $external_id",
        "external_id: $head_sha",
    ),
):
    assert_rejected(
        label,
        "enterprise-evidence-finalizer.yml",
        replace_in_named_step("Reconcile exact five-context merge authority", old, new),
        "weakens App, main-ref, binding, or check payload authentication",
    )
assert_rejected(
    "publisher accepts a non-main workflow ref",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'test "${PUBLISHER_REF}" = "refs/heads/main"',
        'test "${PUBLISHER_REF}" = "refs/pull/${PR_NUMBER}/merge"',
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher skips canonical publication binding digest",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'test "$(printf \'%s\' "${canonical_binding}" | sha256sum | cut -d\' \' -f1)" = "${PUBLICATION_BINDING_DIGEST}"',
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher protected wait accepts a changed merge commit",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'test "$(jq -r \'.object.sha\' <<< "${merge_ref}")" = "${merge_commit_sha}"',
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher protected wait accepts a changed merge tree",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'test "$(jq -r \'.tree.sha\' <<< "${merge_commit}")" = "$(jq -r \'.merge_tree_sha\' <<< "${canonical_binding}")"',
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher defines but skips the protected-wait live recheck",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "          publish_success_authority() {\n          require_publishable_ci\n          revalidate_live_publication_head\n",
        "          publish_success_authority() {\n          require_publishable_ci\n          true\n",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publication binding omits capture job identity",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Seal exact publication binding",
        "                  job_id: $capture_job_id,\n",
        "",
    ),
    "weakens its exact publication binding",
)

assert_rejected(
    "publication authorization gains write permission",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_job(
        "authorize-security-check-publication",
        "      checks: read\n",
        "      checks: write\n",
    ),
    "publication authorization job identity changed",
)
assert_rejected(
    "publisher drops workflow Checks write",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_job(
        "publish-security-contract",
        "      checks: write\n",
        "      checks: read\n",
    ),
    "publisher identity changed",
)
assert_rejected(
    "publisher drops protected signing prerequisite",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_job(
        "publish-security-contract",
        "    needs: [authorize-security-check-publication, sign-validated-capture]\n",
        "    needs: [authorize-security-check-publication]\n",
    ),
    "publisher identity changed",
)
assert_rejected(
    "publisher step inventory widened",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_job(
        "publish-security-contract",
        '          echo "Five exact merge-authority contexts published for ${MERGE_COMMIT_SHA}; Security contract check run ${check_run_id}." >> "${GITHUB_STEP_SUMMARY}"\n',
        '          echo "Five exact merge-authority contexts published for ${MERGE_COMMIT_SHA}; Security contract check run ${check_run_id}." >> "${GITHUB_STEP_SUMMARY}"\n'
        "      - name: Unsealed postpublication action\n        run: true\n",
    ),
    "publisher step inventory changed",
)
assert_rejected(
    "publisher normalized job contract drifts outside semantic markers",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        "        env:\n",
        "        shell: bash\n        env:\n",
    ),
    "publish-security-contract normalized job contract changed",
)

assert_rejected(
    "CI drops the exact N/E/B/M run identity",
    "ci.yml",
    replace_once(
        "run-name: CI N=${{ github.event.pull_request.number }} E=${{ github.event.pull_request.head.sha }} B=${{ github.event.pull_request.base.sha }} M=${{ github.sha }}",
        "run-name: CI ${{ github.event.pull_request.number }}",
    ),
    "required CI exact N/E/B/M run name changed",
)
assert_rejected(
    "CI reusable caller drops artifact metadata write",
    "ci.yml",
    replace_in_named_job(
        "enterprise-security-contract",
        "      artifact-metadata: write\n",
        "      artifact-metadata: read\n",
    ),
    "required CI does not call enterprise-hardening at an immutable full SHA",
)
assert_rejected(
    "merge-binding builder drops OIDC write",
    "enterprise-hardening.yml",
    replace_in_named_job(
        "bind-source",
        "      id-token: write\n",
        "      id-token: read\n",
    ),
    "enterprise bind-source job protection changed",
)
assert_rejected(
    "merge-binding attestation action becomes unpinned",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Attest canonical exact merge binding",
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
        "actions/attest@main",
    ),
    "enterprise bind-source step inventory changed",
)
assert_rejected(
    "merge-binding upload action becomes unpinned",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Upload exact binding and attestation bundle",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "actions/upload-artifact@main",
    ),
    "enterprise bind-source step inventory changed",
)
assert_rejected(
    "merge-binding predicate type drifts",
    "enterprise-hardening.yml",
    replace_in_named_step(
        "Attest canonical exact merge binding",
        "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1",
        "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v2",
    ),
    "enterprise bind-source attestation contract changed",
)
assert_rejected(
    "controller trusts the legacy pull-request merge_commit_sha field",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Authorize exact source and controller context",
        'merge_commit_sha="$(jq -r \'.object.sha\' <<< "${merge_ref}")"',
        'merge_commit_sha="$(jq -r \'.merge_commit_sha\' <<< "${live_pr}")"',
    ),
    "trusts the mutable pull-request merge_commit_sha field",
)
assert_rejected(
    "controller requires its runtime commit to equal the definition baseline",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Authorize exact source and controller context",
        'test "${running_controller_blob_sha}" = "${controller_blob_sha}"',
        'test "${CONTROLLER_SHA}" = "${SECURITY_DEFINITION_SHA}"',
    ),
    "does not bind live workflow, PR, merge, and source authorization",
)
assert_rejected(
    "controller drops the final explicit merge-ref race check",
    "enterprise-evidence-controller.yml",
    replace_in_named_step(
        "Authorize exact source and controller context",
        'test "$(jq -r \'.object.sha\' <<< "${stable_merge_ref}")" = "${merge_commit_sha}"',
        "true",
    ),
    "does not bind live workflow, PR, merge, and source authorization",
)
assert_rejected(
    "publication does not authenticate the CI workflow blob at M",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Bind live committed evidence head and CI definition",
        'test "${merge_ci_blob}" = "${source_ci_blob}"',
        "true",
    ),
    "does not bind E to the current PR head and exact CI definition",
)
assert_rejected(
    "publisher late-CI reconciler creates missing tombstones after PR drift",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'if test "${bad_ci_create_missing}" = false; then',
        "if false; then",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher late-CI reconciler ignores explicit merge-ref drift",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'test "$(jq -r \'.object.sha\' <<< "${live_bad_ci_merge_ref}")" = "${MERGE_COMMIT_SHA}"',
        "true",
    ),
    "weakens App, main-ref, binding, or check payload authentication",
)
assert_rejected(
    "publisher late-CI tombstone POST drops immediate live revalidation",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Reconcile exact five-context merge authority",
        'revalidate_live_publication_head\n              failed_check="$(curl',
        'true\n              failed_check="$(curl',
    ),
    "late-CI branch is not monotone failure-only",
)
assert_rejected(
    "publication trusts nested workflow-run pull-request metadata",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Authenticate exact successful current CI run",
        ".head_repository.full_name == $repository",
        "(.pull_requests[0].number | tostring) == $pr_number",
    ),
    "trusts mutable Actions run pull-request metadata",
)
assert_rejected(
    "publication consults the legacy live pull-request merge_commit_sha field",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Authenticate exact successful current CI run",
        'test "$(jq -r \'.state\' <<< "${live_pr}")" = "open"',
        'legacy_merge_commit_sha="$(jq -r \'.merge_commit_sha\' <<< "${live_pr}")"\n'
        '          test "$(jq -r \'.state\' <<< "${live_pr}")" = "open"',
    ),
    "trusts mutable Actions run pull-request metadata",
)
assert_rejected(
    "publication accepts missing or duplicate merge-binding artifacts",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Verify exact CI merge binding attestation",
        'test "$(jq -r \'length\' <<< "${matches}")" = 1',
        'test "$(jq -r \'length\' <<< "${matches}")" -ge 1',
    ),
    "does not verify one exact trusted merge-binding attestation",
)
assert_rejected(
    "publication accepts multiple attestations in the signed bundle",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Verify exact CI merge binding attestation",
        'test "$(jq -cs \'length\' "${bundle_file}")" = 1',
        'test "$(jq -cs \'length\' "${bundle_file}")" -ge 1',
    ),
    "does not verify one exact trusted merge-binding attestation",
)

for label, old, new in (
    (
        "publication verifier uses the wrong predicate",
        '--predicate-type "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1"',
        '--predicate-type "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v2"',
    ),
    (
        "publication verifier uses the wrong signer workflow",
        '--signer-workflow "bb-connor/arc/.github/workflows/enterprise-hardening.yml"',
        '--signer-workflow "bb-connor/arc/.github/workflows/ci.yml"',
    ),
    (
        "publication verifier uses the wrong signer digest",
        '--signer-digest "${SECURITY_DEFINITION_SHA}"',
        '--signer-digest "${MERGE_COMMIT_SHA}"',
    ),
    (
        "publication verifier uses the wrong source digest",
        '--source-digest "${MERGE_COMMIT_SHA}"',
        '--source-digest "${EVIDENCE_SHA}"',
    ),
    (
        "publication verifier uses the wrong source ref",
        '--source-ref "refs/pull/${PR_NUMBER}/merge"',
        '--source-ref "refs/heads/main"',
    ),
    (
        "publication verifier permits a self-hosted signer",
        "--deny-self-hosted-runners",
        "--allow-self-hosted-runners",
    ),
    (
        "publication accepts the wrong attested subject digest",
        'test "$(jq -r \'.subject[0].digest.sha256\' <<< "${statement}")" = "${binding_sha256}"',
        'test "$(jq -r \'.subject[0].digest.sha256\' <<< "${statement}")" = "${archive_sha256}"',
    ),
    (
        "publication accepts the wrong certificate signer",
        'test "$(jq -r \'.subjectAlternativeName\' <<< "${certificate}")" = "${signer_uri}"',
        'test "$(jq -r \'.subjectAlternativeName\' <<< "${certificate}")" = "${caller_uri}"',
    ),
    (
        "publication accepts the wrong signer certificate digest",
        'test "$(jq -r \'.buildSignerDigest\' <<< "${certificate}")" = "${SECURITY_DEFINITION_SHA}"',
        'test "$(jq -r \'.buildSignerDigest\' <<< "${certificate}")" = "${MERGE_COMMIT_SHA}"',
    ),
    (
        "publication accepts a self-hosted certificate",
        'test "$(jq -r \'.runnerEnvironment\' <<< "${certificate}")" = github-hosted',
        'test "$(jq -r \'.runnerEnvironment\' <<< "${certificate}")" = self-hosted',
    ),
    (
        "publication accepts the wrong certificate source ref",
        'test "$(jq -r \'.sourceRepositoryRef\' <<< "${certificate}")" = "refs/pull/${PR_NUMBER}/merge"',
        'test "$(jq -r \'.sourceRepositoryRef\' <<< "${certificate}")" = refs/heads/main',
    ),
    (
        "publication accepts the wrong signing run invocation",
        'test "$(jq -r \'.runInvocationURI\' <<< "${certificate}")" = "https://github.com/${GITHUB_REPOSITORY}/actions/runs/${CI_RUN_ID}/attempts/${CI_RUN_ATTEMPT}"',
        'test "$(jq -r \'.runInvocationURI\' <<< "${certificate}")" = "https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}"',
    ),
    (
        "publication accepts an unrecognized verified timestamp type",
        '(.type == "Tlog" or .type == "TimestampAuthority")',
        '(.type == "Tlog" or .type == "Unknown")',
    ),
    (
        "publication accepts timestamps before artifact creation",
        'test "${timestamp_epoch}" -ge "$((created_epoch - 300))"',
        'test "${timestamp_epoch}" -ge 0',
    ),
):
    assert_rejected(
        label,
        "enterprise-evidence-finalizer.yml",
        replace_in_named_step("Verify exact CI merge binding attestation", old, new),
        "does not verify one exact trusted merge-binding attestation",
    )

assert_rejected(
    "publication downloads an unpinned GitHub CLI verifier",
    "enterprise-evidence-finalizer.yml",
    replace_in_named_step(
        "Verify exact CI merge binding attestation",
        "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60",
        "0" * 64,
    ),
    "does not verify one exact trusted merge-binding attestation",
)
assert_rejected(
    "revoker loses null-conclusion normalization",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'upstream_conclusion="$(jq -r \'.conclusion // ""\' <<< "${upstream}")"',
        'upstream_conclusion="$(jq -r \'.conclusion\' <<< "${upstream}")"',
    ),
    "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
)
assert_rejected(
    "revoker leaves the event-side null conclusion implicit",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        "${{ github.event.workflow_run.conclusion || '' }}",
        "${{ github.event.workflow_run.conclusion }}",
    ),
    "later-CI revocation binding inputs changed",
)
assert_rejected(
    "revoker trusts nested workflow-run pull-request metadata",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'test "$(jq -r \'.head_repository.full_name\' <<< "${upstream}")" = "${GITHUB_REPOSITORY}"',
        'test "$(jq -r \'.pull_requests[0].number\' <<< "${upstream}")" = "${pr_number}"',
    ),
    "later-CI revocation trusts mutable workflow-run pull-request metadata",
)
assert_rejected(
    "revoker accepts duplicate merge-binding artifacts",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'test "${artifact_count}" = 1',
        'test "${artifact_count}" -ge 1',
    ),
    "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
)
assert_rejected(
    "revoker accepts multiple attestations in the signed bundle",
    "security-contract-revocation.yml",
    replace_in_named_step(
        "Bind later failed CI rerun to existing authority",
        'test "$(jq -cs \'length\' "${bundle_file}")" = 1',
        'test "$(jq -cs \'length\' "${bundle_file}")" -ge 1',
    ),
    "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
)
assert_rejected(
    "revocation listener ignores a completed null or unknown non-success",
    "security-contract-revocation.yml",
    replace_in_named_job(
        "bind-revocation",
        "github.event.workflow_run.conclusion != 'success'",
        "contains(fromJSON('[\"failure\",\"cancelled\",\"timed_out\"]'), github.event.workflow_run.conclusion)",
    ),
    "security check revocation binder identity changed",
)

base_entries = [
    (regular_zip_info(name, 0o600 if index % 2 == 0 else 0o644), b"ok\n")
    for index, name in enumerate(EXTRACTION_NAMES)
]
run_extraction_fixture("real-style regular ZIP", base_entries, accepted=True)
run_extraction_fixture(
    "traversal",
    [(regular_zip_info("../runner-contract.log"), b"x")] + base_entries[:-1],
    accepted=False,
)
run_extraction_fixture(
    "duplicate",
    base_entries[:-1] + [(regular_zip_info(EXTRACTION_NAMES[0]), b"duplicate")],
    accepted=False,
)
symlink_entries = list(base_entries)
symlink = zipfile.ZipInfo(EXTRACTION_NAMES[1])
symlink.create_system = 3
symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
symlink_entries[1] = (symlink, b"target")
run_extraction_fixture("symlink", symlink_entries, accepted=False)
fifo_entries = list(base_entries)
fifo = zipfile.ZipInfo(EXTRACTION_NAMES[2])
fifo.create_system = 3
fifo.external_attr = (stat.S_IFIFO | 0o600) << 16
fifo_entries[2] = (fifo, b"fifo")
run_extraction_fixture("nonregular", fifo_entries, accepted=False)
run_extraction_fixture(
    "encrypted flag", base_entries, accepted=False, encrypted_index=0
)
run_extraction_fixture(
    "member count", base_entries + [(regular_zip_info("extra"), b"x")], accepted=False
)
oversized = list(base_entries)
oversized[0] = (regular_zip_info(EXTRACTION_NAMES[0]), b"x" * 16_385)
run_extraction_fixture("individual size", oversized, accepted=False)
total_entries = [
    (regular_zip_info(name), b"x" * (10_000_000 if name.endswith(".log") else 1))
    for name in EXTRACTION_NAMES
]
run_extraction_fixture("total size", total_entries, accepted=False)
ratio_entries = list(base_entries)
ratio_info = regular_zip_info(EXTRACTION_NAMES[1])
ratio_info.compress_type = zipfile.ZIP_DEFLATED
ratio_entries[1] = (ratio_info, b"0" * 2_000_000)
run_extraction_fixture("compression ratio", ratio_entries, accepted=False)

assert_rejected(
    "Apalache reusable entrypoint removed",
    "apalache-safety.yml",
    replace_once("  workflow_call:\n", ""),
    "must be callable, manual, and scheduled",
)
assert_rejected(
    "Apalache model removed",
    "apalache-safety.yml",
    replace_once(
        "formal/tla/MCDelegationDepthBound.cfg|formal/tla/DelegationDepthBound.tla\n",
        "",
    ),
    "omits the exact seven-model matrix",
)
assert_rejected(
    "Apalache negative ratchet removed",
    "apalache-safety.yml",
    replace_once('          grep -Fq "The outcome is: Error" "${negative_log}"\n', ""),
    "omits its negative mutation ratchet",
)
assert_rejected(
    "threat gate removed",
    "threat-model-coverage.yml",
    replace_once(
        "        run: bash scripts/check-threat-coverage.sh\n", "        run: true\n"
    ),
    "omits exact gate command",
)
assert_rejected(
    "admin audit head SHA used",
    "admin-override-audit.yml",
    replace_once(
        "CHECK_SHA: ${{ github.event.pull_request.merge_commit_sha || github.sha }}",
        "CHECK_SHA: ${{ github.event.pull_request.head.sha || github.sha }}",
    ),
    "not bound to the protected test merge",
)

print("security CI contract rejects trust-boundary and evidence mutations")
