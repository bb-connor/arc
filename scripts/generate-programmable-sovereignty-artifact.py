#!/usr/bin/env python3
"""Generate and validate the bilateral-admission paper artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
PAPER_PREFIX = "docs/papers/programmable-sovereignty/"
PAPER = REPO / PAPER_PREFIX
SUPPLEMENTARY = PAPER / "supplementary"
SOURCE_COMMIT_FILE = SUPPLEMENTARY / "source-commit.txt"
MANIFEST_FILE = SUPPLEMENTARY / "artifact-manifest.json"
LEDGER_FILE = PAPER / "CLAIM_LEDGER.md"
TITLE = "Receiver-Owned Bilateral Admission for Cross-Organization Agent Tool Calls"
TARGET = "USENIX Security 2027 Cycle 1"

LEDGER_BEGIN = "<!-- BEGIN GENERATED MEASUREMENTS -->"
LEDGER_END = "<!-- END GENERATED MEASUREMENTS -->"

RESULT_PREFIX = PAPER_PREFIX + "bench/results/"
BILATERAL_SCRIPT = PAPER_PREFIX + "bench/run-bilateral-admission.sh"
REPLAY_SCRIPT = PAPER_PREFIX + "bench/run-replay-corpus.sh"
BILATERAL_SUMMARY = RESULT_PREFIX + "bilateral-admission.json"
BILATERAL_INLINE = RESULT_PREFIX + "bilateral-admission-inline.tex"
BILATERAL_ENVIRONMENT = RESULT_PREFIX + "bilateral-admission-environment.json"
SUSTAINED_SUMMARY = RESULT_PREFIX + "bilateral-admission-sustained-load.json"
REPLAY_INLINE = RESULT_PREFIX + "replay-corpus-inline.tex"
SUBMISSION_PDF = PAPER_PREFIX + "paper-usenix.pdf"

CRITERION_CASES = [
    "receipt_sign",
    "receipt_verify",
    "receipt_append_sqlite",
    "treaty_predispatch_deny",
    "treaty_predispatch_allow",
    "strict_bilateral_dsse_verify",
    "cross_boundary_admission_allow",
    "buyer_proof_package_verify",
]
PER_INVOCATION_CASES = [
    "treaty_predispatch_deny",
    "treaty_predispatch_allow",
    "receipt_append_sqlite",
]

THEOREMS = [
    {
        "id": "PS-F01",
        "name": "finite_refinement_sound",
        "module": "Chio.Treaty.ReceiptPredicate",
        "declaration": (
            "Chio.Treaty.ReceiptPredicate.finite_refinement_sound"
        ),
        "path": "formal/lean4/Chio/Chio/Treaty/ReceiptPredicate.lean",
        "axioms": ["propext", "Quot.sound"],
        "claimClass": "bounded_theorem",
        "scope": (
            "A successful check preserves the current admission result for "
            "every receipt in the supplied finite domain."
        ),
    },
    {
        "id": "PS-F02",
        "name": "finite_refinement_exact",
        "module": "Chio.Treaty.ReceiptPredicate",
        "declaration": (
            "Chio.Treaty.ReceiptPredicate.finite_refinement_exact"
        ),
        "path": "formal/lean4/Chio/Chio/Treaty/ReceiptPredicate.lean",
        "axioms": ["propext", "Quot.sound"],
        "claimClass": "bounded_theorem",
        "scope": (
            "The Boolean checker is equivalent to the finite-domain "
            "admission implication."
        ),
    },
]

IMPLEMENTATION_SYMBOLS = [
    {
        "id": "PS-I01",
        "name": "ChioRuntimeAdmissionHook",
        "path": "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        "pattern": "pub struct ChioRuntimeAdmissionHook",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-I02",
        "name": "RuntimeAdmissionHook::evaluate",
        "path": "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        "pattern": "fn evaluate(",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-I03",
        "name": "verify_chio_bilateral_invocation",
        "path": (
            "crates/trust/chio-federation/src/"
            "bilateral_verifier/cosign.rs"
        ),
        "pattern": "pub fn verify_chio_bilateral_invocation(",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-I04",
        "name": "CrossKernelContinuation",
        "path": "crates/kernel/chio-runtime-core/src/types.rs",
        "pattern": "pub struct CrossKernelContinuation",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-I05",
        "name": "bounded_treaty_receipt_view_from_verified_artifacts",
        "path": "crates/kernel/chio-runtime-core/src/treaty/predicate.rs",
        "pattern": (
            "pub fn bounded_treaty_receipt_view_from_verified_artifacts("
        ),
        "claimClass": "differentially_aligned",
    },
    {
        "id": "PS-I06",
        "name": "run_runtime_loopback_scenario",
        "path": "crates/kernel/chio-runtime-harness/src/lib.rs",
        "pattern": "pub fn run_runtime_loopback_scenario(",
        "claimClass": "executable_demonstration",
    },
    {
        "id": "PS-I07",
        "name": "verify_package",
        "path": "crates/trust/chio-attest-buyer-core/src/report.rs",
        "pattern": "pub fn verify_package(",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-I08",
        "name": "BilateralCoSigningError::code",
        "path": "crates/trust/chio-federation/src/bilateral.rs",
        "pattern": "pub fn code(&self)",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-I09",
        "name": "VerifiedFederationTreatyMaterial",
        "path": "crates/kernel/chio-kernel/src/kernel/verified_treaty.rs",
        "pattern": "pub struct VerifiedFederationTreatyMaterial",
        "claimClass": "runtime_enforced",
    },
]

BEHAVIORAL_TESTS = [
    {
        "id": "PS-T01",
        "command": "cargo test -p chio-formal-diff-tests",
        "claimClass": "differentially_aligned",
    },
    {
        "id": "PS-T02",
        "command": "cargo test -p chio-runtime-core --test runtime_treaty",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-T03",
        "command": "cargo test -p chio-runtime-core --test runtime_admission",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-T04",
        "command": "cargo test -p chio-runtime-core --test runtime_buyer_review",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-T05",
        "command": "cargo test -p chio-runtime-harness",
        "claimClass": "executable_demonstration",
    },
    {
        "id": "PS-T06",
        "command": "cargo test -p chio-federation",
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-T07",
        "command": (
            "bash scripts/check-chio-live-treaty-buyer-closure.sh"
        ),
        "claimClass": "executable_demonstration",
    },
    {
        "id": "PS-T08",
        "command": (
            "cargo test -p chio-kernel -- "
            "federation_cosign chio_runtime durable_admission"
        ),
        "claimClass": "runtime_enforced",
    },
    {
        "id": "PS-T09",
        "command": (
            "cargo test -p chio-conformance "
            "--test c2_bilateral_invocation_partial_verifier "
            "--test b4_bilateral_dsse_signature_slice "
            "--test b4_bilateral_dsse_pae_conformance"
        ),
        "claimClass": "runtime_enforced",
    },
]

BENCHMARKS = [
    {
        "id": "PS-B01",
        "script": BILATERAL_SCRIPT,
        "results": [
            RESULT_PREFIX + "bilateral-admission-raw.csv",
            RESULT_PREFIX + "bilateral-admission-components.csv",
            BILATERAL_SUMMARY,
            BILATERAL_INLINE,
            RESULT_PREFIX + "bilateral-admission-environment.txt",
            BILATERAL_ENVIRONMENT,
            *[
                f"{RESULT_PREFIX}bilateral-admission-{case}-samples.csv"
                for case in PER_INVOCATION_CASES
            ],
            *[
                f"{RESULT_PREFIX}criterion/{case}/{name}"
                for case in CRITERION_CASES
                for name in ("estimates.json", "sample.json")
            ],
        ],
        "summary": BILATERAL_SUMMARY,
    },
    {
        "id": "PS-B02",
        "script": REPLAY_SCRIPT,
        "results": [
            RESULT_PREFIX + "replay-corpus.csv",
            RESULT_PREFIX + "replay-corpus.json",
            REPLAY_INLINE,
        ],
        "summary": RESULT_PREFIX + "replay-corpus.json",
    },
    {
        "id": "PS-B03",
        "script": BILATERAL_SCRIPT,
        "results": [SUSTAINED_SUMMARY],
        "summary": SUSTAINED_SUMMARY,
    },
]

BENCHMARK_INPUT_ROOTS = [
    ".cargo",
    "Cargo.lock",
    "Cargo.toml",
    "crates",
    "examples",
    "formal",
    "rust-toolchain.toml",
    "scripts",
    "sdks",
    "spec",
]

BENCHMARK_INPUT_EXCLUDES = [
    "formal/lean4",
    "formal/theorem-inventory.json",
    "scripts/generate-programmable-sovereignty-artifact.py",
]

CORPORA = {
    "positive": [
        "examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json",
        (
            "examples/chio-3vendor/fixtures/runtime-spine/"
            "runtime-evidence-manifest.json"
        ),
    ],
    "negative": [
        "examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json"
    ],
}

SOURCE_FILES = [
    PAPER_PREFIX + "CLAIM_LEDGER.md",
    PAPER_PREFIX + "README.md",
    PAPER_PREFIX + "paper-usenix.tex",
    SUBMISSION_PDF,
    PAPER_PREFIX + "paper.tex",
    PAPER_PREFIX + "paper.pdf",
    *[
        f"{PAPER_PREFIX}sections/{index:02d}-{name}.tex"
        for index, name in [
            (1, "introduction"),
            (2, "background"),
            (3, "substrate"),
            (4, "model"),
            (5, "implementation"),
            (6, "evaluation"),
            (7, "discussion"),
            (8, "related-work"),
            (9, "limitations"),
            (10, "conclusion"),
        ]
    ],
    PAPER_PREFIX + "figures/admission-hook.tex",
    PAPER_PREFIX + "figures/treaty-handshake.tex",
    "formal/lean4/Chio/Chio/Treaty/ReceiptPredicate.lean",
    "formal/diff-tests/src/spec.rs",
    "formal/diff-tests/src/generators.rs",
    "formal/diff-tests/Cargo.toml",
    "formal/diff-tests/tests/treaty_predicate_diff.rs",
    "crates/kernel/chio-runtime-core/src/admission_hook.rs",
    "crates/kernel/chio-runtime-core/src/treaty.rs",
    "crates/kernel/chio-runtime-core/src/treaty/predicate.rs",
    "crates/kernel/chio-runtime-core/src/types.rs",
    "crates/kernel/chio-runtime-core/benches/cross_boundary_admission.rs",
    (
        "crates/kernel/chio-runtime-core/benches/fixtures/"
        "treaty_admission_fixture.rs"
    ),
    (
        "crates/kernel/chio-runtime-core/benches/fixtures/"
        "treaty_admission_allow_fixture.rs"
    ),
    "crates/kernel/chio-runtime-core/examples/treaty_sustained_load.rs",
    "crates/kernel/chio-kernel/benches/paper_security_components.rs",
    "crates/trust/chio-federation/src/bilateral.rs",
    "crates/trust/chio-federation/src/bilateral_verifier/cosign.rs",
    "crates/trust/chio-attest-buyer-core/src/report.rs",
    "crates/kernel/chio-runtime-harness/src/lib.rs",
    "scripts/check-chio-live-treaty-buyer-closure.sh",
    "scripts/check-chio-treaty-buyer-hero-loop.sh",
    "scripts/check-programmable-sovereignty-artifact.sh",
    "scripts/generate-programmable-sovereignty-artifact.py",
    PAPER_PREFIX + "supplementary/README.md",
    "spec/schemas/chio-federation/v1/"
    "treaty-runtime-negative-fixture-corpus.schema.json",
]

EXCLUDED = [
    {
        "surface": "Lean verification of the Rust runtime",
        "status": "not_claimed",
        "reason": "The evidence is generated differential alignment, not refinement.",
    },
    {
        "surface": "organizational independence of signers",
        "status": "operational_assumption",
        "reason": "Two distinct keys may be controlled by one actor.",
    },
    {
        "surface": "wide-area performance and failure recovery",
        "status": "not_evaluated",
        "reason": "The evaluated path is a deterministic single-host loopback.",
    },
]

ENVIRONMENT_KEYS = {
    "cpuModel": str,
    "cores": int,
    "memoryGiB": (int, float),
    "os": str,
    "rustc": str,
    "cargo": str,
    "loadAverage1m": (int, float),
    "toolchainPin": str,
    "commit": str,
    "worktreeDirty": bool,
}

TEX_SPECIALS = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"artifact generation failed: {message}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_bytes(relative: str) -> bytes:
    path = REPO / relative
    if not path.is_file():
        fail(f"required file missing: {relative}")
    return path.read_bytes()


def hash_entry(relative: str) -> dict[str, str]:
    return {"path": relative, "sha256": sha256_bytes(file_bytes(relative))}


def git_output(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def git_commit_available(commit: str) -> bool:
    return subprocess.run(
        [
            "git",
            "-C",
            str(REPO),
            "cat-file",
            "-e",
            f"{commit}^{{commit}}",
        ],
        check=False,
        capture_output=True,
    ).returncode == 0


def git_show(commit: str, relative: str) -> bytes | None:
    result = subprocess.run(
        ["git", "-C", str(REPO), "show", f"{commit}:{relative}"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def benchmark_by_id(benchmark_id: str) -> dict[str, Any]:
    benchmark = next(
        (item for item in BENCHMARKS if item["id"] == benchmark_id),
        None,
    )
    if benchmark is None:
        fail(f"unknown benchmark ID: {benchmark_id}")
    return benchmark


def benchmark_input_paths(benchmark_id: str) -> list[str]:
    return [*BENCHMARK_INPUT_ROOTS, benchmark_by_id(benchmark_id)["script"]]


def benchmark_input_tree_sha256(benchmark_id: str, commit: str) -> str:
    try:
        tree = subprocess.run(
            [
                "git",
                "-C",
                str(REPO),
                "ls-tree",
                "-r",
                "--full-tree",
                commit,
                "--",
                *benchmark_input_paths(benchmark_id),
            ],
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.CalledProcessError:
        fail(f"benchmark input commit is unavailable: {commit}")
    included_entries = []
    for entry in tree.splitlines(keepends=True):
        _, separator, path_bytes = entry.partition(b"\t")
        if not separator:
            fail(f"malformed benchmark input tree entry for {benchmark_id}")
        path = path_bytes.rstrip(b"\n").decode("utf-8")
        excluded = any(
            path == prefix or path.startswith(f"{prefix}/")
            for prefix in BENCHMARK_INPUT_EXCLUDES
        )
        if not excluded:
            included_entries.append(entry)
    tree = b"".join(included_entries)
    if not tree:
        fail(f"benchmark input tree is empty for {benchmark_id}")
    return sha256_bytes(tree)


def validate_benchmark_result_provenance(
    benchmark: dict[str, Any],
    result: dict[str, Any],
    source_commit: str,
    *,
    require_local_source_object: bool,
) -> list[str]:
    label = benchmark["id"]
    problems: list[str] = []
    if result.get("worktreeDirty") is not False:
        problems.append(f"{label} result was not produced from a clean worktree")
    producer_commit = result.get("commit")
    if (
        not isinstance(producer_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", producer_commit) is None
    ):
        problems.append(f"{label} result commit is not a full SHA")
    recorded_digest = result.get("benchmarkInputTreeSha256")
    if (
        not isinstance(recorded_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", recorded_digest) is None
    ):
        problems.append(f"{label} result lacks a benchmark input tree digest")
    if problems:
        return problems

    producer_available = git_commit_available(producer_commit)
    source_available = git_commit_available(source_commit)
    if require_local_source_object and (
        not producer_available or not source_available
    ):
        return [f"{label} provenance commit is unavailable"]

    if producer_available:
        producer_digest = benchmark_input_tree_sha256(label, producer_commit)
        if producer_digest != recorded_digest:
            problems.append(
                f"{label} result input digest does not match its producer"
            )
    if producer_available and source_available:
        if subprocess.run(
            [
                "git",
                "-C",
                str(REPO),
                "merge-base",
                "--is-ancestor",
                producer_commit,
                source_commit,
            ],
            check=False,
        ).returncode != 0:
            problems.append(
                f"{label} producer is not an ancestor of pinned source"
            )

    comparison_commit = source_commit if source_available else "HEAD"
    source_digest = benchmark_input_tree_sha256(label, comparison_commit)
    if source_digest != recorded_digest:
        problems.append(f"{label} result inputs differ from pinned source")
    return problems


def resolve_source_commit(
    explicit: str | None,
    *,
    require_local_object: bool,
) -> str:
    candidate = explicit
    if candidate is None and SOURCE_COMMIT_FILE.is_file():
        candidate = SOURCE_COMMIT_FILE.read_text().strip()
    if candidate is None:
        candidate = git_output("rev-parse", "HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", candidate) is None:
        fail("source commit is not a full SHA")
    try:
        return git_output("rev-parse", f"{candidate}^{{commit}}")
    except subprocess.CalledProcessError:
        if require_local_object:
            fail("source commit is not available in local repository history")
        return candidate


def snapshot_paths() -> list[str]:
    paths = [
        *SOURCE_FILES,
        *[benchmark["script"] for benchmark in BENCHMARKS],
        *[
            result
            for benchmark in BENCHMARKS
            for result in benchmark["results"]
        ],
        *[
            path
            for corpus_paths in CORPORA.values()
            for path in corpus_paths
        ],
        PAPER_PREFIX + "supplementary/proof-manifest.toml",
        PAPER_PREFIX + "supplementary/theorem-inventory.json",
        PAPER_PREFIX + "supplementary/lean-source.tar.gz",
    ]
    return sorted(set(paths))


def is_pinned_input(relative: str) -> bool:
    """Inputs must match the pinned commit byte for byte.

    The paper's own files (sections, PDFs, ledger, retained results, and the
    generated supplementary files) are content-addressed by the manifest and
    are allowed to land in the commit that follows the pinned source commit.
    The benchmark scripts live under the paper directory but are inputs.
    """
    if any(relative == benchmark["script"] for benchmark in BENCHMARKS):
        return True
    return not relative.startswith(PAPER_PREFIX)


def validate_pinned_snapshot(
    source_commit: str,
    *,
    require_local_object: bool,
) -> list[str]:
    problems: list[str] = []
    commit_available = git_commit_available(source_commit)
    if not commit_available:
        if require_local_object:
            fail("source commit is not available in local repository history")
        return problems

    for relative in snapshot_paths():
        if not is_pinned_input(relative) or not (REPO / relative).is_file():
            continue
        committed = git_show(source_commit, relative)
        if committed is None:
            problems.append(
                f"pinned commit does not contain required file: {relative}"
            )
        elif committed != file_bytes(relative):
            problems.append(
                "working artifact differs from pinned commit at "
                f"{relative}"
            )
    return problems


def toolchain_channel(text: str) -> str:
    match = re.search(r'channel\s*=\s*"([^"]+)"', text)
    if match is None:
        fail("could not parse pinned Rust toolchain")
    return match.group(1)


def load_json(relative: str) -> dict[str, Any]:
    try:
        document = json.loads(file_bytes(relative))
    except json.JSONDecodeError as error:
        fail(f"{relative} is not valid JSON: {error}")
    if not isinstance(document, dict):
        fail(f"{relative} is not a JSON object")
    return document


def validate_environment(environment: Any, origin: str) -> list[str]:
    problems: list[str] = []
    if not isinstance(environment, dict):
        return [f"{origin} is not a JSON object"]
    for key, expected in ENVIRONMENT_KEYS.items():
        value = environment.get(key)
        if value is None or isinstance(value, bool) != (expected is bool):
            problems.append(f"{origin} lacks a valid {key}")
        elif not isinstance(value, expected):
            problems.append(f"{origin} lacks a valid {key}")
    if isinstance(environment.get("cores"), int) and environment["cores"] < 1:
        problems.append(f"{origin} reports fewer than one core")
    if not environment.get("cpuModel"):
        problems.append(f"{origin} has an empty cpuModel")
    return problems


def validate_sustained_load(document: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for key in (
        "seconds",
        "calls",
        "dispatchCount",
        "denials",
        "receiptStoreBytesBefore",
        "receiptStoreBytesAfter",
    ):
        value = document.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            problems.append(f"sustained load result lacks a valid {key}")
    if problems:
        return problems
    if document["seconds"] < 1 or document["calls"] < 1:
        problems.append("sustained load result records no work")
    if document["denials"] != 0:
        problems.append(
            f"sustained load recorded {document['denials']} denials"
        )
    if document["dispatchCount"] != document["calls"]:
        problems.append(
            "sustained load dispatch count does not equal its call count"
        )
    return problems


# ---- Rendering shared by the bench script and the check --------------------


def tex_text(value: str) -> str:
    return "".join(TEX_SPECIALS.get(char, char) for char in value)


def fixed(value: Any, places: int) -> str:
    return f"{float(value):.{places}f}"


def integer(value: Any) -> str:
    return str(int(value))


def grouped_tex(value: int) -> str:
    return f"{int(value):,}".replace(",", "{,}")


def component_index(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    components = document.get("components")
    if not isinstance(components, list):
        fail("bilateral admission results lack a components list")
    return {component["component"]: component for component in components}


def workflow_macros(prefix: str, path: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (f"PS{prefix}PFiftyMs", fixed(path["p50_ms"], 3)),
        (f"PS{prefix}PNinetyNineMs", fixed(path["p99_ms"], 3)),
        (f"PS{prefix}MeanMs", fixed(path["mean_ms"], 3)),
        (f"PS{prefix}StdMs", fixed(path["std_ms"], 3)),
        (f"PS{prefix}CiLowMs", fixed(path["ci_low_ms"], 3)),
        (f"PS{prefix}CiHighMs", fixed(path["ci_high_ms"], 3)),
    ]


def per_invocation_ms_macros(
    prefix: str,
    component: dict[str, Any],
) -> list[tuple[str, str]]:
    return [
        (f"PS{prefix}PFiftyMs", fixed(component["p50_us"] / 1000.0, 3)),
        (f"PS{prefix}PNinetyNineMs", fixed(component["p99_us"] / 1000.0, 3)),
        (f"PS{prefix}PFiftyUs", fixed(component["p50_us"], 3)),
        (f"PS{prefix}PNinetyNineUs", fixed(component["p99_us"], 3)),
        (f"PS{prefix}MeanMs", fixed(component["mean_us"] / 1000.0, 3)),
        (f"PS{prefix}StdMs", fixed(component["std_us"] / 1000.0, 3)),
        (f"PS{prefix}CiLowMs", fixed(component["ci_low_us"] / 1000.0, 3)),
        (f"PS{prefix}CiHighMs", fixed(component["ci_high_us"] / 1000.0, 3)),
        (f"PS{prefix}SampleCount", integer(component["samples"])),
    ]


def batch_mean_macros(
    prefix: str,
    component: dict[str, Any],
) -> list[tuple[str, str]]:
    return [
        (f"PS{prefix}PFiftyUs", fixed(component["p50_us"], 3)),
        (f"PS{prefix}MaxUs", fixed(component["max_us"], 3)),
        (f"PS{prefix}MeanUs", fixed(component["mean_us"], 3)),
        (f"PS{prefix}CiLowUs", fixed(component["ci_low_us"], 3)),
        (f"PS{prefix}CiHighUs", fixed(component["ci_high_us"], 3)),
        (f"PS{prefix}SampleCount", integer(component["samples"])),
    ]


def inline_macros(document: dict[str, Any]) -> list[tuple[str, str]]:
    environment = document["environment"]
    paths = document["paths"]
    components = component_index(document)
    sustained = document["sustainedLoad"]
    negative = document["negativeMatrix"]
    proof_package_bytes = int(document["proofPackageBytes"])
    buyer_workflow = paths["complete_buyer_workflow"]
    producer = paths["producer_without_buyer_review"]
    receipt_append = components["receipt_append_sqlite"]
    return [
        ("PSHostCpuModel", tex_text(environment["cpuModel"])),
        ("PSHostCores", integer(environment["cores"])),
        ("PSHostMemoryGiB", fixed(environment["memoryGiB"], 1)),
        ("PSHostOs", tex_text(environment["os"])),
        ("PSRustcVersion", tex_text(environment["rustc"])),
        ("PSHostLoadAverage", fixed(environment["loadAverage1m"], 2)),
        ("PSPathSampleCount", integer(document["samples"])),
        ("PSCriterionSampleCount", integer(document["criterionSamples"])),
        ("PSWarmupCount", integer(document["warmups"])),
        *workflow_macros("BuyerWorkflow", buyer_workflow),
        ("PSBuyerWorkflowPFiftySec", fixed(buyer_workflow["p50_ms"] / 1000.0, 3)),
        (
            "PSBuyerWorkflowPNinetyNineSec",
            fixed(buyer_workflow["p99_ms"] / 1000.0, 3),
        ),
        *workflow_macros("Producer", producer),
        *per_invocation_ms_macros(
            "PredispatchDeny",
            components["treaty_predispatch_deny"],
        ),
        *per_invocation_ms_macros(
            "PredispatchAllow",
            components["treaty_predispatch_allow"],
        ),
        ("PSReceiptAppendPFiftyUs", fixed(receipt_append["p50_us"], 3)),
        ("PSReceiptAppendPNinetyNineUs", fixed(receipt_append["p99_us"], 3)),
        ("PSReceiptAppendMeanUs", fixed(receipt_append["mean_us"], 3)),
        ("PSReceiptAppendStdUs", fixed(receipt_append["std_us"], 3)),
        ("PSReceiptAppendCiLowUs", fixed(receipt_append["ci_low_us"], 3)),
        ("PSReceiptAppendCiHighUs", fixed(receipt_append["ci_high_us"], 3)),
        ("PSReceiptAppendSampleCount", integer(receipt_append["samples"])),
        *batch_mean_macros("ReceiptSign", components["receipt_sign"]),
        *batch_mean_macros("ReceiptVerify", components["receipt_verify"]),
        *batch_mean_macros(
            "BilateralVerify",
            components["strict_bilateral_dsse_verify"],
        ),
        *batch_mean_macros(
            "CrossBoundary",
            components["cross_boundary_admission_allow"],
        ),
        *batch_mean_macros(
            "BuyerVerify",
            components["buyer_proof_package_verify"],
        ),
        ("PSSustainedSeconds", integer(sustained["seconds"])),
        ("PSSustainedCalls", integer(sustained["calls"])),
        ("PSSustainedCallsPerSecond", fixed(sustained["callsPerSecond"], 1)),
        ("PSSustainedDispatchCount", integer(sustained["dispatchCount"])),
        ("PSSustainedDenials", integer(sustained["denials"])),
        (
            "PSSustainedReceiptStoreGrowthKiB",
            fixed(sustained["receiptStoreGrowthKiB"], 1),
        ),
        ("PSNegativeMatrixSeconds", fixed(negative["elapsedMs"] / 1000.0, 1)),
        ("PSProofPackageBytes", grouped_tex(proof_package_bytes)),
        ("PSProofPackageKiB", fixed(proof_package_bytes / 1024.0, 1)),
        ("PSThreatCaseCount", integer(negative["cases"])),
    ]


def render_inline(document: dict[str, Any]) -> str:
    return "".join(
        f"\\newcommand{{\\{name}}}{{{value}}}\n"
        for name, value in inline_macros(document)
    )


def render_measurements(document: dict[str, Any]) -> str:
    """Render the ledger's generated Measurements region from the result JSON."""
    environment = document["environment"]
    paths = document["paths"]
    components = component_index(document)
    sustained = document["sustainedLoad"]
    deny = components["treaty_predispatch_deny"]
    allow = components["treaty_predispatch_allow"]
    buyer_workflow = paths["complete_buyer_workflow"]
    producer = paths["producer_without_buyer_review"]

    def per_invocation_line(label: str, component: dict[str, Any]) -> str:
        return (
            f"- {label}: {fixed(component['p50_us'] / 1000.0, 3)} ms p50, "
            f"{fixed(component['p99_us'] / 1000.0, 3)} ms p99, "
            f"{fixed(component['mean_us'] / 1000.0, 3)} ms mean "
            f"(95 percent CI {fixed(component['ci_low_us'] / 1000.0, 3)} to "
            f"{fixed(component['ci_high_us'] / 1000.0, 3)} ms) over "
            f"{integer(component['samples'])} invocations."
        )

    lines = [
        (
            f"- Host: {environment['cpuModel']}, "
            f"{integer(environment['cores'])} cores, "
            f"{fixed(environment['memoryGiB'], 1)} GiB, "
            f"{environment['os']}, rustc {environment['rustc']}."
        ),
        (
            f"- Samples: {integer(document['samples'])} runs per workflow path "
            f"after {integer(document['warmups'])} warm-up runs; "
            f"{integer(document['criterionSamples'])} Criterion samples per "
            "component."
        ),
        per_invocation_line("Pre-dispatch treaty denial", deny),
        per_invocation_line("Pre-dispatch treaty allow", allow),
        (
            "- Complete buyer workflow: "
            f"{fixed(buyer_workflow['p50_ms'] / 1000.0, 3)} s p50 and "
            f"{fixed(buyer_workflow['p99_ms'] / 1000.0, 3)} s p99."
        ),
        (
            "- Producer workflow: "
            f"{fixed(producer['p50_ms'] / 1000.0, 3)} s p50 and "
            f"{fixed(producer['p99_ms'] / 1000.0, 3)} s p99."
        ),
        (
            f"- Sustained load: {fixed(sustained['callsPerSecond'], 1)} calls "
            f"per second over {integer(sustained['seconds'])} s with "
            f"{fixed(sustained['receiptStoreGrowthKiB'], 1)} KiB of receipt "
            "store growth."
        ),
        f"- Buyer package: {int(document['proofPackageBytes']):,} bytes.",
        f"- Negative matrix: {integer(document['negativeMatrix']['cases'])} cases.",
    ]
    return "\n".join(lines)


def ledger_region(text: str) -> tuple[int, int]:
    begin = text.find(LEDGER_BEGIN)
    if begin < 0:
        fail(f"claim ledger lacks the marker {LEDGER_BEGIN}")
    start = begin + len(LEDGER_BEGIN)
    end = text.find(LEDGER_END, start)
    if end < 0:
        fail(f"claim ledger lacks the marker {LEDGER_END}")
    return start, end


def ledger_region_body(measurements: str) -> str:
    return "\n" + measurements + "\n"


def write_measurements(document: dict[str, Any], ledger: Path) -> None:
    text = ledger.read_text(encoding="utf-8")
    start, end = ledger_region(text)
    updated = (
        text[:start]
        + ledger_region_body(render_measurements(document))
        + text[end:]
    )
    if updated != text:
        write_output(ledger, updated.encode("utf-8"))


def parse_inline_macros(text: str) -> dict[str, str]:
    macros: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\\newcommand\{\\(PS[A-Za-z]+)\}\{(.*)\}", line)
        if match is None:
            continue
        macros[match.group(1)] = match.group(2)
    return macros


def is_numeric_macro(value: str) -> bool:
    return re.fullmatch(r"[0-9][0-9,.]*", value.replace("{,}", ",")) is not None


def pdf_text(relative: str) -> str | None:
    if shutil.which("pdftotext") is None:
        print(
            f"pdftotext is not installed; skipping the text check of {relative}",
            file=sys.stderr,
        )
        return None
    result = subprocess.run(
        ["pdftotext", str(REPO / relative), "-"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        fail(f"pdftotext failed on {relative}: {result.stderr.strip()}")
    return re.sub(r"\s+", " ", result.stdout)


def consistency_problems() -> list[str]:
    problems: list[str] = []
    results = load_json(BILATERAL_SUMMARY)
    environment_file = load_json(BILATERAL_ENVIRONMENT)
    inline_text = file_bytes(BILATERAL_INLINE).decode("utf-8")
    macros = parse_inline_macros(inline_text)

    problems.extend(validate_environment(environment_file, BILATERAL_ENVIRONMENT))
    problems.extend(
        validate_environment(results.get("environment"), f"{BILATERAL_SUMMARY} environment")
    )
    if problems:
        return problems

    if results["environment"] != environment_file:
        problems.append(
            f"{BILATERAL_SUMMARY} embeds a different environment than "
            f"{BILATERAL_ENVIRONMENT}"
        )

    try:
        expected_inline = render_inline(results)
    except (KeyError, TypeError, ValueError) as error:
        return [*problems, f"{BILATERAL_SUMMARY} cannot render the inline macros: {error!r}"]
    if inline_text != expected_inline:
        problems.append(
            f"{BILATERAL_INLINE} differs from the macros rendered from "
            f"{BILATERAL_SUMMARY}; rerun the benchmark script"
        )

    ledger_text = file_bytes(PAPER_PREFIX + "CLAIM_LEDGER.md").decode("utf-8")
    start, end = ledger_region(ledger_text)
    if ledger_text[start:end] != ledger_region_body(render_measurements(results)):
        problems.append(
            "CLAIM_LEDGER.md generated measurements differ from "
            f"{BILATERAL_SUMMARY}; rerun the benchmark script"
        )

    for key, macro in (
        ("cpuModel", "PSHostCpuModel"),
        ("cores", "PSHostCores"),
        ("memoryGiB", "PSHostMemoryGiB"),
        ("rustc", "PSRustcVersion"),
    ):
        value = environment_file[key]
        if key == "cores":
            expected = integer(value)
        elif key == "memoryGiB":
            expected = fixed(value, 1)
        else:
            expected = tex_text(value)
        if macros.get(macro) != expected:
            problems.append(
                f"{BILATERAL_ENVIRONMENT} {key} ({expected}) does not match "
                f"\\{macro} ({macros.get(macro)})"
            )

    text = pdf_text(SUBMISSION_PDF)
    if text is not None:
        replay_macros = parse_inline_macros(
            file_bytes(REPLAY_INLINE).decode("utf-8")
        )
        missing = [
            f"\\{name}={value}"
            for name, value in [*macros.items(), *replay_macros.items()]
            if is_numeric_macro(value)
            and value.replace("{,}", ",") not in text
        ]
        if missing:
            problems.append(
                f"{SUBMISSION_PDF} does not print these inline macro values: "
                + ", ".join(missing)
            )
    return problems


def validate_inputs(
    source_commit: str,
    *,
    require_local_source_object: bool,
) -> None:
    problems: list[str] = []
    missing: list[str] = []

    def present(relative: str) -> bool:
        if (REPO / relative).is_file():
            return True
        if relative not in missing:
            missing.append(relative)
        return False

    for theorem in THEOREMS:
        if not present(theorem["path"]):
            continue
        text = file_bytes(theorem["path"]).decode("utf-8")
        if re.search(
            rf"\btheorem\s+{re.escape(theorem['name'])}\b",
            text,
        ) is None:
            problems.append(
                f"theorem {theorem['declaration']} missing from "
                f"{theorem['path']}"
            )
    for symbol in IMPLEMENTATION_SYMBOLS:
        if not present(symbol["path"]):
            continue
        text = file_bytes(symbol["path"]).decode("utf-8")
        if symbol["pattern"] not in text:
            problems.append(
                f"symbol {symbol['name']} missing from {symbol['path']}"
            )
    for benchmark in BENCHMARKS:
        present(benchmark["script"])
        for result in benchmark["results"]:
            present(result)
        if not present(benchmark["summary"]):
            continue
        problems.extend(
            validate_benchmark_result_provenance(
                benchmark,
                load_json(benchmark["summary"]),
                source_commit,
                require_local_source_object=require_local_source_object,
            )
        )
    for paths in CORPORA.values():
        for path in paths:
            present(path)
    if present(CORPORA["negative"][0]):
        negative = load_json(CORPORA["negative"][0])
        cases = negative.get("cases", [])
        if len(cases) != 20:
            problems.append("bilateral negative corpus must contain exactly 20 cases")
        threat_ids = [case.get("threatId") for case in cases]
        if len(set(threat_ids)) != len(cases):
            problems.append("bilateral negative corpus contains duplicate threat IDs")
        if any(case.get("dispatchExpected") is not False for case in cases):
            problems.append(
                "every negative corpus case must set dispatchExpected to false"
            )
        assumptions = negative.get("assumptions", [])
        if [item.get("assumptionId") for item in assumptions] != ["PS-A-01"]:
            problems.append("negative corpus must carry the PS-A-01 assumption")
    if present(BILATERAL_SUMMARY):
        results = load_json(BILATERAL_SUMMARY)
        if results.get("profile") != "release":
            problems.append("bilateral admission results are not release-profile")
        if results.get("negativeMatrix", {}).get("cases") != 20:
            problems.append("benchmark summary does not report 20 negative cases")
    if present(SUSTAINED_SUMMARY):
        problems.extend(validate_sustained_load(load_json(SUSTAINED_SUMMARY)))
    for relative in snapshot_paths():
        present(relative)
    problems.extend(
        validate_pinned_snapshot(
            source_commit,
            require_local_object=require_local_source_object,
        )
    )
    problems = [f"required file missing: {path}" for path in missing] + problems
    if not problems:
        problems.extend(consistency_problems())
    if problems:
        fail("\n  ".join(["the artifact is inconsistent:", *problems]))


def generated_at(source_commit: str) -> str:
    if git_commit_available(source_commit):
        return git_output("show", "-s", "--format=%cs", source_commit)
    if MANIFEST_FILE.is_file():
        recorded = load_json(str(MANIFEST_FILE.relative_to(REPO))).get("generatedAt")
        if isinstance(recorded, str) and recorded:
            return recorded
    fail("cannot determine the artifact date: pinned commit and manifest are both unavailable")


def cargo_lock_sha256(source_commit: str) -> str:
    committed = git_show(source_commit, "Cargo.lock")
    if committed is not None:
        return sha256_bytes(committed)
    if MANIFEST_FILE.is_file():
        recorded = (
            load_json(str(MANIFEST_FILE.relative_to(REPO)))
            .get("source", {})
            .get("cargoLockSha256")
        )
        if isinstance(recorded, str) and recorded:
            return recorded
    fail("cannot determine the Cargo.lock digest at the pinned commit")


def pinned_rust_toolchain(*, check: bool) -> str:
    environment = load_json(BILATERAL_ENVIRONMENT)
    recorded = environment.get("toolchainPin")
    if not isinstance(recorded, str) or not recorded:
        fail(f"{BILATERAL_ENVIRONMENT} lacks a toolchainPin")
    if environment.get("rustc") != recorded:
        fail(
            f"{BILATERAL_ENVIRONMENT} rustc {environment.get('rustc')} is not "
            f"the pinned toolchain {recorded}"
        )
    current = toolchain_channel(file_bytes("rust-toolchain.toml").decode())
    if current != recorded:
        if not check:
            fail(
                f"results were produced under Rust {recorded} but "
                f"rust-toolchain.toml pins {current}; rerun the benchmarks"
            )
        print(
            f"note: rust-toolchain.toml pins {current}; the retained results "
            f"were produced under {recorded}",
            file=sys.stderr,
        )
    return recorded


def proof_manifest_bytes(snapshot_date: str) -> bytes:
    lines = [
        "[manifest]",
        'schema = "chio.programmable-sovereignty.proof-manifest.v1"',
        f'generated_at = "{snapshot_date}"',
        f"paper = {json.dumps(TITLE)}",
        f"target_venue = {json.dumps(TARGET)}",
        'lean_toolchain = "leanprover/lean4:v4.28.0"',
        'model_boundary = "bounded receipt predicates and supplied finite domains"',
        'implementation_relation = "independent Rust differential testing, not extraction or refinement"',
        "",
    ]
    for theorem in THEOREMS:
        lines.extend(
            [
                "[[theorems]]",
                f"id = {json.dumps(theorem['id'])}",
                f"name = {json.dumps(theorem['name'])}",
                f"lean_module = {json.dumps(theorem['module'])}",
                f"lean_declaration = {json.dumps(theorem['declaration'])}",
                f"path = {json.dumps(theorem['path'])}",
                f"claim_class = {json.dumps(theorem['claimClass'])}",
                f"axioms = {json.dumps(theorem['axioms'])}",
                f"scope = {json.dumps(theorem['scope'])}",
                "",
            ]
        )
    return ("\n".join(lines).rstrip() + "\n").encode()


def theorem_inventory_bytes(snapshot_date: str) -> bytes:
    document = {
        "schema": "chio.programmable-sovereignty.theorem-inventory.v1",
        "generatedAt": snapshot_date,
        "paper": TITLE,
        "targetVenue": TARGET,
        "leanToolchain": "leanprover/lean4:v4.28.0",
        "modelBoundary": "bounded receipt predicates and supplied finite domains",
        "implementationRelation": (
            "independent Rust differential testing, not extraction or refinement"
        ),
        "theorems": THEOREMS,
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def archive_readme(snapshot_date: str) -> bytes:
    theorem_lines = "\n".join(
        f"#print axioms {theorem['declaration']}" for theorem in THEOREMS
    )
    text = f"""# Chio Lean artifact

Paper: {TITLE}
Snapshot date: {snapshot_date}

Build from this directory:

```sh
lake build
```

The paper claims only bounded model theorems. It does not claim that this
project verifies the Rust runtime.

To reproduce the recorded axiom lists:

```lean
import Chio.Treaty.ReceiptPredicate
{theorem_lines}
```
"""
    return text.encode()


def lean_archive_bytes(snapshot_date: str) -> bytes:
    project = REPO / "formal/lean4/Chio"
    generated_project_files = {
        project / "Chio.lean",
        project / "lakefile.lean",
    }
    project_files = [
        project / "lean-toolchain",
        project / "lake-manifest.json",
        *sorted(
            path
            for path in project.rglob("*.lean")
            if ".lake" not in path.relative_to(project).parts
            and path not in generated_project_files
        ),
    ]
    vendor = REPO / "formal/lean4/vendor/aeneas"
    vendor_files = [
        vendor / "lean-toolchain",
        vendor / "lakefile.lean",
        vendor / "LICENSE.md",
        vendor / "VENDOR.toml",
        vendor / "Aeneas.lean",
        vendor / "AeneasMeta.lean",
        *sorted((vendor / "Aeneas").rglob("*.lean")),
        *sorted((vendor / "AeneasMeta").rglob("*.lean")),
    ]
    for path in [*project_files, *vendor_files]:
        if not path.is_file():
            fail(f"Lean archive input missing: {path.relative_to(REPO)}")

    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=output,
        mtime=0,
    ) as gz_file:
        with tarfile.open(fileobj=gz_file, mode="w") as archive:
            root_info = tarfile.TarInfo("chio-lean")
            root_info.type = tarfile.DIRTYPE
            root_info.mode = 0o755
            root_info.mtime = 0
            root_info.uid = root_info.gid = 0
            root_info.uname = root_info.gname = "root"
            archive.addfile(root_info)

            entries = [
                ("chio-lean/README.md", archive_readme(snapshot_date)),
                (
                    "chio-lean/lakefile.lean",
                    (
                        "import Lake\n"
                        "open Lake DSL\n\n"
                        "package chioPaper where\n"
                        "  leanOptions := #[\n"
                        "    ⟨`autoImplicit, false⟩\n"
                        "  ]\n\n"
                        "@[default_target]\n"
                        "lean_lib Chio where\n"
                        '  srcDir := "."\n'
                    ).encode(),
                ),
                (
                    "chio-lean/Chio.lean",
                    b"import Chio.Treaty.ReceiptPredicate\n",
                ),
                *[
                    (
                        "chio-lean/" + path.relative_to(project).as_posix(),
                        path.read_bytes(),
                    )
                    for path in project_files
                ],
                *[
                    (
                        "vendor/aeneas/" + path.relative_to(vendor).as_posix(),
                        path.read_bytes(),
                    )
                    for path in vendor_files
                ],
            ]
            entry_names = [name for name, _ in entries]
            if len(entry_names) != len(set(entry_names)):
                fail("Lean archive contains duplicate member paths")
            for name, data in sorted(entries):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def manifest_bytes(
    proof_bytes: bytes,
    inventory_bytes: bytes,
    archive_bytes: bytes,
    source_commit: str,
    source_commit_bytes: bytes,
    *,
    snapshot_date: str,
    rust_toolchain: str,
) -> bytes:
    source_hashes = [hash_entry(path) for path in SOURCE_FILES]
    benchmark_entries: list[dict[str, Any]] = []
    for benchmark in BENCHMARKS:
        benchmark_entries.append(
            {
                "id": benchmark["id"],
                "script": hash_entry(benchmark["script"]),
                "results": [hash_entry(path) for path in benchmark["results"]],
                "claimClass": "experimentally_measured",
            }
        )
    corpus_entries = {
        kind: [hash_entry(path) for path in paths]
        for kind, paths in CORPORA.items()
    }
    supplementary_entries = [
        {
            "path": PAPER_PREFIX + "supplementary/source-commit.txt",
            "sha256": sha256_bytes(source_commit_bytes),
        },
        {
            "path": PAPER_PREFIX + "supplementary/proof-manifest.toml",
            "sha256": sha256_bytes(proof_bytes),
        },
        {
            "path": PAPER_PREFIX + "supplementary/theorem-inventory.json",
            "sha256": sha256_bytes(inventory_bytes),
        },
        {
            "path": PAPER_PREFIX + "supplementary/lean-source.tar.gz",
            "sha256": sha256_bytes(archive_bytes),
        },
    ]
    content_items = [
        *source_hashes,
        *[
            benchmark["script"]
            for benchmark in benchmark_entries
        ],
        *[
            result
            for benchmark in benchmark_entries
            for result in benchmark["results"]
        ],
        *[
            corpus
            for corpus_list in corpus_entries.values()
            for corpus in corpus_list
        ],
        *supplementary_entries,
    ]
    content_digest = hashlib.sha256()
    for item in sorted(content_items, key=lambda entry: entry["path"]):
        content_digest.update(item["path"].encode())
        content_digest.update(b"\0")
        content_digest.update(item["sha256"].encode())
        content_digest.update(b"\n")

    document = {
        "schema": "chio.programmable-sovereignty.artifact-manifest.v1",
        "generatedAt": snapshot_date,
        "paper": {
            "title": TITLE,
            "target": TARGET,
            "bodyPageLimit": 13,
            "submissionSource": PAPER_PREFIX + "paper-usenix.tex",
        },
        "source": {
            "commit": source_commit,
            "snapshotMode": (
                "recorded source commit plus self-contained "
                "content-addressed snapshot"
            ),
            "contentSetSha256": content_digest.hexdigest(),
            "cargoLockSha256": cargo_lock_sha256(source_commit),
        },
        "toolchains": {
            "rust": rust_toolchain,
            "lean": file_bytes(
                "formal/lean4/Chio/lean-toolchain"
            ).decode().strip(),
            "tex": "TeX Live 2023 or compatible pdflatex and BibTeX",
        },
        "claimClasses": [
            "runtime_enforced",
            "bounded_theorem",
            "differentially_aligned",
            "experimentally_measured",
            "executable_demonstration",
            "operational_assumption",
        ],
        "theorems": THEOREMS,
        "implementationSymbols": [
            {
                key: value
                for key, value in symbol.items()
                if key != "pattern"
            }
            for symbol in IMPLEMENTATION_SYMBOLS
        ],
        "behavioralTests": BEHAVIORAL_TESTS,
        "benchmarks": benchmark_entries,
        "corpora": corpus_entries,
        "sourceFiles": source_hashes,
        "supplementaryFiles": supplementary_entries,
        "excludedClaims": EXCLUDED,
        "rebuildCommand": (
            "bash scripts/check-programmable-sovereignty-artifact.sh --full"
        ),
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()


def stale_outputs(outputs: list[tuple[Path, bytes]]) -> list[str]:
    problems: list[str] = []
    for path, expected in outputs:
        relative = path.relative_to(REPO)
        if not path.is_file():
            problems.append(f"generated output missing: {relative}")
        elif path.read_bytes() != expected:
            problems.append(f"generated output is stale: {relative}; run the generator")
    return problems


def write_output(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def load_result_document(path: str) -> dict[str, Any]:
    candidate = Path(path)
    if not candidate.is_file():
        fail(f"result file missing: {path}")
    try:
        document = json.loads(candidate.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"{path} is not valid JSON: {error}")
    if not isinstance(document, dict):
        fail(f"{path} is not a JSON object")
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate generated files without modifying them",
    )
    parser.add_argument(
        "--source-commit",
        help=(
            "record an explicit full source commit; generation writes it to "
            "supplementary/source-commit.txt"
        ),
    )
    parser.add_argument(
        "--benchmark-input-digest",
        choices=[benchmark["id"] for benchmark in BENCHMARKS],
        help="print the input-tree digest for one retained benchmark",
    )
    parser.add_argument(
        "--benchmark-input-paths",
        choices=[benchmark["id"] for benchmark in BENCHMARKS],
        help="print the repository paths whose contents feed one benchmark",
    )
    parser.add_argument(
        "--render-inline",
        metavar="RESULT_JSON",
        help="print the inline TeX macros rendered from a result document",
    )
    parser.add_argument(
        "--render-measurements",
        metavar="RESULT_JSON",
        help="print the claim ledger measurements rendered from a result document",
    )
    parser.add_argument(
        "--write-measurements",
        metavar="RESULT_JSON",
        help="rewrite the claim ledger's generated measurements from a result document",
    )
    args = parser.parse_args()

    if args.benchmark_input_paths is not None:
        print("\n".join(benchmark_input_paths(args.benchmark_input_paths)))
        return 0
    if args.render_inline is not None:
        sys.stdout.write(render_inline(load_result_document(args.render_inline)))
        return 0
    if args.render_measurements is not None:
        print(render_measurements(load_result_document(args.render_measurements)))
        return 0
    if args.write_measurements is not None:
        write_measurements(load_result_document(args.write_measurements), LEDGER_FILE)
        return 0

    source_commit = resolve_source_commit(
        args.source_commit,
        require_local_object=not args.check or args.benchmark_input_digest is not None,
    )
    if args.benchmark_input_digest is not None:
        print(
            benchmark_input_tree_sha256(
                args.benchmark_input_digest,
                source_commit,
            )
        )
        return 0
    source_commit_bytes = f"{source_commit}\n".encode()
    validate_inputs(
        source_commit,
        require_local_source_object=not args.check,
    )
    snapshot_date = generated_at(source_commit)
    rust_toolchain = pinned_rust_toolchain(check=args.check)
    proof_bytes = proof_manifest_bytes(snapshot_date)
    inventory_bytes = theorem_inventory_bytes(snapshot_date)
    archive_bytes = lean_archive_bytes(snapshot_date)
    manifest = manifest_bytes(
        proof_bytes,
        inventory_bytes,
        archive_bytes,
        source_commit,
        source_commit_bytes,
        snapshot_date=snapshot_date,
        rust_toolchain=rust_toolchain,
    )
    outputs = [
        (SOURCE_COMMIT_FILE, source_commit_bytes),
        (SUPPLEMENTARY / "proof-manifest.toml", proof_bytes),
        (SUPPLEMENTARY / "theorem-inventory.json", inventory_bytes),
        (SUPPLEMENTARY / "lean-source.tar.gz", archive_bytes),
        (MANIFEST_FILE, manifest),
    ]
    if args.check:
        problems = stale_outputs(outputs)
        if problems:
            fail("\n  ".join(["the artifact is stale:", *problems]))
        print("programmable sovereignty artifact is current")
    else:
        for path, data in outputs:
            write_output(path, data)
        print("generated programmable sovereignty artifact")
    return 0


if __name__ == "__main__":
    sys.exit(main())
