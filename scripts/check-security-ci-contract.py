#!/usr/bin/env python3
"""Verify that the security release workflow is an unconditional CI dependency."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

import yaml


class ContractError(RuntimeError):
    pass


REQUIRED_AGGREGATE_NEEDS = (
    "check",
    "kani-public-pr",
    "formal-proof-contract",
    "apalache-full-contract",
    "threat-model-coverage-contract",
    "msrv",
    "cargo-vet",
    "cargo-deny",
    "enterprise-security-contract",
)
REQUIRED_AGGREGATE_ASSERTIONS = {
    f"test '${{{{ needs.{identifier}.result }}}}' = success"
    for identifier in REQUIRED_AGGREGATE_NEEDS
}
EXPECTED_REQUIRED_CONTEXTS = {
    "check": "Build, lint, test",
    "msrv": "MSRV build and test",
    "cargo-vet": "cargo-vet (locked supply-chain audit)",
    "cargo-deny": "cargo-deny (supply-chain bans/advisories/licenses)",
    "security-contract-required": "Security contract",
}
EXPECTED_ACTIONLINT_CONFIG = {
    "self-hosted-runner": {"labels": ["chio-enterprise-security"]}
}
EXPECTED_SECURITY_IMAGE_FROM = (
    "--platform=linux/amd64 "
    "rust:1.93.0-alpine3.22@sha256:"
    "efc08a6cc70a6ad8bdcf24176e3e0bdbbc7b984e7471fabf78b90de33b136f51"
)
EXPECTED_APK_LOCK_SHA256 = (
    "b4d4642b66191c1923fe7c293b408b570b71df9edb710ffa09bc518ca36a5ad8"
)
EXPECTED_CARGO_LOCK_SHA256 = (
    "44426ff0f763ae5e8a8f72bf3feb344a7870bf6e8402c2e4b0438a75fbf87032"
)
EXPECTED_RUST_TOOLCHAIN_SHA256 = (
    "8bc51ecab82415fddd8489604f2424e137d71856e7f65cbdcfaa48850d794b46"
)
EXPECTED_CLIPPY_ARCHIVE_SHA256 = (
    "1148e06bad43e30705b952c61d5d3a493b19b67be02ac281d8008df22dc05503"
)
EXPECTED_RUSTFMT_ARCHIVE_SHA256 = (
    "a78e673aa77a24f1e47fce31ba61cf4937450976da91e33c406476a5263742a1"
)
EXPECTED_CARGO_MUTANTS_ARCHIVE_SHA256 = (
    "47040c9cded7996c38b9976af0a9c46c4902ec5eb59369fffec758410dba8028"
)
EXPECTED_CARGO_MUTANTS_LOCK_SHA256 = (
    "0810d8fe5d67224340e560656f51619cf8f78925a4bfeedd2e5f22d199ac92a4"
)
EXPECTED_DIRECT_APK_PACKAGES = (
    "bash=5.2.37-r0",
    "build-base=0.5-r3",
    "ca-certificates=20260611-r0",
    "cmake=3.31.7-r1",
    "coreutils=9.7-r1",
    "curl=8.14.1-r3",
    "git=2.49.1-r0",
    "jq=1.8.1-r0",
    "linux-headers=6.14.2-r0",
    "openssl-dev=3.5.7-r0",
    "pkgconf=2.4.3-r0",
    "protobuf=29.4-r0",
    "protobuf-dev=29.4-r0",
    "python3=3.12.13-r0",
    "util-linux=2.41-r9",
)
EXPECTED_TRUSTED_BOUNDARY_FILES = frozenset(
    {
        "check-cage-all-target-inventory.py",
        "check-cage-enforcement.sh",
        "check-cage-linux-enforcement.sh",
        "check-exact-cargo-test-inventory.py",
        "check-keyring-transparency.sh",
        "check-linux-enforcement-stack.py",
        "check-secret-broker-boundary.sh",
        "check-security-adversarial-evidence.py",
        "command-client.py",
        "entrypoint.py",
        "security-evidence-seccomp.json",
        "verifier-bin/cargo",
        "verifier-bin/cc",
        "verifier-bin/ldd",
    }
)
ALLOWED_WORKFLOW_ENVIRONMENTS: dict[tuple[str, str], object] = {
    ("demo-pages.yml", "deploy"): {
        "name": "github-pages",
        "url": "${{ steps.deployment.outputs.page_url }}",
    },
    (
        "enterprise-evidence-finalizer.yml",
        "sign-validated-capture",
    ): "enterprise-evidence-signing",
    (
        "enterprise-evidence-finalizer.yml",
        "publish-security-contract",
    ): "security-check-publisher",
    (
        "security-contract-revocation.yml",
        "revoke-security-contract",
    ): "security-check-publisher",
    ("release-cpp.yml", "publish-vcpkg"): {"name": "chio-vcpkg-registry"},
    ("release-npm.yml", "publish"): {"name": "npm"},
    ("release-pypi.yml", "publish"): {
        "name": "pypi",
        "url": "https://pypi.org/p/${{ steps.meta.outputs.name }}",
    },
}
PUBLISHER_PRIVATE_KEY_REFERENCE = "${{ secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM }}"
PUBLISHER_PRIVATE_KEY_LOCATIONS = (
    (
        "enterprise-evidence-finalizer.yml",
        (
            "jobs",
            "publish-security-contract",
            "steps",
            0,
            "env",
            "SECURITY_APP_PRIVATE_KEY_PEM",
        ),
        PUBLISHER_PRIVATE_KEY_REFERENCE,
    ),
    (
        "security-contract-revocation.yml",
        (
            "jobs",
            "revoke-security-contract",
            "steps",
            0,
            "env",
            "SECURITY_APP_PRIVATE_KEY_PEM",
        ),
        PUBLISHER_PRIVATE_KEY_REFERENCE,
    ),
)
FORBIDDEN_INHERITED_ENV = {
    "BASH_ENV",
    "BASHOPTS",
    "CDPATH",
    "ENV",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "PATH",
    "PYTHONPATH",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTC_WRAPPER",
    "SHELLOPTS",
}
REQUIRED_CANDIDATE_ENTERPRISE_JOBS = {
    "portable-contracts",
    "active-defense-security",
    "adversarial-evidence",
    "linux-enforcement",
}
REQUIRED_ENTERPRISE_JOBS = REQUIRED_CANDIDATE_ENTERPRISE_JOBS | {
    "bind-source",
    "committed-linux-evidence",
}
EXPECTED_ENTERPRISE_INPUTS = {
    "source_repository": {
        "description": "Exact repository containing the source tree under test",
        "required": "true",
        "type": "string",
    },
    "source_sha": {
        "description": "Exact commit containing the source tree under test",
        "required": "true",
        "type": "string",
    },
}
EXPECTED_ENTERPRISE_EVENTS = {
    "workflow_call": {"inputs": EXPECTED_ENTERPRISE_INPUTS},
    "workflow_dispatch": {"inputs": EXPECTED_ENTERPRISE_INPUTS},
}
EXPECTED_ENTERPRISE_PERMISSIONS = {
    "artifact-metadata": "write",
    "attestations": "write",
    "contents": "read",
    "id-token": "write",
}
EXPECTED_ENTERPRISE_CONCURRENCY = {
    "group": "enterprise-security-source-${{ github.repository }}-${{ github.event.pull_request.head.sha || github.sha }}",
    "cancel-in-progress": "true",
}
EXPECTED_CONTROLLER_PERMISSIONS = {
    "actions": "write",
    "contents": "read",
    "pull-requests": "read",
}
EXPECTED_CAPTURE_PERMISSIONS = {
    "actions": "read",
    "contents": "read",
    "pull-requests": "read",
}
EXPECTED_FINALIZER_PERMISSIONS = {
    "actions": "read",
    "checks": "read",
    "contents": "read",
    "pull-requests": "read",
}
EXPECTED_ACTIONS_WRITE_DECLARATIONS = {
    ("enterprise-evidence-controller.yml", None),
    ("enterprise-linux-capture.yml", "dispatch-trusted-finalizer"),
}
EXPECTED_ACTIONS_WRITE_JOBS = {
    ("enterprise-evidence-controller.yml", "dispatch-isolated-capture"),
    ("enterprise-linux-capture.yml", "dispatch-trusted-finalizer"),
}
EXPECTED_CI_PERMISSIONS = {"contents": "read"}
EXPECTED_CONTROLLER_EVENTS = {
    "pull_request_target": {
        "branches": ["main"],
        "types": ["opened", "synchronize", "reopened", "labeled", "unlabeled"],
    }
}
EXPECTED_CAPTURE_EVENTS = {
    "workflow_dispatch": {
        "inputs": {
            "authorized_source_sha": {
                "description": "Repository-authorized security source commit",
                "required": "true",
                "type": "string",
            },
            "base_ref": {
                "description": "Exact pull request base ref",
                "required": "true",
                "type": "string",
            },
            "base_repository": {
                "description": "Exact pull request base repository",
                "required": "true",
                "type": "string",
            },
            "base_sha": {
                "description": "Exact pull request base commit",
                "required": "true",
                "type": "string",
            },
            "controller_actor": {
                "description": "Actor of the trusted controller run",
                "required": "true",
                "type": "string",
            },
            "controller_blob_sha": {
                "description": "Blob identifier of the trusted controller definition",
                "required": "true",
                "type": "string",
            },
            "controller_dispatch_nonce": {
                "description": "Unique controller-issued capture dispatch nonce",
                "required": "true",
                "type": "string",
            },
            "controller_issued_at_unix_ms": {
                "description": "Trusted controller issuance time",
                "required": "true",
                "type": "string",
            },
            "controller_run_attempt": {
                "description": "Exact trusted controller run attempt",
                "required": "true",
                "type": "string",
            },
            "controller_run_id": {
                "description": "Exact trusted controller run",
                "required": "true",
                "type": "string",
            },
            "controller_workflow_id": {
                "description": "Exact trusted controller workflow identifier",
                "required": "true",
                "type": "string",
            },
            "labels_digest": {
                "description": "Digest of the live pull request label set",
                "required": "true",
                "type": "string",
            },
            "merge_commit_sha": {
                "description": "Exact pull request test merge commit",
                "required": "true",
                "type": "string",
            },
            "merge_tree_sha": {
                "description": "Exact pull request test merge tree",
                "required": "true",
                "type": "string",
            },
            "pr_number": {
                "description": "Pull request bound to the capture",
                "required": "true",
                "type": "string",
            },
            "security_definition_sha": {
                "description": "Authorized security workflow definition baseline commit",
                "required": "true",
                "type": "string",
            },
            "source_repository": {
                "description": "Exact repository containing the candidate commit",
                "required": "true",
                "type": "string",
            },
            "source_sha": {
                "description": "Exact candidate head commit to exercise",
                "required": "true",
                "type": "string",
            },
            "mode": {
                "description": "Enforcement or evidence refresh",
                "required": "true",
                "type": "choice",
                "options": ["enforcement", "refresh"],
            },
        }
    }
}
EXPECTED_FINALIZER_EVENTS = {
    "workflow_dispatch": {
        "inputs": {
            "authorized_source_sha": {
                "description": "Exact authorized security source commit",
                "required": "true",
                "type": "string",
            },
            "capture_run_attempt": {
                "description": "Exact completed capture workflow attempt",
                "required": "true",
                "type": "string",
            },
            "capture_run_id": {
                "description": "Exact completed capture workflow run",
                "required": "true",
                "type": "string",
            },
            "dispatch_nonce": {
                "description": "Unique capture-issued finalizer dispatch nonce",
                "required": "true",
                "type": "string",
            },
            "merge_commit_sha": {
                "description": "Exact pull request test merge commit",
                "required": "true",
                "type": "string",
            },
            "pr_number": {
                "description": "Pull request bound to the capture",
                "required": "true",
                "type": "string",
            },
            "security_definition_sha": {
                "description": "Authorized security workflow definition baseline commit",
                "required": "true",
                "type": "string",
            },
            "source_sha": {
                "description": "Exact reviewed source commit captured by the runner",
                "required": "true",
                "type": "string",
            },
        }
    }
}
EXPECTED_FINALIZER_SECRET = (
    "CANARY_SIGNING_SEED_HEX",
    "${{ secrets.CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX }}",
)
EXPECTED_SOURCE_CHECKOUT = {
    "repository": "${{ needs.authorize-capture.outputs.source_repository }}",
    "ref": "${{ needs.authorize-capture.outputs.source_sha }}",
    "fetch-depth": "0",
    "persist-credentials": "false",
    "path": "candidate",
}
EXPECTED_ENTERPRISE_TESTED_CHECKOUT = {
    "repository": "${{ needs.bind-source.outputs.tested_repository }}",
    "ref": "${{ needs.bind-source.outputs.tested_sha }}",
    "fetch-depth": "0",
    "persist-credentials": "false",
}
EXPECTED_MERGE_CHECKOUT = {
    **EXPECTED_SOURCE_CHECKOUT,
    "ref": "${{ needs.authorize-capture.outputs.merge_commit_sha }}",
}
EXPECTED_CAPTURE_TRUSTED_CHECKOUT = {
    "repository": "${{ needs.authorize-capture.outputs.source_repository }}",
    "ref": "${{ needs.authorize-capture.outputs.authorized_source_sha }}",
    "fetch-depth": "1",
    "persist-credentials": "false",
    "path": "authorized-security",
}
EXPECTED_ENTERPRISE_ISOLATED_CANDIDATE_CHECKOUT = {
    **EXPECTED_ENTERPRISE_TESTED_CHECKOUT,
    "path": "candidate",
}
EXPECTED_ENTERPRISE_TRUSTED_CHECKOUT = {
    "repository": "${{ needs.bind-source.outputs.tested_repository }}",
    "ref": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
    "fetch-depth": "1",
    "persist-credentials": "false",
    "path": "authorized-security",
}
EXPECTED_ENTERPRISE_CALL_INPUTS = {
    "source_repository": "${{ github.repository }}",
    "source_sha": "${{ github.event.pull_request.head.sha || github.sha }}",
}
ENTERPRISE_HARDENING_CALL_PATTERN = re.compile(
    r"bb-connor/arc/\.github/workflows/enterprise-hardening\.yml@([0-9a-f]{40})"
)
ENTERPRISE_HARDENING_BOOTSTRAP_SENTINEL_PATTERN = re.compile(
    r"(?m)^[ \t]*# CHIO_ENTERPRISE_HARDENING_BOOTSTRAP_SHA=([0-9a-f]{40})[ \t]*$"
)
ZERO_COMMIT_SHA = "0" * 40
EXPECTED_CONTROLLER_CONCURRENCY = {
    "group": "enterprise-security-controller-source-${{ github.event.pull_request.head.sha }}",
    "cancel-in-progress": "true",
}
EXPECTED_CAPTURE_CONCURRENCY = {
    "group": "enterprise-security-source-${{ inputs.source_sha }}",
    "cancel-in-progress": "true",
}
EXPECTED_SIGNING_CONCURRENCY = {
    "group": "enterprise-security-source-${{ needs.validate-capture.outputs.source_sha }}",
    "cancel-in-progress": "true",
}
EXPECTED_PUBLISHER_CONCURRENCY = {
    "group": "security-check-authority-${{ needs.authorize-security-check-publication.outputs.merge_commit_sha }}",
    "cancel-in-progress": "false",
    "queue": "max",
}
EXPECTED_REVOCATION_EVENTS = {
    "workflow_dispatch": {
        "inputs": {
            "authorized_source_sha": {
                "description": "Exact authorized source commit bound into the authority checks",
                "required": "true",
                "type": "string",
            },
            "evidence_sha": {
                "description": "Exact evidence head bound into the authority checks",
                "required": "true",
                "type": "string",
            },
            "merge_commit_sha": {
                "description": "Exact test merge commit carrying the five authority contexts",
                "required": "true",
                "type": "string",
            },
            "pr_number": {
                "description": "Pull request number bound into the authority checks",
                "required": "true",
                "type": "string",
            },
            "reason": {
                "description": "Authority withdrawal that makes the successful checks invalid",
                "required": "true",
                "type": "choice",
                "options": [
                    "ci-regression",
                    "source-authority-withdrawn",
                    "evidence-authority-withdrawn",
                    "policy-authority-withdrawn",
                    "app-authority-withdrawn",
                    "operator-security-revocation",
                ],
            },
        }
    },
    "workflow_run": {
        "workflows": ["CI", "Enterprise evidence finalizer"],
        "types": ["completed"],
    },
}
EXPECTED_REVOCATION_CONCURRENCY = {
    "group": "security-check-authority-${{ needs.bind-revocation.outputs.merge_commit_sha }}",
    "cancel-in-progress": "false",
    "queue": "max",
}
EXPECTED_CONTROLLER_STEP_INVENTORY = (
    ("Authorize exact source and controller context", "authorize", None),
    ("Dispatch exact default-branch capture definition", "dispatch", None),
    (
        "Upload exact capture dispatch intent",
        None,
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    ),
)
EXPECTED_CAPTURE_STEP_INVENTORIES = {
    "authorize-capture": (
        ("Revalidate controller source and merge authorization", "authorize", None),
    ),
    "refresh-linux-evidence": (
        (
            "Checkout exact candidate source without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        (
            "Checkout exact authorized security tooling without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        ("Validate isolated refresh inputs", None, None),
        (
            "Build digest-addressed trusted security execution image",
            "security-image",
            None,
        ),
        ("Refresh all evidence inside trusted execution boundary", None, None),
        (
            "Upload unsigned evidence patch",
            None,
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        ),
        ("Require refreshed evidence to be committed", None, None),
    ),
    "capture-linux-enforcement": (
        (
            "Checkout exact candidate merge without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        (
            "Checkout exact authorized security tooling without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        ("Validate exact isolated candidate merge inputs", None, None),
        (
            "Build digest-addressed trusted security execution image",
            "security-image",
            None,
        ),
        ("Run candidate enforcement inside trusted execution boundary", None, None),
        ("Build unsigned fixed-schema capture", None, None),
        (
            "Upload bounded unsigned Linux capture",
            None,
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        ),
    ),
    "dispatch-trusted-finalizer": (
        ("Dispatch exact default-branch finalizer definition", "dispatch", None),
        (
            "Upload exact finalizer dispatch intent",
            None,
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        ),
    ),
}
EXPECTED_CAPTURE_AUTHORIZATION_OUTPUTS = {
    "authorized_source_sha": "${{ steps.authorize.outputs.authorized_source_sha }}",
    "base_ref": "${{ steps.authorize.outputs.base_ref }}",
    "base_repository": "${{ steps.authorize.outputs.base_repository }}",
    "base_sha": "${{ steps.authorize.outputs.base_sha }}",
    "capture_actor": "${{ steps.authorize.outputs.capture_actor }}",
    "capture_blob_sha": "${{ steps.authorize.outputs.capture_blob_sha }}",
    "capture_issued_at_unix_ms": "${{ steps.authorize.outputs.capture_issued_at_unix_ms }}",
    "capture_run_attempt": "${{ steps.authorize.outputs.capture_run_attempt }}",
    "capture_run_id": "${{ steps.authorize.outputs.capture_run_id }}",
    "capture_workflow_id": "${{ steps.authorize.outputs.capture_workflow_id }}",
    "controller_actor": "${{ steps.authorize.outputs.controller_actor }}",
    "controller_blob_sha": "${{ steps.authorize.outputs.controller_blob_sha }}",
    "controller_issued_at_unix_ms": "${{ steps.authorize.outputs.controller_issued_at_unix_ms }}",
    "controller_run_attempt": "${{ steps.authorize.outputs.controller_run_attempt }}",
    "controller_run_id": "${{ steps.authorize.outputs.controller_run_id }}",
    "controller_workflow_id": "${{ steps.authorize.outputs.controller_workflow_id }}",
    "labels_digest": "${{ steps.authorize.outputs.labels_digest }}",
    "merge_commit_sha": "${{ steps.authorize.outputs.merge_commit_sha }}",
    "merge_tree_sha": "${{ steps.authorize.outputs.merge_tree_sha }}",
    "mode": "${{ steps.authorize.outputs.mode }}",
    "pr_number": "${{ steps.authorize.outputs.pr_number }}",
    "security_definition_sha": "${{ steps.authorize.outputs.security_definition_sha }}",
    "source_repository": "${{ steps.authorize.outputs.source_repository }}",
    "source_sha": "${{ steps.authorize.outputs.source_sha }}",
}
EXPECTED_FINALIZER_STEP_INVENTORIES = {
    "validate-capture": (
        ("Bind finalizer capture job and artifact identities", "bind", None),
        ("Download bounded unsigned capture archive", None, None),
        ("Safely extract exact bounded capture files", None, None),
        ("Validate canonical fixed-schema capture data", "validate", None),
        ("Revalidate live authorization and issuance freshness", "revalidate", None),
        (
            "Upload authenticated finalizer dispatch intent",
            None,
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        ),
    ),
    "sign-validated-capture": (
        ("Acquire pinned trusted evidence verifier", None, None),
        ("Create and verify committed migration canary", "sign", None),
        ("Publish committed evidence verification policy", None, None),
        (
            "Upload exact committed migration evidence",
            None,
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        ),
    ),
    "authorize-security-check-publication": (
        ("Bind live committed evidence head and CI definition", "bind", None),
        (
            "Checkout exact committed evidence without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        (
            "Checkout exact authorized checker source without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        ("Verify committed evidence with exact trusted checker", "strict", None),
        ("Authenticate exact successful current CI run", "ci", None),
        ("Verify exact CI merge binding attestation", "attestation", None),
        ("Seal exact publication binding", "seal", None),
    ),
    "publish-security-contract": (
        ("Reconcile exact five-context merge authority", None, None),
    ),
}
EXPECTED_PUBLICATION_AUTHORIZATION_OUTPUTS = {
    "attestation_bundle_sha256": "${{ steps.attestation.outputs.attestation_bundle_sha256 }}",
    "authorized_source_sha": "${{ steps.seal.outputs.authorized_source_sha }}",
    "binding_artifact_digest": "${{ steps.attestation.outputs.binding_artifact_digest }}",
    "binding_artifact_id": "${{ steps.attestation.outputs.binding_artifact_id }}",
    "binding_sha256": "${{ steps.attestation.outputs.binding_sha256 }}",
    "ci_aggregate_check_run_id": "${{ steps.seal.outputs.ci_aggregate_check_run_id }}",
    "ci_run_attempt": "${{ steps.seal.outputs.ci_run_attempt }}",
    "ci_run_id": "${{ steps.seal.outputs.ci_run_id }}",
    "ci_workflow_id": "${{ steps.seal.outputs.ci_workflow_id }}",
    "evidence_sha": "${{ steps.seal.outputs.evidence_sha }}",
    "external_id": "${{ steps.seal.outputs.external_id }}",
    "merge_commit_sha": "${{ steps.seal.outputs.merge_commit_sha }}",
    "pr_number": "${{ steps.seal.outputs.pr_number }}",
    "publication_binding_digest": "${{ steps.seal.outputs.publication_binding_digest }}",
    "publication_binding_json": "${{ steps.seal.outputs.publication_binding_json }}",
    "security_definition_sha": "${{ steps.seal.outputs.security_definition_sha }}",
}
EXPECTED_PUBLICATION_CHECKOUTS = {
    "Checkout exact committed evidence without credentials": {
        "repository": "${{ steps.bind.outputs.source_repository }}",
        "ref": "${{ steps.bind.outputs.evidence_sha }}",
        "fetch-depth": "0",
        "persist-credentials": "false",
        "path": "committed-evidence",
    },
    "Checkout exact authorized checker source without credentials": {
        "repository": "${{ steps.bind.outputs.source_repository }}",
        "ref": "${{ steps.bind.outputs.authorized_source_sha }}",
        "fetch-depth": "1",
        "persist-credentials": "false",
        "path": "authorized-checker",
    },
}
EXPECTED_PUBLICATION_BIND_ENV = {
    "AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
    "BASE_REF": "${{ needs.validate-capture.outputs.base_ref }}",
    "BASE_REPOSITORY": "${{ needs.validate-capture.outputs.base_repository }}",
    "BASE_SHA": "${{ needs.validate-capture.outputs.base_sha }}",
    "CAPTURE_AUTHORIZED_SOURCE_SHA": "${{ needs.validate-capture.outputs.authorized_source_sha }}",
    "COMMITTED_EVIDENCE_SHA": "${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}",
    "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
    "EVIDENCE_SHA": "${{ needs.validate-capture.outputs.source_sha }}",
    "GH_TOKEN": "${{ github.token }}",
    "MERGE_COMMIT_SHA": "${{ needs.validate-capture.outputs.merge_commit_sha }}",
    "PR_NUMBER": "${{ needs.validate-capture.outputs.pr_number }}",
    "SECURITY_DEFINITION_SHA": "${{ needs.validate-capture.outputs.security_definition_sha }}",
    "SOURCE_REPOSITORY": "${{ needs.validate-capture.outputs.source_repository }}",
}
EXPECTED_PUBLICATION_STRICT_ENV = {
    "AUTHORIZED_SOURCE_SHA": "${{ steps.bind.outputs.authorized_source_sha }}",
    "CANARY_SIGNER_PUBLIC_KEY": "${{ vars.CHIO_ENTERPRISE_CANARY_SIGNER_PUBLIC_KEY }}",
    "EVIDENCE_POLICY_JSON": "${{ vars.CHIO_ENTERPRISE_EVIDENCE_POLICY_JSON }}",
    "EVIDENCE_SHA": "${{ steps.bind.outputs.evidence_sha }}",
    "VERIFIER_SHA256": "${{ vars.CHIO_ENTERPRISE_EVIDENCE_VERIFIER_SHA256 }}",
    "VERIFIER_URL": "${{ vars.CHIO_ENTERPRISE_EVIDENCE_VERIFIER_URL }}",
}
EXPECTED_PUBLICATION_CI_ENV = {
    "BASE_REF": "${{ needs.validate-capture.outputs.base_ref }}",
    "BASE_SHA": "${{ needs.validate-capture.outputs.base_sha }}",
    "CI_WORKFLOW_ID": "${{ steps.bind.outputs.ci_workflow_id }}",
    "EVIDENCE_SHA": "${{ steps.bind.outputs.evidence_sha }}",
    "GH_TOKEN": "${{ github.token }}",
    "HEAD_REF": "${{ steps.bind.outputs.head_ref }}",
    "MERGE_COMMIT_SHA": "${{ needs.validate-capture.outputs.merge_commit_sha }}",
    "MERGE_TREE_SHA": "${{ needs.validate-capture.outputs.merge_tree_sha }}",
    "PR_NUMBER": "${{ steps.bind.outputs.pr_number }}",
}
EXPECTED_PUBLICATION_ATTESTATION_ENV = {
    "BASE_REF": "${{ needs.validate-capture.outputs.base_ref }}",
    "BASE_SHA": "${{ needs.validate-capture.outputs.base_sha }}",
    "CI_RUN_ATTEMPT": "${{ steps.ci.outputs.ci_run_attempt }}",
    "CI_RUN_ID": "${{ steps.ci.outputs.ci_run_id }}",
    "CI_WORKFLOW_ID": "${{ steps.bind.outputs.ci_workflow_id }}",
    "EVIDENCE_SHA": "${{ steps.bind.outputs.evidence_sha }}",
    "GH_TOKEN": "${{ github.token }}",
    "HEAD_REF": "${{ steps.bind.outputs.head_ref }}",
    "MERGE_COMMIT_SHA": "${{ needs.validate-capture.outputs.merge_commit_sha }}",
    "MERGE_TREE_SHA": "${{ needs.validate-capture.outputs.merge_tree_sha }}",
    "PR_NUMBER": "${{ steps.bind.outputs.pr_number }}",
    "SECURITY_DEFINITION_SHA": "${{ steps.bind.outputs.security_definition_sha }}",
}
EXPECTED_PUBLICATION_REQUIRED_NAMES = (
    "Build, lint, test",
    "MSRV build and test",
    "cargo-vet (locked supply-chain audit)",
    "cargo-deny (supply-chain bans/advisories/licenses)",
    "Security contract",
)
EXPECTED_PUBLICATION_REQUIRED_NAMES_BLOCK = "\n".join(
    (
        "required_names=(",
        *(f'  "{name}"' for name in EXPECTED_PUBLICATION_REQUIRED_NAMES),
        ")",
    )
)
EXPECTED_PUBLISHER_STEP_ENV = {
    "AUTHORIZED_SOURCE_SHA": "${{ needs.authorize-security-check-publication.outputs.authorized_source_sha }}",
    "CI_AGGREGATE_CHECK_RUN_ID": "${{ needs.authorize-security-check-publication.outputs.ci_aggregate_check_run_id }}",
    "CI_RUN_ATTEMPT": "${{ needs.authorize-security-check-publication.outputs.ci_run_attempt }}",
    "CI_RUN_ID": "${{ needs.authorize-security-check-publication.outputs.ci_run_id }}",
    "CI_WORKFLOW_ID": "${{ needs.authorize-security-check-publication.outputs.ci_workflow_id }}",
    "COMMITTED_EVIDENCE_SHA": "${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}",
    "EVIDENCE_SHA": "${{ needs.authorize-security-check-publication.outputs.evidence_sha }}",
    "EXTERNAL_ID": "${{ needs.authorize-security-check-publication.outputs.external_id }}",
    "FINALIZER_RUN_ATTEMPT": "${{ github.run_attempt }}",
    "FINALIZER_RUN_ID": "${{ github.run_id }}",
    "GH_TOKEN": "${{ github.token }}",
    "MERGE_COMMIT_SHA": "${{ needs.authorize-security-check-publication.outputs.merge_commit_sha }}",
    "PR_NUMBER": "${{ needs.authorize-security-check-publication.outputs.pr_number }}",
    "PUBLICATION_BINDING_DIGEST": "${{ needs.authorize-security-check-publication.outputs.publication_binding_digest }}",
    "PUBLICATION_BINDING_JSON": "${{ needs.authorize-security-check-publication.outputs.publication_binding_json }}",
    "PUBLISHER_REF": "${{ github.ref }}",
    "PUBLISHER_SHA": "${{ github.sha }}",
    "SECURITY_APP_ID": "${{ vars.CHIO_SECURITY_APP_ID }}",
    "SECURITY_APP_INSTALLATION_ID": "${{ vars.CHIO_SECURITY_APP_INSTALLATION_ID }}",
    "SECURITY_APP_PRIVATE_KEY_PEM": "${{ secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM }}",
    "SECURITY_DEFINITION_SHA": "${{ needs.authorize-security-check-publication.outputs.security_definition_sha }}",
    "LIVE_AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
    "LIVE_SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
}
EXPECTED_PUBLISHER_SECRET = (
    "SECURITY_APP_PRIVATE_KEY_PEM",
    "${{ secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM }}",
)
EXPECTED_REVOCATION_STEP_ENV = {
    "AUTHORIZED_SOURCE_SHA": "${{ needs.bind-revocation.outputs.authorized_source_sha }}",
    "BASE_SHA": "${{ needs.bind-revocation.outputs.base_sha }}",
    "CREATE_MISSING": "${{ needs.bind-revocation.outputs.create_missing }}",
    "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
    "EVIDENCE_SHA": "${{ needs.bind-revocation.outputs.evidence_sha }}",
    "EVENT_NAME": "${{ github.event_name }}",
    "GH_TOKEN": "${{ github.token }}",
    "LIVE_AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
    "LIVE_COMMITTED_EVIDENCE_SHA": "${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}",
    "LIVE_SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
    "MERGE_COMMIT_SHA": "${{ needs.bind-revocation.outputs.merge_commit_sha }}",
    "MERGE_TREE_SHA": "${{ needs.bind-revocation.outputs.merge_tree_sha }}",
    "PR_NUMBER": "${{ needs.bind-revocation.outputs.pr_number }}",
    "REASON": "${{ needs.bind-revocation.outputs.reason }}",
    "REVOKER_REF": "${{ github.ref }}",
    "REVOKER_SHA": "${{ github.sha }}",
    "SECURITY_APP_ID": "${{ vars.CHIO_SECURITY_APP_ID }}",
    "SECURITY_APP_INSTALLATION_ID": "${{ vars.CHIO_SECURITY_APP_INSTALLATION_ID }}",
    "SECURITY_APP_PRIVATE_KEY_PEM": "${{ secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM }}",
    "SECURITY_DEFINITION_SHA": "${{ needs.bind-revocation.outputs.security_definition_sha }}",
}
EXPECTED_REVOCATION_STEP_INVENTORY = (
    ("Revoke exact Actions mirrors and dedicated App namespace", None, None),
)
EXPECTED_COMMITTED_EVIDENCE_STEP_INVENTORY = (
    ("Bind committed evidence or authorize narrow bootstrap", "evidence", None),
    (
        "Checkout exact committed evidence without credentials",
        None,
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    ),
    (
        "Checkout exact authorized checker source without credentials",
        None,
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    ),
    ("Verify exact isolated checkout identities", None, None),
    ("Verify committed Linux evidence descendant", None, None),
)
EXPECTED_BIND_SOURCE_STEP_INVENTORY = (
    (
        "Checkout exact event merge without credentials",
        None,
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    ),
    ("Build canonical exact merge binding", "bind", None),
    ("Bind exact pushed commit", "push", None),
    (
        "Attest canonical exact merge binding",
        "attest",
        "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
    ),
    ("Package exact binding and attestation bundle", "package", None),
    (
        "Upload exact binding and attestation bundle",
        "upload",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ),
)
EXPECTED_ENTERPRISE_BOUNDARY_STEP_INVENTORIES = {
    "adversarial-evidence": (
        (
            "Checkout exact candidate source without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        (
            "Checkout exact authorized security tooling without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        ("Verify exact isolated security execution inputs", None, None),
        (
            "Build digest-addressed trusted security execution image",
            "security-image",
            None,
        ),
        ("Verify trusted execution boundary hostile probes", None, None),
        ("Verify freshness-bound mutation evidence", None, None),
    ),
    "linux-enforcement": (
        (
            "Checkout exact candidate source without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        (
            "Checkout exact authorized security tooling without credentials",
            None,
            "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        ),
        ("Verify exact isolated security execution inputs", None, None),
        (
            "Build digest-addressed trusted security execution image",
            "security-image",
            None,
        ),
        ("Run isolated Linux evidence and cage campaigns", None, None),
    ),
}
EXPECTED_TRUST_JOB_DIGESTS = {
    (
        "enterprise-hardening",
        "bind-source",
    ): "7d05d2f074436ae7ee48f865f982f23ada8b2e1f444edada945fa047b1162c4f",
    (
        "enterprise evidence controller",
        "dispatch-isolated-capture",
    ): "22e5b956093ed25b89d6809eb325cb6a82a7de88bfab0eb3acf12d4648f348c3",
    (
        "enterprise Linux capture",
        "authorize-capture",
    ): "00c5dc81fe982d3515e6a80e4723009cb46f5d5085c32bad9db3a1804a92fd2a",
    (
        "enterprise Linux capture",
        "refresh-linux-evidence",
    ): "18e9cdd8888375b9f8fe972983b6a1a563ab32f7f5c2b75b516cfffd1553443e",
    (
        "enterprise Linux capture",
        "capture-linux-enforcement",
    ): "21279f441c48df1082cda19f19e722231da5484016727ff2cc00593de6bcfe6c",
    (
        "enterprise Linux capture",
        "dispatch-trusted-finalizer",
    ): "08c86b8224cce5268679f8c6152a95848c03a707ed387ea2c6252d739927f382",
    (
        "enterprise evidence finalizer",
        "validate-capture",
    ): "579f73c2b6eea625547ff4ad2fde3cbfd99847f51daff6933f6c79ea2de8bc1f",
    (
        "enterprise evidence finalizer",
        "sign-validated-capture",
    ): "d3ab8d49c9e47b9c936db2edfe7d636161d67b9bdd5ef70ac815d1f1ec08ee32",
    (
        "enterprise evidence finalizer",
        "authorize-security-check-publication",
    ): "44f78d1b6726ccb4f9dcf5ffcf1f8f447e6af3c0cd6446803e9719a7bc7ae0ea",
    (
        "enterprise evidence finalizer",
        "publish-security-contract",
    ): "4f1569329509253a78b699249bc0b91f25a2f7b5820ef6634eeb4730017d9da6",
    (
        "security contract revocation",
        "bind-revocation",
    ): "cf3fe01f8fa43d0d51102ce6c82de9271966462207e6b4985d4882f30b76fb63",
    (
        "security contract revocation",
        "revoke-security-contract",
    ): "844cb2102b2cec4c746f523313a7be97432ed4bfcecbbfe58141f6e15e395ef5",
    (
        "enterprise-hardening",
        "committed-linux-evidence",
    ): "9a7f021026ec5253b299113627546ab3beb8d2919473ab8aa5ac6aa79b7b3873",
}
EXPECTED_AGGREGATE_RUN = "\n".join(
    (
        "set -euo pipefail",
        *(
            f"test '${{{{ needs.{identifier}.result }}}}' = success"
            for identifier in REQUIRED_AGGREGATE_NEEDS
        ),
    )
)
EXPECTED_NATIVE_SECURITY_RUN = r"""
set -euo pipefail
cargo test -p chio-conformance --all-targets
./scripts/check-enterprise-cross-mechanism.sh

native_suite_list_output="$(mktemp)"
native_suite_run_output="$(mktemp)"
generated_vector_list_output="$(mktemp)"
generated_vector_run_output="$(mktemp)"
trap 'rm -f "${native_suite_list_output}" "${native_suite_run_output}" "${generated_vector_list_output}" "${generated_vector_run_output}"' EXIT

cargo test -p chio-conformance --features enterprise-native --test native_suite \
  -- --list 2>&1 | tee "${native_suite_list_output}"
cargo test -p chio-conformance --features enterprise-native --test native_suite \
  2>&1 | tee "${native_suite_run_output}"
python3 scripts/check-exact-cargo-test-inventory.py \
  --label "enterprise native suite" \
  --list-output "${native_suite_list_output}" \
  --run-output "${native_suite_run_output}" \
  enterprise_native_runner_executes_exactly_fifteen_behaviors \
  native_conformance_suite_runs_against_fixture \
  native_standards_artifacts_cover_required_categories_and_references

cargo test -p chio-conformance --features enterprise-native --lib \
  native_suite::tests::enterprise_inventory_gate_rejects_missing_duplicate_extra_skipped_and_zero \
  -- --exact

cargo test -p chio-core-types --test security_generated_vectors \
  -- --list 2>&1 | tee "${generated_vector_list_output}"
cargo test -p chio-core-types --test security_generated_vectors \
  2>&1 | tee "${generated_vector_run_output}"
python3 scripts/check-exact-cargo-test-inventory.py \
  --label "Rust generated security vectors" \
  --list-output "${generated_vector_list_output}" \
  --run-output "${generated_vector_run_output}" \
  authoritative_schema_rejects_both_approval_forms_vector \
  generated_active_defense_integer_wrappers_fail_closed \
  generated_active_defense_types_decode_reencode_and_reject \
  generated_detector_health_type_rejects_invalid_serialization \
  generated_detector_health_type_rejects_mutation_corpus \
  generated_protocol_types_preserve_approval_and_aggregate_budget_fields \
  generated_receipt_types_cover_semantic_mutation_corpus \
  legacy_response_transition_canonical_digest_is_unchanged \
  native_receipt_types_reject_unsafe_json_integers \
  protocol_schema_and_generated_types_cover_exact_negative_corpus
""".strip()
EXPECTED_SCHEMA_BINDINGS_RUN = r"""
./scripts/check-chio-schema-registry.sh
python3 scripts/check-security-wire-vectors.py
make codegen-check
cargo xtask freeze-vectors --check
""".strip()
EXPECTED_PYTHON_VECTOR_RUN = r"""
python -m pip install --disable-pip-version-check -e 'sdks/python/chio-sdk-python[dev]'
python -m pytest -q sdks/python/chio-sdk-python/tests/test_security_generated_vectors.py
""".strip()
EXPECTED_TYPESCRIPT_VECTOR_RUN = r"""
cd sdks/typescript/packages/conformance
npm ci
npm test -- test/security-generated-vectors.test.ts
""".strip()
EXPECTED_GO_GENERATED_VECTOR_RUN = r"""
expected_tests=$'TestBothApprovalFormsVectorTracksAuthoritativeExclusion\nTestDetectorHealthGeneratedEmittersRejectInvalidState\nTestDetectorHealthGeneratedTypeRejectsMutationCorpus\nTestDetectorHealthTaggedKnowledgeRejectsInvalidVariants\nTestGeneratedActiveDefenseTypesDecodeReencodeAndReject\nTestGeneratedProtocolTypesPreserveApprovalAndAggregateBudgetFields\nTestGeneratedReceiptEmittersRejectUnsafePortableIntegers\nTestGeneratedReceiptTypesCoverSemanticMutationCorpus\nTestProtocolSchemaAndGeneratedTypesCoverExactNegativeCorpus'
actual_tests="$(
  go test ./... \
    -list '^(TestBothApprovalFormsVectorTracksAuthoritativeExclusion|TestDetectorHealthGeneratedEmittersRejectInvalidState|TestDetectorHealthGeneratedTypeRejectsMutationCorpus|TestDetectorHealthTaggedKnowledgeRejectsInvalidVariants|TestGeneratedActiveDefenseTypesDecodeReencodeAndReject|TestGeneratedProtocolTypesPreserveApprovalAndAggregateBudgetFields|TestGeneratedReceiptEmittersRejectUnsafePortableIntegers|TestGeneratedReceiptTypesCoverSemanticMutationCorpus|TestProtocolSchemaAndGeneratedTypesCoverExactNegativeCorpus)$' |
    awk '/^Test/ { print $1 }' |
    LC_ALL=C sort
)"
test -n "${actual_tests}"
test "${actual_tests}" = "${expected_tests}"
go test ./... \
  -run '^(TestBothApprovalFormsVectorTracksAuthoritativeExclusion|TestDetectorHealthGeneratedEmittersRejectInvalidState|TestDetectorHealthGeneratedTypeRejectsMutationCorpus|TestDetectorHealthTaggedKnowledgeRejectsInvalidVariants|TestGeneratedActiveDefenseTypesDecodeReencodeAndReject|TestGeneratedProtocolTypesPreserveApprovalAndAggregateBudgetFields|TestGeneratedReceiptEmittersRejectUnsafePortableIntegers|TestGeneratedReceiptTypesCoverSemanticMutationCorpus|TestProtocolSchemaAndGeneratedTypesCoverExactNegativeCorpus)$' \
  -count=1
""".strip()
EXPECTED_ACTIVE_DEFENSE_STEPS = (
    (
        "Install Apalache",
        './tools/install-apalache.sh\necho "${HOME}/.local/bin" >> "${GITHUB_PATH}"',
    ),
    ("Information-flow behavior and formal model", "./scripts/check-flow-security.sh"),
    ("Deception boundary behavior", "./scripts/check-deception-security.sh"),
    ("Response recovery behavior", "./scripts/check-response-recovery.sh"),
    (
        "Active defense acceptance behavior",
        "./scripts/check-active-defense-conformance.sh",
    ),
    (
        "Protocol primitive concurrency",
        "./scripts/check-protocol-primitives-concurrency.sh",
    ),
    ("Protocol peer negotiation", "./scripts/check-protocol-peer-negotiation.sh"),
)
EXPECTED_ADVERSARIAL_EVIDENCE_STEPS = (
    ("Install cargo-mutants", "cargo install cargo-mutants --locked --version 25.3.1"),
    (
        "Verify gate rejection behavior",
        "scripts/tests/check-security-adversarial-evidence.test.sh",
    ),
    (
        "Verify freshness-bound mutation evidence",
        "./scripts/check-security-adversarial-evidence.sh --release",
    ),
)
EXPECTED_LINUX_RELEASE_STEPS = (
    (
        "Verify designated runner contract",
        'exec > >(tee "${RUNNER_TEMP}/runner-contract.log") 2>&1\n'
        'test "$(uname -s):$(uname -m)" = "Linux:x86_64"\n'
        "command -v cc\n"
        "test -r /proc/self/status\n"
        "python3 scripts/check-linux-enforcement-stack.py",
    ),
    (
        "Verify committed adversarial bindings",
        'exec > >(tee "${RUNNER_TEMP}/committed-adversarial-evidence.log") 2>&1\n'
        "./scripts/check-security-adversarial-evidence.sh --require-complete",
    ),
    (
        "Key transparency designated-runner mechanics",
        'exec > >(tee "${RUNNER_TEMP}/key-log-transparency.log") 2>&1\n'
        "./scripts/check-keyring-transparency.sh",
    ),
    (
        "Secret broker Linux release boundary",
        'exec > >(tee "${RUNNER_TEMP}/broker-boundary.log") 2>&1\n'
        "./scripts/check-secret-broker-boundary.sh --release",
    ),
    (
        "Parent-child exec observation and cage probes",
        'exec > >(tee "${RUNNER_TEMP}/cage-enforcement.log") 2>&1\n'
        "./scripts/check-cage-enforcement.sh --release",
    ),
    (
        "Rerun designated Linux campaign controls",
        r"""
exec > >(tee "${RUNNER_TEMP}/linux-adversarial-controls.log") 2>&1
campaigns=(
  broker_plaintext_custody
  sandbox_fd_leak
  sandbox_helper_substitution
  sandbox_path_swap
  sandbox_symlink_escape
  sandbox_syscall_escape
)
for campaign in "${campaigns[@]}"; do
  python3 scripts/check-security-adversarial-evidence.py \
    --campaign "${campaign}" \
    --output "${RUNNER_TEMP}/final-${campaign}"
done
git diff --exit-code
""".strip(),
    ),
    (
        "Forward-only migration state mechanics",
        'exec > >(tee "${RUNNER_TEMP}/migration-state-store.log") 2>&1\n'
        "cargo test -p chio-store-sqlite --test enterprise_migration_state",
    ),
    (
        "Strict cage lint",
        "cargo clippy -p chio-cage --all-targets --features real-linux-enforcement -- -D warnings",
    ),
)
EXPECTED_CAPTURE_BUILD_RUN = (
    "cargo build -p chio-control-plane --bin chio-enterprise-evidence"
)
EXPECTED_KANI_ENROLLMENT_RUN = r"""
python3 scripts/check-kani-public-harnesses.py
python3 scripts/tests/check-kani-public-harnesses.test.py
""".strip()
EXPECTED_KANI_MANIFEST_RUN = "./scripts/run-kani-manifest.sh --lane pr"
EXPECTED_ADMIN_AUDIT_ENV = {
    "GH_TOKEN": "${{ github.token }}",
    "CHECK_SHA": "${{ github.event.pull_request.merge_commit_sha || github.sha }}",
    "PR_NUMBER": "${{ github.event.pull_request.number || '' }}",
}
EXPECTED_ADMIN_EVENTS = {
    "pull_request": {"types": ["closed"]},
    "workflow_dispatch": "",
}
EXPECTED_ADMIN_PERMISSIONS = {
    "checks": "read",
    "contents": "read",
    "pull-requests": "write",
}
EXPECTED_ADMIN_JOB_IF = (
    "github.event_name == 'workflow_dispatch' || "
    "github.event.pull_request.merged == true"
)
EXPECTED_ADMIN_CHECKOUT = {
    "uses": "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "with": {"fetch-depth": "1"},
}
EXPECTED_ADMIN_AUDIT_RUN = r"""
set -euo pipefail

required_checks=(
  "Security mirror / Build, lint, test"
  "Security mirror / MSRV build and test"
  "Security mirror / cargo-vet (locked supply-chain audit)"
  "Security mirror / cargo-deny (supply-chain bans/advisories/licenses)"
  "Security contract"
)

gh api \
  -H "Accept: application/vnd.github+json" \
  "repos/${GITHUB_REPOSITORY}/commits/${CHECK_SHA}/check-runs" \
  --paginate \
  --jq '.check_runs[] | [.name, .status, (.conclusion // "pending"), .html_url] | @tsv' \
  > check-runs.tsv

{
  echo "## Admin override audit"
  echo
  echo "Protected merge commit: \`${CHECK_SHA}\`"
  echo
  echo "| Required check | Status | Conclusion | Run |"
  echo "|----------------|--------|------------|-----|"
} > audit.md

red=0
for check in "${required_checks[@]}"; do
  line="$(awk -F '\t' -v want="${check}" '$1 == want {print; found=1; exit} END {if (!found) exit 1}' check-runs.tsv || true)"
  if [[ -z "${line}" ]]; then
    status="missing"
    conclusion="missing"
    url=""
    red=1
  else
    IFS=$'\t' read -r _name status conclusion url <<< "${line}"
    case "${status}:${conclusion}" in
      completed:success|completed:neutral|completed:skipped)
        ;;
      *)
        red=1
        ;;
    esac
  fi

  if [[ -n "${url}" ]]; then
    run_cell="[run](${url})"
  else
    run_cell="n/a"
  fi
  printf '| %s | %s | %s | %s |\n' "${check}" "${status}" "${conclusion}" "${run_cell}" >> audit.md
done

cat audit.md >> "${GITHUB_STEP_SUMMARY}"

if [[ "${red}" == "1" && -n "${PR_NUMBER}" ]]; then
  {
    echo "Admin override audit detected a missing or non-success required check on protected merge commit \`${CHECK_SHA}\`."
    echo
    cat audit.md
  } > comment.md
  gh pr comment "${PR_NUMBER}" --body-file comment.md
fi
""".strip()
EXPECTED_CI_EVIDENCE_STEPS = (
    ("Formal traceability gate", "bash scripts/check-mapping.sh"),
    ("Workspace format", "cargo fmt --all -- --check"),
    ("Workspace clippy", "cargo clippy --workspace --all-targets -- -D warnings"),
    ("Workspace build", "cargo build --workspace"),
    ("Workspace tests", "cargo test --workspace --exclude chio-wasm-guards"),
    (
        "Protocol-primitives production Loom gate",
        "./scripts/check-protocol-primitives-concurrency.sh",
    ),
    ("Protocol peer-negotiation gate", "./scripts/check-protocol-peer-negotiation.sh"),
    ("Wasm guards library tests", "cargo test -p chio-wasm-guards --lib"),
    (
        "Wasm guards Python SDK round-trip tests",
        "cargo test -p chio-wasm-guards --test py_guard_integration -- --nocapture",
    ),
    ("Exact workspace test gate", "cargo test --workspace"),
    ("Patch hygiene", "git diff --check"),
)
EXPECTED_COMMON_CI_STEP_ENV = {
    "CARGO_BUILD_JOBS": "1",
    "RUSTFLAGS": "${{ env.CHIO_CI_RUSTFLAGS }} -C debuginfo=0",
}
EXPECTED_CI_EVIDENCE_EXTRAS = {
    name: {"env": EXPECTED_COMMON_CI_STEP_ENV}
    for name in (
        "Workspace format",
        "Workspace clippy",
        "Workspace build",
        "Workspace tests",
        "Protocol-primitives production Loom gate",
        "Protocol peer-negotiation gate",
        "Wasm guards library tests",
        "Wasm guards Python SDK round-trip tests",
        "Exact workspace test gate",
    )
}
EXPECTED_KANI_STEP_EXTRAS = {
    "Verify all PR Kani harnesses": {
        "env": {"CARGO_BUILD_JOBS": "1", "CARGO_INCREMENTAL": "0"}
    }
}
EXPECTED_MSRV_RUN = r"""
cargo build --workspace
cargo test --workspace --exclude chio-conformance --exclude chio-wasm-guards --exclude chio-formal-diff-tests
cargo test -p chio-formal-diff-tests --no-run
cargo test -p chio-wasm-guards --lib
""".strip()
EXPECTED_MSRV_EXTRAS = {
    "MSRV workspace lane": {
        "env": {
            "CARGO_BUILD_JOBS": "1",
            "CARGO_TARGET_DIR": "${{ runner.temp }}/chio-msrv-target",
            "RUSTFLAGS": "${{ env.CHIO_CI_RUSTFLAGS }} -C debuginfo=0",
        }
    }
}
EXPECTED_CARGO_VET_STEPS = (("cargo vet --locked", "cargo vet --locked"),)
EXPECTED_CARGO_DENY_STEPS = (
    ("cargo deny check advisories", "cargo deny check advisories"),
    ("cargo deny check licenses", "cargo deny check licenses"),
    ("cargo deny check sources", "cargo deny check sources"),
    ("cargo deny check bans", "cargo deny check bans"),
    (
        "Check external wildcard dependencies",
        "python3 scripts/check-external-wildcard-deps.py",
    ),
    (
        "cargo deny duplicate baseline",
        "python3 scripts/check-cargo-deny-duplicate-baseline.py",
    ),
)
EXPECTED_REFRESH_CHECKSUM_RUN = r"""
set -euo pipefail
patch="${RUNNER_TEMP}/linux-evidence.patch"
git diff --binary > "${patch}"
test -s "${patch}"
printf '%s\n' "${EVIDENCE_SOURCE_SHA}" > "${RUNNER_TEMP}/source-sha.txt"
(
  cd "${RUNNER_TEMP}"
  sha256sum linux-evidence.patch > linux-evidence.patch.sha256
)
""".strip()
EXPECTED_ELAN_ENV = {
    "ELAN_VERSION": "v4.2.1",
    "ELAN_TARBALL_SHA256": "4e717523217af592fa2d7b9c479410a31816c065d66ccbf0c2149337cfec0f5c",
}
EXPECTED_ELAN_INSTALL_RUN = r"""
set -euo pipefail
curl -fsSL \
  "https://github.com/leanprover/elan/releases/download/${ELAN_VERSION}/elan-x86_64-unknown-linux-gnu.tar.gz" \
  -o /tmp/elan-x86_64-unknown-linux-gnu.tar.gz
echo "${ELAN_TARBALL_SHA256}  /tmp/elan-x86_64-unknown-linux-gnu.tar.gz" | sha256sum -c -
tar -xzf /tmp/elan-x86_64-unknown-linux-gnu.tar.gz -C /tmp
/tmp/elan-init -y --default-toolchain none
echo "$HOME/.elan/bin" >> "$GITHUB_PATH"
echo "ELAN_HOME=$HOME/.elan" >> "$GITHUB_ENV"
""".strip()
EXPECTED_LEAN_PRIME_RUN = r"""
set -euo pipefail
toolchain="$(tr -d '\r\n' < formal/lean4/Chio/lean-toolchain)"
"$HOME/.elan/bin/elan" toolchain install "$toolchain"
(
  cd formal/lean4/Chio
  "$HOME/.elan/bin/lake" --version
)
""".strip()
EXPECTED_UV_ACTION = "astral-sh/setup-uv@caf0cab7a618c569241d31dcd442f54681755d39"
EXPECTED_UV_INPUTS = {"version": "0.5.11"}
EXPECTED_APALACHE_CONCURRENCY = {
    "group": "apalache-safety-${{ github.workflow }}-${{ github.ref }}",
    "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
}
EXPECTED_THREAT_CONCURRENCY = {
    "group": "threat-model-coverage-${{ github.workflow }}-${{ github.ref }}",
    "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
}
EXPECTED_CI_PYTHON_VALIDATORS_RUN = (
    "python -m pip install --disable-pip-version-check PyYAML==6.0.2"
)
EXPECTED_ENTERPRISE_PYTHON_VALIDATORS_RUN = (
    "python -m pip install --disable-pip-version-check "
    "jsonschema==4.26.0 PyYAML==6.0.2"
)
EXPECTED_APALACHE_SAFETY_RUN = r"""
set -euo pipefail
while IFS="|" read -r cfg spec; do
  apalache-mc check \
    --length=6 \
    --config="${cfg}" \
    "${spec}"
done <<'EOF'
formal/apalache/MCMonotoneLogApalache.cfg|formal/apalache/MonotoneLogApalache.tla
formal/apalache/MCRevocationCutCompleteness.cfg|formal/apalache/RevocationCutCompleteness.tla
formal/apalache/MCReceiptBeforeAllow.cfg|formal/apalache/ReceiptBeforeAllow.tla
formal/apalache/MCKernelTransitionCancelSafe.cfg|formal/apalache/KernelTransitionCancelSafe.tla
formal/tla/MCInformationFlowLattice.cfg|formal/tla/InformationFlowLattice.tla
formal/tla/MCRevocationPropagation.cfg|formal/tla/RevocationPropagation.tla
formal/tla/MCDelegationDepthBound.cfg|formal/tla/DelegationDepthBound.tla
EOF
""".strip()
EXPECTED_APALACHE_MUTATION_RUN = r"""
set -euo pipefail
negative_log="$(mktemp)"
trap 'rm -f "${negative_log}"' EXIT
if apalache-mc check \
  --length=6 \
  --config=formal/tla/_negative_tests/MCInformationFlowLatticeReaderDirectionBroken.cfg \
  formal/tla/_negative_tests/InformationFlowLatticeReaderDirectionBroken.tla \
  2>&1 | tee "${negative_log}"; then
  echo "reader-direction mutation unexpectedly satisfied SafetyInv" >&2
  exit 1
fi
grep -Eq "state invariant [0-9]+ violated" "${negative_log}"
grep -Fq "The outcome is: Error" "${negative_log}"
""".strip()
EXPECTED_THREAT_GATE_COMMANDS = {
    "Run threat-model coverage gate (file-existence)": "bash scripts/check-threat-coverage.sh",
    "Run threat-model mutants gate (per-row evidence)": "bash scripts/check-threat-coverage-mutants.sh",
    "Self-test the coverage gate (state matrix)": "bash scripts/tests/check-threat-coverage.test.sh",
    "Self-test the mutants gate (evidence matrix)": "bash scripts/tests/check-threat-coverage-mutants.test.sh",
    "Cargo test - threat_model_schema_test": "cargo test -p chio-spec-codegen --test threat_model_schema_test",
    "Cargo test - threat-model integration test": "cargo test -p chio-conformance --test threats",
}


def load_workflow(path: Path) -> dict[str, object]:
    try:
        body = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ContractError(f"{path}: unreadable workflow: {error}") from error
    if not isinstance(body, dict):
        raise ContractError(f"{path}: workflow root is not a mapping")
    return body


def workflow_jobs(workflow: dict[str, object]) -> dict[str, object]:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        raise ContractError("workflow jobs are not a mapping")
    return jobs


def job(workflow: dict[str, object], identifier: str) -> dict[str, object]:
    jobs = workflow_jobs(workflow)
    if not isinstance(jobs.get(identifier), dict):
        raise ContractError(f"missing workflow job: {identifier}")
    return jobs[identifier]


def run_lines(job_body: dict[str, object]) -> set[str]:
    steps = job_body.get("steps")
    if not isinstance(steps, list):
        return set()
    lines: set[str] = set()
    for step in steps:
        if not isinstance(step, dict) or not isinstance(step.get("run"), str):
            continue
        lines.update(line.strip() for line in step["run"].splitlines() if line.strip())
    return lines


def named_step(job_body: dict[str, object], name: str) -> dict[str, object]:
    steps = job_body.get("steps")
    if not isinstance(steps, list):
        raise ContractError(f"job has no steps while looking for: {name}")
    matches = [
        step for step in steps if isinstance(step, dict) and step.get("name") == name
    ]
    if len(matches) != 1:
        raise ContractError(f"expected exactly one workflow step named: {name}")
    return matches[0]


def step_position(job_body: dict[str, object], name: str) -> int:
    steps = job_body.get("steps")
    if not isinstance(steps, list):
        raise ContractError(f"job has no steps while looking for: {name}")
    positions = [
        index
        for index, step in enumerate(steps)
        if isinstance(step, dict) and step.get("name") == name
    ]
    if len(positions) != 1:
        raise ContractError(f"expected exactly one workflow step named: {name}")
    return positions[0]


def normalized_expression(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())


def contains_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(contains_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(contains_key(child, key) for child in value)
    return False


def contains_text(value: object, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, dict):
        return any(
            contains_text(key, needle) or contains_text(child, needle)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(contains_text(child, needle) for child in value)
    return False


def action_uses(workflow: dict[str, object]) -> list[str]:
    uses: list[str] = []
    for body in workflow_jobs(workflow).values():
        if not isinstance(body, dict):
            continue
        steps = body.get("steps")
        if not isinstance(steps, list):
            continue
        uses.extend(
            step["uses"]
            for step in steps
            if isinstance(step, dict) and isinstance(step.get("uses"), str)
        )
    return uses


def all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        strings: list[str] = []
        for key, child in value.items():
            strings.extend(all_strings(key))
            strings.extend(all_strings(child))
        return strings
    if isinstance(value, list):
        strings = []
        for child in value:
            strings.extend(all_strings(child))
        return strings
    return []


def forbidden_inherited_env(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        env = value.get("env")
        if isinstance(env, dict):
            found.update(FORBIDDEN_INHERITED_ENV.intersection(env))
        for child in value.values():
            found.update(forbidden_inherited_env(child))
    elif isinstance(value, list):
        for child in value:
            found.update(forbidden_inherited_env(child))
    return found


def normalized_contract_digest(value: object) -> str:
    def normalize(current: object, key: str | None = None) -> object:
        if isinstance(current, dict):
            return {
                child_key: normalize(child, child_key)
                for child_key, child in sorted(current.items())
            }
        if isinstance(current, list):
            return [normalize(child) for child in current]
        if isinstance(current, str) and key == "run":
            return current.strip()
        return current

    encoded = json.dumps(
        normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_job_digest(
    job_body: dict[str, object], expected_digest: str, contract: str
) -> None:
    if normalized_contract_digest(job_body) != expected_digest:
        raise ContractError(f"{contract} normalized job contract changed")


def validate_step_inventory(
    job_body: dict[str, object],
    expected: tuple[tuple[str | None, str | None, str | None], ...],
    contract: str,
) -> None:
    steps = job_body.get("steps")
    if not isinstance(steps, list) or any(not isinstance(step, dict) for step in steps):
        raise ContractError(f"{contract} step inventory is malformed")
    observed = tuple(
        (step.get("name"), step.get("id"), step.get("uses")) for step in steps
    )
    if observed != expected:
        raise ContractError(f"{contract} step inventory changed")


def require_run_markers(
    job_body: dict[str, object],
    step_name: str,
    markers: tuple[str, ...],
    error: str,
) -> str:
    run = named_step(job_body, step_name).get("run")
    if not isinstance(run, str) or any(marker not in run for marker in markers):
        raise ContractError(error)
    return run


def secret_reference_locations(
    value: object, path: tuple[object, ...] = ()
) -> list[tuple[tuple[object, ...], str]]:
    locations: list[tuple[tuple[object, ...], str]] = []
    if isinstance(value, str):
        if "${{ secrets." in value:
            locations.append((path, value))
    elif isinstance(value, dict):
        for key, child in value.items():
            locations.extend(secret_reference_locations(child, (*path, key)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            locations.extend(secret_reference_locations(child, (*path, index)))
    return locations


def grants_actions_write(permissions: object) -> bool:
    return permissions == "write-all" or (
        isinstance(permissions, dict) and permissions.get("actions") == "write"
    )


def validate_global_workflow_boundaries(root: Path) -> None:
    actionlint_config = root / ".github/actionlint.yaml"
    if actionlint_config.is_symlink() or not actionlint_config.is_file():
        raise ContractError("actionlint configuration is not a regular file")
    try:
        actionlint = yaml.load(
            actionlint_config.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
        )
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ContractError(f"unreadable actionlint configuration: {error}") from error
    if actionlint != EXPECTED_ACTIONLINT_CONFIG:
        raise ContractError("actionlint configuration changed")

    workflow_directory = root / ".github/workflows"
    workflow_paths = sorted(
        set(workflow_directory.glob("*.yml")) | set(workflow_directory.glob("*.yaml"))
    )
    if not workflow_paths:
        raise ContractError("repository has no workflow inventory")

    actions_write_declarations: set[tuple[str, str | None]] = set()
    actions_write_jobs: set[tuple[str, str]] = set()
    publisher_key_locations: list[tuple[str, tuple[object, ...], str]] = []
    for path in workflow_paths:
        if path.is_symlink() or not path.is_file():
            raise ContractError(f"workflow is not a regular file: {path.name}")
        workflow = load_workflow(path)
        workflow_permissions = workflow.get("permissions")
        if grants_actions_write(workflow_permissions):
            actions_write_declarations.add((path.name, None))
        for identifier, body in workflow_jobs(workflow).items():
            if not isinstance(body, dict):
                continue
            job_permissions = body.get("permissions")
            if grants_actions_write(job_permissions):
                actions_write_declarations.add((path.name, identifier))
            effective_permissions = (
                job_permissions if "permissions" in body else workflow_permissions
            )
            if grants_actions_write(effective_permissions):
                actions_write_jobs.add((path.name, identifier))
            if "environment" not in body:
                continue
            expected = ALLOWED_WORKFLOW_ENVIRONMENTS.get((path.name, identifier))
            if expected is None or body["environment"] != expected:
                raise ContractError(
                    f"unreviewed workflow environment: {path.name}:{identifier}"
                )

        for location, reference in secret_reference_locations(workflow):
            if "CHIO_SECURITY_APP_PRIVATE_KEY_PEM" in reference:
                publisher_key_locations.append((path.name, location, reference))

    if actions_write_declarations != EXPECTED_ACTIONS_WRITE_DECLARATIONS:
        raise ContractError(
            "Actions write permission escapes its exact trusted dispatcher declarations"
        )
    if actions_write_jobs != EXPECTED_ACTIONS_WRITE_JOBS:
        raise ContractError(
            "Actions write permission escapes its exact trusted dispatcher jobs"
        )
    if tuple(publisher_key_locations) != PUBLISHER_PRIVATE_KEY_LOCATIONS:
        raise ContractError(
            "publisher private key reference escapes its exact protected step"
        )


def markdown_section(document: str, heading: str, next_heading: str) -> str:
    start_marker = f"## {heading}\n"
    end_marker = f"## {next_heading}\n"
    start = document.find(start_marker)
    end = document.find(end_marker, start + len(start_marker))
    if start < 0 or end < 0:
        raise ContractError(f"missing environment contract section: {heading}")
    return document[start:end]


def validate_environment_provisioning_document(root: Path) -> None:
    path = root / "docs/security/committed-linux-evidence.md"
    if path.is_symlink() or not path.is_file():
        raise ContractError("committed Linux evidence contract is not a regular file")
    document = path.read_text(encoding="utf-8")
    definition_markers = (
        "`CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA=B`",
        "finalizer, publisher, and revoker treat `B` as the authorized workflow-content\nbaseline.",
        "Each authenticates its actual execution head from the Actions run API\nand requires the workflow blob at that head to equal the blob at `B`.",
        "The `ci.yml` caller must separately pin\nthe reusable workflow to the same immutable full `B` SHA.",
        "pin and definition variable as one authority rotation only after a new complete\nworkflow set has been reviewed.",
        "Also set\n`CHIO_SECURITY_APP_ID` as a repository variable.",
        "The App ID is public,\nrepository-scoped configuration required by the unprotected secret-free\nrevocation listener as well as the protected publisher.",
    )
    if any(marker not in document for marker in definition_markers):
        raise ContractError("trusted security definition variable contract changed")
    signing = markdown_section(
        document, "Protected signing environment", "Dedicated security check publisher"
    )
    signing_markers = (
        "Create `enterprise-evidence-signing` with a zero-minute wait, no reviewers,\n"
        "and a custom deployment branch policy containing only `main`:",
        "repos/bb-connor/arc/environments/enterprise-evidence-signing \\\n"
        "  --input -",
        "repos/bb-connor/arc/environments/enterprise-evidence-signing/deployment-branch-policies \\\n"
        "  -f name=main \\\n"
        "  -f type=branch",
        "Disable administrator bypass for `enterprise-evidence-signing` in the\n"
        "repository UI. Set only the environment secret\n"
        "`CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX`.",
        "Do not create a repository or\norganization copy of the signing seed.",
        "A pull-request workflow must never be\neligible to enter this environment.",
    )
    if any(marker not in signing for marker in signing_markers):
        raise ContractError("signing environment provisioning contract changed")

    publisher = document[document.find("## Dedicated security check publisher\n") :]
    publisher_markers = (
        "GitHub requires `statuses:write` for an App to\n"
        "be selected as the expected source of an integration-bound ruleset check.",
        "publisher narrows its short-lived installation token to Checks write only",
        "Create the `security-check-publisher` environment with a zero-minute wait, no\n"
        "reviewers, and a custom deployment branch policy containing only `main`:",
        "repos/bb-connor/arc/environments/security-check-publisher \\\n" "  --input -",
        "repos/bb-connor/arc/environments/security-check-publisher/deployment-branch-policies \\\n"
        "  -f name=main \\\n"
        "  -f type=branch",
        "Disable administrator bypass for `security-check-publisher` in the repository\n"
        "UI.",
        "Set only the environment variable `CHIO_SECURITY_APP_INSTALLATION_ID` and\n"
        "the environment secret `CHIO_SECURITY_APP_PRIVATE_KEY_PEM`.",
        "Keep\n`CHIO_SECURITY_APP_ID` at repository scope and do not shadow it with an\n"
        "environment variable.",
        "Do not create a repository or organization copy of the\n"
        "installation ID or private-key secret.",
        "Publication is\nidempotent for `(<PR>, <E>, <M>, <S>)`.",
        "Any prior failure in any of the five\nexact App-and-name namespaces is sticky",
        "Labels authorize and describe capture only. Label\nchanges after capture cannot grant, renew, or revoke a published authority.",
        "A trusted default-branch `workflow_run` listener handles bad CI completions and\n"
        "eligible failed finalizer publishers.",
        "Every completed CI conclusion other than\nsuccess, including an absent conclusion, is failure-authoritative.",
        "Both paths\nbind the immutable `workflow_run.run_attempt` carried by the event, retrieve the\nexact historical attempt endpoint, and require the returned run and attempt\nidentity to match. They never substitute the mutable current-run projection.",
        "The listener never trusts nested workflow-run pull request metadata.",
        "verifies the signed\nbinding artifact and certificate whenever the builder succeeded.",
        "advanced from `(base1, M1)` to `(base2, M2)`, it targets only `M1`,",
        "cannot create a missing namespace,\nand never writes to `M2`.",
        "For a failed finalizer, it authenticates the exact `N/E/M/S/nonce`\n"
        "title, historical default-branch workflow blob, bot actors, ordered merge\n"
        "parents, exact four-job attempt, and capture-owned dispatch intent. Validation,\n"
        "signing, and publication authorization must have completed successfully, while\n"
        "the publication job must have started and completed unsuccessfully. The exact\n"
        "dedicated App success check must carry a `details_url` bound to that failed run\n"
        "and attempt. Earlier finalizer failures are ineligible because they cannot have\n"
        "published dedicated authority. Later source or definition rotation does not\n"
        "erase the authenticated historical failure. The listener can normalize only\n"
        "preexisting exact authority created by that failed attempt and cannot create a\n"
        "namespace.",
        "First, freeze every future\n"
        "publication by setting `CHIO_COMMITTED_LINUX_EVIDENCE_SHA` to the reserved\n"
        "all-zero SHA.",
        "Keep the App, installation, publisher environment, and private\n"
        "key available until revocation verifies:",
        "gh variable set CHIO_COMMITTED_LINUX_EVIDENCE_SHA \\\n"
        "  --body '0000000000000000000000000000000000000000'",
        "gh workflow run security-contract-revocation.yml \\\n" "  --ref main",
        "-f merge_commit_sha='<M>'",
        "The protected manual revoker requires the all-zero freeze, revalidates the\n"
        "requested live `(<PR>, <E>, <M>, <S>)` tuple",
        "It paginates the four App `15368` mirror\nnamespaces and the dedicated-App `Security contract` namespace on `M`",
        "normalization is mandatory because a ruleset binds check name and App",
        "absent namespace receives an exact completed-failure tombstone.",
        "preserving each external ID\nand source metadata",
        "renamed to a unique failure-only superseded name.",
        "requires one exact failed member per namespace",
        "Third,\n"
        "withdraw or replace the affected source, policy, App, installation, key,\n"
        "environment, or ruleset authority.",
        "A repeated revocation is idempotent. Never\n"
        "restore authority for the same test merge.",
        "Publication and revocation use the same non-cancelling maximum-queue\n"
        "`security-check-authority-<M>` concurrency group.",
        "Both jobs set `queue: max`,\n"
        "so a later authority mutation cannot replace an earlier pending member.",
        "Its success-publication branch\nis POST-only and never updates an existing check.",
        "before every success POST, immediately after every\nsuccess POST, and after the complete set",
        "After PR or merge-ref drift, the\npublisher branch may normalize existing authority on historical `M` but cannot\ncreate a missing namespace.",
        "For every matching run it reads the current\nmaximum attempt, retrieves every exact historical attempt from one through that\nmaximum, and fails closed before GitHub's 1,000-result filtered-search ceiling.",
        "A completed non-success attempt dominates any newer incomplete attempt and\nimmediately selects the failure-only branch.",
        "An incomplete history blocks\npublication when no bad completion exists.",
        "The\nwhole scan retries at most three times and fails closed if a run appears or any\nmaximum advances.",
        "including an\nearlier failure followed by a successful rerun",
        "This is deliberately conservative: any completed non-success CI\n"
        "completion for the current `E` and `M` can permanently tombstone\n"
        "that tuple",
        '{context: "Security mirror / Build, lint, test", integration_id: 15368}',
        '{context: "Security mirror / MSRV build and test", integration_id: 15368}',
        '{context: "Security mirror / cargo-vet (locked supply-chain audit)", integration_id: 15368}',
        '{context: "Security mirror / cargo-deny (supply-chain bans/advisories/licenses)", integration_id: 15368}',
        '{context: "Security contract", integration_id: $security_app_id}',
    )
    if any(marker not in publisher for marker in publisher_markers):
        raise ContractError("publisher environment provisioning contract changed")


def validate_exact_steps(
    job_body: dict[str, object],
    expected: tuple[tuple[str, str], ...],
    contract: str,
    expected_extras: dict[str, dict[str, object]] | None = None,
) -> None:
    positions: list[int] = []
    for step_name, expected_run in expected:
        step = named_step(job_body, step_name)
        if "if" in step:
            raise ContractError(
                f"{contract} conditionally skips mandatory step: {step_name}"
            )
        extras = (expected_extras or {}).get(step_name, {})
        expected_keys = {"name", "run"} | set(extras)
        if set(step) != expected_keys or any(
            step.get(key) != value for key, value in extras.items()
        ):
            raise ContractError(f"{contract} changes mandatory step shape: {step_name}")
        observed_run = step.get("run")
        if (
            not isinstance(observed_run, str)
            or observed_run.strip() != expected_run.strip()
        ):
            raise ContractError(f"{contract} changes mandatory step body: {step_name}")
        positions.append(step_position(job_body, step_name))
    if positions != sorted(positions):
        raise ContractError(f"{contract} reorders mandatory evidence steps")


def parse_dockerfile(document: str) -> tuple[tuple[str, str], ...]:
    if any(
        re.fullmatch(r"#\s*(?:syntax|escape|check)\s*=.*", line.strip(), re.I)
        for line in document.splitlines()
    ):
        raise ContractError("security execution image uses a mutable parser directive")
    instructions: list[tuple[str, str]] = []
    current: list[str] = []
    for raw_line in document.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        if continued:
            stripped = stripped[:-1].rstrip()
        current.append(stripped)
        if continued:
            continue
        logical = " ".join(current)
        current = []
        keyword, separator, value = logical.partition(" ")
        if not separator or not re.fullmatch(r"[A-Za-z]+", keyword):
            raise ContractError("security execution image has a malformed instruction")
        instructions.append((keyword.upper(), " ".join(value.split())))
    if current:
        raise ContractError("security execution image has an unterminated instruction")
    return tuple(instructions)


def shell_clauses(run: str) -> tuple[str, ...]:
    return tuple(clause.strip() for clause in run.split(" && "))


def require_exact_file_digest(path: Path, expected: str, description: str) -> str:
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise ContractError(f"{description} digest ratchet changed")
    return observed


def validate_security_dockerfile(root: Path, document: str) -> None:
    apk_lock = root / "deploy/docker/security-evidence-apk.lock"
    apk_digest = require_exact_file_digest(
        apk_lock, EXPECTED_APK_LOCK_SHA256, "security APK inventory"
    )
    cargo_digest = require_exact_file_digest(
        root / "Cargo.lock", EXPECTED_CARGO_LOCK_SHA256, "workspace Cargo.lock"
    )
    toolchain_digest = require_exact_file_digest(
        root / "rust-toolchain.toml",
        EXPECTED_RUST_TOOLCHAIN_SHA256,
        "workspace Rust toolchain",
    )
    apk_lines = apk_lock.read_text(encoding="utf-8").splitlines()
    if (
        len(apk_lines) != 225
        or apk_lines != sorted(apk_lines)
        or len(set(apk_lines)) != len(apk_lines)
        or any(not line or line != line.strip() for line in apk_lines)
    ):
        raise ContractError("security APK inventory is not canonical and exact")

    instructions = parse_dockerfile(document)
    if tuple(keyword for keyword, _value in instructions) != (
        "FROM",
        "COPY",
        "RUN",
        "RUN",
        "RUN",
        "WORKDIR",
        "COPY",
        "ENV",
        "RUN",
        "WORKDIR",
        "ENTRYPOINT",
    ):
        raise ContractError("security execution image instruction graph changed")
    if instructions[0][1] != EXPECTED_SECURITY_IMAGE_FROM:
        raise ContractError("security execution image has an unpinned build stage")
    if instructions[1][1] != (
        "deploy/docker/security-evidence-apk.lock /tmp/security-evidence-apk.lock"
    ):
        raise ContractError("security execution image APK inventory copy changed")

    expected_apk = (
        "apk add --no-cache " + " ".join(EXPECTED_DIRECT_APK_PACKAGES),
        "apk info -v | LC_ALL=C sort > /tmp/security-evidence-apk.actual",
        "cmp /tmp/security-evidence-apk.lock /tmp/security-evidence-apk.actual",
        f"echo '{apk_digest} /tmp/security-evidence-apk.lock' | sha256sum -c -",
        "rm /tmp/security-evidence-apk.lock /tmp/security-evidence-apk.actual",
    )
    if shell_clauses(instructions[2][1]) != expected_apk:
        raise ContractError("security execution image APK closure changed")

    expected_rust_components = (
        "curl --proto '=https' --tlsv1.2 --fail --location --output "
        "/tmp/clippy.tar.gz https://static.rust-lang.org/dist/2026-01-22/"
        "clippy-1.93.0-x86_64-unknown-linux-musl.tar.gz",
        f"echo '{EXPECTED_CLIPPY_ARCHIVE_SHA256} /tmp/clippy.tar.gz' | sha256sum -c -",
        "tar -xzf /tmp/clippy.tar.gz -C /tmp",
        "/tmp/clippy-1.93.0-x86_64-unknown-linux-musl/install.sh "
        "--prefix=/usr/local/rustup/toolchains/1.93.0-x86_64-unknown-linux-musl "
        "--disable-ldconfig",
        "curl --proto '=https' --tlsv1.2 --fail --location --output "
        "/tmp/rustfmt.tar.gz https://static.rust-lang.org/dist/2026-01-22/"
        "rustfmt-1.93.0-x86_64-unknown-linux-musl.tar.gz",
        f"echo '{EXPECTED_RUSTFMT_ARCHIVE_SHA256} /tmp/rustfmt.tar.gz' | sha256sum -c -",
        "tar -xzf /tmp/rustfmt.tar.gz -C /tmp",
        "/tmp/rustfmt-1.93.0-x86_64-unknown-linux-musl/install.sh "
        "--prefix=/usr/local/rustup/toolchains/1.93.0-x86_64-unknown-linux-musl "
        "--disable-ldconfig",
        "printf '%s\\n' cargo-x86_64-unknown-linux-musl "
        "clippy-x86_64-unknown-linux-musl rust-std-x86_64-unknown-linux-musl "
        "rustc-x86_64-unknown-linux-musl rustfmt-x86_64-unknown-linux-musl "
        "> /tmp/security-evidence-rust-components.expected",
        "rustup component list --installed | LC_ALL=C sort > "
        "/tmp/security-evidence-rust-components.actual",
        "cmp /tmp/security-evidence-rust-components.expected "
        "/tmp/security-evidence-rust-components.actual",
        "rm -rf /tmp/clippy.tar.gz /tmp/clippy-1.93.0-x86_64-unknown-linux-musl "
        "/tmp/rustfmt.tar.gz /tmp/rustfmt-1.93.0-x86_64-unknown-linux-musl "
        "/tmp/security-evidence-rust-components.expected "
        "/tmp/security-evidence-rust-components.actual",
    )
    if shell_clauses(instructions[3][1]) != expected_rust_components:
        raise ContractError("security execution image Rust component closure changed")

    expected_mutants = (
        "curl --proto '=https' --tlsv1.2 --fail --location --output "
        "/tmp/cargo-mutants-25.3.1.crate "
        "https://static.crates.io/crates/cargo-mutants/cargo-mutants-25.3.1.crate",
        f"echo '{EXPECTED_CARGO_MUTANTS_ARCHIVE_SHA256} "
        "/tmp/cargo-mutants-25.3.1.crate' | sha256sum -c -",
        "tar -xzf /tmp/cargo-mutants-25.3.1.crate -C /tmp",
        f"echo '{EXPECTED_CARGO_MUTANTS_LOCK_SHA256} "
        "/tmp/cargo-mutants-25.3.1/Cargo.lock' | sha256sum -c -",
        "cargo install --locked --path /tmp/cargo-mutants-25.3.1 "
        "--root /usr/local/cargo",
        "rm -rf /tmp/cargo-mutants-25.3.1 /tmp/cargo-mutants-25.3.1.crate",
    )
    if shell_clauses(instructions[4][1]) != expected_mutants:
        raise ContractError("security execution image Cargo tool closure changed")
    if instructions[5:8] != (
        ("WORKDIR", "/opt/authorized-source"),
        ("COPY", ". ."),
        (
            "ENV",
            "CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 CARGO_TERM_COLOR=never",
        ),
    ):
        raise ContractError("security execution image source construction changed")

    authority_installs = (
        "install -m 0555 scripts/security-execution-container-entrypoint.py "
        "/opt/chio-security/entrypoint.py",
        "install -m 0555 scripts/security-execution-command-client.py "
        "/opt/chio-security/command-client.py",
        "install -D -m 0555 scripts/security-execution-command-client.py "
        "/opt/chio-security/verifier-bin/cargo",
        "install -D -m 0555 scripts/security-execution-command-client.py "
        "/opt/chio-security/verifier-bin/cc",
        "install -D -m 0555 scripts/security-execution-command-client.py "
        "/opt/chio-security/verifier-bin/ldd",
        "install -m 0444 scripts/check-security-adversarial-evidence.py "
        "/opt/chio-security/check-security-adversarial-evidence.py",
        "install -D -m 0555 scripts/check-linux-enforcement-stack.py "
        "/opt/chio-security/gates/check-linux-enforcement-stack.py",
        "install -D -m 0555 scripts/check-keyring-transparency.sh "
        "/opt/chio-security/gates/check-keyring-transparency.sh",
        "install -D -m 0555 scripts/check-secret-broker-boundary.sh "
        "/opt/chio-security/gates/check-secret-broker-boundary.sh",
        "install -D -m 0555 scripts/check-cage-enforcement.sh "
        "/opt/chio-security/gates/check-cage-enforcement.sh",
        "install -D -m 0555 scripts/check-exact-cargo-test-inventory.py "
        "/opt/chio-security/gates/check-exact-cargo-test-inventory.py",
        "install -D -m 0555 scripts/check-cage-all-target-inventory.py "
        "/opt/chio-security/gates/check-cage-all-target-inventory.py",
        "install -D -m 0555 crates/security/chio-cage/scripts/check-linux-enforcement.sh "
        "/opt/chio-security/gates/check-cage-linux-enforcement.sh",
        "install -m 0444 deploy/docker/security-evidence-seccomp.json "
        "/opt/chio-security/security-evidence-seccomp.json",
    )
    expected_authority = (
        'test "$(rustc --version | cut -d\' \' -f1-2)" = "rustc 1.93.0"',
        'test "$(cargo mutants --version | awk \'{print $2}\')" = "25.3.1"',
        'test "$(cargo clippy --version | cut -d\' \' -f1)" = "clippy"',
        'test "$(cargo fmt --version | cut -d\' \' -f1)" = "rustfmt"',
        f"echo '{cargo_digest} Cargo.lock' | sha256sum -c -",
        f"echo '{toolchain_digest} rust-toolchain.toml' | sha256sum -c -",
        "cargo fetch --locked",
        "mkdir -p /opt/chio-security/cargo-cache",
        "if test -d /usr/local/cargo/registry; then cp -a "
        "/usr/local/cargo/registry /opt/chio-security/cargo-cache/; fi",
        "if test -d /usr/local/cargo/git; then cp -a /usr/local/cargo/git "
        "/opt/chio-security/cargo-cache/; fi",
        *authority_installs,
        "rm -rf /opt/authorized-source",
    )
    if shell_clauses(instructions[8][1]) != expected_authority:
        raise ContractError("security execution image authority graph changed")
    if instructions[9] != ("WORKDIR", "/private/candidate"):
        raise ContractError("security execution image runtime workdir changed")
    try:
        entrypoint = json.loads(instructions[10][1])
    except json.JSONDecodeError as error:
        raise ContractError("security execution image entrypoint is not JSON") from error
    if entrypoint != [
        "/usr/bin/python3",
        "-I",
        "/opt/chio-security/entrypoint.py",
    ]:
        raise ContractError("security execution image entrypoint changed")


def ast_call_name(call: ast.Call) -> str:
    def name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    return name(call.func)


def ast_function_map(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }


def ast_parent_map(root: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: parent
        for parent in ast.walk(root)
        for child in ast.iter_child_nodes(parent)
    }


def statically_dead(
    node: ast.AST, function: ast.FunctionDef, parents: dict[ast.AST, ast.AST]
) -> bool:
    current = node
    while current is not function:
        parent = parents.get(current)
        if parent is None:
            return True
        if isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
        ):
            if parent is not function:
                return True
        if isinstance(parent, ast.If):
            try:
                condition = ast.literal_eval(parent.test)
            except (ValueError, TypeError):
                condition = None
            if condition is False and current in parent.body:
                return True
            if condition is True and current in parent.orelse:
                return True
        if isinstance(parent, ast.While):
            try:
                if ast.literal_eval(parent.test) is False and current in parent.body:
                    return True
            except (ValueError, TypeError):
                pass
        current = parent
    return False


def live_calls(
    function: ast.FunctionDef, call_name: str, parents: dict[ast.AST, ast.AST]
) -> list[ast.Call]:
    return sorted(
        (
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and ast_call_name(node) == call_name
            and not statically_dead(node, function, parents)
        ),
        key=lambda node: (node.lineno, node.col_offset),
    )


def has_control_guard(
    node: ast.AST, function: ast.FunctionDef, parents: dict[ast.AST, ast.AST]
) -> bool:
    current = node
    while current is not function:
        parent = parents.get(current)
        if parent is None:
            return True
        if isinstance(parent, (ast.If, ast.For, ast.While, ast.Match)):
            return True
        current = parent
    return False


def assignment_node(function: ast.FunctionDef, name: str) -> ast.expr:
    matches = [
        node.value
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    if len(matches) != 1:
        raise ContractError(f"trusted security entrypoint assignment changed: {name}")
    return matches[0]


def literal_top_level_assignment(tree: ast.Module, name: str) -> object:
    matches = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    if len(matches) != 1:
        raise ContractError(f"trusted security entrypoint constant changed: {name}")
    value = matches[0]
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "frozenset"
        and len(value.args) == 1
        and not value.keywords
    ):
        try:
            return frozenset(ast.literal_eval(value.args[0]))
        except (ValueError, TypeError) as error:
            raise ContractError(
                f"trusted security entrypoint constant is not literal: {name}"
            ) from error
    try:
        return ast.literal_eval(value)
    except (ValueError, TypeError) as error:
        raise ContractError(
            f"trusted security entrypoint constant is not literal: {name}"
        ) from error


def dictionary_expression(node: ast.expr) -> dict[str, str]:
    if not isinstance(node, ast.Dict) or any(
        not isinstance(key, ast.Constant) or not isinstance(key.value, str)
        for key in node.keys
    ):
        raise ContractError("trusted security entrypoint environment is not literal-keyed")
    return {
        key.value: ast.unparse(value)
        for key, value in zip(node.keys, node.values, strict=True)
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }


def expression_matches(node: ast.expr, expected: str) -> bool:
    expected_node = ast.parse(expected, mode="eval").body
    return ast.dump(node, include_attributes=False) == ast.dump(
        expected_node, include_attributes=False
    )


def direct_call_statement(statement: ast.stmt, call_name: str) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and ast_call_name(statement.value) == call_name
    )


def assignment_for_name(function: ast.FunctionDef, name: str) -> ast.Assign:
    matches = [
        statement
        for statement in ast.walk(function)
        if isinstance(statement, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == name
            for target in statement.targets
        )
    ]
    if len(matches) != 1:
        raise ContractError(f"trusted security entrypoint assignment changed: {name}")
    return matches[0]


def protected_target_root(node: ast.expr) -> str | None:
    current = node
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def validate_protected_bindings(
    tree: ast.Module,
    constants: set[str],
    functions: set[str],
    contract: str,
) -> None:
    if constants.intersection(functions):
        raise ContractError(contract)
    protected = constants | functions
    parents = ast_parent_map(tree)

    def binds_in_module_scope(node: ast.AST) -> bool:
        current = node
        while current is not tree:
            parent = parents.get(current)
            if parent is None:
                return False
            if isinstance(
                parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            ):
                return False
            current = parent
        return True

    approved_assignments: dict[str, ast.Assign] = {}
    for name in constants:
        matches = [
            statement
            for statement in tree.body
            if isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == name
        ]
        if len(matches) != 1:
            raise ContractError(contract)
        approved_assignments[name] = matches[0]
    for name in functions:
        if (
            sum(
                isinstance(statement, ast.FunctionDef) and statement.name == name
                for statement in tree.body
            )
            != 1
        ):
            raise ContractError(contract)
    for node in ast.walk(tree):
        if binds_in_module_scope(node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                approved_function = (
                    isinstance(node, ast.FunctionDef)
                    and parents.get(node) is tree
                    and node.name in functions
                )
                if node.name in protected and not approved_function:
                    raise ContractError(contract)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound_name = alias.asname or alias.name.split(".", maxsplit=1)[0]
                    if bound_name in protected:
                        raise ContractError(contract)
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    bound_name = alias.asname or alias.name
                    if bound_name in protected:
                        raise ContractError(contract)
            if isinstance(node, ast.ExceptHandler) and node.name in protected:
                raise ContractError(contract)
        if isinstance(node, (ast.Global, ast.Nonlocal)) and protected.intersection(
            node.names
        ):
            raise ContractError(contract)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            if node.id not in protected:
                continue
            parent = parents.get(node)
            if (
                node.id in approved_assignments
                and parent is approved_assignments[node.id]
                and isinstance(node.ctx, ast.Store)
            ):
                continue
            raise ContractError(contract)
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            targets: list[ast.expr]
            if isinstance(node, ast.Assign):
                targets = node.targets
            else:
                targets = [node.target]
            for target in targets:
                root_name = protected_target_root(target)
                if root_name in protected and not (
                    isinstance(node, ast.Assign)
                    and node is approved_assignments.get(root_name)
                    and isinstance(target, ast.Name)
                ):
                    raise ContractError(contract)
        if isinstance(node, ast.Delete):
            if any(protected_target_root(target) in protected for target in node.targets):
                raise ContractError(contract)
        if isinstance(node, ast.Call):
            call_name = ast_call_name(node)
            if call_name in {
                "compile",
                "delattr",
                "eval",
                "exec",
                "globals",
                "locals",
                "setattr",
                "vars",
                "__import__",
            }:
                raise ContractError(contract)
            if isinstance(node.func, ast.Attribute):
                root_name = protected_target_root(node.func.value)
                if root_name in protected and node.func.attr in {
                    "clear",
                    "pop",
                    "popitem",
                    "remove",
                    "setdefault",
                    "update",
                }:
                    raise ContractError(contract)


def validate_security_entrypoint(root: Path, source: str) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise ContractError("trusted security entrypoint is invalid Python") from error
    module_constants = {
        target.id
        for statement in tree.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    module_functions = {
        statement.name
        for statement in tree.body
        if isinstance(statement, ast.FunctionDef)
    }
    validate_protected_bindings(
        tree,
        module_constants,
        module_functions,
        "trusted security entrypoint protected authority binding changed",
    )
    functions = ast_function_map(tree)
    decorator_inventory = {
        name: [ast.unparse(decorator) for decorator in function.decorator_list]
        for name, function in functions.items()
        if function.decorator_list
    }
    if decorator_inventory != {"effective_identity": ["contextlib.contextmanager"]}:
        raise ContractError("trusted security entrypoint protected authority binding changed")
    required_functions = {
        "adversarial_release",
        "broker_server",
        "candidate_environment",
        "candidate_process_options",
        "configure_child_subreaper",
        "execution_boundary_record",
        "hostile_probe",
        "initialize_baseline",
        "linux_enforcement",
        "main",
        "prepare_candidate_state",
        "prepare_private_runtime",
        "quiesce_identity_processes",
        "refresh_evidence",
        "remove_candidate_state",
        "repository_inventory",
        "require_exact_repository_inventory",
        "run_candidate_bounded",
        "run_candidate_capture",
        "run_trusted_bounded",
        "trusted_checker_arguments",
        "verifier_environment",
        "verifier_process_options",
        "workspace_copy_process_options",
    }
    if not required_functions.issubset(functions):
        raise ContractError("trusted security entrypoint function graph changed")
    parents = ast_parent_map(tree)
    if (
        literal_top_level_assignment(tree, "CANDIDATE_UID") != 65532
        or literal_top_level_assignment(tree, "CANDIDATE_GID") != 65532
        or literal_top_level_assignment(tree, "VERIFIER_UID") != 65533
        or literal_top_level_assignment(tree, "VERIFIER_GID") != 65533
        or literal_top_level_assignment(tree, "COMMAND_EXECUTABLES")
        != {"cargo": "/usr/local/cargo/bin/cargo", "cc": "/usr/bin/cc", "ldd": "/usr/bin/ldd"}
        or set(literal_top_level_assignment(tree, "TRUSTED_GATES"))
        != {
            "check-cage-all-target-inventory.py",
            "check-cage-enforcement.sh",
            "check-cage-linux-enforcement.sh",
            "check-exact-cargo-test-inventory.py",
            "check-keyring-transparency.sh",
            "check-linux-enforcement-stack.py",
            "check-secret-broker-boundary.sh",
        }
    ):
        raise ContractError("trusted security entrypoint identity inventory changed")
    expected_paths = {
        "TRUSTED_CHECKER": "Path('/opt/chio-security/check-security-adversarial-evidence.py')",
        "TRUSTED_ENTRYPOINT": "Path('/opt/chio-security/entrypoint.py')",
        "TRUSTED_COMMAND_CLIENT": "Path('/opt/chio-security/command-client.py')",
        "TRUSTED_SECCOMP_PROFILE": "Path('/opt/chio-security/security-evidence-seccomp.json')",
        "WORKSPACE": "Path('/private/candidate')",
        "VERIFIER_ROOT": "Path('/baseline/verifier')",
        "CANDIDATE_STATE_ROOT": "Path('/baseline/candidate-state')",
        "BROKER_BIN": "Path('/opt/chio-security/verifier-bin')",
    }
    for name, expected in expected_paths.items():
        matches = [
            node.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets
            )
        ]
        if len(matches) != 1 or ast.unparse(matches[0]) != expected:
            raise ContractError("trusted security entrypoint authority paths changed")

    expected_options = {
        "candidate_process_options": (
            "{'extra_groups': [], 'group': CANDIDATE_GID, 'user': CANDIDATE_UID}"
        ),
        "verifier_process_options": (
            "{'extra_groups': [], 'group': VERIFIER_GID, 'user': VERIFIER_UID}"
        ),
        "workspace_copy_process_options": (
            "{'extra_groups': [], 'group': VERIFIER_GID, 'user': CANDIDATE_UID}"
        ),
    }
    for name, expected in expected_options.items():
        returns = [node for node in functions[name].body if isinstance(node, ast.Return)]
        if len(returns) != 1 or ast.unparse(returns[0].value) != expected:
            raise ContractError("trusted security entrypoint UID transition changed")

    candidate_environment = functions["candidate_environment"]
    candidate_target = assignment_node(candidate_environment, "target")
    candidate_values = dictionary_expression(
        assignment_node(candidate_environment, "environment")
    )
    verifier_returns = [
        node for node in functions["verifier_environment"].body if isinstance(node, ast.Return)
    ]
    if len(verifier_returns) != 1:
        raise ContractError("trusted verifier environment return changed")
    verifier_values = dictionary_expression(verifier_returns[0].value)
    expected_candidate_keys = {
        "CARGO_BUILD_JOBS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_NET_OFFLINE",
        "CARGO_PROFILE_DEV_DEBUG",
        "CARGO_PROFILE_TEST_DEBUG",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "CHIO_ENTERPRISE_SECURITY_RUNNER",
        "CHIO_SECURITY_CAGE_INVENTORY_CHECKER",
        "CHIO_SECURITY_CAGE_LINUX_RUNNER",
        "CHIO_SECURITY_EXACT_INVENTORY_CHECKER",
        "CHIO_SECURITY_IMAGE_ID",
        "CHIO_SECURITY_LINUX_STACK_CHECKER",
        "CHIO_SECURITY_WORKSPACE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_VALUE_0",
        "GIT_DIR",
        "GIT_OPTIONAL_LOCKS",
        "GIT_TERMINAL_PROMPT",
        "GIT_WORK_TREE",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONNOUSERSITE",
        "PYTHONSAFEPATH",
        "RUSTUP_HOME",
        "SOURCE_SHA",
        "TMPDIR",
    }
    expected_verifier_keys = (
        expected_candidate_keys
        - {"CARGO_HOME", "CARGO_NET_OFFLINE", "CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_TEST_DEBUG", "CHIO_SECURITY_IMAGE_ID"}
        | {
            "CHIO_SECURITY_BROKER_SOCKET",
            "CHIO_SECURITY_BROKER_TOKEN",
            "CHIO_SECURITY_CANDIDATE_ARTIFACTS",
            "CHIO_SECURITY_VERIFIER_ARTIFACTS",
        }
    )
    expected_candidate_values = {
        "CARGO_BUILD_JOBS": "'1'",
        "CARGO_HOME": "'/cargo-home'",
        "CARGO_INCREMENTAL": "'0'",
        "CARGO_NET_OFFLINE": "'true'",
        "CARGO_PROFILE_DEV_DEBUG": "'0'",
        "CARGO_PROFILE_TEST_DEBUG": "'0'",
        "CARGO_TARGET_DIR": "os.fspath(target)",
        "CARGO_TERM_COLOR": "'never'",
        "CHIO_ENTERPRISE_SECURITY_RUNNER": "'1'",
        "CHIO_SECURITY_CAGE_INVENTORY_CHECKER": (
            "'/opt/chio-security/gates/check-cage-all-target-inventory.py'"
        ),
        "CHIO_SECURITY_CAGE_LINUX_RUNNER": (
            "'/opt/chio-security/gates/check-cage-linux-enforcement.sh'"
        ),
        "CHIO_SECURITY_EXACT_INVENTORY_CHECKER": (
            "'/opt/chio-security/gates/check-exact-cargo-test-inventory.py'"
        ),
        "CHIO_SECURITY_LINUX_STACK_CHECKER": (
            "'/opt/chio-security/gates/check-linux-enforcement-stack.py'"
        ),
        "CHIO_SECURITY_IMAGE_ID": "os.environ.get('CHIO_SECURITY_IMAGE_ID', '')",
        "CHIO_SECURITY_WORKSPACE": "'/private/candidate'",
        "GIT_CONFIG_GLOBAL": "'/dev/null'",
        "GIT_CONFIG_COUNT": "'1'",
        "GIT_CONFIG_KEY_0": "'safe.directory'",
        "GIT_CONFIG_NOSYSTEM": "'1'",
        "GIT_CONFIG_VALUE_0": "'/private/candidate'",
        "GIT_DIR": "'/baseline/git'",
        "GIT_OPTIONAL_LOCKS": "'0'",
        "GIT_TERMINAL_PROMPT": "'0'",
        "GIT_WORK_TREE": "'/private/candidate'",
        "HOME": "os.fspath(home)",
        "LANG": "'C.UTF-8'",
        "LC_ALL": "'C.UTF-8'",
        "PATH": (
            "'/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:"
            "/usr/bin:/sbin:/bin'"
        ),
        "PYTHONNOUSERSITE": "'1'",
        "PYTHONSAFEPATH": "'1'",
        "RUSTUP_HOME": "'/usr/local/rustup'",
        "SOURCE_SHA": "os.environ.get('SOURCE_SHA', '')",
        "TMPDIR": "'/target/tmp'",
    }
    if (
        candidate_values != expected_candidate_values
        or set(verifier_values) != expected_verifier_keys
        or ast.unparse(candidate_target) != "Path('/target/build')"
        or candidate_values.get("CARGO_HOME") != "'/cargo-home'"
        or candidate_values.get("CARGO_TARGET_DIR") != "os.fspath(target)"
        or candidate_values.get("HOME") != "os.fspath(home)"
        or candidate_values.get("TMPDIR") != "'/target/tmp'"
        or candidate_values.get("GIT_DIR") != "'/baseline/git'"
        or candidate_values.get("PYTHONNOUSERSITE") != "'1'"
        or candidate_values.get("PYTHONSAFEPATH") != "'1'"
        or verifier_values.get("CARGO_TARGET_DIR") != "'/target/build'"
        or verifier_values.get("CHIO_SECURITY_BROKER_SOCKET")
        != "os.fspath(socket_path)"
        or verifier_values.get("CHIO_SECURITY_BROKER_TOKEN") != "token"
        or verifier_values.get("CHIO_SECURITY_CANDIDATE_ARTIFACTS")
        != "'/target/artifacts'"
        or verifier_values.get("CHIO_SECURITY_VERIFIER_ARTIFACTS")
        != "os.fspath(verifier_root / 'artifacts')"
        or verifier_values.get("HOME") != "os.fspath(verifier_root / 'home')"
        or verifier_values.get("TMPDIR") != "os.fspath(verifier_root / 'tmp')"
        or verifier_values.get("GIT_DIR") != "'/baseline/git'"
        or verifier_values.get("PATH")
        != "f'{BROKER_BIN}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'"
        or verifier_values.get("PYTHONNOUSERSITE") != "'1'"
        or verifier_values.get("PYTHONSAFEPATH") != "'1'"
    ):
        raise ContractError("trusted security entrypoint environment boundary changed")
    expected_forwarding = ast.parse(
        """
if forwarded:
    for key, value in forwarded.items():
        if key.startswith("CHIO_CAGE_"):
            environment[key] = value
        elif key == "RUSTFLAGS":
            environment[key] = value
        elif key == "LC_ALL" and value == "C":
            environment[key] = value
        elif key == "CARGO_TARGET_DIR":
            requested = Path(value)
            persistent_cage_target = Path("/target/artifacts/static-pie-target")
            if not requested.is_absolute() or not (
                requested.is_relative_to(target)
                or requested == persistent_cage_target
            ):
                raise EntrypointError("candidate target override escapes gate state")
            environment[key] = value
        else:
            raise EntrypointError("candidate command requested an unsafe environment")
return environment
"""
    ).body
    if ast.dump(
        ast.Module(body=candidate_environment.body[-2:], type_ignores=[]),
        include_attributes=False,
    ) != ast.dump(
        ast.Module(body=expected_forwarding, type_ignores=[]),
        include_attributes=False,
    ):
        raise ContractError("trusted candidate environment forwarding changed")

    private_runtime_source = ast.unparse(functions["prepare_private_runtime"])
    for required in (
        "validate_trusted_regular_file(TRUSTED_ENTRYPOINT, expected_mode=365",
        "validate_trusted_regular_file(TRUSTED_COMMAND_CLIENT, expected_mode=365",
        "validate_trusted_regular_file(BROKER_BIN / executable, expected_mode=365",
        "validate_trusted_regular_file(TRUSTED_CHECKER, expected_mode=292",
        "validate_trusted_regular_file(gate, expected_mode=365",
        "validate_trusted_regular_file(TRUSTED_SECCOMP_PROFILE, expected_mode=292",
    ):
        if required not in private_runtime_source:
            raise ContractError("trusted security entrypoint file modes changed")
    supervisor_source = ast.unparse(functions["validate_supervisor_boundary"])
    for required in (
        "os.setgroups([])",
        "configure_child_subreaper()",
        "host_uid = numeric_environment('CHIO_HOST_UID')",
        "host_gid = numeric_environment('CHIO_HOST_GID')",
        "NoNewPrivs:\\t1\\n",
        "Seccomp:\\t2\\n",
        "CapEff:\\t00000000000000c0",
    ):
        if required not in supervisor_source:
            raise ContractError("trusted root supervisor boundary changed")
    subreaper = functions["configure_child_subreaper"]
    subreaper_calls = live_calls(subreaper, "prctl", parents)
    if (
        not expression_matches(assignment_node(subreaper, "set_child_subreaper"), "36")
        or not expression_matches(
            assignment_node(subreaper, "get_child_subreaper"), "37"
        )
        or len(subreaper_calls) != 2
        or len(live_calls(subreaper, "ctypes.CDLL", parents)) != 1
    ):
        raise ContractError("trusted root supervisor child subreaper changed")

    trusted_checker_returns = [
        node
        for node in functions["trusted_checker_arguments"].body
        if isinstance(node, ast.Return)
    ]
    if (
        len(trusted_checker_returns) != 1
        or ast.unparse(trusted_checker_returns[0].value)
        != "['/usr/bin/python3', '-I', os.fspath(TRUSTED_CHECKER), '--root', os.fspath(WORKSPACE), *arguments]"
    ):
        raise ContractError("trusted Python checker isolation changed")

    main = functions["main"]
    main_sequence = []
    for call_name in (
        "validate_supervisor_boundary",
        "prepare_private_runtime",
        "initialize_baseline",
    ):
        calls = live_calls(main, call_name, parents)
        if len(calls) != 1 or has_control_guard(calls[0], main, parents):
            raise ContractError("trusted security entrypoint main control flow changed")
        main_sequence.append(calls[0].lineno)
    if main_sequence != sorted(main_sequence):
        raise ContractError("trusted security entrypoint main control flow reordered")

    capture = functions["run_candidate_capture"]
    capture_popen = live_calls(capture, "subprocess.Popen", parents)
    capture_collect = live_calls(capture, "collect_bounded_process", parents)
    capture_quiesce = live_calls(capture, "quiesce_process_namespace", parents)
    if (
        len(capture_popen) != 1
        or len(capture_collect) != 1
        or len(capture_quiesce) != 1
        or capture_popen[0].lineno >= capture_collect[0].lineno
        or capture_collect[0].lineno >= capture_quiesce[0].lineno
        or not any(
            keyword.arg is None
            and isinstance(keyword.value, ast.Call)
            and ast_call_name(keyword.value) == "candidate_process_options"
            for keyword in capture_popen[0].keywords
        )
    ):
        raise ContractError("candidate command supervision control flow changed")
    capture_finally = [
        statement
        for statement in capture.body
        if isinstance(statement, ast.Try)
        and any(
            isinstance(body_statement, ast.Return)
            and any(call is capture_collect[0] for call in ast.walk(body_statement))
            for body_statement in statement.body
        )
    ]
    if (
        len(capture_finally) != 1
        or len(capture_finally[0].finalbody) != 1
        or not direct_call_statement(
            capture_finally[0].finalbody[0], "quiesce_process_namespace"
        )
        or capture_finally[0].finalbody[0].value.args
        or capture_finally[0].finalbody[0].value.keywords
    ):
        raise ContractError("candidate command quiescence is not unconditional")

    quiesce = functions["quiesce_identity_processes"]
    kills = live_calls(quiesce, "os.kill", parents)
    if (
        len(kills) != 1
        or len(kills[0].args) != 2
        or ast.unparse(kills[0].args[0]) != "pid"
        or ast.unparse(kills[0].args[1]) != "signal.SIGKILL"
        or not live_calls(quiesce, "identity_process_ids", parents)
    ):
        raise ContractError("candidate or verifier namespace quiescence changed")

    state = functions["prepare_candidate_state"]
    probe_value = assignment_node(state, "execution_probe")
    probe_calls = live_calls(state, "run_candidate_capture", parents)
    if (
        ast.unparse(probe_value)
        != "Path('/target/build/.chio-execution-probe')"
        or len(probe_calls) != 2
        or probe_calls[0].lineno >= probe_calls[1].lineno
        or "['/bin/cp', '/bin/true', os.fspath(execution_probe)]"
        not in ast.unparse(probe_calls[0])
        or "[os.fspath(execution_probe)]" not in ast.unparse(probe_calls[1])
    ):
        raise ContractError("disposable candidate execution state changed")
    state_source = ast.unparse(state)
    for required in (
        "Path('/cargo-home')",
        "Path('/target')",
        "Path('/target/build')",
        "Path('/target/artifacts')",
        "Path('/target/tmp')",
        "clear_identity_directory(external_root, CANDIDATE_UID, CANDIDATE_GID)",
    ):
        if required not in state_source:
            raise ContractError("disposable candidate execution state changed")

    trusted = functions["run_trusted_bounded"]
    broker_values = dictionary_expression(assignment_node(trusted, "broker_environment"))
    if set(broker_values) != {
        "CHIO_HOST_GID",
        "CHIO_HOST_UID",
        "CHIO_SECURITY_BROKER_TOKEN",
        "CHIO_SECURITY_IMAGE_ID",
        "CHIO_SECCOMP_PROFILE_SHA256",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONNOUSERSITE",
        "PYTHONSAFEPATH",
        "SOURCE_SHA",
    } or any(
        broker_values.get(key) != expected
        for key, expected in {
            "PATH": "'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'",
            "PYTHONNOUSERSITE": "'1'",
            "PYTHONSAFEPATH": "'1'",
        }.items()
    ):
        raise ContractError("trusted broker environment changed")
    trusted_popen = live_calls(trusted, "subprocess.Popen", parents)
    trusted_sequence_names = (
        "collect_bounded_process",
        "stop_broker",
    )
    trusted_sequence: list[int] = []
    for call_name in trusted_sequence_names:
        calls = live_calls(trusted, call_name, parents)
        if len(calls) != 1:
            raise ContractError("trusted verifier supervision control flow changed")
        trusted_sequence.append(calls[0].lineno)
    verifier_quiescence = live_calls(trusted, "quiesce_verifier_namespace", parents)
    if (
        len(trusted_popen) != 2
        or len(verifier_quiescence) != 1
        or trusted_popen[0].lineno >= trusted_popen[1].lineno
        or trusted_popen[1].lineno >= trusted_sequence[0]
        or not (
            trusted_sequence[0]
            < verifier_quiescence[0].lineno
            < trusted_sequence[1]
        )
        or "['/usr/bin/python3', '-I', os.fspath(TRUSTED_ENTRYPOINT)"
        not in ast.unparse(trusted_popen[0])
        or "--broker-token" in ast.unparse(trusted_popen[0])
        or "f'broker-{socket_identity}.sock'" not in ast.unparse(trusted)
        or not any(
            keyword.arg is None
            and isinstance(keyword.value, ast.Call)
            and ast_call_name(keyword.value) == "verifier_process_options"
            for keyword in trusted_popen[1].keywords
        )
    ):
        raise ContractError("trusted verifier supervision control flow changed")
    trusted_cleanup_try = [
        statement
        for statement in trusted.body
        if isinstance(statement, ast.Try)
        and any(call is trusted_popen[1] for call in ast.walk(statement))
    ]
    expected_cleanup_handler = ast.parse(
        """
try:
    pass
except BaseException as primary_error:
    cleanup_errors: list[BaseException] = []
    for cleanup in (
        quiesce_verifier_namespace,
        lambda: abandon_broker(broker, socket_path, gate_root),
    ):
        try:
            cleanup()
        except BaseException as cleanup_error:
            cleanup_errors.append(cleanup_error)
    for cleanup_error in cleanup_errors:
        primary_error.add_note(
            f"security boundary cleanup also failed: {cleanup_error!r}"
        )
    raise
"""
    ).body[0]
    if (
        len(trusted_cleanup_try) != 1
        or len(trusted_cleanup_try[0].handlers) != 1
        or not isinstance(expected_cleanup_handler, ast.Try)
        or ast.dump(
            trusted_cleanup_try[0].handlers[0], include_attributes=False
        )
        != ast.dump(expected_cleanup_handler.handlers[0], include_attributes=False)
        or [
            ast_call_name(statement.value)
            for statement in trusted_cleanup_try[0].body
            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
        ]
        != ["quiesce_verifier_namespace", "stop_broker"]
    ):
        raise ContractError("trusted verifier exceptional cleanup changed")

    broker = functions["broker_server"]
    broker_prepare = live_calls(broker, "prepare_candidate_state", parents)
    broker_execute = live_calls(broker, "run_candidate_capture", parents)
    broker_bind = live_calls(broker, "server.bind", parents)
    if (
        len(broker_prepare) != 1
        or len(broker_bind) != 1
        or len(broker_execute) != 1
        or not (
            broker_prepare[0].lineno < broker_bind[0].lineno < broker_execute[0].lineno
        )
        or "effective_identity(VERIFIER_UID, VERIFIER_GID)"
        not in ast.unparse(broker)
    ):
        raise ContractError("candidate command broker control flow changed")

    subprocess_sites: list[tuple[str, ast.Call]] = []
    popen_sites: list[tuple[str, ast.Call]] = []
    for function_name, function in functions.items():
        subprocess_sites.extend(
            (function_name, call)
            for call in live_calls(function, "subprocess.run", parents)
        )
        popen_sites.extend(
            (function_name, call)
            for call in live_calls(function, "subprocess.Popen", parents)
        )
        for call in ast.walk(function):
            if not isinstance(call, ast.Call):
                continue
            for keyword in call.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    raise ContractError("trusted security entrypoint enables a shell")
    if sorted(name for name, _call in subprocess_sites) != [
        "initialize_baseline",
        "prepare_candidate_state",
        "prepare_private_runtime",
        "prepare_private_runtime",
        "reset_candidate_command_state",
    ] or sorted(name for name, _call in popen_sites) != [
        "run_candidate_capture",
        "run_trusted_bounded",
        "run_trusted_bounded",
    ]:
        raise ContractError("trusted security entrypoint command surface changed")
    for function_name, call in subprocess_sites:
        current: ast.AST = call
        containing_try: ast.Try | None = None
        while current is not functions[function_name]:
            parent = parents.get(current)
            if parent is None:
                break
            if isinstance(parent, ast.Try) and current in parent.body:
                containing_try = parent
                break
            current = parent
        if containing_try is None:
            raise ContractError("bootstrap command lacks unconditional quiescence")
        final_source = "\n".join(ast.unparse(node) for node in containing_try.finalbody)
        if "quiesce_process_namespace()" not in final_source or (
            function_name == "initialize_baseline"
            and "quiesce_verifier_namespace()" not in final_source
        ):
            raise ContractError("bootstrap command lacks unconditional quiescence")

    for function_name, function in functions.items():
        for node in ast.walk(function):
            if not isinstance(node, ast.List) or not node.elts:
                continue
            if not (
                isinstance(node.elts[0], ast.Constant)
                and node.elts[0].value == "/usr/bin/python3"
            ):
                continue
            values = [
                element.value if isinstance(element, ast.Constant) else None
                for element in node.elts
            ]
            if values[:2] == ["/usr/bin/python3", "probe.py"] and function_name == "hostile_probe":
                continue
            if values[:2] != ["/usr/bin/python3", "-I"]:
                raise ContractError("trusted Python execution is not isolated")

    hostile = functions["hostile_probe"]
    hostile_candidate = live_calls(hostile, "run_candidate_bounded", parents)
    hostile_trusted = live_calls(hostile, "run_trusted_bounded", parents)
    hostile_unlinks = live_calls(hostile, "detached_sentinel.unlink", parents)
    hostile_sleeps = live_calls(hostile, "time.sleep", parents)
    hostile_exists = live_calls(hostile, "detached_sentinel.exists", parents)
    if (
        len(hostile_candidate) != 1
        or len(hostile_trusted) != 2
        or len(hostile_unlinks) != 2
        or len(hostile_sleeps) != 1
        or len(hostile_exists) != 1
        or max(hostile_candidate[0].lineno, hostile_trusted[0].lineno)
        >= hostile_trusted[-1].lineno
        or not (
            hostile_unlinks[0].lineno
            < min(hostile_candidate[0].lineno, hostile_trusted[0].lineno)
            <= max(hostile_candidate[0].lineno, hostile_trusted[0].lineno)
            < hostile_unlinks[1].lineno
            < hostile_sleeps[0].lineno
            < hostile_exists[0].lineno
            < hostile_trusted[-1].lineno
        )
        or not expression_matches(hostile_sleeps[0].args[0], "2")
        or "set -euo pipefail\\ncargo test --offline\\ncargo --version\\n"
        not in ast.unparse(hostile)
        or "['/usr/bin/python3', '-I', os.fspath(TRUSTED_CHECKER), '--help']"
        not in ast.unparse(hostile)
    ):
        raise ContractError("hostile poisoning probe control flow changed")

    for function_name in ("adversarial_release", "linux_enforcement", "refresh_evidence"):
        function = functions[function_name]
        publications = live_calls(function, "publish_regular", parents)
        if not publications:
            raise ContractError("candidate repository publication graph changed")
        if function_name == "refresh_evidence":
            inventory_calls = live_calls(
                function, "require_exact_repository_inventory", parents
            )
        else:
            inventory_calls = live_calls(function, "require_clean_repository", parents)
        if (
            len(inventory_calls) != 1
            or has_control_guard(inventory_calls[0], function, parents)
            or inventory_calls[0].lineno >= min(call.lineno for call in publications)
        ):
            raise ContractError("candidate repository publication graph changed")
    linux = functions["linux_enforcement"]
    clippy_calls = [
        call
        for call in live_calls(linux, "run_candidate_bounded", parents)
        if "'clippy'" in ast.unparse(call)
    ]
    linux_inventory = live_calls(linux, "require_clean_repository", parents)
    if (
        len(clippy_calls) != 1
        or len(linux_inventory) != 1
        or clippy_calls[0].lineno >= linux_inventory[0].lineno
    ):
        raise ContractError("candidate repository publication graph changed")

    record = functions["execution_boundary_record"]
    trusted_files_expression = assignment_node(record, "trusted_files")
    record_expression = assignment_node(record, "record")
    if not expression_matches(
        trusted_files_expression,
        """
{
    "check-security-adversarial-evidence.py": TRUSTED_CHECKER,
    "command-client.py": TRUSTED_COMMAND_CLIENT,
    "entrypoint.py": TRUSTED_ENTRYPOINT,
    "security-evidence-seccomp.json": TRUSTED_SECCOMP_PROFILE,
    **{
        f"verifier-bin/{name}": BROKER_BIN / name
        for name in COMMAND_EXECUTABLES
    },
    **{name: TRUSTED_GATE_ROOT / name for name in TRUSTED_GATES},
}
""",
    ) or not expression_matches(
        record_expression,
        """
{
    "image_id": image_id,
    "platform": "linux/amd64",
    "schema": "chio.security-execution-boundary.v1",
    "seccomp_profile_sha256": seccomp_digest,
    "trusted_file_sha256": {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(trusted_files.items())
    },
}
""",
    ):
        raise ContractError("trusted execution boundary hash inventory changed")

    command_client_path = root / "scripts/security-execution-command-client.py"
    command_client = command_client_path.read_text(encoding="utf-8")
    try:
        client_tree = ast.parse(command_client)
    except SyntaxError as error:
        raise ContractError("candidate command client is invalid Python") from error
    client_constants = {
        target.id
        for statement in client_tree.body
        if isinstance(statement, ast.Assign)
        for target in statement.targets
        if isinstance(target, ast.Name)
    }
    client_function_names = {
        statement.name
        for statement in client_tree.body
        if isinstance(statement, ast.FunctionDef)
    }
    validate_protected_bindings(
        client_tree,
        client_constants,
        client_function_names,
        "candidate command client protected authority binding changed",
    )
    imports = {
        alias.name
        for node in client_tree.body
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_names = {
        (node.module, alias.name)
        for node in client_tree.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    if (
        command_client.splitlines()[0] != "#!/usr/bin/python3 -I"
        or literal_top_level_assignment(client_tree, "FORWARDED_EXACT")
        != frozenset({"CARGO_TARGET_DIR", "LC_ALL", "RUSTFLAGS"})
        or imports != {"json", "os", "socket", "sys"}
        or imported_names != {("__future__", "annotations"), ("pathlib", "Path")}
    ):
        raise ContractError("candidate command client authority changed")
    client_functions = ast_function_map(client_tree)
    if set(client_functions) != {"forwarded_environment", "main", "read_line"}:
        raise ContractError("candidate command client authority changed")
    if any(function.decorator_list for function in client_functions.values()):
        raise ContractError("candidate command client protected authority binding changed")
    forwarded_returns = [
        statement
        for statement in client_functions["forwarded_environment"].body
        if isinstance(statement, ast.Return)
    ]
    if len(forwarded_returns) != 1 or not expression_matches(
        forwarded_returns[0].value,
        """
{
    key: value
    for key, value in os.environ.items()
    if (
        (key in FORWARDED_EXACT and (key != "LC_ALL" or value == "C"))
        or key.startswith("CHIO_CAGE_")
    )
}
""",
    ):
        raise ContractError("candidate command client environment forwarding changed")
    client_main = client_functions["main"]
    client_parents = ast_parent_map(client_tree)
    request_expression = assignment_node(client_main, "request")
    if not expression_matches(
        request_expression,
        """
{
    "arguments": sys.argv[1:],
    "cwd": os.getcwd(),
    "environment": forwarded_environment(),
    "executable": executable,
    "operation": "run",
    "token": token,
}
""",
    ):
        raise ContractError("candidate command client request changed")
    client_sequence = []
    for call_name in (
        "connection.connect",
        "connection.sendall",
        "read_line",
        "sys.stdout.buffer.write",
        "sys.stdout.buffer.flush",
    ):
        calls = live_calls(client_main, call_name, client_parents)
        if len(calls) != 1:
            raise ContractError("candidate command client control flow changed")
        client_sequence.append(calls[0].lineno)
    if client_sequence != sorted(client_sequence) or not (
        len(client_main.body) >= 3
        and direct_call_statement(
            client_main.body[-3], "sys.stdout.buffer.write"
        )
        and direct_call_statement(
            client_main.body[-2], "sys.stdout.buffer.flush"
        )
        and isinstance(client_main.body[-1], ast.Return)
        and expression_matches(client_main.body[-1].value, "returncode")
    ):
        raise ContractError("candidate command client control flow changed")


def validate_security_execution_boundary_files(root: Path) -> None:
    inventory = {
        "deploy/docker/Dockerfile.security-evidence-runner": 0o644,
        "deploy/docker/security-evidence-apk.lock": 0o644,
        "deploy/docker/security-evidence-seccomp.json": 0o644,
        "crates/security/chio-cage/scripts/check-linux-enforcement.sh": 0o755,
        "scripts/check-cage-all-target-inventory.py": 0o644,
        "scripts/check-cage-enforcement.sh": 0o755,
        "scripts/check-exact-cargo-test-inventory.py": 0o755,
        "scripts/check-keyring-transparency.sh": 0o755,
        "scripts/check-linux-enforcement-stack.py": 0o755,
        "scripts/check-secret-broker-boundary.sh": 0o755,
        "scripts/check-security-adversarial-evidence.py": 0o755,
        "scripts/run-security-execution-container.py": 0o755,
        "scripts/security-execution-command-client.py": 0o755,
        "scripts/security-execution-container-entrypoint.py": 0o755,
        "scripts/tests/run-security-execution-container.test.py": 0o755,
    }
    for relative, mode in inventory.items():
        path = root / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or stat.S_IMODE(path.stat().st_mode) != mode
        ):
            raise ContractError(
                f"security execution boundary file is not regular: {path.relative_to(root)}"
            )
    dockerfile = (root / "deploy/docker/Dockerfile.security-evidence-runner").read_text(
        encoding="utf-8"
    )
    validate_security_dockerfile(root, dockerfile)

    profile = json.loads(
        (root / "deploy/docker/security-evidence-seccomp.json").read_text(
            encoding="utf-8"
        )
    )
    expected_denied = (
        "_sysctl",
        "acct",
        "add_key",
        "bpf",
        "clone3",
        "delete_module",
        "finit_module",
        "fsconfig",
        "fsmount",
        "fsopen",
        "fspick",
        "init_module",
        "ioperm",
        "iopl",
        "kcmp",
        "kexec_file_load",
        "kexec_load",
        "keyctl",
        "lookup_dcookie",
        "mount",
        "move_mount",
        "open_by_handle_at",
        "open_tree",
        "perf_event_open",
        "pivot_root",
        "process_vm_readv",
        "process_vm_writev",
        "quotactl",
        "reboot",
        "request_key",
        "setns",
        "settimeofday",
        "stime",
        "swapoff",
        "swapon",
        "syslog",
        "umount",
        "umount2",
        "unshare",
        "userfaultfd",
    )
    clone_masks = (
        128,
        131072,
        33554432,
        67108864,
        134217728,
        268435456,
        536870912,
        1073741824,
    )
    expected_profile = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "defaultErrnoRet": 1,
        "archMap": [
            {
                "architecture": "SCMP_ARCH_X86_64",
                "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"],
            }
        ],
        "syscalls": [
            {
                "names": list(expected_denied),
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 1,
            },
            *[
                {
                    "names": ["clone"],
                    "action": "SCMP_ACT_ERRNO",
                    "errnoRet": 1,
                    "args": [
                        {
                            "index": 0,
                            "value": mask,
                            "valueTwo": mask,
                            "op": "SCMP_CMP_MASKED_EQ",
                        }
                    ],
                }
                for mask in clone_masks
            ],
        ],
    }
    if profile != expected_profile:
        raise ContractError("trusted security seccomp syscall contract changed")

    runner = (root / "scripts/run-security-execution-container.py").read_text(
        encoding="utf-8"
    )
    runner_markers = (
        'IMAGE_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")',
        'MANAGED_LABEL = "org.chio.security-execution.managed=true"',
        'STATE_LABEL = "org.chio.security-execution.state"',
        '"--network",\n        "none"',
        '"--read-only"',
        '"--cap-drop",\n        "ALL"',
        '"--cap-add",\n        "SETGID"',
        '"--cap-add",\n        "SETUID"',
        '"no-new-privileges"',
        '"--pids-limit"',
        '"--memory"',
        '"--memory-swap"',
        '"--cpus"',
        '"--log-driver",\n        "none"',
        '"CARGO_NET_OFFLINE": "true"',
        '"CARGO_PROFILE_DEV_DEBUG": "0"',
        '"CARGO_PROFILE_TEST_DEBUG": "0"',
        'f"seccomp={seccomp_profile}"',
        'f"type=bind,src={source},dst=/source,readonly"',
        '"/baseline:rw,nosuid,nodev,noexec,size=268435456,mode=0755"',
        '"core=0:0"',
        '"fsize=1073741824:1073741824"',
        '"nofile=1024:1024"',
        "materialize_private_copy(candidate, work)",
        "directory_chain_identity",
        "open_private_lock",
        (
            "def open_private_lock(path: Path) -> int:\n"
            '    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)\n'
            '    if hasattr(os, "O_NOFOLLOW"):\n'
            "        flags |= os.O_NOFOLLOW"
        ),
        "STATE_LABEL",
        "os.O_NOFOLLOW",
        "before.st_nlink != 1",
        "read_regular_file_once",
        "revalidate_repository(candidate)",
        "collect_outputs(",
        "publish_outputs(output_dir, payloads)",
        "reject_published_outputs(output_dir, set(payloads))",
        "stop_and_remove_container",
        "clean_stale_state",
        '[docker, "kill", "--signal", "KILL", identifier]',
        '["wait", identifier]',
    )
    if any(marker not in runner for marker in runner_markers):
        raise ContractError("trusted security container runner contract changed")
    if runner.count("revalidate_repository(candidate)") != 4:
        raise ContractError("trusted security container runner contract changed")
    try:
        runner_tree = ast.parse(runner)
    except SyntaxError as error:
        raise ContractError(
            "trusted security container runner is invalid Python"
        ) from error
    runner_lines = runner.splitlines(keepends=True)
    runner_functions = {
        node.name: "".join(runner_lines[node.lineno - 1 : node.end_lineno])
        for node in runner_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    create_body = runner_functions.get("container_create_arguments", "")
    create_flag_counts = {
        "--cap-add": 2,
        "--cap-drop": 1,
        "--cidfile": 1,
        "--cpus": 1,
        "--env": 1,
        "--init": 1,
        "--label": 3,
        "--log-driver": 1,
        "--memory": 1,
        "--memory-swap": 1,
        "--mount": 2,
        "--name": 1,
        "--network": 1,
        "--pids-limit": 1,
        "--platform": 1,
        "--read-only": 1,
        "--security-opt": 2,
        "--timeout-seconds": 1,
        "--tmpfs": 5,
        "--ulimit": 3,
    }
    create_value_markers = (
        '"linux/amd64"',
        '"none"',
        '"ALL"',
        '"SETGID"',
        '"SETUID"',
        '"no-new-privileges"',
        'f"seccomp={seccomp_profile}"',
        '"512"',
        '"12g"',
        '"4"',
        '"core=0:0"',
        '"fsize=1073741824:1073741824"',
        '"nofile=1024:1024"',
        '"/tmp:rw,nosuid,nodev,size=536870912,mode=1777"',
        '"/private:rw,nosuid,nodev,size=2147483648,uid=65532,gid=65532,mode=0755"',
        '"/baseline:rw,nosuid,nodev,noexec,size=268435456,mode=0755"',
        '"/target:rw,nosuid,nodev,size=8589934592,uid=65532,gid=65532,mode=0700"',
        '"/cargo-home:rw,nosuid,nodev,noexec,size=2147483648,uid=65532,gid=65532,mode=0700"',
        'f"type=bind,src={source},dst=/source,readonly"',
        'f"type=bind,src={output},dst=/output"',
    )
    if any(
        create_body.count(f'"{flag}"') != count
        for flag, count in create_flag_counts.items()
    ) or any(marker not in create_body for marker in create_value_markers):
        raise ContractError("trusted security container runner contract changed")
    create_validator = runner_functions.get("validate_container_create_arguments", "")
    created_validator = runner_functions.get("validate_created_container", "")
    validator_markers = (
        '"--cap-add": 2',
        '"--env": 19',
        '"--label": 3',
        '"--mount": 2',
        '"--security-opt": 2',
        '"--tmpfs": 5',
        '"--ulimit": 3',
        '"--cpus": ["4"]',
        '"--memory": ["12g"]',
        '"--memory-swap": ["12g"]',
        '"--network": ["none"]',
        '"--pids-limit": ["512"]',
        "flag not in value_flags",
        "len(environment) != len(environment_entries)",
    )
    created_markers = (
        '["inspect", identifier]',
        '"NetworkMode": "none"',
        '"ReadonlyRootfs": True',
        '"Privileged": False',
        '"PidsLimit": 512',
        '"Memory": 12884901888',
        '"MemorySwap": 12884901888',
        '"NanoCpus": 4000000000',
        '"Runtime": "runc"',
        '"ShmSize": 67108864',
        '"Tmpfs": EXPECTED_TMPFS',
        "normalized_ulimits != EXPECTED_ULIMITS",
        "tuple(mounts) != expected_mounts",
        "observed_seccomp != seccomp_profile",
    )
    if any(marker not in create_validator for marker in validator_markers) or any(
        marker not in created_validator for marker in created_markers
    ):
        raise ContractError("trusted security container runner contract changed")
    main_body = runner_functions.get("main", "")
    create_contract_call = main_body.find(
        "validate_container_create_arguments(create_arguments)"
    )
    inspect_contract_call = main_body.find("validate_created_container(")
    start_call = main_body.find('docker_output(docker, ["start", identifier]')
    if (
        create_contract_call < 0
        or inspect_contract_call < create_contract_call
        or start_call < inspect_contract_call
    ):
        raise ContractError("trusted security container runner contract changed")
    if (
        "/var/run/docker.sock" in runner
        or "os.environ.copy()" in runner
        or "seccomp=unconfined" in runner
        or '"--user"' in runner
    ):
        raise ContractError(
            "trusted security container runner exposes a host capability"
        )

    entrypoint = (
        root / "scripts/security-execution-container-entrypoint.py"
    ).read_text(encoding="utf-8")
    validate_security_entrypoint(root, entrypoint)

    gate_contracts = {
        "scripts/check-keyring-transparency.sh": (
            "/private/candidate",
            "/opt/chio-security/gates/check-exact-cargo-test-inventory.py",
        ),
        "scripts/check-secret-broker-boundary.sh": (
            "/private/candidate",
            "/opt/chio-security/gates/check-exact-cargo-test-inventory.py",
        ),
        "scripts/check-cage-enforcement.sh": (
            "/private/candidate",
            "/opt/chio-security/gates/check-linux-enforcement-stack.py",
            "/opt/chio-security/gates/check-cage-all-target-inventory.py",
            "/opt/chio-security/gates/check-cage-linux-enforcement.sh",
        ),
        "crates/security/chio-cage/scripts/check-linux-enforcement.sh": (
            "/private/candidate",
            "/opt/chio-security/gates/check-cage-all-target-inventory.py",
        ),
    }
    for relative, markers in gate_contracts.items():
        gate = (root / relative).read_text(encoding="utf-8")
        if any(marker not in gate for marker in markers):
            raise ContractError(f"trusted gate helper routing changed: {relative}")

    boundary_test = (
        root / "scripts/tests/run-security-execution-container.test.py"
    ).read_text(encoding="utf-8")
    for marker in (
        "fake_docker_main_tests",
        "post-publication source race",
        "state parent symlink",
        "state lock symlink",
        "C2-to-C3 stale state",
        "candidate can ptrace the trusted supervisor",
        "broker_token_argv",
        "detached candidate quiescence verified",
        "while :; do printf CANDIDATE_POISON_RAN",
        "while True:",
        "complete evidence refresh inventory is not exact",
    ):
        if marker not in boundary_test:
            raise ContractError("security execution hostile test contract changed")


def validate_isolated_execution_job(
    job_body: dict[str, object],
    *,
    contract: str,
    inventory: tuple[tuple[str | None, str | None, str | None], ...],
    candidate_step_name: str,
    candidate_checkout: dict[str, str],
    trusted_checkout: dict[str, str],
    execution_step_name: str,
    operation: str,
) -> None:
    validate_step_inventory(job_body, inventory, contract)
    trusted_inventory = (
        "644 deploy/docker/Dockerfile.security-evidence-runner",
        "644 deploy/docker/security-evidence-apk.lock",
        "644 deploy/docker/security-evidence-seccomp.json",
        "755 crates/security/chio-cage/scripts/check-linux-enforcement.sh",
        "644 scripts/check-cage-all-target-inventory.py",
        "755 scripts/check-cage-enforcement.sh",
        "755 scripts/check-exact-cargo-test-inventory.py",
        "755 scripts/check-keyring-transparency.sh",
        "755 scripts/check-linux-enforcement-stack.py",
        "755 scripts/check-secret-broker-boundary.sh",
        "755 scripts/check-security-adversarial-evidence.py",
        "755 scripts/run-security-execution-container.py",
        "755 scripts/security-execution-command-client.py",
        "755 scripts/security-execution-container-entrypoint.py",
        "755 scripts/tests/run-security-execution-container.test.py",
    )
    if any(not contains_text(job_body, marker) for marker in trusted_inventory):
        raise ContractError(f"{contract} authorized tooling inventory is incomplete")
    candidate_checkout_step = named_step(job_body, candidate_step_name)
    trusted_checkout_step = named_step(
        job_body, "Checkout exact authorized security tooling without credentials"
    )
    expected_action = "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
    if candidate_checkout_step != {
        "name": candidate_step_name,
        "uses": expected_action,
        "with": candidate_checkout,
    }:
        raise ContractError(f"{contract} candidate checkout is not isolated and exact")
    if trusted_checkout_step != {
        "name": "Checkout exact authorized security tooling without credentials",
        "uses": expected_action,
        "with": trusted_checkout,
    }:
        raise ContractError(f"{contract} tooling is not pinned to authorized source")
    build = named_step(
        job_body, "Build digest-addressed trusted security execution image"
    )
    if build.get("id") != "security-image":
        raise ContractError(f"{contract} image identity is not exported")
    build_run = build.get("run")
    build_markers = (
        "--platform linux/amd64",
        "--file authorized-security/deploy/docker/Dockerfile.security-evidence-runner",
        '--tag "${tag}"',
        "authorized-security",
        "docker image inspect --format '{{.Id}}'",
        '[[ "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]]',
        "image inspect --format '{{.Os}}/{{.Architecture}}'",
        '"linux/amd64"',
        'echo "image=${image_id}" >> "${GITHUB_OUTPUT}"',
    )
    if not isinstance(build_run, str) or any(
        marker not in build_run for marker in build_markers
    ):
        raise ContractError(
            f"{contract} does not build a digest-addressed trusted image"
        )
    if " candidate" in build_run or "--file candidate/" in build_run:
        raise ContractError(
            f"{contract} builds an image from candidate-controlled tooling"
        )
    execution = named_step(job_body, execution_step_name)
    execution_run = execution.get("run")
    execution_markers = (
        "authorized-security/scripts/run-security-execution-container.py",
        "--authorized-source-sha",
        "--candidate candidate",
        "--expected-sha",
        ' --image "${SECURITY_EXECUTION_IMAGE}"',
        f"--operation {operation}",
        '--output-dir "${RUNNER_TEMP}/',
        '--state-dir "${RUNNER_TEMP}/security-execution-state"',
        "--timeout-seconds",
    )
    if not isinstance(execution_run, str) or any(
        marker not in execution_run for marker in execution_markers
    ):
        raise ContractError(f"{contract} bypasses the trusted execution runner")
    forbidden_host_execution = (
        "cargo ",
        "cargo\n",
        "rustup ",
        "python3 scripts/",
        "/bin/bash scripts/",
        "bash scripts/",
        "./scripts/",
        "candidate/scripts/",
        "cargo-mutants",
        "working-directory",
    )
    for step in job_body.get("steps", []):
        if not isinstance(step, dict):
            raise ContractError(f"{contract} has a malformed step")
        run = step.get("run", "")
        if isinstance(run, str) and any(
            value in run for value in forbidden_host_execution
        ):
            raise ContractError(f"{contract} executes candidate tooling on the host")


def validate(root: Path) -> None:
    validate_global_workflow_boundaries(root)
    validate_environment_provisioning_document(root)
    validate_security_execution_boundary_files(root)
    ci = load_workflow(root / ".github/workflows/ci.yml")
    enterprise = load_workflow(root / ".github/workflows/enterprise-hardening.yml")
    evidence_controller = load_workflow(
        root / ".github/workflows/enterprise-evidence-controller.yml"
    )
    linux_capture = load_workflow(
        root / ".github/workflows/enterprise-linux-capture.yml"
    )
    evidence_finalizer = load_workflow(
        root / ".github/workflows/enterprise-evidence-finalizer.yml"
    )
    security_revocation = load_workflow(
        root / ".github/workflows/security-contract-revocation.yml"
    )
    apalache = load_workflow(root / ".github/workflows/apalache-safety.yml")
    threat_coverage = load_workflow(
        root / ".github/workflows/threat-model-coverage.yml"
    )
    admin_override = load_workflow(root / ".github/workflows/admin-override-audit.yml")

    for workflow_name, workflow in (
        ("CI", ci),
        ("enterprise-hardening", enterprise),
        ("enterprise evidence controller", evidence_controller),
        ("enterprise Linux capture", linux_capture),
        ("enterprise evidence finalizer", evidence_finalizer),
        ("security contract revocation", security_revocation),
        ("Apalache", apalache),
        ("threat-model coverage", threat_coverage),
        ("admin override audit", admin_override),
    ):
        jobs = workflow_jobs(workflow)
        if "defaults" in workflow or any(
            isinstance(body, dict) and "defaults" in body for body in jobs.values()
        ):
            raise ContractError(f"{workflow_name} overrides the fail-fast run shell")
        inherited_env = forbidden_inherited_env(workflow)
        if inherited_env:
            raise ContractError(
                f"{workflow_name} inherits dangerous execution environment: "
                + ", ".join(sorted(inherited_env))
            )

    ci_events = ci.get("on")
    if ci.get("run-name") != (
        "CI N=${{ github.event.pull_request.number }} "
        "E=${{ github.event.pull_request.head.sha }} "
        "B=${{ github.event.pull_request.base.sha }} M=${{ github.sha }}"
    ):
        raise ContractError("required CI exact N/E/B/M run name changed")
    if ci.get("permissions") != EXPECTED_CI_PERMISSIONS:
        raise ContractError("required CI permissions changed")
    ci_pull_request = (
        ci_events.get("pull_request") if isinstance(ci_events, dict) else None
    )
    if not isinstance(ci_pull_request, dict) or ci_pull_request.get("types") != [
        "opened",
        "synchronize",
        "reopened",
        "unlabeled",
    ]:
        raise ContractError(
            "required CI does not rerun after Linux refresh label removal"
        )

    ci_env = ci.get("env")
    if not isinstance(ci_env, dict) or any(
        ci_env.get(key) != value
        for key, value in {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "1"}.items()
    ):
        raise ContractError(
            "required CI does not enforce serialized nonincremental Cargo"
        )

    enterprise_events = enterprise.get("on")
    if enterprise_events != EXPECTED_ENTERPRISE_EVENTS:
        raise ContractError("enterprise-hardening source input contract changed")
    if enterprise.get("permissions") != EXPECTED_ENTERPRISE_PERMISSIONS:
        raise ContractError("enterprise-hardening permissions changed")

    if enterprise.get("concurrency") != EXPECTED_ENTERPRISE_CONCURRENCY:
        raise ContractError(
            "enterprise-hardening concurrency does not isolate caller and standalone runs"
        )

    enterprise_jobs = workflow_jobs(enterprise)
    observed_enterprise_jobs = set(enterprise_jobs)
    if observed_enterprise_jobs != REQUIRED_ENTERPRISE_JOBS:
        missing = sorted(REQUIRED_ENTERPRISE_JOBS - observed_enterprise_jobs)
        unexpected = sorted(observed_enterprise_jobs - REQUIRED_ENTERPRISE_JOBS)
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise ContractError(
            "enterprise job inventory changed (" + "; ".join(details) + ")"
        )

    for workflow_name, workflow in (
        ("required CI", ci),
        ("enterprise-hardening", enterprise),
        ("enterprise evidence controller", evidence_controller),
        ("enterprise Linux capture", linux_capture),
    ):
        if contains_text(workflow, "self-hosted"):
            raise ContractError(
                f"{workflow_name} exposes required or candidate work to a persistent runner"
            )
        if contains_text(workflow, "${{ secrets."):
            raise ContractError(
                f"{workflow_name} exposes a repository secret to candidate work"
            )

    bind_source = job(enterprise, "bind-source")
    expected_bind_outputs = {
        "attestation_bundle_sha256": "${{ steps.package.outputs.attestation_bundle_sha256 }}",
        "attestation_id": "${{ steps.attest.outputs.attestation-id }}",
        "binding_artifact_digest": "${{ steps.upload.outputs.artifact-digest }}",
        "binding_artifact_id": "${{ steps.upload.outputs.artifact-id }}",
        "binding_artifact_name": "${{ steps.package.outputs.binding_artifact_name }}",
        "binding_sha256": "${{ steps.package.outputs.binding_sha256 }}",
        "merge_commit_sha": "${{ steps.bind.outputs.merge_commit_sha }}",
        "merge_tree_sha": "${{ steps.bind.outputs.merge_tree_sha }}",
        "source_repository": "${{ steps.bind.outputs.source_repository || steps.push.outputs.source_repository }}",
        "source_sha": "${{ steps.bind.outputs.source_sha || steps.push.outputs.source_sha }}",
        "tested_repository": "${{ steps.bind.outputs.tested_repository || steps.push.outputs.tested_repository }}",
        "tested_sha": "${{ steps.bind.outputs.tested_sha || steps.push.outputs.tested_sha }}",
    }
    if (
        bind_source.get("name") != "attest exact pull request merge binding"
        or bind_source.get("permissions") != EXPECTED_ENTERPRISE_PERMISSIONS
        or bind_source.get("runs-on") != "ubuntu-24.04"
        or bind_source.get("timeout-minutes") != "10"
        or bind_source.get("outputs") != expected_bind_outputs
        or any(
            key in bind_source
            for key in (
                "if",
                "needs",
                "env",
                "concurrency",
                "continue-on-error",
            )
        )
    ):
        raise ContractError("enterprise bind-source job protection changed")
    validate_step_inventory(
        bind_source,
        EXPECTED_BIND_SOURCE_STEP_INVENTORY,
        "enterprise bind-source",
    )
    bind_checkout = named_step(
        bind_source, "Checkout exact event merge without credentials"
    )
    if bind_checkout.get("with") != {
        "repository": "${{ github.repository }}",
        "ref": "${{ github.sha }}",
        "fetch-depth": "0",
        "persist-credentials": "false",
    }:
        raise ContractError("enterprise bind-source exact merge checkout changed")
    bind_step = named_step(bind_source, "Build canonical exact merge binding")
    expected_bind_env = {
        "BASE_REF": "${{ github.event.pull_request.base.ref }}",
        "BASE_REPOSITORY": "${{ github.event.pull_request.base.repo.full_name }}",
        "BASE_REPOSITORY_ID": "${{ github.event.pull_request.base.repo.id }}",
        "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "CALLER_WORKFLOW_REF": "${{ github.workflow_ref }}",
        "CALLER_WORKFLOW_SHA": "${{ github.workflow_sha }}",
        "EVENT_NAME": "${{ github.event_name }}",
        "EVENT_PR_HEAD_REF": "${{ github.event.pull_request.head.ref }}",
        "EVENT_PR_HEAD_REPOSITORY": "${{ github.event.pull_request.head.repo.full_name }}",
        "EVENT_PR_HEAD_REPOSITORY_ID": "${{ github.event.pull_request.head.repo.id }}",
        "EVENT_PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "INPUT_SOURCE_REPOSITORY": "${{ inputs.source_repository }}",
        "INPUT_SOURCE_SHA": "${{ inputs.source_sha }}",
        "PR_NUMBER": "${{ github.event.pull_request.number }}",
        "REPOSITORY_ID": "${{ github.repository_id }}",
        "REPOSITORY_OWNER_ID": "${{ github.repository_owner_id }}",
        "SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
        "TESTED_REPOSITORY": "${{ github.repository }}",
        "TESTED_SHA": "${{ github.sha }}",
    }
    if (
        bind_step.get("if") != "github.event_name == 'pull_request'"
        or bind_step.get("env") != expected_bind_env
    ):
        raise ContractError("enterprise bind-source event inputs changed")
    bind_run = require_run_markers(
        bind_source,
        "Build canonical exact merge binding",
        (
            '[[ "${INPUT_SOURCE_REPOSITORY}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]',
            'test "${INPUT_SOURCE_REPOSITORY}" = "${TESTED_REPOSITORY}"',
            'test "${INPUT_SOURCE_REPOSITORY}" = "${EVENT_PR_HEAD_REPOSITORY}"',
            'test "${INPUT_SOURCE_SHA}" = "${EVENT_PR_HEAD_SHA}"',
            'test "${GITHUB_REF}" = "refs/pull/${PR_NUMBER}/merge"',
            'test "${CALLER_WORKFLOW_SHA}" = "${TESTED_SHA}"',
            'test "$(git rev-parse HEAD)" = "${TESTED_SHA}"',
            "test \"${#parents[@]}\" = 2",
            'test "${parents[0]}" = "${BASE_SHA}"',
            'test "${parents[1]}" = "${EVENT_PR_HEAD_SHA}"',
            "X-GitHub-Api-Version: 2026-03-10",
            "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml",
            'expected_run_name="CI N=${PR_NUMBER} E=${EVENT_PR_HEAD_SHA} B=${BASE_SHA} M=${TESTED_SHA}"',
            'schema: "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1"',
            'merge: {parents: [$base_sha, $head_sha], ref: $merge_ref, sha: $merge_sha, tree_sha: $merge_tree_sha}',
            'test "$(jq -cS . ci-merge-binding.json)" = "$(< ci-merge-binding.json)"',
            'echo "source_sha=${INPUT_SOURCE_SHA}"',
            'echo "tested_sha=${TESTED_SHA}"',
            'echo "merge_commit_sha=${TESTED_SHA}"',
            'echo "merge_tree_sha=${merge_tree_sha}"',
        ),
        "enterprise bind-source does not attest the exact event merge",
    )
    if "merge_commit_sha" not in bind_run or "merge_tree_sha" not in bind_run:
        raise ContractError(
            "enterprise bind-source omits the exact merge identity"
        )
    attest_step = named_step(bind_source, "Attest canonical exact merge binding")
    if attest_step.get("if") != "github.event_name == 'pull_request'" or attest_step.get(
        "with"
    ) != {
        "subject-path": "ci-merge-binding.json",
        "predicate-type": "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1",
        "predicate-path": "ci-merge-binding.json",
        "show-summary": "false",
    }:
        raise ContractError("enterprise bind-source attestation contract changed")
    upload_step = named_step(bind_source, "Upload exact binding and attestation bundle")
    if upload_step.get("if") != "github.event_name == 'pull_request'" or upload_step.get(
        "with"
    ) != {
        "name": "ci-merge-binding-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "ci-merge-binding-artifact",
        "if-no-files-found": "error",
        "retention-days": "7",
        "compression-level": "0",
        "overwrite": "false",
        "include-hidden-files": "false",
        "archive": "true",
    }:
        raise ContractError("enterprise bind-source artifact contract changed")
    validate_job_digest(
        bind_source,
        EXPECTED_TRUST_JOB_DIGESTS[("enterprise-hardening", "bind-source")],
        "enterprise-hardening bind-source",
    )

    for identifier in REQUIRED_CANDIDATE_ENTERPRISE_JOBS:
        enterprise_job = job(enterprise, identifier)
        if enterprise_job.get("runs-on") != "ubuntu-24.04":
            raise ContractError(
                f"required enterprise job is not on an ephemeral hosted runner: {identifier}"
            )
        if enterprise_job.get("permissions") != {"contents": "read"}:
            raise ContractError(
                f"required enterprise job permissions changed: {identifier}"
            )
        if "if" in enterprise_job:
            raise ContractError(f"required enterprise job is conditional: {identifier}")
        if enterprise_job.get("needs") != ["bind-source"]:
            raise ContractError(
                f"required enterprise job bypasses bound event source: {identifier}"
            )
        if identifier in EXPECTED_ENTERPRISE_BOUNDARY_STEP_INVENTORIES:
            execution_step = (
                "Verify freshness-bound mutation evidence"
                if identifier == "adversarial-evidence"
                else "Run isolated Linux evidence and cage campaigns"
            )
            operation = (
                "adversarial-release"
                if identifier == "adversarial-evidence"
                else "linux-enforcement"
            )
            validate_isolated_execution_job(
                enterprise_job,
                contract=f"enterprise {identifier}",
                inventory=EXPECTED_ENTERPRISE_BOUNDARY_STEP_INVENTORIES[identifier],
                candidate_step_name="Checkout exact candidate source without credentials",
                candidate_checkout=EXPECTED_ENTERPRISE_ISOLATED_CANDIDATE_CHECKOUT,
                trusted_checkout=EXPECTED_ENTERPRISE_TRUSTED_CHECKOUT,
                execution_step_name=execution_step,
                operation=operation,
            )
            continue
        steps = enterprise_job.get("steps")
        if not isinstance(steps, list) or len(steps) < 2:
            raise ContractError(
                f"required enterprise source steps are missing: {identifier}"
            )
        checkout_matches = [
            step
            for step in steps
            if isinstance(step, dict)
            and step.get("uses")
            == "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
        ]
        if (
            len(checkout_matches) != 1
            or steps[0] is not checkout_matches[0]
            or checkout_matches[0].get("with") != EXPECTED_ENTERPRISE_TESTED_CHECKOUT
            or set(checkout_matches[0]) != {"uses", "with"}
        ):
            raise ContractError(
                f"required enterprise job does not checkout the exact source without credentials: {identifier}"
            )
        source_check = named_step(enterprise_job, "Verify exact event test checkout")
        expected_source_check = (
            "set -euo pipefail\n"
            '[[ "${{ needs.bind-source.outputs.tested_sha }}" =~ ^[0-9a-f]{40}$ ]]\n'
            'test "$(git rev-parse HEAD)" = "${{ needs.bind-source.outputs.tested_sha }}"'
        )
        if (
            steps[1] is not source_check
            or set(source_check) != {"name", "run"}
            or source_check.get("run", "").strip() != expected_source_check
        ):
            raise ContractError(
                f"required enterprise job does not validate the exact source checkout: {identifier}"
            )

    if contains_key(enterprise, "continue-on-error"):
        raise ContractError("enterprise-hardening contains continue-on-error")

    portable = job(enterprise, "portable-contracts")
    for identifier in (
        "portable-contracts",
        "active-defense-security",
        "adversarial-evidence",
    ):
        if "if" in job(enterprise, identifier):
            raise ContractError(f"required enterprise job is conditional: {identifier}")
    enterprise_validators = named_step(portable, "Install Python validators")
    if enterprise_validators.get("run") != EXPECTED_ENTERPRISE_PYTHON_VALIDATORS_RUN:
        raise ContractError(
            "enterprise portable contracts do not install pinned Python validators"
        )
    uv_matches = [
        step
        for step in portable.get("steps", [])
        if isinstance(step, dict) and step.get("uses") == EXPECTED_UV_ACTION
    ]
    if len(uv_matches) != 1 or uv_matches[0].get("with") != EXPECTED_UV_INPUTS:
        raise ContractError("enterprise portable contracts do not install pinned uv")
    portable_evidence_steps = (
        ("Schema registry and generated bindings", EXPECTED_SCHEMA_BINDINGS_RUN),
        ("Native security conformance", EXPECTED_NATIVE_SECURITY_RUN),
        ("Python generated security conformance", EXPECTED_PYTHON_VECTOR_RUN),
        ("TypeScript generated security conformance", EXPECTED_TYPESCRIPT_VECTOR_RUN),
        ("Go generated security conformance", EXPECTED_GO_GENERATED_VECTOR_RUN),
    )
    validate_exact_steps(
        portable,
        portable_evidence_steps,
        "enterprise portable schema, codegen, and vector evidence",
        {
            "Go generated security conformance": {
                "working-directory": "sdks/go/chio-go-http"
            }
        },
    )

    validate_exact_steps(
        job(enterprise, "active-defense-security"),
        EXPECTED_ACTIVE_DEFENSE_STEPS,
        "active-defense security evidence",
    )
    hostile_probe = named_step(
        job(enterprise, "adversarial-evidence"),
        "Verify trusted execution boundary hostile probes",
    )
    hostile_probe_run = hostile_probe.get("run")
    if (
        hostile_probe.get("env")
        != {
            "CHIO_SECURITY_EXECUTION_IMAGE": "${{ steps.security-image.outputs.image }}"
        }
        or not isinstance(hostile_probe_run, str)
        or "authorized-security/scripts/tests/run-security-execution-container.test.py"
        not in hostile_probe_run
        or "--docker" not in hostile_probe_run
        or '--image "${CHIO_SECURITY_EXECUTION_IMAGE}"' not in hostile_probe_run
    ):
        raise ContractError(
            "enterprise adversarial evidence omits executable hostile probes"
        )

    committed_evidence = job(enterprise, "committed-linux-evidence")
    if (
        committed_evidence.get("name")
        != "verify committed Linux evidence from trusted checker bytes"
        or committed_evidence.get("needs") != ["bind-source", "linux-enforcement"]
        or committed_evidence.get("runs-on") != "ubuntu-24.04"
        or committed_evidence.get("timeout-minutes") != "15"
        or committed_evidence.get("permissions") != {"contents": "read"}
        or any(
            key in committed_evidence
            for key in ("if", "env", "concurrency", "continue-on-error")
        )
    ):
        raise ContractError("committed Linux evidence job protection changed")
    validate_step_inventory(
        committed_evidence,
        EXPECTED_COMMITTED_EVIDENCE_STEP_INVENTORY,
        "committed Linux evidence",
    )
    bootstrap_step = named_step(
        committed_evidence, "Bind committed evidence or authorize narrow bootstrap"
    )
    if set(bootstrap_step) != {"name", "id", "env", "run"} or bootstrap_step.get(
        "env"
    ) != {
        "AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
        "EVIDENCE_SHA": "${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}",
        "SOURCE_REPOSITORY": "${{ needs.bind-source.outputs.source_repository }}",
        "SOURCE_SHA": "${{ needs.bind-source.outputs.source_sha }}",
    }:
        raise ContractError("committed Linux evidence bootstrap bindings changed")
    require_run_markers(
        committed_evidence,
        "Bind committed evidence or authorize narrow bootstrap",
        (
            '[[ "${AUTHORIZED_SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            '[[ "${SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            'if test -z "${EVIDENCE_SHA}"; then',
            'test "${SOURCE_REPOSITORY}" = "${GITHUB_REPOSITORY}"',
            'test "${SOURCE_SHA}" = "${AUTHORIZED_SOURCE_SHA}"',
            'echo "verify=false" >> "${GITHUB_OUTPUT}"',
            '[[ "${EVIDENCE_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            'test "${EVIDENCE_SHA}" != "${AUTHORIZED_SOURCE_SHA}"',
            'echo "verify=true" >> "${GITHUB_OUTPUT}"',
        ),
        "committed Linux evidence bootstrap is wider than empty-E at authorized S",
    )
    verify_condition = "steps.evidence.outputs.verify == 'true'"
    evidence_checkout = named_step(
        committed_evidence, "Checkout exact committed evidence without credentials"
    )
    if evidence_checkout != {
        "name": "Checkout exact committed evidence without credentials",
        "if": verify_condition,
        "uses": "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        "with": {
            "repository": "${{ needs.bind-source.outputs.tested_repository }}",
            "ref": "${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}",
            "fetch-depth": "0",
            "persist-credentials": "false",
            "path": "committed-evidence",
        },
    }:
        raise ContractError(
            "committed Linux evidence checkout is not bound to detached E"
        )
    checker_checkout = named_step(
        committed_evidence,
        "Checkout exact authorized checker source without credentials",
    )
    if checker_checkout != {
        "name": "Checkout exact authorized checker source without credentials",
        "if": verify_condition,
        "uses": "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        "with": {
            "repository": "${{ needs.bind-source.outputs.tested_repository }}",
            "ref": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
            "fetch-depth": "1",
            "persist-credentials": "false",
            "path": "authorized-checker",
        },
    }:
        raise ContractError(
            "committed Linux evidence checker is not pinned to authorized S"
        )
    identity_step = named_step(
        committed_evidence, "Verify exact isolated checkout identities"
    )
    if identity_step.get("if") != verify_condition or identity_step.get("env") != {
        "AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
        "EVIDENCE_SHA": "${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}",
        "TESTED_REPOSITORY": "${{ needs.bind-source.outputs.tested_repository }}",
    }:
        raise ContractError("committed Linux evidence checkout identities changed")
    require_run_markers(
        committed_evidence,
        "Verify exact isolated checkout identities",
        (
            'test "$(git -C committed-evidence rev-parse HEAD)" = "${EVIDENCE_SHA}"',
            'test "$(git -C authorized-checker rev-parse HEAD)" = "${AUTHORIZED_SOURCE_SHA}"',
            "test -f authorized-checker/scripts/check-committed-linux-evidence.py",
            "test ! -L authorized-checker/scripts/check-committed-linux-evidence.py",
        ),
        "committed Linux evidence checkout identities changed",
    )
    committed_verify = named_step(
        committed_evidence, "Verify committed Linux evidence descendant"
    )
    if (
        committed_verify.get("if") != verify_condition
        or committed_verify.get("env")
        != {
            "AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
            "CANARY_SIGNER_PUBLIC_KEY": "${{ vars.CHIO_ENTERPRISE_CANARY_SIGNER_PUBLIC_KEY }}",
            "EVIDENCE_SHA": "${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}",
            "EVIDENCE_POLICY_JSON": "${{ vars.CHIO_ENTERPRISE_EVIDENCE_POLICY_JSON }}",
            "VERIFIER_SHA256": "${{ vars.CHIO_ENTERPRISE_EVIDENCE_VERIFIER_SHA256 }}",
            "VERIFIER_URL": "${{ vars.CHIO_ENTERPRISE_EVIDENCE_VERIFIER_URL }}",
        }
        or contains_text(committed_verify, "inputs.source_sha")
    ):
        raise ContractError("committed Linux evidence verification bindings changed")
    require_run_markers(
        committed_evidence,
        "Verify committed Linux evidence descendant",
        (
            'test "$(jq -r \'.source_commit\' <<< "${policy}")" = "${AUTHORIZED_SOURCE_SHA}"',
            "--proto '=https'",
            "--tlsv1.2",
            "--max-filesize 268435456",
            'test "$(sha256sum "${partial}" | cut -d\' \' -f1)" = "${VERIFIER_SHA256}"',
            "/usr/bin/python3 authorized-checker/scripts/check-committed-linux-evidence.py",
            "--root committed-evidence",
            '--source-commit "${AUTHORIZED_SOURCE_SHA}"',
            '--evidence-commit "${EVIDENCE_SHA}"',
            '--expected-binding-digest "0x$(jq -r \'.binding_digest\' <<< "${policy}")"',
        ),
        "committed Linux evidence does not use pinned checker bytes for detached E",
    )
    validate_job_digest(
        committed_evidence,
        EXPECTED_TRUST_JOB_DIGESTS[
            ("enterprise-hardening", "committed-linux-evidence")
        ],
        "enterprise-hardening committed-linux-evidence",
    )

    if evidence_controller.get("on") != EXPECTED_CONTROLLER_EVENTS:
        raise ContractError(
            "enterprise evidence controller is not base-defined on PR target"
        )
    if evidence_controller.get("permissions") != EXPECTED_CONTROLLER_PERMISSIONS:
        raise ContractError(
            "enterprise evidence controller changes its dispatch permissions"
        )
    if evidence_controller.get("concurrency") != EXPECTED_CONTROLLER_CONCURRENCY:
        raise ContractError(
            "enterprise evidence controller is not source-SHA serialized"
        )
    if action_uses(evidence_controller) != [
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    ]:
        raise ContractError(
            "enterprise evidence controller action inventory changed"
        )
    controller_jobs = workflow_jobs(evidence_controller)
    if set(controller_jobs) != {"dispatch-isolated-capture"}:
        raise ContractError("enterprise evidence controller job inventory changed")
    controller = job(evidence_controller, "dispatch-isolated-capture")
    if (
        controller.get("name") != "dispatch isolated enterprise Linux capture"
        or controller.get("runs-on") != "ubuntu-24.04"
        or controller.get("timeout-minutes") != "10"
        or controller.get("env")
        != {
            "AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
            "ENTERPRISE_SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
            "GH_TOKEN": "${{ github.token }}",
        }
    ):
        raise ContractError("enterprise evidence controller is not GitHub-hosted")
    expected_controller_condition = normalized_expression(
        "github.event.sender.type == 'User' && "
        "github.actor == github.repository_owner && "
        "github.event.pull_request.author_association == 'OWNER' && "
        "github.event.pull_request.head.repo.full_name == github.repository"
    )
    if normalized_expression(controller.get("if")) != expected_controller_condition:
        raise ContractError(
            "enterprise evidence controller does not restrict dispatch identity"
        )
    validate_step_inventory(
        controller,
        EXPECTED_CONTROLLER_STEP_INVENTORY,
        "enterprise evidence controller",
    )
    controller_authorize_step = named_step(
        controller, "Authorize exact source and controller context"
    )
    if controller_authorize_step.get("env") != {
        "CONTROLLER_ACTOR": "${{ github.actor }}",
        "CONTROLLER_RUN_ATTEMPT": "${{ github.run_attempt }}",
        "CONTROLLER_RUN_ID": "${{ github.run_id }}",
        "CONTROLLER_SHA": "${{ github.sha }}",
        "EVENT_BASE_REF": "${{ github.event.pull_request.base.ref }}",
        "EVENT_BASE_REPOSITORY": "${{ github.event.pull_request.base.repo.full_name }}",
        "EVENT_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "EVENT_HEAD_REPOSITORY": "${{ github.event.pull_request.head.repo.full_name }}",
        "EVENT_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
        "PR_NUMBER": "${{ github.event.pull_request.number }}",
        "SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
    }:
        raise ContractError("enterprise evidence controller trusted inputs changed")
    controller_authorize_run = require_run_markers(
        controller,
        "Authorize exact source and controller context",
        (
            "git/commits/${AUTHORIZED_SOURCE_SHA}",
            "git/trees/${authorized_tree_sha}?recursive=1",
            'test "$(jq -r \'.truncated\' <<< "${authorized_tree}")" = "false"',
            'test "${SECURITY_DEFINITION_SHA}" = "${ENTERPRISE_SECURITY_DEFINITION_SHA}"',
            "100644:deploy/docker/Dockerfile.security-evidence-runner",
            "100644:deploy/docker/security-evidence-apk.lock",
            "100644:deploy/docker/security-evidence-seccomp.json",
            "100755:crates/security/chio-cage/scripts/check-linux-enforcement.sh",
            "100644:scripts/check-cage-all-target-inventory.py",
            "100755:scripts/check-cage-enforcement.sh",
            "100755:scripts/check-exact-cargo-test-inventory.py",
            "100755:scripts/check-keyring-transparency.sh",
            "100755:scripts/check-linux-enforcement-stack.py",
            "100755:scripts/check-secret-broker-boundary.sh",
            "100755:scripts/check-security-adversarial-evidence.py",
            "100755:scripts/run-security-execution-container.py",
            "100755:scripts/security-execution-command-client.py",
            "100755:scripts/security-execution-container-entrypoint.py",
            "100755:scripts/tests/run-security-execution-container.test.py",
            "actions/workflows/enterprise-evidence-controller.yml",
            'test "$(jq -r \'.path\' <<< "${controller_run}")" = ".github/workflows/enterprise-evidence-controller.yml"',
            'test "$(jq -r \'.event\' <<< "${controller_run}")" = "pull_request_target"',
            'test "$(jq -r \'.head_sha\' <<< "${controller_run}")" = "${CONTROLLER_SHA}"',
            'test "$(jq -r \'.actor.login\' <<< "${controller_run}")" = "${CONTROLLER_ACTOR}"',
            'test "$(jq -r \'.triggering_actor.login\' <<< "${controller_run}")" = "${CONTROLLER_ACTOR}"',
            'test "${CONTROLLER_RUN_ATTEMPT}" = "1"',
            'test "$((now_epoch - controller_created_epoch))" -le 900',
            "contents/.github/workflows/enterprise-evidence-controller.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-evidence-controller.yml?ref=${CONTROLLER_SHA}",
            'test "${running_controller_blob_sha}" = "${controller_blob_sha}"',
            'test "$(jq -r \'.state\' <<< "${live_pr}")" = "open"',
            'test "$(jq -r \'.user.login\' <<< "${live_pr}")" = "${GITHUB_REPOSITORY_OWNER}"',
            'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${EVENT_HEAD_SHA}"',
            'test "$(jq -r \'.base.sha\' <<< "${live_pr}")" = "${EVENT_BASE_SHA}"',
            'test "$(jq -r \'.parents[0].sha\' <<< "${merge_commit}")" = "${EVENT_BASE_SHA}"',
            'test "$(jq -r \'.parents[1].sha\' <<< "${merge_commit}")" = "${EVENT_HEAD_SHA}"',
            "for _ in $(seq 0 32); do",
            "(.files | length) as $file_count |",
            '(.status == "added" or .status == "modified")',
            'select(.mode == "100644" and .type == "blob")',
            "enterprise-migration-binding-digest.txt",
            "enterprise-migration-canary.json.sha256",
            'test "$(jq -r \'.tree | length\' <<< "${evidence_tree}")" = "3"',
            'test "$(jq -r \'.object.sha\' <<< "${stable_merge_ref}")" = "${merge_commit_sha}"',
            'test "$(jq -r \'.tree.sha\' <<< "${stable_merge_commit}")" = "${merge_tree_sha}"',
        ),
        "enterprise evidence controller does not bind live workflow, PR, merge, and source authorization",
    )
    if ".merge_commit_sha" in controller_authorize_run:
        raise ContractError(
            "enterprise evidence controller trusts the mutable pull-request merge_commit_sha field"
        )
    dispatch_run = require_run_markers(
        controller,
        "Dispatch exact default-branch capture definition",
        (
            "contents/.github/workflows/enterprise-linux-capture.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-linux-capture.yml?ref=${default_commit_sha}",
            'test "${default_capture_blob_sha}" = "${authorized_capture_blob_sha}"',
            "actions/workflows/enterprise-linux-capture.yml",
            'test "$(jq -r \'.path\' <<< "${capture_workflow}")" = ".github/workflows/enterprise-linux-capture.yml"',
            'test "$(jq -r \'.state\' <<< "${capture_workflow}")" = "active"',
            'dispatch_nonce="$(openssl rand -hex 32)"',
            'display_title="Enterprise Linux capture N=${PR_NUMBER} E=${HEAD_SHA} M=${MERGE_COMMIT_SHA} S=${AUTHORIZED_SOURCE_SHA} K=${dispatch_nonce}"',
            "enterprise-linux-capture.yml/dispatches",
            '--arg ref "${default_branch}"',
            '--arg authorized_source_sha "${AUTHORIZED_SOURCE_SHA}"',
            '--arg controller_blob_sha "${CONTROLLER_BLOB_SHA}"',
            '--arg controller_dispatch_nonce "${dispatch_nonce}"',
            '--arg controller_issued_at_unix_ms "${CONTROLLER_ISSUED_AT_UNIX_MS}"',
            '--arg controller_run_attempt "${CONTROLLER_RUN_ATTEMPT}"',
            '--arg controller_run_id "${CONTROLLER_RUN_ID}"',
            '--arg controller_workflow_id "${CONTROLLER_WORKFLOW_ID}"',
            '--arg labels_digest "${LABELS_DIGEST}"',
            '--arg merge_commit_sha "${MERGE_COMMIT_SHA}"',
            '--arg merge_tree_sha "${MERGE_TREE_SHA}"',
            '--arg security_definition_sha "${SECURITY_DEFINITION_SHA}"',
            '--arg source_repository "${HEAD_REPOSITORY}"',
            '--arg source_sha "${HEAD_SHA}"',
            '--input - <<< "${payload}"',
            "enterprise-linux-capture.yml/runs?event=workflow_dispatch&branch=${default_branch}&per_page=100",
            "--paginate",
            '.display_title == $display_title',
            '.created_at >= $started_at',
            '.run_attempt == 1',
            'test "${match_count}" -le 1',
            'test "$(jq -r \'.display_title\' <<< "${dispatched_run}")" = "${display_title}"',
            'test "$(jq -r \'.run_attempt\' <<< "${dispatched_run}")" = "1"',
            'schema: "chio.enterprise-capture-dispatch-intent.v1"',
            'capture_run_attempt: "1"',
            '--argjson inputs "$(jq -cS \'.inputs\' <<< "${payload}")"',
            'echo "capture_run_id=${capture_run_id}"',
        ),
        "enterprise evidence controller does not bind exact capture inputs",
    )
    if dispatch_run.count("--arg ") != 32:
        raise ContractError(
            "enterprise evidence controller does not bind exact capture inputs"
        )
    expected_controller_intent_upload = {
        "name": "Upload exact capture dispatch intent",
        "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "with": {
            "name": "enterprise-capture-intent-${{ github.run_id }}-${{ github.run_attempt }}-${{ steps.dispatch.outputs.capture_run_id }}",
            "path": "${{ steps.dispatch.outputs.intent_path }}",
            "if-no-files-found": "error",
            "include-hidden-files": "false",
            "retention-days": "7",
        },
    }
    if (
        named_step(controller, "Upload exact capture dispatch intent")
        != expected_controller_intent_upload
    ):
        raise ContractError("enterprise evidence controller intent upload changed")
    validate_job_digest(
        controller,
        EXPECTED_TRUST_JOB_DIGESTS[
            ("enterprise evidence controller", "dispatch-isolated-capture")
        ],
        "enterprise evidence controller",
    )

    if linux_capture.get("on") != EXPECTED_CAPTURE_EVENTS:
        raise ContractError(
            "enterprise Linux capture changes its manual fixed-input contract"
        )
    if (
        linux_capture.get("run-name")
        != "Enterprise Linux capture N=${{ inputs.pr_number }} E=${{ inputs.source_sha }} M=${{ inputs.merge_commit_sha }} S=${{ inputs.authorized_source_sha }} K=${{ inputs.controller_dispatch_nonce }}"
    ):
        raise ContractError("enterprise Linux capture authenticated title changed")
    if linux_capture.get("permissions") != EXPECTED_CAPTURE_PERMISSIONS:
        raise ContractError(
            "enterprise Linux capture has permissions beyond read-only contents"
        )
    if linux_capture.get("concurrency") != EXPECTED_CAPTURE_CONCURRENCY:
        raise ContractError("enterprise Linux capture is not source-SHA serialized")
    capture_jobs = workflow_jobs(linux_capture)
    if set(capture_jobs) != {
        "authorize-capture",
        "refresh-linux-evidence",
        "capture-linux-enforcement",
        "dispatch-trusted-finalizer",
    }:
        raise ContractError("enterprise Linux capture job inventory changed")
    capture_authorization = job(linux_capture, "authorize-capture")
    if (
        capture_authorization.get("runs-on") != "ubuntu-24.04"
        or capture_authorization.get("timeout-minutes") != "10"
        or "if" in capture_authorization
        or capture_authorization.get("outputs")
        != EXPECTED_CAPTURE_AUTHORIZATION_OUTPUTS
        or capture_authorization.get("env")
        != {
            "AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
            "ENTERPRISE_SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
            "GH_TOKEN": "${{ github.token }}",
        }
    ):
        raise ContractError("isolated capture authorization job shape changed")
    validate_step_inventory(
        capture_authorization,
        EXPECTED_CAPTURE_STEP_INVENTORIES["authorize-capture"],
        "isolated capture authorization",
    )
    capture_authorization_step = named_step(
        capture_authorization, "Revalidate controller source and merge authorization"
    )
    if capture_authorization_step.get("env") != {
        "CAPTURE_ACTOR": "${{ github.actor }}",
        "CAPTURE_RUN_ATTEMPT": "${{ github.run_attempt }}",
        "CAPTURE_RUN_ID": "${{ github.run_id }}",
        "CAPTURE_SHA": "${{ github.sha }}",
        "INPUT_AUTHORIZED_SOURCE_SHA": "${{ inputs.authorized_source_sha }}",
        "INPUT_BASE_REF": "${{ inputs.base_ref }}",
        "INPUT_BASE_REPOSITORY": "${{ inputs.base_repository }}",
        "INPUT_BASE_SHA": "${{ inputs.base_sha }}",
        "INPUT_CONTROLLER_ACTOR": "${{ inputs.controller_actor }}",
        "INPUT_CONTROLLER_BLOB_SHA": "${{ inputs.controller_blob_sha }}",
        "INPUT_CONTROLLER_DISPATCH_NONCE": "${{ inputs.controller_dispatch_nonce }}",
        "INPUT_CONTROLLER_ISSUED_AT_UNIX_MS": "${{ inputs.controller_issued_at_unix_ms }}",
        "INPUT_CONTROLLER_RUN_ATTEMPT": "${{ inputs.controller_run_attempt }}",
        "INPUT_CONTROLLER_RUN_ID": "${{ inputs.controller_run_id }}",
        "INPUT_CONTROLLER_WORKFLOW_ID": "${{ inputs.controller_workflow_id }}",
        "INPUT_LABELS_DIGEST": "${{ inputs.labels_digest }}",
        "INPUT_MERGE_COMMIT_SHA": "${{ inputs.merge_commit_sha }}",
        "INPUT_MERGE_TREE_SHA": "${{ inputs.merge_tree_sha }}",
        "INPUT_MODE": "${{ inputs.mode }}",
        "INPUT_PR_NUMBER": "${{ inputs.pr_number }}",
        "INPUT_SECURITY_DEFINITION_SHA": "${{ inputs.security_definition_sha }}",
        "INPUT_SOURCE_REPOSITORY": "${{ inputs.source_repository }}",
        "INPUT_SOURCE_SHA": "${{ inputs.source_sha }}",
    }:
        raise ContractError("isolated capture trusted input bindings changed")
    capture_authorization_run = require_run_markers(
        capture_authorization,
        "Revalidate controller source and merge authorization",
        (
            'test "${INPUT_AUTHORIZED_SOURCE_SHA}" = "${AUTHORIZED_SOURCE_SHA}"',
            'test "${INPUT_SECURITY_DEFINITION_SHA}" = "${ENTERPRISE_SECURITY_DEFINITION_SHA}"',
            'test "${CAPTURE_RUN_ATTEMPT}" = "1"',
            'test "${INPUT_CONTROLLER_RUN_ATTEMPT}" = "1"',
            'test "${CAPTURE_ACTOR}" = "github-actions[bot]"',
            'test "$(jq -r \'.display_title\' <<< "${capture_run}")" = "Enterprise Linux capture N=${INPUT_PR_NUMBER} E=${INPUT_SOURCE_SHA} M=${INPUT_MERGE_COMMIT_SHA} S=${INPUT_AUTHORIZED_SOURCE_SHA} K=${INPUT_CONTROLLER_DISPATCH_NONCE}"',
            'test "$(jq -r \'.head_sha\' <<< "${capture_run}")" = "${CAPTURE_SHA}"',
            'test "$(jq -r \'.actor.login\' <<< "${capture_run}")" = "${CAPTURE_ACTOR}"',
            'test "$(jq -r \'.triggering_actor.login\' <<< "${capture_run}")" = "${CAPTURE_ACTOR}"',
            "actions/workflows/enterprise-evidence-controller.yml",
            "for _ in $(seq 1 30); do",
            'test "$(jq -r \'.status\' <<< "${controller_run}")" = "completed"',
            'test "$(jq -r \'.conclusion\' <<< "${controller_run}")" = "success"',
            'test "$(jq -r \'.triggering_actor.login\' <<< "${controller_run}")" = "${INPUT_CONTROLLER_ACTOR}"',
            'test "$(jq -r \'.conclusion\' <<< "${intent_upload_step}")" = "success"',
            "actions/runs/${INPUT_CONTROLLER_RUN_ID}/artifacts?per_page=100",
            'expected_intent_name="enterprise-capture-intent-${INPUT_CONTROLLER_RUN_ID}-${INPUT_CONTROLLER_RUN_ATTEMPT}-${CAPTURE_RUN_ID}"',
            'test "$(jq -r \'.workflow_run.id\' <<< "${intent_artifact}")" = "${INPUT_CONTROLLER_RUN_ID}"',
            "actions/artifacts/${intent_artifact_id}/zip",
            'test "$(sha256sum "${intent_partial}" | cut -d\' \' -f1)" = "${intent_artifact_digest#sha256:}"',
            'expected_name = "capture-dispatch-intent.json"',
            'test "$(jq -r \'.schema\' <<< "${intent}")" = "chio.enterprise-capture-dispatch-intent.v1"',
            'test "$(jq -cS \'.inputs\' <<< "${intent}")" = "${expected_inputs}"',
            'test "$(jq -r \'.capture_run_attempt\' <<< "${intent}")" = "${CAPTURE_RUN_ATTEMPT}"',
            'test "$(jq -r \'.dispatch_nonce\' <<< "${intent}")" = "${INPUT_CONTROLLER_DISPATCH_NONCE}"',
            "contents/.github/workflows/enterprise-evidence-controller.yml?ref=${INPUT_SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-evidence-controller.yml?ref=${controller_sha}",
            'test "${running_controller_blob_sha}" = "${controller_blob_sha}"',
            "contents/.github/workflows/enterprise-linux-capture.yml?ref=${INPUT_SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-linux-capture.yml?ref=${CAPTURE_SHA}",
            'test "${running_capture_blob_sha}" = "${capture_blob_sha}"',
            'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${INPUT_SOURCE_SHA}"',
            "repos/${GITHUB_REPOSITORY}/git/ref/pull/${INPUT_PR_NUMBER}/merge",
            'test "$(jq -r \'.ref\' <<< "${merge_ref}")" = "refs/pull/${INPUT_PR_NUMBER}/merge"',
            'test "$(jq -r \'.object.type\' <<< "${merge_ref}")" = commit',
            'test "$(jq -r \'.object.sha\' <<< "${merge_ref}")" = "${INPUT_MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.parents[0].sha\' <<< "${merge_commit}")" = "${INPUT_BASE_SHA}"',
            'test "$(jq -r \'.parents[1].sha\' <<< "${merge_commit}")" = "${INPUT_SOURCE_SHA}"',
            'test "$(jq -r \'.tree.sha\' <<< "${merge_commit}")" = "${INPUT_MERGE_TREE_SHA}"',
            "for _ in $(seq 0 32); do",
            "(.files | length) as $file_count |",
            '(.status == "added" or .status == "modified")',
            'select(.mode == "100644" and .type == "blob")',
            "enterprise-migration-binding-digest.txt",
            "enterprise-migration-canary.json.sha256",
            'test "$(jq -r \'.tree | length\' <<< "${evidence_tree}")" = "3"',
            'test "$((now_epoch - controller_epoch))" -le 1800',
            'test "$(jq -r \'.head.sha\' <<< "${stable_pr}")" = "${INPUT_SOURCE_SHA}"',
            'test "$(jq -r \'.base.sha\' <<< "${stable_pr}")" = "${INPUT_BASE_SHA}"',
            'test "$(jq -r \'.object.sha\' <<< "${stable_merge_ref}")" = "${INPUT_MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.tree.sha\' <<< "${stable_merge_commit}")" = "${INPUT_MERGE_TREE_SHA}"',
        ),
        "isolated capture does not revalidate controller, run, merge, source, and freshness bindings",
    )
    if "${{ inputs." in capture_authorization_run:
        raise ContractError(
            "isolated capture interpolates untrusted dispatch inputs into its trusted shell"
        )
    expected_capture_conditions = {
        "refresh-linux-evidence": "needs.authorize-capture.outputs.mode == 'refresh'",
        "capture-linux-enforcement": "needs.authorize-capture.outputs.mode == 'enforcement'",
    }
    for identifier, condition in expected_capture_conditions.items():
        capture_job = job(linux_capture, identifier)
        if capture_job.get("runs-on") != "ubuntu-24.04":
            raise ContractError(
                f"isolated capture job is not GitHub-hosted: {identifier}"
            )
        expected_timeout = "360" if identifier == "refresh-linux-evidence" else "180"
        if capture_job.get("timeout-minutes") != expected_timeout:
            raise ContractError(f"isolated capture timeout changed: {identifier}")
        if capture_job.get("if") != condition:
            raise ContractError(f"isolated capture mode is not exact: {identifier}")
        if capture_job.get("needs") != ["authorize-capture"]:
            raise ContractError(
                f"isolated capture bypasses authorization: {identifier}"
            )
        if capture_job.get("permissions") != {"contents": "read"}:
            raise ContractError(
                f"isolated capture job permissions changed: {identifier}"
            )
        validate_step_inventory(
            capture_job,
            EXPECTED_CAPTURE_STEP_INVENTORIES[identifier],
            f"isolated capture job {identifier}",
        )
        candidate_step_name = (
            "Checkout exact candidate source without credentials"
            if identifier == "refresh-linux-evidence"
            else "Checkout exact candidate merge without credentials"
        )
        candidate_checkout = (
            EXPECTED_SOURCE_CHECKOUT
            if identifier == "refresh-linux-evidence"
            else EXPECTED_MERGE_CHECKOUT
        )
        execution_step_name = (
            "Refresh all evidence inside trusted execution boundary"
            if identifier == "refresh-linux-evidence"
            else "Run candidate enforcement inside trusted execution boundary"
        )
        operation = (
            "refresh-all-evidence"
            if identifier == "refresh-linux-evidence"
            else "linux-enforcement"
        )
        validate_isolated_execution_job(
            capture_job,
            contract=f"isolated capture job {identifier}",
            inventory=EXPECTED_CAPTURE_STEP_INVENTORIES[identifier],
            candidate_step_name=candidate_step_name,
            candidate_checkout=candidate_checkout,
            trusted_checkout=EXPECTED_CAPTURE_TRUSTED_CHECKOUT,
            execution_step_name=execution_step_name,
            operation=operation,
        )
    capture_enforcement = job(linux_capture, "capture-linux-enforcement")
    require_run_markers(
        capture_enforcement,
        "Validate exact isolated candidate merge inputs",
        (
            'test "$(/usr/bin/git -C candidate rev-parse HEAD)" = "${MERGE_COMMIT_SHA}"',
            'test "$(/usr/bin/git -C candidate rev-parse \'HEAD^{tree}\')" = "${MERGE_TREE_SHA}"',
            'test "$(/usr/bin/git -C candidate rev-parse \'HEAD^1\')" = "${BASE_SHA}"',
            'test "$(/usr/bin/git -C candidate rev-parse \'HEAD^2\')" = "${EVIDENCE_SOURCE_SHA}"',
            'test "$(/usr/bin/git -C authorized-security rev-parse HEAD)" = "${AUTHORIZED_SOURCE_SHA}"',
        ),
        "isolated Linux capture does not execute the exact test merge",
    )
    unsigned_summary_run = named_step(
        capture_enforcement, "Build unsigned fixed-schema capture"
    ).get("run")
    image_provenance_marker = (
        '"security_execution_image": os.environ["SECURITY_EXECUTION_IMAGE"]'
    )
    seccomp_provenance_marker = (
        '"security_execution_seccomp_sha256": '
        'os.environ["SECURITY_EXECUTION_SECCOMP_SHA256"]'
    )
    if (
        not isinstance(unsigned_summary_run, str)
        or not all(
            value in unsigned_summary_run
            for value in (
                '"candidate_artifacts_executed": True',
                '"authorized_source_commit": os.environ["AUTHORIZED_SOURCE_SHA"]',
                '"capture_actor": os.environ["CAPTURE_ACTOR"]',
                '"capture_definition_blob": os.environ["CAPTURE_BLOB_SHA"]',
                '"capture_workflow_id": os.environ["CAPTURE_WORKFLOW_ID"]',
                '"controller_definition_blob": os.environ["CONTROLLER_BLOB_SHA"]',
                '"controller_workflow_id": os.environ["CONTROLLER_WORKFLOW_ID"]',
                '"gate_result_digests": gate_result_digests',
                '"merge_commit": os.environ["MERGE_COMMIT_SHA"]',
                '"merge_tree": os.environ["MERGE_TREE_SHA"]',
                '"runner_environment": "github-hosted"',
                '"runner_name": os.environ["RUNNER_NAME"]',
                '"schema": "chio.enterprise-linux-capture.v2"',
                '"signed": False',
                '"source_commit": os.environ["EVIDENCE_SOURCE_SHA"]',
                '"security_definition_commit": os.environ["SECURITY_DEFINITION_SHA"]',
                image_provenance_marker,
                seccomp_provenance_marker,
                "sha256sum authorized-security/deploy/docker/security-evidence-seccomp.json",
                "> artifact-files.sha256",
            )
        )
        or unsigned_summary_run.count(image_provenance_marker) != 2
        or unsigned_summary_run.count(seccomp_provenance_marker) != 2
    ):
        raise ContractError(
            "isolated Linux capture changes its unsigned summary contract"
        )
    expected_capture_upload = {
        "name": "Upload bounded unsigned Linux capture",
        "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "with": {
            "name": "enterprise-linux-capture-${{ needs.authorize-capture.outputs.source_sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
            "path": "${{ runner.temp }}/enterprise-linux-capture/",
            "if-no-files-found": "error",
            "include-hidden-files": "false",
            "retention-days": "7",
        },
    }
    capture_upload = named_step(
        capture_enforcement, "Upload bounded unsigned Linux capture"
    )
    if capture_upload != expected_capture_upload:
        raise ContractError(
            "isolated Linux capture does not upload the fixed unsigned artifact"
        )
    finalizer_dispatch = job(linux_capture, "dispatch-trusted-finalizer")
    if (
        finalizer_dispatch.get("name")
        != "dispatch trusted enterprise evidence finalizer"
        or finalizer_dispatch.get("if")
        != "needs.authorize-capture.outputs.mode == 'enforcement'"
        or finalizer_dispatch.get("needs")
        != ["authorize-capture", "capture-linux-enforcement"]
        or finalizer_dispatch.get("permissions")
        != {"actions": "write", "contents": "read"}
        or finalizer_dispatch.get("runs-on") != "ubuntu-24.04"
        or finalizer_dispatch.get("timeout-minutes") != "10"
        or "env" in finalizer_dispatch
    ):
        raise ContractError("trusted finalizer dispatch job protection changed")
    if contains_text(finalizer_dispatch, "actions/checkout@") or contains_text(
        finalizer_dispatch, "git checkout"
    ):
        raise ContractError(
            "trusted finalizer dispatch job must not checkout candidate code"
        )
    validate_step_inventory(
        finalizer_dispatch,
        EXPECTED_CAPTURE_STEP_INVENTORIES["dispatch-trusted-finalizer"],
        "trusted finalizer dispatch",
    )
    dispatch_step = named_step(
        finalizer_dispatch, "Dispatch exact default-branch finalizer definition"
    )
    if dispatch_step.get("env") != {
        "AUTHORIZED_SOURCE_SHA": "${{ needs.authorize-capture.outputs.authorized_source_sha }}",
        "CAPTURE_RUN_ATTEMPT": "${{ needs.authorize-capture.outputs.capture_run_attempt }}",
        "CAPTURE_RUN_ID": "${{ needs.authorize-capture.outputs.capture_run_id }}",
        "GH_TOKEN": "${{ github.token }}",
        "LIVE_SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
        "MERGE_COMMIT_SHA": "${{ needs.authorize-capture.outputs.merge_commit_sha }}",
        "PR_NUMBER": "${{ needs.authorize-capture.outputs.pr_number }}",
        "SECURITY_DEFINITION_SHA": "${{ needs.authorize-capture.outputs.security_definition_sha }}",
        "SOURCE_SHA": "${{ needs.authorize-capture.outputs.source_sha }}",
    }:
        raise ContractError("trusted finalizer dispatch inputs changed")
    finalizer_dispatch_run = require_run_markers(
        finalizer_dispatch,
        "Dispatch exact default-branch finalizer definition",
        (
            'test "${GITHUB_ACTOR}" = "github-actions[bot]"',
            'test "${GITHUB_TRIGGERING_ACTOR}" = "github-actions[bot]"',
            'test "${LIVE_SECURITY_DEFINITION_SHA}" = "${SECURITY_DEFINITION_SHA}"',
            '[[ "${AUTHORIZED_SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            '[[ "${MERGE_COMMIT_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            '[[ "${PR_NUMBER}" =~ ^[1-9][0-9]*$ ]]',
            "contents/.github/workflows/enterprise-linux-capture.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-linux-capture.yml?ref=${GITHUB_SHA}",
            'test "${running_capture_blob_sha}" = "${authorized_capture_blob_sha}"',
            'default_commit_sha="$(jq -r \'.sha\' <<< "${default_commit}")"',
            "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${default_commit_sha}",
            'test "${default_finalizer_blob_sha}" = "${authorized_finalizer_blob_sha}"',
            "actions/workflows/enterprise-evidence-finalizer.yml",
            'test "$(jq -r \'.path\' <<< "${finalizer_workflow}")" = ".github/workflows/enterprise-evidence-finalizer.yml"',
            'test "$(jq -r \'.state\' <<< "${finalizer_workflow}")" = "active"',
            'dispatch_nonce="$(openssl rand -hex 32)"',
            'display_title="Enterprise evidence finalizer N=${PR_NUMBER} E=${SOURCE_SHA} M=${MERGE_COMMIT_SHA} S=${AUTHORIZED_SOURCE_SHA} K=${dispatch_nonce}"',
            '--arg authorized_source_sha "${AUTHORIZED_SOURCE_SHA}"',
            '--arg capture_run_attempt "${CAPTURE_RUN_ATTEMPT}"',
            '--arg capture_run_id "${CAPTURE_RUN_ID}"',
            '--arg dispatch_nonce "${dispatch_nonce}"',
            '--arg merge_commit_sha "${MERGE_COMMIT_SHA}"',
            '--arg pr_number "${PR_NUMBER}"',
            '--arg ref "${default_branch}"',
            '--arg security_definition_sha "${SECURITY_DEFINITION_SHA}"',
            '--arg source_sha "${SOURCE_SHA}"',
            "enterprise-evidence-finalizer.yml/dispatches",
            '--input - <<< "${payload}"',
            "enterprise-evidence-finalizer.yml/runs?event=workflow_dispatch&branch=${default_branch}&per_page=100",
            "--paginate",
            '--arg display_title "${display_title}"',
            ".display_title == $display_title",
            ".created_at >= $started_at",
            'test "${match_count}" -le 1',
            'if test "${match_count}" = "1"; then',
            'case "$(jq -r \'.status\' <<< "${candidate_run}")" in',
            "in_progress)",
            'dispatched_run="${candidate_run}"',
            "queued)",
            "completed)",
            "exact finalizer completed before in-progress ownership was observed",
            "for _ in $(seq 1 120); do",
            'test -n "${dispatched_run}"',
            'test "$(jq -r \'.display_title\' <<< "${dispatched_run}")" = "${display_title}"',
            'test "$(jq -r \'.head_sha\' <<< "${dispatched_run}")" = "${default_commit_sha}"',
            'test "$(jq -r \'.run_attempt\' <<< "${dispatched_run}")" = "1"',
            'test "$(jq -r \'.status\' <<< "${dispatched_run}")" = "in_progress"',
            'schema: "chio.enterprise-finalizer-dispatch-intent.v1"',
            'finalizer_run_attempt: "1"',
            '--arg finalizer_run_id "${dispatched_run_id}"',
            'echo "finalizer_run_id=${dispatched_run_id}"',
            'echo "intent_path=${intent_path}"',
        ),
        "trusted finalizer dispatch does not bind the exact run, definition, source, and workflow",
    )
    final_output_assertion = '} >> "${GITHUB_OUTPUT}"'
    if (
        finalizer_dispatch_run.count("--arg ") != 26
        or "queued|in_progress)" in finalizer_dispatch_run
        or "queued|in_progress|completed)" in finalizer_dispatch_run
        or not finalizer_dispatch_run.strip().endswith(final_output_assertion)
    ):
        raise ContractError("trusted finalizer dispatch inputs changed")
    expected_finalizer_intent_upload = {
        "name": "Upload exact finalizer dispatch intent",
        "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "with": {
            "name": "enterprise-finalizer-intent-${{ github.run_id }}-${{ github.run_attempt }}-${{ steps.dispatch.outputs.finalizer_run_id }}",
            "path": "${{ steps.dispatch.outputs.intent_path }}",
            "if-no-files-found": "error",
            "include-hidden-files": "false",
            "retention-days": "7",
        },
    }
    if (
        named_step(finalizer_dispatch, "Upload exact finalizer dispatch intent")
        != expected_finalizer_intent_upload
    ):
        raise ContractError("trusted finalizer dispatch intent upload changed")
    refresh_upload = named_step(
        job(linux_capture, "refresh-linux-evidence"), "Upload unsigned evidence patch"
    )
    if refresh_upload != {
        "name": "Upload unsigned evidence patch",
        "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "with": {
            "name": "linux-adversarial-evidence-${{ needs.authorize-capture.outputs.source_sha }}-${{ github.run_id }}-${{ github.run_attempt }}",
            "path": (
                "${{ runner.temp }}/linux-evidence-artifact/all-evidence-inventory.json\n"
                "${{ runner.temp }}/linux-evidence-artifact/all-evidence.patch\n"
                "${{ runner.temp }}/linux-evidence-artifact/all-evidence.patch.sha256\n"
                "${{ runner.temp }}/linux-evidence-artifact/source-sha.txt\n"
            ),
            "if-no-files-found": "error",
            "retention-days": "7",
        },
    }:
        raise ContractError("isolated Linux evidence refresh upload changed")
    for identifier in capture_jobs:
        validate_job_digest(
            job(linux_capture, identifier),
            EXPECTED_TRUST_JOB_DIGESTS[("enterprise Linux capture", identifier)],
            f"enterprise Linux capture {identifier}",
        )

    if evidence_finalizer.get("on") != EXPECTED_FINALIZER_EVENTS:
        raise ContractError(
            "enterprise evidence finalizer changes its explicit dispatch contract"
        )
    if (
        evidence_finalizer.get("run-name")
        != "Enterprise evidence finalizer N=${{ inputs.pr_number }} E=${{ inputs.source_sha }} M=${{ inputs.merge_commit_sha }} S=${{ inputs.authorized_source_sha }} K=${{ inputs.dispatch_nonce }}"
    ):
        raise ContractError("enterprise evidence finalizer authenticated title changed")
    if evidence_finalizer.get("permissions") != EXPECTED_FINALIZER_PERMISSIONS:
        raise ContractError(
            "enterprise evidence finalizer changes its read-only permissions"
        )
    if "concurrency" in evidence_finalizer:
        raise ContractError(
            "enterprise evidence finalizer workflow concurrency is not deferred to source binding"
        )
    finalizer_uses = action_uses(evidence_finalizer)
    if finalizer_uses != [
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    ]:
        raise ContractError("enterprise evidence finalizer action inventory changed")
    finalizer_jobs = workflow_jobs(evidence_finalizer)
    if set(finalizer_jobs) != {
        "validate-capture",
        "sign-validated-capture",
        "authorize-security-check-publication",
        "publish-security-contract",
    }:
        raise ContractError("enterprise evidence finalizer job inventory changed")
    validate_capture = job(evidence_finalizer, "validate-capture")
    sign_capture = job(evidence_finalizer, "sign-validated-capture")
    authorize_publication = job(
        evidence_finalizer, "authorize-security-check-publication"
    )
    publish_security_contract = job(evidence_finalizer, "publish-security-contract")
    if contains_text(validate_capture, "${{ secrets."):
        raise ContractError("capture validation receives a signing secret")
    if (
        "if" in validate_capture
        or validate_capture.get("runs-on") != "ubuntu-24.04"
        or validate_capture.get("timeout-minutes") != "15"
        or validate_capture.get("env")
        != {
            "AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
            "ENTERPRISE_SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
            "GH_TOKEN": "${{ github.token }}",
        }
    ):
        raise ContractError("enterprise evidence validation job identity changed")
    validate_step_inventory(
        validate_capture,
        EXPECTED_FINALIZER_STEP_INVENTORIES["validate-capture"],
        "enterprise evidence validation",
    )
    artifact_bind_step = named_step(
        validate_capture, "Bind finalizer capture job and artifact identities"
    )
    if artifact_bind_step.get("env") != {
        "AUTHORIZED_SOURCE_INPUT_SHA": "${{ inputs.authorized_source_sha }}",
        "CAPTURE_RUN_ATTEMPT": "${{ inputs.capture_run_attempt }}",
        "CAPTURE_RUN_ID": "${{ inputs.capture_run_id }}",
        "DISPATCH_NONCE": "${{ inputs.dispatch_nonce }}",
        "FINALIZER_ACTOR": "${{ github.actor }}",
        "FINALIZER_RUN_ATTEMPT": "${{ github.run_attempt }}",
        "FINALIZER_RUN_ID": "${{ github.run_id }}",
        "FINALIZER_SHA": "${{ github.sha }}",
        "MERGE_COMMIT_SHA": "${{ inputs.merge_commit_sha }}",
        "PR_NUMBER": "${{ inputs.pr_number }}",
        "SECURITY_DEFINITION_SHA": "${{ inputs.security_definition_sha }}",
        "SOURCE_SHA": "${{ inputs.source_sha }}",
    }:
        raise ContractError("enterprise evidence finalizer trusted inputs changed")
    artifact_bind_run = require_run_markers(
        validate_capture,
        "Bind finalizer capture job and artifact identities",
        (
            "actions/workflows/enterprise-evidence-finalizer.yml",
            'test "${FINALIZER_ACTOR}" = "github-actions[bot]"',
            'test "${GITHUB_TRIGGERING_ACTOR}" = "github-actions[bot]"',
            'test "${SECURITY_DEFINITION_SHA}" = "${ENTERPRISE_SECURITY_DEFINITION_SHA}"',
            'test "${AUTHORIZED_SOURCE_INPUT_SHA}" = "${AUTHORIZED_SOURCE_SHA}"',
            'test "$(jq -r \'.actor.login\' <<< "${finalizer_run}")" = "${FINALIZER_ACTOR}"',
            'test "$(jq -r \'.triggering_actor.login\' <<< "${finalizer_run}")" = "${FINALIZER_ACTOR}"',
            'test "$(jq -r \'.event\' <<< "${finalizer_run}")" = "workflow_dispatch"',
            '[[ "${DISPATCH_NONCE}" =~ ^[0-9a-f]{64}$ ]]',
            'test "$(jq -r \'.display_title\' <<< "${finalizer_run}")" = "Enterprise evidence finalizer N=${PR_NUMBER} E=${SOURCE_SHA} M=${MERGE_COMMIT_SHA} S=${AUTHORIZED_SOURCE_SHA} K=${DISPATCH_NONCE}"',
            'test "$(jq -r \'.head_sha\' <<< "${finalizer_run}")" = "${FINALIZER_SHA}"',
            "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${FINALIZER_SHA}",
            'test "${running_finalizer_blob_sha}" = "${finalizer_blob_sha}"',
            "actions/workflows/enterprise-linux-capture.yml",
            "for _ in $(seq 1 120); do",
            "sleep 5",
            'test "$(jq -r \'.path\' <<< "${capture_run}")" = ".github/workflows/enterprise-linux-capture.yml"',
            'test "$(jq -r \'.conclusion\' <<< "${capture_run}")" = "success"',
            'capture_sha="$(jq -r \'.head_sha\' <<< "${capture_run}")"',
            'test "${capture_actor}" = "github-actions[bot]"',
            'test "$(jq -r \'.triggering_actor.login\' <<< "${capture_run}")" = "${capture_actor}"',
            "contents/.github/workflows/enterprise-linux-capture.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-linux-capture.yml?ref=${capture_sha}",
            'test "${running_capture_blob_sha}" = "${capture_blob_sha}"',
            'test "$((now_epoch - capture_created_epoch))" -le 14400',
            "attempts/${CAPTURE_RUN_ATTEMPT}/jobs?filter=all&per_page=100",
            'select(.name == "capture isolated enterprise Linux enforcement")',
            'test "$(jq -r \'.conclusion\' <<< "${capture_job}")" = "success"',
            'test "$(jq -r \'.runner_group_id\' <<< "${capture_job}")" = "0"',
            'test "$(jq -r \'.runner_group_name\' <<< "${capture_job}")" = "GitHub Actions"',
            'test "${runner_labels}" = \'["ubuntu-24.04"]\'',
            r'[[ "${runner_name}" =~ ^GitHub\ Actions\ [1-9][0-9]*$ ]]',
            "actions/runs/${CAPTURE_RUN_ID}/artifacts?per_page=100",
            "--paginate",
            "--jq '.artifacts[]'",
            'expected_artifact_name="enterprise-linux-capture-${SOURCE_SHA}-${CAPTURE_RUN_ID}-${CAPTURE_RUN_ATTEMPT}"',
            '--arg artifact_name "${expected_artifact_name}"',
            '--arg capture_run_id "${CAPTURE_RUN_ID}"',
            ".name == $artifact_name",
            "(.workflow_run.id | tostring) == $capture_run_id",
            'test "$(jq -r \'length\' <<< "${attempt_artifacts}")" = "1"',
            'artifact="$(jq -c \'.[0]\' <<< "${attempt_artifacts}")"',
            'test "${artifact_name}" = "${expected_artifact_name}"',
            'test "$(jq -r \'.expired\' <<< "${artifact}")" = "false"',
            'test "$(jq -r \'.workflow_run.id\' <<< "${artifact}")" = "${CAPTURE_RUN_ID}"',
            'test "${artifact_size}" -le 67108864',
            'test "${artifact_updated_epoch}" -le "${job_completed_epoch}"',
            'test "${artifact_updated_epoch}" -le "${finalizer_created_epoch}"',
            'test "$((artifact_updated_epoch - artifact_created_epoch))" -le 600\n',
        ),
        "enterprise evidence finalizer does not bind exact workflow, job, actor, run, artifact, and freshness identities",
    )
    if (
        ".total_count" in artifact_bind_run
        or 'length\' <<< "${artifacts}")" = "1"' in artifact_bind_run
    ):
        raise ContractError(
            "enterprise evidence finalizer requires a global artifact singleton across rerun attempts"
        )
    require_run_markers(
        validate_capture,
        "Download bounded unsigned capture archive",
        (
            "actions/artifacts/${ARTIFACT_ID}/zip",
            'test "$(stat --format=\'%F:%a\' "${partial}")" = "regular file:600"',
            'test "$(stat --format=\'%s\' "${partial}")" = "${ARTIFACT_SIZE}"',
            'test "$(sha256sum "${partial}" | cut -d\' \' -f1)" = "${ARTIFACT_DIGEST}"',
            'mv -- "${partial}" "${archive}"',
        ),
        "enterprise evidence finalizer does not prebind the downloaded artifact",
    )
    require_run_markers(
        validate_capture,
        "Safely extract exact bounded capture files",
        (
            'with zipfile.ZipFile(archive, "r") as source:',
            "if len(infos) != max_members:",
            "name not in expected",
            "or name in observed",
            "or path.is_absolute()",
            "or len(path.parts) != 1",
            'or "\\\\" in name',
            "or info.is_dir()",
            "or info.flag_bits & 0x1",
            "not stat.S_ISREG(mode)",
            "info.file_size > expected[name]",
            "info.compress_size > 67_108_864",
            "info.file_size > (info.compress_size * 100) + 1_048_576",
            "if total > max_total:",
            "os.O_EXCL | os.O_NOFOLLOW",
            "remaining = info.file_size",
            "if member.read(1):",
            "if observed != set(expected):",
        ),
        "enterprise evidence finalizer weakens safe bounded extraction",
    )
    fixed_schema_run = require_run_markers(
        validate_capture,
        "Validate canonical fixed-schema capture data",
        (
            "if summary_bytes != canonical_summary:",
            "if sha_lines != expected_lines:",
            'summary["schema"] != "chio.enterprise-linux-capture.v2"',
            'summary["candidate_artifacts_executed"] is not True',
            'summary["signed"] is not False or summary["mode"] != "enforcement"',
            'summary["capture_actor"] != os.environ["EXPECTED_CAPTURE_ACTOR"]',
            'summary["capture_definition_blob"] != os.environ["EXPECTED_CAPTURE_DEFINITION_BLOB"]',
            'summary["capture_issued_at_unix_ms"] != os.environ["EXPECTED_CAPTURE_ISSUED_AT_UNIX_MS"]',
            'summary["capture_workflow_id"] != os.environ["EXPECTED_CAPTURE_WORKFLOW_ID"]',
            'summary["security_definition_commit"] != os.environ["SECURITY_DEFINITION_SHA"]',
            'summary["merge_commit"] != os.environ["EXPECTED_MERGE_COMMIT_SHA"]',
            'str(summary["pull_request_number"]) != os.environ["EXPECTED_PR_NUMBER"]',
            'summary["security_execution_image"]',
            'summary["security_execution_seccomp_sha256"]',
            'boundary["schema"] != "chio.security-execution-boundary.v1"',
            'boundary["image_id"] != summary["security_execution_image"]',
            'boundary["seccomp_profile_sha256"]',
            'boundary["trusted_file_sha256"]',
            'set(boundary["trusted_file_sha256"]) != expected_trusted_files',
            '"command-client.py"',
            '"verifier-bin/cargo"',
            '"verifier-bin/cc"',
            '"verifier-bin/ldd"',
            'summary["base_ref"] != os.environ["EXPECTED_BASE_REF"]',
            'summary["base_repository"] != os.environ["EXPECTED_REPOSITORY"]',
            'summary["source_repository"] != os.environ["EXPECTED_REPOSITORY"]',
            'summary["controller_actor"] != os.environ["EXPECTED_CONTROLLER_ACTOR"]',
            'artifact_match.group(1) != summary["source_commit"]',
            'if summary["inventory"] != inventory:',
            'if summary["gate_result_digests"] != expected_gate_digests:',
            'summary["configuration_digest"]',
        ),
        "enterprise evidence finalizer weakens fixed-schema validation",
    )
    output_write_marker = 'with Path(os.environ["GITHUB_OUTPUT"]).open('
    fixed_output_bindings = (
        'summary["base_ref"] != os.environ["EXPECTED_BASE_REF"]',
        'summary["base_repository"] != os.environ["EXPECTED_REPOSITORY"]',
        'summary["source_repository"] != os.environ["EXPECTED_REPOSITORY"]',
        'summary["controller_actor"] != os.environ["EXPECTED_CONTROLLER_ACTOR"]',
    )
    if output_write_marker not in fixed_schema_run or any(
        fixed_schema_run.index(binding) > fixed_schema_run.index(output_write_marker)
        for binding in fixed_output_bindings
    ):
        raise ContractError(
            "enterprise evidence finalizer writes attacker-controlled identity outputs"
        )
    require_run_markers(
        validate_capture,
        "Revalidate live authorization and issuance freshness",
        (
            "actions/workflows/enterprise-evidence-controller.yml",
            'test "${CONTROLLER_WORKFLOW_ID}" = "${expected_controller_workflow_id}"',
            'test "$(jq -r \'.triggering_actor.login\' <<< "${controller_run}")" = "${CONTROLLER_ACTOR}"',
            'test "$(( $(date --date="$(jq -r \'.created_at\' <<< "${controller_run}")" +%s) * 1000 ))" = "${CONTROLLER_ISSUED_AT_UNIX_MS}"',
            "contents/.github/workflows/enterprise-evidence-controller.yml?ref=${SECURITY_DEFINITION_SHA}",
            'test "${controller_blob_sha}" = "${CONTROLLER_DEFINITION_BLOB}"',
            "contents/.github/workflows/enterprise-evidence-controller.yml?ref=${controller_sha}",
            'test "${running_controller_blob_sha}" = "${controller_blob_sha}"',
            'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${SOURCE_SHA}"',
            "repos/${GITHUB_REPOSITORY}/git/ref/pull/${PR_NUMBER}/merge",
            'test "$(jq -r \'.object.sha\' <<< "${merge_ref}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.labels | any(.name == "refresh-linux-evidence")\' <<< "${live_pr}")" = "false"',
            'test "$(jq -r \'.parents[0].sha\' <<< "${merge_commit}")" = "${BASE_SHA}"',
            'test "$(jq -r \'.parents[1].sha\' <<< "${merge_commit}")" = "${SOURCE_SHA}"',
            "for _ in $(seq 0 32); do",
            "(.files | length) as $file_count |",
            '(.status == "added" or .status == "modified")',
            'select(.mode == "100644" and .type == "blob")',
            "enterprise-migration-binding-digest.txt",
            "enterprise-migration-canary.json.sha256",
            'test "$(jq -r \'.tree | length\' <<< "${evidence_tree}")" = "3"',
            'test "$((now_unix_ms - CONTROLLER_ISSUED_AT_UNIX_MS))" -le 14400000',
        ),
        "enterprise evidence finalizer does not revalidate live source and issuance bindings",
    )
    if contains_text(validate_capture, "generated_at_not_"):
        raise ContractError(
            "enterprise evidence finalizer computes the canary window before protected signing"
        )
    secret_locations = secret_reference_locations(evidence_finalizer)
    expected_secret_locations = [
        (
            (
                "jobs",
                "sign-validated-capture",
                "steps",
                1,
                "env",
                EXPECTED_FINALIZER_SECRET[0],
            ),
            EXPECTED_FINALIZER_SECRET[1],
        ),
        (
            (
                "jobs",
                "publish-security-contract",
                "steps",
                0,
                "env",
                EXPECTED_PUBLISHER_SECRET[0],
            ),
            EXPECTED_PUBLISHER_SECRET[1],
        ),
    ]
    if secret_locations != expected_secret_locations:
        raise ContractError(
            "trusted finalizer signing and publisher secret inventory changed"
        )
    if (
        sign_capture.get("name") != "sign committed enterprise Linux migration evidence"
        or sign_capture.get("needs") != ["validate-capture"]
        or sign_capture.get("environment") != "enterprise-evidence-signing"
        or sign_capture.get("concurrency") != EXPECTED_SIGNING_CONCURRENCY
        or sign_capture.get("permissions") != {"contents": "read"}
        or sign_capture.get("runs-on") != "ubuntu-24.04"
        or sign_capture.get("timeout-minutes") != "10"
        or "env" in sign_capture
    ):
        raise ContractError("trusted finalizer signing job protection changed")
    validate_step_inventory(
        sign_capture,
        EXPECTED_FINALIZER_STEP_INVENTORIES["sign-validated-capture"],
        "enterprise evidence signing",
    )
    signing_step = named_step(
        sign_capture, "Create and verify committed migration canary"
    )
    if (
        signing_step.get("env", {}).get(EXPECTED_FINALIZER_SECRET[0])
        != EXPECTED_FINALIZER_SECRET[1]
    ):
        raise ContractError(
            "trusted finalizer seed is not confined to its signing step"
        )
    signing_env = signing_step.get("env", {})
    if (
        signing_env.get("CAPTURE_ISSUED_AT_UNIX_MS")
        != "${{ needs.validate-capture.outputs.capture_issued_at_unix_ms }}"
        or signing_env.get("CONTROLLER_ISSUED_AT_UNIX_MS")
        != "${{ needs.validate-capture.outputs.controller_issued_at_unix_ms }}"
        or "GENERATED_AT_NOT_BEFORE_UNIX_MS" in signing_env
        or "GENERATED_AT_NOT_AFTER_UNIX_MS" in signing_env
    ):
        raise ContractError(
            "trusted finalizer signing freshness inputs or window ownership changed"
        )
    verifier_step = named_step(sign_capture, "Acquire pinned trusted evidence verifier")
    if verifier_step.get("env") != {
        "CANARY_SIGNER_PUBLIC_KEY": "${{ vars.CHIO_ENTERPRISE_CANARY_SIGNER_PUBLIC_KEY }}",
        "VERIFIER_SHA256": "${{ vars.CHIO_ENTERPRISE_EVIDENCE_VERIFIER_SHA256 }}",
        "VERIFIER_URL": "${{ vars.CHIO_ENTERPRISE_EVIDENCE_VERIFIER_URL }}",
    }:
        raise ContractError("trusted finalizer verifier inputs changed")
    require_run_markers(
        sign_capture,
        "Acquire pinned trusted evidence verifier",
        (
            '[[ "${CANARY_SIGNER_PUBLIC_KEY}" =~ ^[0-9a-f]{64}$ ]]',
            '[[ "${VERIFIER_SHA256}" =~ ^[0-9a-f]{64}$ ]]',
            "https://github.com/bb-connor/arc/releases/download/",
            "--proto '=https'",
            "--tlsv1.2",
            "--max-filesize 268435456",
            'test "$(sha256sum "${partial}" | cut -d\' \' -f1)" = "${VERIFIER_SHA256}"',
            'chmod 0500 "${partial}"',
        ),
        "trusted finalizer does not acquire a bounded hash-pinned verifier",
    )
    signing_run = require_run_markers(
        sign_capture,
        "Create and verify committed migration canary",
        (
            "trap 'unset CANARY_SIGNING_SEED_HEX;",
            '"${database}-journal"',
            '[[ "${CANARY_SIGNING_SEED_HEX}" =~ ^[0-9a-f]{64}$ ]]',
            "printf '%s\\n' \"${CANARY_SIGNING_SEED_HEX}\" |",
            '"${verifier}" create-canary',
            '--source-commit "${SOURCE_SHA}"',
            '--runner-labels-digest "${RUNNER_LABELS_DIGEST}"',
            '--configuration-digest "${CONFIGURATION_DIGEST}"',
            '--inventory-digest "${INVENTORY_DIGEST}"',
            '--migration-state-store-digest "${MIGRATION_STATE_STORE_DIGEST}"',
            '--expected-runner-public-key "${CANARY_SIGNER_PUBLIC_KEY}"',
            '[[ "${CONTROLLER_ISSUED_AT_UNIX_MS}" =~ ^[1-9][0-9]{12}$ ]]',
            '[[ "${CAPTURE_ISSUED_AT_UNIX_MS}" =~ ^[1-9][0-9]{12}$ ]]',
            'signing_now_unix_ms="$(( $(date +%s) * 1000 ))"',
            'test "${CONTROLLER_ISSUED_AT_UNIX_MS}" -le "${CAPTURE_ISSUED_AT_UNIX_MS}"',
            'test "${CAPTURE_ISSUED_AT_UNIX_MS}" -le "${signing_now_unix_ms}"',
            'test "$((signing_now_unix_ms - CONTROLLER_ISSUED_AT_UNIX_MS))" -le 14400000',
            'test "$((signing_now_unix_ms - CAPTURE_ISSUED_AT_UNIX_MS))" -le 14400000',
            'generated_at_not_before_unix_ms="${signing_now_unix_ms}"',
            'generated_at_not_after_unix_ms="$((signing_now_unix_ms + 300000))"',
            "unset CANARY_SIGNING_SEED_HEX",
            "enterprise-migration-canary.json.sha256",
            "enterprise-migration-binding-digest.txt",
            "expected_files=(",
            'test "${evidence_files[*]}" = "${expected_files[*]}"',
            '"${verifier}" verify-committed-linux-evidence',
            '--expected-binding-digest "${binding_digest}"',
            '--generated-at-not-before-unix-ms "${generated_at_not_before_unix_ms}"',
            '--generated-at-not-after-unix-ms "${generated_at_not_after_unix_ms}"',
            'echo "generated_at_not_before_unix_ms=${generated_at_not_before_unix_ms}"',
            'echo "generated_at_not_after_unix_ms=${generated_at_not_after_unix_ms}"',
        ),
        "trusted finalizer does not create and verify the strict three-file canary",
    )
    if not (
        signing_run.index('signing_now_unix_ms="$(( $(date +%s) * 1000 ))"')
        < signing_run.index('"${verifier}" create-canary')
        < signing_run.index(
            '--generated-at-not-before-unix-ms "${generated_at_not_before_unix_ms}"'
        )
        < signing_run.index(
            'echo "generated_at_not_before_unix_ms=${generated_at_not_before_unix_ms}"'
        )
    ):
        raise ContractError(
            "trusted finalizer does not compute, verify, and publish one signing-time window"
        )
    policy_step = named_step(
        sign_capture, "Publish committed evidence verification policy"
    )
    if (
        policy_step.get("env", {}).get("GENERATED_AT_NOT_BEFORE_UNIX_MS")
        != "${{ steps.sign.outputs.generated_at_not_before_unix_ms }}"
        or policy_step.get("env", {}).get("GENERATED_AT_NOT_AFTER_UNIX_MS")
        != "${{ steps.sign.outputs.generated_at_not_after_unix_ms }}"
    ):
        raise ContractError(
            "trusted finalizer policy does not consume the exact signing-time window"
        )
    expected_signed_upload = {
        "name": "Upload exact committed migration evidence",
        "uses": "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "with": {
            "name": "enterprise-linux-committed-evidence-${{ needs.validate-capture.outputs.source_sha }}",
            "path": "${{ runner.temp }}/committed-enterprise-linux-evidence/",
            "if-no-files-found": "error",
            "include-hidden-files": "false",
            "retention-days": "7",
        },
    }
    if (
        named_step(sign_capture, "Upload exact committed migration evidence")
        != expected_signed_upload
    ):
        raise ContractError("trusted finalizer committed evidence upload changed")

    if (
        authorize_publication.get("name")
        != "authorize dedicated Security contract publication"
        or authorize_publication.get("needs") != ["validate-capture"]
        or authorize_publication.get("permissions") != EXPECTED_FINALIZER_PERMISSIONS
        or authorize_publication.get("runs-on") != "ubuntu-24.04"
        or authorize_publication.get("timeout-minutes") != "240"
        or authorize_publication.get("outputs")
        != EXPECTED_PUBLICATION_AUTHORIZATION_OUTPUTS
        or any(
            key in authorize_publication
            for key in ("concurrency", "env", "environment", "if")
        )
    ):
        raise ContractError(
            "security check publication authorization job identity changed"
        )
    validate_step_inventory(
        authorize_publication,
        EXPECTED_FINALIZER_STEP_INVENTORIES["authorize-security-check-publication"],
        "security check publication authorization",
    )
    for step_name, expected_with in EXPECTED_PUBLICATION_CHECKOUTS.items():
        checkout = named_step(authorize_publication, step_name)
        if checkout != {
            "name": step_name,
            "uses": "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
            "with": expected_with,
        }:
            raise ContractError(
                "security check publication does not isolate committed evidence and trusted checker source"
            )

    publication_bind = named_step(
        authorize_publication, "Bind live committed evidence head and CI definition"
    )
    if publication_bind.get("env") != EXPECTED_PUBLICATION_BIND_ENV:
        raise ContractError(
            "security check publication does not bind the current committed evidence head"
        )
    require_run_markers(
        authorize_publication,
        "Bind live committed evidence head and CI definition",
        (
            'test "${AUTHORIZED_SOURCE_SHA}" = "${CAPTURE_AUTHORIZED_SOURCE_SHA}"',
            'test "${COMMITTED_EVIDENCE_SHA}" = "${EVIDENCE_SHA}"',
            'test "${SOURCE_REPOSITORY}" = "${GITHUB_REPOSITORY}"',
            'test "${BASE_REPOSITORY}" = "${GITHUB_REPOSITORY}"',
            'test "${BASE_REF}" = "${DEFAULT_BRANCH}"',
            'test "${DEFAULT_BRANCH}" = "main"',
            'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${EVIDENCE_SHA}"',
            'test "$(jq -r \'.base.sha\' <<< "${live_pr}")" = "${BASE_SHA}"',
            "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml",
            'test "$(jq -r \'.path\' <<< "${ci_workflow}")" = ".github/workflows/ci.yml"',
            "contents/.github/workflows/ci.yml?ref=${AUTHORIZED_SOURCE_SHA}",
            "contents/.github/workflows/ci.yml?ref=${EVIDENCE_SHA}",
            "contents/.github/workflows/ci.yml?ref=${MERGE_COMMIT_SHA}",
            'test "${evidence_ci_blob}" = "${source_ci_blob}"',
            'test "${merge_ci_blob}" = "${source_ci_blob}"',
        ),
        "security check publication does not bind E to the current PR head and exact CI definition",
    )

    strict_publication = named_step(
        authorize_publication, "Verify committed evidence with exact trusted checker"
    )
    if strict_publication.get("env") != EXPECTED_PUBLICATION_STRICT_ENV:
        raise ContractError("security check publication strict evidence inputs changed")
    require_run_markers(
        authorize_publication,
        "Verify committed evidence with exact trusted checker",
        (
            'test "$(git -C committed-evidence rev-parse HEAD)" = "${EVIDENCE_SHA}"',
            'test "$(git -C authorized-checker rev-parse HEAD)" = "${AUTHORIZED_SOURCE_SHA}"',
            "test -f authorized-checker/scripts/check-committed-linux-evidence.py",
            "test ! -L authorized-checker/scripts/check-committed-linux-evidence.py",
            'test "$(jq -r \'.source_commit\' <<< "${policy}")" = "${AUTHORIZED_SOURCE_SHA}"',
            "/usr/bin/python3 authorized-checker/scripts/check-committed-linux-evidence.py",
            "--root committed-evidence",
            '--source-commit "${AUTHORIZED_SOURCE_SHA}"',
            '--evidence-commit "${EVIDENCE_SHA}"',
            r'[[ "${verification_output}" =~ ^committed\ Linux\ evidence\ verified:\ (0x[0-9a-f]{64})$ ]]',
            'echo "committed_binding_digest=${BASH_REMATCH[1]#0x}" >> "${GITHUB_OUTPUT}"',
        ),
        "security check publication skips the exact trusted checker from S against E",
    )

    publication_ci = named_step(
        authorize_publication, "Authenticate exact successful current CI run"
    )
    if publication_ci.get("env") != EXPECTED_PUBLICATION_CI_ENV:
        raise ContractError("security check publication CI identity inputs changed")
    publication_ci_run = require_run_markers(
        authorize_publication,
        "Authenticate exact successful current CI run",
        (
            'query="event=pull_request&head_sha=${EVIDENCE_SHA}&"',
            "actions/workflows/ci.yml/runs?${query}per_page=100&page=1",
            'if test "${total_count}" -ge 1000; then',
            "actions/workflows/ci.yml/runs?per_page=100&page=1",
            'page_response="${first_response}"',
            'test "${page_total}" = "${total_count}"',
            'test "$(jq -r \'length\' <<< "${page_runs}")" = 100',
            'test "$(jq -r \'[.[].id] | unique | length\' <<< "${runs}")" = "${total_count}"',
            'if ! matching_runs="$(list_matching_ci_runs)"; then',
            '.name == "CI"',
            '.path == ".github/workflows/ci.yml"',
            '.event == "pull_request"',
            "(.workflow_id | tostring) == $workflow_id",
            ".display_title == $expected_run_name",
            ".head_sha == $evidence_sha",
            '"repos/${GITHUB_REPOSITORY}/actions/runs/${ci_run_id}"',
            'test "$(jq -r \'.status\' <<< "${ci_run}")" = "completed"',
            'test "$(jq -r \'.conclusion\' <<< "${ci_run}")" = "success"',
            'test "$(jq -r \'.workflow_id\' <<< "${ci_run}")" = "${CI_WORKFLOW_ID}"',
            'test "$(jq -r \'.display_title\' <<< "${ci_run}")" = "${expected_run_name}"',
            'test "$(jq -r \'.head_sha\' <<< "${ci_run}")" = "${EVIDENCE_SHA}"',
            'test "$(jq -r \'.run_attempt\' <<< "${ci_run}")" = "${ci_run_attempt}"',
            "actions/runs/${ci_run_id}/attempts/${ci_run_attempt}/jobs?filter=all&per_page=100",
            'test "$(jq -r \'.head_sha\' <<< "${required_job}")" = "${EVIDENCE_SHA}"',
            'test "$(jq -r \'.head_sha\' <<< "${check_run}")" = "${EVIDENCE_SHA}"',
            'test "$(jq -r \'.check_suite.id\' <<< "${check_run}")" = "${check_suite_id}"',
            'test "$(jq -r \'.app.id\' <<< "${check_run}")" = "15368"',
            'test "$(jq -r \'.app.slug\' <<< "${check_run}")" = "github-actions"',
            'test "$(jq -r \'.state\' <<< "${live_pr}")" = "open"',
            'test "$(jq -r \'.head.repo.full_name\' <<< "${live_pr}")" = "${GITHUB_REPOSITORY}"',
            'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${EVIDENCE_SHA}"',
            'test "$(jq -r \'.head.ref\' <<< "${live_pr}")" = "${HEAD_REF}"',
            'test "$(jq -r \'.base.repo.full_name\' <<< "${live_pr}")" = "${GITHUB_REPOSITORY}"',
            'test "$(jq -r \'.base.ref\' <<< "${live_pr}")" = "${BASE_REF}"',
            'test "$(jq -r \'.base.sha\' <<< "${live_pr}")" = "${BASE_SHA}"',
            "repos/${GITHUB_REPOSITORY}/git/ref/pull/${PR_NUMBER}/merge",
            'test "$(jq -r \'.object.sha\' <<< "${merge_ref}")" = "${MERGE_COMMIT_SHA}"',
            '"repos/${GITHUB_REPOSITORY}/git/commits/${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.parents[0].sha\' <<< "${merge_commit}")" = "${BASE_SHA}"',
            'test "$(jq -r \'.parents[1].sha\' <<< "${merge_commit}")" = "${EVIDENCE_SHA}"',
            'test "$(jq -r \'.tree.sha\' <<< "${merge_commit}")" = "${MERGE_TREE_SHA}"',
        ),
        "security check publication does not authenticate the exact CI run, head, workflow, attempt, and Actions App",
    )
    if "pull_requests[" in publication_ci_run or ".merge_commit_sha" in publication_ci_run:
        raise ContractError(
            "security check publication trusts mutable Actions run pull-request metadata"
        )
    if EXPECTED_PUBLICATION_REQUIRED_NAMES_BLOCK not in publication_ci_run:
        raise ContractError(
            "security check publication omits an intended CI job or Actions aggregate"
        )

    publication_attestation = named_step(
        authorize_publication, "Verify exact CI merge binding attestation"
    )
    if publication_attestation.get("env") != EXPECTED_PUBLICATION_ATTESTATION_ENV:
        raise ContractError("security check publication attestation inputs changed")
    require_run_markers(
        authorize_publication,
        "Verify exact CI merge binding attestation",
        (
            'artifact_name="ci-merge-binding-${CI_RUN_ID}-${CI_RUN_ATTEMPT}"',
            "actions/runs/${CI_RUN_ID}/artifacts?per_page=100",
            "--paginate",
            'test "$(jq -r \'length\' <<< "${matches}")" = 1',
            'test "$(jq -r \'.expired\' <<< "${artifact}")" = false',
            'test "$(jq -r \'.workflow_run.id\' <<< "${artifact}")" = "${CI_RUN_ID}"',
            'test "$(jq -r \'.workflow_run.head_sha\' <<< "${artifact}")" = "${EVIDENCE_SHA}"',
            'test "${created_epoch}" -le "${updated_epoch}"',
            'test "${updated_epoch}" -le "${now_epoch}"',
            "X-GitHub-Api-Version: 2026-03-10",
            'test "$(sha256sum "${archive}" | cut -d\' \' -f1)" = "${archive_sha256}"',
            '"ci-merge-binding.bundle.jsonl": 8 * 1024 * 1024',
            '"ci-merge-binding.json": 64 * 1024',
            "sorted(member.filename for member in members) != sorted(allowed)",
            "stat.S_ISLNK(mode)",
            "member.file_size > 64 * member.compress_size",
            'test "$(jq -cs \'length\' "${bundle_file}")" = 1',
            'test "$(jq -cS \'keys\' <<< "${binding}")" = \'["base","builder","caller","ci","head","merge","pull_request_number","repository","schema"]\'',
            'test "$(jq -r \'.merge.sha\' <<< "${binding}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -cS \'.merge.parents\' <<< "${binding}")" = "[\\"${BASE_SHA}\\",\\"${EVIDENCE_SHA}\\"]"',
            'test "$(jq -r \'.ci.run_id\' <<< "${binding}")" = "${CI_RUN_ID}"',
            'test "$(jq -r \'.ci.run_attempt\' <<< "${binding}")" = "${CI_RUN_ATTEMPT}"',
            "https://github.com/cli/cli/releases/download/v2.96.0/gh_2.96.0_linux_amd64.tar.gz",
            "83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60",
            "gh_2.96.0_linux_amd64/bin/gh",
            'test "$(sed -n \'1s/^gh version \\([^ ]*\\) .*/\\1/p\' <<< "${gh_version_output}")" = 2.96.0',
            '"${gh_bin}" attestation verify "${binding_file}"',
            '--bundle "${bundle_file}"',
            '--repo "${GITHUB_REPOSITORY}"',
            '--predicate-type "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1"',
            '--signer-workflow "bb-connor/arc/.github/workflows/enterprise-hardening.yml"',
            '--signer-digest "${SECURITY_DEFINITION_SHA}"',
            '--source-digest "${MERGE_COMMIT_SHA}"',
            '--source-ref "refs/pull/${PR_NUMBER}/merge"',
            "--deny-self-hosted-runners",
            "--format json",
            'test "$(jq -r \'length\' "${verification_json}")" = 1',
            'test "$(jq -r \'.predicateType\' <<< "${statement}")" = "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1"',
            'test "$(jq -r \'.subject | length\' <<< "${statement}")" = 1',
            'test "$(jq -r \'.subject[0].name\' <<< "${statement}")" = ci-merge-binding.json',
            'test "$(jq -r \'.subject[0].digest.sha256\' <<< "${statement}")" = "${binding_sha256}"',
            'test "$(jq -cS \'.predicate\' <<< "${statement}")" = "${binding}"',
            'test "$(jq -r \'.issuer\' <<< "${certificate}")" = "https://token.actions.githubusercontent.com"',
            'test "$(jq -r \'.subjectAlternativeName\' <<< "${certificate}")" = "${signer_uri}"',
            'test "$(jq -r \'.buildSignerURI\' <<< "${certificate}")" = "${signer_uri}"',
            'test "$(jq -r \'.buildSignerDigest\' <<< "${certificate}")" = "${SECURITY_DEFINITION_SHA}"',
            'test "$(jq -r \'.runnerEnvironment\' <<< "${certificate}")" = github-hosted',
            'test "$(jq -r \'.sourceRepositoryURI\' <<< "${certificate}")" = "https://github.com/${GITHUB_REPOSITORY}"',
            'test "$(jq -r \'.sourceRepositoryDigest\' <<< "${certificate}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.sourceRepositoryRef\' <<< "${certificate}")" = "refs/pull/${PR_NUMBER}/merge"',
            'test "$(jq -r \'.sourceRepositoryIdentifier\' <<< "${certificate}")" = "${repository_id}"',
            'test "$(jq -r \'.sourceRepositoryOwnerURI\' <<< "${certificate}")" = "https://github.com/${GITHUB_REPOSITORY_OWNER}"',
            'test "$(jq -r \'.sourceRepositoryOwnerIdentifier\' <<< "${certificate}")" = "${repository_owner_id}"',
            'test "$(jq -r \'.buildConfigURI\' <<< "${certificate}")" = "${caller_uri}"',
            'test "$(jq -r \'.buildConfigDigest\' <<< "${certificate}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.buildTrigger\' <<< "${certificate}")" = pull_request',
            'test "$(jq -r \'.runInvocationURI\' <<< "${certificate}")" = "https://github.com/${GITHUB_REPOSITORY}/actions/runs/${CI_RUN_ID}/attempts/${CI_RUN_ATTEMPT}"',
            'test "$(jq -r \'.sourceRepositoryVisibilityAtSigning\' <<< "${certificate}")" = public',
            'test "$(jq -r \'.githubWorkflowTrigger\' <<< "${certificate}")" = pull_request',
            'test "$(jq -r \'.githubWorkflowSHA\' <<< "${certificate}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.githubWorkflowName\' <<< "${certificate}")" = CI',
            'test "$(jq -r \'.githubWorkflowRepository\' <<< "${certificate}")" = "${GITHUB_REPOSITORY}"',
            'test "$(jq -r \'.githubWorkflowRef\' <<< "${certificate}")" = "refs/pull/${PR_NUMBER}/merge"',
            '[[ "$(jq -r \'.certificateIssuer\' <<< "${certificate}")" =~ ^[[:print:]]{1,512}$ ]]',
            'test "$(jq -r \'length >= 1 and length <= 8\' <<< "${timestamps}")" = true',
            '(.type == "Tlog" or .type == "TimestampAuthority")',
            'test "${timestamp_epoch}" -ge "$((created_epoch - 300))"',
            'test "${timestamp_epoch}" -le "$((now_epoch + 300))"',
            "repos/${GITHUB_REPOSITORY}/git/ref/pull/${PR_NUMBER}/merge",
            'test "$(jq -r \'.object.sha\' <<< "${stable_merge_ref}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.tree.sha\' <<< "${stable_merge_commit}")" = "${MERGE_TREE_SHA}"',
        ),
        "security check publication does not verify one exact trusted merge-binding attestation",
    )

    require_run_markers(
        authorize_publication,
        "Seal exact publication binding",
        (
            'test "${SOURCE_REPOSITORY}" = "${GITHUB_REPOSITORY}"',
            'test "${BASE_REPOSITORY}" = "${GITHUB_REPOSITORY}"',
            'test "${BASE_REF}" = "main"',
            'test "${CAPTURE_ACTOR}" = "github-actions[bot]"',
            'test "${CONTROLLER_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"',
            'test "${ARTIFACT_NAME}" = "enterprise-linux-capture-${EVIDENCE_SHA}-${CAPTURE_RUN_ID}-${CAPTURE_RUN_ATTEMPT}"',
            "artifact: {",
            "authorized_source_sha: $authorized_source_sha",
            "base: {",
            "capture: {",
            "job_id: $capture_job_id",
            "ci: {",
            "aggregate_check_run_id: $ci_aggregate_check_run_id",
            "required_check_run_ids: {",
            "build: $build_check_run_id",
            "deny: $deny_check_run_id",
            "msrv: $msrv_check_run_id",
            "vet: $vet_check_run_id",
            "committed_binding_digest: $committed_binding_digest",
            "controller: {",
            "evidence_sha: $evidence_sha",
            "gate_result_digests: {",
            'schema: "chio.security-check-publication.v1"',
            "security_definition_sha: $security_definition_sha",
            "publication_binding_digest=\"$(printf '%s' \"${publication_binding}\" | sha256sum | cut -d' ' -f1)\"",
            'external_id="arc:${PR_NUMBER}:${EVIDENCE_SHA}:${MERGE_COMMIT_SHA}:${AUTHORIZED_SOURCE_SHA}"',
            'echo "merge_commit_sha=${MERGE_COMMIT_SHA}"',
            'echo "publication_binding_json=${publication_binding}"',
        ),
        "security check publication weakens its exact publication binding",
    )

    if (
        publish_security_contract.get("name")
        != "reconcile exact merge authority contexts"
        or publish_security_contract.get("needs")
        != ["authorize-security-check-publication", "sign-validated-capture"]
        or publish_security_contract.get("environment") != "security-check-publisher"
        or publish_security_contract.get("concurrency")
        != EXPECTED_PUBLISHER_CONCURRENCY
        or publish_security_contract.get("permissions")
        != {
            "actions": "read",
            "checks": "write",
            "contents": "read",
            "pull-requests": "read",
        }
        or publish_security_contract.get("runs-on") != "ubuntu-24.04"
        or publish_security_contract.get("timeout-minutes") != "10"
        or "env" in publish_security_contract
        or "if" in publish_security_contract
    ):
        raise ContractError("dedicated Security contract publisher identity changed")
    validate_step_inventory(
        publish_security_contract,
        EXPECTED_FINALIZER_STEP_INVENTORIES["publish-security-contract"],
        "dedicated Security contract publisher",
    )
    publisher_step = named_step(
        publish_security_contract, "Reconcile exact five-context merge authority"
    )
    if publisher_step.get("env") != EXPECTED_PUBLISHER_STEP_ENV:
        raise ContractError(
            "dedicated Security contract publisher App variables or sealed inputs changed"
        )
    publisher_run = require_run_markers(
        publish_security_contract,
        "Reconcile exact five-context merge authority",
        (
            '[[ "${SECURITY_APP_ID}" =~ ^[1-9][0-9]*$ ]]',
            '[[ "${SECURITY_APP_INSTALLATION_ID}" =~ ^[1-9][0-9]*$ ]]',
            'test "${SECURITY_APP_ID}" != "15368"',
            '[[ "${FINALIZER_RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]',
            '[[ "${FINALIZER_RUN_ID}" =~ ^[1-9][0-9]*$ ]]',
            'test "${PUBLISHER_REF}" = "refs/heads/main"',
            'test "${LIVE_SECURITY_DEFINITION_SHA}" = "${SECURITY_DEFINITION_SHA}"',
            "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${PUBLISHER_SHA}",
            'test "${running_publisher_blob_sha}" = "${authorized_publisher_blob_sha}"',
            'test "${COMMITTED_EVIDENCE_SHA}" = "${EVIDENCE_SHA}"',
            'test "${LIVE_AUTHORIZED_SOURCE_SHA}" = "${AUTHORIZED_SOURCE_SHA}"',
            'test "${EXTERNAL_ID}" = "arc:${PR_NUMBER}:${EVIDENCE_SHA}:${MERGE_COMMIT_SHA}:${AUTHORIZED_SOURCE_SHA}"',
            'publication_details_url="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${FINALIZER_RUN_ID}/attempts/${FINALIZER_RUN_ATTEMPT}"',
            'test "${canonical_binding}" = "${PUBLICATION_BINDING_JSON}"',
            'test "$(printf \'%s\' "${canonical_binding}" | sha256sum | cut -d\' \' -f1)" = "${PUBLICATION_BINDING_DIGEST}"',
            'test "$(jq -r \'.schema\' <<< "${canonical_binding}")" = "chio.security-check-publication.v1"',
            'test "$(jq -r \'.repository\' <<< "${canonical_binding}")" = "${GITHUB_REPOSITORY}"',
            'test "$(jq -r \'.pr_number\' <<< "${canonical_binding}")" = "${PR_NUMBER}"',
            'test "$(jq -r \'.evidence_sha\' <<< "${canonical_binding}")" = "${EVIDENCE_SHA}"',
            'test "$(jq -r \'.merge_commit_sha\' <<< "${canonical_binding}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.authorized_source_sha\' <<< "${canonical_binding}")" = "${AUTHORIZED_SOURCE_SHA}"',
            'test "$(jq -r \'.security_definition_sha\' <<< "${canonical_binding}")" = "${SECURITY_DEFINITION_SHA}"',
            'test "$(jq -r \'.ci.workflow_id\' <<< "${canonical_binding}")" = "${CI_WORKFLOW_ID}"',
            'test "$(jq -r \'.ci.run_id\' <<< "${canonical_binding}")" = "${CI_RUN_ID}"',
            'test "$(jq -r \'.ci.run_attempt\' <<< "${canonical_binding}")" = "${CI_RUN_ATTEMPT}"',
            'test "$(jq -r \'.ci.aggregate_check_run_id\' <<< "${canonical_binding}")" = "${CI_AGGREGATE_CHECK_RUN_ID}"',
            '[[ "$(jq -r \'.labels_digest\' <<< "${canonical_binding}")" =~ ^[0-9a-f]{64}$ ]]',
            '[[ "$(jq -r \'.merge_commit_sha\' <<< "${canonical_binding}")" =~ ^[0-9a-f]{40}$ ]]',
            '[[ "$(jq -r \'.merge_tree_sha\' <<< "${canonical_binding}")" =~ ^[0-9a-f]{40}$ ]]',
            "trap 'unset SECURITY_APP_PRIVATE_KEY_PEM installation_token token_response jwt jwt_header jwt_claims jwt_unsigned jwt_signature;",
            "unset SECURITY_APP_PRIVATE_KEY_PEM",
            "unset token_response jwt jwt_header jwt_claims jwt_unsigned jwt_signature",
            'test "$(jq -r \'.id\' <<< "${app}")" = "${SECURITY_APP_ID}"',
            'test "$(jq -r \'.slug\' <<< "${app}")" = "chio-security-authority"',
            'test "$(jq -r \'.owner.login\' <<< "${app}")" = "${GITHUB_REPOSITORY_OWNER}"',
            'test "$(jq -cS \'.permissions\' <<< "${app}")" = \'{"checks":"write","metadata":"read","statuses":"write"}\'',
            'token_request=\'{"permissions":{"checks":"write"}}\'',
            '"https://api.github.com/app/installations/${SECURITY_APP_INSTALLATION_ID}/access_tokens"',
            r'[[ "${installation_token}" =~ ^ghs_[A-Za-z0-9_.-]{16,4096}$ ]]',
            'token_permissions="$(jq -cS \'.permissions\' <<< "${token_response}")"',
            '\'{"checks":"write"}\'|\'{"checks":"write","metadata":"read"}\') ;;',
            'test "$(jq -r \'.id\' <<< "${installation}")" = "${SECURITY_APP_INSTALLATION_ID}"',
            'test "$(jq -r \'.app_id\' <<< "${installation}")" = "${SECURITY_APP_ID}"',
            'test "$(jq -r \'.repository_selection\' <<< "${installation}")" = "selected"',
            'test "$(jq -cS \'.permissions\' <<< "${installation}")" = \'{"checks":"write","metadata":"read","statuses":"write"}\'',
            'test "$(jq -r \'.total_count\' <<< "${repositories}")" = "1"',
            'test "$(jq -r \'.repositories[0].full_name\' <<< "${repositories}")" = "${GITHUB_REPOSITORY}"',
            '"https://api.github.com/repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"',
            'test "$(jq -r \'.state\' <<< "${live_pr}")" = "open"',
            'test "$(jq -r \'.head.repo.full_name\' <<< "${live_pr}")" = "${GITHUB_REPOSITORY}"',
            'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${EVIDENCE_SHA}"',
            '"https://api.github.com/repos/${GITHUB_REPOSITORY}/git/ref/pull/${PR_NUMBER}/merge"',
            'test "$(jq -r \'.object.type\' <<< "${merge_ref}")" = commit',
            'test "$(jq -r \'.object.sha\' <<< "${merge_ref}")" = "${merge_commit_sha}"',
            '"https://api.github.com/repos/${GITHUB_REPOSITORY}/git/commits/${merge_commit_sha}"',
            'test "$(jq -r \'.parents[0].sha\' <<< "${merge_commit}")" = "$(jq -r \'.base.sha\' <<< "${canonical_binding}")"',
            'test "$(jq -r \'.parents[1].sha\' <<< "${merge_commit}")" = "${EVIDENCE_SHA}"',
            'test "$(jq -r \'.tree.sha\' <<< "${merge_commit}")" = "$(jq -r \'.merge_tree_sha\' <<< "${canonical_binding}")"',
            "list_actions_mirror_checks()",
            "list_namespace_checks()",
            "normalize_bad_ci_namespace()",
            'canonical_check_id="$(jq -r --arg external_id "${required_external_id}"',
            'target_name="${check_name} / superseded ${existing_check_id}"',
            'test "$(jq -r \'.name\' <<< "${failed_check}")" = "${target_name}"',
            "reconcile_bad_ci()",
            "shopt -s inherit_errexit",
            "require_publishable_ci()",
            'query="event=pull_request&head_sha=${EVIDENCE_SHA}&"',
            "actions/workflows/ci.yml/runs?${query}per_page=100&page=1",
            'if test "${total_count}" -ge 1000; then',
            "actions/workflows/ci.yml/runs?per_page=100&page=1",
            "actions/workflows/ci.yml/runs?${query}per_page=100&page=${page}",
            'page_response="${first_response}"',
            'test "${page_total}" = "${total_count}"',
            'test "$(jq -r \'length\' <<< "${page_runs}")" = 100',
            'test "$(jq -r \'[.[].id] | unique | length\' <<< "${ci_runs}")" = "${total_count}"',
            "list_matching_ci_runs()",
            ".display_title == $expected_run_name",
            'test "$(jq -r --arg run_id "${CI_RUN_ID}" \'[.[] | select((.id | tostring) == $run_id)] | length\' <<< "${matching_ci_runs}")" = 1',
            "get_current_ci_run()",
            "get_exact_ci_attempt()",
            "require_matching_ci_identity()",
            '"https://api.github.com/repos/${GITHUB_REPOSITORY}/actions/runs/${run_id}/attempts/${run_attempt}"',
            'for _ in 1 2 3; do',
            'if ! matching_ci_runs="$(list_matching_ci_runs)"; then',
            'matching_ci_ids="$(jq -cS \'[.[].id]\' <<< "${matching_ci_runs}")"',
            'for ((run_attempt = 1; run_attempt <= max_attempt; run_attempt++)); do',
            'test "$(jq -r \'.run_attempt\' <<< "${exact_attempt}")" = "${run_attempt}"',
            'scan_incomplete=false',
            'if test "${attempt_status}" != completed; then',
            'scan_incomplete=true',
            'if test "$(jq -r \'length\' <<< "${scanned_bad_ci_runs}")" -gt 0; then',
            'bad_ci_runs="${scanned_bad_ci_runs}"',
            'if test "${scan_incomplete}" = true; then',
            'if test "${attempt_conclusion}" != success; then',
            'current_max_fingerprint="$(jq -cS \'{conclusion: (.conclusion // ""), run_attempt: .run_attempt, status: .status}\' <<< "${current_ci_run}")"',
            'exact_max_fingerprint="$(jq -cS \'{conclusion: (.conclusion // ""), run_attempt: .run_attempt, status: .status}\' <<< "${exact_attempt}")"',
            'stable_max_fingerprint="$(jq -cS \'{conclusion: (.conclusion // ""), run_attempt: .run_attempt, status: .status}\' <<< "${stable_ci_run}")"',
            'revalidated_fingerprint="$(jq -cS \'{conclusion: (.conclusion // ""), run_attempt: .run_attempt, status: .status}\' <<< "${revalidated_ci_run}")"',
            'if test "${stable_max_attempt}" != "${max_attempt}"; then',
            'test "${stable_max_attempt}" -gt "${max_attempt}"',
            'if test "${current_max_fingerprint}" != "${exact_max_fingerprint}" ||',
            'test "${stable_max_fingerprint}" != "${exact_max_fingerprint}"; then',
            'if ! stable_matching_ci_runs="$(list_matching_ci_runs)"; then',
            'stable_matching_ci_ids="$(jq -cS \'[.[].id]\' <<< "${stable_matching_ci_runs}")"',
            'if test "${stable_matching_ci_ids}" != "${matching_ci_ids}"; then',
            'revalidated_ci_run="$(get_current_ci_run "${run_id}")"',
            'if test "${revalidated_fingerprint}" != "${expected_fingerprint}"; then',
            'test "${scan_stable}" = true',
            'bad_ci_runs="$(jq -cS \'sort_by([.id, .run_attempt])\' <<< "${bad_ci_runs}")"',
            'test "$(jq -r \'[.[] | "\\(.id):\\(.run_attempt)"] | unique | length\' <<< "${bad_ci_runs}")" = "$(jq -r \'length\' <<< "${bad_ci_runs}")"',
            'bad_ci_create_missing=false',
            'if test "${bad_ci_create_missing}" = false; then',
            'test "$(jq -r \'.object.sha\' <<< "${live_bad_ci_merge_ref}")" = "${MERGE_COMMIT_SHA}"',
            'normalize_bad_ci_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / Build, lint, test" "${EXTERNAL_ID}:actions:build"',
            'normalize_bad_ci_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / MSRV build and test" "${EXTERNAL_ID}:actions:msrv"',
            'normalize_bad_ci_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / cargo-vet (locked supply-chain audit)" "${EXTERNAL_ID}:actions:vet"',
            'normalize_bad_ci_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / cargo-deny (supply-chain bans/advisories/licenses)" "${EXTERNAL_ID}:actions:deny"',
            'normalize_bad_ci_namespace "${installation_token}" "${SECURITY_APP_ID}" chio-security-authority "Security contract" "${EXTERNAL_ID}"',
            "publish_success_authority()",
            'reconcile_bad_ci\nif test "${bad_ci_observed}" = false; then',
            "publish_success_authority",
            "else\n  exit 1",
            "commits/${MERGE_COMMIT_SHA}/check-runs?app_id=15368&check_name=${encoded_name}&filter=all&per_page=100&page=${page}",
            '["Security mirror / Build, lint, test", "build", "Build, lint, test", .ci.required_check_run_ids.build]',
            '["Security mirror / MSRV build and test", "msrv", "MSRV build and test", .ci.required_check_run_ids.msrv]',
            '["Security mirror / cargo-vet (locked supply-chain audit)", "vet", "cargo-vet (locked supply-chain audit)", .ci.required_check_run_ids.vet]',
            '["Security mirror / cargo-deny (supply-chain bans/advisories/licenses)", "deny", "cargo-deny (supply-chain bans/advisories/licenses)", .ci.required_check_run_ids.deny]',
            'mirror_external_id="${EXTERNAL_ID}:actions:${mirror_key}"',
            'schema: "chio.security-check-authority.v2"',
            'test "${mirror_match_count}" -le 1',
            'test "$(jq -r \'.conclusion\' <<< "${mirror_check}")" = "success"',
            '-H "Authorization: Bearer ${GH_TOKEN}"',
            'test "$(jq -r \'.head_sha\' <<< "${mirror_check}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.app.id\' <<< "${mirror_check}")" = "15368"',
            'test "$(jq -r \'.app.slug\' <<< "${mirror_check}")" = "github-actions"',
            'test "${observed_mirror_text}" = "${mirror_text}"',
            'test "$(jq -r \'.total_count\' <<< "${verified_mirror_namespace}")" = "1"',
            'revalidate_live_publication_head\nauthority_created=false\nif test "${existing_authority_match_count}" = "1"; then',
            "commits/${MERGE_COMMIT_SHA}/check-runs?app_id=${SECURITY_APP_ID}&check_name=Security%20contract&filter=all&per_page=100&page=${page}",
            '[[ "${page_total}" =~ ^[0-9]+$ ]]',
            'test "${page_total}" = "${total_count}"',
            'test "${collected_count}" -le "${total_count}"',
            'if test "${collected_count}" = "${total_count}"; then',
            'test "$(jq -r \'length\' <<< "${page_checks}")" = "100"',
            'page="$((page + 1))"',
            'test "$(jq -r \'[.[].id] | unique | length\' <<< "${collected_checks}")" = "${total_count}"',
            "'{check_runs: $check_runs, total_count: $total_count}'",
            'test "$(jq -r \'.check_runs | length\' <<< "${existing_authority_checks}")" = "$(jq -r \'.total_count\' <<< "${existing_authority_checks}")"',
            "all(.check_runs[];",
            '.name == "Security contract" and',
            ".head_sha == $head_sha and",
            "(.app.id | tostring) == $app_id and",
            '.app.slug == "chio-security-authority"',
            'test "${existing_authority_match_count}" -le 1',
            'test "$(jq -r \'.[0].external_id\' <<< "${existing_authority_matches}")" = "${EXTERNAL_ID}"',
            'test "$(jq -r \'.[0].status\' <<< "${existing_authority_matches}")" = "completed"',
            'test "$(jq -r \'.[0].conclusion\' <<< "${existing_authority_matches}")" = "success"',
            'check_run="$(jq -cS \'.[0]\' <<< "${existing_authority_matches}")"',
            '--arg external_id "${EXTERNAL_ID}"',
            '--arg details_url "${publication_details_url}"',
            '--arg head_sha "${MERGE_COMMIT_SHA}"',
            'conclusion: "success"',
            "details_url: $details_url",
            "external_id: $external_id",
            "head_sha: $head_sha",
            'name: "Security contract"',
            '--arg text "${authority_text}"',
            'status: "completed"',
            '"https://api.github.com/repos/${GITHUB_REPOSITORY}/check-runs"',
            'test "$(jq -r \'.name\' <<< "${check_run}")" = "Security contract"',
            'test "$(jq -r \'.head_sha\' <<< "${check_run}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.status\' <<< "${check_run}")" = "completed"',
            'test "$(jq -r \'.conclusion\' <<< "${check_run}")" = "success"',
            'test "$(jq -r \'.external_id\' <<< "${check_run}")" = "${EXTERNAL_ID}"',
            '[[ "$(jq -r \'.details_url\' <<< "${check_run}")" =~ ^https://github\\.com/${GITHUB_REPOSITORY}/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$ ]]',
            'test "$(jq -r \'.details_url\' <<< "${check_run}")" = "${publication_details_url}"',
            'test "$(jq -r \'.app.id\' <<< "${check_run}")" = "${SECURITY_APP_ID}"',
            'test "$(jq -r \'.name\' <<< "${verified_check}")" = "Security contract"',
            'test "$(jq -r \'.head_sha\' <<< "${verified_check}")" = "${MERGE_COMMIT_SHA}"',
            'test "$(jq -r \'.status\' <<< "${verified_check}")" = "completed"',
            'test "$(jq -r \'.conclusion\' <<< "${verified_check}")" = "success"',
            'test "$(jq -r \'.external_id\' <<< "${verified_check}")" = "${EXTERNAL_ID}"',
            '[[ "$(jq -r \'.details_url\' <<< "${verified_check}")" =~ ^https://github\\.com/${GITHUB_REPOSITORY}/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*$ ]]',
            'test "$(jq -r \'.app.id\' <<< "${verified_check}")" = "${SECURITY_APP_ID}"',
            'observed_authority_text="$(jq -cS \'.output.text | fromjson\' <<< "${check_run}")"',
            'test "${observed_authority_text}" = "${authority_text}"',
            'test "${verified_authority_text}" = "${authority_text}"',
            '((.output.text | fromjson) == ($expected_text | fromjson))',
        ),
        "dedicated Security contract publisher weakens App, main-ref, binding, or check payload authentication",
    )
    failure_start = publisher_run.index("normalize_bad_ci_namespace()")
    reconciliation_start = publisher_run.index("reconcile_bad_ci()")
    success_start = publisher_run.index("publish_success_authority()")
    branch_start = publisher_run.index(
        'reconcile_bad_ci\nif test "${bad_ci_observed}" = false; then'
    )
    if not failure_start < reconciliation_start < success_start < branch_start:
        raise ContractError(
            "dedicated Security contract reconciler branch ordering changed"
        )
    failure_routine = publisher_run[failure_start:reconciliation_start]
    bad_ci_routine = publisher_run[reconciliation_start:success_start]
    success_routine = publisher_run[success_start:branch_start]
    branch_routine = publisher_run[branch_start:]
    if (
        failure_routine.count("--request POST") != 1
        or failure_routine.count("--request PATCH") != 1
        or failure_routine.count('conclusion: "failure"') != 2
        or 'conclusion: "success"' in failure_routine
        or 'status: "completed"' not in failure_routine
        or failure_routine.count("revalidate_live_publication_head\n") != 2
        or 'if test "${bad_ci_create_missing}" = false; then'
        not in failure_routine
        or 'test "${verified_metadata}" = "${preserved_metadata}"'
        not in failure_routine
    ):
        raise ContractError(
            "dedicated Security contract late-CI branch is not monotone failure-only"
        )
    if (
        "--request POST" in bad_ci_routine
        or "--request PATCH" in bad_ci_routine
        or bad_ci_routine.count("normalize_bad_ci_namespace ") != 5
        or bad_ci_routine.count("return 0") != 2
        or "return 1" in bad_ci_routine
        or "bad_ci_observed=false" not in bad_ci_routine
        or "bad_ci_observed=true" not in bad_ci_routine
        or "bad_ci_create_missing=false" not in bad_ci_routine
        or "bad_ci_create_missing=true" not in bad_ci_routine
        or 'require_publishable_ci() {\n  reconcile_bad_ci\n  test "${bad_ci_observed}" = false\n}'
        not in bad_ci_routine
        or 'if test "$(jq -r \'length\' <<< "${bad_ci_runs}")" = "0"; then'
        not in bad_ci_routine
        or bad_ci_routine.count('matching_ci_runs="$(list_matching_ci_runs)"') != 2
        or bad_ci_routine.count('stable_matching_ci_runs="$(list_matching_ci_runs)"')
        != 1
        or bad_ci_routine.count('get_current_ci_run "${run_id}"') != 3
        or bad_ci_routine.count(
            'get_exact_ci_attempt "${run_id}" "${run_attempt}"'
        )
        != 1
        or bad_ci_routine.count(
            'require_matching_ci_identity "${exact_attempt}" "${run_id}"'
        )
        != 1
        or 'if test "${attempt_status}" != completed; then' not in bad_ci_routine
        or "scan_incomplete=true" not in bad_ci_routine
        or 'if test "$(jq -r \'length\' <<< "${scanned_bad_ci_runs}")" -gt 0; then'
        not in bad_ci_routine
        or 'if test "${scan_incomplete}" = true; then' not in bad_ci_routine
        or bad_ci_routine.find(
            'if test "$(jq -r \'length\' <<< "${scanned_bad_ci_runs}")" -gt 0; then'
        )
        > bad_ci_routine.find('if test "${scan_incomplete}" = true; then')
        or 'test "${scan_stable}" = true' not in bad_ci_routine
    ):
        raise ContractError(
            "dedicated Security contract bad-CI evidence does not dominate failure reconciliation"
        )
    if (
        "--request PATCH" in success_routine
        or success_routine.count("--request POST") != 2
        or success_routine.count('conclusion: "success"') != 2
        or 'conclusion: "failure"' in success_routine
        or success_routine.count("require_publishable_ci\n") != 8
    ):
        raise ContractError(
            "dedicated Security contract publisher weakens App, main-ref, binding, or check payload authentication"
        )
    if branch_routine.strip() != (
        "reconcile_bad_ci\n"
        'if test "${bad_ci_observed}" = false; then\n'
        "  publish_success_authority\n"
        "else\n"
        "  exit 1\n"
        "fi"
    ):
        raise ContractError(
            "dedicated Security contract reconciler does not fail closed before publication"
        )
    for marker, expected_count in (
        ('conclusion: "success"', 2),
        ('conclusion: "failure"', 2),
        ("external_id: $external_id", 4),
        ("head_sha: $head_sha", 3),
        ('--arg details_url "${publication_details_url}"', 2),
        ("details_url: $details_url", 2),
        ('= "${publication_details_url}"', 2),
        (
            "actions/runs/${FINALIZER_RUN_ID}/attempts/${FINALIZER_RUN_ATTEMPT}",
            1,
        ),
        (".details_url", 5),
        ("revalidate_live_publication_head\n", 10),
        ('status: "completed"', 4),
        ("--request PATCH", 1),
    ):
        if publisher_run.count(marker) != expected_count:
            raise ContractError(
                "dedicated Security contract publisher weakens App, main-ref, binding, or check payload authentication"
            )

    forbidden_candidate_commands = (
        "actions/checkout",
        "cargo ",
        "./scripts/",
        "target/",
    )
    if any(
        contains_text(candidate_free_job, value)
        for candidate_free_job in (
            validate_capture,
            sign_capture,
            publish_security_contract,
        )
        for value in forbidden_candidate_commands
    ):
        raise ContractError(
            "enterprise evidence finalizer executes candidate artifacts"
        )
    if any(
        contains_text(authorize_publication, value)
        for value in ("cargo ", "./scripts/", "target/")
    ):
        raise ContractError(
            "security check publication authorization executes candidate artifacts"
        )
    for identifier in finalizer_jobs:
        validate_job_digest(
            job(evidence_finalizer, identifier),
            EXPECTED_TRUST_JOB_DIGESTS[("enterprise evidence finalizer", identifier)],
            f"enterprise evidence finalizer {identifier}",
        )

    if (
        security_revocation.get("name") != "Security contract revocation"
        or security_revocation.get("on") != EXPECTED_REVOCATION_EVENTS
        or security_revocation.get("permissions") != {}
        or set(workflow_jobs(security_revocation))
        != {"bind-revocation", "revoke-security-contract"}
        or any(key in security_revocation for key in ("concurrency", "env"))
    ):
        raise ContractError("security check revocation workflow identity changed")
    bind_revocation = job(security_revocation, "bind-revocation")
    expected_bind_outputs = {
        "authorized_source_sha": "${{ steps.manual.outputs.authorized_source_sha || steps.failure.outputs.authorized_source_sha || steps.finalizer.outputs.authorized_source_sha }}",
        "base_sha": "${{ steps.manual.outputs.base_sha || steps.failure.outputs.base_sha || steps.finalizer.outputs.base_sha }}",
        "create_missing": "${{ steps.manual.outputs.create_missing || steps.failure.outputs.create_missing || steps.finalizer.outputs.create_missing }}",
        "eligible": "${{ steps.manual.outputs.eligible || steps.failure.outputs.eligible || steps.finalizer.outputs.eligible }}",
        "evidence_sha": "${{ steps.manual.outputs.evidence_sha || steps.failure.outputs.evidence_sha || steps.finalizer.outputs.evidence_sha }}",
        "merge_commit_sha": "${{ steps.manual.outputs.merge_commit_sha || steps.failure.outputs.merge_commit_sha || steps.finalizer.outputs.merge_commit_sha }}",
        "merge_tree_sha": "${{ steps.manual.outputs.merge_tree_sha || steps.failure.outputs.merge_tree_sha || steps.finalizer.outputs.merge_tree_sha }}",
        "pr_number": "${{ steps.manual.outputs.pr_number || steps.failure.outputs.pr_number || steps.finalizer.outputs.pr_number }}",
        "reason": "${{ steps.manual.outputs.reason || steps.failure.outputs.reason || steps.finalizer.outputs.reason }}",
        "security_definition_sha": "${{ steps.manual.outputs.security_definition_sha || steps.failure.outputs.security_definition_sha || steps.finalizer.outputs.security_definition_sha }}",
    }
    if (
        bind_revocation.get("name") != "bind exact manual or failed authority revocation"
        or normalized_expression(bind_revocation.get("if"))
        != normalized_expression(
            "${{ github.event_name == 'workflow_dispatch' || "
            "(github.event.action == 'completed' && "
            "github.event.workflow_run.conclusion != 'success') }}"
        )
        or bind_revocation.get("permissions") != EXPECTED_FINALIZER_PERMISSIONS
        or bind_revocation.get("runs-on") != "ubuntu-24.04"
        or bind_revocation.get("timeout-minutes") != "10"
        or bind_revocation.get("outputs") != expected_bind_outputs
        or set(bind_revocation)
        != {
            "name",
            "if",
            "permissions",
            "runs-on",
            "timeout-minutes",
            "outputs",
            "steps",
        }
    ):
        raise ContractError("security check revocation binder identity changed")
    validate_step_inventory(
        bind_revocation,
        (
            ("Bind frozen manual revocation", "manual", None),
            ("Bind later failed CI rerun to existing authority", "failure", None),
            ("Bind failed finalizer to existing authority", "finalizer", None),
        ),
        "security check revocation binder",
    )
    manual_bind = named_step(bind_revocation, "Bind frozen manual revocation")
    failure_bind = named_step(
        bind_revocation, "Bind later failed CI rerun to existing authority"
    )
    finalizer_bind = named_step(
        bind_revocation, "Bind failed finalizer to existing authority"
    )
    if (
        manual_bind.get("if") != "${{ github.event_name == 'workflow_dispatch' }}"
        or failure_bind.get("if")
        != "${{ github.event_name == 'workflow_run' && github.event.workflow_run.name == 'CI' }}"
        or finalizer_bind.get("if")
        != "${{ github.event_name == 'workflow_run' && github.event.workflow_run.name == 'Enterprise evidence finalizer' }}"
    ):
        raise ContractError("security check revocation event routing changed")
    if manual_bind.get("env") != {
        "AUTHORIZED_SOURCE_SHA": "${{ inputs.authorized_source_sha }}",
        "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
        "EVIDENCE_SHA": "${{ inputs.evidence_sha }}",
        "GH_TOKEN": "${{ github.token }}",
        "MERGE_COMMIT_SHA": "${{ inputs.merge_commit_sha }}",
        "PR_NUMBER": "${{ inputs.pr_number }}",
        "REASON": "${{ inputs.reason }}",
        "REVOKER_ACTOR": "${{ github.actor }}",
        "REVOKER_REF": "${{ github.ref }}",
        "REVOKER_RUN_ID": "${{ github.run_id }}",
        "REVOKER_SHA": "${{ github.sha }}",
        "REVOKER_TRIGGERING_ACTOR": "${{ github.triggering_actor }}",
        "RUN_ATTEMPT": "${{ github.run_attempt }}",
        "SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
    }:
        raise ContractError("manual revocation binding inputs changed")
    require_run_markers(
        bind_revocation,
        "Bind frozen manual revocation",
        (
            'test "${GITHUB_REPOSITORY}" = "${GITHUB_REPOSITORY_OWNER}/arc"',
            'test "${REVOKER_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"',
            'test "${REVOKER_TRIGGERING_ACTOR}" = "${GITHUB_REPOSITORY_OWNER}"',
            'test "${RUN_ATTEMPT}" = "1"',
            'test "${DEFAULT_BRANCH}" = "main"',
            'test "${REVOKER_REF}" = "refs/heads/main"',
            "contents/.github/workflows/security-contract-revocation.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/security-contract-revocation.yml?ref=${REVOKER_SHA}",
            'test "${running_revoker_blob_sha}" = "${authorized_revoker_blob_sha}"',
            "actions/workflows/security-contract-revocation.yml",
            'test "$(jq -r \'.path\' <<< "${revoker_run}")" = ".github/workflows/security-contract-revocation.yml"',
            'test "$(jq -r \'.event\' <<< "${revoker_run}")" = workflow_dispatch',
            'test "$(jq -r \'.head_sha\' <<< "${revoker_run}")" = "${REVOKER_SHA}"',
            '[[ "${MERGE_COMMIT_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            'echo "eligible=true"',
            'echo "merge_commit_sha=${MERGE_COMMIT_SHA}"',
            'echo "security_definition_sha=${SECURITY_DEFINITION_SHA}"',
        ),
        "manual revocation loses owner, main, or exact M binding",
    )
    if failure_bind.get("env") != {
        "AUTHORIZED_SOURCE_SHA": "${{ vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA }}",
        "COMMITTED_EVIDENCE_SHA": "${{ vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA }}",
        "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
        "EVENT_ACTION": "${{ github.event.action }}",
        "EVENT_CONCLUSION": "${{ github.event.workflow_run.conclusion || '' }}",
        "EVENT_RUN_ATTEMPT": "${{ github.event.workflow_run.run_attempt }}",
        "EVENT_RUN_ID": "${{ github.event.workflow_run.id }}",
        "EVENT_WORKFLOW_ID": "${{ github.event.workflow_run.workflow_id }}",
        "GH_TOKEN": "${{ github.token }}",
        "LISTENER_REF": "${{ github.ref }}",
        "LISTENER_RUN_ATTEMPT": "${{ github.run_attempt }}",
        "LISTENER_RUN_ID": "${{ github.run_id }}",
        "LISTENER_SHA": "${{ github.sha }}",
        "REPOSITORY_ID": "${{ github.repository_id }}",
        "REPOSITORY_OWNER_ID": "${{ github.repository_owner_id }}",
        "SECURITY_APP_ID": "${{ vars.CHIO_SECURITY_APP_ID }}",
        "SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
    }:
        raise ContractError("later-CI revocation binding inputs changed")
    require_run_markers(
        bind_revocation,
        "Bind later failed CI rerun to existing authority",
        (
            'test "${EVENT_CONCLUSION}" != success',
            '[[ "${EVENT_RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]',
            "contents/.github/workflows/security-contract-revocation.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/security-contract-revocation.yml?ref=${LISTENER_SHA}",
            'test "${running_listener_blob_sha}" = "${authorized_listener_blob_sha}"',
            "actions/workflows/security-contract-revocation.yml",
            'test "$(jq -r \'.path\' <<< "${listener_run}")" = ".github/workflows/security-contract-revocation.yml"',
            'test "$(jq -r \'.event\' <<< "${listener_run}")" = workflow_run',
            'test "$(jq -r \'.head_sha\' <<< "${listener_run}")" = "${LISTENER_SHA}"',
            "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml",
            "repos/${GITHUB_REPOSITORY}/actions/runs/${EVENT_RUN_ID}/attempts/${EVENT_RUN_ATTEMPT}",
            'test "$(jq -r \'.path\' <<< "${upstream}")" = ".github/workflows/ci.yml"',
            'test "$(jq -r \'.event\' <<< "${upstream}")" = "pull_request"',
            'upstream_conclusion="$(jq -r \'.conclusion // ""\' <<< "${upstream}")"',
            'test "${upstream_conclusion}" = "${EVENT_CONCLUSION}"',
            'run_attempt="${EVENT_RUN_ATTEMPT}"',
            'test "$(jq -r \'.run_attempt\' <<< "${upstream}")" = "${run_attempt}"',
            'run_name="$(jq -r \'.display_title\' <<< "${upstream}")"',
            r'[[ "${run_name}" =~ ^CI\ N=([1-9][0-9]*)\ E=([0-9a-f]{40})\ B=([0-9a-f]{40})\ M=([0-9a-f]{40})$ ]]',
            "contents/.github/workflows/ci.yml?ref=${AUTHORIZED_SOURCE_SHA}",
            "contents/.github/workflows/ci.yml?ref=${evidence_sha}",
            "contents/.github/workflows/ci.yml?ref=${merge_commit_sha}",
            'test "${evidence_ci_blob}" = "${authorized_ci_blob}"',
            'test "${merge_ci_blob}" = "${authorized_ci_blob}"',
            'test "$(jq -cS \'[.parents[].sha]\' <<< "${merge_commit}")" = "[\\"${base_sha}\\",\\"${evidence_sha}\\"]"',
            "actions/runs/${EVENT_RUN_ID}/artifacts?per_page=100",
            'artifact_name="ci-merge-binding-${EVENT_RUN_ID}-${run_attempt}"',
            'if test "${builder_conclusion}" = success; then',
            '\n  test "${artifact_count}" = 1\n',
            'test "$(jq -cs \'length\' "${bundle_file}")" = 1',
            '"${gh_bin}" attestation verify "${binding_file}"',
            '--predicate-type "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1"',
            '--signer-workflow "bb-connor/arc/.github/workflows/enterprise-hardening.yml"',
            '--signer-digest "${SECURITY_DEFINITION_SHA}"',
            '--source-digest "${merge_commit_sha}"',
            '--source-ref "refs/pull/${pr_number}/merge"',
            '--deny-self-hosted-runners',
            'test "$(jq -r \'.predicateType\' <<< "${statement}")" = "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1"',
            'test "$(jq -r \'.subject | length\' <<< "${statement}")" = 1',
            'test "$(jq -r \'.subject[0].name\' <<< "${statement}")" = ci-merge-binding.json',
            'test "$(jq -r \'.subject[0].digest.sha256\' <<< "${statement}")" = "${binding_sha256}"',
            'test "$(jq -cS \'.predicate\' <<< "${statement}")" = "${binding}"',
            'test "$(jq -r \'.issuer\' <<< "${certificate}")" = "https://token.actions.githubusercontent.com"',
            'test "$(jq -r \'.subjectAlternativeName\' <<< "${certificate}")" = "${signer_uri}"',
            'test "$(jq -r \'.buildSignerURI\' <<< "${certificate}")" = "${signer_uri}"',
            'test "$(jq -r \'.buildSignerDigest\' <<< "${certificate}")" = "${SECURITY_DEFINITION_SHA}"',
            'test "$(jq -r \'.runnerEnvironment\' <<< "${certificate}")" = github-hosted',
            'test "$(jq -r \'.sourceRepositoryURI\' <<< "${certificate}")" = "https://github.com/${GITHUB_REPOSITORY}"',
            'test "$(jq -r \'.sourceRepositoryDigest\' <<< "${certificate}")" = "${merge_commit_sha}"',
            'test "$(jq -r \'.sourceRepositoryRef\' <<< "${certificate}")" = "refs/pull/${pr_number}/merge"',
            'test "$(jq -r \'.sourceRepositoryIdentifier\' <<< "${certificate}")" = "${REPOSITORY_ID}"',
            'test "$(jq -r \'.sourceRepositoryOwnerIdentifier\' <<< "${certificate}")" = "${REPOSITORY_OWNER_ID}"',
            'test "$(jq -r \'.buildConfigURI\' <<< "${certificate}")" = "${caller_uri}"',
            'test "$(jq -r \'.buildConfigDigest\' <<< "${certificate}")" = "${merge_commit_sha}"',
            'test "$(jq -r \'.buildTrigger\' <<< "${certificate}")" = pull_request',
            'test "$(jq -r \'.runInvocationURI\' <<< "${certificate}")" = "https://github.com/${GITHUB_REPOSITORY}/actions/runs/${EVENT_RUN_ID}/attempts/${run_attempt}"',
            'test "$(jq -r \'.sourceRepositoryVisibilityAtSigning\' <<< "${certificate}")" = public',
            'test "$(jq -r \'.githubWorkflowSHA\' <<< "${certificate}")" = "${merge_commit_sha}"',
            'test "$(jq -r \'.githubWorkflowRef\' <<< "${certificate}")" = "refs/pull/${pr_number}/merge"',
            'test "$(jq -r \'length >= 1 and length <= 8\' <<< "${timestamps}")" = true',
            '(.type == "Tlog" or .type == "TimestampAuthority")',
            'test "${timestamp_epoch}" -ge "$((artifact_created_epoch - 300))"',
            'create_missing=false',
            'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${evidence_sha}"',
            'test "$(jq -r \'.base.sha\' <<< "${live_pr}")" = "${base_sha}"',
            "repos/${GITHUB_REPOSITORY}/git/ref/pull/${pr_number}/merge",
            'test "$(jq -r \'.object.sha\' <<< "${live_merge_ref}")" = "${merge_commit_sha}"',
            'create_missing=true',
            'test "${COMMITTED_EVIDENCE_SHA}" = "${evidence_sha}"',
            "commits/${merge_commit_sha}/check-runs?filter=all&per_page=100",
            'echo "eligible=false" >> "${GITHUB_OUTPUT}"',
            'echo "authorized_source_sha=${AUTHORIZED_SOURCE_SHA}"',
            'echo "base_sha=${base_sha}"',
            'echo "create_missing=${create_missing}"',
            'echo "eligible=true"',
            'echo "merge_tree_sha=${merge_tree_sha}"',
            'echo "reason=ci-regression"',
            'echo "security_definition_sha=${SECURITY_DEFINITION_SHA}"',
        ),
        "later-CI revocation loses failure-only, definition, source, PR/E/M, or evidence-variable binding",
    )
    failure_bind_run = str(failure_bind.get("run", ""))
    if (
        "pull_requests[" in failure_bind_run
        or ".merge_commit_sha" in failure_bind_run
        or '"repos/${GITHUB_REPOSITORY}/actions/runs/${EVENT_RUN_ID}"'
        in failure_bind_run
        or 'run_attempt="$(jq' in failure_bind_run
        or "contents/.github/workflows/ci.yml?ref=${AUTHORIZED_SOURCE_SHA}"
        not in failure_bind_run
    ):
        raise ContractError(
            "later-CI revocation trusts mutable workflow-run pull-request metadata"
        )
    if finalizer_bind.get("env") != {
        "DEFAULT_BRANCH": "${{ github.event.repository.default_branch }}",
        "EVENT_ACTION": "${{ github.event.action }}",
        "EVENT_CONCLUSION": "${{ github.event.workflow_run.conclusion || '' }}",
        "EVENT_RUN_ATTEMPT": "${{ github.event.workflow_run.run_attempt }}",
        "EVENT_RUN_ID": "${{ github.event.workflow_run.id }}",
        "EVENT_WORKFLOW_ID": "${{ github.event.workflow_run.workflow_id }}",
        "GH_TOKEN": "${{ github.token }}",
        "LISTENER_REF": "${{ github.ref }}",
        "LISTENER_RUN_ATTEMPT": "${{ github.run_attempt }}",
        "LISTENER_RUN_ID": "${{ github.run_id }}",
        "LISTENER_SHA": "${{ github.sha }}",
        "SECURITY_APP_ID": "${{ vars.CHIO_SECURITY_APP_ID }}",
        "SECURITY_DEFINITION_SHA": "${{ vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA }}",
    }:
        raise ContractError("failed-finalizer revocation binding inputs changed")
    finalizer_bind_run = require_run_markers(
        bind_revocation,
        "Bind failed finalizer to existing authority",
        (
            'test "${EVENT_ACTION}" = completed',
            'test "${EVENT_CONCLUSION}" != success',
            '[[ "${EVENT_RUN_ATTEMPT}" =~ ^[1-9][0-9]*$ ]]',
            "contents/.github/workflows/security-contract-revocation.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/security-contract-revocation.yml?ref=${LISTENER_SHA}",
            'test "${running_listener_blob_sha}" = "${authorized_listener_blob_sha}"',
            "actions/workflows/security-contract-revocation.yml",
            'test "$(jq -r \'.path\' <<< "${listener_run}")" = .github/workflows/security-contract-revocation.yml',
            'test "$(jq -r \'.event\' <<< "${listener_run}")" = workflow_run',
            'test "$(jq -r \'.head_sha\' <<< "${listener_run}")" = "${LISTENER_SHA}"',
            "actions/workflows/enterprise-evidence-finalizer.yml",
            "actions/runs/${EVENT_RUN_ID}/attempts/${EVENT_RUN_ATTEMPT}",
            'test "$(jq -r \'.path\' <<< "${upstream}")" = .github/workflows/enterprise-evidence-finalizer.yml',
            'test "$(jq -r \'.event\' <<< "${upstream}")" = workflow_dispatch',
            'test "$(jq -r \'.status\' <<< "${upstream}")" = completed',
            'test "$(jq -r \'.conclusion // ""\' <<< "${upstream}")" = "${EVENT_CONCLUSION}"',
            'test "$(jq -r \'.actor.login\' <<< "${upstream}")" = "github-actions[bot]"',
            'test "$(jq -r \'.triggering_actor.login\' <<< "${upstream}")" = "github-actions[bot]"',
            'run_attempt="${EVENT_RUN_ATTEMPT}"',
            'test "$(jq -r \'.run_attempt\' <<< "${upstream}")" = "${run_attempt}"',
            'test "${run_attempt}" = "1"',
            'test "$(jq -r \'length\' <<< "${finalizer_jobs}")" = 4',
            'require_successful_finalizer_job "validate unsigned enterprise Linux capture"',
            'require_successful_finalizer_job "sign committed enterprise Linux migration evidence"',
            'require_successful_finalizer_job "authorize dedicated Security contract publication"',
            'publisher_jobs="$(jq -cS \'[.[] | select(.name == "reconcile exact merge authority contexts")]\' <<< "${finalizer_jobs}")"',
            'test "$(jq -r \'length\' <<< "${publisher_jobs}")" = 1',
            'test "$(jq -r \'.status\' <<< "${publisher_job}")" = completed',
            'test "$(jq -r \'.conclusion // ""\' <<< "${publisher_job}")" != success',
            r'[[ "${run_name}" =~ ^Enterprise\ evidence\ finalizer\ N=([1-9][0-9]*)\ E=([0-9a-f]{40})\ M=([0-9a-f]{40})\ S=([0-9a-f]{40})\ K=([0-9a-f]{64})$ ]]',
            'authenticated_intent_name="authenticated-finalizer-intent-${EVENT_RUN_ID}-${run_attempt}"',
            "actions/runs/${EVENT_RUN_ID}/artifacts?per_page=100",
            'test "$(jq -r \'length\' <<< "${intent_artifacts}")" = 1',
            r'[[ "${intent_artifact_digest}" =~ ^sha256:[0-9a-f]{64}$ ]]',
            'test "$(jq -r \'.expired\' <<< "${intent_artifact}")" = false',
            'test "${validate_started_epoch}" -le "${intent_created_epoch}"',
            'test "${intent_updated_epoch}" -le "${validate_completed_epoch}"',
            'test "$(sha256sum "${intent_partial}" | cut -d\' \' -f1)" = "${intent_artifact_digest#sha256:}"',
            'expected_name = "finalizer-dispatch-intent.json"',
            "if len(infos) != 1:",
            "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW",
            "while pending:",
            'test "$(jq -r \'.schema\' <<< "${intent}")" = "chio.enterprise-finalizer-dispatch-intent.v1"',
            'test "$(jq -r \'.authorized_source_sha\' <<< "${intent}")" = "${authorized_source_sha}"',
            'test "$(jq -r \'.capture_run_attempt\' <<< "${intent}")" = "1"',
            'test "$(jq -r \'.default_commit_sha\' <<< "${intent}")" = "${upstream_sha}"',
            'test "$(jq -r \'.dispatch_job_key\' <<< "${intent}")" = "dispatch-trusted-finalizer"',
            'test "$(jq -r \'.dispatch_nonce\' <<< "${intent}")" = "${dispatch_nonce}"',
            'test "$(jq -r \'.finalizer_run_attempt\' <<< "${intent}")" = "${run_attempt}"',
            'test "$(jq -r \'.finalizer_run_id\' <<< "${intent}")" = "${EVENT_RUN_ID}"',
            'test "$(jq -r \'.merge_commit_sha\' <<< "${intent}")" = "${merge_commit_sha}"',
            'test "$(jq -r \'.pr_number\' <<< "${intent}")" = "${pr_number}"',
            'test "$(jq -r \'.source_sha\' <<< "${intent}")" = "${evidence_sha}"',
            'historical_security_definition_sha="$(jq -r \'.security_definition_sha\' <<< "${intent}")"',
            "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${historical_security_definition_sha}",
            "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${upstream_sha}",
            'test "${running_finalizer_blob_sha}" = "${authorized_finalizer_blob_sha}"',
            "git/commits/${merge_commit_sha}",
            'test "$(jq -r \'.parents | length\' <<< "${merge_commit}")" = 2',
            'test "$(jq -r \'.parents[1].sha\' <<< "${merge_commit}")" = "${evidence_sha}"',
            'external_id="arc:${pr_number}:${evidence_sha}:${merge_commit_sha}:${authorized_source_sha}"',
            "commits/${merge_commit_sha}/check-runs?filter=all&per_page=100",
            'finalizer_details_url="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${EVENT_RUN_ID}/attempts/${run_attempt}"',
            '.status == "completed" and .conclusion == "success" and .details_url == $details_url and (.app.id | tostring) == $app_id and .name == "Security contract" and .external_id == $external_id',
            'test "${relevant_count}" -le 1',
            'echo "eligible=false" >> "${GITHUB_OUTPUT}"',
            'echo "create_missing=false"',
            'echo "eligible=true"',
            'echo "reason=finalizer-failure"',
        ),
        "failed-finalizer revocation loses workflow, definition, N/E/M/S, or existing-authority binding",
    )
    if (
        "LIVE_AUTHORIZED_SOURCE_SHA" in finalizer_bind_run
        or "Security mirror /" in finalizer_bind_run
        or "contents/.github/workflows/enterprise-evidence-finalizer.yml?ref=${SECURITY_DEFINITION_SHA}"
        in finalizer_bind_run
        or finalizer_bind_run.count("require_successful_finalizer_job ") != 3
        or finalizer_bind_run.count("create_missing=false") != 1
        or finalizer_bind_run.count("(.app.id | tostring) == $app_id") != 1
        or '"repos/${GITHUB_REPOSITORY}/actions/runs/${EVENT_RUN_ID}"'
        in finalizer_bind_run
        or 'run_attempt="$(jq' in finalizer_bind_run
    ):
        raise ContractError(
            "failed-finalizer revocation accepts mutable authority or non-dedicated evidence"
        )
    revocation = job(security_revocation, "revoke-security-contract")
    if (
        revocation.get("name")
        != "normalize exact five-context authority to sticky failure"
        or revocation.get("needs") != ["bind-revocation"]
        or revocation.get("if")
        != "${{ needs.bind-revocation.outputs.eligible == 'true' }}"
        or revocation.get("environment") != "security-check-publisher"
        or revocation.get("concurrency") != EXPECTED_REVOCATION_CONCURRENCY
        or revocation.get("permissions")
        != {"checks": "write", "pull-requests": "read", "contents": "read"}
        or revocation.get("runs-on") != "ubuntu-24.04"
        or revocation.get("timeout-minutes") != "10"
        or set(revocation)
        != {
            "name",
            "needs",
            "if",
            "environment",
            "concurrency",
            "permissions",
            "runs-on",
            "timeout-minutes",
            "steps",
        }
    ):
        raise ContractError("security check revocation job identity changed")
    validate_step_inventory(
        revocation,
        EXPECTED_REVOCATION_STEP_INVENTORY,
        "security check revocation",
    )
    revocation_step = named_step(
        revocation, "Revoke exact Actions mirrors and dedicated App namespace"
    )
    if (
        set(revocation_step) != {"name", "env", "run"}
        or revocation_step.get("env") != EXPECTED_REVOCATION_STEP_ENV
    ):
        raise ContractError("security check revocation sealed inputs changed")
    revocation_run = require_run_markers(
        revocation,
        "Revoke exact Actions mirrors and dedicated App namespace",
        (
            'test "${GITHUB_REPOSITORY}" = "${GITHUB_REPOSITORY_OWNER}/arc"',
            'test "${DEFAULT_BRANCH}" = "main"',
            'test "${REVOKER_REF}" = "refs/heads/main"',
            '[[ "${AUTHORIZED_SOURCE_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            '[[ "${EVIDENCE_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            '[[ "${MERGE_COMMIT_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            '[[ "${SECURITY_DEFINITION_SHA}" =~ ^[0-9a-f]{40}$ ]]',
            'if test "${EVENT_NAME}" = "workflow_dispatch"; then',
            'test "${LIVE_COMMITTED_EVIDENCE_SHA}" = "0000000000000000000000000000000000000000"',
            'test "${EVENT_NAME}" = "workflow_run"',
            'test "${LIVE_COMMITTED_EVIDENCE_SHA}" = "${EVIDENCE_SHA}"',
            'test "${LIVE_SECURITY_DEFINITION_SHA}" = "${SECURITY_DEFINITION_SHA}"',
            "contents/.github/workflows/security-contract-revocation.yml?ref=${SECURITY_DEFINITION_SHA}",
            "contents/.github/workflows/security-contract-revocation.yml?ref=${REVOKER_SHA}",
            'test "${running_revoker_blob_sha}" = "${authorized_revoker_blob_sha}"',
            'if test "${REASON}" != "finalizer-failure"; then',
            'test "${LIVE_AUTHORIZED_SOURCE_SHA}" = "${AUTHORIZED_SOURCE_SHA}"',
            'test "${SECURITY_APP_ID}" != "15368"',
            '[[ "${CREATE_MISSING}" == true || "${CREATE_MISSING}" == false ]]',
            'external_id="arc:${PR_NUMBER}:${EVIDENCE_SHA}:${MERGE_COMMIT_SHA}:${AUTHORIZED_SOURCE_SHA}"',
            'test "$(jq -cS \'[.parents[].sha]\' <<< "${merge_commit}")" = "[\\"${BASE_SHA}\\",\\"${EVIDENCE_SHA}\\"]"',
            'test "$(jq -r \'.tree.sha\' <<< "${merge_commit}")" = "${MERGE_TREE_SHA}"',
            'if test "${CREATE_MISSING}" = true; then',
            'test "$(jq -r \'.head.sha\' <<< "${live_pr}")" = "${EVIDENCE_SHA}"',
            '"repos/${GITHUB_REPOSITORY}/git/ref/pull/${PR_NUMBER}/merge"',
            'test "$(jq -r \'.object.type\' <<< "${merge_ref}")" = commit',
            'test "$(jq -r \'.object.sha\' <<< "${merge_ref}")" = "${MERGE_COMMIT_SHA}"',
            "trap 'unset SECURITY_APP_PRIVATE_KEY_PEM installation_token",
            'test "$(jq -r \'.slug\' <<< "${app}")" = "chio-security-authority"',
            'test "$(jq -cS \'.permissions\' <<< "${app}")" = \'{"checks":"write","metadata":"read","statuses":"write"}\'',
            'token_request=\'{"permissions":{"checks":"write"}}\'',
            '\'{"checks":"write"}\'|\'{"checks":"write","metadata":"read"}\') ;;',
            'test "$(jq -cS \'.permissions\' <<< "${installation}")" = \'{"checks":"write","metadata":"read","statuses":"write"}\'',
            'test "$(jq -r \'.repositories[0].full_name\' <<< "${repositories}")" = "${GITHUB_REPOSITORY}"',
            "filter=all&per_page=100&page=${page}",
            'test "$(jq -r \'[.[].id] | unique | length\' <<< "${collected}")" = "${total_count}"',
            "normalize_namespace()",
            'canonical_check_id="$(jq -r --arg external_id "${required_external_id}"',
            'target_name="${check_name} / superseded ${check_run_id}"',
            'test "$(jq -r \'.name\' <<< "${updated}")" = "${target_name}"',
            'if test "${namespace_count}" = "0"; then',
            'schema: "chio.security-check-revocation.v1"',
            'conclusion: "failure"',
            'head_sha: $head_sha',
            'created="$(curl --proto \'=https\' --tlsv1.2 --fail --silent --show-error --request POST',
            '--request POST',
            '"https://api.github.com/repos/${GITHUB_REPOSITORY}/check-runs"',
            'title: "Chio security authority revoked"',
            "--request PATCH",
            '"https://api.github.com/repos/${GITHUB_REPOSITORY}/check-runs/${check_run_id}"',
            'test "$(jq -r \'.total_count\' <<< "${verified}")" = "1"',
            '.name == $name and .head_sha == $head_sha and .status == "completed" and .conclusion == "failure" and (.app.id | tostring) == $app_id and .app.slug == $app_slug',
            'test "$(jq -r \'.check_runs[0].external_id\' <<< "${verified}")" = "${required_external_id}"',
            'test "${verified_metadata}" = "${preserved_metadata}"',
            'normalize_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / Build, lint, test" "${external_id}:actions:build"',
            'normalize_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / MSRV build and test" "${external_id}:actions:msrv"',
            'normalize_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / cargo-vet (locked supply-chain audit)" "${external_id}:actions:vet"',
            'normalize_namespace "${GH_TOKEN}" 15368 github-actions "Security mirror / cargo-deny (supply-chain bans/advisories/licenses)" "${external_id}:actions:deny"',
            'normalize_namespace "${installation_token}" "${SECURITY_APP_ID}" chio-security-authority "Security contract" "${external_id}"',
        ),
        "security check revocation weakens event, owner, App, binding, or failure verification",
    )
    for marker, expected_count in (
        ("--request POST", 2),
        ("--request PATCH", 1),
        ('conclusion: "failure"', 2),
        ('status: "completed"', 2),
        ("normalize_namespace ", 5),
    ):
        if revocation_run.count(marker) != expected_count:
            raise ContractError(
                "security check revocation weakens event, owner, App, binding, or failure verification"
            )
    if any(
        contains_text(candidate_free_revocation_job, value)
        for candidate_free_revocation_job in (bind_revocation, revocation)
        for value in (
            "actions/checkout",
            "cargo ",
            "./scripts/",
            "target/",
        )
    ):
        raise ContractError(
            "security check revocation executes candidate code"
        )
    for identifier in ("bind-revocation", "revoke-security-contract"):
        validate_job_digest(
            job(security_revocation, identifier),
            EXPECTED_TRUST_JOB_DIGESTS[("security contract revocation", identifier)],
            f"security contract revocation {identifier}",
        )

    called = job(ci, "enterprise-security-contract")
    call_ref = called.get("uses")
    call_match = (
        ENTERPRISE_HARDENING_CALL_PATTERN.fullmatch(call_ref)
        if isinstance(call_ref, str)
        else None
    )
    if (
        set(called) != {"permissions", "uses", "with"}
        or called.get("permissions") != EXPECTED_ENTERPRISE_PERMISSIONS
        or called.get("with") != EXPECTED_ENTERPRISE_CALL_INPUTS
        or call_match is None
    ):
        raise ContractError(
            "required CI does not call enterprise-hardening at an immutable full SHA"
        )
    bootstrap_sha = call_match.group(1)
    ci_text = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    bootstrap_sentinels = ENTERPRISE_HARDENING_BOOTSTRAP_SENTINEL_PATTERN.findall(
        ci_text
    )
    if bootstrap_sha == ZERO_COMMIT_SHA or ZERO_COMMIT_SHA in bootstrap_sentinels:
        raise ContractError("enterprise-hardening bootstrap SHA cannot be all zero")
    if (
        bootstrap_sentinels != [bootstrap_sha]
        or "uses: ./.github/workflows/enterprise-hardening.yml" in ci_text
    ):
        raise ContractError("enterprise-hardening bootstrap SHA sentinel is not exact")

    reusable_calls = {
        "apalache-full-contract": "./.github/workflows/apalache-safety.yml",
        "threat-model-coverage-contract": "./.github/workflows/threat-model-coverage.yml",
    }
    for identifier, workflow_path in reusable_calls.items():
        called_workflow = job(ci, identifier)
        if called_workflow.get("uses") != workflow_path:
            raise ContractError(
                f"required CI does not call the exact reusable workflow: {identifier}"
            )
        if "if" in called_workflow:
            raise ContractError(
                f"required CI conditionally calls reusable workflow: {identifier}"
            )

    apalache_events = apalache.get("on")
    if not isinstance(apalache_events, dict) or set(apalache_events) != {
        "workflow_call",
        "workflow_dispatch",
        "schedule",
    }:
        raise ContractError(
            "full Apalache workflow must be callable, manual, and scheduled without a duplicate PR trigger"
        )
    if apalache.get("concurrency") != EXPECTED_APALACHE_CONCURRENCY:
        raise ContractError(
            "full Apalache workflow does not isolate caller concurrency"
        )
    apalache_job = job(apalache, "apalache-subset")
    if contains_key(apalache_job, "continue-on-error") or contains_key(
        apalache_job, "if"
    ):
        raise ContractError(
            "full Apalache workflow contains a conditional or soft-fail gate"
        )
    apalache_safety = named_step(apalache_job, "Apalache safety checks").get("run")
    if (
        not isinstance(apalache_safety, str)
        or apalache_safety.strip() != EXPECTED_APALACHE_SAFETY_RUN
    ):
        raise ContractError("full Apalache workflow omits the exact seven-model matrix")
    mutation_run = named_step(
        apalache_job, "Apalache information-flow mutation check"
    ).get("run")
    if (
        not isinstance(mutation_run, str)
        or mutation_run.strip() != EXPECTED_APALACHE_MUTATION_RUN
    ):
        raise ContractError(
            "full Apalache workflow omits its negative mutation ratchet"
        )

    threat_events = threat_coverage.get("on")
    if not isinstance(threat_events, dict) or set(threat_events) != {
        "workflow_call",
        "workflow_dispatch",
    }:
        raise ContractError(
            "threat-model coverage must be callable and manual without duplicate PR or push triggers"
        )
    if threat_coverage.get("concurrency") != EXPECTED_THREAT_CONCURRENCY:
        raise ContractError(
            "threat-model coverage workflow does not isolate caller concurrency"
        )
    threat_env = threat_coverage.get("env")
    if not isinstance(threat_env, dict) or any(
        threat_env.get(key) != value
        for key, value in {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "1"}.items()
    ):
        raise ContractError(
            "threat-model coverage does not serialize nonincremental Cargo"
        )
    threat_job = job(threat_coverage, "coverage-gate")
    if contains_key(threat_job, "continue-on-error") or contains_key(threat_job, "if"):
        raise ContractError(
            "threat-model coverage contains a conditional or soft-fail gate"
        )
    for step_name, command in EXPECTED_THREAT_GATE_COMMANDS.items():
        if named_step(threat_job, step_name).get("run") != command:
            raise ContractError(
                f"threat-model coverage omits exact gate command: {step_name}"
            )

    formal = job(ci, "formal-proof-contract")
    if formal.get("name") != "Formal proof contract":
        raise ContractError("formal proof job has the wrong check name")
    if formal.get("runs-on") != "ubuntu-24.04":
        raise ContractError("formal proof job is not pinned to Ubuntu 24.04")
    formal_steps = formal.get("steps")
    checkout_matches = (
        [
            step
            for step in formal_steps
            if isinstance(step, dict)
            and step.get("uses")
            == "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5"
        ]
        if isinstance(formal_steps, list)
        else []
    )
    if len(checkout_matches) != 1:
        raise ContractError("formal proof job lacks its pinned checkout")
    elan = named_step(formal, "Install Lean 4 toolchain")
    if elan.get("shell") != "bash" or elan.get("env") != EXPECTED_ELAN_ENV:
        raise ContractError("formal proof job does not pin the approved elan release")
    elan_run = elan.get("run")
    if not isinstance(elan_run, str) or elan_run.strip() != EXPECTED_ELAN_INSTALL_RUN:
        raise ContractError(
            "formal proof job does not verify the elan archive checksum"
        )
    prime_run = named_step(formal, "Prime Lean 4 toolchain").get("run")
    if not isinstance(prime_run, str) or prime_run.strip() != EXPECTED_LEAN_PRIME_RUN:
        raise ContractError(
            "formal proof job does not prime the repository Lean toolchain"
        )
    proof_run = named_step(formal, "Verify formal proof contract").get("run")
    if proof_run != "./scripts/check-formal-proofs.sh":
        raise ContractError("formal proof job omits the exact proof gate")
    if not (
        step_position(formal, "Install Lean 4 toolchain")
        < step_position(formal, "Prime Lean 4 toolchain")
        < step_position(formal, "Verify formal proof contract")
    ):
        raise ContractError(
            "formal proof job reorders toolchain setup and proof execution"
        )

    aggregate = job(ci, "security-contract-required")
    for identifier, context_name in EXPECTED_REQUIRED_CONTEXTS.items():
        if job(ci, identifier).get("name") != context_name:
            raise ContractError(
                f"planned main ruleset context changed: {identifier} must report {context_name}"
            )
    security_contract_jobs = {
        identifier
        for identifier, body in workflow_jobs(ci).items()
        if isinstance(body, dict) and body.get("name") == "Security contract"
    }
    if security_contract_jobs != {"security-contract-required"}:
        raise ContractError(
            "Security contract must be the exact unique aggregate check name"
        )
    needs = aggregate.get("needs")
    if needs != list(REQUIRED_AGGREGATE_NEEDS):
        raise ContractError(
            "security aggregate does not depend on the exact required jobs"
        )
    if aggregate.get("if") != "${{ always() }}":
        raise ContractError(
            "security aggregate is not evaluated after every dependency result"
        )
    aggregate_lines = run_lines(aggregate)
    missing_assertions = REQUIRED_AGGREGATE_ASSERTIONS - aggregate_lines
    if missing_assertions:
        missing_jobs = sorted(
            identifier
            for identifier in REQUIRED_AGGREGATE_NEEDS
            if f"test '${{{{ needs.{identifier}.result }}}}' = success"
            in missing_assertions
        )
        raise ContractError(
            "security aggregate omits exact dependency assertions: "
            + ", ".join(missing_jobs)
        )
    aggregate_step = named_step(aggregate, "Require every security dependency")
    aggregate_run = aggregate_step.get("run")
    if (
        set(aggregate_step) != {"name", "run"}
        or not isinstance(aggregate_run, str)
        or aggregate_run.strip() != EXPECTED_AGGREGATE_RUN
    ):
        raise ContractError("security aggregate changes its exact fail-closed body")

    for identifier in (*REQUIRED_AGGREGATE_NEEDS, "security-contract-required"):
        if contains_key(job(ci, identifier), "continue-on-error"):
            raise ContractError(f"required CI job uses continue-on-error: {identifier}")

    check_job = job(ci, "check")
    ci_validators = named_step(check_job, "Install Python workflow validators")
    if ci_validators.get("run") != EXPECTED_CI_PYTHON_VALIDATORS_RUN:
        raise ContractError("required CI does not install pinned PyYAML")
    check_lines = run_lines(check_job)
    mapping = named_step(check_job, "Formal traceability gate")
    if mapping.get("run") != "bash scripts/check-mapping.sh":
        raise ContractError("required CI omits the exact formal traceability gate")
    if (
        step_position(check_job, "Formal traceability gate")
        != step_position(check_job, "Workspace structural gates") + 1
    ):
        raise ContractError(
            "formal traceability gate is not adjacent to structural gates"
        )
    for command in (
        "cargo build --workspace",
        "cargo test --workspace",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "bash scripts/check-mapping.sh",
        "git diff --check",
    ):
        if command not in check_lines:
            raise ContractError(f"required CI omits exact command: {command}")
    validate_exact_steps(
        check_job,
        EXPECTED_CI_EVIDENCE_STEPS,
        "required CI test and Loom evidence",
        EXPECTED_CI_EVIDENCE_EXTRAS,
    )

    kani = job(ci, "kani-public-pr")
    validate_exact_steps(
        kani,
        (
            ("Verify public Kani harness enrollment", EXPECTED_KANI_ENROLLMENT_RUN),
            ("Verify all PR Kani harnesses", EXPECTED_KANI_MANIFEST_RUN),
        ),
        "Kani PR manifest evidence",
        EXPECTED_KANI_STEP_EXTRAS,
    )

    validate_exact_steps(
        job(ci, "formal-proof-contract"),
        (("Verify formal proof contract", "./scripts/check-formal-proofs.sh"),),
        "formal proof evidence",
    )
    validate_exact_steps(
        job(ci, "msrv"),
        (("MSRV workspace lane", EXPECTED_MSRV_RUN),),
        "MSRV evidence",
        EXPECTED_MSRV_EXTRAS,
    )
    validate_exact_steps(
        job(ci, "cargo-vet"),
        EXPECTED_CARGO_VET_STEPS,
        "cargo-vet evidence",
    )
    validate_exact_steps(
        job(ci, "cargo-deny"),
        EXPECTED_CARGO_DENY_STEPS,
        "cargo-deny evidence",
    )

    audit = job(admin_override, "audit")
    if admin_override.get("on") != EXPECTED_ADMIN_EVENTS:
        raise ContractError("admin override audit changes its closed-PR trigger")
    if admin_override.get("permissions") != EXPECTED_ADMIN_PERMISSIONS:
        raise ContractError(
            "admin override audit lacks its exact read/comment permissions"
        )
    if (
        set(audit) != {"name", "if", "runs-on", "env", "steps"}
        or audit.get("name") != "admin-override-audit"
        or audit.get("if") != EXPECTED_ADMIN_JOB_IF
        or audit.get("runs-on") != "ubuntu-latest"
    ):
        raise ContractError("admin override audit changes its execution contract")
    audit_env = audit.get("env")
    if audit_env != EXPECTED_ADMIN_AUDIT_ENV:
        raise ContractError(
            "admin override audit is not bound to the protected test merge"
        )
    audit_step = named_step(audit, "Audit required checks at protected merge commit")
    audit_steps = audit.get("steps")
    if (
        not isinstance(audit_steps, list)
        or len(audit_steps) != 2
        or audit_steps[0] != EXPECTED_ADMIN_CHECKOUT
    ):
        raise ContractError("admin override audit changes its unconditional checkout")
    audit_run = audit_step.get("run")
    if not isinstance(audit_run, str) or not all(
        required in audit_run
        for required in (
            '"Security mirror / Build, lint, test"',
            '"Security mirror / MSRV build and test"',
            '"Security mirror / cargo-vet (locked supply-chain audit)"',
            '"Security mirror / cargo-deny (supply-chain bans/advisories/licenses)"',
            '"Security contract"',
            "commits/${CHECK_SHA}/check-runs",
        )
    ):
        raise ContractError(
            "admin override audit omits a planned context or merge-commit query"
        )
    if (
        set(audit_step) != {"name", "shell", "run"}
        or audit_step.get("shell") != "bash"
        or audit_run.strip() != EXPECTED_ADMIN_AUDIT_RUN
    ):
        raise ContractError("admin override audit changes its exact merge-commit audit body")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    try:
        validate(args.root.resolve())
    except ContractError as error:
        print(f"security CI contract failed: {error}", file=sys.stderr)
        return 1
    print("security CI contract is closed and unconditional")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
