#!/usr/bin/env python3
"""Fail on oversized hand-maintained Rust modules and malformed generated Rust.

Size is measured on the assembled logical module: a file plus every fragment
it splices in through `include!`, transitively. `include!` creates no module
and therefore no privacy boundary, so a parent and its fragments share one
namespace and one reviewer's working memory, which is what the cap bounds.
A fragment is also measured at its own path, because its lines are real
wherever they land.

`include!` fragments are frozen rather than forbidden. `cargo fmt` follows
`mod` declarations, including `#[path]`, but not `include!`, so a fragment is
invisible to the format gate; and a fragment carries no privacy boundary, so
it buys none of the encapsulation a split is usually reaching for. Every
module that already assembles fragments carries an allowlist entry capping
how many it may have, so the inventory can shrink and cannot grow. New code
uses `mod` with `#[path]`, which keeps both the boundary and the formatter.

An include whose path is not a literal or `concat!(env!("CARGO_MANIFEST_DIR"),
"...")` cannot be resolved from source. Those sites are declared in
`BUILD_GENERATED_INCLUDES` and are the build script's output rather than
hand-maintained code; an undeclared one fails rather than being skipped,
because a gate that silently drops what it cannot read reports green on
whatever it missed.

Allowlist policy: entries are debt, not configuration. Renew only through
`--ratchet`, which re-caps every entry at the module's current size and
fragment count (caps can only shrink), drops entries whose modules came back
under their base limit with no fragments, and advances the expiry one month.
Hand-editing an entry to raise a cap or extend an expiry without shrinking
the module defeats the gate.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import subprocess
import sys


PRODUCTION_LIMIT = 2_000
LIB_ROOT_LIMIT = 1_000
WARN_LIMIT = 1_200
LIB_WARN_LIMIT = 900
TEST_LIMIT = 2_000
SUMMARY_LIMIT = 25
WIRE_GENERATED_PREFIX = "crates/core/chio-core-types/src/_generated/"
GENERATED_HEADER_SOURCE = "crates/tooling/chio-spec-codegen/src/lib.rs"
GENERATED_HEADER_CONST_MARKER = 'pub const GENERATED_HEADER: &str = "\\\n'
ERRORS_GENERATED_PREFIX = "crates/core/chio-errors/src/_generated/"
ERRORS_GENERATED_HEADER_SOURCE = "crates/tooling/chio-spec-codegen/src/errors_pass.rs"
ERRORS_GENERATED_HEADER_CONST_MARKER = 'const ERROR_CODES_GENERATED_HEADER: &str = "\\\n'
STATEMACHINE_GENERATED_PREFIXES = (
    "crates/tooling/chio-conformance/tests/_generated/",
    "crates/trust/chio-federation/src/_generated/",
)
STATEMACHINE_GENERATED_HEADER_SOURCE = (
    "crates/tooling/chio-spec-codegen/src/statemachines_pass.rs"
)
STATEMACHINE_GENERATED_HEADER_CONST_MARKER = (
    'const STATE_MACHINE_GENERATED_HEADER_PREFIX: &str = "\\\n'
)
# Immutable generated files from the checksum-verified regress 0.11.1 archive.
# These retain upstream paths for module resolution. Any byte change requires
# renewed provenance review; a generated header alone cannot excuse a file.
VENDORED_GENERATED_SHA256 = {
    "third_party/regress-chio/src/unicodetables.rs": "c3ec026fcfb6bc607f0002915c824d1792a368ecb5bf489abc0f94aea586d963",
    "third_party/regress-chio/tests/unicode_property_escapes.rs": "84301dee923b2a7822d393bb30cf8a05f9290450cb5380adcee0ca78a03d92c5",
}

TEXT_HYGIENE_PREFIXES = ("crates/", "docs/", "sdks/", "scripts/", "spec/", "xtask/")
TEXT_HYGIENE_SUFFIXES = (".rs", ".md", ".inc")
TEXT_HYGIENE_PATTERNS = ("*.rs", "*.md", "*.inc")
EM_DASH = "\u2014"

SOURCE_PATTERNS = ("*.rs", "*.inc")
MAX_INCLUDE_DEPTH = 64

# Sites whose `include!` argument is a build script's output path. The file is
# generated into OUT_DIR at build time and is not in the tree, so its lines
# cannot be attributed to the including module. Every other non-literal
# include fails.
BUILD_GENERATED_INCLUDES = frozenset(
    {
        "crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs",
        "crates/products/chio-proof-room/src/lib.rs",
        "third_party/nono-upstream-chio/src/manifest.rs",
    }
)


@dataclass(frozen=True)
class AllowlistEntry:
    rationale: str
    expires: str
    max_lines: int | None = None
    max_fragments: int | None = None


def allow(
    expires: str,
    rationale: str,
    *,
    max_lines: int | None = None,
    max_fragments: int | None = None,
) -> AllowlistEntry:
    return AllowlistEntry(
        rationale=rationale,
        expires=expires,
        max_lines=max_lines,
        max_fragments=max_fragments,
    )


ALLOWLIST_WAVES = 4

# Entries expire in four waves rather than on one day. A single shared date
# meant the gate would refuse 84 files at once, which is not a deadline
# anyone can act on: the only available response is to move the date again.
# The waves are ordered by cap, smallest first, so the files that are
# cheapest to bring back under their limit come due first.
ALLOWLIST: dict[str, AllowlistEntry] = {
    "third_party/aws-lc-rs-chio/src/cipher.rs": allow(
        "2026-11-30",
        "reviewed upstream AWS-LC cipher surface; capped to exact vendored size until split upstream",
        max_lines=2_266,
    ),
    "crates/products/chio-cli/tests/mcp_serve_http.rs": allow(
        "2027-01-31",
        "existing oversized CLI MCP HTTP integration suite; capped to current size until split",
        max_lines=6_102,
    ),
    "crates/products/chio-cli/tests/passport.rs": allow(
        "2027-01-31",
        "existing oversized CLI passport integration suite; capped to current size until split",
        max_lines=5_395,
    ),
    "crates/products/chio-cli/tests/mcp_serve.rs": allow(
        "2027-01-31",
        "existing oversized CLI MCP serve integration suite; capped to current size until split",
        max_lines=4_175,
    ),
    "crates/protocol/chio-mcp-edge/src/runtime/runtime_tests.rs": allow(
        "2027-01-31",
        "existing oversized MCP edge runtime test suite; capped to current size until split",
        max_lines=4_512,
    ),
    "crates/products/chio-cli/tests/certify.rs": allow(
        "2026-12-31",
        "existing oversized CLI certify integration suite; capped to current size until split",
        max_lines=3_645,
    ),
    "crates/products/chio-cli/src/cli/dispatch/proof/fixture.rs": allow(
        "2027-01-31",
        "launch proof fixture dispatch surface; capped to current size until split",
        max_lines=6_320,
    ),
    "crates/products/chio-cli/src/cli/dispatch/proof.rs": allow(
        "2026-12-31",
        "proof dispatch with ClaimSet-routed family verification; capped to current size until split",
        max_lines=3_484,
    ),
    "crates/products/chio-mercury/tests/cli.rs": allow(
        "2026-12-31",
        "existing oversized Mercury CLI integration suite; capped to current size until split",
        max_lines=3_183,
    ),
    "crates/products/chio-cli/tests/trust_cluster.rs": allow(
        "2026-12-31",
        "existing oversized CLI trust-cluster integration suite with signed delegation and same-second revocation coverage; capped to current size until split",
        max_lines=3_272,
    ),
    "crates/products/chio-api-protect/src/proxy/tests.rs": allow(
        "2026-12-31",
        "existing oversized API protect proxy test suite; capped to current size until split",
        max_lines=3_456,
    ),
    "crates/products/chio-cli/tests/proof_cli_contract/support.rs": allow(
        "2026-12-31",
        "launch proof CLI contract support module; capped to current size until split",
        max_lines=3_896,
    ),
    "crates/products/chio-cli/tests/proof_verify.rs": allow(
        "2026-12-31",
        "launch proof verifier integration suite; capped to current size until split",
        max_lines=3_094,
    ),
    "crates/platform/chio-enterprise-export/tests/enterprise_export.rs": allow(
        "2026-12-31",
        "launch enterprise export integration suite; capped to current size until split",
        max_lines=2_724,
    ),
    "crates/products/chio-cli/tests/federated_issue.rs": allow(
        "2026-11-30",
        "existing oversized CLI federated issue integration suite; capped to current size until split",
        max_lines=2_271,
    ),
    "crates/core/chio-core-types/src/capability/tests.rs": allow(
        "2026-12-31",
        "existing oversized capability type test suite; capped to current size until split; covers time-checked verification, attenuation narrowing, and wildcard/concrete reflection regressions",
        max_lines=3_163,
    ),
    "crates/kernel/chio-runtime-core/tests/runtime_buyer_review.rs": allow(
        "2026-10-31",
        "existing oversized runtime buyer review integration suite; capped to current size until split",
        max_lines=2_068,
    ),
    "crates/kernel/chio-runtime-core/tests/runtime_admission.rs": allow(
        "2026-12-31",
        "runtime admission integration suite; capped to current size after swarm authority split",
        max_lines=3_673,
        max_fragments=1,
    ),
    "crates/platform/chio-transaction-passport/tests/transaction_passport.rs": allow(
        "2026-12-31",
        "transaction passport integration suite with runtime-security and transparency-anchor review regressions; capped until split",
        max_lines=2_789,
    ),
    "crates/platform/chio-transaction-passport/tests/cognition_market.rs": allow(
        "2026-11-30",
        "cognition-market transaction passport regression suite; capped to current size until split",
        max_lines=2_655,
        max_fragments=2,
    ),
    "crates/trust/chio-selective-disclosure/src/lib.rs": allow(
        "2026-10-31",
        "launch selective disclosure verifier surface; capped to current size until split",
        max_lines=1_346,
    ),
    "crates/platform/chio-risk-comptroller/src/lib.rs": allow(
        "2026-10-31",
        "launch risk comptroller verifier surface; capped to current size until split",
        max_lines=1_356,
    ),
    "crates/economy/chio-web3/src/tests.rs": allow(
        "2026-12-31",
        "web3 test module with public-settlement review regressions; capped until split",
        max_lines=2_697,
    ),
    "crates/kernel/chio-runtime-proof-parity/src/lib.rs": allow(
        "2026-10-31",
        "runtime proof parity surface; capped to current size until split",
        max_lines=1_058,
    ),
    "crates/kernel/chio-swarm-authority/src/verifier.rs": allow(
        "2026-10-31",
        "swarm authority verifier surface; capped to current size until split",
        max_lines=2_004,
    ),
    "crates/platform/chio-transaction-passport/src/runtime_security/artifacts.rs": allow(
        "2026-11-30",
        "runtime security artifact verifier with trusted join and overflow hardening; capped until split",
        max_lines=2_322,
    ),
    "crates/products/chio-cli/tests/proof_cli_contract/fixture.rs": allow(
        "2026-11-30",
        "launch proof CLI fixture contract suite; capped to current size until split",
        max_lines=2_210,
    ),
    "crates/products/chio-cli/tests/proof_verify/support.rs": allow(
        "2026-11-30",
        "launch proof verifier support module; capped to current size until split",
        max_lines=2_231,
    ),
    "crates/products/chio-proof-room/src/lib.rs": allow(
        "2026-10-31",
        "Proof Room product surface; capped to current size until split",
        max_lines=1_196,
    ),
    "crates/economy/chio-settle/src/evm/tests.rs": allow(
        "2026-11-30",
        "EVM settlement unit test module with anchor content-hash regression coverage; capped until split",
        max_lines=2_380,
    ),
    "crates/products/chio-cli/src/cli/chio/dispatch/pheromone/iroh_mount.rs": allow(
        "2026-12-31",
        "pheromone iroh mount dispatch surface; capped to current size until split",
        max_lines=3_375,
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store.rs": allow(
        "2027-01-31",
        "receipt store hot-path module with anchored receipt, lineage metadata, checkpoint, and retention writes plus qualified read verification; capped to current size until split",
        max_lines=5_630,
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store/tests/retention.rs": allow(
        "2027-01-31",
        "receipt retention regression suite; capped to current size until split",
        max_lines=4_581,
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store/tests/verified_head.rs": allow(
        "2026-10-31",
        "receipt verified-head regression suite with live qualified rollback coverage; capped to current size until split",
        max_lines=2_048,
    ),
    "crates/trust/chio-federation-transport-iroh/src/lanes/pheromone.rs": allow(
        "2026-12-31",
        "iroh pheromone lane; capped to current size until split",
        max_lines=2_818,
    ),
    "crates/platform/chio-control-plane/src/trust_control/cluster_and_reports.rs": allow(
        "2026-12-31",
        "trust-control cluster and reports surface with mixed-version revocation cursor coverage; capped to current size until split",
        max_lines=2_696,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/tests.rs": allow(
        "2026-11-30",
        "existing oversized budget store test suite; capped to current size until split",
        max_lines=2_479,
    ),
    "crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs": allow(
        "2026-11-30",
        "iroh revocation lane; capped to current size until split",
        max_lines=2_511,
    ),
    "crates/trust/chio-federation-transport-iroh/src/lanes/fanout.rs": allow(
        "2026-11-30",
        "iroh fanout lane; capped to current size until split",
        max_lines=2_443,
    ),
    "crates/economy/chio-web3/src/settlement_proof.rs": allow(
        "2026-10-31",
        "web3 settlement proof surface; capped to current size until split",
        max_lines=2_053,
    ),
    "crates/products/chio-wall/src/commands.rs": allow(
        "2026-10-31",
        "wall command surface; capped to current size until split",
        max_lines=2_048,
    ),
    "crates/platform/chio-http-session/src/lib.rs": allow(
        "2026-10-31",
        "shared HTTP session crate root; capped to current size until split",
        max_lines=1_103,
    ),
    "crates/economy/chio-credit/src/obligation/credit_admission.rs": allow(
        "2026-10-31",
        "authoritative credit admission surface; capped to current size until split",
        max_lines=2_042,
    ),
    "crates/economy/chio-market/src/tests.rs": allow(
        "2026-11-30",
        "market admission and quote test suite; capped to current size until split",
        max_lines=2_387,
    ),
    "crates/economy/chio-open-market/tests/finding_admission.rs": allow(
        "2026-12-31",
        "cognition-market admission regression suite; capped to current size until split",
        max_lines=3_023,
        max_fragments=4,
    ),
    "crates/economy/chio-settle/src/channel/tests/support.rs": allow(
        "2026-10-31",
        "settlement channel test support module; capped to current size until split",
        max_lines=2_030,
    ),
    "crates/kernel/chio-kernel/src/admission_operation_tests.rs": allow(
        "2026-11-30",
        "durable admission operation regression suite with authoritative outcome binding coverage; capped to current size until split",
        max_lines=2_356,
    ),
    "crates/kernel/chio-kernel/src/admission_operation/projection.rs": allow(
        "2026-10-31",
        "durable admission projection surface with current-status denial binding; capped to current size until split",
        max_lines=2_096,
    ),
    "crates/kernel/chio-kernel/src/kernel/validation.rs": allow(
        "2026-12-31",
        "kernel capability and admission validation surface; capped to current size until split",
        max_lines=2_747,
    ),
    "crates/platform/chio-control-plane/src/trust_control/capital_and_liability/liability.rs": allow(
        "2026-11-30",
        "capital liability control surface; capped to current size until split",
        max_lines=2_166,
    ),
    "crates/platform/chio-control-plane/src/trust_control/finding_handlers.rs": allow(
        "2026-11-30",
        "cognition finding handler surface with authenticated status-operator standing and live service-bond renewal; capped to current size until split",
        max_lines=2_426,
    ),
    "crates/economy/chio-finding/tests/challenge_families.rs": allow(
        "2026-11-30",
        "cognition challenge artifact and schema regression suite; capped to current size until split",
        max_lines=2_277,
    ),
    "crates/trust/chio-finding-verifier/tests/verifier.rs": allow(
        "2026-11-30",
        "cognition finding verifier regression suite with authority standing and evidence-role separation coverage; capped until split",
        max_lines=2_219,
    ),
    "crates/trust/chio-finding-verifier/src/verify.rs": allow(
        "2026-10-31",
        "cognition finding verifier with current authority standing and terminal-receipt-checkpoint role separation; capped to current size until split",
        max_lines=2_107,
    ),
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_challenge_enforcement_e2e_tests.rs": allow(
        "2027-01-31",
        "cognition challenge enforcement end-to-end regression suite with unavailable-status, authority-rotation, and bounded admission coverage; capped to current size until split",
        max_lines=8_088,
        max_fragments=1,
    ),
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_market_exit_tests.rs": allow(
        "2026-12-31",
        "cognition market exit regression suite with status-gated activation, admission-view, and replay coverage; capped to current size until split",
        max_lines=3_609,
        max_fragments=2,
    ),
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_wedge_purchase_e2e_tests.rs": allow(
        "2027-01-31",
        "cognition purchase and recovery end-to-end regression suite with bounded buyer admission and durable replay coverage; capped to current size until split",
        max_lines=7_576,
        max_fragments=3,
    ),
    "crates/platform/chio-store-sqlite/src/admission_operation_store/factor_assignment.rs": allow(
        "2026-11-30",
        "admission factor assignment store surface; capped to current size until split",
        max_lines=2_211,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/composite_schema.rs": allow(
        "2026-10-31",
        "durable composite budget schema and migration surface; capped to current size until split",
        max_lines=2_104,
    ),
    "crates/platform/chio-store-sqlite/src/finding_market_store.rs": allow(
        "2026-11-30",
        "cognition finding market authority store with atomic status and sales-blocked participation fences; capped to current size until split",
        max_lines=2_328,
    ),
    "crates/platform/chio-store-sqlite/src/finding_challenge_store_tests.rs": allow(
        "2027-01-31",
        "cognition challenge authority store regression suite; capped to current size until split",
        max_lines=4_760,
        max_fragments=2,
    ),
    "crates/trust/chio-finding-challenge/tests/support/mod.rs": allow(
        "2026-11-30",
        "cognition challenge authenticated standing fixtures; capped to current size until split",
        max_lines=2_142,
    ),
    "crates/platform/chio-store-sqlite/src/finding_purchase_store.rs": allow(
        "2026-12-31",
        "cognition purchase and recovery authority store with atomic finding-status and sales-block reservation gates; capped until split",
        max_lines=3_385,
    ),
    "crates/platform/chio-store-sqlite/src/finding_purchase_store_tests.rs": allow(
        "2026-12-31",
        "cognition purchase authority store regression suite split for sales-block coverage; capped to current size until split",
        max_lines=3_161,
    ),
    "crates/platform/chio-store-sqlite/src/fiscal_store.rs": allow(
        "2026-12-31",
        "fiscal persistence surface; capped to current size until split",
        max_lines=2_937,
    ),
    "crates/platform/chio-store-sqlite/src/receipt_store/tests/support.rs": allow(
        "2026-10-31",
        "receipt store test support module; capped to current size until split",
        max_lines=2_056,
    ),
    "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs": allow(
        "2026-12-31",
        "serving-owner commit chain persistence surface; capped to current size until split",
        max_lines=2_851,
    ),
    "crates/products/chio-cli/src/cli/dispatch/finding/unit_tests.rs": allow(
        "2026-11-30",
        "cognition-market CLI regression suite with status trust-input migration coverage; capped to current size until split",
        max_lines=2_175,
    ),
    "crates/platform/chio-store-sqlite/src/serving_owner/tests.rs": allow(
        "2026-11-30",
        "serving-owner provisioning test suite with sequenced revocation stream coverage; capped to current size until split",
        max_lines=2_281,
    ),
    "crates/kernel/chio-kernel/src/kernel/tests.rs": allow(
        "2027-01-31",
        "kernel test suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=40_754,
        max_fragments=48,
    ),
    "crates/platform/chio-control-plane/src/security/adapters.rs": allow(
        "2027-01-31",
        "control-plane security adapter surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=13_956,
        max_fragments=40,
    ),
    "crates/platform/chio-store-sqlite/src/security_state.rs": allow(
        "2027-01-31",
        "SQLite security-state store assembled from include! fragments; capped until the fragments become modules",
        max_lines=13_473,
        max_fragments=13,
    ),
    "crates/protocol/chio-acp-proxy/src/lib.rs": allow(
        "2027-01-31",
        "ACP proxy surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=12_263,
        max_fragments=33,
    ),
    "crates/protocol/chio-a2a-adapter/src/lib.rs": allow(
        "2027-01-31",
        "A2A adapter surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=12_016,
        max_fragments=18,
    ),
    "crates/trust/chio-credentials/src/lib.rs": allow(
        "2027-01-31",
        "credentials surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=10_253,
        max_fragments=15,
    ),
    "crates/platform/chio-control-plane/src/security/event_consumer.rs": allow(
        "2027-01-31",
        "security event consumer assembled from include! fragments; capped until the fragments become modules",
        max_lines=9_412,
        max_fragments=8,
    ),
    "crates/security/chio-secret-broker/src/service.rs": allow(
        "2027-01-31",
        "secret broker service assembled from include! fragments; capped until the fragments become modules",
        max_lines=9_371,
        max_fragments=16,
    ),
    "crates/protocol/chio-mcp-remote/src/lib.rs": allow(
        "2027-01-31",
        "MCP remote surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=7_716,
        max_fragments=9,
    ),
    "crates/platform/chio-control-plane/src/trust_control/finding_challenge_coordinator.rs": allow(
        "2027-01-31",
        "finding challenge coordinator assembled from include! fragments; capped until the fragments become modules",
        max_lines=7_173,
        max_fragments=14,
    ),
    "xtask/src/fixtures.rs": allow(
        "2027-01-31",
        "xtask fixture handlers assembled from include! fragments; capped until the fragments become modules",
        max_lines=7_153,
        max_fragments=6,
    ),
    "crates/protocol/chio-acp-edge/src/lib.rs": allow(
        "2027-01-31",
        "ACP edge surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=6_101,
        max_fragments=11,
    ),
    "crates/platform/chio-store-sqlite/src/finding_challenge_store.rs": allow(
        "2027-01-31",
        "finding challenge store assembled from include! fragments; capped until the fragments become modules",
        max_lines=6_031,
        max_fragments=12,
    ),
    "crates/protocol/chio-a2a-edge/src/lib.rs": allow(
        "2027-01-31",
        "A2A edge surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=5_913,
        max_fragments=11,
    ),
    "crates/platform/chio-control-plane/src/security/adapters/effect_port.rs": allow(
        "2027-01-31",
        "security effect port adapter assembled from include! fragments; capped until the fragments become modules",
        max_lines=5_061,
        max_fragments=4,
    ),
    "crates/security/chio-security-types/src/ports.rs": allow(
        "2027-01-31",
        "security port surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=5_033,
        max_fragments=4,
    ),
    "crates/platform/chio-control-plane/src/security/scheduler_worker.rs": allow(
        "2027-01-31",
        "response scheduler worker assembled from include! fragments; capped until the fragments become modules",
        max_lines=5_004,
        max_fragments=4,
    ),
    "crates/kernel/chio-kernel/src/budget_store/in_memory.rs": allow(
        "2027-01-31",
        "in-memory budget store assembled from include! fragments; capped until the fragments become modules",
        max_lines=4_064,
        max_fragments=4,
    ),
    "crates/platform/chio-store-sqlite/src/finding_status_store.rs": allow(
        "2027-01-31",
        "finding status store assembled from include! fragments; capped until the fragments become modules",
        max_lines=4_015,
        max_fragments=1,
    ),
    "crates/security/chio-cage/src/launch/linux.rs": allow(
        "2027-01-31",
        "cage Linux launch path assembled from include! fragments; capped until the fragments become modules",
        max_lines=3_946,
        max_fragments=4,
    ),
    "crates/kernel/chio-kernel/src/security_admission_operation.rs": allow(
        "2026-12-31",
        "kernel security admission operation assembled from include! fragments; capped until the fragments become modules",
        max_lines=3_612,
        max_fragments=3,
    ),
    "crates/platform/chio-store-sqlite/tests/security_state_contract.rs": allow(
        "2026-12-31",
        "security-state store contract suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=3_596,
        max_fragments=2,
    ),
    "crates/protocol/chio-mcp-adapter/src/transport/stdio.rs": allow(
        "2026-12-31",
        "MCP stdio transport assembled from include! fragments; capped until the fragments become modules",
        max_lines=3_211,
        max_fragments=2,
    ),
    "crates/guards/chio-policy/src/evaluate.rs": allow(
        "2026-12-31",
        "policy evaluation surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=3_170,
        max_fragments=5,
    ),
    "third_party/regress-chio/tests/unicodesets.rs": allow(
        "2026-12-31",
        "vendored regress unicode-set suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=3_161,
        max_fragments=2,
    ),
    "crates/core/chio-core-types/src/receipt/security.rs": allow(
        "2026-12-31",
        "security receipt projection assembled from include! fragments; capped until the fragments become modules",
        max_lines=3_157,
        max_fragments=2,
    ),
    "crates/platform/chio-control-plane/src/security/active_response.rs": allow(
        "2026-12-31",
        "control-plane active response surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_976,
        max_fragments=2,
    ),
    "crates/platform/chio-store-sqlite/tests/security_state.rs": allow(
        "2026-12-31",
        "security-state store suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_931,
        max_fragments=2,
    ),
    "crates/platform/chio-store-sqlite/tests/response_dispatch.rs": allow(
        "2026-12-31",
        "response dispatch store suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_833,
        max_fragments=1,
    ),
    "crates/security/chio-cage/src/lib.rs": allow(
        "2026-11-30",
        "cage crate surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_438,
        max_fragments=2,
    ),
    "crates/platform/chio-control-plane/src/security/orchestration.rs": allow(
        "2026-11-30",
        "security orchestration surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_380,
        max_fragments=1,
    ),
    "third_party/regress-chio/tests/tests.rs": allow(
        "2026-11-30",
        "vendored regress case suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_376,
        max_fragments=2,
    ),
    "crates/platform/chio-store-sqlite/src/security_admission_operation_store.rs": allow(
        "2026-11-30",
        "SQLite admission-operation store assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_373,
        max_fragments=2,
    ),
    "crates/security/chio-keyring/src/sqlite.rs": allow(
        "2026-11-30",
        "keyring SQLite store assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_270,
        max_fragments=2,
    ),
    "crates/kernel/chio-kernel/src/kernel/active_response_coordinator.rs": allow(
        "2026-11-30",
        "kernel active response coordinator assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_212,
        max_fragments=1,
    ),
    "crates/security/chio-quarantine/src/executor.rs": allow(
        "2026-11-30",
        "quarantine executor assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_191,
        max_fragments=1,
    ),
    "crates/kernel/chio-kernel/src/kernel/tests/support_monetary_durability.rs": allow(
        "2026-11-30",
        "kernel monetary durability test support assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_162,
        max_fragments=1,
    ),
    "crates/security/chio-quarantine/src/state_machine.rs": allow(
        "2026-11-30",
        "quarantine state machine assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_151,
        max_fragments=1,
    ),
    "crates/platform/chio-agent-web-interop/tests/agent_web_interop/core_tests.rs": allow(
        "2026-11-30",
        "agent-web interop core suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_143,
        max_fragments=1,
    ),
    "crates/tooling/chio-conformance/tests/active_defense.rs": allow(
        "2026-10-31",
        "active-defense conformance suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_103,
        max_fragments=2,
    ),
    "crates/security/chio-quarantine/tests/state_machine.rs": allow(
        "2026-10-31",
        "quarantine state machine suite assembled from include! fragments; capped until the fragments become modules",
        max_lines=2_023,
        max_fragments=1,
    ),
    "crates/kernel/chio-kernel/src/budget_store.rs": allow(
        "2026-10-31",
        "budget store surface assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "crates/protocol/chio-cross-protocol/src/tests.rs": allow(
        "2026-10-31",
        "cross-protocol test suite assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "crates/trust/chio-reputation/src/lib.rs": allow(
        "2026-10-31",
        "reputation surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=1_718,
        max_fragments=5,
    ),
    "crates/platform/chio-agent-web-interop/src/lib.rs": allow(
        "2026-10-31",
        "agent-web interop surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=1_480,
        max_fragments=1,
    ),
    "crates/platform/chio-manifest/src/lib.rs": allow(
        "2026-10-31",
        "manifest surface assembled from include! fragments; capped until the fragments become modules",
        max_lines=1_392,
        max_fragments=1,
    ),
    "crates/economy/chio-credit/src/lib.rs": allow(
        "2026-10-31",
        "credit surface assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "formal/rust-verification/creusot-core/src/lib.rs": allow(
        "2026-10-31",
        "Creusot core verification surface assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "crates/platform/chio-store-sqlite/src/budget_store/composite/caller_resume_tests.rs": allow(
        "2026-10-31",
        "composite budget caller-resume suite assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "crates/protocol/chio-mcp-edge/src/runtime/runtime_tests/authorization.rs": allow(
        "2026-10-31",
        "MCP edge runtime authorization suite assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "crates/kernel/chio-kernel/tests/durable_admission_sqlite/federation_context.rs": allow(
        "2026-10-31",
        "durable admission federation context assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "crates/products/chio-cli/src/bin/chio.rs": allow(
        "2026-10-31",
        "CLI binary entry point assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "crates/products/chio-cli/build.rs": allow(
        "2026-10-31",
        "CLI proof fixture build script assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
    "crates/products/chio-proof-room/build.rs": allow(
        "2026-10-31",
        "proof room fixture build script assembled from include! fragments; capped until the fragments become modules",
        max_fragments=1,
    ),
}


@dataclass(frozen=True)
class RustModule:
    """A file and everything `include!` splices into it, measured as one unit."""

    path: str
    lines: int
    own_lines: int
    fragments: tuple[str, ...]
    category: str
    violations: tuple[str, ...]
    allowlist: AllowlistEntry | None


@dataclass(frozen=True)
class GeneratedHeaderSpec:
    prefix: str
    source: str
    const_marker: str
    label: str


GENERATED_HEADER_SPECS = (
    GeneratedHeaderSpec(
        prefix=WIRE_GENERATED_PREFIX,
        source=GENERATED_HEADER_SOURCE,
        const_marker=GENERATED_HEADER_CONST_MARKER,
        label="chio_spec_codegen::GENERATED_HEADER",
    ),
    GeneratedHeaderSpec(
        prefix=ERRORS_GENERATED_PREFIX,
        source=ERRORS_GENERATED_HEADER_SOURCE,
        const_marker=ERRORS_GENERATED_HEADER_CONST_MARKER,
        label="chio_spec_codegen::errors_pass::ERROR_CODES_GENERATED_HEADER",
    ),
    *(
        GeneratedHeaderSpec(
            prefix=prefix,
            source=STATEMACHINE_GENERATED_HEADER_SOURCE,
            const_marker=STATEMACHINE_GENERATED_HEADER_CONST_MARKER,
            label="chio_spec_codegen::statemachines_pass::STATE_MACHINE_GENERATED_HEADER_PREFIX",
        )
        for prefix in STATEMACHINE_GENERATED_PREFIXES
    ),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def discover_rust_files(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            *SOURCE_PATTERNS,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [
        line
        for line in result.stdout.splitlines()
        if line and (root / line).is_file()
    ]


def discover_text_hygiene_files(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            *TEXT_HYGIENE_PATTERNS,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [
        line
        for line in result.stdout.splitlines()
        if line
        and (root / line).is_file()
        and line.startswith(TEXT_HYGIENE_PREFIXES)
        and line.endswith(TEXT_HYGIENE_SUFFIXES)
        and "/_generated/" not in f"/{line}/"
    ]


# Rust comments and literals are blanked before the token scan so an `include!`
# written inside a doc comment or a test fixture string is not mistaken for a
# real one. Offsets and newlines are preserved so reported line numbers stay
# true.
RUST_NOISE = re.compile(
    r"""
      //[^\n]*                         # line comment
    | /\*                              # block comment; nesting handled below
    | (?:b|c)?r(\#*)"                  # raw string opener, hashes captured
    | (?:b|c)?"(?:[^"\\]|(?s:\\.))*"  # string, including \<newline> continuation
    | b?'(?:(?s:\\.)|[^\\'])'         # char literal, never a lifetime
    """,
    re.VERBOSE,
)
INCLUDE_CALL = re.compile(r"\b(?:core::|std::)?include\s*!\s*\(")
# The same call anchored to the start of a line. Every real include in the tree
# is written this way, so a line-anchored hit the blanked scan did not also find
# is either a commented-out include or a blanking defect. Both fail: the second
# would mean the gate is silently reading past code it should have measured.
INCLUDE_CALL_ANCHORED = re.compile(r"^[ \t]*(?:core::|std::)?include\s*!\s*\(", re.M)
INCLUDE_LITERAL = re.compile(r'\A\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\Z')
INCLUDE_FROM_MANIFEST_DIR = re.compile(
    r'\A\s*concat!\s*\(\s*env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*,?\s*\)\s*,'
    r'\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\)\s*,?\s*\Z',
    re.S,
)


def blank_rust_noise(text: str) -> str:
    def blanked(span: str) -> str:
        return "".join("\n" if char == "\n" else " " for char in span)

    chunks: list[str] = []
    position = 0
    while True:
        match = RUST_NOISE.search(text, position)
        if match is None:
            chunks.append(text[position:])
            return "".join(chunks)
        chunks.append(text[position : match.start()])
        if match.group(0) == "/*":
            end = match.end()
            depth = 1
            while depth and end < len(text):
                opened = text.find("/*", end)
                closed = text.find("*/", end)
                if closed == -1:
                    end = len(text)
                    break
                if opened != -1 and opened < closed:
                    depth += 1
                    end = opened + 2
                else:
                    depth -= 1
                    end = closed + 2
            chunks.append(blanked(text[match.start() : end]))
            position = end
            continue
        if match.group(1) is not None:
            terminator = '"' + match.group(1)
            end = text.find(terminator, match.end())
            end = len(text) if end == -1 else end + len(terminator)
            chunks.append(blanked(text[match.start() : end]))
            position = end
            continue
        chunks.append(blanked(match.group(0)))
        position = match.end()


def include_arguments(text: str) -> tuple[list[tuple[int, str]], list[int]]:
    """Every `include!` argument in the file, plus lines the blanking lost."""
    blanked = blank_rust_noise(text)
    arguments: list[tuple[int, str]] = []
    scanned: set[int] = set()
    for match in INCLUDE_CALL.finditer(blanked):
        depth = 1
        cursor = match.end()
        while cursor < len(blanked) and depth:
            if blanked[cursor] == "(":
                depth += 1
            elif blanked[cursor] == ")":
                depth -= 1
            cursor += 1
        line = blanked.count("\n", 0, match.start()) + 1
        scanned.add(line)
        arguments.append((line, text[match.end() : cursor - 1]))
    unscanned = [
        text.count("\n", 0, match.start()) + 1
        for match in INCLUDE_CALL_ANCHORED.finditer(text)
        if text.count("\n", 0, match.start()) + 1 not in scanned
    ]
    return arguments, unscanned


def crate_manifest_dir(root: Path, path: str) -> Path | None:
    directory = (root / path).parent
    while directory != root:
        if (directory / "Cargo.toml").is_file():
            return directory
        directory = directory.parent
    return None


def resolve_include(
    root: Path, path: str, line: int, argument: str
) -> tuple[str | None, str | None]:
    """The included path relative to the root, or the reason it is unreadable."""
    literal = INCLUDE_LITERAL.match(argument)
    if literal is not None:
        base = (root / path).parent
        target = literal.group(1)
    else:
        from_manifest = INCLUDE_FROM_MANIFEST_DIR.match(argument)
        if from_manifest is None:
            if path in BUILD_GENERATED_INCLUDES:
                return None, None
            return None, (
                f"{path}:{line}: include! path is not a literal and not declared "
                "as build script output"
            )
        base = crate_manifest_dir(root, path)
        if base is None:
            return None, f"{path}:{line}: include! is outside any Cargo package"
        target = from_manifest.group(1).lstrip("/")
    resolved = (base / target).resolve()
    try:
        relative = resolved.relative_to(root.resolve())
    except ValueError:
        return None, f"{path}:{line}: include! path leaves the repository"
    relative = str(relative)
    if not (root / relative).is_file():
        return None, f"{path}:{line}: include! target {relative} does not exist"
    return relative, None


def build_include_graph(
    root: Path, paths: list[str], failures: list[str]
) -> dict[str, tuple[str, ...]]:
    graph: dict[str, tuple[str, ...]] = {}
    declared: set[str] = set()
    for path in sorted(paths):
        data = (root / path).read_bytes()
        if b"include" not in data:
            graph[path] = ()
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as err:
            failures.append(f"{path}: could not decode Rust source: {err}")
            graph[path] = ()
            continue
        arguments, unscanned = include_arguments(text)
        for line in unscanned:
            failures.append(
                f"{path}:{line}: include! was not readable by the source scan"
            )
        included: list[str] = []
        for line, argument in arguments:
            target, reason = resolve_include(root, path, line, argument)
            if reason is not None:
                failures.append(reason)
                continue
            if target is None:
                declared.add(path)
                continue
            included.append(target)
        graph[path] = tuple(included)
    for path in sorted(BUILD_GENERATED_INCLUDES - declared):
        if path in graph:
            failures.append(
                f"{path}: declared as including build script output but no longer does"
            )
    return graph


def fragment_paths(graph: dict[str, tuple[str, ...]]) -> set[str]:
    """Files spliced into another file. A fragment is not a module of its own."""
    return {target for targets in graph.values() for target in targets}


def assemble(path: str, graph: dict[str, tuple[str, ...]]) -> list[str]:
    """Every fragment `include!` reaches from a module, transitively."""
    reached: list[str] = []
    seen = {path}
    stack = [path]
    while stack:
        for target in graph.get(stack.pop(), ()):
            if target in seen:
                continue
            seen.add(target)
            reached.append(target)
            stack.append(target)
    return reached


def report_include_cycles(graph: dict[str, tuple[str, ...]], failures: list[str]) -> None:
    """A cycle splices a file into itself, so no module has a finite size."""
    settled: set[str] = set()
    for origin in sorted(graph):
        if origin in settled:
            continue
        path: list[str] = []
        on_path: set[str] = set()
        stack: list[tuple[str, int]] = [(origin, 0)]
        while stack:
            node, index = stack.pop()
            if index == 0:
                if node in settled:
                    continue
                if node in on_path:
                    cycle = path[path.index(node) :] + [node]
                    failures.append(f"include! cycle: {' -> '.join(cycle)}")
                    settled.update(cycle)
                    continue
                if len(path) >= MAX_INCLUDE_DEPTH:
                    failures.append(f"include! nesting deeper than {MAX_INCLUDE_DEPTH} at {node}")
                    settled.add(node)
                    continue
                path.append(node)
                on_path.add(node)
            targets = graph.get(node, ())
            if index < len(targets):
                stack.append((node, index + 1))
                stack.append((targets[index], 0))
                continue
            path.pop()
            on_path.discard(node)
            settled.add(node)


def line_count(path: Path) -> int:
    data = path.read_bytes()
    return data.count(b"\n")


def load_generated_header(root: Path, spec: GeneratedHeaderSpec) -> str | None:
    source = root / spec.source
    if not source.exists():
        return None
    text = source.read_text()
    start = text.find(spec.const_marker)
    if start == -1:
        return None
    start += len(spec.const_marker)
    end = text.find('";', start)
    if end == -1:
        return None
    return text[start:end]


def classify(path: str) -> str:
    parts = path.split("/")
    name = parts[-1]
    if path in VENDORED_GENERATED_SHA256 or "/_generated/" in f"/{path}/":
        return "generated"
    if path.startswith("examples/") or "/examples/" in f"/{path}/":
        return "example"
    if (
        path.startswith("tests/")
        or "/tests/" in f"/{path}/"
        or name == "tests.rs"
        or name.endswith("_tests.rs")
        or name.endswith("_test.rs")
        or name.endswith("_tests_support.rs")
        or name.endswith("_test_support.rs")
    ):
        return "test"
    return "production"


def is_lib_root(path: str) -> bool:
    return path.endswith("/src/lib.rs")


def validate_allowlist(errors: list[str]) -> None:
    for path, entry in sorted(ALLOWLIST.items()):
        if not entry.rationale.strip():
            errors.append(f"{path}: allowlist entry has an empty rationale")
        if not entry.expires.strip():
            errors.append(f"{path}: allowlist entry has an empty expiry date")
            continue
        try:
            expires_on = date.fromisoformat(entry.expires)
        except ValueError:
            errors.append(
                f"{path}: allowlist entry expiry {entry.expires!r} is not an ISO date"
            )
            continue
        if expires_on < date.today():
            errors.append(f"{path}: allowlist entry expired on {entry.expires}")
        if entry.max_lines is not None and entry.max_lines <= 0:
            errors.append(f"{path}: allowlist entry has a non-positive max_lines cap")
        if entry.max_fragments is not None and entry.max_fragments <= 0:
            errors.append(
                f"{path}: allowlist entry has a non-positive max_fragments cap"
            )


def validate_generated_headers(
    root: Path,
    paths: list[str],
    failures: list[str],
) -> None:
    generated_paths = [path for path in paths if classify(path) == "generated"]
    if not generated_paths:
        return
    covered_paths: set[str] = set()
    for spec in GENERATED_HEADER_SPECS:
        spec_paths = [
            path
            for path in generated_paths
            if path.startswith(spec.prefix) and path.endswith(".rs")
        ]
        if not spec_paths:
            continue
        header = load_generated_header(root, spec)
        if header is None:
            failures.append(f"{spec.source}: could not read {spec.label}")
            continue
        for path in spec_paths:
            covered_paths.add(path)
            try:
                body = (root / path).read_text()
            except OSError as err:
                failures.append(f"{path}: could not read generated Rust file: {err}")
                continue
            if not body.startswith(header):
                failures.append(
                    f"{path}: generated Rust file does not begin with {spec.label}"
                )

    for path in generated_paths:
        expected = VENDORED_GENERATED_SHA256.get(path)
        if expected is not None:
            covered_paths.add(path)
            raw = (root / path).read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                failures.append(f"{path}: vendored generated source differs from reviewed archive")
        if path not in covered_paths:
            failures.append(
                f"{path}: generated Rust path is not covered by a known generator header check"
            )


def validate_rust_example_packages(
    root: Path,
    paths: list[str],
    failures: list[str],
) -> None:
    checked: set[str] = set()
    for path in paths:
        parts = Path(path).parts
        if len(parts) < 4 or parts[0] != "examples" or parts[2] != "src":
            continue
        example = str(Path(parts[0]) / parts[1])
        if example in checked:
            continue
        checked.add(example)
        if not (root / example / "Cargo.toml").is_file():
            failures.append(
                f"{example}: contains Rust src files but has no Cargo.toml"
            )


def validate_text_hygiene(root: Path, failures: list[str]) -> None:
    try:
        paths = discover_text_hygiene_files(root)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        failures.append(f"failed to list text hygiene files under {root}: {stderr}")
        return

    for path in sorted(paths):
        try:
            text = (root / path).read_text(encoding="utf-8")
        except UnicodeDecodeError as err:
            failures.append(f"{path}: could not decode text hygiene file: {err}")
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            column = line.find(EM_DASH)
            if column != -1:
                failures.append(f"{path}:{index}:{column + 1}: contains U+2014 em dash")
                break


# The only violations an allowlist entry excuses. Anything else it can
# carry, including exceeding its own cap or no longer needing the entry at
# all, is a failure: a violation this does not name denies rather than
# passing silently.
PRODUCTION_OVER_LIMIT = "production file has"
LIB_ROOT_OVER_LIMIT = "src/lib.rs has"
TEST_OVER_LIMIT = "test file has"
ASSEMBLED_BY_INCLUDE = "module is assembled from"
ALLOWLIST_EXCUSES = (
    f"{PRODUCTION_OVER_LIMIT} ",
    f"{LIB_ROOT_OVER_LIMIT} ",
    f"{TEST_OVER_LIMIT} ",
    f"{ASSEMBLED_BY_INCLUDE} ",
)


def measure(
    path: str, sizes: dict[str, int], graph: dict[str, tuple[str, ...]]
) -> tuple[int, tuple[str, ...]]:
    fragments = assemble(path, graph)
    own = sizes[path]
    return own + sum(sizes.get(fragment, 0) for fragment in fragments), tuple(fragments)


def size_note(own: int, fragments: tuple[str, ...]) -> str:
    if not fragments:
        return ""
    return f" ({own} own plus {len(fragments)} include! fragments)"


def inspect_module(
    root: Path,
    path: str,
    sizes: dict[str, int],
    graph: dict[str, tuple[str, ...]],
) -> RustModule:
    lines, fragments = measure(path, sizes, graph)
    category = classify(path)
    note = size_note(sizes[path], fragments)
    violations: list[str] = []
    if category == "production" and lines > PRODUCTION_LIMIT:
        violations.append(
            f"{PRODUCTION_OVER_LIMIT} {lines} lines{note}, limit is {PRODUCTION_LIMIT}"
        )
    if category == "production" and is_lib_root(path) and lines > LIB_ROOT_LIMIT:
        violations.append(
            f"{LIB_ROOT_OVER_LIMIT} {lines} lines{note}, limit is {LIB_ROOT_LIMIT}"
        )
    if category == "test" and lines > TEST_LIMIT:
        violations.append(f"{TEST_OVER_LIMIT} {lines} lines{note}, limit is {TEST_LIMIT}")
    if fragments:
        violations.append(
            f"{ASSEMBLED_BY_INCLUDE} {len(fragments)} include! fragments; "
            "use mod with #[path] so the privacy boundary and cargo fmt follow"
        )
    allowlist = ALLOWLIST.get(path)
    if allowlist and allowlist.max_lines is not None and lines > allowlist.max_lines:
        violations.append(
            f"allowlisted file has {lines} lines{note}, cap is {allowlist.max_lines}"
        )
    if (
        allowlist
        and allowlist.max_fragments is not None
        and len(fragments) > allowlist.max_fragments
    ):
        violations.append(
            f"allowlisted module has {len(fragments)} include! fragments, "
            f"cap is {allowlist.max_fragments}"
        )
    if (
        allowlist
        and not violations
        and not fragments
        and lines <= base_limit_for(path, category)
    ):
        violations.append(
            f"file is back under its base limit ({lines} lines); "
            "remove its allowlist entry (run --ratchet)"
        )
    return RustModule(
        path=path,
        lines=lines,
        own_lines=sizes[path],
        fragments=fragments,
        category=category,
        violations=tuple(violations),
        allowlist=allowlist,
    )


def warning_for_file(file: RustModule) -> str | None:
    if file.category != "production":
        return None
    if is_lib_root(file.path):
        if LIB_WARN_LIMIT < file.lines <= LIB_ROOT_LIMIT:
            return (
                f"warning: {file.path} has {file.lines} lines, "
                f"warn limit is {LIB_WARN_LIMIT}"
            )
        return None
    if WARN_LIMIT < file.lines <= PRODUCTION_LIMIT:
        return (
            f"warning: {file.path} has {file.lines} lines, "
            f"warn limit is {WARN_LIMIT}"
        )
    return None


def print_summary(files: list[RustModule]) -> None:
    categories = ["generated", "production", "test", "example"]
    print("Rust file hygiene summary")
    for category in categories:
        category_files = sorted(
            (file for file in files if file.category == category),
            key=lambda file: (-file.lines, file.path),
        )
        if not category_files:
            continue
        print(f"\n==> {category} top {min(SUMMARY_LIMIT, len(category_files))}")
        for file in category_files[:SUMMARY_LIMIT]:
            marker = ""
            if file.violations and file.allowlist:
                marker = f" allowlisted until {file.allowlist.expires}"
            elif file.violations:
                marker = " violation"
            print(f"{file.lines:5d} {file.path}{size_note(file.own_lines, file.fragments)}{marker}")


def base_limit_for(path: str, category: str) -> int:
    if category == "test":
        return TEST_LIMIT
    if is_lib_root(path):
        return LIB_ROOT_LIMIT
    return PRODUCTION_LIMIT


def next_month_end(today: date) -> date:
    year, month = (
        (today.year + 1, 1) if today.month == 12 else (today.year, today.month + 1)
    )
    if month == 12:
        return date(year, 12, 31)
    return date.fromordinal(date(year, month + 1, 1).toordinal() - 1)


def wave_expiries(today: date) -> list[str]:
    """The deadlines entries are spread across, soonest first."""
    deadlines = [next_month_end(today)]
    for _ in range(ALLOWLIST_WAVES - 1):
        deadlines.append(next_month_end(deadlines[-1].replace(day=1)))
    return [deadline.isoformat() for deadline in deadlines]


def ratchet_allowlist(root: Path) -> int:
    today = date.today()
    expiries = wave_expiries(today)
    kept: list[tuple[int, str, str, int | None, int | None]] = []
    dropped: list[str] = []
    tightened: list[str] = []
    paths = discover_rust_files(root)
    sizes = {path: line_count(root / path) for path in paths}
    graph = build_include_graph(root, paths, [])
    spliced = fragment_paths(graph)
    for path, entry in ALLOWLIST.items():
        file_path = root / path
        if not file_path.exists():
            dropped.append(f"{path}: file no longer exists")
            continue
        if path in spliced:
            dropped.append(f"{path}: now an include! fragment of another module")
            continue
        if path not in sizes:
            sizes[path] = line_count(file_path)
        lines, fragments = measure(path, sizes, graph)
        category = classify(path)
        base = base_limit_for(path, category)
        if lines <= base and not fragments:
            dropped.append(f"{path}: {lines} lines is under its base limit")
            continue
        line_cap: int | None = None
        if lines > base:
            old_cap = entry.max_lines if entry.max_lines is not None else lines
            line_cap = min(lines, old_cap)
            if line_cap < old_cap:
                tightened.append(f"{path}: cap {old_cap} -> {line_cap}")
        elif entry.max_lines is not None:
            tightened.append(f"{path}: line cap dropped, {lines} lines is under {base}")
        fragment_cap: int | None = None
        if fragments:
            old_fragments = (
                entry.max_fragments if entry.max_fragments is not None else len(fragments)
            )
            fragment_cap = min(len(fragments), old_fragments)
            if fragment_cap < old_fragments:
                tightened.append(
                    f"{path}: fragments {old_fragments} -> {fragment_cap}"
                )
        elif entry.max_fragments is not None:
            tightened.append(f"{path}: fragment cap dropped, no include! remains")
        kept.append(
            (
                line_cap if line_cap is not None else lines,
                path,
                entry.rationale,
                line_cap,
                fragment_cap,
            )
        )
    # Spread the deadlines rather than stamping one on every entry. A
    # single date is not a deadline anyone can act on, because the only
    # available response is to move it again. Smallest caps come due
    # first: they are the cheapest to bring back under their limit.
    per_wave = max(1, -(-len(kept) // ALLOWLIST_WAVES))
    by_cap = sorted(kept, key=lambda item: (item[0], item[1]))
    schedule = {
        path: expiries[min(index // per_wave, len(expiries) - 1)]
        for index, (_, path, _, _, _) in enumerate(by_cap)
    }
    kept = [
        f'    "{path}": allow(\n'
        f'        "{schedule[path]}",\n'
        f'        "{rationale}",\n'
        + (f"        max_lines={line_cap:_},\n" if line_cap is not None else "")
        + (
            f"        max_fragments={fragment_cap},\n"
            if fragment_cap is not None
            else ""
        )
        + "    ),\n"
        for _, path, rationale, line_cap, fragment_cap in kept
    ]
    script = Path(__file__).resolve()
    source = script.read_text(encoding="utf-8")
    start_marker = "ALLOWLIST: dict[str, AllowlistEntry] = {\n"
    start = source.index(start_marker) + len(start_marker)
    end = source.index("\n}\n", start)
    script.write_text(source[:start] + "".join(kept).rstrip("\n") + source[end:], encoding="utf-8")
    for line in dropped:
        print(f"dropped: {line}")
    for line in tightened:
        print(f"tightened: {line}")
    print(
        f"allowlist ratcheted: {len(kept)} entries kept, {len(dropped)} dropped, "
        f"{len(tightened)} tightened, expiries {', '.join(expiries)}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Rust source file line-count hygiene."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=repo_root(),
        help="repository root to inspect",
    )
    parser.add_argument(
        "--ratchet",
        action="store_true",
        help=(
            "rewrite the allowlist in place: re-cap each entry at the file's "
            "current size (never larger than before), drop entries whose "
            "files are back under their base limit, and advance expiries one "
            "month"
        ),
    )
    args = parser.parse_args()

    if args.ratchet:
        return ratchet_allowlist(args.root.resolve())

    root = args.root.resolve()
    errors: list[str] = []
    validate_allowlist(errors)

    try:
        paths = discover_rust_files(root)
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip()
        print(f"failed to list Rust files under {root}: {stderr}", file=sys.stderr)
        return 1

    sizes = {path: line_count(root / path) for path in paths}
    graph = build_include_graph(root, paths, errors)
    report_include_cycles(graph, errors)
    fragments = fragment_paths(graph)
    files = [
        inspect_module(root, path, sizes, graph)
        for path in paths
        if path not in fragments
    ]
    print_summary(files)
    for path in sorted(set(ALLOWLIST) & fragments):
        includers = ", ".join(
            sorted(parent for parent, targets in graph.items() if path in targets)
        )
        errors.append(
            f"{path}: allowlist entry names an include! fragment; "
            f"the cap belongs to {includers}"
        )

    warnings = [
        warning
        for warning in (
            warning_for_file(file) for file in sorted(files, key=lambda item: item.path)
        )
        if warning is not None
    ]
    if warnings:
        print(
            f"\nRust file hygiene warnings: {len(warnings)} files exceed warning limits"
        )
        for warning in warnings:
            print(warning)

    failures: list[str] = []
    for file in sorted(files, key=lambda candidate: candidate.path):
        if not file.violations:
            continue
        if file.allowlist:
            uncovered = []
            if file.category == "test" and file.lines > TEST_LIMIT:
                if file.allowlist.max_lines is None:
                    uncovered.append(
                        "oversized test allowlist entry must set a max_lines cap"
                    )
            uncovered.extend(
                violation
                for violation in file.violations
                if not violation.startswith(ALLOWLIST_EXCUSES)
            )
            if uncovered:
                for violation in uncovered:
                    failures.append(f"{file.path}: {violation}")
                continue
            print(
                f"allowlisted: {file.path}: {file.allowlist.rationale}; "
                f"expires {file.allowlist.expires}; "
                f"max_lines {file.allowlist.max_lines or 'uncapped'}; "
                f"max_fragments {file.allowlist.max_fragments or 'none'}"
            )
            continue
        for violation in file.violations:
            failures.append(f"{file.path}: {violation}")

    validate_generated_headers(root, paths, failures)
    validate_rust_example_packages(root, paths, failures)
    validate_text_hygiene(root, failures)

    if errors:
        failures.extend(errors)

    if failures:
        print("\nRust file hygiene failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nRust file hygiene check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
