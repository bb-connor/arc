#!/usr/bin/env python3
"""Run an explicit local P4 gate and retain its actual command and result."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[6]
EVIDENCE = Path(__file__).resolve().parent
PYPATH = "/Users/connor/Medica/backbay/standalone/arc/sdks/python/chio-crewai/.venv/bin/python"
PACKAGES = ["chio-core-types", "chio-security-types", "chio-flow", "chio-recovery", "chio-semantic-contracts", "chio-kernel", "chio-process", "chio-store-sqlite", "chio-control-plane", "chio-conformance", "chio-spec-codegen", "xtask"]
OWNING = [p for p in PACKAGES if p not in {"chio-control-plane", "chio-conformance", "chio-kernel", "chio-store-sqlite"}]
CARGO = ["--offline", "--locked"]
# These exact unchanged payment tests need listeners forbidden by this sandbox.
# Their actual failed broad run is retained in kernel-listener-attempt.log.
KERNEL_LISTENER_TESTS = [
 "kernel::tests::governed_acp_hold_flow_records_commerce_scope_and_payment_metadata",
 "kernel::tests::governed_x402_authorization_failure_denies_before_tool_execution",
 "kernel::tests::governed_x402_prepaid_flow_records_governed_authorization_and_receipt_metadata",
 "payment::tests::acp_adapter_externalizes_capture_release_and_refund",
 "payment::tests::acp_adapter_posts_authorize_request_with_commerce_context_and_returns_hold",
 "payment::tests::acp_adapter_queries_bound_settlement_state",
 "payment::tests::acp_adapter_rejects_unbound_terminal_response",
 "payment::tests::payment_error_bodies_are_not_reflected",
 "payment::tests::payment_response_body_is_bounded",
 "payment::tests::x402_adapter_maps_http_402_to_insufficient_funds",
 "payment::tests::x402_adapter_posts_authorize_request_and_returns_settled_payment",
 "payment::tests::x402_adapter_uses_custom_path_bearer_token_and_governed_payload",
]
# These unchanged tests require /dev/shm on a separate snapshot device. Their
# actual failed macOS run is retained in store-platform-attempt.log. Never replace
# their independent anchor with a directory on the database's own device.
SQLITE_LINUX_ANCHOR_TESTS = [
 "capability_lineage::tests::qualified_capability_snapshots_advance_the_external_rollback_generation",
 "dead_letters::tests::qualified_alongside_store_rejects_dead_letter_rollback",
 "finding_pool_ledger::tests::claimed_admission_operation_scan_is_bounded_and_cursor_ordered",
 "finding_pool_ledger::tests::leased_outbox_rows_remain_observable_as_pending",
 "finding_pool_ledger::tests::qualified_ledger_binds_validation_to_the_borrowed_database_file",
 "finding_pool_ledger::tests::qualified_ledger_persists_one_receipt_sink",
 "finding_pool_ledger::tests::qualified_ledger_rejects_a_writable_parent_directory",
 "finding_pool_ledger::tests::qualified_ledger_rejects_unusable_domains",
 "finding_pool_ledger::tests::qualified_schema_indexes_pending_outbox_and_expiration_reclamation",
 "finding_pool_ledger::tests::recovered_mutation_loads_the_reservations_persisted_tenant",
 "finding_pool_ledger::tests::unknown_dispatch_exact_replay_ignores_later_allocation_totals",
 "iou_store::tests::qualified_alongside_store_rejects_iou_rollback",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_allows_explicitly_false_immutable_sqlite_uris",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_anchors_background_checkpoint_commits",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_anchors_checkpoint_publication_bindings",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_anchors_imported_checkpoint_commits",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_anchors_lineage_only_duplicate_mutations",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_anchors_retention_rotation",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_anchors_standalone_checkpoint_commits",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_anchors_standalone_lineage_mutations",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_refuses_to_seed_an_archive_only_store",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_rejects_atomic_database_replacement",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_rejects_internal_sink_identity_change",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_rejects_nonlocal_sqlite_uri_authorities",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_rejects_read_only_sqlite_uris",
 "receipt_store::tests::qualified_finding_pool::qualified_receipt_sink_verifies_rollback_anchor_before_metadata_jobs",
 "receipt_store::tests::qualified_finding_pool::qualified_settlement_state_writes_advance_the_rollback_anchor",
 "receipt_store::tests::verified_head::qualified_reader_and_reopen_reject_live_rollback_after_writer_routed_receipt",
 "receipt_store::tests::verified_head::qualified_receipt_sink_rejects_locking_disabled_sqlite_uris",
]
# Keep the platform aliases out of no-follow SQLite paths without changing the
# production path checks. All test subprocesses inherit this canonical directory.
TEST_TMPDIR = str(Path(os.environ.get("TMPDIR", "/tmp")).resolve())
SQLITE_UNAVAILABLE_TESTS = SQLITE_LINUX_ANCHOR_TESTS if not Path("/dev/shm").is_dir() else []
GATES = {
 "native": (["cargo", "test", *CARGO, "-p", "chio-control-plane", "--lib", "p4_", "--", "--test-threads=1"], ".", {}),
 "owner-doc-tests": (["cargo", "test", *CARGO, "-p", "chio-control-plane", "--doc"], ".", {}),
 "p3-native": (["cargo", "test", *CARGO, "-p", "chio-control-plane", "--lib", "p3_", "--", "--test-threads=1"], ".", {}),
 "p1-native": (["cargo", "test", *CARGO, "-p", "chio-control-plane", "--lib", "recovery_p1_", "--", "--test-threads=1"], ".", {}),
 "p2-native": (["cargo", "test", *CARGO, "-p", "chio-control-plane", "--lib", "recovery_p2_", "--", "--test-threads=1"], ".", {}),
 "owning-tests": (["cargo", "test", *CARGO, *sum((["-p", p] for p in OWNING), []), "--", "--test-threads=2"], ".", {"TMPDIR": TEST_TMPDIR}),
 "store-native": (["cargo", "test", *CARGO, "-p", "chio-store-sqlite", "--lib", "security_participant", "--", "--test-threads=1"], ".", {"TMPDIR": TEST_TMPDIR}),
 "store-ordering": (["cargo", "test", *CARGO, "-p", "chio-store-sqlite", "--lib", "global_commit", "--", "--test-threads=1"], ".", {"TMPDIR": TEST_TMPDIR}),
 "store-schema": (["cargo", "test", *CARGO, "-p", "chio-store-sqlite", "--lib", "admission_operation_store::tests::schema", "--", "--test-threads=1"], ".", {"TMPDIR": TEST_TMPDIR}),
 "store-regression": (["cargo", "test", *CARGO, "-p", "chio-store-sqlite", "--lib", "restoring", "--", "--test-threads=2", *sum((["--skip", name] for name in SQLITE_UNAVAILABLE_TESTS), [])], ".", {"TMPDIR": TEST_TMPDIR}),
 "store-doc-tests": (["cargo", "test", *CARGO, "-p", "chio-store-sqlite", "--doc"], ".", {"TMPDIR": TEST_TMPDIR}),
 "conformance-lib": (["cargo", "test", *CARGO, "-p", "chio-conformance", "--lib"], ".", {}),
 "kernel-lib": (["cargo", "test", *CARGO, "-p", "chio-kernel", "--lib", "--", *sum((["--skip", name] for name in KERNEL_LISTENER_TESTS), [])], ".", {}),
 "kernel-doc-tests": (["cargo", "test", *CARGO, "-p", "chio-kernel", "--doc"], ".", {}),
 "clippy": (["cargo", "clippy", *CARGO, *sum((["-p", p] for p in PACKAGES), []), "--all-targets", "--", "-D", "warnings"], ".", {}),
 "format": (["cargo", "fmt", "--all", "--", "--check"], ".", {}),
 "diff": (["git", "diff", "--check"], ".", {}),
 "rust-codegen": (["target/debug/xtask", "codegen", "rust", "--check"], ".", {}),
 "vector-recompute": (["python3", "docs/architecture/recoverable-agent-runtime/implementation/p4/evidence/verify-vectors.py"], ".", {}),
 "ts-codegen": (["target/debug/xtask", "codegen", "ts", "--check"], ".", {}),
 "python-codegen": (["target/debug/xtask", "codegen", "python", "--check"], ".", {"PATH": str(ROOT / "target/recovery-p0-codegen-bin") + os.pathsep + os.environ["PATH"]}),
 "pure-guard": (["python3", "scripts/check-recovery-p0.py", "--offline"], ".", {}),
 "guard-mutations": (["python3", "scripts/tests/check-recovery-p0.test.py"], ".", {}),
 "schemas": (["bash", "scripts/check-chio-schema-registry.sh"], ".", {}),
 "domains": (["python3", "scripts/check-domain-separation.py"], ".", {}),
 "wire-lock": (["python3", "scripts/check-wire-schemas.py"], ".", {}),
 "lint-parity": (["python3", "scripts/check-lint-parity.py"], ".", {}),
 "toolchain-parity": (["python3", "scripts/check-rust-toolchain-parity.py"], ".", {}),
 "layering": (["bash", "scripts/check-workspace-layering.sh"], ".", {}),
 "hygiene": (["python3", "scripts/check-rust-file-hygiene.py"], ".", {}),
 "alloc": (["cargo", "check", *CARGO, "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml"], ".", {}),
 "std": (["cargo", "check", *CARGO, "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml", "--features", "std"], ".", {}),
 "wasm": (["cargo", "check", *CARGO, "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml", "--target", "wasm32-unknown-unknown"], ".", {}),
 "msrv-alloc": (["cargo", "+1.93.0", "check", *CARGO, "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml"], ".", {}),
 "msrv-std": (["cargo", "+1.93.0", "check", *CARGO, "--manifest-path", "fixtures/recovery-portable-consumer/Cargo.toml", "--features", "std"], ".", {}),
 "python": ([PYPATH, "-m", "pytest", "-q", "sdks/python/chio-sdk-python/tests"], ".", {"PYTHONPATH": "sdks/python/chio-sdk-python/src"}),
 "ts": (["node", "node_modules/vitest/vitest.mjs", "run", "test/recovery_schema.test.ts", "test/recovery_p1_schema.test.ts", "test/recovery_p2_schema.test.ts", "test/recovery_p3_schema.test.ts", "test/recovery_p4_schema.test.ts", "test/recovery_client.test.ts"], "sdks/typescript/packages/conformance", {}),
 "ts-node-build": (["node", "node_modules/typescript/bin/tsc", "-p", "packages/node-http/tsconfig.json"], "sdks/typescript", {}),
 "ts-conformance-build": (["node", "node_modules/typescript/bin/tsc", "-p", "packages/conformance/tsconfig.json", "--noEmit"], "sdks/typescript", {}),
 "architecture": (["python3", "docs/architecture/recoverable-agent-runtime/check.py", "--source-revision", "de84fc306"], ".", {}),
}

def main():
 parser = argparse.ArgumentParser(); parser.add_argument("gates", nargs="+", choices=list(GATES)); args = parser.parse_args()
 failures = []
 for name in args.gates:
  command, cwd, env = GATES[name]
  if command[0] == "cargo":
   env = {"CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2", "TMPDIR": TEST_TMPDIR, **env}
  log = EVIDENCE / f"{name}.log"
  started = time.time()
  with log.open("wb") as stream:
   result = subprocess.run(command, cwd=ROOT / cwd, env={**os.environ, **env}, stdout=stream, stderr=subprocess.STDOUT, check=False)
  row = {"id": name, "actual_command": command, "cwd": cwd, "environment": env, "exit_code": result.returncode, "status": "passed" if result.returncode == 0 else "failed", "started_unix_seconds": int(started), "duration_seconds": round(time.time()-started,3), "log": "evidence/"+log.name, "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(), "required_for_local_phase_acceptance": True}
  (EVIDENCE / f"{name}.result.json").write_text(json.dumps(row, indent=2)+"\n")
  print(name, row["status"], row["duration_seconds"], flush=True)
  if result.returncode: failures.append(name)
 raise SystemExit(bool(failures))

if __name__ == "__main__": main()
