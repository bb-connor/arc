//! Real charged reservations exercise the actual Process finalize/admit writers.
use super::*;
use crate::store::Store;
use crate::{ProcessLimits, ProcessRuntime, ProcessSecurityProfile};
use chio_core_types::capability::attenuation::scope_hash;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::{ChioKernel, KernelConfig, ToolCallRequest};
use chio_security_types::recovery::{ContinuationId, IntentDigest, ProcessId};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};
use rusqlite::{params, OptionalExtension};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    runtime: ProcessRuntime,
    authority: String,
    kernel_key: String,
}

struct Reserved {
    reservation: RecoveryCallReservation,
    request: ToolCallRequest,
    binding: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    version: i64,
    calls: Vec<(String, String, String, i64)>,
    reservations: Vec<(String, String, String, Vec<u8>, Option<String>)>,
    closures: Vec<(String, String, Vec<u8>)>,
    tree_calls: u32,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let locks = directory.path().join("locks");
        std::fs::create_dir(&locks)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))?;
        }
        let native_path = directory.path().join("authority.db");
        SqliteAuthorityStore::provision(&native_path, &locks)?;
        let authority = SqliteAuthorityStore::open_serving(&native_path, &locks)?;
        let issuer = Keypair::from_seed(&[43; 32]);
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: issuer.clone(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 8,
            policy_hash: sha256_hex(b"unused process reservation test policy"),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: 30,
            max_stream_total_bytes: 1_048_576,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            allow_ephemeral_revocation_store: false,
            checkpoint_batch_size: 0,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: Default::default(),
        });
        let scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "tools".into(),
                tool_name: "read".into(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        };
        kernel.set_capability_trust_root(issuer.public_key(), scope_hash(&scope)?);
        let receipts = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;
        receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
        kernel.set_receipt_store(Box::new(receipts))?;
        kernel.set_revocation_store(Box::new(authority.revocation_store()));
        kernel.set_budget_store(Box::new(authority.budget_store()));
        kernel.set_durable_admission_store(
            Arc::new(authority.admission_operation_store()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )?;
        kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
        kernel.reconcile_durable_admission_startup()?;
        let kernel = Arc::new(kernel);
        let path = directory.path().join("process.db");
        let runtime = ProcessRuntime::open(&path, kernel.clone())?;
        let subject = Keypair::from_seed(&[44; 32]);
        let capability = kernel.issue_capability(&subject.public_key(), scope, 1_200)?;
        runtime.create_root(
            "root",
            &capability,
            ProcessLimits {
                max_processes: 8,
                max_depth: 4,
                max_calls: 8,
                state: Default::default(),
            },
        )?;
        // This is the real owning journal transition, not a forced version row.
        runtime.with_store(Store::enable_knowledge)?;
        let value = Self {
            _directory: directory,
            path,
            runtime,
            authority: kernel
                .durable_admission_store_uuid()
                .ok_or("actual native authority absent")?
                .to_owned(),
            kernel_key: kernel.public_key().to_hex(),
        };
        assert_eq!(value.snapshot()?.version, 5);
        assert_eq!(value.snapshot()?.tree_calls, 0);
        Ok(value)
    }

    fn reserve(&self, id: &str) -> TestResult<Reserved> {
        let continuation = ContinuationId::new(id)?;
        let operation_key = format!("recovery:{}", continuation.as_str());
        let reservation = self.runtime.reserve_recovery_call(
            "root",
            &operation_key,
            &continuation,
            IntentDigest::from_bytes(*chio_core_types::sha256(id.as_bytes()).as_bytes()),
            "tools",
        )?;
        let request = self.runtime.tool_request(
            "root",
            &operation_key,
            "tools",
            "read",
            serde_json::json!({"source": "unused-reservation-control"}),
        )?;
        assert_eq!(request.request_id, reservation.request_id());
        let (_, binding) =
            self.runtime
                .recovery_request_digests("root", &operation_key, &request)?;
        self.runtime
            .with_store(|store| store.verify_recovery_reservation(&reservation))?;
        let snapshot = self.snapshot()?;
        let row = snapshot
            .reservations
            .iter()
            .find(|row| row.1 == operation_key)
            .ok_or("actual charged reservation absent")?;
        assert_eq!(row.3, canonical_json_bytes(&reservation)?);
        assert!(
            row.4.is_none(),
            "the actual reservation is not yet finalized"
        );
        assert!(!snapshot.calls.iter().any(|row| row.1 == operation_key));
        Ok(Reserved {
            reservation,
            request,
            binding,
        })
    }

    fn finalize(&self, value: &Reserved) -> Result<(), crate::ProcessError> {
        self.runtime.with_store(|store| {
            store.finalize_recovery(&value.reservation, &value.request, &value.binding)
        })
    }

    fn snapshot(&self) -> TestResult<Snapshot> {
        self.runtime.with_store(|store| {
            let version = store.connection.query_row(
                "SELECT version FROM process_runtime WHERE singleton=1", [], |row| row.get(0),
            )?;
            let calls = store.connection.prepare(
                "SELECT process_id,operation_key,request_hash,attempts FROM process_calls ORDER BY process_id,operation_key",
            )?.query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?
                .collect::<Result<Vec<_>,_>>()?;
            let reservations = store.connection.prepare(
                "SELECT process_id,operation_key,continuation_id,reservation,final_binding FROM process_recovery_calls ORDER BY process_id,operation_key",
            )?.query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?
                .collect::<Result<Vec<_>,_>>()?;
            let has_closures = store.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='process_unused_recovery_reservations')", [], |row| row.get::<_,bool>(0),
            )?;
            let closures = if has_closures {
                store.connection.prepare(
                    "SELECT process_id,operation_key,closure FROM process_unused_recovery_reservations ORDER BY process_id,operation_key",
                )?.query_map([], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?
                    .collect::<Result<Vec<_>,_>>()?
            } else {
                Vec::new()
            };
            Ok(Snapshot { version, calls, reservations, closures, tree_calls: store.process("root")?.tree_calls })
        }).map_err(Into::into)
    }
}

#[test]
fn charged_unused_reservation_closure_prevents_late_finalize_without_refunding_calls() -> TestResult
{
    let f = Fixture::new()?;
    let control = f.reserve("late-finalize-control")?;
    assert_eq!(f.snapshot()?.tree_calls, 1);
    f.finalize(&control)?;
    f.runtime.with_store(|store| {
        store.admit(
            "root",
            control.reservation.operation_key(),
            &control.request,
            &control.binding,
        )
    })?;
    assert_eq!(
        f.snapshot()?.tree_calls,
        1,
        "finalizing the actual reserved control must charge no second call"
    );
    let value = f.reserve("permanently-closed-unused")?;
    assert_eq!(f.snapshot()?.tree_calls, 2);
    let retained = canonical_json_bytes(&value.reservation)?;
    let closure = f
        .runtime
        .close_unused_recovery_reservation(&value.reservation);
    assert!(closure.is_ok(), "real charged unused reservation still has no permanent closure after the actual late-finalize control succeeded: {closure:?}");
    let closure = closure?;
    assert_eq!(closure.reservation(), &value.reservation);
    assert_eq!(closure.runtime_id(), f.runtime.runtime_id());
    let sealed = f.snapshot()?;
    assert_eq!(sealed.version, 6);
    assert_eq!(
        sealed.tree_calls, 2,
        "closure must preserve the original logical debit"
    );
    let row = sealed
        .reservations
        .iter()
        .find(|row| row.1 == value.reservation.operation_key())
        .ok_or("retained closed reservation absent")?;
    assert_eq!(row.3, retained);
    assert!(row.4.is_none());
    assert!(f.finalize(&value).is_err());
    assert!(f
        .runtime
        .with_store(|store| store.admit(
            "root",
            value.reservation.operation_key(),
            &value.request,
            &value.binding
        ))
        .is_err());
    assert!(f
        .runtime
        .with_store(|store| store.reserve_recovery(&value.reservation))
        .is_err());
    assert_eq!(
        f.snapshot()?,
        sealed,
        "late participants cannot alter closed history or debit"
    );
    let mut reopened = Store::open(&f.path, &f.authority, &f.kernel_key)?;
    assert!(reopened
        .finalize_recovery(&value.reservation, &value.request, &value.binding)
        .is_err());
    assert!(reopened
        .admit(
            "root",
            value.reservation.operation_key(),
            &value.request,
            &value.binding
        )
        .is_err());
    assert!(reopened
        .connection
        .execute("UPDATE process_runtime SET version=5 WHERE singleton=1", [])
        .is_err());
    assert!(reopened
        .connection
        .execute("DELETE FROM process_unused_recovery_reservations", [])
        .is_err());
    assert_eq!(f.snapshot()?, sealed);
    Ok(())
}

#[test]
fn unused_reservation_closure_committed_first_fences_a_separate_finalize_writer() -> TestResult {
    let f = Fixture::new()?;
    let value = f.reserve("close-before-concurrent-finalize")?;
    let mut closer = Store::open(&f.path, &f.authority, &f.kernel_key)?;
    let mut finalizer = Store::open(&f.path, &f.authority, &f.kernel_key)?;
    let barrier = Arc::new(Barrier::new(2));
    let close_barrier = barrier.clone();
    let (closed, finalized) = std::thread::scope(|scope| {
        let closed = scope.spawn(|| {
            let result = closer.close_unused_recovery_reservation(
                (&f.authority, &f.kernel_key),
                &value.reservation,
            );
            close_barrier.wait();
            result
        });
        let finalized = scope.spawn(|| {
            barrier.wait();
            finalizer.finalize_recovery(&value.reservation, &value.request, &value.binding)
        });
        Ok::<_, Box<dyn std::error::Error>>((
            closed.join().map_err(|_| "closure writer panicked")?,
            finalized.join().map_err(|_| "finalize writer panicked")?,
        ))
    })?;
    assert!(closed.is_ok(), "the actual unused reservation could not close before its late writer: close={closed:?}, finalize={finalized:?}");
    assert!(
        finalized.is_err(),
        "late finalize crossed the committed permanent closure"
    );
    assert_eq!(f.snapshot()?.tree_calls, 1);
    assert!(f.snapshot()?.calls.is_empty());
    Ok(())
}

#[test]
fn actual_finalization_committed_first_prevents_unused_reservation_closure() -> TestResult {
    let f = Fixture::new()?;
    let value = f.reserve("finalize-before-concurrent-close")?;
    let mut finalizer = Store::open(&f.path, &f.authority, &f.kernel_key)?;
    let mut closer = Store::open(&f.path, &f.authority, &f.kernel_key)?;
    let barrier = Arc::new(Barrier::new(2));
    let finalize_barrier = barrier.clone();
    let (finalized, closed) = std::thread::scope(|scope| {
        let finalized = scope.spawn(|| {
            let result =
                finalizer.finalize_recovery(&value.reservation, &value.request, &value.binding);
            finalize_barrier.wait();
            result
        });
        let closed = scope.spawn(|| {
            barrier.wait();
            closer.close_unused_recovery_reservation(
                (&f.authority, &f.kernel_key),
                &value.reservation,
            )
        });
        Ok::<_, Box<dyn std::error::Error>>((
            finalized.join().map_err(|_| "finalize writer panicked")?,
            closed.join().map_err(|_| "closure writer panicked")?,
        ))
    })?;
    assert!(
        finalized.is_ok(),
        "the actual finalized control failed: {finalized:?}"
    );
    assert!(
        closed.is_err(),
        "a committed Process participant cannot retire as unused"
    );
    let retained = f.snapshot()?;
    assert_eq!(retained.version, 5);
    assert_eq!(retained.tree_calls, 1);
    assert_eq!(retained.calls.len(), 1);
    assert!(retained.closures.is_empty());
    assert_eq!(
        retained.reservations[0].4.as_deref(),
        Some(value.binding.as_str())
    );
    Ok(())
}

#[test]
fn reservation_closure_refuses_changed_or_missing_original_without_mutation() -> TestResult {
    let f = Fixture::new()?;
    let value = f.reserve("exact-unused-original")?;
    let before = f.snapshot()?;
    for altered in [
        serde_json::json!({"runtime_id": "other-runtime"}),
        serde_json::json!({"operation_key": "recovery:missing-original"}),
        serde_json::json!({"capability_digest": "0".repeat(64)}),
        serde_json::json!({"continuation_id": "other-continuation"}),
    ] {
        let mut wire = serde_json::to_value(&value.reservation)?;
        for (key, value) in altered.as_object().ok_or("altered reservation shape")? {
            wire[key] = value.clone();
        }
        let altered: RecoveryCallReservation = serde_json::from_value(wire)?;
        assert!(f
            .runtime
            .close_unused_recovery_reservation(&altered)
            .is_err());
        assert_eq!(f.snapshot()?, before);
    }
    let observed: Option<String> = f.runtime.with_store(|store| {
        Ok(store.connection.query_row(
            "SELECT final_binding FROM process_recovery_calls WHERE process_id=?1 AND operation_key=?2",
            params!["root",value.reservation.operation_key()], |row| row.get(0),
        ).optional()?.flatten())
    })?;
    assert!(observed.is_none());
    Ok(())
}

#[test]
fn closed_reservation_replay_preserves_original_journal_provenance_and_one_marker() -> TestResult {
    let f = Fixture::new()?;
    let original = f.reserve("retained-finalized-original")?;
    f.finalize(&original)?;
    let value = f.reserve("retained-closed-original")?;
    let role = f
        .runtime
        .close_unused_recovery_reservation(&value.reservation)?;
    role.verify_for(&value.reservation, &f.authority)?;
    let retained = f.snapshot()?;
    assert_eq!(retained.closures.len(), 1);
    assert_eq!(retained.tree_calls, 2);
    let replay = f
        .runtime
        .close_unused_recovery_reservation(&value.reservation)?;
    assert_eq!(replay.historical_data(), role.historical_data());
    replay.verify_for(&value.reservation, &f.authority)?;
    let recovered = f.runtime.original_snapshot.original_call_key(
        "root",
        &original.request,
        &[original.binding.clone(), original.binding.clone()],
    )?;
    assert_eq!(recovered, original.reservation.operation_key());
    assert_eq!(
        f.snapshot()?,
        retained,
        "closure replay must append no marker or debit"
    );
    assert!(crate::ProcessStateReader::open(&f.path).is_err());
    Ok(())
}

#[test]
fn a_version_six_label_without_closed_custody_cannot_open_or_authorize_provenance() -> TestResult {
    let f = Fixture::new()?;
    let original = f.reserve("counterfeit-version-control")?;
    f.finalize(&original)?;
    let before = f.snapshot()?;
    f.runtime.with_store(|store| {
        assert!(store
            .connection
            .execute("UPDATE process_runtime SET version=6 WHERE singleton=1", [])
            .is_err());
        Ok(())
    })?;
    assert_eq!(f.snapshot()?, before);
    // A privileged corruption fixture forges the label while restoring the
    // exact guards. Neither an empty cohort nor its version is closure proof.
    f.runtime.with_store(|store| {
        store.connection.execute_batch(
            "DROP TRIGGER process_unused_recovery_version_requires_closure;
            UPDATE process_runtime SET version=6 WHERE singleton=1;",
        )?;
        store.connection.execute_batch(super::catalog::SQL)?;
        Ok(())
    })?;
    let counterfeit = f.snapshot()?;
    assert_eq!(counterfeit.version, 6);
    assert!(counterfeit.closures.is_empty());
    assert!(Store::open(&f.path, &f.authority, &f.kernel_key).is_err());
    assert!(f
        .runtime
        .original_snapshot
        .original_call_key(
            "root",
            &original.request,
            &[original.binding.clone(), original.binding.clone()],
        )
        .is_err());
    assert_eq!(f.snapshot()?, counterfeit);
    Ok(())
}

#[test]
fn closed_reservation_cannot_be_represented_by_a_predecessor_journal_header() -> TestResult {
    for predecessor in 1..=5 {
        let f = Fixture::new()?;
        let original = f.reserve("original-provenance-before-closed-cohort")?;
        f.finalize(&original)?;
        let unused = f.reserve("closed-custody-under-predecessor-header")?;
        let role = f
            .runtime
            .close_unused_recovery_reservation(&unused.reservation)?;
        role.verify_for(&unused.reservation, &f.authority)?;
        let original_key = f.runtime.original_snapshot.original_call_key(
            "root",
            &original.request,
            &[original.binding.clone(), original.binding.clone()],
        )?;
        assert_eq!(original_key, original.reservation.operation_key());
        let mut retained = f.snapshot()?;
        assert_eq!(retained.version, 6);
        assert_eq!(retained.tree_calls, 2);
        assert_eq!(retained.closures.len(), 1);
        // Deliberate operator corruption keeps the entire genuine closed
        // cohort and restores every guard after forging an older header.
        f.runtime.with_store(|store| {
            let tx = store
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let guards = [
                "process_recovery_version_monotone",
                "process_knowledge_no_downgrade",
                "process_unused_recovery_version_no_downgrade",
            ];
            let definitions = guards
                .iter()
                .map(|name| {
                    tx.query_row(
                        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                        [name],
                        |row| row.get::<_, String>(0),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            for name in guards {
                tx.execute_batch(&format!("DROP TRIGGER {name}"))?;
            }
            assert_eq!(
                tx.execute(
                    "UPDATE process_runtime SET version=?1 WHERE singleton=1 AND version=6",
                    [predecessor],
                )?,
                1
            );
            for definition in definitions {
                tx.execute_batch(&definition)?;
            }
            super::catalog::verify(&tx)?;
            tx.commit()?;
            Ok(())
        })?;
        retained.version = predecessor;
        assert_eq!(f.snapshot()?, retained);
        assert!(
            Store::open(&f.path, &f.authority, &f.kernel_key).is_err(),
            "a populated closed cohort cannot open under predecessor {predecessor}"
        );
        assert!(
            f.runtime
                .original_snapshot
                .original_call_key(
                    "root",
                    &original.request,
                    &[original.binding.clone(), original.binding.clone()],
                )
                .is_err(),
            "original provenance cannot accept closed custody under predecessor {predecessor}"
        );
        assert!(role.verify_for(&unused.reservation, &f.authority).is_err());
        f.runtime
            .with_store(|store| super::catalog::verify(&store.connection))?;
        assert_eq!(f.snapshot()?, retained);
    }
    Ok(())
}

#[test]
fn a_missing_closed_reservation_guard_is_refused_before_open_time_repair() -> TestResult {
    for guard in [
        "process_unused_recovery_no_call_insert",
        "process_unused_recovery_closure_no_delete",
        "process_recovery_identity_immutable",
        "process_recovery_version_monotone",
    ] {
        let f = Fixture::new()?;
        let value = f.reserve("guarded-closed-original")?;
        let role = f
            .runtime
            .close_unused_recovery_reservation(&value.reservation)?;
        role.verify_for(&value.reservation, &f.authority)?;
        f.runtime.with_store(|store| {
            store
                .connection
                .execute_batch(&format!("DROP TRIGGER {guard}"))?;
            Ok(())
        })?;
        let before = f.snapshot()?;
        assert!(
            role.verify_for(&value.reservation, &f.authority).is_err(),
            "missing guard {guard} cannot retain a live closure role"
        );
        assert!(
            Store::open(&f.path, &f.authority, &f.kernel_key).is_err(),
            "open must refuse missing guard {guard} before repairing DDL"
        );
        let repaired: bool = f.runtime.with_store(|store| {
            Ok(store.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name=?1)",
                [guard],
                |row| row.get(0),
            )?)
        })?;
        assert!(!repaired);
        assert_eq!(f.snapshot()?, before);
    }
    Ok(())
}

#[test]
fn live_knowledge_reader_refuses_closed_custody_under_a_forged_predecessor_header() -> TestResult {
    let mut f = Fixture::new()?;
    f.runtime = f
        .runtime
        .clone()
        .with_security_profile(ProcessSecurityProfile {
            tenant_id: "unused-closure-reader-tenant".into(),
            isolation_epoch_id: "unused-closure-reader-epoch".into(),
            generation: 1,
        })?;
    let broker = f.runtime.enable_durable_knowledge()?;
    let process = ProcessId::new("root")?;
    let usage = broker.storage_usage(&process)?;
    assert_eq!(usage.process_bytes, 0);
    assert_eq!(usage.process_blobs, 0);
    let unused = f.reserve("closed-reservation-live-knowledge-reader")?;
    let role = f
        .runtime
        .close_unused_recovery_reservation(&unused.reservation)?;
    role.verify_for(&unused.reservation, &f.authority)?;
    assert_eq!(broker.storage_usage(&process)?, usage);
    let mut retained = f.snapshot()?;
    assert_eq!(retained.version, 6);
    assert_eq!(retained.tree_calls, 1);
    assert_eq!(retained.closures.len(), 1);
    // Keep the real closed cohort and all exact guards, forging only its
    // predecessor header through deliberate privileged corruption.
    f.runtime.with_store(|store| {
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let guards = [
            "process_recovery_version_monotone",
            "process_knowledge_no_downgrade",
            "process_unused_recovery_version_no_downgrade",
        ];
        let definitions = guards
            .iter()
            .map(|name| {
                tx.query_row(
                    "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
                    [name],
                    |row| row.get::<_, String>(0),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        for guard in guards {
            tx.execute_batch(&format!("DROP TRIGGER {guard}"))?;
        }
        assert_eq!(
            tx.execute(
                "UPDATE process_runtime SET version=5 WHERE singleton=1 AND version=6",
                []
            )?,
            1
        );
        for definition in definitions {
            tx.execute_batch(&definition)?;
        }
        super::catalog::verify(&tx)?;
        tx.commit()?;
        Ok(())
    })?;
    retained.version = 5;
    assert_eq!(f.snapshot()?, retained);
    assert!(Store::open(&f.path, &f.authority, &f.kernel_key).is_err());
    assert!(role.verify_for(&unused.reservation, &f.authority).is_err());
    let warm_usage = broker.storage_usage(&process);
    let warm_gate = f
        .runtime
        .with_store(|store| store.require_enforced_knowledge());
    f.runtime
        .with_store(|store| super::catalog::verify(&store.connection))?;
    assert_eq!(
        f.snapshot()?,
        retained,
        "warm metadata reads must preserve closed custody and its charge"
    );
    assert!(warm_usage.is_err(), "the already-open public Knowledge broker accepted a forged predecessor header despite real closed custody: {warm_usage:?}; enforced gate={warm_gate:?}");
    assert!(warm_gate.is_err());
    Ok(())
}

#[test]
fn live_participants_refuse_a_removed_closed_reservation_catalog_without_mutation() -> TestResult {
    let f = Fixture::new()?;
    let control = f.reserve("whole-catalog-finalize-control")?;
    f.finalize(&control)?;
    f.runtime.with_store(|store| {
        store.admit(
            "root",
            control.reservation.operation_key(),
            &control.request,
            &control.binding,
        )
    })?;
    let unused = f.reserve("closed-reservation-with-removed-catalog")?;
    let role = f
        .runtime
        .close_unused_recovery_reservation(&unused.reservation)?;
    role.verify_for(&unused.reservation, &f.authority)?;
    let mut retained = f.snapshot()?;
    assert_eq!(retained.version, 6);
    assert_eq!(retained.tree_calls, 2);
    assert_eq!(retained.calls.len(), 1);
    assert_eq!(retained.closures.len(), 1);
    // Remove only the closure family through deliberate privileged
    // corruption. The version, original reservation, call and debit stay.
    f.runtime.with_store(|store| {
        let tx = store
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for guard in [
            "process_unused_recovery_closure_no_update",
            "process_unused_recovery_closure_no_delete",
            "process_unused_recovery_no_call_insert",
            "process_unused_recovery_no_call_update",
            "process_unused_recovery_no_reservation_update",
            "process_unused_recovery_no_reservation_reinsert",
            "process_unused_recovery_version_requires_closure",
            "process_unused_recovery_version_no_downgrade",
        ] {
            tx.execute_batch(&format!("DROP TRIGGER {guard}"))?;
        }
        tx.execute_batch("DROP TABLE process_unused_recovery_reservations")?;
        tx.commit()?;
        Ok(())
    })?;
    retained.closures.clear();
    assert_eq!(f.snapshot()?, retained);
    assert!(Store::open(&f.path, &f.authority, &f.kernel_key).is_err());
    assert!(role.verify_for(&unused.reservation, &f.authority).is_err());
    let late_finalize = f.finalize(&unused);
    let late_admit = f.runtime.with_store(|store| {
        store.admit(
            "root",
            unused.reservation.operation_key(),
            &unused.request,
            &unused.binding,
        )
    });
    assert!(late_finalize.is_err(), "the already-open finalizer crossed real permanent closure after its catalog disappeared: finalize={late_finalize:?}; admit={late_admit:?}");
    assert!(
        late_admit.is_err(),
        "late admission crossed closed catalog loss: {late_admit:?}"
    );
    assert_eq!(
        f.snapshot()?,
        retained,
        "lost closure catalog must never create a call, finalize a binding or change a debit"
    );
    let family = f
        .runtime
        .with_store(|store| super::catalog::family_present(&store.connection))?;
    assert!(
        !family,
        "refusal must not repair or reinstall the lost family"
    );
    Ok(())
}

mod public_knowledge;
