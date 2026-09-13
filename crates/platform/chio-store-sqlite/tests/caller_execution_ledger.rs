//! Executor custody tests with explicit signed authorizer fixtures. These do
//! not qualify a kernel start route; the effects and ledger are real.

#![cfg(unix)]

use chio_core::{canonical_json_bytes, sha256_hex, Keypair};
use chio_kernel::caller_delivery::*;
use chio_kernel::{CallerExecutionReport, KernelError};
use chio_store_sqlite::caller_execution_ledger::{
    CallerExecutionLedgerError, SqliteCallerExecutionLedger,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    directory: tempfile::TempDir,
    kernel: Keypair,
    executor: Keypair,
    authorization: SignedCallerDispatchAuthorizationV1,
}

fn fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let kernel = Keypair::from_seed(&[71; 32]);
    let executor = Keypair::from_seed(&[72; 32]);
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let operation = sha256_hex(b"executor-original-operation");
    let body = serde_json::from_value(serde_json::json!({
        "schema": CALLER_DISPATCH_AUTHORIZATION_SCHEMA,
        "kernel_public_key": kernel.public_key(),
        "executor": {"executor_id": "executor", "public_key": executor.public_key(), "key_epoch": 7},
        "invocation": {
            "operation_id": operation, "request_id": "request", "request_binding_hash": sha256_hex(b"request"),
            "capability_id": "capability", "capability_digest": sha256_hex(b"capability"),
            "server_id": "server", "tool_name": "mutate", "parameters_digest": sha256_hex(b"parameters"),
        },
        "committed": {
            "execution_nonce_id": "nonce", "budget_hold_id": "hold", "frozen_context_digest": sha256_hex(b"context"),
            "dispatch_commit": {
                "committed_version": 9, "coordinator_lease_id": "coordinator", "coordinator_lease_epoch": 3,
                "store_fence": {"store_uuid": "authority", "lease_id": "owner", "owner_epoch": 3},
                "provider_attempt": {"operation_id": operation, "attempt_id": "attempt", "transport_id": "caller-report:server", "transport_key_epoch": 7},
            },
        },
        "not_before_unix_ms": now - 1_000, "expires_at_unix_ms": now + 30_000,
    }))?;
    Ok(Fixture {
        directory,
        authorization: SignedCallerDispatchAuthorizationV1::sign(body, &kernel)?,
        kernel,
        executor,
    })
}

impl Fixture {
    fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("executor.sqlite3")
    }
    fn provision(&self, capacity: u32) -> TestResult<SqliteCallerExecutionLedger> {
        Ok(SqliteCallerExecutionLedger::provision(
            &self.path(),
            self.authorization.authorization.executor.clone(),
            capacity,
        )?)
    }
    fn open(&self) -> TestResult<SqliteCallerExecutionLedger> {
        Ok(SqliteCallerExecutionLedger::open(
            &self.path(),
            self.authorization.authorization.executor.clone(),
        )?)
    }
    fn execute(
        &self,
        ledger: &SqliteCallerExecutionLedger,
        effect: impl FnOnce() -> Result<CallerExecutionReport, KernelError>,
    ) -> Result<SignedCallerDeliveryReportV1, CallerExecutionLedgerError> {
        ledger.execute_once(
            &self.authorization,
            &self.kernel.public_key(),
            &self.authorization.authorization.invocation,
            &self.executor,
            effect,
        )
    }
}

fn returned() -> Result<CallerExecutionReport, KernelError> {
    Ok(CallerExecutionReport {
        output: serde_json::json!({"effect": "complete"}),
        realized_cost: None,
    })
}

#[test]
fn completed_delivery_replays_the_exact_report_after_reopen_without_another_effect() -> TestResult {
    let fixture = fixture()?;
    assert!(
        fixture.open().is_err(),
        "restart cannot provision missing history"
    );
    let ledger = fixture.provision(2)?;
    let effects = AtomicUsize::new(0);
    let first = fixture.execute(&ledger, || {
        effects.fetch_add(1, Ordering::SeqCst);
        returned()
    })?;
    drop(ledger);
    let ledger = fixture.open()?;
    let replay = fixture.execute(&ledger, || {
        effects.fetch_add(1, Ordering::SeqCst);
        returned()
    })?;
    assert_eq!(
        canonical_json_bytes(&first)?,
        canonical_json_bytes(&replay)?
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert!(
        fixture.provision(2).is_err(),
        "provision cannot replace history"
    );
    Ok(())
}

#[test]
fn expired_permission_can_replay_a_retained_report_but_cannot_execute() -> TestResult {
    let mut fixture = fixture()?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    let mut body = fixture.authorization.authorization.clone();
    body.expires_at_unix_ms = now + 2_000;
    fixture.authorization = SignedCallerDispatchAuthorizationV1::sign(body, &fixture.kernel)?;
    let ledger = fixture.provision(2)?;
    let first = fixture.execute(&ledger, returned)?;
    drop(ledger);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?
        < fixture.authorization.authorization.expires_at_unix_ms
    {
        if std::time::Instant::now() >= deadline {
            return Err("test clock did not reach permission expiry".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let ledger = fixture.open()?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    assert!(matches!(
        fixture.authorization.verify_for_claim(
            &fixture.kernel.public_key(),
            &fixture.authorization.authorization.executor,
            &fixture.authorization.authorization.invocation,
            now,
        ),
        Err(CallerDeliveryError::Expired)
    ));
    let invoked = AtomicUsize::new(0);
    let replay = fixture.execute(&ledger, || {
        invoked.fetch_add(1, Ordering::SeqCst);
        returned()
    })?;
    assert_eq!(replay.canonical_bytes()?, first.canonical_bytes()?);
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn substituted_key_epoch_or_physical_ledger_fails_closed() -> TestResult {
    let fixture = fixture()?;
    let ledger = fixture.provision(2)?;
    fixture.execute(&ledger, returned)?;
    for change_key in [false, true] {
        let mut identity = fixture.authorization.authorization.executor.clone();
        if change_key {
            identity.public_key = fixture.kernel.public_key();
        } else {
            identity.key_epoch += 1;
        }
        assert!(SqliteCallerExecutionLedger::open(&fixture.path(), identity).is_err());
    }
    let connection = rusqlite::Connection::open(fixture.path())?;
    let copy = fixture.directory.path().join("substituted.sqlite3");
    connection.execute("VACUUM INTO ?1", [copy.to_str().ok_or("test path")?])?;
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600))?;
    // VACUUM INTO defaults to a different journal profile. Match that profile
    // so this negative control actually reaches the physical-identity check.
    let copied = rusqlite::Connection::open(&copy)?;
    copied.execute_batch("PRAGMA journal_mode=WAL")?;
    drop(copied);
    assert!(
        matches!(SqliteCallerExecutionLedger::open(
            &copy,
            fixture.authorization.authorization.executor.clone(),
        ), Err(CallerExecutionLedgerError::Storage(message)) if message.contains("physical ledger")),
        "a copied ledger cannot acquire the original physical identity"
    );
    // Keep the original file recoverable, but remove its configured pathname.
    std::fs::rename(
        fixture.path(),
        fixture.directory.path().join("retained.sqlite3"),
    )?;
    let invoked = AtomicUsize::new(0);
    assert!(fixture
        .execute(&ledger, || {
            invoked.fetch_add(1, Ordering::SeqCst);
            returned()
        })
        .is_err());
    assert_eq!(invoked.load(Ordering::SeqCst), 0);
    assert!(fixture.open().is_err());
    Ok(())
}

#[test]
fn failed_or_panicking_effect_retains_an_unknown_attempt_across_restart() -> TestResult {
    for panic_effect in [false, true] {
        let fixture = fixture()?;
        let ledger = fixture.provision(2)?;
        let result = fixture.execute(&ledger, || {
            if panic_effect {
                panic!("executor effect interruption");
            }
            Err(KernelError::ToolServerError("lost downstream reply".into()))
        });
        assert!(matches!(
            result,
            Err(CallerExecutionLedgerError::OutcomeUnknown)
        ));
        drop(ledger);
        let ledger = fixture.open()?;
        let count = AtomicUsize::new(0);
        assert!(matches!(
            fixture.execute(&ledger, || {
                count.fetch_add(1, Ordering::SeqCst);
                returned()
            }),
            Err(CallerExecutionLedgerError::OutcomeUnknown)
        ));
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn independent_connections_race_one_operation_without_holding_sqlite_across_effect() -> TestResult {
    let fixture = fixture()?;
    let first = fixture.provision(2)?;
    let second = fixture.open()?;
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let count = AtomicUsize::new(0);
    std::thread::scope(|scope| -> TestResult {
        let fixture = &fixture;
        let count = &count;
        let worker = scope.spawn(move || {
            fixture.execute(&first, || {
                count.fetch_add(1, Ordering::SeqCst);
                entered_tx
                    .send(())
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
                release_rx
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
                returned()
            })
        });
        entered_rx.recv_timeout(std::time::Duration::from_secs(10))?;
        let duplicate = fixture.execute(&second, || {
            count.fetch_add(1, Ordering::SeqCst);
            returned()
        });
        release_tx.send(())?;
        assert!(matches!(
            duplicate,
            Err(CallerExecutionLedgerError::OutcomeUnknown)
        ));
        worker.join().map_err(|_| "executor worker panicked")??;
        Ok(())
    })?;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn another_attempt_or_kernel_signing_key_cannot_create_a_second_execution() -> TestResult {
    let fixture = fixture()?;
    let ledger = fixture.provision(2)?;
    fixture.execute(&ledger, returned)?;
    let effects = AtomicUsize::new(0);
    for rotate_kernel in [false, true] {
        let mut body = fixture.authorization.authorization.clone();
        let key = if rotate_kernel {
            Keypair::from_seed(&[73; 32])
        } else {
            fixture.kernel.clone()
        };
        body.kernel_public_key = key.public_key();
        if !rotate_kernel {
            body.committed
                .dispatch_commit
                .provider_attempt
                .as_mut()
                .ok_or("attempt")?
                .attempt_id = "replacement-attempt".into();
        }
        let changed = SignedCallerDispatchAuthorizationV1::sign(body, &key)?;
        let denied = ledger.execute_once(
            &changed,
            &key.public_key(),
            &changed.authorization.invocation,
            &fixture.executor,
            || {
                effects.fetch_add(1, Ordering::SeqCst);
                returned()
            },
        );
        assert!(denied.is_err());
    }
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn expired_or_untrusted_authorization_never_claims_or_invokes() -> TestResult {
    let fixture = fixture()?;
    let ledger = fixture.provision(1)?;
    let mut body = fixture.authorization.authorization.clone();
    body.expires_at_unix_ms = body.not_before_unix_ms + 1;
    let expired = SignedCallerDispatchAuthorizationV1::sign(body, &fixture.kernel)?;
    let effects = AtomicUsize::new(0);
    for (authorization, trusted) in [
        (&expired, fixture.kernel.public_key()),
        (&fixture.authorization, fixture.executor.public_key()),
    ] {
        assert!(ledger
            .execute_once(
                authorization,
                &trusted,
                &fixture.authorization.authorization.invocation,
                &fixture.executor,
                || {
                    effects.fetch_add(1, Ordering::SeqCst);
                    returned()
                }
            )
            .is_err());
    }
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    fixture.execute(&ledger, returned)?;
    Ok(())
}

#[test]
fn full_ledger_and_changed_schema_do_not_reset_retained_claims() -> TestResult {
    let fixture = fixture()?;
    let ledger = fixture.provision(1)?;
    fixture.execute(&ledger, returned)?;
    let mut body = fixture.authorization.authorization.clone();
    let operation = sha256_hex(b"second-operation");
    body.invocation.operation_id =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(&operation)?;
    body.committed
        .dispatch_commit
        .provider_attempt
        .as_mut()
        .ok_or("attempt")?
        .operation_id = operation;
    let second = SignedCallerDispatchAuthorizationV1::sign(body, &fixture.kernel)?;
    assert!(matches!(
        ledger.execute_once(
            &second,
            &fixture.kernel.public_key(),
            &second.authorization.invocation,
            &fixture.executor,
            returned
        ),
        Err(CallerExecutionLedgerError::Capacity)
    ));
    let connection = rusqlite::Connection::open(fixture.path())?;
    for statement in [
        "DELETE FROM caller_executor_claims",
        "UPDATE caller_executor_claims SET claim_id='replacement'",
        "DELETE FROM caller_executor_reports",
        "INSERT OR REPLACE INTO caller_executor_claims SELECT * FROM caller_executor_claims",
        "DELETE FROM caller_executor_clock",
        "UPDATE caller_executor_clock SET high_water_unix_ms=1",
        "INSERT OR REPLACE INTO caller_executor_clock SELECT * FROM caller_executor_clock",
    ] {
        assert!(
            connection.execute(statement, []).is_err(),
            "allowed {statement}"
        );
    }
    connection.execute_batch("DROP TRIGGER caller_executor_claims_no_delete")?;
    assert!(fixture.execute(&ledger, returned).is_err());
    drop(ledger);
    assert!(
        fixture.open().is_err(),
        "restart cannot repair a missing barrier"
    );
    Ok(())
}

#[test]
fn claimed_attempt_survives_process_death_without_redispatch() -> TestResult {
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    const CHILD_ROOT: &str = "CHIO_CALLER_LEDGER_M3_CHILD_ROOT";
    const CHILD_CUT: &str = "CHIO_CALLER_LEDGER_M3_CHILD_CUT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let root = std::path::PathBuf::from(root);
        let authorization = SignedCallerDispatchAuthorizationV1::from_canonical_bytes(
            &std::fs::read(root.join("authorization.json"))?,
        )?;
        let ledger = SqliteCallerExecutionLedger::open(
            &root.join("executor.sqlite3"),
            authorization.authorization.executor.clone(),
        )?;
        let cut = std::env::var(CHILD_CUT)?;
        ledger.execute_once(
            &authorization,
            &Keypair::from_seed(&[71; 32]).public_key(),
            &authorization.authorization.invocation,
            &Keypair::from_seed(&[72; 32]),
            || {
                if cut != "before-effect" {
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(root.join("effect"))
                        .map_err(|error| KernelError::Internal(error.to_string()))?;
                    file.write_all(b"effect\n")
                        .and_then(|()| file.sync_all())
                        .map_err(|error| KernelError::Internal(error.to_string()))?;
                }
                if cut == "after-report" {
                    return returned();
                }
                let mut marker = std::fs::File::create(root.join("cutpoint"))
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
                marker
                    .write_all(cut.as_bytes())
                    .and_then(|()| marker.sync_all())
                    .map_err(|error| KernelError::Internal(error.to_string()))?;
                std::process::abort();
            },
        )?;
        if cut == "after-report" {
            // The caller has received no report. Only the executor's durable
            // ledger can recover it after this process exits abruptly.
            let mut marker = std::fs::File::create(root.join("cutpoint"))?;
            marker.write_all(cut.as_bytes())?;
            marker.sync_all()?;
            std::process::abort();
        }
        return Err("child did not reach its abort cutpoint".into());
    }
    for cut in ["before-effect", "after-effect", "after-report"] {
        let fixture = fixture()?;
        drop(fixture.provision(2)?);
        std::fs::write(
            fixture.directory.path().join("authorization.json"),
            fixture.authorization.canonical_bytes()?,
        )?;
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "claimed_attempt_survives_process_death_without_redispatch",
                "--nocapture",
            ])
            .env(CHILD_ROOT, fixture.directory.path())
            .env(CHILD_CUT, cut)
            .stdout(std::process::Stdio::null())
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err("executor crash child exceeded its deadline".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            status.signal(),
            Some(6),
            "child failed outside its selected cutpoint: {cut}"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.directory.path().join("cutpoint"))?,
            cut
        );
        let effect = fixture.directory.path().join("effect");
        if cut != "before-effect" {
            assert_eq!(std::fs::read(&effect)?, b"effect\n");
        } else {
            assert!(!effect.exists());
        }
        let ledger = fixture.open()?;
        let invoked = AtomicUsize::new(0);
        let replay = fixture.execute(&ledger, || {
            invoked.fetch_add(1, Ordering::SeqCst);
            returned()
        });
        if cut == "after-report" {
            let report = replay?;
            report.verify(
                &fixture.authorization,
                &fixture.kernel.public_key(),
                &fixture.authorization.authorization.executor,
                &fixture.authorization.authorization.invocation,
            )?;
            assert_eq!(report.report.output, returned()?.output);
            let connection = rusqlite::Connection::open(fixture.path())?;
            let retained: Vec<u8> =
                connection.query_row("SELECT report FROM caller_executor_reports", [], |row| {
                    row.get(0)
                })?;
            assert_eq!(report.canonical_bytes()?, retained);
        } else {
            assert!(matches!(
                replay,
                Err(CallerExecutionLedgerError::OutcomeUnknown)
            ));
        }
        assert_eq!(invoked.load(Ordering::SeqCst), 0);
        if cut != "before-effect" {
            assert_eq!(std::fs::read(effect)?, b"effect\n");
        }
    }
    Ok(())
}
