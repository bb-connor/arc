//! Abrupt loss of the real kernel and executor process, not a dropped future.
use super::*;
use chio_store_sqlite::caller_execution_ledger::{
    CallerExecutionLedgerError, SqliteCallerExecutionLedger,
};
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};

const ROOT: &str = "CHIO_M3_CRASH_ROOT";
const CUT: &str = "CHIO_M3_CRASH_CUT";

fn persist(path: &Path, bytes: &[u8]) -> TestResult {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[test]
fn process_loss_retains_capture_and_never_reexecutes_original_attempt() -> TestResult {
    if let Some(root) = std::env::var_os(ROOT) {
        let root = std::path::PathBuf::from(root);
        let cut = std::env::var(CUT)?;
        let mut fixture = Fixture::attach(
            root.clone(),
            &std::env::var("CHIO_M3_KERNEL_SEED")?,
            &std::env::var("CHIO_M3_AGENT_SEED")?,
        )?;
        let key = Keypair::from_seed_hex(&std::env::var("CHIO_M3_EXECUTOR_SEED")?)?;
        let executor = CallerExecutorIdentityV1 {
            executor_id: AdmissionIdentifier::try_new("executor_id", "trusted-test-executor")?,
            public_key: key.public_key(),
            key_epoch: 42,
        };
        fixture.nonce_ttl_secs = 300;
        fixture.caller_executor = Some(executor.clone());
        let runtime = fixture.open()?;
        let request = reserve(&fixture, &runtime, "process-loss-caller")?;
        let authorization = start(&runtime, &request)?;
        assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        persist(
            &root.join("request.json"),
            &chio_core::canonical::canonical_json_bytes(&request)?,
        )?;
        persist(
            &root.join("authorization.json"),
            &authorization.canonical_bytes()?,
        )?;
        let ledger = SqliteCallerExecutionLedger::open(&root.join("executor.db"), executor)?;
        ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &key,
            || {
                persist(&root.join("effect"), b"exactly one external effect\n").map_err(
                    |error| chio_kernel::KernelError::ToolServerError(error.to_string()),
                )?;
                if cut == "after-effect" {
                    std::process::abort();
                }
                Ok(super::super::report())
            },
        )?;
        if cut == "after-report" {
            persist(
                &root.join("report-persisted"),
                b"report returned only to crashed executor\n",
            )?;
            std::process::abort();
        }
        return Err("child missed its selected process-loss cutpoint".into());
    }
    for cut in ["after-effect", "after-report"] {
        let (fixture, executor_key) = fixture()?;
        let root = fixture.directory.path();
        let executor = fixture.caller_executor.clone().ok_or("executor")?;
        drop(SqliteCallerExecutionLedger::provision(
            &root.join("executor.db"),
            executor.clone(),
            4,
        )?);
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", "authenticated::process_loss::process_loss_retains_capture_and_never_reexecutes_original_attempt", "--nocapture"])
            .env(ROOT, root).env(CUT, cut)
            .env("CHIO_M3_KERNEL_SEED", fixture.signer.seed_hex())
            .env("CHIO_M3_AGENT_SEED", fixture.agent.seed_hex())
            .env("CHIO_M3_EXECUTOR_SEED", executor_key.seed_hex())
            .stdin(Stdio::null()).stdout(Stdio::null()).spawn()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
                return Err("caller crash child exceeded its deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            status.signal(),
            Some(6),
            "child failed outside its crash cutpoint"
        );
        let request: ToolCallRequest =
            serde_json::from_slice(&std::fs::read(root.join("request.json"))?)?;
        let authorization = SignedCallerDispatchAuthorizationV1::from_canonical_bytes(
            &std::fs::read(root.join("authorization.json"))?,
        )?;
        assert_eq!(
            std::fs::read(root.join("effect"))?,
            b"exactly one external effect\n"
        );
        let expires = authorization.authorization.expires_at_unix_ms / 1_000;
        assert!(
            expires + 1 < request.capability.expires_at,
            "quota denial must not be capability expiry"
        );
        let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires + 1, []);
        let runtime = fixture.open()?;
        assert_state(&fixture, &request, "awaiting_caller_report")?;
        assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
        let mut second = request.clone();
        second.request_id = "second-after-process-loss".into();
        second.execution_nonce = None;
        assert_eq!(
            runtime
                .kernel
                .reserve_caller_execution_blocking(&second)?
                .verdict,
            Verdict::Deny
        );
        let ledger = SqliteCallerExecutionLedger::open(&root.join("executor.db"), executor)?;
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let recovered = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &executor_key,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(super::super::report())
            },
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "recovery cannot execute the effect again"
        );
        if cut == "after-effect" {
            assert!(matches!(
                recovered,
                Err(CallerExecutionLedgerError::OutcomeUnknown)
            ));
            assert_state(&fixture, &request, "awaiting_caller_report")?;
        } else {
            let report = recovered?;
            let completed = runtime
                .kernel
                .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
            assert_eq!(completed.verdict, Verdict::Allow, "{:?}", completed.reason);
            assert!(
                completed.execution_nonce.is_none(),
                "historical delivery cannot issue fresh permission"
            );
            assert_state(&fixture, &request, "completed")?;
        }
        assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    }
    Ok(())
}
