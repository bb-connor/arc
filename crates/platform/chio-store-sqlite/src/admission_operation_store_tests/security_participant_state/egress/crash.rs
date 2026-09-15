use super::*;

#[test]
fn child_process_crash() -> AnchoredTestResult {
    let Some(directory) = std::env::var_os("CHIO_NATIVE_EGRESS_CRASH_DIRECTORY") else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    let database = directory.join("authority.db");
    let lock_root = directory.join("locks");
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fixture = Fixture {
        _temp: tempfile::tempdir()?,
        database,
        lock_root,
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
    };
    let (operation, retained) = fixture
        .store
        .load_unambiguous_retained_tool_request(
            &identifier("request", "egress-crash"),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("crash operation absent")?;
    let initialized = fixture
        .store
        .load_security_participant_state(
            &identifier("authority", "source"),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("crash initialization absent")?;
    let joined = fixture
        .store
        .load_security_participant_flow_join(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("crash join absent")?;
    let snapshot = joined.historical_snapshot();
    let (context, _) = mutations::request("crash-context")?;
    let context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(snapshot.context_generation),
    );
    let request = retained.request_for_revalidation().clone();
    let hash: [u8; 32] = hex::decode(operation.binding().action_parameter_hash().as_str())?
        .try_into()
        .map_err(|_| "action digest width")?;
    let plan = EgressFenceRequest {
        key: snapshot.key.clone(),
        request_id: RequestId::new("egress-crash")?,
        request_hash: Digest32::new(hash),
        expected_context_generation: snapshot.context_generation,
        expires_at_unix_ms: std::env::var("CHIO_NATIVE_EGRESS_CRASH_EXPIRY")?.parse()?,
    };
    let lease = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant", "crash-worker"),
        now_ms(),
        now_ms() + 120_000,
        &fixture.fence,
    )?;
    let pending = Pending {
        operation,
        lease,
        initialized,
        context,
        request,
        plan,
    };
    if std::env::var("CHIO_NATIVE_EGRESS_CRASH_PHASE")? == "commit" {
        let history = fixture
            .store
            .load_security_participant_egress(
                pending.operation.binding().operation_id(),
                &fixture.fence,
                now_ms(),
            )?
            .ok_or("crash acquisition absent")?;
        pending.commit(&fixture, &commitment(history.historical_fence())?)?;
    } else {
        pending.acquire(&fixture)?;
    }
    Err("child did not reach native egress cutpoint".into())
}

#[test]
fn independent_process_abort_recovers_acquire_and_commit_without_partial_custody(
) -> AnchoredTestResult {
    use std::os::unix::process::ExitStatusExt as _;
    for commit_phase in [false, true] {
        for stage in 12..=16 {
            let fixture = fixture();
            hydrate(&fixture, &imported(&fixture, "source")?)?;
            let mut pending = pending(&fixture, "egress-crash", None)?;
            let planned_commitment = if commit_phase {
                Some(commitment(&pending.acquire(&fixture)?)?)
            } else {
                None
            };
            let before = counts(&fixture)?;
            let Fixture {
                _temp,
                database,
                lock_root,
                authority,
                store,
                ..
            } = fixture;
            drop(store);
            drop(authority);
            let output = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "admission_operation_store::tests::security_participant_state::egress::crash::child_process_crash", "--nocapture"])
                .env("CHIO_SECURITY_NATIVE_CRASH_STAGE", stage.to_string())
                .env("CHIO_NATIVE_EGRESS_CRASH_DIRECTORY", _temp.path())
                .env("CHIO_NATIVE_EGRESS_CRASH_EXPIRY", pending.plan.expires_at_unix_ms.to_string())
                .env("CHIO_NATIVE_EGRESS_CRASH_PHASE", if commit_phase { "commit" } else { "acquire" })
                .current_dir(_temp.path()).output()?;
            assert_eq!(
                output.status.signal(),
                Some(6),
                "commit {commit_phase}, stage {stage}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
            let fixture = Fixture {
                _temp,
                database,
                lock_root,
                store: authority.admission_operation_store(),
                fence: authority.mutation_fence(),
                authority,
            };
            assert_eq!(counts(&fixture)?.0, before.0 + i64::from(stage >= 15));
            pending.operation = fixture
                .store
                .load_by_operation_id(pending.operation.binding().operation_id())?
                .ok_or("operation absent")?;
            pending.lease = renew(&fixture, &pending.operation, &pending.lease)?;
            match &planned_commitment {
                Some(previous) => {
                    let history = fixture
                        .store
                        .load_security_participant_egress(
                            pending.operation.binding().operation_id(),
                            &fixture.fence,
                            now_ms(),
                        )?
                        .ok_or("acquisition absent after commit crash")?;
                    let mut retry = commitment(&previous.fence)?;
                    if let Some(committed) = history.historical_commitment() {
                        retry.dispatch_commitment_id = committed.dispatch_commitment_id.clone();
                        retry.committed_at_unix_ms = committed.committed_at_unix_ms;
                    }
                    pending.commit(&fixture, &retry)?;
                }
                None => {
                    pending.acquire(&fixture)?;
                }
            }
            assert_eq!(counts(&fixture)?.0, before.0 + 1);
            native::verify_coverage(&*fixture.store.connection()?)?;
        }
    }
    Ok(())
}
