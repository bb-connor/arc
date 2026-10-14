//! Native ownership must distinguish local connector refusals from dispatched work.
use super::*;
use crate::recovery::connector::capacity_test_support;
use crate::recovery::{PinnedSupportIssueConnector, RecoveryRuntimeError};
use chio_egress_contract::HttpEgressContract;
use std::collections::BTreeSet;
use std::time::Duration;

#[path = "connector_resources/lookup_spacing.rs"]
mod lookup_spacing;
#[path = "connector_resources/submission_admission.rs"]
mod submission_admission;

struct NativeObservationHold {
    release: std::sync::mpsc::Sender<()>,
    holder: Option<
        std::thread::JoinHandle<
            Result<(), chio_kernel::admission_operation::AdmissionOperationStoreError>,
        >,
    >,
}
impl NativeObservationHold {
    fn start(
        store: chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore,
    ) -> TestResult<Self> {
        let (entered, wait_for_entry) = std::sync::mpsc::sync_channel(1);
        let (release, wait_for_release) = std::sync::mpsc::channel();
        let holder = std::thread::Builder::new()
            .name("lookup-native-authentication-holder".into())
            .spawn(move || {
                store.hold_current_connection_for_authentication_test(entered, wait_for_release)
            })?;
        let hold = Self {
            release,
            holder: Some(holder),
        };
        wait_for_entry.recv_timeout(Duration::from_secs(2))?;
        Ok(hold)
    }
    fn finish(mut self) -> TestResult {
        if let Some(holder) = self.holder.take() {
            holder
                .join()
                .map_err(|_| "lookup authentication holder panicked")??;
        }
        Ok(())
    }
}
impl Drop for NativeObservationHold {
    fn drop(&mut self) {
        let _ = self.release.send(());
        if let Some(holder) = self.holder.take() {
            let _ = holder.join();
        }
    }
}

fn pinned_connector(contract: RecoveryEffectContractV1) -> TestResult<PinnedSupportIssueConnector> {
    let url = reqwest::Url::parse(contract.resource.as_str())?;
    let host = url.host_str().ok_or("connector host is absent")?;
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    Ok(PinnedSupportIssueConnector::new(
        "server-a".into(),
        "send".into(),
        contract,
        HttpEgressContract {
            tenant_egress_namespace: "tests.recovery.connector-resources".into(),
            allowed_schemes: BTreeSet::from(["https".into()]),
            allowed_authority_set: BTreeSet::from([authority]),
            deny_loopback: false,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 65536,
        },
        "submission-fixture-secret".into(),
        "observation-fixture-secret".into(),
    )?)
}

fn native_original(fixture: &RecoveryFixture, workflow: &WorkflowId) -> TestResult<Vec<u8>> {
    let record = fixture.record(workflow)?;
    let intent = record
        .admission
        .as_ref()
        .ok_or("native original is absent")?;
    let operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                intent.native_operation_id.as_str(),
            )?,
        )?
        .ok_or("retained native original is absent")?;
    Ok(chio_core::canonical_json_bytes(&operation.to_persisted())?)
}

async fn unknown_original(fixture: &RecoveryFixture) -> TestResult<WorkflowId> {
    let workflow = Box::pin(fixture.ready()).await?;
    fixture.behavior.store(1, Ordering::SeqCst);
    let result = fixture
        .execute(
            "capture-unacknowledged-original",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: fixture.record(&workflow)?.revision,
            },
        )
        .await?;
    assert!(matches!(
        result.status.effect,
        EffectObservationV1::Unknown { .. }
    ));
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.record(&workflow)?.provider_lookups.get(), 0);
    Ok(workflow)
}

#[tokio::test]
async fn saturated_submission_closes_native_admission_before_dispatch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let locks = directory.path().join("locks");
    std::fs::create_dir(&locks)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("admission.db");
    SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let ca = Keypair::from_seed(&[182; 32]);
    let agent = Keypair::from_seed(&[183; 32]);
    let (mut kernel, _) = bootstrap::open_kernel(directory.path(), &authority, &ca)?;
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;

    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let mut contract = authority_history::fixture_effect_contract(directory.path())?;
    contract.resource = ProtectedText::new(&format!("https://{}/issues", listener.local_addr()?,))?;
    let connector = pinned_connector(contract)?;
    let held_capacity = capacity_test_support::hold_submission_capacity(&connector)?;
    kernel.register_tool_server(Box::new(connector));
    kernel.reconcile_durable_admission_startup()?;
    let capability = kernel.issue_capability(
        &agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "server-a".into(),
                tool_name: "send".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(4),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        },
        600,
    )?;
    let kernel = Arc::new(kernel);
    let process = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    process.create_root(
        "root",
        &capability,
        ProcessLimits {
            max_processes: 1,
            max_depth: 1,
            max_calls: 4,
            state: Default::default(),
        },
    )?;
    let request = process.tool_request(
        "root",
        "saturated-connector",
        "server-a",
        "send",
        serde_json::json!({"title":"support", "body":"private-connector-canary"}),
    )?;
    // The actual Process route retains the caller namespace and original-only
    // binding. A direct kernel call omits those owning admission prerequisites.
    let response = process
        .invoke_known_only("root", "saturated-connector", &request)
        .await?;
    let (original, _) = authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("native capacity refusal is not retained")?;
    let connection = listener.accept();
    drop(held_capacity);
    eprintln!(
        "CONNECTOR_NATIVE_CAPACITY state={:?} dispatch_commit={} verdict={:?} provider_connected={}",
        original.state(),
        original.dispatch_commit().is_some(),
        response.verdict,
        connection.is_ok(),
    );
    assert!(matches!(connection, Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(
        original.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(original.dispatch_commit().is_none());
    assert!(request.execution_nonce.is_none());
    assert!(response.execution_nonce.is_none());
    assert!(original.execution_nonce_id().is_none());
    assert_eq!(process.process("root")?.tree_calls, 1);
    let usage = authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&capability.id, 0))?
        .ok_or("native capacity refusal quota is absent")?;
    assert_eq!(
        (usage.reserved_invocations, usage.captured_invocations),
        (0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn saturated_lookup_preserves_original_attempt_budget() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = Box::pin(unknown_original(&fixture)).await?;
    let original = native_original(&fixture, &workflow)?;
    let connector = pinned_connector(authority_history::fixture_effect_contract(&fixture.path)?)?;
    let _held_capacity = capacity_test_support::hold_lookup_capacity(&connector)?;
    for _ in 0..32 {
        let result = Box::pin(fixture.runtime.settle_from_provider(
            &fixture.control,
            &workflow,
            &connector,
        ))
        .await;
        let record = fixture.record(&workflow)?;
        eprintln!(
            "CONNECTOR_LOOKUP_CAPACITY result={result:?} provider_lookups={}",
            record.provider_lookups.get(),
        );
        assert!(result.is_err());
        assert_eq!(record.provider_lookups.get(), 0);
        assert_eq!(result.err(), Some(RecoveryRuntimeError::Unavailable));
        assert!(matches!(record.effect, EffectObservationV1::Unknown { .. }));
        assert_eq!(native_original(&fixture, &workflow)?, original);
        assert_eq!(external_count(&fixture.path)?, 1);
    }
    Ok(())
}

#[tokio::test]
async fn insufficient_lookup_deadline_preserves_original_attempt_budget() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = Box::pin(unknown_original(&fixture)).await?;
    let original = native_original(&fixture, &workflow)?;
    let connector = pinned_connector(authority_history::fixture_effect_contract(&fixture.path)?)?;
    let short_control = fixture.kernel.issue_capability(
        &fixture.approval_key.public_key(),
        fixture.control.scope.clone(),
        10,
    )?;
    let result = Box::pin(fixture.runtime.settle_from_provider(
        &short_control,
        &workflow,
        &connector,
    ))
    .await;
    let record = fixture.record(&workflow)?;
    eprintln!(
        "CONNECTOR_LOOKUP_DEADLINE result={result:?} provider_lookups={}",
        record.provider_lookups.get(),
    );
    assert!(result.is_err());
    assert_eq!(record.provider_lookups.get(), 0);
    assert_eq!(result.err(), Some(RecoveryRuntimeError::Unavailable));
    assert!(matches!(record.effect, EffectObservationV1::Unknown { .. }));
    assert_eq!(native_original(&fixture, &workflow)?, original);
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn repeated_lookup_is_spaced_by_durable_original_observation() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = Box::pin(unknown_original(&fixture)).await?;
    let original = native_original(&fixture, &workflow)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Settle,
    )?;
    // Select only the existing trusted clock test port. Actual authority
    // transactions and immutable event timestamps use this same clock; disk
    // latency cannot turn an immediate logical attempt into a spaced one.
    let selected = now_ms()?.checked_add(999).ok_or("fixture clock overflow")? / 1000;
    let clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(selected);
    let first = fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)?;
    assert_eq!(first.workflow().provider_lookups.get(), 1);
    let second = fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow);
    eprintln!(
        "CONNECTOR_LOOKUP_SPACING selected_unix_secs={selected} second={:?} provider_lookups={}",
        second
            .as_ref()
            .map(|_| "reserved")
            .map_err(ToString::to_string),
        fixture.record(&workflow)?.provider_lookups.get(),
    );
    assert!(
        second.is_err(),
        "an immediate observation spent another durable attempt"
    );
    assert_eq!(fixture.record(&workflow)?.provider_lookups.get(), 1);
    drop(clock);
    let _clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(
        selected.checked_add(1).ok_or("fixture clock overflow")?,
    );
    let spaced = fixture
        .kernel
        .reserve_recovery_provider_lookup(&actor, &workflow)?;
    assert_eq!(spaced.workflow().provider_lookups.get(), 2);
    assert_eq!(native_original(&fixture, &workflow)?, original);
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn provider_lookup_authentication_keeps_the_callers_executor_running() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = Box::pin(unknown_original(&fixture)).await?;
    let original = native_original(&fixture, &workflow)?;
    let connector = pinned_connector(authority_history::fixture_effect_contract(&fixture.path)?)?;
    let _capacity = capacity_test_support::hold_lookup_capacity(&connector)?;
    let hold = NativeObservationHold::start(fixture.authority.admission_operation_store())?;
    let release = hold.release.clone();
    let (progress, wait_for_progress) = std::sync::mpsc::sync_channel(1);
    let watchdog = std::thread::Builder::new()
        .name("lookup-native-authentication-watchdog".into())
        .spawn(move || {
            let responsive = wait_for_progress
                .recv_timeout(Duration::from_secs(2))
                .is_ok();
            // Always release actual native ownership before any assertion.
            let released = release.send(()).is_ok();
            (responsive, released)
        })?;
    let heartbeat = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        progress.send(()).is_ok()
    });
    tokio::task::yield_now().await;
    let result = Box::pin(fixture.runtime.settle_from_provider(
        &fixture.control,
        &workflow,
        &connector,
    ))
    .await;
    let (responsive, released) = watchdog
        .join()
        .map_err(|_| "lookup authentication watchdog panicked")?;
    hold.finish()?;
    let heartbeat = heartbeat.await?;
    eprintln!(
        "CONNECTOR_LOOKUP_EXECUTOR responsive={responsive} released={released} heartbeat={heartbeat} result={result:?}",
    );
    assert!(released);
    assert!(
        responsive,
        "provider lookup authentication blocked the only executor until the native holder timed out",
    );
    assert!(heartbeat);
    assert_eq!(result.err(), Some(RecoveryRuntimeError::Unavailable));
    assert_eq!(fixture.record(&workflow)?.provider_lookups.get(), 0);
    assert_eq!(native_original(&fixture, &workflow)?, original);
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn native_lookup_writer_checks_the_configured_budget_without_renewing_authority() -> TestResult
{
    let fixture = RecoveryFixture::new(false)?;
    let workflow = Box::pin(unknown_original(&fixture)).await?;
    let original = native_original(&fixture, &workflow)?;
    let capability = fixture.kernel.issue_capability(
        &fixture.approval_key.public_key(),
        fixture.control.scope.clone(),
        10,
    )?;
    let selected = now_ms()?.checked_add(999).ok_or("fixture clock overflow")? / 1000;
    let _clock = chio_kernel::scope_fixed_runtime_clock_for_current_thread(selected);
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &capability,
        RecoveryPermission::Settle,
    )?;
    let insufficient = fixture.kernel.reserve_recovery_provider_lookup_with_budget(
        &actor,
        &workflow,
        RecoveryProviderLookupBudget::from_duration(Duration::from_secs(20))?,
    );
    assert!(insufficient.is_err());
    assert_eq!(fixture.record(&workflow)?.provider_lookups.get(), 0);
    // A genuinely smaller configured transport remains eligible. This also
    // rules out an Unsupported port or a blanket fixed twenty-second check.
    let budget = RecoveryProviderLookupBudget::from_duration(Duration::from_millis(500))?;
    let eligible = fixture
        .kernel
        .reserve_recovery_provider_lookup_with_budget(&actor, &workflow, budget)?;
    assert_eq!(eligible.workflow().provider_lookups.get(), 1);
    assert_eq!(eligible.request_budget(), Some(budget));
    assert_eq!(eligible.expires_at_unix_ms(), capability.expires_at * 1000);
    assert_eq!(native_original(&fixture, &workflow)?, original);
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}
