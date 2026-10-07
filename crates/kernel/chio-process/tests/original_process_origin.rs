//! Exact, read-only provenance of a process journal's original first attempt.
mod support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core_types::{Keypair, SignedDeclassificationGrant};
use chio_kernel::recovery::RecoveryProcessOriginPort;
use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection, Verdict,
};
use chio_process::{ProcessRoute, ProcessRuntime, ProcessSecurityProfile};
use chio_security_types::recovery::{
    AuthorityDomainId, ProcessId, RecoveryScopeV1, RecoveryTenantId,
};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use support::Result;

struct CountingServer(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "tools"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["append".into(), "read".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

fn scope(kernel: &ChioKernel, process: &str, tenant: &str) -> Result<RecoveryScopeV1> {
    Ok(RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new(
            kernel.durable_authority_id().ok_or("authority")?,
        )?,
        tenant_id: RecoveryTenantId::new(tenant)?,
        process_id: ProcessId::new(process)?,
    })
}

struct LegacyJournal {
    _directory: tempfile::TempDir,
    kernel: Arc<ChioKernel>,
    runtime: ProcessRuntime,
    request: ToolCallRequest,
    scope: RecoveryScopeV1,
    database: PathBuf,
}

impl LegacyJournal {
    fn new(
        known_only: bool,
        with_route: bool,
        with_profile: bool,
        attempted: bool,
    ) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let kernel = support::kernel(
            directory.path(),
            Box::new(CountingServer(Arc::new(AtomicUsize::new(0)))),
        )?;
        let database = directory.path().join("process.db");
        drop(ProcessRuntime::open(&database, kernel.clone())?);
        let vector: Value = serde_json::from_str(include_str!(
            "../../../../spec/vectors/recovery/v1/legacy-process-binding.json"
        ))?;
        let connection = Connection::open(&database)?;
        connection.execute(
            "UPDATE process_runtime SET namespace=?1 WHERE singleton=1",
            [vector["namespace"].as_str().ok_or("namespace")?],
        )?;
        let mut runtime = ProcessRuntime::open(&database, kernel.clone())?;
        let request: ToolCallRequest = serde_json::from_value(vector["request"].clone())?;
        runtime.create_root("root", &request.capability, support::limits(8))?;
        if with_route {
            runtime = runtime.with_routes([(
                request.server_id.clone(),
                ProcessRoute::new("bridge-a", "provider-a", "route-a")?,
            )])?;
        }
        if with_profile {
            runtime = runtime
                .with_security_profile(serde_json::from_value(vector["profile"].clone())?)?;
        }
        if attempted {
            // The fixed predecessor digest was derived independently in Python.
            // The port cannot synthesize a passing journal with its own helper.
            let case = vector["cases"]
                .as_array()
                .ok_or("cases")?
                .iter()
                .find(|case| {
                    case["known_outcome_only"] == known_only
                        && case["with_route"] == with_route
                        && case["with_profile"] == with_profile
                })
                .ok_or("case")?;
            connection.execute(
                "INSERT INTO process_calls(process_id,operation_key,request_hash) VALUES('root',?1,?2)",
                params![vector["operation_key"].as_str().ok_or("operation key")?, case["binding_hash"].as_str().ok_or("binding")?],
            )?;
            connection.execute("UPDATE processes SET tree_calls=1 WHERE id='root'", [])?;
        }
        let scope = scope(&kernel, "root", "legacy-tenant")?;
        Ok(Self {
            _directory: directory,
            kernel,
            runtime,
            request,
            scope,
            database,
        })
    }

    fn verify(&self, request: &ToolCallRequest) -> Result {
        self.runtime
            .verify_original_request(&self.scope, request, self.runtime.runtime_id())?;
        Ok(())
    }

    fn accounting(&self) -> Result<(i64, i64, i64, i64)> {
        accounting(&self.database)
    }
}

fn accounting(database: &std::path::Path) -> Result<(i64, i64, i64, i64)> {
    Ok(Connection::open(database)?.query_row(
        "SELECT (SELECT COALESCE(SUM(tree_calls),0) FROM processes),
                (SELECT COALESCE(SUM(attempts),0) FROM process_calls),
                (SELECT COUNT(*) FROM process_recovery_calls),
                (SELECT COUNT(*) FROM process_call_nonces)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?)
}

#[test]
fn original_process_binding_accepts_both_modes_with_exact_current_routes_and_profiles() -> Result {
    for known_only in [false, true] {
        for with_route in [false, true] {
            for with_profile in [false, true] {
                let journal = LegacyJournal::new(known_only, with_route, with_profile, true)?;
                let before = journal.accounting()?;
                assert!(
                    journal.verify(&journal.request).is_ok(),
                    "unchanged first attempt refused: known_only={known_only}, route={with_route}, profile={with_profile}"
                );
                journal.verify(&journal.request)?;
                assert_eq!(journal.accounting()?, before);
            }
        }
    }
    Ok(())
}

#[test]
fn original_process_binding_refuses_unattempted_and_absent_process_calls() -> Result {
    let journal = LegacyJournal::new(false, false, false, false)?;
    let before = journal.accounting()?;
    assert!(journal.verify(&journal.request).is_err());
    let mut absent = journal.scope.clone();
    absent.process_id = ProcessId::new("absent")?;
    assert!(journal
        .runtime
        .verify_original_request(&absent, &journal.request, journal.runtime.runtime_id(),)
        .is_err());
    assert_eq!(journal.accounting()?, before);
    Ok(())
}

#[test]
fn original_process_binding_refuses_changed_route_profile_tenant_and_session() -> Result {
    let journal = LegacyJournal::new(true, true, true, true)?;
    let before = journal.accounting()?;
    let changed_route = journal.runtime.clone().with_routes([(
        journal.request.server_id.clone(),
        ProcessRoute::new("bridge-a", "provider-a", "different-route")?,
    )])?;
    let no_route = journal.runtime.clone().with_routes([])?;
    let changed_profile =
        journal
            .runtime
            .clone()
            .with_security_profile(ProcessSecurityProfile {
                tenant_id: "legacy-tenant".into(),
                isolation_epoch_id: "legacy-epoch".into(),
                generation: 2,
            })?;
    let no_profile =
        ProcessRuntime::open(&journal.database, journal.kernel.clone())?.with_routes([(
            journal.request.server_id.clone(),
            ProcessRoute::new("bridge-a", "provider-a", "route-a")?,
        )])?;
    for runtime in [&changed_route, &no_route, &changed_profile, &no_profile] {
        assert!(runtime
            .verify_original_request(&journal.scope, &journal.request, runtime.runtime_id(),)
            .is_err());
    }
    let mut wrong_tenant = journal.scope.clone();
    wrong_tenant.tenant_id = RecoveryTenantId::new("foreign-tenant")?;
    assert!(journal
        .runtime
        .verify_original_request(
            &wrong_tenant,
            &journal.request,
            journal.runtime.runtime_id(),
        )
        .is_err());
    assert!(journal
        .runtime
        .verify_original_request(&journal.scope, &journal.request, "foreign-session",)
        .is_err());
    assert_eq!(journal.accounting()?, before);
    Ok(())
}

#[test]
fn original_process_binding_refuses_any_changed_request_bytes() -> Result {
    let journal = LegacyJournal::new(false, true, true, true)?;
    let before = journal.accounting()?;
    let mut variants = Vec::new();
    let mut changed = journal.request.clone();
    changed.request_id.push_str("-changed");
    variants.push(changed);
    let mut changed = journal.request.clone();
    changed.agent_id.push_str("-changed");
    variants.push(changed);
    let mut changed = journal.request.clone();
    changed.server_id.push_str("-changed");
    variants.push(changed);
    let mut changed = journal.request.clone();
    changed.tool_name.push_str("-changed");
    variants.push(changed);
    let mut changed = journal.request.clone();
    changed.arguments["body"] = json!("changed");
    variants.push(changed);
    let mut changed = journal.request.clone();
    changed.capability.expires_at += 1;
    variants.push(changed);
    for changed in variants {
        assert!(journal.verify(&changed).is_err());
    }
    assert_eq!(journal.accounting()?, before);
    Ok(())
}

#[test]
fn original_process_binding_requires_the_exact_persisted_capability() -> Result {
    let journal = LegacyJournal::new(false, false, false, true)?;
    let mut changed = journal.request.capability.clone();
    changed.expires_at += 1;
    Connection::open(&journal.database)?.execute(
        "UPDATE processes SET capability=?1 WHERE id='root'",
        [serde_json::to_string(&changed)?],
    )?;
    let before = journal.accounting()?;
    assert!(journal.verify(&journal.request).is_err());
    assert_eq!(journal.accounting()?, before);
    Ok(())
}

#[test]
fn original_process_binding_refuses_ambiguous_matches() -> Result {
    let journal = LegacyJournal::new(false, false, false, true)?;
    Connection::open(&journal.database)?.execute(
        "INSERT INTO process_calls(process_id,operation_key,request_hash)
         SELECT process_id,'ambiguous-key',request_hash FROM process_calls WHERE process_id='root'",
        [],
    )?;
    let before = journal.accounting()?;
    assert!(journal.verify(&journal.request).is_err());
    assert_eq!(journal.accounting()?, before);
    Ok(())
}

#[test]
fn original_process_binding_requires_the_stored_keys_first_attempt_identity() -> Result {
    let journal = LegacyJournal::new(false, false, false, true)?;
    Connection::open(&journal.database)?.execute(
        "UPDATE process_calls SET operation_key='different-key' WHERE process_id='root'",
        [],
    )?;
    let before = journal.accounting()?;
    assert!(journal.verify(&journal.request).is_err());
    assert_eq!(journal.accounting()?, before);
    Ok(())
}

#[test]
fn original_process_binding_refuses_later_attempts_without_rewriting_the_seed() -> Result {
    let journal = LegacyJournal::new(false, false, false, true)?;
    Connection::open(&journal.database)?.execute(
        "UPDATE process_calls SET attempts=2 WHERE process_id='root'",
        [],
    )?;
    let before = journal.accounting()?;
    assert!(journal.verify(&journal.request).is_err());
    let later = journal.runtime.tool_request(
        "root",
        "legacy-binding",
        "server-a",
        "send",
        journal.request.arguments.clone(),
    )?;
    assert_ne!(later.request_id, journal.request.request_id);
    assert!(journal.verify(&later).is_err());
    assert_eq!(journal.accounting()?, before);
    Ok(())
}

#[tokio::test]
async fn original_process_binding_refuses_sibling_reuse_of_an_identical_capability() -> Result {
    let directory = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = support::kernel(directory.path(), Box::new(CountingServer(calls.clone())))?;
    let database = directory.path().join("process.db");
    let runtime = ProcessRuntime::open(&database, kernel.clone())?;
    let parent = support::root(&runtime, &kernel, 4)?;
    let child = support::child(
        &parent,
        &support::parent_key(),
        "reader-capability",
        &Keypair::from_seed(&[62; 32]),
        support::scope(&["read"]),
    )?;
    runtime.spawn("root", "reader", &child)?;
    runtime.spawn("root", "sibling", &child)?;
    let request = runtime.tool_request("reader", "denied", "tools", "append", json!({}))?;
    assert_eq!(
        runtime
            .invoke_known_only("reader", "denied", &request)
            .await?
            .verdict,
        Verdict::Deny
    );
    let sibling_request =
        runtime.tool_request("sibling", "denied", "tools", "append", json!({}))?;
    assert_eq!(
        runtime
            .invoke_known_only("sibling", "denied", &sibling_request)
            .await?
            .verdict,
        Verdict::Deny
    );
    let reader = scope(&kernel, "reader", "test-tenant")?;
    let sibling = scope(&kernel, "sibling", "test-tenant")?;
    let before = accounting(&database)?;
    runtime.verify_original_request(&reader, &request, runtime.runtime_id())?;
    runtime.verify_original_request(&sibling, &sibling_request, runtime.runtime_id())?;
    assert_ne!(sibling_request.request_id, request.request_id);
    assert!(runtime
        .verify_original_request(&sibling, &request, runtime.runtime_id())
        .is_err());
    // Even a duplicate journal digest under the sibling cannot normalize away
    // the original reader's request id and claim that sibling's first attempt.
    Connection::open(&database)?.execute(
        "INSERT INTO process_calls(process_id,operation_key,request_hash)
         SELECT 'sibling','copied-reader',request_hash FROM process_calls WHERE process_id='reader'",
        [],
    )?;
    assert!(runtime
        .verify_original_request(&sibling, &request, runtime.runtime_id())
        .is_err());
    let after = accounting(&database)?;
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1 + 1);
    assert_eq!((after.2, after.3), (before.2, before.3));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn original_process_binding_reads_independently_during_contention_and_refuses_poison(
) -> Result {
    use std::sync::mpsc;
    use std::time::Duration;

    let directory = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = support::kernel(directory.path(), Box::new(CountingServer(calls.clone())))?;
    let database = directory.path().join("process.db");
    let runtime = ProcessRuntime::open(&database, kernel.clone())?;
    let signer = support::parent_key();
    let capability =
        kernel.issue_capability(&signer.public_key(), support::scope(&["read"]), 3600)?;
    runtime.create_root("root", &capability, support::limits(4))?;
    let registry = runtime.registry();
    registry.provision_signers(&[("root".into(), &signer)])?;
    let request = runtime.tool_request("root", "denied", "tools", "append", json!({}))?;
    assert_eq!(
        runtime
            .invoke_known_only("root", "denied", &request)
            .await?
            .verdict,
        Verdict::Deny
    );
    let scope = scope(&kernel, "root", "test-tenant")?;
    let before = accounting(&database)?;
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder = std::thread::spawn(move || -> std::result::Result<(), String> {
        registry
            .with_process_signer("root", |_, _| {
                held_tx.send(()).map_err(|error| error.to_string())?;
                release_rx.recv().map_err(|error| error.to_string())
            })
            .map_err(|error| error.to_string())?
    });
    held_rx.recv_timeout(Duration::from_secs(10))?;
    let (completed_tx, completed_rx) = mpsc::channel();
    let verifying_runtime = runtime.clone();
    let verifying_scope = scope.clone();
    let verifying_request = request.clone();
    let verifier = std::thread::spawn(move || {
        let outcome = verifying_runtime
            .verify_original_request(
                &verifying_scope,
                &verifying_request,
                verifying_runtime.runtime_id(),
            )
            .map_err(|error| error.to_string());
        completed_tx
            .send(outcome)
            .map_err(|error| error.to_string())
    });
    let completed = completed_rx.recv_timeout(Duration::from_secs(1));
    // Always release and join before asserting. The predecessor can otherwise
    // leave a blocked test thread holding the process journal indefinitely.
    release_tx.send(())?;
    holder.join().map_err(|_| "journal holder panicked")??;
    verifier.join().map_err(|_| "origin verifier panicked")??;
    assert!(
        completed.is_ok(),
        "origin verification waited for the process journal mutex"
    );
    assert!(
        completed?.is_ok(),
        "a stable committed process snapshot was refused because its writer handle was busy",
    );
    runtime.verify_original_request(&scope, &request, runtime.runtime_id())?;
    assert_eq!(accounting(&database)?, before);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let registry = runtime.registry();
    let poisoned = std::thread::spawn(move || {
        let _ = registry.with_process_signer("root", |_, _| {
            panic!("intentional test journal mutex poisoning");
        });
    });
    assert!(poisoned.join().is_err());
    assert!(runtime
        .verify_original_request(&scope, &request, runtime.runtime_id())
        .is_err());
    assert_eq!(accounting(&database)?, before);
    Ok(())
}

fn grant(capability: &str, purpose: &str) -> Result<SignedDeclassificationGrant> {
    let body = serde_json::from_value(json!({
        "domain_version": 1, "grant_id": "frozen-grant",
        "capability_id": capability, "tenant_id": "test-tenant",
        "subject_id": "test-subject", "agent_id": "test-agent", "session_id": "test-session",
        "source_label_hash": vec![1; 32],
        "target_label": {"kind": "known", "owners": {}, "compartments": []},
        "destination_id": "tools", "tool_name": "append", "purpose": purpose,
        "request_hash": vec![2; 32], "issued_at_unix_seconds": 100,
        "expires_at_unix_seconds": 200, "authority_key_id": "test-authority"
    }))?;
    Ok(SignedDeclassificationGrant::sign(body, &support::issuer())?)
}

#[tokio::test]
async fn original_process_binding_preserves_automatic_nonce_absence_and_frozen_credentials(
) -> Result {
    let directory = tempfile::tempdir()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let kernel = support::kernel_with_artifacts(
        directory.path(),
        Box::new(CountingServer(calls.clone())),
        false,
        true,
        false,
    )?;
    let database = directory.path().join("process.db");
    let runtime = ProcessRuntime::open(&database, kernel.clone())?;
    let capability = support::root(&runtime, &kernel, 4)?;
    let original = runtime.tool_request("root", "automatic-nonce", "tools", "append", json!({}))?;
    let response = runtime.invoke("root", "automatic-nonce", &original).await?;
    assert_eq!(response.verdict, Verdict::Allow);
    let nonce = response.execution_nonce.ok_or("automatic nonce")?;
    let scope = scope(&kernel, "root", "test-tenant")?;
    let before = accounting(&database)?;
    runtime.verify_original_request(&scope, &original, runtime.runtime_id())?;
    let mut added_nonce = original.clone();
    added_nonce.execution_nonce = Some(*nonce.clone());
    assert!(runtime
        .verify_original_request(&scope, &added_nonce, runtime.runtime_id())
        .is_err());
    assert_eq!(accounting(&database)?, before);

    let mut frozen =
        runtime.tool_request("root", "supplied-credentials", "tools", "append", json!({}))?;
    frozen.execution_nonce = Some(*nonce);
    frozen.declassification_grant = Some(grant(&capability.id, "frozen-original")?.into());
    // Synthetic and stale credentials are evidence of immutable process bytes,
    // not execution authority. Native admission refuses their use.
    assert_eq!(
        runtime
            .invoke_known_only("root", "supplied-credentials", &frozen)
            .await?
            .verdict,
        Verdict::Deny
    );
    let before = accounting(&database)?;
    runtime.verify_original_request(&scope, &frozen, runtime.runtime_id())?;
    let mut without_grant = frozen.clone();
    without_grant.declassification_grant = None;
    let mut changed_grant = frozen.clone();
    changed_grant.declassification_grant = Some(grant(&capability.id, "changed")?.into());
    let mut without_nonce = frozen.clone();
    without_nonce.execution_nonce = None;
    let mut changed_nonce = frozen.clone();
    changed_nonce
        .execution_nonce
        .as_mut()
        .ok_or("nonce")?
        .nonce
        .nonce_id
        .push_str("-changed");
    for changed in [without_grant, changed_grant, without_nonce, changed_nonce] {
        assert!(runtime
            .verify_original_request(&scope, &changed, runtime.runtime_id())
            .is_err());
    }
    assert_eq!(accounting(&database)?, before);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}
