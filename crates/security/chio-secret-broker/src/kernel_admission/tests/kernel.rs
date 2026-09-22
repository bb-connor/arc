//! A real kernel and anchored SQLite authority own all three quota participants.
use super::*;
use chio_core_types::capability::{
    attenuation::scope_hash,
    scope::{ChioScope, Operation, ToolGrant},
};
use chio_core_types::SigningBackend;
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, DurableAdmissionMode,
};
use chio_kernel::budget_store::{BudgetMutationKind, BudgetQuotaProfile};
use chio_kernel::supplemental_admission::{
    SupplementalAdmissionAuthorityBindingV1, SupplementalAdmissionParticipant,
    SupplementalAdmissionRegistrationContext,
};
use chio_kernel::{
    BudgetStore, ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolServerConnection,
    Verdict,
};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

struct RegistrationBeforeHold {
    budget: chio_store_sqlite::SqliteBudgetStore,
    ipc: Option<Arc<BrokerAdmissionParticipant>>,
    mode: AtomicUsize,
    operations: Mutex<Vec<String>>,
}

impl SupplementalAdmissionParticipant for RegistrationBeforeHold {
    fn requires_registration(&self, server_id: &str, tool_name: &str) -> bool {
        self.ipc
            .as_ref()
            .is_none_or(|ipc| ipc.requires_registration(server_id, tool_name))
    }

    fn register_original(
        &self,
        context: &SupplementalAdmissionRegistrationContext<'_>,
    ) -> std::result::Result<(), SupplementalQuotaVerifierError> {
        let failure = || SupplementalQuotaVerifierError::new("registration refused");
        let hold = context.budget().hold_id.as_deref().ok_or_else(failure)?;
        if self
            .budget
            .get_budget_hold(hold)
            .map_err(|_| failure())?
            .is_some()
        {
            return Err(SupplementalQuotaVerifierError::new(
                "budget preceded registration",
            ));
        }
        self.operations.lock().map_err(|_| failure())?.push(
            context
                .operation()
                .binding()
                .operation_id()
                .as_str()
                .to_owned(),
        );
        match self.mode.load(Ordering::SeqCst) {
            0 => match self.ipc.as_ref() {
                Some(ipc) => ipc.register_original(context),
                None => Ok(()),
            },
            1 => Err(failure()),
            _ => panic!("registration acknowledgement lost"),
        }
    }
}

struct CountDispatch(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for CountDispatch {
    fn server_id(&self) -> &str {
        "broker-tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["execute".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"completed": true}))
    }
}

#[test]
fn kernel_captures_parent_family_and_broker_once_and_denies_exhaustion() -> TestResult {
    registered_composite_execution(false, None)
}

#[test]
fn strict_nonce_registers_original_broker_attempt_before_both_holds() -> TestResult {
    registered_composite_execution(true, None)
}

enum ParticipantChange {
    Remove,
    Reconfigure,
}

#[test]
fn issued_nonce_cannot_adopt_a_changed_or_removed_broker_participant() -> TestResult {
    for change in [ParticipantChange::Remove, ParticipantChange::Reconfigure] {
        registered_composite_execution(true, Some(change))?;
    }
    Ok(())
}

fn registered_composite_execution(
    strict_nonce: bool,
    participant_change: Option<ParticipantChange>,
) -> TestResult {
    let directory = crate::private_tempdir()?;
    let locks = directory.path().join("locks");
    std::fs::create_dir(&locks)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locks, std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("authority.db");
    SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
    let signer = Keypair::generate();
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer.clone(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "a".repeat(64),
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
    let receipts = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;
    receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
    kernel.set_receipt_store_handle(Arc::new(receipts))?;
    kernel.set_revocation_store(Box::new(authority.revocation_store()));
    kernel.set_budget_store(Box::new(authority.budget_store()));
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    if strict_nonce {
        let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
            require_nonce: true,
            nonce_ttl_secs: 60,
            nonce_store_capacity: 32,
        };
        kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(
                chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config),
            ),
        );
    }
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "broker-tools".into(),
            tool_name: "execute".into(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(4),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    };
    kernel.set_capability_trust_root(signer.public_key(), scope_hash(&scope)?);
    let effects = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountDispatch(effects.clone())));
    let (fixture_verifier, mut execute, _) = fixture()?;
    let verifier = BrokerQuotaVerifier::new(
        fixture_verifier.config,
        Arc::new(crate::daemon::SystemDaemonClock),
    )?;
    let binding = verifier.binding().clone();
    #[cfg(target_os = "linux")]
    let (mut peer, ipc) = {
        let signer = Arc::new(Ed25519Backend::new(Keypair::from_seed(&[34; 32])));
        let peer =
            super::registration_peer::RegistrationPeer::new(directory.path(), signer.public_key())?;
        let ipc = Arc::new(BrokerAdmissionParticipant::new(
            peer.config.clone(),
            signer,
            "broker-revocation-domain".into(),
            &verifier,
        )?);
        (peer, Some(ipc))
    };
    #[cfg(not(target_os = "linux"))]
    let ipc: Option<Arc<BrokerAdmissionParticipant>> = None;
    let participant_binding = match ipc.as_ref() {
        Some(ipc) => ipc.binding().clone(),
        None => SupplementalAdmissionAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("participant", "broker-registration-fixture")?,
            AdmissionDigest::try_new("participant configuration", "d".repeat(64))?,
            AdmissionIdentifier::try_new("verifier", &binding.verifier_identity)?,
            AdmissionDigest::try_new("verifier configuration", &binding.configuration_digest)?,
        ),
    };
    let registrar = Arc::new(RegistrationBeforeHold {
        budget: authority.budget_store(),
        ipc,
        mode: AtomicUsize::new(0),
        operations: Mutex::new(Vec::new()),
    });
    assert!(kernel
        .set_supplemental_admission_participant(registrar.clone(), participant_binding.clone(),)
        .is_err());
    let verifier = Arc::new(verifier);
    kernel.set_supplemental_quota_verifier(verifier.clone(), binding.clone())?;
    kernel.set_supplemental_admission_participant(registrar.clone(), participant_binding)?;
    let mut changed_verifier_binding = binding.clone();
    changed_verifier_binding.configuration_digest = "e".repeat(64);
    assert!(kernel
        .set_supplemental_quota_verifier(verifier, changed_verifier_binding)
        .is_err());
    kernel.reconcile_durable_admission_startup()?;
    let caller = Keypair::from_seed(&[32; 32]);
    let parent = kernel.issue_aggregate_family_root(&caller.public_key(), scope, 300, 3)?;
    let now = crate::daemon::SystemDaemonClock.now_unix_seconds()?;
    let mut body = execute.capability.body;
    body.parent_capability_id = parent.id.clone();
    body.issued_at_unix_seconds = now;
    body.not_before_unix_seconds = now;
    body.expires_at_unix_seconds = now + 300;
    execute.capability = issue_capability(
        body,
        &Ed25519Backend::new(Keypair::from_seed(&[31; 32])),
        true,
    )?;
    execute.proof = issue_request_proof(
        &execute.capability,
        &execute.request,
        "1".repeat(32),
        now,
        &caller,
    )?;
    let request = |execute: &BrokerExecuteRequest| -> TestResult<chio_kernel::ToolCallRequest> {
        Ok(serde_json::from_value(json!({
            "request_id": execute.invocation_id, "capability": parent, "tool_name": "execute", "server_id": "broker-tools",
            "agent_id": caller.public_key().to_hex(), "arguments": execute,
            "supplemental_authorization": {"signed_extension": String::from_utf8(canonical_json_bytes(execute)?)?},
        }))?)
    };
    let mut changed = execute.clone();
    changed.request.body = b"substituted".to_vec();
    let denied = kernel.evaluate_tool_call_blocking(&request(&changed)?)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert!(registrar
        .operations
        .lock()
        .map_err(|_| "registration lock")?
        .is_empty());
    let mut omitted = execute.clone();
    omitted.invocation_id = "registration-authorization-omitted".into();
    let mut omitted = request(&omitted)?;
    omitted.supplemental_authorization = None;
    let denied = kernel.evaluate_tool_call_blocking(&omitted)?;
    assert_eq!(
        denied.verdict,
        Verdict::Deny,
        "a broker route requires its supplemental authority"
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert!(authority
        .budget_store()
        .list_mutation_events(32, Some(&parent.id), None)?
        .is_empty());
    for mode in [1, 2] {
        registrar.mode.store(mode, Ordering::SeqCst);
        let mut refused = execute.clone();
        refused.invocation_id = format!("registration-refused-{mode}");
        let denied = kernel.evaluate_tool_call_blocking(&request(&refused)?)?;
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        assert!(authority
            .budget_store()
            .list_mutation_events(32, Some(&parent.id), None)?
            .is_empty());
        assert_eq!(
            registrar
                .operations
                .lock()
                .map_err(|_| "registration lock")?
                .len(),
            mode,
            "the refusal must come from the selected participant",
        );
    }
    registrar.mode.store(0, Ordering::SeqCst);
    #[cfg(target_os = "linux")]
    {
        peer.misbind_ack.store(true, Ordering::SeqCst);
        let mut refused = execute.clone();
        refused.invocation_id = "registration-ack-substituted".into();
        refused.proof = issue_request_proof(
            &refused.capability,
            &refused.request,
            "4".repeat(32),
            now,
            &caller,
        )?;
        let denied = kernel.evaluate_tool_call_blocking(&request(&refused)?)?;
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        assert!(authority
            .budget_store()
            .list_mutation_events(32, Some(&parent.id), None)?
            .is_empty());
        peer.misbind_ack.store(false, Ordering::SeqCst);
    }
    registrar
        .operations
        .lock()
        .map_err(|_| "registration lock")?
        .clear();
    let mut original = request(&execute)?;
    if strict_nonce {
        let preflight = kernel.evaluate_tool_call_blocking(&original)?;
        assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        original.execution_nonce = Some(*preflight.execution_nonce.ok_or("original nonce")?);
    }
    if let Some(change) = participant_change {
        match change {
            ParticipantChange::Remove => kernel.clear_supplemental_admission_participant(),
            ParticipantChange::Reconfigure => {
                kernel.set_supplemental_admission_participant(
                    registrar.clone(),
                    SupplementalAdmissionAuthorityBindingV1::new(
                        AdmissionIdentifier::try_new("participant", "broker-registration-fixture")?,
                        AdmissionDigest::try_new("participant configuration", "f".repeat(64))?,
                        AdmissionIdentifier::try_new("verifier", binding.verifier_identity)?,
                        AdmissionDigest::try_new(
                            "verifier configuration",
                            binding.configuration_digest,
                        )?,
                    ),
                )?;
            }
        }
        let denied = kernel.evaluate_tool_call_blocking(&original)?;
        assert_eq!(denied.verdict, Verdict::Deny);
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        assert_eq!(
            registrar
                .operations
                .lock()
                .map_err(|_| "registration lock")?
                .len(),
            1
        );
        assert!(authority
            .budget_store()
            .list_mutation_events(32, Some(&parent.id), None)?
            .iter()
            .all(|event| event.kind != BudgetMutationKind::CaptureInvocation));
        #[cfg(target_os = "linux")]
        {
            let registered = peer.finish()?;
            assert_eq!(
                registered
                    .iter()
                    .filter(|attempt| attempt.invocation_id == execute.invocation_id)
                    .count(),
                1
            );
        }
        return Ok(());
    }
    let allowed = kernel.evaluate_tool_call_blocking(&original)?;
    assert_eq!(allowed.verdict, Verdict::Allow, "{:?}", allowed.reason);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    {
        let operations = registrar
            .operations
            .lock()
            .map_err(|_| "registration lock")?;
        assert_eq!(operations.len(), if strict_nonce { 2 } else { 1 });
        assert!(operations
            .iter()
            .all(|operation| operation == &operations[0]));
    }
    assert_eq!(
        canonical_json_bytes(&kernel.evaluate_tool_call_blocking(&original)?.receipt)?,
        canonical_json_bytes(&allowed.receipt)?
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    execute.invocation_id = "second-request".into();
    execute.proof = issue_request_proof(
        &execute.capability,
        &execute.request,
        "2".repeat(32),
        now,
        &caller,
    )?;
    let denied = kernel.evaluate_tool_call_blocking(&request(&execute)?)?;
    assert_eq!(denied.verdict, Verdict::Deny, "{:?}", denied.reason);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    // A fresh signed broker capability has available quota, but its independent
    // revocation identity is checked in the same owning authority before effect.
    let mut fresh = execute.capability.body.clone();
    fresh.capability_id = "another-broker-capability".into();
    fresh.revocation_id = "another-broker-revocation".into();
    kernel.revoke_capability(&fresh.revocation_id)?;
    execute.capability = issue_capability(
        fresh,
        &Ed25519Backend::new(Keypair::from_seed(&[31; 32])),
        true,
    )?;
    execute.invocation_id = "revoked-broker-request".into();
    execute.proof = issue_request_proof(
        &execute.capability,
        &execute.request,
        "3".repeat(32),
        now,
        &caller,
    )?;
    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&request(&execute)?)?
            .verdict,
        Verdict::Deny
    );
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let events = authority
        .budget_store()
        .list_mutation_events(100, Some(&parent.id), None)?;
    let captures: Vec<_> = events
        .iter()
        .filter(|event| {
            event.kind == BudgetMutationKind::CaptureInvocation && event.allowed == Some(true)
        })
        .collect();
    assert_eq!(captures.len(), 1);
    let profiles: std::collections::BTreeSet<_> = captures[0]
        .invocation_quota_usages
        .iter()
        .map(|usage| usage.quota.key.profile)
        .collect();
    assert_eq!(
        profiles,
        [
            BudgetQuotaProfile::GrantInvocation,
            BudgetQuotaProfile::AggregateFamilyInvocation,
            BudgetQuotaProfile::SupplementalBrokerCapabilityExecution
        ]
        .into_iter()
        .collect()
    );
    for usage in &captures[0].invocation_quota_usages {
        let current = authority
            .budget_store()
            .get_invocation_quota_usage(&usage.quota.key)?
            .ok_or("missing original quota")?;
        assert_eq!(
            (current.reserved_invocations, current.captured_invocations),
            (0, 1)
        );
    }
    #[cfg(target_os = "linux")]
    {
        let registered = peer.finish()?;
        let original: Vec<_> = registered
            .iter()
            .filter(|attempt| attempt.invocation_id == "request-1")
            .collect();
        assert_eq!(original.len(), if strict_nonce { 2 } else { 1 });
        assert!(original.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(original[0].quotas.len(), 3);
    }
    Ok(())
}
