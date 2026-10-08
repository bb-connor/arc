use crate::security::adapters::{FlowResolverConfig, NativeFlowResolver};
use chio_core::{
    Keypair,
    capability::scope::{ChioScope, Operation, ToolGrant},
    capability::token::CapabilityToken,
};
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationState, AdmissionOperationStore,
};
use chio_kernel::budget_store::BudgetQuotaKey;
use chio_kernel::{
    BudgetStore, ChioKernel, KernelError, NestedFlowBridge, SecurityPreDispatchPolicy,
    ToolCallRequest, ToolServerConnection, Verdict,
};
use chio_security_types::flow::{DeclassificationPurpose, InformationLabel, PrincipalId};
use chio_security_types::ports::{
    DeclassificationEvidenceCommitStore, DestinationId, FlowJoinRequest, FlowStateStore, RecordId,
};
use chio_store_sqlite::security_state::SqliteSecurityParticipantSource;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteSecurityStateStore};
use std::collections::BTreeMap;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
mod bootstrap;
use bootstrap::*;

#[path = "tests/refusals.rs"]
mod additional_refusals;
#[path = "tests/authority_history.rs"]
mod authority_history;

pub(super) fn record_host_port_cutpoint(stage: &str) {
    authority_history::host_port_replay::record_signed_cutpoint(stage);
}
#[path = "tests/command_identities.rs"]
mod command_identities;
#[path = "tests/command_quotas.rs"]
mod command_quotas;
#[path = "tests/connector_resources.rs"]
mod connector_resources;
#[path = "tests/explanations.rs"]
mod explanations;
#[path = "tests/linked_generations.rs"]
mod linked_generations;
#[path = "tests/native_lineage_bootstrap.rs"]
mod native_lineage_bootstrap;
#[path = "tests/original_action_semantics.rs"]
mod original_action_semantics;
#[path = "tests/original_denials.rs"]
mod original_denials;
#[path = "tests/original_namespaces.rs"]
mod original_namespaces;
#[path = "tests/original_no_effect_replacement.rs"]
mod original_no_effect_replacement;
#[path = "tests/output_retention.rs"]
mod output_retention;
#[path = "tests/overload.rs"]
mod overload;
#[path = "tests/participant_intake.rs"]
mod participant_intake;
#[path = "tests/preview_authority.rs"]
mod preview_authority;
#[path = "tests/semantic.rs"]
mod semantic;
#[path = "tests/stale_owner.rs"]
mod stale_owner;
#[path = "tests/wire_boundaries.rs"]
mod wire_boundaries;
#[path = "tests/workflow_lifecycle.rs"]
mod workflow_lifecycle;

use crate::recovery::{RecoveryCommandResultV1, RecoveryRuntime};
use chio_core::crypto::Ed25519Backend;
use chio_core_types::recovery::SignedAuthorityCoverageAttestationV1;
use chio_kernel::ToolInvocationContext;
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::recovery::*;
use chio_process::{ProcessLimits, ProcessRuntime, ProcessSecurityProfile};
use chio_security_types::recovery::*;
use serde_json::Value;

struct RecoveryFixture {
    runtime: Arc<RecoveryRuntime>,
    kernel: Arc<ChioKernel>,
    process: ProcessRuntime,
    authority: SqliteAuthorityStore,
    control: CapabilityToken,
    approval_key: Keypair,
    seed: ToolCallRequest,
    effects: Arc<AtomicUsize>,
    _directory: Option<tempfile::TempDir>,
    path: std::path::PathBuf,
    behavior: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
fn text<const N: usize, T: serde::Serialize>(data: &T) -> TestResult<ProtectedText<N>> {
    Ok(ProtectedText::new(std::str::from_utf8(
        &chio_core::canonical_json_bytes(data)?,
    )?)?)
}
impl RecoveryFixture {
    fn new(nonce: bool) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        Self::open(directory.path().to_path_buf(), Some(directory), nonce)
    }
    fn open(
        path: std::path::PathBuf,
        directory: Option<tempfile::TempDir>,
        nonce: bool,
    ) -> TestResult<Self> {
        Self::open_with_native_observer(path, directory, nonce, None)
    }
    fn open_with_native_observer(
        path: std::path::PathBuf,
        directory: Option<tempfile::TempDir>,
        nonce: bool,
        observer: Option<chio_kernel::NativeSecurityCaptureObserver>,
    ) -> TestResult<Self> {
        Self::open_with_tool_server(path, directory, nonce, observer, None)
    }
    fn open_with_tool_server(
        path: std::path::PathBuf,
        directory: Option<tempfile::TempDir>,
        nonce: bool,
        observer: Option<chio_kernel::NativeSecurityCaptureObserver>,
        tool_server: Option<Box<dyn ToolServerConnection>>,
    ) -> TestResult<Self> {
        Self::open_with_participants(path, directory, nonce, observer, tool_server, None)
    }
    fn open_with_payment_adapter(
        path: std::path::PathBuf,
        directory: Option<tempfile::TempDir>,
        nonce: bool,
        payment_adapter: Box<dyn chio_kernel::PaymentAdapter>,
    ) -> TestResult<Self> {
        Self::open_with_participants(path, directory, nonce, None, None, Some(payment_adapter))
    }
    fn open_with_participants(
        path: std::path::PathBuf,
        directory: Option<tempfile::TempDir>,
        nonce: bool,
        observer: Option<chio_kernel::NativeSecurityCaptureObserver>,
        tool_server: Option<Box<dyn ToolServerConnection>>,
        payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    ) -> TestResult<Self> {
        let monetary_semantic = payment_adapter.is_some();
        let fresh = !path.join("fixture.json").exists();
        let locks = path.join("locks");
        std::fs::create_dir_all(&locks)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [path.as_path(), locks.as_path()] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let database = path.as_path().join("admission.db");
        if !database.exists() {
            SqliteAuthorityStore::provision(&database, &locks)?;
        }
        let authority = SqliteAuthorityStore::open_serving(&database, &locks)?;
        let ca = Keypair::from_seed(
            if path.join("legacy-near-capacity").exists()
                && path.join("current-recovery-receipt-signer").exists()
            {
                &[207; 32]
            } else {
                &[140; 32]
            },
        );
        let agent = Keypair::from_seed(&[141; 32]);
        let approval_key = authority_history::fixture_approval_key(&path);
        let issuer = authority_history::fixture_aggregate_key(&path);
        let (mut kernel, effects) = open_kernel(path.as_path(), &authority, &ca)?;
        let behavior = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let ordinary_server = PersistentEffectServer::new(
            path.join("effects.db"),
            effects.clone(),
            behavior.clone(),
            started.clone(),
            release.clone(),
        )?;
        kernel.register_tool_server(tool_server.unwrap_or_else(|| Box::new(ordinary_server)));
        install_native_fault(&mut kernel, &authority)?;
        if let Some(adapter) = payment_adapter {
            kernel.set_payment_adapter(adapter);
        }
        let persisted: Option<(ToolCallRequest, CapabilityToken)> = if fresh {
            None
        } else {
            Some(serde_json::from_slice(&std::fs::read(
                path.join("fixture.json"),
            )?)?)
        };
        kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
        let retention_path = path.join("output-retention-profile.json");
        if retention_path.exists() {
            let profile: chio_kernel::admission_operation::NativeOutputRetentionProfileV1 =
                serde_json::from_slice(&std::fs::read(retention_path)?)?;
            kernel.select_native_output_retention(profile)?;
        }
        if nonce {
            let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
                nonce_ttl_secs: 30,
                nonce_store_capacity: 64,
                require_nonce: true,
            };
            kernel.set_execution_nonce_store(
                config.clone(),
                Box::new(
                    chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config),
                ),
            );
        }
        let mut scope = ChioScope {
            grants: vec![ToolGrant {
                server_id: "server-a".into(),
                tool_name: "send".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(8),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..Default::default()
        };
        if path.join("confined-profile").exists() {
            scope.grants[0].operations.push(Operation::Delegate);
        }
        if path.join("mismatched-output-digest").exists() {
            scope.grants[0].constraints.push(
                chio_core::capability::scope::Constraint::OutputDigestSha256(
                    chio_core::sha256_hex(b"an output the provider will never return"),
                ),
            );
        }
        if path.join("semantic-kind").exists() {
            for server in ["semantic-a", "semantic-source"] {
                scope.grants.push(ToolGrant {
                    server_id: server.into(),
                    tool_name: "remedy".into(),
                    operations: vec![Operation::Invoke],
                    constraints: semantic::fixture_output_constraints(&path)?,
                    max_invocations: Some(8),
                    max_cost_per_invocation: monetary_semantic.then(|| {
                        chio_core::capability::scope::MonetaryAmount {
                            units: 10,
                            currency: "USD".into(),
                        }
                    }),
                    max_total_cost: monetary_semantic.then(|| {
                        chio_core::capability::scope::MonetaryAmount {
                            units: 80,
                            currency: "USD".into(),
                        }
                    }),
                    dpop_required: None,
                });
            }
        }
        let cap = match &persisted {
            Some((seed, _)) => seed.capability.clone(),
            None => kernel.issue_capability(
                &agent.public_key(),
                scope,
                if path.join("extended-setup-validity").exists() {
                    1_800
                } else {
                    600
                },
            )?,
        };
        let permissions = vec![
            RecoveryPermission::Create,
            RecoveryPermission::Inspect,
            RecoveryPermission::Select,
            RecoveryPermission::Approve,
            RecoveryPermission::Resume,
            RecoveryPermission::Cancel,
            RecoveryPermission::Report,
            RecoveryPermission::Settle,
            RecoveryPermission::InspectExplanationGraph,
        ];
        let control = match &persisted {
            Some((_, control)) => control.clone(),
            None => kernel.issue_capability(
                &approval_key.public_key(),
                ChioScope {
                    grants: permissions
                        .iter()
                        .map(|p| ToolGrant {
                            server_id: "chio.recovery".into(),
                            tool_name: p.wire_name().into(),
                            operations: vec![Operation::Invoke],
                            constraints: vec![],
                            max_invocations: None,
                            max_cost_per_invocation: None,
                            max_total_cost: None,
                            dpop_required: None,
                        })
                        .collect(),
                    ..Default::default()
                },
                1200,
            )?,
        };
        let initial = Arc::new(kernel);
        let process_path = path.as_path().join("process.db");
        let process = ProcessRuntime::open(&process_path, initial.clone())?.with_security_profile(
            ProcessSecurityProfile {
                tenant_id: "native-tenant".into(),
                isolation_epoch_id: "native-epoch".into(),
                generation: 1,
            },
        )?;
        if fresh {
            process.create_root(
                "root",
                &cap,
                ProcessLimits {
                    max_processes: 8,
                    max_depth: 2,
                    max_calls: if path.join("workflow-flood").exists() {
                        256
                    } else {
                        32
                    },
                    state: if path.join("bounded-artifact-storage").exists() {
                        chio_process::ProcessStateLimits {
                            max_bytes: 131_072,
                            max_blobs: 32,
                        }
                    } else {
                        Default::default()
                    },
                },
            )?;
        }
        let context = process.recovery_security_context("root")?;
        let seed = match &persisted {
            Some((seed, _)) => seed.clone(),
            None => process.tool_request(
                "root",
                "seed",
                "server-a",
                "send",
                command_quotas::fixture_seed_arguments(
                    &path,
                    serde_json::json!({"title":"support ticket", "body":"private-canary"}),
                )?,
            )?,
        };
        drop(process);
        let mut kernel = Arc::try_unwrap(initial).map_err(|_| "kernel still borrowed")?;
        let store = authority.admission_operation_store();
        let fence = authority.mutation_fence();
        let scope = RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new(&fence.store_uuid)?,
            tenant_id: RecoveryTenantId::new("native-tenant")?,
            process_id: ProcessId::new("root")?,
        };
        let native = if fresh {
            let source_path = path.as_path().join("source.db");
            let source = SqliteSecurityStateStore::open(&source_path)?;
            source.seal_declassification_live_dispatch()?;
            let initial_label = if path.join("confined-profile").exists() {
                restricted_label()
            } else {
                InformationLabel::bottom()
            };
            let [principal_join, lineage_join, session_join] =
                command_quotas::fixture_source_labels(&path, initial_label)?;
            if !path.join("empty-native-import").exists() {
                source.join(&FlowJoinRequest {
                    key: chio_kernel::recovery::recovery_flow_key(&context),
                    principal_join,
                    lineage_join,
                    session_join,
                    transition_id: RecordId::new("recovery-initial-source")?,
                })?;
            }
            drop(source);
            let source = SqliteSecurityParticipantSource::open(source_path)?;
            let selected = AdmissionIdentifier::try_new("authority", "recovery-native")?;
            let time = now_ms()?;
            let expectation = store
                .expect_security_participant_source(&selected, &selected, &source, &fence, time)?;
            store.import_security_participant_source(
                &selected,
                expectation.expectation_id(),
                &source,
                &fence,
                time,
            )?;
            store
                .hydrate_security_participant_state(
                    &selected,
                    expectation.expectation_id(),
                    &fence,
                    time,
                )?
                .admission_binding()?
        } else {
            store
                .deployment(&scope, &fence, now_ms()?)?
                .native_authority
        };
        let purpose = DeclassificationPurpose::new("approved-disclosure")?;
        let config = FlowResolverConfig::new(
            if path.join("public-original-profile").exists() {
                InformationLabel::bottom()
            } else {
                restricted_label()
            },
            category_labels(),
            BTreeMap::from([(RecordId::new("aggregate")?, issuer.public_key())]),
            60000,
        )?;
        let flow = Arc::new(
            NativeFlowResolver::new(
                native.clone(),
                if path.join("semantic-kind").exists() {
                    semantic::manifest(&path)?
                } else {
                    declassification_registry_with_output_floor(
                        &purpose,
                        authority_history::fixture_output_floor(&path)?,
                    )
                },
                authority_history::fixture_classifier(&path),
                fixture_native_clock(&path),
                config,
            )?
            .with_captured_lifecycle(),
        );
        kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
        authority_history::configure_fixture_history_hooks(
            &mut kernel,
            &path,
            flow.clone(),
            &authority,
            &control,
        )?;
        if path.join("revoke-initiating").exists() {
            kernel.revoke_capability(&seed.capability.id)?;
        }
        kernel.reconcile_durable_admission_startup()?;
        let scope = RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new(&fence.store_uuid)?,
            tenant_id: RecoveryTenantId::new("native-tenant")?,
            process_id: ProcessId::new("root")?,
        };
        let obligations = chio_flow::required_recovery_disclosure_obligations(
            &command_quotas::fixture_preview_clearance(&path)?,
            &InformationLabel::bottom(),
        )?;
        let contract = authority_history::fixture_effect_contract(&path)?;
        let mut deployment = RecoveryDeploymentV1 {
            scope: scope.clone(),
            setup_policy: None,
            native_authority: native,
            security_context: context,
            server_id: RecordName::new("server-a")?,
            tool_name: RecordName::new("send")?,
            recipient: DestinationId::new("server-a")?,
            purpose,
            target_label: InformationLabel::bottom(),
            policy_digest: PolicyDigest::from_bytes(
                *chio_core::sha256(b"native-flow-policy-test").as_bytes(),
            ),
            contract_digest: ContractDigest::from_bytes(recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::EffectContract,
                &contract,
            )?),
            authority_scope: AuthorityScopeDigest::from_bytes([0; 32]),
            attachment_profile: if nonce {
                RecoveryAttachmentProfile::OperationOwnedNonce
            } else {
                RecoveryAttachmentProfile::Ordinary
            },
            aggregate_issuer: issuer.public_key(),
            aggregate_issuer_id: RecordName::new("aggregate")?,
            actors: NonEmptyBoundedList::new(vec![RecoveryActorAssignment {
                subject: approval_key.public_key(),
                principal: PrincipalId::new("reviewer")?,
                permissions: BoundedList::new(permissions)?,
                preview_clearance: command_quotas::fixture_preview_clearance(&path)?,
            }])?,
            coverage: NonEmptyBoundedList::new(vec![RecoveryCoverageAssignment {
                issuer_id: IssuerId::new("reviewer")?,
                principal: PrincipalId::new("reviewer")?,
                key: approval_key.public_key(),
                obligations,
            }])?,
            effect_cardinality: SafeInteger::new(1)?,
            effect_contract: contract,
        };
        preview_authority::extend_fixture_actors(&path, &mut deployment)?;
        deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
        if fresh {
            store.configure_recovery_deployment(&deployment)?;
        }
        if path.join("semantic-kind").exists() {
            semantic::install_connector(
                &mut kernel,
                &authority,
                &deployment,
                &path,
                effects.clone(),
            )?;
        }
        if let Some(observer) = observer {
            kernel.install_native_capture_observer_for_test(observer);
        }
        let kernel = Arc::new(kernel);
        let mut process = ProcessRuntime::open(&process_path, kernel.clone())?
            .with_security_profile(ProcessSecurityProfile {
                tenant_id: "native-tenant".into(),
                isolation_epoch_id: "native-epoch".into(),
                generation: 1,
            })?;
        if std::env::var_os("CHIO_RECOVERY_CRASH_CHILD").is_some() {
            let point = std::env::var("CHIO_RECOVERY_CRASH_POINT")?;
            process = process.with_recovery_test_cutpoint(Arc::new(move |actual| {
                use chio_process::RecoveryProcessTestCutpoint;
                if matches!(
                    (point.as_str(), actual),
                    (
                        "nonce-preflight",
                        RecoveryProcessTestCutpoint::NativeNonceIssued
                    ) | (
                        "nonce-attached",
                        RecoveryProcessTestCutpoint::ProcessNonceRetained
                    )
                ) {
                    crate::recovery::test_cutpoint(&point);
                }
            }));
        }
        let runtime = Arc::new(RecoveryRuntime::new(
            kernel.clone(),
            process.clone(),
            flow,
            scope,
            Arc::new(Ed25519Backend::new(issuer)),
        )?);
        if fresh {
            std::fs::write(
                path.join("fixture.json"),
                chio_core::canonical_json_bytes(&(&seed, &control))?,
            )?;
        }
        Ok(Self {
            runtime,
            kernel,
            process,
            authority,
            control,
            approval_key,
            seed,
            effects,
            _directory: directory,
            path,
            behavior,
            started,
            release,
        })
    }
    fn command(&self, id: &str, body: RecoveryCommandBodyV1) -> TestResult<RecoveryCommandV1> {
        Ok(RecoveryCommandV1 {
            schema: RecoveryCommandSchema::V1,
            version: VersionV1,
            command_id: CommandId::new(id)?,
            command: body,
        })
    }
    async fn execute(
        &self,
        id: &str,
        body: RecoveryCommandBodyV1,
    ) -> TestResult<RecoveryCommandResultV1> {
        Ok(self
            .runtime
            .execute_command(&self.control, &self.command(id, body)?)
            .await
            .map_err(|error| format!("{id}: {error}"))?)
    }
    async fn ready(&self) -> TestResult<WorkflowId> {
        Box::pin(self.ready_named("ticket-1", "")).await
    }
    async fn denied_seed_named(&self, creation_key: &str) -> TestResult<ToolCallRequest> {
        let (key, seed) = if creation_key == "ticket-1" {
            ("seed".to_owned(), self.seed.clone())
        } else {
            let key = format!("denied:{creation_key}");
            let seed = self.process.tool_request(
                self.runtime.scope().process_id.as_str(),
                &key,
                &self.seed.server_id,
                &self.seed.tool_name,
                self.seed.arguments.clone(),
            )?;
            (key, seed)
        };
        let before = external_count(&self.path)?;
        let denial = Box::pin(self.process.invoke_known_only(
            self.runtime.scope().process_id.as_str(),
            &key,
            &seed,
        ))
        .await?;
        assert_eq!(denial.verdict, Verdict::Deny);
        assert_eq!(external_count(&self.path)?, before);
        let (operation, _) = self
            .authority
            .admission_operation_store()
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &seed.request_id)?,
                &self.authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("original denial was not retained")?;
        assert_eq!(
            operation.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        assert!(operation.dispatch_commit().is_none());
        Ok(seed)
    }
    async fn ready_named(&self, creation_key: &str, prefix: &str) -> TestResult<WorkflowId> {
        let identity = |suffix: &str| {
            if prefix.is_empty() {
                suffix.to_owned()
            } else {
                format!("{prefix}-{suffix}")
            }
        };
        let original = Box::pin(self.denied_seed_named(creation_key)).await?;
        let created = self
            .execute(
                &identity("create"),
                RecoveryCommandBodyV1::CreateWorkflow {
                    creation_key: CreationKey::new(creation_key)?,
                    template: RecoveryTemplateV1::SupportTicketPublicIssue,
                    request_seed: text(&original)?,
                },
            )
            .await?;
        let id = created.status.workflow_id;
        std::fs::write(
            self.path.join("workflow.json"),
            chio_core::canonical_json_bytes(&id)?,
        )?;
        let actor = self.kernel.authenticate_recovery_actor(
            self.runtime.scope(),
            &self.control,
            RecoveryPermission::Inspect,
        )?;
        let record = self.kernel.read_recovery_workflow(&actor, &id)?;
        let action = record.action.as_ref().ok_or("action")?;
        let bytes = recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
            action,
        )?;
        let offer = format!(
            "offer:{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        if !record.selected {
            self.execute(
                &identity("select"),
                RecoveryCommandBodyV1::SelectOffer {
                    workflow_id: id.clone(),
                    expected_revision: record.revision,
                    offer_id: OfferId::new(&offer)?,
                },
            )
            .await?;
        }
        let intent = self.runtime.approval_intent(&self.control, &id)?;
        let record = self.kernel.read_recovery_workflow(&actor, &id)?;
        if record.approval.is_some() {
            return Ok(id);
        }
        let action = record.action.as_ref().ok_or("action")?;
        let evidence = AuthorityCoverageAttestationV1 {
            schema: AuthorityCoverageSchema::V1,
            version: VersionV1,
            scope: self.runtime.scope().clone(),
            approval_intent: intent.approval_intent.clone(),
            challenge: intent.challenge.clone(),
            action_intent: intent.action_intent,
            authorization_requirements: intent.authorization_requirements,
            source_basis: action.basis,
            issuer_id: IssuerId::new("reviewer")?,
            principal: PrincipalId::new("reviewer")?,
            obligations: intent.obligations.clone(),
            issued_at_unix_ms: intent.issued_at_unix_ms,
            expires_at_unix_ms: intent.expires_at_unix_ms,
        };
        let submission = RecoveryApprovalSubmissionV1 {
            intent,
            coverage: NonEmptyBoundedList::new(vec![SignedAuthorityCoverageAttestationV1::sign(
                evidence,
                &self.approval_key,
            )?])?,
        };
        self.execute(
            &identity("approve"),
            RecoveryCommandBodyV1::SubmitApproval {
                workflow_id: id.clone(),
                expected_revision: record.revision,
                approval: text(&submission)?,
            },
        )
        .await?;
        Ok(id)
    }
    fn record(&self, id: &WorkflowId) -> TestResult<RecoveryWorkflowRecordV1> {
        let actor = self.kernel.authenticate_recovery_actor(
            self.runtime.scope(),
            &self.control,
            RecoveryPermission::Inspect,
        )?;
        Ok(self.kernel.read_recovery_workflow(&actor, id)?)
    }
}
#[tokio::test]
async fn recovery_native_disclosure_once_and_exact_receipt_replay() -> TestResult {
    for nonce in [false, true] {
        let f = RecoveryFixture::new(nonce)?;
        let id = f
            .ready()
            .await
            .map_err(|error| format!("ready nonce={nonce}: {error}"))?;
        let record = f.record(&id)?;
        let resume = f.command(
            "resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: record.revision,
            },
        )?;
        let mut response = match f.runtime.execute_command(&f.control, &resume).await {
            Ok(response) => response,
            Err(error) => {
                let actor = f.kernel.authenticate_recovery_actor(
                    f.runtime.scope(),
                    &f.control,
                    RecoveryPermission::Resume,
                )?;
                let current = f.record(&id)?;
                eprintln!(
                    "native recovery stage effect={:?} captured={}",
                    current.effect, current.captured
                );
                eprintln!(
                    "native result replay: {:?}",
                    f.kernel.replay_recovery_result(&actor, &id).err()
                );
                return Err(format!("resume nonce={nonce}: {error}").into());
            }
        };
        if nonce && response.original_response.is_none() {
            let record = f.record(&id)?;
            response = f
                .execute(
                    "execute-original",
                    RecoveryCommandBodyV1::ResumeWorkflow {
                        workflow_id: id.clone(),
                        expected_revision: record.revision,
                    },
                )
                .await?;
        }
        assert!(
            matches!(response.status.effect, EffectObservationV1::Complete { .. }),
            "{:?}",
            response.status
        );
        let receipt = response
            .original_response
            .ok_or("original response")?
            .receipt;
        assert!(receipt.verify_signature()?);
        assert_eq!(f.effects.load(Ordering::SeqCst), 1);
        let replay = f.runtime.execute_command(&f.control, &resume).await?;
        assert_eq!(
            chio_core::canonical_json_bytes(&receipt)?,
            chio_core::canonical_json_bytes(
                &replay.original_response.ok_or("replayed response")?.receipt
            )?
        );
        assert_eq!(f.effects.load(Ordering::SeqCst), 1);
        assert_eq!(f.process.process("root")?.tree_calls, 2);
        let record = f.record(&id)?;
        let native = record.admission.ok_or("intent")?;
        let operation = f
            .authority
            .admission_operation_store()
            .load_by_operation_id(
                &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                    native.native_operation_id.as_str(),
                )?,
            )?
            .ok_or("operation")?;
        assert_eq!(operation.state(), AdmissionOperationState::Completed);
        assert_eq!(operation.execution_nonce_id().is_some(), nonce);
        let usage = f
            .authority
            .budget_store()
            .get_invocation_quota_usage(&BudgetQuotaKey::grant(f.seed.capability.id.as_str(), 0))?
            .ok_or("quota")?;
        assert_eq!(
            (usage.reserved_invocations, usage.captured_invocations),
            (0, 1)
        );
        let observed = f.kernel.observe_recovery_source(f.runtime.scope())?;
        let current = observed.snapshot().ok_or("source")?;
        assert_eq!(current.principal_label, restricted_label());
        assert_eq!(current.lineage_label, restricted_label());
        assert_eq!(current.session_label, restricted_label());
    }
    Ok(())
}

#[tokio::test]
async fn recovery_frozen_denial_gets_a_distinct_successful_native_continuation() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let original_bytes = chio_core::canonical_json_bytes(&f.seed)?;
    let denial = f.process.invoke_known_only("root", "seed", &f.seed).await?;
    assert_eq!(denial.verdict, Verdict::Deny);
    assert!(denial.receipt.verify_signature()?);
    assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    let original_receipt = chio_core::canonical_json_bytes(&denial.receipt)?;
    let frozen_binding = || -> TestResult<(String, u32)> {
        let journal = rusqlite::Connection::open(f.path.join("process.db"))?;
        Ok(journal.query_row(
            "SELECT request_hash, attempts FROM process_calls WHERE process_id='root' AND operation_key='seed'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    };
    let original_binding = frozen_binding()?;
    let id = f.ready().await?;
    let record = f.record(&id)?;
    assert_ne!(record.seed.request_id, f.seed.request_id);
    let result = f
        .execute(
            "disclose-denied-ticket",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: record.revision,
            },
        )
        .await?;
    assert!(matches!(
        result.status.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(
        result
            .original_response
            .ok_or("useful disclosure result")?
            .receipt
            .verify_signature()?
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    assert_eq!(chio_core::canonical_json_bytes(&f.seed)?, original_bytes);
    let replay = f.process.invoke_known_only("root", "seed", &f.seed).await?;
    // A compensated pre-dispatch refusal has no terminal tool outcome to
    // replay. Its current diagnostic may differ; the original logged receipt
    // and frozen process binding must remain immutable and cannot dispatch.
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay.output.is_none());
    assert_eq!(frozen_binding()?, original_binding);
    let receipts = rusqlite::Connection::open(f.path.join("receipts.db"))?;
    let retained: String = receipts.query_row(
        "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id=?1",
        [&denial.receipt.id],
        |row| row.get(0),
    )?;
    let retained: serde_json::Value = serde_json::from_str(&retained)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&retained)?,
        original_receipt
    );
    let mut rewritten = f.seed.clone();
    rewritten.declassification_grant = Some(
        f.record(&id)?
            .signed_grant
            .ok_or("continuation grant")?
            .into(),
    );
    assert!(matches!(
        f.process
            .invoke_known_only("root", "seed", &rewritten)
            .await,
        Err(chio_process::ProcessError::Conflict)
    ));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    Ok(())
}

/// This database is outside the authority/process journals. No unique operation
/// constraint or idempotency shim can conceal an accidental second submission.
struct PersistentEffectServer {
    path: std::path::PathBuf,
    local: Arc<AtomicUsize>,
    behavior: Arc<AtomicUsize>,
    started: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    contract: RecoveryEffectContractV1,
}
impl PersistentEffectServer {
    fn new(
        path: std::path::PathBuf,
        local: Arc<AtomicUsize>,
        behavior: Arc<AtomicUsize>,
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    ) -> TestResult<Self> {
        rusqlite::Connection::open(&path)?.execute_batch(
            "PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS effects(sequence INTEGER PRIMARY KEY,operation TEXT NOT NULL,attempt TEXT NOT NULL,arguments BLOB NOT NULL);"
        )?;
        let contract = authority_history::fixture_effect_contract(
            path.parent().ok_or("effect fixture directory is absent")?,
        )?;
        Ok(Self {
            path,
            local,
            behavior,
            started,
            release,
            contract,
        })
    }
}
#[async_trait::async_trait]
impl ToolServerConnection for PersistentEffectServer {
    fn recovery_effect_contract(&self) -> Option<RecoveryEffectContractV1> {
        Some(self.contract.clone())
    }
    fn server_id(&self) -> &str {
        "server-a"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["send".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(KernelError::Internal("native context required".into()))
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        nested: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.invoke_with_cost_and_context(context, arguments, nested)
            .await
            .map(|(value, _)| value)
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<chio_kernel::ToolInvocationCost>), KernelError> {
        let save = || -> TestResult {
            let dispatch = context.dispatch().ok_or("native dispatch missing")?;
            let db = rusqlite::Connection::open(&self.path)?;
            db.execute(
                "INSERT INTO effects(operation,attempt,arguments) VALUES (?1,?2,?3)",
                rusqlite::params![
                    dispatch.operation_id(),
                    dispatch.attempt_id(),
                    chio_core::canonical_json_bytes(&arguments)?
                ],
            )?;
            Ok(())
        };
        save().map_err(|_| KernelError::Internal("external fixture unavailable".into()))?;
        self.local.fetch_add(1, Ordering::SeqCst);
        crate::recovery::test_cutpoint("effect");
        self.started.notify_one();
        if self.behavior.load(Ordering::SeqCst) == 2 {
            self.release.notified().await;
        }
        if self.behavior.load(Ordering::SeqCst) == 1 {
            return Err(KernelError::Internal("external response lost".into()));
        }
        Ok((arguments, None))
    }
}
fn install_native_fault(kernel: &mut ChioKernel, authority: &SqliteAuthorityStore) -> TestResult {
    if std::env::var_os("CHIO_RECOVERY_CRASH_CHILD").is_none() {
        return Ok(());
    }
    let point = std::env::var("CHIO_RECOVERY_CRASH_POINT")?;
    if point == "admission" {
        kernel.install_native_egress_checkpoint_hook(Arc::new(|_, _, _, _| {
            crate::recovery::test_cutpoint("admission");
        }));
    }
    use chio_store_sqlite::admission_operation_store::NativeDispatchCaptureTransactionTestCutpoint as Capture;
    let capture = match point.as_str() {
        "capture-before-commit" => Some(Capture::BeforeCommit),
        "capture-before-anchor" => Some(Capture::CommittedBeforeAnchor),
        _ => None,
    };
    if let Some(point) = capture {
        authority
            .admission_operation_store()
            .install_native_capture_transaction_cutpoint_for_test(point)?;
    }
    use chio_kernel::DurableFinalizationCutpoint as Finalization;
    let finalization = match point.as_str() {
        "return-recorded" | "return-recorded-revoked" => Some(Finalization::ToolReturnRecorded),
        "evaluation" => Some(Finalization::PostReturnEvaluationBegun),
        "resolved" => Some(Finalization::PostReturnResolved),
        "release-ack" => Some(Finalization::SecurityReleaseAcknowledged),
        "release-checkpoint" => Some(Finalization::SecurityReleaseCheckpointed),
        "terminal" => Some(Finalization::TerminalProjected),
        _ => None,
    };
    if let Some(selected) = finalization {
        kernel.install_durable_finalization_cutpoint(Arc::new(move |actual| {
            if actual == selected {
                crate::recovery::test_cutpoint(&point);
            }
        }));
    }
    Ok(())
}
fn external_count(path: &std::path::Path) -> TestResult<usize> {
    Ok(rusqlite::Connection::open(path.join("effects.db"))?
        .query_row("SELECT count(*) FROM effects", [], |row| {
            row.get::<_, i64>(0)
        })?
        .try_into()?)
}
#[tokio::test]
#[ignore = "only the fresh-process native recovery parent starts this child"]
async fn recovery_crash_child() -> TestResult {
    let path =
        std::path::PathBuf::from(std::env::var_os("CHIO_RECOVERY_CRASH_ROOT").ok_or("child root")?);
    let nonce = std::env::var_os("CHIO_RECOVERY_CRASH_NONCE").is_some();
    let f = RecoveryFixture::open(path, None, nonce)?;
    let id = f.ready().await?;
    let record = f.record(&id)?;
    let resume = f.command(
        "resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id,
            expected_revision: record.revision,
        },
    )?;
    std::fs::write(
        f.path.join("resume.json"),
        chio_core::canonical_json_bytes(&resume)?,
    )?;
    let response = f.runtime.execute_command(&f.control, &resume).await?;
    if nonce && response.original_response.is_none() {
        let record = f.record(&response.status.workflow_id)?;
        f.execute(
            "execute-original",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: record.workflow_id,
                expected_revision: record.revision,
            },
        )
        .await?;
    }
    let returned = f.record(&response.status.workflow_id)?;
    let effect = match &returned.effect {
        EffectObservationV1::NeverAdmitted => "never_admitted",
        EffectObservationV1::AdmissionUnresolved { .. } => "admission_unresolved",
        EffectObservationV1::ClosedBeforeEffect { .. } => "closed_before_effect",
        EffectObservationV1::AwaitingApproval { .. } => "awaiting_approval",
        EffectObservationV1::InFlight { .. } => "in_flight",
        EffectObservationV1::AwaitingCallerReport { .. } => "awaiting_caller_report",
        EffectObservationV1::Unknown { .. } => "unknown",
        EffectObservationV1::Complete { .. } => "complete",
        EffectObservationV1::Partial { .. } => "partial",
        EffectObservationV1::FailedAfterEffect { .. } => "failed_after_effect",
    };
    eprintln!(
        "recovery crash child returned: control={:?} effect={effect} captured={} admission_closed={} revision={} response_present={} external_effects={}",
        returned.control,
        returned.captured,
        returned.admission_closed,
        returned.revision.get(),
        response.original_response.is_some(),
        external_count(&f.path)?,
    );
    if let Some(intent) = returned.admission.as_ref() {
        use chio_kernel::ReceiptStore;
        use chio_kernel::admission_operation::{AdmissionOperationId, AdmissionTerminalReplay};
        if let Some(operation) = f
            .authority
            .admission_operation_store()
            .load_by_operation_id(&AdmissionOperationId::from_persisted(
                intent.native_operation_id.as_str(),
            )?)?
        {
            eprintln!("recovery crash child native state={:?}", operation.state());
            if let Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) =
                operation.terminal_replay()
            {
                if let Some(receipt) = f
                    .authority
                    .admission_operation_store()
                    .load_chio_receipt(receipt_id.as_str())?
                {
                    if let Some(chio_core::receipt::decision::Decision::Deny { guard, .. }) =
                        receipt.decision
                    {
                        eprintln!("recovery crash child native denial guard={guard}");
                    }
                }
            }
        }
    }
    Err("child did not reach its declared cutpoint".into())
}
#[cfg(unix)]
#[tokio::test]
async fn recovery_fresh_process_cutpoints_preserve_original_ownership() -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};
    // Includes all new bridge/issuance boundaries plus the existing physical
    // native transaction and every post-return checkpoint. No unwind/Drop runs.
    let points = [
        "creation",
        "action",
        "reservation",
        "reservation-attached",
        "selection",
        "review",
        "approval",
        "issuance",
        "signed",
        "signature-attached",
        "envelope",
        "process-finalized",
        "admission",
        "capture-before-commit",
        "capture-before-anchor",
        "effect",
        "return-recorded",
        "evaluation",
        "resolved",
        "release-ack",
        "release-checkpoint",
        "terminal",
        "returned-response",
        "projection",
        "nonce-preflight",
        "nonce-attached",
        "return-recorded-revoked",
    ];
    for point in points {
        if std::env::var("CHIO_RECOVERY_CRASH_SINGLE_POINT").is_ok_and(|only| only != point) {
            continue;
        }
        let directory = tempfile::tempdir()?;
        let nonce = matches!(point, "nonce-preflight" | "nonce-attached");
        // The original closed denial predates every recovery cutpoint. Its
        // durable custody survives the fresh child and is never redispatched.
        let original = RecoveryFixture::open(directory.path().to_path_buf(), None, nonce)?;
        original.denied_seed_named("ticket-1").await?;
        assert_eq!(original.process.process("root")?.tree_calls, 1);
        drop(original);
        let log = std::fs::File::create(directory.path().join("child.log"))?;
        let mut command = std::process::Command::new(std::env::current_exe()?);
        command
            .arg("--exact")
            .arg("recovery::tests::recovery_crash_child")
            .arg("--ignored")
            .arg("--nocapture")
            .env("CHIO_RECOVERY_CRASH_CHILD", "1")
            .env("CHIO_RECOVERY_CRASH_ROOT", directory.path())
            .env("CHIO_RECOVERY_CRASH_POINT", point)
            .stdout(log.try_clone()?)
            .stderr(log);
        if nonce {
            command.env("CHIO_RECOVERY_CRASH_NONCE", "1");
        }
        let mut child = command.spawn()?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if started.elapsed() > Duration::from_secs(90) {
                child.kill()?;
                child.wait()?;
                return Err(format!("cutpoint timed out: {point}").into());
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        let log = std::fs::read_to_string(directory.path().join("child.log"))?;
        assert_eq!(status.signal(), Some(6), "{point}: {log}");
        let marker = match point {
            "capture-before-commit" => "native capture transaction cutpoint: BeforeCommit",
            "capture-before-anchor" => "native capture transaction cutpoint: CommittedBeforeAnchor",
            _ => "recovery crash cutpoint:",
        };
        assert!(
            log.contains(marker),
            "aborted outside declared cutpoint {point}: {log}"
        );
        let before = external_count(directory.path())?;
        if point == "return-recorded-revoked" {
            std::fs::write(
                directory.path().join("revoke-initiating"),
                b"current settlement remains independent",
            )?;
        }
        let f = RecoveryFixture::open(directory.path().to_path_buf(), None, nonce)?;
        let id: WorkflowId = if f.path.join("workflow.json").exists() {
            serde_json::from_slice(&std::fs::read(f.path.join("workflow.json"))?)?
        } else {
            f.ready().await?
        };
        let original = f.record(&id)?;
        let original_nonce = if nonce {
            let store = f.authority.admission_operation_store();
            let operation = store
                .load_by_operation_id(
                    &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                        original
                            .admission
                            .as_ref()
                            .ok_or("nonce intent")?
                            .native_operation_id
                            .as_str(),
                    )?,
                )?
                .ok_or("nonce original")?;
            let issuance = store.load_execution_nonce_issuance(
                operation.binding().operation_id(),
                &f.authority.mutation_fence(),
                now_ms()?,
            )?;
            Some(
                issuance
                    .ok_or("original nonce issuance")?
                    .canonical_bytes()
                    .to_vec(),
            )
        } else {
            None
        };
        let action = original.action.clone();
        let signed = original.signed_grant.clone();
        let envelope = original.envelope.clone();
        let intent = original.admission.clone();
        if !original.captured && original.admission.is_none() {
            f.ready().await?;
        }
        let record = f.record(&id)?;
        let resume: RecoveryCommandV1 = if f.path.join("resume.json").exists() {
            serde_json::from_slice(&std::fs::read(f.path.join("resume.json"))?)?
        } else {
            f.command(
                "resume",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: id.clone(),
                    expected_revision: record.revision,
                },
            )?
        };
        let mut response = f
            .runtime
            .execute_command(&f.control, &resume)
            .await
            .map_err(|e| format!("{point}: {e}"))?;
        if nonce && !response.status.effect.is_settled() {
            let record = f.record(&id)?;
            response = f
                .execute(
                    "execute-original",
                    RecoveryCommandBodyV1::ResumeWorkflow {
                        workflow_id: id.clone(),
                        expected_revision: record.revision,
                    },
                )
                .await?;
        }
        let after = external_count(f.path.as_path())?;
        if original.captured {
            assert_eq!(after, before, "resubmitted captured effect: {point}");
        }
        let expected_effects = if matches!(
            point,
            "admission" | "capture-before-commit" | "capture-before-anchor"
        ) {
            0
        } else {
            1
        };
        assert_eq!(
            after, expected_effects,
            "lost or repeated physical effect: {point}, {:?}",
            response.status.effect
        );
        let recovered = f.record(&id)?;
        if let Some(bytes) = original_nonce {
            let intent = recovered
                .admission
                .as_ref()
                .ok_or("recovered nonce intent")?;
            let operation = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                intent.native_operation_id.as_str(),
            )?;
            let issuance = f
                .authority
                .admission_operation_store()
                .load_execution_nonce_issuance(
                    &operation,
                    &f.authority.mutation_fence(),
                    now_ms()?,
                )?
                .ok_or("recovered original nonce")?;
            assert_eq!(
                bytes,
                issuance.canonical_bytes(),
                "renewed original nonce: {point}"
            );
        }
        if point == "signed" {
            assert_eq!(
                std::fs::read(f.path.join("unacknowledged-signature.json"))?,
                chio_core::canonical_json_bytes(
                    recovered
                        .signed_grant
                        .as_ref()
                        .ok_or("recovered signature")?
                )?
            );
        }
        for (old, new) in [
            (
                action
                    .map(|v| chio_core::canonical_json_bytes(&v))
                    .transpose()?,
                recovered
                    .action
                    .as_ref()
                    .map(chio_core::canonical_json_bytes)
                    .transpose()?,
            ),
            (
                signed
                    .map(|v| chio_core::canonical_json_bytes(&v))
                    .transpose()?,
                recovered
                    .signed_grant
                    .as_ref()
                    .map(chio_core::canonical_json_bytes)
                    .transpose()?,
            ),
            (
                envelope
                    .map(|v| chio_core::canonical_json_bytes(&v))
                    .transpose()?,
                recovered
                    .envelope
                    .as_ref()
                    .map(chio_core::canonical_json_bytes)
                    .transpose()?,
            ),
            (
                intent
                    .map(|v| chio_core::canonical_json_bytes(&v))
                    .transpose()?,
                recovered
                    .admission
                    .as_ref()
                    .map(chio_core::canonical_json_bytes)
                    .transpose()?,
            ),
        ] {
            if let Some(old) = old {
                assert_eq!(Some(old), new, "rewrote original: {point}");
            }
        }
        assert_eq!(
            f.process.process("root")?.tree_calls,
            2,
            "process quota: {point}"
        );
        if let Some(original_response) = response.original_response {
            let replay = f.runtime.execute_command(&f.control, &resume).await?;
            assert_eq!(
                chio_core::canonical_json_bytes(&original_response.receipt)?,
                chio_core::canonical_json_bytes(
                    &replay
                        .original_response
                        .ok_or("lost original receipt")?
                        .receipt
                )?
            );
        }
        eprintln!(
            "RECOVERY_CRASH_CUTPOINT {point} before={before} after={after} effect={:?}",
            recovered.effect
        );
    }
    Ok(())
}

#[tokio::test]
async fn recovery_command_replay_conflict_rotation_and_revocation() -> TestResult {
    use crate::recovery::RecoveryRuntimeError;
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let first = f.command(
        "inspect-stable",
        RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: id.clone(),
        },
    )?;
    f.runtime.execute_command(&f.control, &first).await?;
    let mut changed = first.clone();
    changed.command = RecoveryCommandBodyV1::InspectWorkflow {
        workflow_id: WorkflowId::new("foreign-workflow")?,
    };
    assert_eq!(
        f.runtime.execute_command(&f.control, &changed).await.err(),
        Some(RecoveryRuntimeError::Conflict)
    );
    let record = f.record(&id)?;
    let resume = f.command(
        "resume-stable",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: record.revision,
        },
    )?;
    let original = f
        .runtime
        .execute_command(&f.control, &resume)
        .await?
        .original_response
        .ok_or("result")?;
    let renewed =
        f.kernel
            .issue_capability(&f.approval_key.public_key(), f.control.scope.clone(), 600)?;
    let replay = f
        .runtime
        .execute_command(&renewed, &resume)
        .await?
        .original_response
        .ok_or("replay")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&original.receipt)?,
        chio_core::canonical_json_bytes(&replay.receipt)?
    );
    assert_eq!(external_count(&f.path)?, 1);
    f.kernel.revoke_capability(&f.seed.capability.id)?;
    // Initiating authority is historical; current release authority remains live.
    f.runtime.execute_command(&renewed, &resume).await?;
    f.runtime.settle(&renewed, &id)?;
    f.kernel.revoke_capability(&renewed.id)?;
    assert_eq!(
        f.runtime.execute_command(&renewed, &resume).await.err(),
        Some(RecoveryRuntimeError::AuthorityDenied)
    );
    assert_eq!(external_count(&f.path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    Ok(())
}
#[tokio::test]
async fn recovery_cancel_negative_lookup_fences_late_original_admission() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let custody = crate::recovery::freeze_original_for_test(&f.runtime, &f.control, &id)?;
    let record = f.record(&id)?;
    assert!(record.admission.is_some());
    assert!(!record.captured);
    f.execute(
        "cancel",
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: id.clone(),
            expected_revision: record.revision,
        },
    )
    .await?;
    f.runtime.settle(&f.control, &id)?;
    let closed = f.record(&id)?;
    assert!(closed.admission_closed);
    assert_eq!(closed.control, WorkflowControlV1::Cancelled);
    let key = format!("recovery:{}", closed.continuation_id.as_str());
    let _ = f
        .process
        .invoke_known_only("root", &key, custody.request())
        .await;
    assert_eq!(external_count(&f.path)?, 0);
    let native = closed.admission.ok_or("intent")?;
    assert!(
        f.authority
            .admission_operation_store()
            .load_by_operation_id(
                &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                    native.native_operation_id.as_str()
                )?
            )?
            .is_none()
    );
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    assert!(f.record(&id)?.admission_closed);
    Ok(())
}
#[tokio::test]
async fn recovery_cancel_after_capture_preserves_effect_and_no_lock_spans_await() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    f.behavior.store(2, Ordering::SeqCst);
    let record = f.record(&id)?;
    let resume = f.command(
        "resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: record.revision,
        },
    )?;
    let cancel = async {
        tokio::time::timeout(std::time::Duration::from_secs(30), f.started.notified()).await?;
        let record = f.record(&id)?;
        assert!(record.captured);
        f.execute(
            "cancel-after-capture",
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: id.clone(),
                expected_revision: record.revision,
            },
        )
        .await?;
        f.release.notify_one();
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (result, cancel) = tokio::time::timeout(std::time::Duration::from_secs(45), async {
        tokio::join!(f.runtime.execute_command(&f.control, &resume), cancel)
    })
    .await?;
    cancel?;
    let result = result?;
    assert!(matches!(
        result.status.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(matches!(
        result.status.control,
        WorkflowControlV1::CancelRequested | WorkflowControlV1::Cancelled
    ));
    f.runtime.execute_command(&f.control, &resume).await?;
    assert_eq!(external_count(&f.path)?, 1);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    Ok(())
}
#[tokio::test]
async fn recovery_partial_finality_is_positive_scoped_and_spends_the_original() -> TestResult {
    use chio_core_types::recovery::SignedRecoveryProviderFinalityV1;
    for disposition in [
        RecoveryEffectDisposition::Succeeded,
        RecoveryEffectDisposition::PartiallyApplied,
        RecoveryEffectDisposition::FailedAfterEffect,
    ] {
        let f = RecoveryFixture::new(false)?;
        let id = f.ready().await?;
        f.behavior.store(1, Ordering::SeqCst);
        let record = f.record(&id)?;
        let resume = f.command(
            "resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: record.revision,
            },
        )?;
        let response = f.runtime.execute_command(&f.control, &resume).await?;
        assert!(matches!(
            response.status.effect,
            EffectObservationV1::Unknown { .. }
        ));
        assert_eq!(external_count(&f.path)?, 1);
        f.kernel.revoke_capability(&f.seed.capability.id)?;
        let actor = f.kernel.authenticate_recovery_actor(
            f.runtime.scope(),
            &f.control,
            RecoveryPermission::Settle,
        )?;
        let lookup = f.kernel.reserve_recovery_provider_lookup(&actor, &id)?;
        let record = lookup.workflow();
        let intent = record.admission.as_ref().ok_or("intent")?;
        let native = f
            .authority
            .admission_operation_store()
            .load_by_operation_id(
                &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                    intent.native_operation_id.as_str(),
                )?,
            )?
            .ok_or("native")?;
        let before = chio_core::canonical_json_bytes(&native.to_persisted())?;
        let operation = match &record.effect {
            EffectObservationV1::Unknown { operation } => operation,
            _ => return Err("unknown required".into()),
        };
        let profile = lookup.deployment();
        let now = now_ms()?;
        let body = RecoveryProviderFinalityV1 {
            schema: RecoveryProviderFinalitySchema::V1,
            version: VersionV1,
            scope: record.scope.clone(),
            workflow_id: record.workflow_id.clone(),
            continuation_id: record.continuation_id.clone(),
            operation_id: operation.operation_id().clone(),
            native_admission_digest: operation.native_admission_digest(),
            attempt_id: ProviderAttemptId::new(
                &native.provider_attempt().ok_or("attempt")?.attempt_id,
            )?,
            provider: profile.effect_contract.provider.clone(),
            account: profile.effect_contract.account.clone(),
            resource_digest: ResourceDigest::from_bytes(recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::ProviderResource,
                &profile.effect_contract.resource,
            )?),
            contract_digest: profile.contract_digest,
            observed_at_unix_ms: SafeInteger::new(now)?,
            expires_at_unix_ms: SafeInteger::new(now + 30_000)?,
            disposition,
            applied_effects: SafeInteger::new(1)?,
        };
        let signer = Keypair::from_seed(&[143; 32]);
        let mut foreign = body.clone();
        foreign.workflow_id = WorkflowId::new("foreign")?;
        let foreign = SignedRecoveryProviderFinalityV1::sign(foreign, &signer)?;
        assert!(foreign.verify_signature()?);
        assert!(
            f.kernel
                .attach_recovery_provider_finality(&actor, &id, &foreign)
                .is_err()
        );
        let proof = SignedRecoveryProviderFinalityV1::sign(body, &signer)?;
        f.kernel
            .attach_recovery_provider_finality(&actor, &id, &proof)?;
        f.kernel
            .attach_recovery_provider_finality(&actor, &id, &proof)?;
        let settled = f.runtime.settle(&f.control, &id)?;
        assert_eq!(settled.effect.applied_effects(), Some(SafeInteger::new(1)?));
        assert!(settled.effect.is_settled());
        assert_eq!(settled.release, ReleaseDispositionV1::NotAvailable);
        f.runtime.execute_command(&f.control, &resume).await?;
        assert_eq!(external_count(&f.path)?, 1);
        assert_eq!(f.process.process("root")?.tree_calls, 2);
        let after = f
            .authority
            .admission_operation_store()
            .load_by_operation_id(native.binding().operation_id())?
            .ok_or("original")?;
        assert_eq!(
            before,
            chio_core::canonical_json_bytes(&after.to_persisted())?
        );
        assert_eq!(
            after.state(),
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "explicit regeneration of public synthetic native recovery conformance vectors"]
async fn recovery_export_signed_vectors() -> TestResult {
    use chio_core_types::recovery::SignedRecoveryProviderFinalityV1;
    let output = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_AUTHORITY_VECTORS")
            .ok_or("explicit vector path required")?,
    );
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    crate::recovery::freeze_original_for_test(&f.runtime, &f.control, &id)?;
    let record = f.record(&id)?;
    let review = f.runtime.review_document(&f.control, &id)?;
    let command = f.command(
        "resume-vector",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: record.revision,
        },
    )?;
    let result = f.runtime.execute_command(&f.control, &command).await?;
    let record = f.record(&id)?;
    let action = record.action.as_ref().ok_or("action")?;
    let intent = record.admission.as_ref().ok_or("admission")?;
    let native = f
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                intent.native_operation_id.as_str(),
            )?,
        )?
        .ok_or("native")?;
    let operation = record.effect.operation().ok_or("operation")?;
    let profile = f.kernel.recovery_deployment(f.runtime.scope())?;
    let now = now_ms()?;
    let finality = SignedRecoveryProviderFinalityV1::sign(
        RecoveryProviderFinalityV1 {
            schema: RecoveryProviderFinalitySchema::V1,
            version: VersionV1,
            scope: record.scope.clone(),
            workflow_id: id,
            continuation_id: record.continuation_id.clone(),
            operation_id: operation.operation_id().clone(),
            native_admission_digest: operation.native_admission_digest(),
            attempt_id: ProviderAttemptId::new(
                &native.provider_attempt().ok_or("attempt")?.attempt_id,
            )?,
            provider: profile.effect_contract.provider.clone(),
            account: profile.effect_contract.account.clone(),
            resource_digest: ResourceDigest::from_bytes(recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::ProviderResource,
                &profile.effect_contract.resource,
            )?),
            contract_digest: profile.contract_digest,
            observed_at_unix_ms: SafeInteger::new(now)?,
            expires_at_unix_ms: SafeInteger::new(now + 30_000)?,
            disposition: RecoveryEffectDisposition::Succeeded,
            applied_effects: SafeInteger::new(1)?,
        },
        &Keypair::from_seed(&[143; 32]),
    )?;
    let request: ToolCallRequest =
        serde_json::from_str(record.envelope.as_ref().ok_or("envelope")?.request.as_str())?;
    let data = serde_json::json!({"format_version":1,"provenance":"public synthetic keys; actual native recovery capture, protected custody and receipt",
        "action":action,"requirements":action.authorization_requirements,"approval_intent":record.review,"coverage":record.approval.as_ref().ok_or("approval")?.coverage,
        "grant":record.signed_grant,"provider_finality":finality,"support_issue_effect":profile.effect_contract,
        "support_issue_input":request.arguments,"request":request,"command":command,"command_result":result,"command_response":result.status,"review_document":review});
    std::fs::write(output, chio_core::canonical_json_bytes(&data)?)?;
    Ok(())
}

#[tokio::test]
async fn recovery_workflow_flood_retains_settlement_and_tombstones() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("workflow-flood"),
        b"bounded quota campaign",
    )?;
    let f = RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?;
    let id = f.ready().await?;
    let record = f.record(&id)?;
    let resume = f.command(
        "resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: record.revision,
        },
    )?;
    f.runtime.execute_command(&f.control, &resume).await?;
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Create,
    )?;
    let mut another_process = f.kernel.recovery_deployment(f.runtime.scope())?;
    another_process.scope.process_id = ProcessId::new("another-process-scope")?;
    f.process.create_root(
        another_process.scope.process_id.as_str(),
        &f.seed.capability,
        ProcessLimits {
            max_processes: 8,
            max_depth: 2,
            max_calls: 256,
            state: Default::default(),
        },
    )?;
    another_process.security_context = f
        .process
        .recovery_security_context(another_process.scope.process_id.as_str())?;
    another_process.authority_scope = recovery_authority_scope_digest(&another_process)?;
    f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&another_process)?;
    let another_actor = f.kernel.authenticate_recovery_actor(
        &another_process.scope,
        &f.control,
        RecoveryPermission::Create,
    )?;
    for index in 1..64 {
        let selected = if index % 2 == 0 {
            &another_actor
        } else {
            &actor
        };
        let key = format!("flood-denial-{index}");
        let seed = f.process.tool_request(
            selected.scope().process_id.as_str(),
            &key,
            &f.seed.server_id,
            &f.seed.tool_name,
            f.seed.arguments.clone(),
        )?;
        let denial = f
            .process
            .invoke_known_only(selected.scope().process_id.as_str(), &key, &seed)
            .await?;
        assert_eq!(denial.verdict, Verdict::Deny);
        let command = f.command(
            &format!("flood-{index}"),
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new(&format!("ticket-{index}-flood"))?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )?;
        f.kernel
            .execute_recovery_command_with_origin(selected, &command, &f.process)?;
    }
    for selected in [&actor, &another_actor] {
        let key = format!("flood-over-limit-{}", selected.scope().process_id.as_str());
        let seed = f.process.tool_request(
            selected.scope().process_id.as_str(),
            &key,
            &f.seed.server_id,
            &f.seed.tool_name,
            f.seed.arguments.clone(),
        )?;
        let denial = f
            .process
            .invoke_known_only(selected.scope().process_id.as_str(), &key, &seed)
            .await?;
        assert_eq!(denial.verdict, Verdict::Deny);
        let command = f.command(
            &key,
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new(&key)?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )?;
        assert_eq!(
            f.kernel
                .execute_recovery_command_with_origin(selected, &command, &f.process)
                .err(),
            Some(RecoveryCommandError::Unavailable)
        );
    }
    f.runtime.settle(&f.control, &id)?;
    assert!(matches!(
        f.runtime
            .execute_command(&f.control, &resume)
            .await?
            .status
            .effect,
        EffectObservationV1::Complete { .. }
    ));
    assert_eq!(external_count(&f.path)?, 1);
    // One initial denial and continuation reservation, 32 further root
    // denials, and the over-limit root denial. No recovery dispatch is repeated.
    assert_eq!(f.process.process("root")?.tree_calls, 35);
    assert_eq!(
        f.process
            .process(another_process.scope.process_id.as_str())?
            .tree_calls,
        32
    );
    let connection = rusqlite::Connection::open(f.path.join("admission.db"))?;
    let workflows: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(workflows, 64);
    assert!(
        connection
            .execute(
                "DELETE FROM admission_operation_recovery_records WHERE kind='workflow'",
                []
            )
            .is_err()
    );
    assert!(connection.execute("UPDATE admission_operation_recovery_records SET native_request='foreign' WHERE native_request IS NOT NULL",[]).is_err());
    let native = f.record(&id)?.admission.ok_or("intent")?;
    assert!(
        f.authority
            .admission_operation_store()
            .load_by_operation_id(
                &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                    native.native_operation_id.as_str()
                )?
            )?
            .is_some()
    );
    Ok(())
}
#[tokio::test]
async fn recovery_two_coordinators_select_once_and_review_exact_payload() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let seed = f.denied_seed_named("concurrent").await?;
    let result = f
        .execute(
            "create",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("concurrent")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )
        .await?;
    let id = result.status.workflow_id;
    let record = f.record(&id)?;
    let action = record.action.ok_or("action")?;
    let offer = OfferId::new(&format!(
        "offer:{}",
        recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
            &action
        )?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
    ))?;
    let first = f.command(
        "select-1",
        RecoveryCommandBodyV1::SelectOffer {
            workflow_id: id.clone(),
            expected_revision: record.revision,
            offer_id: offer.clone(),
        },
    )?;
    let second = f.command(
        "select-2",
        RecoveryCommandBodyV1::SelectOffer {
            workflow_id: id.clone(),
            expected_revision: record.revision,
            offer_id: offer,
        },
    )?;
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        &f.control,
        RecoveryPermission::Select,
    )?;
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let handles = [first.clone(), second]
            .into_iter()
            .map(|command| {
                let barrier = &barrier;
                let actor = &actor;
                let kernel = &f.kernel;
                scope.spawn(move || {
                    barrier.wait();
                    kernel.execute_recovery_command(actor, &command)
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| "selection worker panicked"))
            .collect::<std::result::Result<Vec<_>, _>>()
    })?;
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(RecoveryCommandError::Conflict)))
            .count(),
        1
    );
    let review = f.runtime.review_document(&f.control, &id)?;
    let preview: Value = serde_json::from_str(review.canonical_preview.as_str())?;
    assert_eq!(preview[1]["arguments"], f.seed.arguments);
    assert_eq!(
        preview[1]["capability_signing_body"],
        serde_json::to_value(f.seed.capability.signing_body())?
    );
    for field in [
        "server_id",
        "tool_name",
        "agent_id",
        "request_id",
        "model_metadata",
        "governed_intent",
        "federated_origin_kernel_id",
    ] {
        assert!(
            preview[1].get(field).is_some(),
            "missing exact review field: {field}"
        );
    }
    assert_eq!(
        review.intent.preview,
        recovery_review_digest(
            &f.record(&id)?.action.ok_or("action")?,
            &f.record(&id)?.seed
        )?
    );
    assert_eq!(external_count(&f.path)?, 0);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[tokio::test]
async fn recovery_transport_closed_replay_and_audience_refusals() -> TestResult {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let router = crate::recovery::recovery_router(f.runtime.clone())?;
    let command = f.command(
        "transport-inspect",
        RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: id.clone(),
        },
    )?;
    let envelope = serde_json::json!({"capability":serde_json::to_string_pretty(&f.control)?,"command":std::str::from_utf8(&chio_core::canonical_json_bytes(&command)?)?});
    let wire = chio_core::canonical_json_bytes(&envelope)?;
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/recovery/commands")
            .header("content-type", "application/json")
            .body(Body::from(wire.clone()))
    };
    let response = router.clone().oneshot(request()?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = serde_json::from_slice(&to_bytes(response.into_body(), 262144).await?)?;
    assert_eq!(result["status"]["workflow_id"], serde_json::to_value(&id)?);
    let response = router.clone().oneshot(request()?).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&to_bytes(response.into_body(), 262144).await?)?,
        result
    );
    let mut changed = command.clone();
    changed.command = RecoveryCommandBodyV1::InspectWorkflow {
        workflow_id: WorkflowId::new("foreign-canary")?,
    };
    let bytes = chio_core::canonical_json_bytes(
        &serde_json::json!({"capability":serde_json::to_string(&f.control)?,"command":std::str::from_utf8(&chio_core::canonical_json_bytes(&changed)?)?}),
    )?;
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/recovery/commands")
                .body(Body::from(bytes))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = to_bytes(response.into_body(), 262144).await?;
    assert_eq!(bytes.as_ref(), b"recovery.conflict");
    let mut unknown = envelope.clone();
    unknown["unexpected"] = "protected-canary".into();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/recovery/commands")
                .body(Body::from(chio_core::canonical_json_bytes(&unknown)?))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        !std::str::from_utf8(&to_bytes(response.into_body(), 262144).await?)?
            .contains("protected-canary")
    );
    f.kernel.revoke_capability(&f.control.id)?;
    let response = router.oneshot(request()?).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}
#[tokio::test]
async fn recovery_expired_initiating_authority_cannot_renew_pending_work() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let before = f.record(&id)?;
    let action = chio_core::canonical_json_bytes(&before.action)?;
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(f.seed.capability.expires_at + 1, []);
    let current = &f.control;
    let resume = f.command(
        "expired-original",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: before.revision,
        },
    )?;
    assert!(f.runtime.execute_command(current, &resume).await.is_err());
    let actor = f.kernel.authenticate_recovery_actor(
        f.runtime.scope(),
        current,
        RecoveryPermission::Inspect,
    )?;
    let after = f.kernel.read_recovery_workflow(&actor, &id)?;
    assert_eq!(action, chio_core::canonical_json_bytes(&after.action)?);
    assert!(after.issuance.is_none());
    assert!(after.envelope.is_none());
    assert!(!after.captured);
    assert_eq!(external_count(&f.path)?, 0);
    assert_eq!(f.process.process("root")?.tree_calls, 2);
    Ok(())
}
#[tokio::test]
async fn recovery_rotated_scope_refuses_pending_approval_without_replacing_identity() -> TestResult
{
    let f = RecoveryFixture::new(false)?;
    let id = f.ready().await?;
    let before = f.record(&id)?;
    let mut profile = f.kernel.recovery_deployment(f.runtime.scope())?;
    let key = Keypair::from_seed(&[144; 32]);
    let mut assignments = profile.coverage.as_slice().to_vec();
    assignments[0].key = key.public_key();
    profile.coverage = NonEmptyBoundedList::new(assignments)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&profile)?;
    let resume = f.command(
        "rotated-original",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: id.clone(),
            expected_revision: before.revision,
        },
    )?;
    assert!(
        f.runtime
            .execute_command(&f.control, &resume)
            .await
            .is_err()
    );
    let after = f.record(&id)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&before.action)?,
        chio_core::canonical_json_bytes(&after.action)?
    );
    assert_eq!(before.continuation_id, after.continuation_id);
    assert!(after.issuance.is_none());
    assert!(after.envelope.is_none());
    assert!(!after.captured);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}

mod knowledge;
