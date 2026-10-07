//! Production native capture and release, with an independently counted provider.
use super::*;
use crate::semantic::*;
use chio_core_types::recovery::*;
use chio_manifest::{
    sign_manifest, AuthoritativeToolPolicy, RuntimeToolTopology, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use chio_security_types::semantic::*;
use chio_store_sqlite::admission_operation_store::NativeSemanticInstallationV1;
#[path = "../../../../../../fixtures/recovery-semantic-profile.rs"]
mod profile;
use profile::*;
#[path = "semantic/completed_delivery.rs"]
mod completed_delivery;
#[path = "semantic/constraints.rs"]
mod constraints;
#[path = "semantic/dispatch_interceptors.rs"]
mod dispatch_interceptors;
#[path = "semantic/emergency_stop_finalization.rs"]
mod emergency_stop_finalization;
#[path = "semantic/finalization_history.rs"]
mod finalization_history;
#[path = "semantic/grant_sources.rs"]
mod grant_sources;
#[path = "semantic/legacy_annotation_history.rs"]
mod legacy_annotation_history;
#[path = "semantic/legacy_output_history.rs"]
mod legacy_output_history;
#[path = "semantic/legacy_status_history.rs"]
mod legacy_status_history;
#[path = "semantic/status_observations.rs"]
mod status_observations;
#[path = "semantic/status_refusals.rs"]
mod status_refusals;
#[path = "semantic/trusted_history.rs"]
mod trusted_history;
use dispatch_interceptors::{ExpiringHeldSemanticConnector, SaturatedSemanticConnector};

pub(super) fn fixture_output_constraints(
    path: &std::path::Path,
) -> TestResult<Vec<chio_core::capability::scope::Constraint>> {
    if path.join("semantic-mismatched-output-digest").exists() {
        Ok(vec![
            chio_core::capability::scope::Constraint::OutputDigestSha256(chio_core::sha256_hex(
                b"an output the semantic provider will never return",
            )),
        ])
    } else {
        Ok(vec![])
    }
}

fn kind(path: &std::path::Path) -> TestResult<SemanticOperationKindV1> {
    Ok(
        match std::fs::read_to_string(path.join("semantic-kind"))?.as_str() {
            "read"
            | "read-weak-manifest"
            | "read-missing-status"
            | "annotated-read"
            | "annotated-read-weak-manifest"
            | "annotated-disclosure"
            | "acl-subjects" => SemanticOperationKindV1::SupportRead,
            "write" | "saturated-write" | "alternate" | "error" | "transform" | "historical"
            | "current" | "held" | "held-expired" | "external-history" | "trusted-history" => {
                SemanticOperationKindV1::IssueWrite
            }
            "project" => SemanticOperationKindV1::FieldProjection,
            _ => return Err("invalid semantic fixture".into()),
        },
    )
}
pub(super) fn manifest(path: &std::path::Path) -> TestResult<Arc<VerifiedManifestRegistry>> {
    let key = Keypair::from_seed(&[73; 32]);
    let mode = std::fs::read_to_string(path.join("semantic-kind"))?;
    let output_floor = if matches!(
        mode.as_str(),
        "read-weak-manifest"
            | "read-missing-status"
            | "annotated-read-weak-manifest"
            | "external-history"
            | "trusted-history"
    ) {
        InformationLabel::bottom()
    } else {
        restricted_label()
    };
    let disclosure = mode == "annotated-disclosure";
    let input_audience = if disclosure {
        InformationLabel::bottom()
    } else {
        restricted_label()
    };
    let purposes: std::collections::BTreeSet<_> = if disclosure {
        std::iter::once(DeclassificationPurpose::new("approved-disclosure")?).collect()
    } else {
        Default::default()
    };
    let flow = ToolFlowDeclaration::new(
        Some(output_floor.clone()),
        Some(input_audience.clone()),
        disclosure,
        purposes.clone(),
    )?;
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.into(),
        server_id: "semantic-a".into(),
        name: "Semantic fixture".into(),
        description: None,
        version: "1.0.0".into(),
        tools: vec![ToolDefinition {
            name: "remedy".into(),
            description: "bounded native remedy".into(),
            input_schema: serde_json::json!({"type":"object"}),
            output_schema: Some(serde_json::json!({"type":"object"})),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: kind(path)? != SemanticOperationKindV1::IssueWrite,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: None,
            flow: Some(flow),
        }],
        server_tools: vec![],
        required_permissions: None,
        public_key: key.public_key().to_hex(),
    };
    let source_manifest = ToolManifest {
        server_id: "semantic-source".into(),
        tools: manifest
            .tools
            .clone()
            .into_iter()
            .map(|mut tool| {
                tool.annotations.read_only = true;
                tool
            })
            .collect(),
        ..manifest.clone()
    };
    let signed = sign_manifest(&manifest, &key)?;
    let policy = AuthoritativeToolPolicy::new(
        vec![input_audience.clone()],
        output_floor.clone(),
        purposes.clone(),
    )?;
    let mut registry = Arc::try_unwrap(declassification_registry(&DeclassificationPurpose::new(
        "approved-disclosure",
    )?))
    .map_err(|_| "manifest still borrowed")?;
    registry.register(
        signed,
        &key.public_key(),
        &BTreeMap::from([("remedy".into(), policy)]),
        &BTreeMap::from([("remedy".into(), RuntimeToolTopology::remote())]),
    )?;
    let source_policy = AuthoritativeToolPolicy::new(vec![input_audience], output_floor, purposes)?;
    registry.register(
        sign_manifest(&source_manifest, &key)?,
        &key.public_key(),
        &BTreeMap::from([("remedy".into(), source_policy)]),
        &BTreeMap::from([("remedy".into(), RuntimeToolTopology::remote())]),
    )?;
    Ok(Arc::new(registry))
}
struct CountingTransport {
    path: std::path::PathBuf,
    effects: Arc<AtomicUsize>,
    destination: SemanticDestinationV1,
}

#[async_trait::async_trait]
impl SemanticTransport for CountingTransport {
    fn precondition_guarantee(&self) -> ProviderPreconditionGuaranteeV1 {
        ProviderPreconditionGuaranteeV1::AtomicIfMatch
    }
    async fn submit(
        &self,
        submission: CapturedSemanticSubmissionV1,
    ) -> Result<SemanticPayloadV1, KernelError> {
        let request = submission.into_request();
        if request.destination != self.destination
            || request.provider_version.as_str() != "\"resource-v1\""
        {
            return Err(KernelError::Internal(
                "provider precondition refused".into(),
            ));
        }
        let connection = rusqlite::Connection::open(&self.path)
            .map_err(|_| KernelError::Internal("provider unavailable".into()))?;
        connection.execute("INSERT INTO semantic_submissions(operation,attempt,payload,account,resource) VALUES (?1,?2,?3,?4,?5)", rusqlite::params![request.operation.as_str(), request.attempt.as_str(), chio_core::canonical_json_bytes(&request.payload).map_err(|_| KernelError::Internal("provider encoding refused".into()))?, request.destination.account.as_str(), request.destination.resource.as_str()]).map_err(|_| KernelError::Internal("provider unavailable".into()))?;
        self.effects.fetch_add(1, Ordering::SeqCst);
        if self
            .path
            .parent()
            .is_some_and(|parent| parent.join("provider-error").exists())
        {
            return Err(KernelError::Internal(
                "provider-private-error-canary".into(),
            ));
        }
        let mut output = request.payload;
        let mut fields = output.fields.as_slice().to_vec();
        for field in &mut fields {
            if field.field.as_str() == "body" {
                field.value = SemanticValueV1::Text {
                    value: ProtectedText::new("provider-output-canary")
                        .map_err(|_| KernelError::Internal("provider encoding refused".into()))?,
                };
            }
        }
        output.fields = NonEmptyBoundedList::new(fields)
            .map_err(|_| KernelError::Internal("provider encoding refused".into()))?;
        Ok(output)
    }
}
pub(super) fn install_connector(
    kernel: &mut ChioKernel,
    authority: &SqliteAuthorityStore,
    native: &RecoveryDeploymentV1,
    path: &std::path::Path,
    effects: Arc<AtomicUsize>,
) -> TestResult {
    let mode = std::fs::read_to_string(path.join("semantic-kind"))?;
    let (mut p, mut source) = chains::bundle(native.scope.clone(), now_ms()?, &mode)?;
    pin_deployment(&mut p, source.as_mut(), native)?;
    let store = Arc::new(authority.admission_operation_store());
    let mut installed = NativeSemanticInstallationV1 {
        deployment: p.deployment.clone(),
        packages: NonEmptyBoundedList::new(
            std::iter::once(p.package.clone())
                .chain(source.as_ref().map(|source| source.package.clone()))
                .collect(),
        )?,
        operator_root: p.operator.public_key(),
        publisher_roots: NonEmptyBoundedList::new(vec![p.publisher.public_key()])?,
        exposed: NonEmptyBoundedList::new(
            std::iter::once(p.exposed.clone())
                .chain(source.as_ref().map(|source| source.exposed.clone()))
                .collect(),
        )?,
        native_authority: native.native_authority.clone(),
        security_context: native.security_context.clone(),
    };
    if path.join("fixture.json").exists() {
        // Reopen the selected native generation rather than reinstalling the
        // fixture's initial generation. Compilation still pins all roots.
        installed = store.read_semantic_installation(
            &native.scope,
            &authority.mutation_fence(),
            now_ms()?,
        )?;
    } else {
        store.configure_semantic_deployment(&installed)?;
        store.install_semantic_audience(&p.invocation.audience)?;
        if let Some(source) = &source {
            store.install_semantic_audience(&source.invocation.audience)?;
        }
    }
    chio_semantic_contracts::compile_semantic_registry(
        &installed.deployment,
        installed.packages.as_slice(),
        &installed.operator_root,
        installed.publisher_roots.as_slice(),
        installed.exposed.as_slice(),
        &mut chio_semantic_contracts::VerificationBudget::new(4096)?,
    )?;
    let connection = rusqlite::Connection::open(path.join("semantic-effects.db"))?;
    connection.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS semantic_submissions(sequence INTEGER PRIMARY KEY,operation TEXT NOT NULL UNIQUE,attempt TEXT NOT NULL,payload BLOB NOT NULL,account TEXT NOT NULL,resource TEXT NOT NULL)")?;
    let existing: i64 =
        connection.query_row("SELECT count(*) FROM semantic_submissions", [], |row| {
            row.get(0)
        })?;
    effects.store(usize::try_from(existing)?, Ordering::SeqCst);
    for route in installed.deployment.body().routes.as_slice() {
        let package = installed
            .packages
            .as_slice()
            .iter()
            .find(|package| {
                semantic_package_digest(package.body()).is_ok_and(|digest| digest == route.package)
            })
            .ok_or("selected package absent")?;
        let contract = package
            .body()
            .operations
            .as_slice()
            .iter()
            .find(|operation| operation.operation == route.operation)
            .ok_or("selected operation absent")?;
        let transports = route
            .destinations
            .as_slice()
            .iter()
            .map(|destination| {
                (
                    destination.clone(),
                    Arc::new(CountingTransport {
                        path: path.join("semantic-effects.db"),
                        effects: effects.clone(),
                        destination: destination.clone(),
                    }) as Arc<dyn SemanticTransport>,
                )
            })
            .collect();
        let connector = PinnedSemanticConnector::new(
            route.clone(),
            contract.clone(),
            store.clone(),
            Arc::new(SemanticTransportRouter::new(transports)?),
        )?;
        if mode == "saturated-write" {
            let occupied = crate::semantic::hold_submission_capacity_for_test(&connector)?;
            kernel.register_tool_server(Box::new(SaturatedSemanticConnector {
                inner: connector,
                _occupied: occupied,
            }));
        } else if mode == "held-expired" && route.server.as_str() == "semantic-a" {
            kernel.register_tool_server(Box::new(ExpiringHeldSemanticConnector {
                inner: Arc::new(connector),
                path: path.to_path_buf(),
            }));
        } else {
            kernel.register_tool_server(Box::new(connector));
        }
    }
    Ok(())
}
fn native_profile(
    scope: RecoveryScopeV1,
    now: u64,
    kind: SemanticOperationKindV1,
) -> TestResult<SemanticFixture> {
    let mut p = semantic_fixture(scope, now, restricted_label(), kind)?;
    let mut body = p.deployment.body().clone();
    let mut route = body.routes.as_slice()[0].clone();
    route.server = ProtectedText::new("semantic-a")?;
    route.tool = ProtectedText::new("remedy")?;
    body.routes = NonEmptyBoundedList::new(vec![route])?;
    p.exposed.server = ProtectedText::new("semantic-a")?;
    p.exposed.tool = ProtectedText::new("remedy")?;
    body.exposure_binding = semantic_content_digest(&core::slice::from_ref(&p.exposed))?;
    p.deployment = SignedSemanticDeploymentV1::sign(body, &p.operator)?;
    p.exposed.server = ProtectedText::new("semantic-a")?;
    p.exposed.tool = ProtectedText::new("remedy")?;
    p.plan.registry = semantic_registry_digest(p.deployment.body())?;
    p.invocation.action.registry = p.plan.registry;
    Ok(p)
}
fn pin_deployment(
    p: &mut SemanticFixture,
    source: Option<&mut SemanticFixture>,
    native: &RecoveryDeploymentV1,
) -> TestResult {
    let mut body = p.deployment.body().clone();
    body.native_binding = semantic_content_digest(&native.native_authority)?;
    body.context_binding = semantic_content_digest(&(
        chio_kernel::recovery::recovery_flow_key(&native.security_context),
        native.security_context.as_v1().context_generation(),
    ))?;
    let exposed: Vec<_> = std::iter::once(p.exposed.clone())
        .chain(source.as_ref().map(|source| source.exposed.clone()))
        .collect();
    body.exposure_binding = semantic_content_digest(&exposed)?;
    p.deployment = SignedSemanticDeploymentV1::sign(body, &p.operator)?;
    p.plan.registry = semantic_registry_digest(p.deployment.body())?;
    p.invocation.action.registry = p.plan.registry;
    if let Some(source) = source {
        source.deployment = p.deployment.clone();
        source.plan.registry = p.plan.registry;
        source.invocation.action.registry = p.plan.registry;
    }
    Ok(())
}
fn provider_output(input: &SemanticPayloadV1) -> TestResult<SemanticPayloadV1> {
    let mut fields = input.fields.as_slice().to_vec();
    for field in &mut fields {
        if field.field.as_str() == "body" {
            field.value = SemanticValueV1::Text {
                value: ProtectedText::new("provider-output-canary")?,
            };
        }
    }
    Ok(SemanticPayloadV1 {
        fields: NonEmptyBoundedList::new(fields)?,
    })
}
pub(super) fn native_fixture(kind: &str) -> TestResult<RecoveryFixture> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("semantic-kind"), kind)?;
    if matches!(
        kind,
        "read-weak-manifest" | "read-missing-status" | "annotated-read-weak-manifest"
    ) {
        // Both native manifest and operator input floors must be public, so
        // only the independently signed semantic origin can add restrictions.
        std::fs::write(directory.path().join("public-original-profile"), "selected")?;
    }
    RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)
}
pub(super) fn prepare(
    f: &RecoveryFixture,
    key: &str,
    output: SemanticOutputDispositionV1,
) -> TestResult<(NativeSemanticRuntime, ToolCallRequest, SemanticFixture)> {
    let scope = f.runtime.scope.clone();
    let mode = std::fs::read_to_string(f.path.join("semantic-kind"))?;
    let (mut p, _) = chains::bundle(scope.clone(), now_ms()?, &mode)?;
    pin_deployment(&mut p, None, &f.kernel.recovery_deployment(&scope)?)?;
    let installed = f
        .authority
        .admission_operation_store()
        .read_semantic_installation(&scope, &f.authority.mutation_fence(), now_ms()?)?;
    p.deployment = installed.deployment;
    p.plan.registry = semantic_registry_digest(p.deployment.body())?;
    p.invocation.action.registry = p.plan.registry;
    p.invocation.action.generation = p.deployment.body().generation;
    let runtime = NativeSemanticRuntime::new(
        f.kernel.clone(),
        Arc::new(f.authority.admission_operation_store()),
        scope,
        f.authority.mutation_fence(),
    );
    let mut step = p.plan.steps.as_slice()[0].clone();
    step.step = StepId::new(key)?;
    step.output = output;
    if mode == "alternate" {
        let destination = &p.deployment.body().routes.as_slice()[0]
            .destinations
            .as_slice()[1];
        step.destination = destination.destination.clone();
        p.invocation.action.destination = destination.destination.clone();
        let mut acl = p.invocation.audience.body().clone();
        acl.account = destination.account.clone();
        acl.resource = destination.resource.clone();
        p.invocation.audience = SignedSemanticAudienceV1::sign(acl, &p.resolver)?;
    }
    p.plan.steps = NonEmptyBoundedList::new(vec![step])?;
    let plan = runtime.accept_plan(&f.control, &p.plan)?;
    let request =
        f.process
            .tool_request("root", key, "semantic-a", "remedy", serde_json::json!({}))?;
    p.invocation.action.plan = plan;
    p.invocation.action.step = StepId::new(key)?;
    p.invocation.action.output = output;
    p.invocation.action = runtime.frame_action(&request, p.invocation.action, &p.payload)?;
    if !p.invocation.endorsements.as_slice().is_empty() {
        let mut body = p.invocation.endorsements.as_slice()[0].body().clone();
        body.evidence = EvidenceRef::new(&format!("endorsement-{key}"))?;
        body.target = SemanticEndorsementTargetV1::ExactAction {
            action: semantic_action_digest(&p.invocation.action)?,
        };
        body.destination = p.invocation.action.destination.clone();
        p.invocation.endorsements =
            BoundedList::new(vec![SignedScopedEndorsementV1::sign(body, &p.endorser)?])?;
    }
    f.authority
        .admission_operation_store()
        .install_semantic_audience(&p.invocation.audience)?;
    let mut request = request;
    request.arguments = serde_json::to_value(&p.invocation)?;
    Ok((runtime, request, p))
}
/// Build a fresh accepted exact-input plan for a synthetic read title boundary.
pub(super) fn prepare_title(
    f: &RecoveryFixture,
    key: &str,
    title: &str,
) -> TestResult<(NativeSemanticRuntime, ToolCallRequest, SemanticFixture)> {
    let (runtime, mut request, mut p) = prepare(f, key, SemanticOutputDispositionV1::ReturnValue)?;
    if p.package.body().operations.as_slice()[0].kind != SemanticOperationKindV1::SupportRead {
        return Err("title fixture requires a read contract".into());
    }
    let mut fields = p.payload.fields.as_slice().to_vec();
    fields[0].value = SemanticValueV1::Text {
        value: ProtectedText::new(title)?,
    };
    p.payload.fields = NonEmptyBoundedList::new(fields)?;
    let content = semantic_content_digest(&p.payload)?;
    let input = SemanticInputVersionV1 {
        resource: ProviderResourceId::new("ticket")?,
        version: ArtifactVersionId::from_bytes(*content.as_bytes()),
        content,
    };
    let mut step = p.plan.steps.as_slice()[0].clone();
    step.inputs = NonEmptyBoundedList::new(vec![SemanticPlanInputV1::Exact {
        resource: input.resource.clone(),
        version: input.version,
        material: input.content,
    }])?;
    p.plan.steps = NonEmptyBoundedList::new(vec![step])?;
    p.invocation.action.plan = runtime.accept_plan(&f.control, &p.plan)?;
    p.invocation.action.inputs = NonEmptyBoundedList::new(vec![input])?;
    p.invocation.action.influence = semantic_content_digest(&(
        &p.invocation.action.inputs,
        p.package.body().operations.as_slice()[0].external_influence,
    ))?;
    p.invocation.action = runtime.frame_action(&request, p.invocation.action, &p.payload)?;
    p.invocation.payload = p.payload.clone();
    request.arguments = serde_json::to_value(&p.invocation)?;
    Ok((runtime, request, p))
}

#[tokio::test]
async fn native_integrity_only_endorsement_captures_and_returns_without_disclosure_grant(
) -> TestResult {
    let f = native_fixture("write")?;
    let (runtime, request, p) = prepare(&f, "write-a", SemanticOutputDispositionV1::ReturnValue)?;
    assert!(request.declassification_grant.is_none());
    let response = runtime
        .execute_step(&f.process, "root", "write-a", &request)
        .await?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        response.output,
        Some(chio_kernel::ToolCallOutput::Value(serde_json::to_value(
            provider_output(&p.payload)?
        )?))
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let replay = runtime
        .execute_step(&f.process, "root", "write-a", &request)
        .await?;
    assert_eq!(replay.request_id, response.request_id);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn native_withhold_preserves_completed_effect_and_replay_never_returns_raw() -> TestResult {
    let f = native_fixture("write")?;
    let (runtime, request, _) = prepare(&f, "withhold-a", SemanticOutputDispositionV1::Withhold)?;
    let response = runtime
        .execute_step(&f.process, "root", "withhold-a", &request)
        .await?;
    assert_eq!(
        response.output,
        Some(chio_kernel::ToolCallOutput::Value(
            serde_json::json!({"status":"withheld"})
        ))
    );
    assert!(!format!(
        "{:?} {}",
        response.output,
        chio_core::canonical_json_string(&response.receipt)?
    )
    .contains("provider-output-canary"));
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    let replay = runtime
        .execute_step(&f.process, "root", "withhold-a", &request)
        .await?;
    assert_eq!(replay.output, response.output);
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
#[tokio::test]
async fn native_support_read_and_separate_projection_have_native_capture() -> TestResult {
    for kind in ["read", "project"] {
        let f = native_fixture(kind)?;
        let (runtime, request, _) =
            prepare(&f, "read-a", SemanticOutputDispositionV1::ReturnValue)?;
        let response = runtime
            .execute_step(&f.process, "root", "read-a", &request)
            .await?;
        assert!(response.output.is_some());
        if kind == "project" {
            assert!(!format!("{:?}", response.output).contains("private-canary"));
            assert_eq!(f.effects.load(Ordering::SeqCst), 0);
        } else {
            assert_eq!(f.effects.load(Ordering::SeqCst), 1);
        }
    }
    Ok(())
}
#[tokio::test]
async fn native_refuses_stale_acl_endorsement_absence_and_emergency_stop() -> TestResult {
    for case in ["acl", "endorsement", "stop"] {
        let f = native_fixture("write")?;
        let (runtime, mut request, mut p) =
            prepare(&f, "stale-a", SemanticOutputDispositionV1::ReturnValue)?;
        match case {
            "acl" => {
                let mut acl = p.invocation.audience.body().clone();
                acl.completeness = SemanticAudienceCompletenessV1::Partial;
                acl.observed_at_unix_ms = SafeInteger::new(now_ms()?)?;
                f.authority
                    .admission_operation_store()
                    .install_semantic_audience(&SignedSemanticAudienceV1::sign(
                        acl,
                        &p.resolver,
                    )?)?;
            }
            "endorsement" => {
                p.invocation.endorsements = BoundedList::new(vec![])?;
                request.arguments = serde_json::to_value(&p.invocation)?;
            }
            _ => f
                .authority
                .admission_operation_store()
                .set_semantic_emergency_stop(&p.plan.scope, true)?,
        }
        let response = runtime
            .execute_step(&f.process, "root", "stale-a", &request)
            .await;
        assert!(
            response.is_err()
                || response
                    .as_ref()
                    .is_ok_and(|response| response.verdict == Verdict::Deny)
        );
        assert_eq!(f.effects.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[path = "semantic/chains.rs"]
mod chains;

#[path = "semantic/authority.rs"]
mod authority;
