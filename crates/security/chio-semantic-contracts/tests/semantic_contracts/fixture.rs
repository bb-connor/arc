//! A signed support deployment with one package, one route and one
//! invocation.
use chio_core_types::recovery::{
    semantic_action_digest, semantic_content_digest, semantic_key_digest, semantic_package_digest,
    semantic_plan_digest, semantic_registry_digest, SemanticInvocationV1,
    SignedScopedEndorsementV1, SignedSemanticAudienceV1, SignedSemanticDeploymentV1,
    SignedSemanticPackageV1,
};
use chio_core_types::Keypair;
use chio_security_types::flow::InformationLabel;
use chio_security_types::recovery::{
    ArtifactVersionId, AuthorityDomainId, BoundedList, CanonicalPayloadDigest,
    CapabilityBodyDigest, ContractError, EvidenceRef, NonEmptyBoundedList, ProcessId,
    ProtectedText, ProviderAccountId, ProviderId, ProviderResourceId, RecoveryScopeV1,
    RecoveryTenantId, RequestId, RequestNamespaceDigest, SafeInteger, SemanticDestinationId,
    SemanticFactId, SemanticFieldId, SemanticOperationId, SemanticPackageId, StepId, VersionV1,
    MAX_RECOVERY_VERIFICATION_WORK,
};
use chio_security_types::semantic::{
    ScopedEndorsementV1, SemanticAclCursorV1, SemanticAclPaginationV1, SemanticActionV1,
    SemanticAudienceCompletenessV1, SemanticAudienceObservationV1, SemanticChannelRuleV1,
    SemanticChannelV1, SemanticDeploymentV1, SemanticDestinationV1, SemanticEndorsementTargetV1,
    SemanticFieldV1, SemanticInputVersionV1, SemanticInvocationSchemaV1,
    SemanticNativeSourceBasisV1, SemanticOperationContractV1, SemanticOperationKindV1,
    SemanticOutputDispositionV1, SemanticPackageV1, SemanticPayloadV1, SemanticPlanInputV1,
    SemanticPlanStepV1, SemanticPlanV1, SemanticRouteV1, SemanticSelectorV1, SemanticValueV1,
    SemanticWithheldStatusV1,
};
use chio_security_types::work::VerificationBudget;
use chio_semantic_contracts::{
    compile_semantic_registry, verify_semantic_invocation, CompiledSemanticRegistryV1,
    ExposedSemanticToolV1, SemanticInvocationExpectationV1, VerifiedSemanticInvocationV1,
};

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The action is issued at this instant and stays valid for 50 seconds.
pub const NOW: u64 = 1000;
pub const VERIFY_AT: u64 = NOW + 1;
pub const VALID_UNTIL: u64 = NOW + 50_000;

pub struct SemanticFixture {
    pub scope: RecoveryScopeV1,
    pub publisher: Keypair,
    pub operator: Keypair,
    pub resolver: Keypair,
    pub endorser: Keypair,
    pub annotator: Keypair,
    pub transformer: Keypair,
    pub prerequisite: Keypair,
    pub package: SignedSemanticPackageV1,
    pub deployment: SignedSemanticDeploymentV1,
    pub exposed: ExposedSemanticToolV1,
    pub payload: SemanticPayloadV1,
    pub plan: SemanticPlanV1,
    pub invocation: SemanticInvocationV1,
}

pub fn scope() -> Result<RecoveryScopeV1, ContractError> {
    Ok(RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new("authority")?,
        tenant_id: RecoveryTenantId::new("tenant")?,
        process_id: ProcessId::new("root")?,
    })
}

pub fn channels() -> Vec<SemanticChannelRuleV1> {
    [
        SemanticChannelV1::Input,
        SemanticChannelV1::Success,
        SemanticChannelV1::Error,
        SemanticChannelV1::NoValue,
        SemanticChannelV1::Nested,
        SemanticChannelV1::Batch,
        SemanticChannelV1::Pagination,
        SemanticChannelV1::Redirect,
        SemanticChannelV1::Stream,
        SemanticChannelV1::File,
        SemanticChannelV1::Log,
        SemanticChannelV1::Shell,
        SemanticChannelV1::Model,
    ]
    .into_iter()
    .enumerate()
    .map(|(index, channel)| SemanticChannelRuleV1 {
        channel,
        enabled: index < 4,
    })
    .collect()
}

pub fn text(value: &str) -> Result<SemanticValueV1, ContractError> {
    Ok(SemanticValueV1::Text {
        value: ProtectedText::new(value)?,
    })
}

pub fn semantic_fixture(
    label: InformationLabel,
    kind: SemanticOperationKindV1,
) -> TestResult<SemanticFixture> {
    let scope = scope()?;
    let publisher = Keypair::from_seed(&[210; 32]);
    let operator = Keypair::from_seed(&[211; 32]);
    let resolver = Keypair::from_seed(&[212; 32]);
    let endorser = Keypair::from_seed(&[213; 32]);
    let annotator = Keypair::from_seed(&[214; 32]);
    let transformer = Keypair::from_seed(&[215; 32]);
    let prerequisite = Keypair::from_seed(&[216; 32]);
    let required = if kind == SemanticOperationKindV1::IssueWrite {
        vec![SemanticFactId::new("customer-instructions-reviewed")?]
    } else {
        vec![]
    };
    let contract = SemanticOperationContractV1 {
        operation: SemanticOperationId::new("support-remedy")?,
        kind,
        input_schema: CanonicalPayloadDigest::from_bytes([1; 32]),
        output_schema: CanonicalPayloadDigest::from_bytes([2; 32]),
        implementation: CanonicalPayloadDigest::from_bytes([3; 32]),
        channels: NonEmptyBoundedList::new(channels())?,
        input_fields: BoundedList::new(vec![
            SemanticFieldId::new("title")?,
            SemanticFieldId::new("body")?,
        ])?,
        selectors: BoundedList::new(vec![SemanticSelectorV1::TextBytesAtMost {
            field: SemanticFieldId::new("title")?,
            bytes: SafeInteger::new(512)?,
        }])?,
        required_assertions: BoundedList::new(required.clone())?,
        prerequisites: BoundedList::new(vec![])?,
        projection_fields: BoundedList::new(if kind == SemanticOperationKindV1::FieldProjection {
            vec![SemanticFieldId::new("title")?]
        } else {
            vec![]
        })?,
        source_label: label.clone(),
        external_influence: true,
        withheld_status: Some(SemanticWithheldStatusV1 {
            audience: label.clone(),
        }),
    };
    let package = SignedSemanticPackageV1::sign(
        SemanticPackageV1 {
            domain_version: VersionV1,
            package: SemanticPackageId::new("support-issue")?,
            dependencies: BoundedList::new(vec![])?,
            operations: NonEmptyBoundedList::new(vec![contract.clone()])?,
        },
        &publisher,
    )?;
    let destination = SemanticDestinationV1 {
        destination: SemanticDestinationId::new("tenant-issue-queue")?,
        provider: ProviderId::new("support-provider")?,
        account: ProviderAccountId::new("tenant-account")?,
        resource: ProviderResourceId::new("issue-queue")?,
        endpoint: ProtectedText::new("https://fixture.invalid/issues")?,
        audience: label.clone(),
        purpose: ProtectedText::new("customer-support")?,
        subject_mapping: CanonicalPayloadDigest::from_bytes([4; 32]),
        acl_query: CanonicalPayloadDigest::from_bytes([5; 32]),
        require_provider_precondition: true,
    };
    let route = SemanticRouteV1 {
        server: ProtectedText::new("server-a")?,
        tool: ProtectedText::new("send")?,
        package: semantic_package_digest(package.body())?,
        operation: contract.operation.clone(),
        implementation: contract.implementation,
        input_schema: contract.input_schema,
        output_schema: contract.output_schema,
        destinations: NonEmptyBoundedList::new(vec![destination.clone()])?,
        operator_selectors: BoundedList::new(vec![])?,
        reviewed_overrides: BoundedList::new(vec![])?,
        resolver_key: semantic_key_digest(&resolver.public_key())?,
        endorsement_key: semantic_key_digest(&endorser.public_key())?,
        prerequisite_key: semantic_key_digest(&prerequisite.public_key())?,
        transformation_key: semantic_key_digest(&transformer.public_key())?,
        annotators: BoundedList::new(vec![])?,
    };
    let exposed = ExposedSemanticToolV1 {
        server: route.server.clone(),
        tool: route.tool.clone(),
        implementation: contract.implementation,
        input_schema: contract.input_schema,
        output_schema: contract.output_schema,
        channels: contract.channels.clone(),
    };
    let deployment = SignedSemanticDeploymentV1::sign(
        SemanticDeploymentV1 {
            domain_version: VersionV1,
            scope: scope.clone(),
            generation: SafeInteger::new(1)?,
            native_binding: CanonicalPayloadDigest::from_bytes([18; 32]),
            context_binding: CanonicalPayloadDigest::from_bytes([19; 32]),
            exposure_binding: semantic_content_digest(&core::slice::from_ref(&exposed))?,
            packages: NonEmptyBoundedList::new(vec![route.package])?,
            routes: NonEmptyBoundedList::new(vec![route.clone()])?,
        },
        &operator,
    )?;
    let payload = SemanticPayloadV1 {
        fields: NonEmptyBoundedList::new(vec![
            SemanticFieldV1 {
                field: SemanticFieldId::new("title")?,
                value: text("support ticket")?,
            },
            SemanticFieldV1 {
                field: SemanticFieldId::new("body")?,
                value: text("private-canary")?,
            },
        ])?,
    };
    let content = semantic_content_digest(&payload)?;
    let input = SemanticInputVersionV1 {
        resource: ProviderResourceId::new("ticket")?,
        version: ArtifactVersionId::from_bytes(*content.as_bytes()),
        content,
    };
    let registry = semantic_registry_digest(deployment.body())?;
    let step = StepId::new("remedy")?;
    let plan = SemanticPlanV1 {
        domain_version: VersionV1,
        scope: scope.clone(),
        registry,
        steps: NonEmptyBoundedList::new(vec![SemanticPlanStepV1 {
            step: step.clone(),
            operation: contract.operation.clone(),
            destination: destination.destination.clone(),
            dependencies: BoundedList::new(vec![])?,
            inputs: NonEmptyBoundedList::new(vec![SemanticPlanInputV1::Exact {
                resource: input.resource.clone(),
                version: input.version,
                material: content,
            }])?,
            output: SemanticOutputDispositionV1::ReturnValue,
        }])?,
    };
    let inputs = NonEmptyBoundedList::new(vec![input])?;
    let action = SemanticActionV1 {
        domain_version: VersionV1,
        scope: scope.clone(),
        registry,
        generation: SafeInteger::new(1)?,
        operation: contract.operation.clone(),
        destination: destination.destination.clone(),
        request_id: RequestId::new("request-a")?,
        request_namespace: RequestNamespaceDigest::from_bytes([6; 32]),
        capability: CapabilityBodyDigest::from_bytes([7; 32]),
        payload: content,
        request_semantics: CanonicalPayloadDigest::from_bytes([20; 32]),
        inputs: inputs.clone(),
        source_label: label.clone(),
        native_source: SemanticNativeSourceBasisV1 {
            key: CanonicalPayloadDigest::from_bytes([21; 32]),
            generation: SafeInteger::new(0)?,
            principal_label: InformationLabel::bottom(),
            lineage_label: InformationLabel::bottom(),
            session_label: InformationLabel::bottom(),
        },
        influence: semantic_content_digest(&(&inputs, contract.external_influence))?,
        externally_influenced: true,
        plan: semantic_plan_digest(&plan)?,
        step,
        output: SemanticOutputDispositionV1::ReturnValue,
        issued_at_unix_ms: SafeInteger::new(NOW)?,
        valid_until_unix_ms: SafeInteger::new(VALID_UNTIL)?,
    };
    let audience = SignedSemanticAudienceV1::sign(
        SemanticAudienceObservationV1 {
            domain_version: VersionV1,
            scope: scope.clone(),
            provider: destination.provider,
            account: destination.account,
            resource: destination.resource,
            audience: label,
            subject_mapping: destination.subject_mapping,
            query: destination.acl_query,
            provider_version: ProtectedText::new("\"resource-v1\"")?,
            completeness: SemanticAudienceCompletenessV1::Complete,
            pagination: SemanticAclPaginationV1 {
                pages_observed: SafeInteger::new(1)?,
                pages_expected: SafeInteger::new(1)?,
                cursor: SemanticAclCursorV1::Complete,
            },
            observed_at_unix_ms: SafeInteger::new(NOW)?,
            valid_until_unix_ms: SafeInteger::new(VALID_UNTIL)?,
        },
        &resolver,
    )?;
    let endorsements = if required.is_empty() {
        vec![]
    } else {
        vec![SignedScopedEndorsementV1::sign(
            ScopedEndorsementV1 {
                domain_version: VersionV1,
                evidence: EvidenceRef::new("endorsement-a")?,
                scope: scope.clone(),
                target: SemanticEndorsementTargetV1::ExactAction {
                    action: semantic_action_digest(&action)?,
                },
                influence: action.influence,
                assertions: NonEmptyBoundedList::new(required)?,
                destination: action.destination.clone(),
                purpose: destination.purpose,
                issued_at_unix_ms: action.issued_at_unix_ms,
                valid_until_unix_ms: action.valid_until_unix_ms,
            },
            &endorser,
        )?]
    };
    let invocation = SemanticInvocationV1 {
        schema: SemanticInvocationSchemaV1::V1,
        action,
        payload: payload.clone(),
        audience,
        endorsements: BoundedList::new(endorsements)?,
        annotations: BoundedList::new(vec![])?,
        transformation: None,
        prerequisites: BoundedList::new(vec![])?,
    };
    Ok(SemanticFixture {
        scope,
        publisher,
        operator,
        resolver,
        endorser,
        annotator,
        transformer,
        prerequisite,
        package,
        deployment,
        exposed,
        payload,
        plan,
        invocation,
    })
}

impl SemanticFixture {
    pub fn compile_with(
        &self,
        expected_scope: &RecoveryScopeV1,
        exposed: &[ExposedSemanticToolV1],
    ) -> Result<CompiledSemanticRegistryV1, ContractError> {
        compile_semantic_registry(
            &self.deployment,
            expected_scope,
            core::slice::from_ref(&self.package),
            &self.operator.public_key(),
            &[self.publisher.public_key()],
            exposed,
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?,
        )
    }

    pub fn compiled(&self) -> Result<CompiledSemanticRegistryV1, ContractError> {
        self.compile_with(&self.scope, core::slice::from_ref(&self.exposed))
    }

    pub fn expectation(&self, now: u64) -> SemanticInvocationExpectationV1<'static> {
        SemanticInvocationExpectationV1 {
            server: "server-a",
            tool: "send",
            request_id: "request-a",
            request_namespace: self.invocation.action.request_namespace,
            capability: self.invocation.action.capability,
            request_semantics: self.invocation.action.request_semantics,
            source_label: bottom(),
            externally_influenced: false,
            influence: self.invocation.action.influence,
            native_disclosure_target: None,
            now_unix_ms: now,
        }
    }

    pub fn verify_with(
        &self,
        invocation: &SemanticInvocationV1,
        expected: &SemanticInvocationExpectationV1<'_>,
    ) -> Result<VerifiedSemanticInvocationV1, ContractError> {
        verify_semantic_invocation(
            &self.compiled()?,
            invocation,
            expected,
            &mut VerificationBudget::new(4096, MAX_RECOVERY_VERIFICATION_WORK)?,
        )
    }

    pub fn verify(
        &self,
        invocation: &SemanticInvocationV1,
        now: u64,
    ) -> Result<VerifiedSemanticInvocationV1, ContractError> {
        self.verify_with(invocation, &self.expectation(now))
    }

    /// Re-sign the deployment after `edit` changes its only route, and bind
    /// the fixture action and endorsement to the new registry.
    pub fn rebind_route(&mut self, edit: impl FnOnce(&mut SemanticRouteV1)) -> TestResult {
        let mut deployment = self.deployment.body().clone();
        let mut route = only(deployment.routes.as_slice())?.clone();
        edit(&mut route);
        deployment.routes = NonEmptyBoundedList::new(vec![route])?;
        self.deployment = SignedSemanticDeploymentV1::sign(deployment, &self.operator)?;
        self.refresh_action()
    }

    /// Re-sign the package after `edit` changes its only operation, then route
    /// the deployment to the new package digest.
    pub fn rebind_operation(
        &mut self,
        edit: impl FnOnce(&mut SemanticOperationContractV1),
    ) -> TestResult {
        let mut package = self.package.body().clone();
        let mut operation = only(package.operations.as_slice())?.clone();
        edit(&mut operation);
        package.operations = NonEmptyBoundedList::new(vec![operation])?;
        self.package = SignedSemanticPackageV1::sign(package, &self.publisher)?;
        let digest = semantic_package_digest(self.package.body())?;
        let mut deployment = self.deployment.body().clone();
        deployment.packages = NonEmptyBoundedList::new(vec![digest])?;
        self.deployment = SignedSemanticDeploymentV1::sign(deployment, &self.operator)?;
        self.rebind_route(|route| route.package = digest)
    }

    /// Re-sign the audience observation after `edit`.
    pub fn rebind_audience(
        &mut self,
        edit: impl FnOnce(&mut SemanticAudienceObservationV1),
    ) -> TestResult {
        let mut audience = self.invocation.audience.body().clone();
        edit(&mut audience);
        self.invocation.audience = SignedSemanticAudienceV1::sign(audience, &self.resolver)?;
        Ok(())
    }

    /// Point the action at the current registry and re-endorse it.
    pub fn refresh_action(&mut self) -> TestResult {
        self.invocation.action.registry = semantic_registry_digest(self.deployment.body())?;
        let mut invocation = self.invocation.clone();
        self.endorse(&mut invocation)?;
        self.invocation = invocation;
        Ok(())
    }

    /// Re-sign every endorsement of `invocation` for its current action.
    pub fn endorse(&self, invocation: &mut SemanticInvocationV1) -> TestResult {
        let mut endorsements = Vec::new();
        for endorsement in invocation.endorsements.as_slice() {
            let mut body = endorsement.body().clone();
            body.target = SemanticEndorsementTargetV1::ExactAction {
                action: semantic_action_digest(&invocation.action)?,
            };
            body.influence = invocation.action.influence;
            endorsements.push(SignedScopedEndorsementV1::sign(body, &self.endorser)?);
        }
        invocation.endorsements = BoundedList::new(endorsements)?;
        Ok(())
    }
}

pub fn only<T>(items: &[T]) -> TestResult<&T> {
    match items {
        [item] => Ok(item),
        _ => Err("expected exactly one fixture item".into()),
    }
}

fn bottom() -> &'static InformationLabel {
    static BOTTOM: std::sync::OnceLock<InformationLabel> = std::sync::OnceLock::new();
    BOTTOM.get_or_init(InformationLabel::bottom)
}
