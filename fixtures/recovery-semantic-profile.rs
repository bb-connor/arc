//! Deterministic test fixture shared by pure and native semantic acceptance.
use chio_core_types::{recovery::*, Keypair};
use chio_security_types::{flow::InformationLabel, recovery::*, semantic::*};
use chio_semantic_contracts::ExposedSemanticToolV1;
type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

pub struct SemanticFixture {
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
pub fn semantic_fixture(
    scope: RecoveryScopeV1,
    now: u64,
    label: InformationLabel,
    kind: SemanticOperationKindV1,
) -> FixtureResult<SemanticFixture> {
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
    let channels = [
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
    .collect();
    let contract = SemanticOperationContractV1 {
        operation: SemanticOperationId::new("support-remedy")?,
        kind,
        input_schema: CanonicalPayloadDigest::from_bytes([1; 32]),
        output_schema: CanonicalPayloadDigest::from_bytes([2; 32]),
        implementation: CanonicalPayloadDigest::from_bytes([3; 32]),
        channels: NonEmptyBoundedList::new(channels)?,
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
                value: SemanticValueV1::Text {
                    value: ProtectedText::new("support ticket")?,
                },
            },
            SemanticFieldV1 {
                field: SemanticFieldId::new("body")?,
                value: SemanticValueV1::Text {
                    value: ProtectedText::new("private-canary")?,
                },
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
        issued_at_unix_ms: SafeInteger::new(now)?,
        valid_until_unix_ms: SafeInteger::new(now + 50_000)?,
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
            observed_at_unix_ms: SafeInteger::new(now)?,
            valid_until_unix_ms: SafeInteger::new(now + 50_000)?,
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
                scope,
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
