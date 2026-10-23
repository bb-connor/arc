//! Finite local schema and native typed/cryptographic semantic wire conformance.
use chio_core_types::recovery::*;
use chio_security_types::{flow::InformationLabel, recovery::*, semantic::*};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[allow(dead_code)]
mod fixture {
    use chio_core_types::recovery::{
        semantic_action_digest, semantic_content_digest, semantic_key_digest,
        semantic_package_digest, semantic_plan_digest, semantic_registry_digest,
        SemanticInvocationV1, SignedScopedEndorsementV1, SignedSemanticAudienceV1,
        SignedSemanticDeploymentV1, SignedSemanticPackageV1,
    };
    use chio_core_types::Keypair;
    use chio_security_types::flow::InformationLabel;
    use chio_security_types::recovery::{
        ArtifactVersionId, AuthorityDomainId, BoundedList, CanonicalPayloadDigest,
        CapabilityBodyDigest, ContractError, EvidenceRef, NonEmptyBoundedList, ProcessId,
        ProtectedText, ProviderAccountId, ProviderId, ProviderResourceId, RecoveryScopeV1,
        RecoveryTenantId, RequestId, RequestNamespaceDigest, SafeInteger, SemanticDestinationId,
        SemanticFactId, SemanticFieldId, SemanticOperationId, SemanticPackageId, StepId, VersionV1,
    };
    use chio_security_types::semantic::{
        ScopedEndorsementV1, SemanticAclCursorV1, SemanticAclPaginationV1, SemanticActionV1,
        SemanticAnnotatorBindingV1, SemanticAudienceCompletenessV1, SemanticAudienceObservationV1,
        SemanticChannelRuleV1, SemanticChannelV1, SemanticDeploymentV1, SemanticDestinationV1,
        SemanticEndorsementTargetV1, SemanticFieldV1, SemanticInputVersionV1,
        SemanticInvocationSchemaV1, SemanticNativeSourceBasisV1, SemanticOperationContractV1,
        SemanticOperationKindV1, SemanticOutputDispositionV1, SemanticPackageV1, SemanticPayloadV1,
        SemanticPlanInputV1, SemanticPlanStepV1, SemanticPlanV1, SemanticRouteV1,
        SemanticSelectorV1, SemanticValueV1,
    };
    use chio_semantic_contracts::ExposedSemanticToolV1;

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
            projection_fields: BoundedList::new(
                if kind == SemanticOperationKindV1::FieldProjection {
                    vec![SemanticFieldId::new("title")?]
                } else {
                    vec![]
                },
            )?,
            source_label: label.clone(),
            external_influence: true,
            withheld_status: None,
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
            annotators: BoundedList::new(vec![SemanticAnnotatorBindingV1 {
                key: semantic_key_digest(&annotator.public_key())?,
                facts: BoundedList::new(vec![])?,
                may_attest_facts: false,
            }])?,
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
}
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize)]
struct Corpus {
    format_version: u8,
    vectors: Vec<Vector>,
}
#[derive(Deserialize)]
struct Vector {
    name: String,
    schema: String,
    wire: String,
    valid: bool,
    schema_valid: bool,
}
fn typed<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> bool {
    decode_contract::<T>(bytes).is_ok()
}
fn accepts(schema: &str, bytes: &[u8]) -> bool {
    match schema {
        "semantic-package.schema.json" => typed::<SemanticPackageV1>(bytes),
        "semantic-deployment.schema.json" => typed::<SemanticDeploymentV1>(bytes),
        "semantic-action.schema.json" => typed::<SemanticActionV1>(bytes),
        "semantic-payload.schema.json" => typed::<SemanticPayloadV1>(bytes),
        "semantic-plan.schema.json" => typed::<SemanticPlanV1>(bytes),
        "semantic-audience.schema.json" => typed::<SemanticAudienceObservationV1>(bytes),
        "scoped-endorsement.schema.json" => typed::<ScopedEndorsementV1>(bytes),
        "semantic-annotation.schema.json" => typed::<SemanticAnnotationV1>(bytes),
        "semantic-transformation.schema.json" => typed::<SemanticTransformationV1>(bytes),
        "semantic-prerequisite.schema.json" => typed::<SemanticPrerequisiteV1>(bytes),
        "semantic-invocation.schema.json" => typed::<SemanticInvocationV1>(bytes),
        "semantic-provider-request.schema.json" => typed::<SemanticProviderRequestV1>(bytes),
        "semantic-provider-response.schema.json" => typed::<SemanticProviderResponseV1>(bytes),
        "signed-semantic-package.schema.json" => decode_contract::<SignedSemanticPackageV1>(bytes)
            .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|v| v)),
        "signed-semantic-deployment.schema.json" => {
            decode_contract::<SignedSemanticDeploymentV1>(bytes)
                .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|v| v))
        }
        "signed-semantic-audience.schema.json" => {
            decode_contract::<SignedSemanticAudienceV1>(bytes)
                .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|v| v))
        }
        "signed-scoped-endorsement.schema.json" => {
            decode_contract::<SignedScopedEndorsementV1>(bytes)
                .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|v| v))
        }
        "signed-semantic-annotation.schema.json" => {
            decode_contract::<SignedSemanticAnnotationV1>(bytes)
                .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|v| v))
        }
        "signed-semantic-transformation.schema.json" => {
            decode_contract::<SignedSemanticTransformationV1>(bytes)
                .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|v| v))
        }
        "signed-semantic-prerequisite.schema.json" => {
            decode_contract::<SignedSemanticPrerequisiteV1>(bytes)
                .is_ok_and(|p| p.verify_integrity_embedded_key().is_ok_and(|v| v))
        }
        _ => false,
    }
}
#[test]
fn shared_closed_wire_and_role_signature_corpus() -> Result {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-wire/v1");
    let mut registry = jsonschema::Registry::new();
    let mut schemas = std::collections::BTreeMap::new();
    for group in std::fs::read_dir(&root)? {
        let group = group?;
        if !group.file_type()?.is_dir() {
            continue;
        }
        for path in std::fs::read_dir(group.path())? {
            let path = path?.path();
            if !path.to_string_lossy().ends_with(".schema.json") {
                continue;
            }
            let value: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            let Some(id) = value["$id"].as_str().map(str::to_owned) else {
                continue;
            };
            registry = registry.add(&id, value.clone())?;
            for domain in ["chio.world", "chio-protocol.dev"] {
                let file_id = format!(
                    "https://{domain}/schemas/chio-wire/v1/{}",
                    path.strip_prefix(&root)?.to_string_lossy()
                );
                if id != file_id {
                    registry = registry.add(&file_id, value.clone())?;
                }
            }
            schemas.insert(
                path.file_name()
                    .ok_or("filename")?
                    .to_string_lossy()
                    .into_owned(),
                value,
            );
        }
    }
    let registry = registry.prepare()?;
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/semantic-contracts.json"
    ))?;
    assert_eq!(corpus.format_version, 1);
    for vector in corpus.vectors {
        let validator = jsonschema::options()
            .with_registry(&registry)
            .build(&schemas[&vector.schema])?;
        assert_eq!(
            validator.is_valid(&serde_json::from_str::<Value>(&vector.wire)?),
            vector.schema_valid,
            "schema: {}",
            vector.name
        );
        assert_eq!(
            accepts(&vector.schema, vector.wire.as_bytes()),
            vector.valid,
            "typed/crypto: {}",
            vector.name
        );
    }
    Ok(())
}
#[test]
fn ingress_bounds_and_private_diagnostics() -> Result {
    let oversized = vec![b' '; MAX_RECOVERY_WIRE_BYTES + 1];
    assert!(decode_contract::<SemanticInvocationV1>(&oversized).is_err());
    let depth = format!("{}0{}", "[".repeat(80), "]".repeat(80));
    assert!(decode_contract::<SemanticInvocationV1>(depth.as_bytes()).is_err());
    let payload = SemanticPayloadV1 {
        fields: NonEmptyBoundedList::new(vec![SemanticFieldV1 {
            field: SemanticFieldId::new("body")?,
            value: SemanticValueV1::Text {
                value: ProtectedText::new("private-debug-canary")?,
            },
        }])?,
    };
    assert!(!format!("{payload:?}").contains("private-debug-canary"));
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/semantic-contracts.json"
    ))?;
    let value = corpus["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .find(|case| case["schema"] == "signed-scoped-endorsement.schema.json")
        .ok_or("endorsement")?;
    let signed: SignedScopedEndorsementV1 = serde_json::from_value(value["value"].clone())?;
    assert!(signed.verify_integrity_embedded_key()?);
    assert!(matches!(
        chio_core_types::crypto::verify_wrapped(
            signed.authority_key(),
            chio_core_types::recovery::CHIO_RECOVERY_GRANT_SCHEMA,
            signed.body(),
            signed.signature(),
        ),
        Err(chio_core_types::Error::SignatureRejected)
    ));
    Ok(())
}

fn built_corpus() -> Result<String> {
    let f = fixture::semantic_fixture(
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    let scope = f.scope.clone();
    let annotation = SignedSemanticAnnotationV1::sign(
        SemanticAnnotationV1 {
            domain_version: VersionV1,
            scope: scope.clone(),
            input: f.invocation.action.inputs.as_slice()[0].clone(),
            restrictions: InformationLabel::bottom(),
            externally_influenced: true,
            facts: BoundedList::new(vec![])?,
            confidence_basis_points: SafeInteger::new(10000)?,
            issued_at_unix_ms: SafeInteger::new(fixture::NOW)?,
            valid_until_unix_ms: SafeInteger::new(fixture::VALID_UNTIL)?,
        },
        &f.annotator,
    )?;
    let transformation = SignedSemanticTransformationV1::sign(
        SemanticTransformationV1 {
            domain_version: VersionV1,
            scope: scope.clone(),
            producer: OperationId::new("synthetic-producer")?,
            producer_action: semantic_action_digest(&f.invocation.action)?,
            inputs: f.invocation.action.inputs.clone(),
            implementation: CanonicalPayloadDigest::from_bytes([3; 32]),
            configuration: CanonicalPayloadDigest::from_bytes([8; 32]),
            output_schema: CanonicalPayloadDigest::from_bytes([2; 32]),
            output: semantic_content_digest(&f.payload)?,
            output_label: InformationLabel::bottom(),
            influence: f.invocation.action.influence,
            destination: f.invocation.action.destination.clone(),
            purpose: ProtectedText::new("customer-support")?,
            disposition: SemanticOutputDispositionV1::ReturnValue,
            issued_at_unix_ms: SafeInteger::new(fixture::NOW)?,
            valid_until_unix_ms: SafeInteger::new(fixture::VALID_UNTIL)?,
        },
        &f.transformer,
    )?;
    let prerequisite = SignedSemanticPrerequisiteV1::sign(
        SemanticPrerequisiteV1 {
            domain_version: VersionV1,
            evidence: EvidenceRef::new("synthetic-evidence")?,
            scope,
            action: semantic_action_digest(&f.invocation.action)?,
            fact: SemanticFactId::new("synthetic-fact")?,
            kind: SemanticPrerequisiteKindV1::HistoricalFact,
            resource: ProviderResourceId::new("ticket")?,
            version: f.invocation.action.inputs.as_slice()[0].version,
            material: f.invocation.action.inputs.as_slice()[0].content,
            producer: OperationId::new("synthetic-producer")?,
            lease: None,
            purpose: ProtectedText::new("customer-support")?,
            issued_at_unix_ms: SafeInteger::new(fixture::NOW)?,
            valid_until_unix_ms: SafeInteger::new(fixture::VALID_UNTIL)?,
        },
        &f.prerequisite,
    )?;
    let request = SemanticProviderRequestV1 {
        domain_version: VersionV1,
        kind: SemanticOperationKindV1::IssueWrite,
        provider: ProviderId::new("support-provider")?,
        account: ProviderAccountId::new("tenant-account")?,
        resource: ProviderResourceId::new("issue-queue")?,
        provider_version: ProtectedText::new("\"resource-v1\"")?,
        operation: OperationId::new("synthetic-operation")?,
        attempt: SemanticProviderAttemptId::new("synthetic-attempt")?,
        payload: f.payload.clone(),
    };
    let response = SemanticProviderResponseV1 {
        provider: ProviderId::new("support-provider")?,
        account: ProviderAccountId::new("tenant-account")?,
        resource: ProviderResourceId::new("issue-queue")?,
        checked_provider_version: ProtectedText::new("\"resource-v1\"")?,
        operation: OperationId::new("synthetic-operation")?,
        attempt: SemanticProviderAttemptId::new("synthetic-attempt")?,
        payload: f.payload.clone(),
    };
    let endorsement = &f.invocation.endorsements.as_slice()[0];
    let mut cases = Vec::new();
    let mut case = |name: &str, value: Value| {
        cases.push(serde_json::json!({"schema": format!("{name}.schema.json"), "value": value}));
    };
    case("semantic-package", serde_json::to_value(f.package.body())?);
    case("signed-semantic-package", serde_json::to_value(&f.package)?);
    case(
        "semantic-deployment",
        serde_json::to_value(f.deployment.body())?,
    );
    case(
        "signed-semantic-deployment",
        serde_json::to_value(&f.deployment)?,
    );
    case(
        "semantic-action",
        serde_json::to_value(&f.invocation.action)?,
    );
    case("semantic-payload", serde_json::to_value(&f.payload)?);
    case("semantic-plan", serde_json::to_value(&f.plan)?);
    case(
        "semantic-audience",
        serde_json::to_value(f.invocation.audience.body())?,
    );
    case(
        "signed-semantic-audience",
        serde_json::to_value(&f.invocation.audience)?,
    );
    case(
        "scoped-endorsement",
        serde_json::to_value(endorsement.body())?,
    );
    case(
        "signed-scoped-endorsement",
        serde_json::to_value(endorsement)?,
    );
    case(
        "semantic-annotation",
        serde_json::to_value(annotation.body())?,
    );
    case(
        "signed-semantic-annotation",
        serde_json::to_value(&annotation)?,
    );
    case(
        "semantic-transformation",
        serde_json::to_value(transformation.body())?,
    );
    case(
        "signed-semantic-transformation",
        serde_json::to_value(&transformation)?,
    );
    case(
        "semantic-prerequisite",
        serde_json::to_value(prerequisite.body())?,
    );
    case(
        "signed-semantic-prerequisite",
        serde_json::to_value(&prerequisite)?,
    );
    case("semantic-invocation", serde_json::to_value(&f.invocation)?);
    case("semantic-provider-request", serde_json::to_value(&request)?);
    case(
        "semantic-provider-response",
        serde_json::to_value(&response)?,
    );
    let wire = |value: &Value| chio_core_types::canonical_json_string(value);
    let mut vectors = Vec::new();
    for case in &cases {
        let schema = case["schema"].as_str().ok_or("schema name")?;
        let value = &case["value"];
        vectors.push(serde_json::json!({"name": schema, "schema": schema, "wire": wire(value)?, "valid": true, "schema_valid": true}));
        let mut unknown = value.clone();
        unknown["unexpected"] = serde_json::json!("private-error-canary");
        vectors.push(serde_json::json!({"name": format!("{schema}:unknown-field"), "schema": schema, "wire": wire(&unknown)?, "valid": false, "schema_valid": false}));
        if schema.starts_with("signed-") {
            let mut forged = value.clone();
            let signature = forged["signature"].as_str().ok_or("signature text")?;
            forged["signature"] = serde_json::json!(format!(
                "{}{}",
                if signature.starts_with('0') { "1" } else { "0" },
                &signature[1..]
            ));
            vectors.push(serde_json::json!({"name": format!("{schema}:signature-substitution"), "schema": schema, "wire": wire(&forged)?, "valid": false, "schema_valid": true}));
        }
    }
    for (schema, field) in [
        ("semantic-prerequisite.schema.json", "lease"),
        ("semantic-invocation.schema.json", "transformation"),
    ] {
        let mut value = cases
            .iter()
            .find(|case| case["schema"] == schema)
            .ok_or("nullable schema")?["value"]
            .clone();
        value
            .as_object_mut()
            .ok_or("nullable object")?
            .remove(field);
        vectors.push(serde_json::json!({"name": format!("{schema}:required-nullable-omitted"), "schema": schema, "wire": wire(&value)?, "valid": false, "schema_valid": false}));
    }
    let payload = serde_json::to_value(&f.payload)?;
    let canonical = wire(&payload)?;
    let duplicate = format!(
        "{{\"fields\":{},{}",
        wire(&payload["fields"])?,
        &canonical[1..]
    );
    vectors.push(serde_json::json!({"name": "payload:duplicate-key", "schema": "semantic-payload.schema.json", "wire": duplicate, "valid": false, "schema_valid": true}));
    let output = serde_json::json!({
        "format_version": 1,
        "qualification": "synthetic_wire_data_only",
        "cases": cases,
        "vectors": vectors,
        "exposed": f.exposed,
        "role_keys": [
            f.publisher.public_key(),
            f.operator.public_key(),
            f.resolver.public_key(),
            f.endorser.public_key(),
            f.annotator.public_key(),
            f.transformer.public_key(),
            f.prerequisite.public_key(),
        ],
    });
    Ok(format!("{}\n", serde_json::to_string_pretty(&output)?))
}

const COMMITTED: &str =
    include_str!("../../../../spec/vectors/recovery/v1/semantic-contracts.json");

#[test]
fn semantic_vectors_are_current() -> Result {
    assert!(
        COMMITTED == built_corpus()?,
        "fixture spec/vectors/recovery/v1/semantic-contracts.json is out of date"
    );
    Ok(())
}

#[test]
fn signed_cases_verify_against_their_pinned_role_keys() -> Result {
    let corpus: Value = serde_json::from_str(COMMITTED)?;
    let keys = corpus["role_keys"].as_array().ok_or("role_keys")?;
    for (schema, role) in [
        ("signed-semantic-package.schema.json", 0),
        ("signed-semantic-deployment.schema.json", 1),
        ("signed-semantic-audience.schema.json", 2),
        ("signed-scoped-endorsement.schema.json", 3),
        ("signed-semantic-annotation.schema.json", 4),
        ("signed-semantic-transformation.schema.json", 5),
        ("signed-semantic-prerequisite.schema.json", 6),
    ] {
        let case = corpus["cases"]
            .as_array()
            .ok_or("cases")?
            .iter()
            .find(|case| case["schema"] == schema)
            .ok_or("signed case")?;
        assert_eq!(case["value"]["authority_key"], keys[role], "{schema}");
        let bytes = serde_json::to_vec(&case["value"])?;
        assert!(accepts(schema, &bytes), "{schema}");
    }
    Ok(())
}

#[test]
#[ignore = "regenerator: rewrite spec/vectors/recovery/v1/semantic-contracts.json from the semantic contract builders; run with --ignored"]
fn write_semantic_vectors() -> Result {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/vectors/recovery/v1/semantic-contracts.json");
    std::fs::write(path, built_corpus()?)?;
    Ok(())
}
