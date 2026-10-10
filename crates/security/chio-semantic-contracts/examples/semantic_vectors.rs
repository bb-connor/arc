//! Deterministic wire fixtures. Synthetic signatures are data, not native proof.
#[path = "../../../../fixtures/recovery-semantic-profile.rs"]
mod fixture;
use chio_core_types::recovery::*;
use chio_security_types::{flow::InformationLabel, recovery::*, semantic::*};
use fixture::*;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scope = RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new("authority")?,
        tenant_id: RecoveryTenantId::new("tenant")?,
        process_id: ProcessId::new("root")?,
    };
    let f = semantic_fixture(
        scope.clone(),
        1000,
        InformationLabel::bottom(),
        SemanticOperationKindV1::IssueWrite,
    )?;
    let annotation = SignedSemanticAnnotationV1::sign(
        SemanticAnnotationV1 {
            domain_version: VersionV1,
            scope: scope.clone(),
            input: f.invocation.action.inputs.as_slice()[0].clone(),
            restrictions: InformationLabel::bottom(),
            externally_influenced: true,
            facts: BoundedList::new(vec![])?,
            confidence_basis_points: SafeInteger::new(10000)?,
            issued_at_unix_ms: SafeInteger::new(1000)?,
            valid_until_unix_ms: SafeInteger::new(51000)?,
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
            issued_at_unix_ms: SafeInteger::new(1000)?,
            valid_until_unix_ms: SafeInteger::new(51000)?,
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
            issued_at_unix_ms: SafeInteger::new(1000)?,
            valid_until_unix_ms: SafeInteger::new(51000)?,
        },
        &f.prerequisite,
    )?;
    let mut cases = Vec::new();
    macro_rules! case { ($name:literal, $value:expr) => { cases.push(serde_json::json!({"schema":concat!($name,".schema.json"),"value":$value})); }; }
    case!("semantic-package", f.package.body());
    case!("signed-semantic-package", &f.package);
    case!("semantic-deployment", f.deployment.body());
    case!("signed-semantic-deployment", &f.deployment);
    case!("semantic-action", &f.invocation.action);
    case!("semantic-payload", &f.payload);
    case!("semantic-plan", &f.plan);
    case!("semantic-audience", f.invocation.audience.body());
    case!("signed-semantic-audience", &f.invocation.audience);
    case!(
        "scoped-endorsement",
        f.invocation.endorsements.as_slice()[0].body()
    );
    case!(
        "signed-scoped-endorsement",
        &f.invocation.endorsements.as_slice()[0]
    );
    case!("semantic-annotation", annotation.body());
    case!("signed-semantic-annotation", &annotation);
    case!("semantic-transformation", transformation.body());
    case!("signed-semantic-transformation", &transformation);
    case!("semantic-prerequisite", prerequisite.body());
    case!("signed-semantic-prerequisite", &prerequisite);
    case!("semantic-invocation", &f.invocation);
    case!(
        "semantic-provider-request",
        SemanticProviderRequestV1 {
            domain_version: VersionV1,
            kind: SemanticOperationKindV1::IssueWrite,
            provider: ProviderId::new("support-provider")?,
            account: ProviderAccountId::new("tenant-account")?,
            resource: ProviderResourceId::new("issue-queue")?,
            provider_version: ProtectedText::new("\"resource-v1\"")?,
            operation: OperationId::new("synthetic-operation")?,
            attempt: SemanticProviderAttemptId::new("synthetic-attempt")?,
            payload: f.payload.clone()
        }
    );
    case!(
        "semantic-provider-response",
        SemanticProviderResponseV1 {
            provider: ProviderId::new("support-provider")?,
            account: ProviderAccountId::new("tenant-account")?,
            resource: ProviderResourceId::new("issue-queue")?,
            checked_provider_version: ProtectedText::new("\"resource-v1\"")?,
            operation: OperationId::new("synthetic-operation")?,
            attempt: SemanticProviderAttemptId::new("synthetic-attempt")?,
            payload: f.payload
        }
    );
    let positive = cases.clone();
    let mut vectors = Vec::new();
    for case in &positive {
        let schema = case["schema"].as_str().ok_or("schema name")?;
        let value = &case["value"];
        vectors.push(serde_json::json!({"name":schema,"schema":schema,"wire":chio_core_types::canonical_json_string(value)?,"valid":true,"schema_valid":true}));
        let mut unknown = value.clone();
        unknown["unexpected"] = serde_json::json!("private-error-canary");
        vectors.push(serde_json::json!({"name":format!("{schema}:unknown-field"),"schema":schema,"wire":chio_core_types::canonical_json_string(&unknown)?,"valid":false,"schema_valid":false}));
        if schema.starts_with("signed-") {
            let mut forged = value.clone();
            let signature = forged["signature"].as_str().ok_or("signature text")?;
            forged["signature"] = serde_json::json!(format!(
                "{}{}",
                if signature.starts_with('0') { "1" } else { "0" },
                &signature[1..]
            ));
            vectors.push(serde_json::json!({"name":format!("{schema}:signature-substitution"),"schema":schema,"wire":chio_core_types::canonical_json_string(&forged)?,"valid":false,"schema_valid":true}));
        }
    }
    for (schema, field) in [
        ("semantic-prerequisite.schema.json", "lease"),
        ("semantic-invocation.schema.json", "transformation"),
    ] {
        let mut value = positive
            .iter()
            .find(|case| case["schema"] == schema)
            .ok_or("nullable schema")?["value"]
            .clone();
        value
            .as_object_mut()
            .ok_or("nullable object")?
            .remove(field);
        vectors.push(serde_json::json!({"name":format!("{schema}:required-nullable-omitted"),"schema":schema,"wire":chio_core_types::canonical_json_string(&value)?,"valid":false,"schema_valid":false}));
    }
    let payload = positive
        .iter()
        .find(|case| case["schema"] == "semantic-payload.schema.json")
        .ok_or("payload")?["value"]
        .clone();
    let wire = chio_core_types::canonical_json_string(&payload)?;
    let duplicate = format!(
        "{{\"fields\":{},{}",
        chio_core_types::canonical_json_string(&payload["fields"])?,
        &wire[1..]
    );
    vectors.push(serde_json::json!({"name":"payload:duplicate-key","schema":"semantic-payload.schema.json","wire":duplicate,"valid":false,"schema_valid":true}));
    let output = serde_json::json!({"format_version":1,"qualification":"synthetic_wire_data_only","cases":cases,"vectors":vectors,
        "exposed":f.exposed,"role_keys":[f.publisher.public_key(),f.operator.public_key(),f.resolver.public_key(),f.endorser.public_key(),f.annotator.public_key(),f.transformer.public_key(),f.prerequisite.public_key()]});
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
