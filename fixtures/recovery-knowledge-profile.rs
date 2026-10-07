//! Deterministic development-only portable knowledge contracts. No live authorities.
use chio_core_types::{recovery::*, Keypair};
use chio_security_types::{knowledge::*, recovery::*, InformationLabel, PrincipalId};

pub fn metadata() -> Result<ArtifactVersionV1, Box<dyn std::error::Error>> {
    Ok(ArtifactVersionV1 {
        domain_version: VersionV1,
        scope: RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new("knowledge-fixture-authority")?,
            tenant_id: RecoveryTenantId::new("fixture-tenant")?,
            process_id: ProcessId::new("fixture-process")?,
        },
        artifact: ArtifactId::new("fixture-artifact")?,
        version: ArtifactRevisionId::new("fixture-version")?,
        content: knowledge_content_digest(b"fixture-value"),
        size_bytes: SafeInteger::new(13)?,
        media_type: ProtectedText::new("application/octet-stream")?,
        schema: knowledge_content_digest(b"chio.knowledge.opaque-bytes.v1"),
        producer: ArtifactProducerV1::Adoption {
            evidence: EvidenceRef::new("fixture-classification")?,
        },
        dependencies: BoundedList::new(vec![])?,
        label: InformationLabel::bottom(),
        influence: ArtifactInfluenceV1 {
            commitment: CanonicalPayloadDigest::from_bytes([218; 32]),
            externally_influenced: true,
            unknown: true,
        },
        lineage: IsolationLineageId::new("fixture-lineage")?,
        isolation_epoch: ProtectedText::new("fixture-isolation")?,
        evidence: BoundedList::new(vec![EvidenceRef::new("fixture-classification")?])?,
        policy: PolicyDigest::from_bytes([219; 32]),
        contract: ContractDigest::from_bytes([220; 32]),
        creation_sequence: SafeInteger::new(1)?,
        retention: ArtifactRetentionV1::Checkpoint,
    })
}
pub fn recipient() -> Result<ArtifactRecipientV1, Box<dyn std::error::Error>> {
    let metadata = metadata()?;
    Ok(ArtifactRecipientV1 {
        recipient: ArtifactRecipientId::new("fixture-recipient")?,
        scope: metadata.scope,
        runtime: ProtectedText::new("fixture-runtime")?,
        principal: PrincipalId::new("fixture-principal")?,
        lineage: metadata.lineage,
        isolation_epoch: metadata.isolation_epoch,
        context_generation: SafeInteger::new(1)?,
        clearance: InformationLabel::bottom(),
        sink: ArtifactSinkV1::Agent,
    })
}
pub fn contracts() -> Result<Vec<(&'static str, serde_json::Value)>, Box<dyn std::error::Error>> {
    let metadata = metadata()?;
    let reference = artifact_version_reference(&metadata)?;
    let recipient = recipient()?;
    let certificate = ArtifactCertificateV1 {
        domain_version: VersionV1,
        evidence: EvidenceRef::new("fixture-classification")?,
        scope: metadata.scope.clone(),
        kind: ArtifactCertificateKindV1::Classification,
        artifact: metadata.artifact.clone(),
        version: metadata.version.clone(),
        producer: metadata.producer.clone(),
        content: metadata.content,
        size_bytes: metadata.size_bytes,
        schema: metadata.schema,
        dependencies: metadata.dependencies.clone(),
        implementation: CanonicalPayloadDigest::from_bytes([221; 32]),
        configuration: CanonicalPayloadDigest::from_bytes([222; 32]),
        output_label: metadata.label.clone(),
        influence: metadata.influence.clone(),
        issued_at_unix_ms: SafeInteger::new(10_000)?,
        valid_until_unix_ms: SafeInteger::new(20_000)?,
    };
    let manifest = ArtifactArchiveManifestV1 {
        domain_version: VersionV1,
        scope: metadata.scope.clone(),
        root: reference.clone(),
        versions: NonEmptyBoundedList::new(vec![metadata.clone()])?,
        total_bytes: metadata.size_bytes,
    };
    let model = ModelContextV1 {
        context: ModelContextId::new("fixture-model")?,
        provider: ProviderId::new("fixture-provider")?,
        account: ProviderAccountId::new("fixture-account")?,
        conversation: ProtectedText::new("fixture-conversation")?,
        cache: ProtectedText::new("fixture-cache")?,
        side_files: BoundedList::new(vec![reference.clone()])?,
        contract: metadata.contract,
    };
    let release = ArtifactReleaseIntentV1 {
        domain_version: VersionV1,
        release: ReleaseId::new("fixture-release")?,
        kind: ArtifactReleaseKindV1::IndependentlyAdmitted {
            request: RequestId::new("fixture-request")?,
        },
        artifact: reference.clone(),
        source_label: metadata.label.clone(),
        influence: metadata.influence.clone(),
        admitted_label: metadata.label.clone(),
        recipient: recipient.clone(),
        policy: metadata.policy,
        authorization: ReleaseAuthorizationDigest::from_bytes([223; 32]),
        observation_transition: EvidenceRef::new("fixture-observation")?,
        observation_generation: SafeInteger::new(2)?,
        state: ArtifactDeliveryStateV1::Admitted,
    };
    let checkpoint = LabeledCheckpointV1 {
        domain_version: VersionV1,
        checkpoint: CheckpointId::new("fixture-checkpoint")?,
        revision: SafeInteger::new(1)?,
        scope: metadata.scope.clone(),
        runtime: ProtectedText::new("fixture-runtime")?,
        artifacts: NonEmptyBoundedList::new(vec![reference.clone()])?,
        model_contexts: BoundedList::new(vec![model.clone()])?,
        label: metadata.label.clone(),
        influence: metadata.influence.clone(),
        lineage: metadata.lineage.clone(),
        isolation_epoch: metadata.isolation_epoch.clone(),
        native_evidence_sequence: SafeInteger::new(10)?,
        policy: metadata.policy,
    };
    let mut result = Vec::new();
    macro_rules! contract {
        ($name:literal,$body:expr) => {
            result.push(($name, serde_json::to_value($body)?));
        };
    }
    contract!("artifact-reference.schema.json", reference);
    contract!("artifact-influence.schema.json", metadata.influence.clone());
    contract!("artifact-producer.schema.json", metadata.producer.clone());
    contract!("artifact-version.schema.json", metadata);
    contract!("artifact-recipient.schema.json", recipient);
    contract!("artifact-certificate.schema.json", certificate.clone());
    contract!(
        "signed-artifact-certificate.schema.json",
        SignedArtifactCertificateV1::sign(certificate, &Keypair::from_seed(&[224; 32]))?
    );
    contract!("artifact-archive-manifest.schema.json", manifest.clone());
    contract!(
        "signed-artifact-archive-manifest.schema.json",
        SignedArtifactArchiveManifestV1::sign(manifest, &Keypair::from_seed(&[225; 32]))?
    );
    contract!("model-context.schema.json", model);
    contract!("labeled-checkpoint.schema.json", checkpoint);
    contract!("artifact-release-intent.schema.json", release);
    contract!(
        "artifact-handle.schema.json",
        ArtifactHandleV1 {
            handle: ArtifactHandleId::new("fixture-handle")?,
            recipient: ArtifactRecipientId::new("fixture-recipient")?
        }
    );
    Ok(result)
}
