//! Independent blob and authority commits are explicit recoverable cutpoints.
use super::*;

pub(super) fn ensure_publication_audience(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    record: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let uncertified_adoption = actor.permission() == RecoveryPermission::KnowledgeAdopt
        && matches!(record.input.producer, ArtifactProducerV1::Adoption { .. })
        && matches!(
            record.state,
            ArtifactPublicationStateV1::Reserved | ArtifactPublicationStateV1::Staged
        )
        && record.certificate.is_none()
        && record.metadata.label == InformationLabel::Top;
    // Top is a quarantine placeholder before exact content classification.
    // The unavailable reservation confers no read or release authority.
    let audience_label = if uncertified_adoption {
        InformationLabel::bottom()
    } else {
        record.metadata.label.clone()
    };
    traversal::ensure_audience(tx, actor, &audience_label)
}

fn publication(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    input: &ArtifactPublicationInputV1,
) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
    let key = publication_key(actor.scope(), actor.principal(), &input.publication)?;
    let record: NativeArtifactRecordV1 = load(tx, &key)?.ok_or_else(|| refused("reservation"))?;
    if record.input != *input
        || record.metadata.scope != *actor.scope()
        || record.publication_principal.as_ref() != Some(actor.principal())
        || record_publication_key(&record)? != key
    {
        return Err(refused("publication conflict"));
    }
    Ok(record)
}
fn write_record(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &NativeArtifactRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    save(
        tx,
        owner,
        &record.metadata.scope,
        &record_publication_key(record)?,
        record,
    )
}
fn validate_certificate(
    tx: &Transaction<'_>,
    profile: &NativeKnowledgeInstallationV1,
    record: &mut NativeArtifactRecordV1,
    certificate: &SignedArtifactCertificateV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let body = certificate.body();
    let metadata = &record.metadata;
    verify_artifact_certificate(certificate, &profile.certificate_root, metadata, now)
        .map_err(refused)?;
    match (&metadata.producer, body.kind) {
        (ArtifactProducerV1::Adoption { evidence }, ArtifactCertificateKindV1::Classification) => {
            if evidence != &body.evidence
                || body.implementation != profile.classifier_implementation
                || body.configuration != profile.classifier_configuration
            {
                return Err(refused("classifier identity"));
            }
        }
        (
            ArtifactProducerV1::NativeOperation { operation },
            ArtifactCertificateKindV1::Projection,
        ) => {
            validate_native_projection(tx, profile, record, operation, body)?;
        }
        _ => return Err(refused("certificate role")),
    }
    let spent = format!(
        "knowledge-certificate:{}:{}",
        scope_key(&profile.scope)?,
        body.evidence.as_str()
    );
    if let Some(prior) = load::<ArtifactVersionRefV1>(tx, &spent)? {
        if prior.artifact != metadata.artifact || prior.version != metadata.version {
            return Err(refused("certificate replay"));
        }
    }
    record.metadata.label = body.output_label.clone();
    record.metadata.evidence = BoundedList::new(vec![body.evidence.clone()]).map_err(refused)?;
    record.certificate = Some(certificate.clone());
    Ok(())
}
fn validate_native_projection(
    tx: &Transaction<'_>,
    profile: &NativeKnowledgeInstallationV1,
    record: &NativeArtifactRecordV1,
    operation: &OperationId,
    body: &ArtifactCertificateV1,
) -> Result<(), AdmissionOperationStoreError> {
    use chio_security_types::semantic::*;
    use chio_semantic_contracts::{project_semantic_fields, VerificationBudget};
    let captured: super::super::semantic::NativeSemanticCaptureRecordV1 =
        load(tx, &format!("semantic-capture:{}", operation.as_str()))?
            .ok_or_else(|| refused("projection producer"))?;
    if captured.contract.kind != SemanticOperationKindV1::FieldProjection
        || captured.invocation.action.output != SemanticOutputDispositionV1::ReturnValue
        || captured.invocation.action.scope != profile.scope
        || captured.native_authority != profile.native_authority
        || recovery_flow_key(&captured.security_context)
            != recovery_flow_key(&profile.producer_context)
        || captured.contract.implementation != body.implementation
        || semantic_content_digest(&captured.contract.projection_fields).map_err(refused)?
            != body.configuration
    {
        return Err(refused("native projection binding"));
    }
    let expected = project_semantic_fields(
        &captured.invocation.payload,
        captured.contract.projection_fields.as_slice(),
        &mut VerificationBudget::new(4096).map_err(refused)?,
    )
    .map_err(refused)?;
    let outcome = crate::tool_outcome_store::load_outcome_connection(tx, operation.as_str())
        .map_err(refused)?
        .ok_or_else(|| refused("projection outcome"))?;
    let actual = crate::tool_outcome_store::load_resolved_blob_connection(tx, &outcome)
        .map_err(refused)?
        .ok_or_else(|| refused("projection bytes"))?;
    if chio_core::canonical_json_bytes(&expected)
        .map_err(refused)?
        .as_slice()
        != actual.bytes()
        || knowledge_content_digest(actual.bytes()) != body.content
    {
        return Err(refused("projection recomputation"));
    }
    let mut inputs = Vec::new();
    for reference in record.metadata.dependencies.as_slice() {
        let dependency = artifact(tx, reference)?;
        if dependency.metadata.content
            != knowledge_content_digest(
                &chio_core::canonical_json_bytes(&captured.invocation.payload).map_err(refused)?,
            )
        {
            return Err(refused("projection dependency bytes"));
        }
        inputs.push(semantic_content_digest(&captured.invocation.payload).map_err(refused)?);
    }
    if !captured
        .invocation
        .action
        .inputs
        .as_slice()
        .iter()
        .all(|input| inputs.contains(&input.content))
    {
        return Err(refused("projection input omission"));
    }
    Ok(())
}
impl SqliteAdmissionOperationStore {
    pub fn reserve_artifact(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: &ArtifactPublicationInputV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
        if !matches!(
            actor.permission(),
            RecoveryPermission::KnowledgeWrite | RecoveryPermission::KnowledgeAdopt
        ) || input.size_bytes.get() > MAX_ARTIFACT_BYTES as u64
        {
            return Err(refused("publication authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let key = publication_key(actor.scope(), actor.principal(), &input.publication)?;
            if let Some(existing) = load::<NativeArtifactRecordV1>(&tx, &key)? {
                if existing.input != *input
                    || existing.metadata.scope != *actor.scope()
                    || existing.publication_principal.as_ref() != Some(actor.principal())
                    || record_publication_key(&existing)? != key
                    || existing.state == ArtifactPublicationStateV1::Retired
                {
                    return Err(refused("publication identity"));
                }
                ensure_publication_audience(&tx, actor, &existing)?;
                return Ok((tx, existing));
            }
            // Older envelopes omitted writer identity. Preserve their custody
            // rather than assigning the current principal to historical work.
            if load::<NativeArtifactRecordV1>(
                &tx,
                &legacy_publication_key(actor.scope(), &input.publication)?,
            )?
            .is_some()
            {
                return Err(refused("legacy publication owner unproven"));
            }
            let count:i64=tx.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'knowledge-publication:*'",[],|row|row.get(0)).map_err(sqlite_error)?;
            if count >= 512 {
                return Err(refused("artifact quota"));
            }
            let dependencies =
                traversal::dependencies(&tx, actor.scope(), input.dependencies.as_slice())?;
            let mut label = source(&tx, &profile.native_authority, &profile.producer_context)?;
            let mut imported = None;
            let adoption = matches!(input.producer, ArtifactProducerV1::Adoption { .. });
            match &input.producer {
                ArtifactProducerV1::NativeOperation { operation } => {
                    let id = AdmissionOperationId::from_persisted(operation.as_str())
                        .map_err(refused)?;
                    let original = load_operation_for_participant_tx(&tx, &id)?
                        .ok_or_else(|| refused("producer"))?;
                    if original.state() != AdmissionOperationState::Completed
                        || original.native_dispatch_ledger_digest().is_none()
                    {
                        return Err(refused("producer incomplete"));
                    }
                    let retained =
                        super::super::retained_request::load_retained_request_tx(&tx, &original)?
                            .ok_or_else(|| refused("producer request"))?;
                    retained.validate_native_security_authority(&profile.native_authority)?;
                    retained.validate_native_security_context(&profile.producer_context)?;
                    let outcome =
                        crate::tool_outcome_store::load_outcome_connection(&tx, operation.as_str())
                            .map_err(refused)?
                            .ok_or_else(|| refused("producer outcome"))?;
                    let bytes =
                        crate::tool_outcome_store::load_resolved_blob_connection(&tx, &outcome)
                            .map_err(refused)?
                            .ok_or_else(|| refused("producer bytes"))?;
                    if knowledge_content_digest(bytes.bytes()) != input.content
                        || bytes.bytes().len() as u64 != input.size_bytes.get()
                    {
                        return Err(refused("producer content"));
                    }
                }
                ArtifactProducerV1::Adoption { .. } => {
                    if actor.permission() != RecoveryPermission::KnowledgeAdopt
                        || !input.dependencies.as_slice().is_empty()
                    {
                        return Err(refused("adoption"));
                    }
                    label = InformationLabel::Top;
                }
                ArtifactProducerV1::Checkpoint { .. } | ArtifactProducerV1::Derivation { .. } => {
                    if actor.permission() != RecoveryPermission::KnowledgeWrite {
                        return Err(refused("write"));
                    }
                }
                ArtifactProducerV1::Import { .. } => {
                    if actor.permission() != RecoveryPermission::KnowledgeWrite {
                        return Err(refused("import write"));
                    }
                    let source = super::transfer::import_source(&tx, profile, input)?;
                    label = label.join_restrictions(&source.label).map_err(refused)?;
                    imported = Some(source);
                }
            }
            label = traversal::join_metadata(label, &dependencies)?;
            let sequence: i64 = tx
                .query_row(
                    "SELECT COALESCE(max(sequence),0)+1 FROM admission_operation_recovery_events",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            let mut metadata = ArtifactVersionV1 {
                domain_version: VersionV1,
                scope: profile.scope.clone(),
                artifact: ArtifactId::new(&uuid::Uuid::new_v4().to_string()).map_err(refused)?,
                version: ArtifactRevisionId::new(&uuid::Uuid::new_v4().to_string())
                    .map_err(refused)?,
                content: input.content,
                size_bytes: input.size_bytes,
                media_type: input.media_type.clone(),
                schema: input.schema,
                producer: input.producer.clone(),
                dependencies: input.dependencies.clone(),
                label,
                influence: traversal::influence(
                    &tx,
                    &profile.native_authority,
                    &profile.producer_context,
                    &dependencies,
                    adoption,
                )?,
                lineage: IsolationLineageId::new(
                    profile.producer_context.as_v1().lineage_root_id().as_str(),
                )
                .map_err(refused)?,
                isolation_epoch: ProtectedText::new(
                    profile
                        .producer_context
                        .as_v1()
                        .isolation_epoch_id()
                        .as_str(),
                )
                .map_err(refused)?,
                evidence: BoundedList::new(vec![]).map_err(refused)?,
                policy: profile.policy,
                contract: profile.contract,
                creation_sequence: SafeInteger::new(u64::try_from(sequence).map_err(refused)?)
                    .map_err(refused)?,
                retention: input.retention,
            };
            if let Some(origin) = imported {
                metadata.influence.commitment = CanonicalPayloadDigest::from_bytes(
                    knowledge_digest(
                        RecoveryDigestDomain::KnowledgeImportInfluence,
                        &(&origin.influence, &metadata.influence),
                    )
                    .map_err(refused)?,
                );
                metadata.influence.unknown |= origin.influence.unknown;
                metadata.evidence = origin.evidence;
            }
            metadata.validate().map_err(refused)?;
            let record = NativeArtifactRecordV1 {
                input: input.clone(),
                metadata,
                object: ArtifactObjectId::new(&uuid::Uuid::new_v4().to_string())
                    .map_err(refused)?,
                seal: None,
                state: ArtifactPublicationStateV1::Reserved,
                installation_generation: profile.generation,
                certificate: None,
                location: ProtectedText::new("private-process-blob").map_err(refused)?,
                publication_principal: Some(actor.principal().clone()),
            };
            ensure_publication_audience(&tx, actor, &record)?;
            write_record(&tx, &self.serving_owner, &record)?;
            Ok((tx, record))
        })
    }
    pub fn stage_artifact(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: &ArtifactPublicationInputV1,
        seal: &ArtifactBlobSealV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
        if !matches!(
            actor.permission(),
            RecoveryPermission::KnowledgeWrite | RecoveryPermission::KnowledgeAdopt
        ) {
            return Err(refused("stage authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, _| {
            let mut record = publication(&tx, actor, input)?;
            ensure_publication_audience(&tx, actor, &record)?;
            if seal.object != record.object
                || seal.runtime.as_str() != profile.producer_context.as_v1().session_id().as_str()
                || seal.process != profile.scope.process_id
                || seal.content != input.content
                || seal.bytes != input.size_bytes
            {
                return Err(refused("sealed object"));
            }
            lifecycle::require_stage_not_sweeping(&tx, profile, seal)?;
            if let Some(old) = &record.seal {
                if old != seal {
                    return Err(refused("stage changed"));
                }
                return Ok((tx, record));
            }
            if record.state != ArtifactPublicationStateV1::Reserved
                || record.installation_generation != profile.generation
            {
                return Err(refused("stage state"));
            }
            record.seal = Some(seal.clone());
            record.state = ArtifactPublicationStateV1::Staged;
            write_record(&tx, &self.serving_owner, &record)?;
            Ok((tx, record))
        })
    }
    pub fn commit_artifact_metadata(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: &ArtifactPublicationInputV1,
        certificate: Option<&SignedArtifactCertificateV1>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeArtifactRecordV1, AdmissionOperationStoreError> {
        if !matches!(
            actor.permission(),
            RecoveryPermission::KnowledgeWrite | RecoveryPermission::KnowledgeAdopt
        ) {
            return Err(refused("metadata authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let mut record = publication(&tx, actor, input)?;
            if matches!(
                record.state,
                ArtifactPublicationStateV1::MetadataCommitted
                    | ArtifactPublicationStateV1::Available
            ) {
                traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
                if record.certificate.as_ref() != certificate {
                    return Err(refused("certificate changed"));
                }
                return Ok((tx, record));
            }
            if record.state != ArtifactPublicationStateV1::Staged
                || record.installation_generation != profile.generation
            {
                return Err(refused("metadata state"));
            }
            traversal::dependencies(&tx, actor.scope(), input.dependencies.as_slice())?;
            if certificate.is_none() {
                record.metadata.label = traversal::join_metadata(
                    record
                        .metadata
                        .label
                        .join_restrictions(&source(
                            &tx,
                            &profile.native_authority,
                            &profile.producer_context,
                        )?)
                        .map_err(refused)?,
                    &traversal::dependencies(&tx, actor.scope(), input.dependencies.as_slice())?,
                )?;
            }
            if let Some(certificate) = certificate {
                validate_certificate(&tx, profile, &mut record, certificate, now)?;
            } else if matches!(input.producer, ArtifactProducerV1::Adoption { .. }) {
                return Err(refused("legacy certificate absent"));
            }
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            record.state = ArtifactPublicationStateV1::MetadataCommitted;
            let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
            if load::<String>(&tx, &version_key(&reference)?)?.is_some() {
                return Err(refused("version collision"));
            }
            save(
                &tx,
                &self.serving_owner,
                actor.scope(),
                &version_key(&reference)?,
                &record_publication_key(&record)?,
            )?;
            if let Some(certificate) = &record.certificate {
                save(
                    &tx,
                    &self.serving_owner,
                    actor.scope(),
                    &format!(
                        "knowledge-certificate:{}:{}",
                        scope_key(actor.scope())?,
                        certificate.body().evidence.as_str()
                    ),
                    &reference,
                )?;
            }
            write_record(&tx, &self.serving_owner, &record)?;
            let _reference_delta = reference_activation::initialize_committed_artifact_references(
                &tx,
                &self.serving_owner,
                &record,
            )?;
            Ok((tx, record))
        })
    }
    /// Final availability CAS occurs only after exact private object verification.
    pub fn finalize_artifact(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: &ArtifactPublicationInputV1,
        verified_seal: &ArtifactBlobSealV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ArtifactVersionRefV1, AdmissionOperationStoreError> {
        if !matches!(
            actor.permission(),
            RecoveryPermission::KnowledgeWrite | RecoveryPermission::KnowledgeAdopt
        ) {
            return Err(refused("finalize authority"));
        }
        let outcome = mutate(self, actor, fence, now, |tx, profile, _| {
            let mut record = publication(&tx, actor, input)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            if record.seal.as_ref() != Some(verified_seal) {
                return Err(refused("final object changed"));
            }
            if record.state == ArtifactPublicationStateV1::Available {
                let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
                return Ok((tx, Some(reference)));
            }
            if record.state != ArtifactPublicationStateV1::MetadataCommitted
                || record.installation_generation != profile.generation
            {
                return Err(refused("availability state"));
            }
            traversal::dependencies(&tx, actor.scope(), input.dependencies.as_slice())?;
            if record.certificate.is_none()
                && !source(&tx, &profile.native_authority, &profile.producer_context)?
                    .flows_to(&record.metadata.label)
            {
                record.state = ArtifactPublicationStateV1::Quarantined;
                write_record(&tx, &self.serving_owner, &record)?;
                return Ok((tx, None));
            }
            record.state = ArtifactPublicationStateV1::Available;
            write_record(&tx, &self.serving_owner, &record)?;
            let reference = artifact_version_reference(&record.metadata).map_err(refused)?;
            Ok((tx, Some(reference)))
        })?;
        outcome.ok_or_else(|| refused("producer context strengthened"))
    }
    pub fn quarantine_artifact(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: &ArtifactPublicationInputV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !matches!(
            actor.permission(),
            RecoveryPermission::KnowledgeRead
                | RecoveryPermission::KnowledgeWrite
                | RecoveryPermission::KnowledgeAdopt
                | RecoveryPermission::KnowledgeAdmin
        ) {
            return Err(refused("quarantine authority"));
        }
        mutate(self, actor, fence, now, |tx, _, _| {
            let mut record = publication(&tx, actor, input)?;
            if record.state != ArtifactPublicationStateV1::Retired {
                record.state = ArtifactPublicationStateV1::Quarantined;
                write_record(&tx, &self.serving_owner, &record)?;
            }
            Ok((tx, ()))
        })
    }
    /// Private read failure quarantines the exact selected version, regardless
    /// of which authorized publisher originally created its immutable record.
    pub fn quarantine_artifact_version(
        &self,
        actor: &AuthenticatedRecoveryActor,
        reference: &ArtifactVersionRefV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if reference.scope != *actor.scope()
            || !matches!(
                actor.permission(),
                RecoveryPermission::KnowledgeRead | RecoveryPermission::KnowledgeAdmin
            )
        {
            return Err(refused("quarantine authority"));
        }
        mutate(self, actor, fence, now, |tx, _, _| {
            let mut record = artifact(&tx, reference)?;
            traversal::ensure_audience(&tx, actor, &record.metadata.label)?;
            record.state = ArtifactPublicationStateV1::Quarantined;
            write_record(&tx, &self.serving_owner, &record)?;
            Ok((tx, ()))
        })
    }
}
