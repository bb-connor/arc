//! Return admission is an independent native release, never a schema-only permit.
use super::*;

mod candidate;
mod delivery;
mod original_admission;
pub(super) use original_admission::OriginalReturnOrigin;

fn metadata(record: &BoundaryRecord) -> Result<&ArtifactVersionV1, AdmissionOperationStoreError> {
    record
        .return_metadata
        .as_ref()
        .ok_or_else(|| refused("return metadata"))
}
fn expected_evidence(
    record: &BoundaryRecord,
    issued: SafeInteger,
    expires: SafeInteger,
    evidence: EvidenceRef,
) -> Result<ConfinedReturnEvidenceV1, AdmissionOperationStoreError> {
    let m = metadata(record)?;
    let b = &record.reservation.boundary;
    Ok(ConfinedReturnEvidenceV1 {
        domain_version: VersionV1,
        evidence,
        boundary: isolation_boundary_digest(b).map_err(refused)?,
        launch: record.launch.ok_or_else(|| refused("launch"))?,
        artifact: artifact_version_reference(m).map_err(refused)?,
        content: m.content,
        size_bytes: m.size_bytes,
        source: m.label.clone(),
        influence: m.influence.clone(),
        parent: b.parent.clone(),
        contract: b.return_contract,
        implementation: record.installation.contract.implementation,
        observation: b.observation.clone(),
        target: record.installation.contract.target.clone(),
        policy: b.policy,
        issued_at_unix_ms: issued,
        expires_at_unix_ms: expires,
    })
}
fn check_evidence(
    record: &BoundaryRecord,
    body: &ConfinedReturnEvidenceV1,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    body.validate().map_err(refused)?;
    if *body
        != expected_evidence(
            record,
            body.issued_at_unix_ms,
            body.expires_at_unix_ms,
            body.evidence.clone(),
        )?
        || now < body.issued_at_unix_ms.get()
        || now >= body.expires_at_unix_ms.get()
    {
        return Err(refused("return authority binding"));
    }
    Ok(())
}
fn spend(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
    role: &str,
    root: &PublicKey,
    body: &ConfinedReturnEvidenceV1,
) -> Result<(), AdmissionOperationStoreError> {
    let key = format!(
        "confined-evidence:{role}:{}:{}",
        root.to_hex(),
        body.evidence.as_str()
    );
    let digest = CanonicalPayloadDigest::from_bytes(
        knowledge_digest(RecoveryDigestDomain::ConfinedEvidenceBinding, body).map_err(refused)?,
    );
    if let Some(old) = load::<CanonicalPayloadDigest>(tx, &key)? {
        if old != digest {
            return Err(refused("evidence consumed"));
        }
    } else {
        save(tx, owner, scope, &key, &digest)?;
    }
    Ok(())
}
impl SqliteAdmissionOperationStore {
    /// A fresh unit-only audience check precedes host channel and exit handling.
    /// It grants no value, evidence, recipient or launch authority.
    pub fn verify_confined_staging_audience(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("staging audience authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let record = record(&tx, actor.scope(), request)?;
            let input = require_input_source_audience(
                &tx,
                actor,
                parent_source,
                &record.reservation.boundary,
            )?;
            require_child_source_audience(&tx, actor, profile, &record, input)?;
            validate_current(&tx, &record, profile, now)?;
            Ok((tx, ()))
        })
    }
    /// Classified, current-authority review of a retained staged artifact. A
    /// disappeared host can recover approval data without launching again.
    pub fn confined_return_evidence(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ConfinedReturnEvidenceV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedReturn {
            return Err(refused("review authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let record = record(&tx, actor.scope(), request)?;
            let input = require_input_source_audience(
                &tx,
                actor,
                parent_source,
                &record.reservation.boundary,
            )?;
            require_child_source_audience(&tx, actor, profile, &record, input)?;
            validate_current(&tx, &record, profile, now)?;
            if !matches!(
                record.reservation.state,
                IsolationStateV1::ReturnStaged
                    | IsolationStateV1::ReturnAdmitted
                    | IsolationStateV1::Closed
            ) {
                return Err(refused("review unavailable"));
            }
            traversal::ensure_audience(&tx, actor, &metadata(&record)?.label)?;
            let expires = now
                .checked_add(60_000)
                .ok_or_else(|| refused("review deadline"))?
                .min(record.installation.contract.expires_at_unix_ms.get());
            let body = expected_evidence(
                &record,
                SafeInteger::new(now).map_err(refused)?,
                SafeInteger::new(expires).map_err(refused)?,
                EvidenceRef::new(&uuid::Uuid::new_v4().to_string()).map_err(refused)?,
            )?;
            Ok((tx, body))
        })
    }
    /// Only canonical, independently recomputed output becomes a staged return.
    /// The exact immutable seal is retained even if a later permit is withheld.
    /// Staging authority does not expose classified return evidence.
    ///
    /// ```compile_fail
    /// use chio_kernel::{admission_operation::{AdmissionOperationStoreError, StoreMutationFence},
    ///     knowledge::ArtifactBlobSealV1, recovery::AuthenticatedRecoveryActor};
    /// use chio_security_types::recovery::{CanonicalPayloadDigest, RequestId};
    /// use chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore;
    /// fn expose_staged_digest(store: &SqliteAdmissionOperationStore,
    ///     actor: &AuthenticatedRecoveryActor, request: &RequestId,
    ///     seal: &ArtifactBlobSealV1, fence: &StoreMutationFence,
    /// ) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    ///     Ok(store.stage_confined_return(actor, request, seal, b"true", fence, 1)?.content)
    /// }
    /// ```
    ///
    /// ```no_run
    /// use chio_kernel::{admission_operation::{AdmissionOperationStoreError, StoreMutationFence},
    ///     knowledge::ArtifactBlobSealV1, recovery::AuthenticatedRecoveryActor};
    /// use chio_security_types::recovery::RequestId;
    /// use chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore;
    /// fn stage_without_metadata(store: &SqliteAdmissionOperationStore,
    ///     actor: &AuthenticatedRecoveryActor, request: &RequestId,
    ///     seal: &ArtifactBlobSealV1, fence: &StoreMutationFence,
    /// ) -> Result<(), AdmissionOperationStoreError> {
    ///     store.stage_confined_return(actor, request, seal, b"true", fence, 1)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn stage_confined_return(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        seal: &ArtifactBlobSealV1,
        bytes: &[u8],
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedLaunch {
            return Err(refused("return staging authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let mut record = record(&tx, actor.scope(), request)?;
            let input = require_input_source_audience(
                &tx,
                actor,
                parent_source,
                &record.reservation.boundary,
            )?;
            require_child_source_audience(&tx, actor, profile, &record, input)?;
            let basis = candidate::basis(&tx, actor, &record, profile, bytes, now)?;
            let b = &record.reservation.boundary;
            if seal.content != knowledge_content_digest(bytes)
                || seal.bytes.get() != bytes.len() as u64
                || seal.process != b.child
                || seal.runtime != b.parent.runtime
            {
                return Err(refused("return producer"));
            }
            if let Some(old) = &record.return_seal {
                if old != seal {
                    return Err(refused("return substitution"));
                }
            } else {
                let mut roots = b.seed_artifacts.as_slice().to_vec();
                roots.push(b.observation.clone());
                let m = ArtifactVersionV1 {
                    domain_version: VersionV1,
                    scope: actor.scope().clone(),
                    artifact: ArtifactId::new(&uuid::Uuid::new_v4().to_string())
                        .map_err(refused)?,
                    version: ArtifactRevisionId::new(&uuid::Uuid::new_v4().to_string())
                        .map_err(refused)?,
                    content: seal.content,
                    size_bytes: seal.bytes,
                    media_type: ProtectedText::new("application/json").map_err(refused)?,
                    schema: record.installation.contract.schema,
                    producer: ArtifactProducerV1::Derivation {
                        operation: OperationId::new(b.boundary.as_str()).map_err(refused)?,
                    },
                    dependencies: BoundedList::new(roots).map_err(refused)?,
                    label: basis.label,
                    influence: basis.influence,
                    lineage: b.lineage.clone(),
                    isolation_epoch: b.isolation_epoch.clone(),
                    evidence: BoundedList::new(vec![b.boundary.clone()]).map_err(refused)?,
                    policy: profile.policy,
                    contract: profile.contract,
                    creation_sequence: SafeInteger::new(1).map_err(refused)?,
                    retention: ArtifactRetentionV1::Evidence,
                };
                record.return_artifact = Some(artifact_version_reference(&m).map_err(refused)?);
                record.return_metadata = Some(m);
                record.return_seal = Some(seal.clone());
                record.reservation.state = IsolationStateV1::ReturnStaged;
                retain(&tx, &self.serving_owner, &record)?;
            }
            Ok((tx, ()))
        })
    }

    /// The broker must resolve the exact seal privately. Returning this tuple is
    /// host custody, not an agent/model read or a parent-visible metadata route.
    pub fn prepare_confined_return(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(ArtifactBlobSealV1, ArtifactVersionRefV1), AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedReturn {
            return Err(refused("return read authority"));
        }
        mutate(self, actor, fence, now, |tx, profile, now| {
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let record = record(&tx, actor.scope(), request)?;
            let input = require_input_source_audience(
                &tx,
                actor,
                parent_source,
                &record.reservation.boundary,
            )?;
            require_child_source_audience(&tx, actor, profile, &record, input)?;
            validate_current(&tx, &record, profile, now)?;
            if !matches!(
                record.reservation.state,
                IsolationStateV1::ReturnStaged
                    | IsolationStateV1::ReturnAdmitted
                    | IsolationStateV1::Closed
            ) {
                return Err(refused("return unavailable"));
            }
            let result = (
                record.return_seal.ok_or_else(|| refused("return seal"))?,
                record
                    .return_artifact
                    .ok_or_else(|| refused("return artifact"))?,
            );
            Ok((tx, result))
        })
    }
    pub fn admit_confined_return(
        &self,
        actor: &AuthenticatedRecoveryActor,
        input: ConfinedReturnAdmissionInput<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ReturnAdmissionV1, AdmissionOperationStoreError> {
        let ConfinedReturnAdmissionInput {
            request,
            seal,
            parent,
            disclosure,
            endorsement,
        } = input;
        if actor.permission() != RecoveryPermission::ConfinedReturn {
            return Err(refused("return authority"));
        }
        super::super::require_finite_recipient(parent)?;
        mutate(self, actor, fence, now, |tx, profile, now| {
            let native_source_origin = self
                .serving_owner
                .prepare_native_source_transaction(&tx)
                .map_err(map_owner_error)?;
            let parent_source = require_parent_source_audience(&tx, actor, profile)?;
            let mut record = record(&tx, actor.scope(), request)?;
            let input = require_input_source_audience(
                &tx,
                actor,
                parent_source,
                &record.reservation.boundary,
            )?;
            require_child_source_audience(&tx, actor, profile, &record, input)?;
            validate_current(&tx, &record, profile, now)?;
            if record.return_seal.as_ref() != Some(seal)
                || *parent != record.installation.contract.parent
                || !profile
                    .recipients
                    .as_slice()
                    .iter()
                    .any(|r| r.recipient == *parent)
                || !matches!(
                    record.reservation.state,
                    IsolationStateV1::ReturnStaged
                        | IsolationStateV1::ReturnAdmitted
                        | IsolationStateV1::Closed
                )
            {
                return Err(refused("exact return recipient"));
            }
            let authority = capability_digest(actor.capability())?;
            if let Some(prior) = record.return_admission {
                if record.return_authority != Some(authority) {
                    return Err(refused("redelivery authority changed"));
                }
                traversal::ensure_audience(&tx, actor, &prior.admitted.admitted_label)?;
                return Ok((tx, prior));
            }
            let m = metadata(&record)?;
            let source = source(
                &tx,
                &profile.native_authority,
                &record.reservation.child_context,
            )?;
            let rows = traversal::dependencies(&tx, actor.scope(), m.dependencies.as_slice())?;
            let influence = traversal::influence(
                &tx,
                &profile.native_authority,
                &record.reservation.child_context,
                &rows,
                false,
            )?;
            if source != m.label || influence != m.influence || m.influence.unknown {
                return Err(refused("stale child basis"));
            }
            // Execution is already staged. Its launch deadline cannot retire
            // the retained result or replace current RETURN approval checks.
            let target = &record.installation.contract.target;
            traversal::ensure_audience(&tx, actor, target)?;
            let mut disclosure_id = None;
            let mut endorsement_id = None;
            if !source.flows_to(target) {
                let signed = disclosure.ok_or_else(|| refused("disclosure required"))?;
                if signed.authority_key() != &record.installation.disclosure_root
                    || !signed.verify_signature().map_err(refused)?
                {
                    return Err(refused("disclosure root"));
                }
                check_evidence(&record, signed.body(), now)?;
                spend(
                    &tx,
                    &self.serving_owner,
                    actor.scope(),
                    "disclosure",
                    signed.authority_key(),
                    signed.body(),
                )?;
                disclosure_id = Some(signed.body().evidence.clone());
            }
            if record.installation.contract.require_integrity {
                let signed = endorsement.ok_or_else(|| refused("endorsement required"))?;
                if signed.authority_key() != &record.installation.endorsement_root
                    || !signed.verify_signature().map_err(refused)?
                {
                    return Err(refused("endorsement root"));
                }
                check_evidence(&record, signed.body(), now)?;
                spend(
                    &tx,
                    &self.serving_owner,
                    actor.scope(),
                    "endorsement",
                    signed.authority_key(),
                    signed.body(),
                )?;
                endorsement_id = Some(signed.body().evidence.clone());
            }
            let release = ArtifactReleaseIntentV1 {
                domain_version: VersionV1,
                release: ReleaseId::new(&uuid::Uuid::new_v4().to_string()).map_err(refused)?,
                kind: ArtifactReleaseKindV1::IndependentlyAdmitted {
                    request: request.clone(),
                },
                artifact: artifact_version_reference(m).map_err(refused)?,
                source_label: target.clone(),
                admitted_label: target.clone(),
                influence: m.influence.clone(),
                recipient: parent.clone(),
                policy: profile.policy,
                // Confined release identity is the complete signed capability,
                // not the ordinary read-authority preimage used by other releases.
                authorization: ReleaseAuthorizationDigest::from_bytes(*authority.as_bytes()),
                observation_transition: EvidenceRef::new(&format!(
                    "confined-return:{}",
                    record.reservation.boundary.boundary.as_str()
                ))
                .map_err(refused)?,
                observation_generation: SafeInteger::new(0).map_err(refused)?,
                state: ArtifactDeliveryStateV1::Admitted,
            };
            let context = profile
                .recipients
                .as_slice()
                .iter()
                .find(|r| r.recipient == *parent)
                .ok_or_else(|| refused("recipient context"))?
                .context
                .clone();
            let (tx, release) =
                super::super::super::security_participant_state::knowledge::join_with_origin(
                    tx,
                    &self.serving_owner,
                    &native_source_origin,
                    super::super::super::security_participant_state::knowledge::KnowledgeJoin {
                        binding: &profile.native_authority,
                        key: &recovery_flow_key(&context),
                        source: target,
                        scope: actor.scope(),
                        release,
                        now,
                    },
                )?;
            let admission = ReturnAdmissionV1 {
                domain_version: VersionV1,
                boundary: record.reservation.boundary.boundary.clone(),
                child: record.reservation.boundary.child.clone(),
                launch: record.launch.ok_or_else(|| refused("launch"))?,
                artifact: record
                    .return_artifact
                    .clone()
                    .ok_or_else(|| refused("artifact"))?,
                contract: record.installation.contract.contract,
                observed_source: source,
                admitted: release,
                disclosure: disclosure_id,
                endorsement: endorsement_id,
            };
            let later = schema::authority_validation_time(&tx, now)?;
            for signed in disclosure
                .map(|s| s.body())
                .into_iter()
                .chain(endorsement.map(|s| s.body()))
            {
                check_evidence(&record, signed, later)?;
            }
            record.return_admission = Some(admission.clone());
            record.return_authority = Some(authority);
            record.reservation.state = IsolationStateV1::ReturnAdmitted;
            record.return_origin = Some(original_admission::capture(&tx, actor, &record)?);
            retain(&tx, &self.serving_owner, &record)?;
            original_admission::verify_source(&tx, &record)?;
            Ok((tx, admission))
        })
    }
    pub fn acknowledge_confined_return(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        admission: &ReturnAdmissionV1,
        delivered: bool,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ArtifactDeliveryStateV1, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::ConfinedReturn {
            return Err(refused("return acknowledgement"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        if actor.scope().authority_domain.as_str() != fence.store_uuid {
            return Err(refused("return acknowledgement authority"));
        }
        let mut record = record(&tx, actor.scope(), request)?;
        original_admission::verify_actor_and_admission(&tx, &record, actor, admission)?;
        let prior = record
            .return_admission
            .as_mut()
            .ok_or_else(|| refused("return admission"))?;
        let next = if delivered {
            ArtifactDeliveryStateV1::Delivered
        } else {
            ArtifactDeliveryStateV1::Uncertain
        };
        // The two fate transitions are monotone and exact retries add no event.
        // This logical packet keeps ordinary storage checks. Dedicated full
        // family financing is installed separately before its acceptance.
        if prior.admitted.state != ArtifactDeliveryStateV1::Delivered
            && prior.admitted.state != next
        {
            prior.admitted.state = next;
            if delivered && !record.stop_requested {
                record.reservation.state = IsolationStateV1::Closed;
            }
            retain(&tx, &self.serving_owner, &record)?;
        }
        let acknowledged = record
            .return_admission
            .as_ref()
            .ok_or_else(|| refused("return admission"))?
            .admitted
            .state
            .clone();
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(acknowledged)
    }
}
