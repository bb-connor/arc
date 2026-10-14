//! Ephemeral archive admission and replay share the ordinary release owner.
use super::*;

/// Validate replay identity without requiring live publication sources.
fn ensure_retained_release_identity(
    record: &ReleaseRecord,
    handle: &ArtifactHandleV1,
    recipient: &ArtifactRecipientV1,
    profile: &NativeKnowledgeInstallationV1,
    digest: &ReleaseAuthorizationDigest,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(record.purpose, ReleasePurpose::RetainedArchiveFrame { .. }) {
        return Err(refused("retained archive release purpose"));
    }
    if record.handle != *handle
        || record.intent.recipient != *recipient
        || record.intent.recipient
            != selected(profile, &record.intent.recipient.recipient)?.recipient
        || record.intent.policy != profile.policy
        || record.capability != *digest
    {
        return Err(refused("retained archive release identity changed"));
    }
    Ok(())
}

impl SqliteAdmissionOperationStore {
    /// Fresh storage admin admits one retained-archive release of an ended
    /// owner. The archive frame is ephemeral: the host passes the exact
    /// in-memory manifest and bytes, and this writer recomputes the frame
    /// binding against the current scoped root, the original DAG sources and
    /// their genuine Process seals, the archive signing root and the fresh
    /// actor, audience and authorization before the native knowledge
    /// observation joins. No second frame copy is persisted anywhere: the
    /// standard source custody and release lifetime carry the export, and
    /// the release record commits the exact frame content digest, byte
    /// count and the bounded originally signed manifest so a replay must
    /// reproduce the same frame without a second signing call. After the
    /// fresh profile, admin, recipient, handle and authorization checks,
    /// a prior record for this exact request decides before any live
    /// source or fresh frame check: a Delivered prior is terminal proof
    /// and returns its original intent, while an unsettled prior must
    /// still reproduce the exact current sources and frame.
    pub fn admit_retained_archive(
        &self,
        actor: &AuthenticatedRecoveryActor,
        preparation: &super::retained_archive::NativeRetainedArchivePreparation,
        handle: &ArtifactHandleV1,
        frame: super::retained_archive::NativeRetainedArchiveInput<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ArtifactReleaseIntentV1, AdmissionOperationStoreError> {
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            if protected::encode(&preparation.profile())? != protected::encode(profile)? {
                return Err(refused("retained archive installation changed"));
            }
            let digest = authority_digest(actor)?;
            if preparation.authorization() != &digest {
                return Err(refused("retained archive authorization changed"));
            }
            let selection = selected(profile, &preparation.recipient().recipient.recipient)?;
            require_finite_recipient(&selection.recipient)?;
            if selection.recipient != preparation.recipient().recipient {
                return Err(refused("retained archive recipient changed"));
            }
            // Terminal replay uses its retained proof; pending delivery still
            // requires the original sources and exact frame below.
            let prior = match release_for_actor(&tx, actor, preparation.request())? {
                Some((_, prior)) => {
                    ensure_retained_release_identity(
                        &prior,
                        handle,
                        &selection.recipient,
                        profile,
                        &digest,
                    )?;
                    if prior.intent.artifact != *preparation.root() {
                        return Err(refused("retained archive root handle changed"));
                    }
                    traversal::ensure_audience(&tx, actor, &prior.intent.source_label)?;
                    if prior.intent.state == ArtifactDeliveryStateV1::Delivered {
                        return Ok((tx, prior.intent));
                    }
                    Some(prior)
                }
                None => None,
            };
            let root =
                retained_archive_root(&tx, actor, handle, &preparation.recipient().recipient)?;
            if root != *preparation.root() {
                return Err(refused("retained archive root handle changed"));
            }
            let records = traversal::dependencies(&tx, actor.scope(), std::slice::from_ref(&root))?;
            super::retained_archive::require_current_sources(&records, profile)?;
            let versions = records
                .iter()
                .map(|record| record.metadata.clone())
                .collect::<Vec<_>>();
            let frame_digest = super::retained_archive::validate_frame(
                &profile.archive_root,
                &profile.scope,
                &root,
                &versions,
                &frame,
            )?;
            let frame_bytes = SafeInteger::new(u64::try_from(frame.bytes.len()).map_err(refused)?)
                .map_err(refused)?;
            let label = traversal::join_metadata(InformationLabel::bottom(), &records)?;
            traversal::ensure_audience(&tx, actor, &label)?;
            if !label.flows_to(&selection.recipient.clearance) {
                return Err(refused("retained archive audience"));
            }
            if let Some(prior) = prior {
                if !matches!(
                    &prior.purpose,
                    ReleasePurpose::RetainedArchiveFrame { content, bytes, manifest }
                        if *content == frame_digest
                            && *bytes == frame_bytes
                            && manifest.as_ref() == frame.manifest
                ) {
                    return Err(refused("retained archive release identity changed"));
                }
                // A replay returns the original admitted transition after fresh
                // authority, source and frame reproduction checks; it cannot
                // mint another join.
                return Ok((tx, prior.intent));
            }
            let release = ReleaseId::new(&uuid::Uuid::new_v4().to_string()).map_err(refused)?;
            let intent = ArtifactReleaseIntentV1 {
                domain_version: VersionV1,
                release: release.clone(),
                kind: ArtifactReleaseKindV1::IndependentlyAdmitted {
                    request: preparation.request().clone(),
                },
                artifact: root,
                influence: traversal::influence(
                    &tx,
                    &profile.native_authority,
                    &selection.context,
                    &records,
                    false,
                )?,
                source_label: label.clone(),
                admitted_label: label.clone(),
                recipient: selection.recipient.clone(),
                policy: profile.policy,
                authorization: digest,
                observation_transition: EvidenceRef::new(&format!(
                    "knowledge:{}",
                    release.as_str()
                ))
                .map_err(refused)?,
                observation_generation: SafeInteger::new(0).map_err(refused)?,
                state: ArtifactDeliveryStateV1::Admitted,
            };
            let (tx, intent) = super::super::security_participant_state::knowledge::join(
                tx,
                &self.serving_owner,
                super::super::security_participant_state::knowledge::KnowledgeJoin {
                    binding: &profile.native_authority,
                    key: &recovery_flow_key(&selection.context),
                    source: &label,
                    scope: actor.scope(),
                    release: intent,
                    now,
                },
            )?;
            let retained = ReleaseRecord {
                intent: intent.clone(),
                handle: handle.clone(),
                capability: digest,
                purpose: ReleasePurpose::RetainedArchiveFrame {
                    content: frame_digest,
                    bytes: frame_bytes,
                    manifest: Box::new(frame.manifest.clone()),
                },
            };
            let key = release_key(actor, preparation.request())?;
            let admission =
                super::super::intake::AuthenticatedKnowledgeIntakeSource::release_admission(
                    &tx,
                    actor,
                    profile,
                    now,
                    preparation.request(),
                    &retained,
                )?;
            protected::persist_knowledge_intake(&tx, &self.serving_owner, admission)?;
            super::reference_custody::retain_release_references(&tx, &self.serving_owner, &key)?;
            Ok((tx, intent))
        })
    }

    /// Retained-archive acknowledgement reuses the exact release ownership:
    /// identity is stable per actor request, an uncertain acknowledgement
    /// retains the release identity for a stable replay, and Delivered is
    /// sticky and retires the retained source pins.
    pub fn acknowledge_retained_archive_delivery(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        intent: &ArtifactReleaseIntentV1,
        delivered: bool,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        mutate_retained_admin(self, actor, fence, now, |tx, profile, now| {
            transition_delivery_state(
                &tx,
                &self.serving_owner,
                profile,
                actor,
                fence,
                request,
                intent,
                delivered,
                now,
            )?;
            Ok((tx, ()))
        })
    }

    /// Stable outcome of a retained-archive request that already reached
    /// Delivered. The early replay read reuses the release ownership: fresh
    /// admin authority, the current installation, the exact original handle
    /// binding, the current selected recipient and the fresh authorization
    /// are all revalidated, then the original delivered intent returns
    /// without a new join, without re-staging any frame and without
    /// re-delivering terminal bytes. Collected original sources are not
    /// required: the delivered record itself is the terminal proof.
    pub fn delivered_retained_release(
        &self,
        actor: &AuthenticatedRecoveryActor,
        request: &RequestId,
        handle: &ArtifactHandleV1,
        recipient: &ArtifactRecipientV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<ArtifactReleaseIntentV1>, AdmissionOperationStoreError> {
        if actor.permission() != RecoveryPermission::KnowledgeAdmin {
            return Err(refused("retained storage authority"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let recovery = protected::deployment_tx(&tx, actor.scope())?;
        super::super::recovery::verify_actor(&tx, actor, &recovery, now)?;
        let profile = installation(&tx, actor.scope())?;
        validate_installation(&tx, &recovery, &profile)?;
        let Some((_, record)) = release_for_actor(&tx, actor, request)? else {
            return Ok(None);
        };
        ensure_retained_release_identity(
            &record,
            handle,
            recipient,
            &profile,
            &authority_digest(actor)?,
        )?;
        traversal::ensure_audience(&tx, actor, &record.intent.source_label)?;
        let delivered = record.intent.state == ArtifactDeliveryStateV1::Delivered;
        tx.commit().map_err(sqlite_error)?;
        Ok(delivered.then_some(record.intent))
    }
}
