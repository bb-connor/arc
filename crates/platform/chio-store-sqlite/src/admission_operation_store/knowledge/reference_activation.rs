//! Bounded reference reads require a complete native account activation.
use super::references::{ReferenceBaselineSource, SourceAnchor};
use super::*;
use std::ops::Deref;

/// The real host-selected installation writer owns the fenced transaction.
/// Cold activation authenticates the entire retained account before emitting
/// its first capacity or index row, then consumes exact writer receipts.
pub(super) fn activate_installation_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &NativeKnowledgeInstallationV1,
) -> Result<protected::ProtectedMutationDelta, AdmissionOperationStoreError> {
    let account = super::references::ReferenceAccount::from_scope(&profile.scope);
    if protected::raw_checked(tx, &account.ready_key()?)?.is_some() {
        super::references::ready_reference_account(tx, &profile.scope)?.verify_current(tx)?;
        return Ok(protected::ProtectedMutationDelta::zero());
    }
    let baseline =
        super::reference_census::VerifiedKnowledgeReferenceAccountBaseline::for_installation(
            tx, owner, profile,
        )?;
    let (baseline, receipt, initial) =
        protected::initialize_knowledge_reference_account(tx, owner, baseline)?;
    let mut activation = super::reference_ready::KnowledgeReferenceColdActivation::after_account(
        tx, owner, baseline, receipt,
    )?;
    let baselines = activation.persist_baselines(tx, owner)?;
    let ready = activation.finish(tx, owner)?;
    let (_, final_marker) = protected::persist_knowledge_reference_ready(tx, owner, ready)?;
    initial.checked_add(&baselines)?.checked_add(&final_marker)
}

/// Only the actual metadata writer calls this, after the certificate, complete
/// publication body and exact immutable pointer have committed in this Tx.
pub(super) fn initialize_committed_artifact_references(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &NativeArtifactRecordV1,
) -> Result<protected::ProtectedMutationDelta, AdmissionOperationStoreError> {
    let source = super::reference_baseline::VerifiedNewArtifactReferenceBaseline::new(tx, record)?;
    let plan = super::references::prepare_new_artifact_reference_baseline(tx, source)?;
    let (_, delta) = protected::persist_knowledge_new_artifact_reference_baseline(tx, owner, plan)?;
    Ok(delta)
}

/// Fresh native storage administration authorizes a cold inventory rebuild.
/// This does not retire a source, renew execution, or admit byte disclosure.
pub(in crate::admission_operation_store) struct VerifiedKnowledgeReferenceRebuildAuthority<
    'tx,
    'conn,
> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    installation: NativeKnowledgeInstallationV1,
    reference: ArtifactVersionRefV1,
    publication: protected::ProtectedSourceReference,
    pointer: protected::ProtectedSourceReference,
}

impl<'tx, 'conn> VerifiedKnowledgeReferenceRebuildAuthority<'tx, 'conn> {
    /// Only the same-scope retained Admin writer can call this constructor.
    pub(super) fn new(
        tx: &'tx Transaction<'conn>,
        actor: &'tx AuthenticatedRecoveryActor,
        profile: &NativeKnowledgeInstallationV1,
        reference: &ArtifactVersionRefV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let (_, publication, pointer) = retained_reference_artifact(tx, reference)?;
        let proof = Self {
            transaction: tx,
            actor,
            installation: profile.clone(),
            reference: reference.clone(),
            publication,
            pointer,
        };
        proof.verify(tx)?;
        Ok(proof)
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }

    pub(in crate::admission_operation_store) fn reference(&self) -> &ArtifactVersionRefV1 {
        &self.reference
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(refused("reference rebuild changed physical writer"));
        }
        // A complete census can be slow. Recheck actual trusted authority time
        // after that work rather than reusing the time at its first admission.
        let now = schema::observe_authority_time(tx)?;
        let deployment = protected::deployment_tx(tx, self.actor.scope())?;
        super::super::recovery::verify_actor(tx, self.actor, &deployment, now)?;
        let profile = installation(tx, self.actor.scope())?;
        validate_installation(tx, &deployment, &profile)?;
        if self.actor.permission() != RecoveryPermission::KnowledgeAdmin
            || self.reference.scope != *self.actor.scope()
            || protected::encode(&profile)? != protected::encode(&self.installation)?
        {
            return Err(refused("reference rebuild lost fresh storage authority"));
        }
        protected::verify_source_reference(tx, &self.publication)?;
        protected::verify_source_reference(tx, &self.pointer)?;
        let (record, publication, pointer) = retained_reference_artifact(tx, &self.reference)?;
        if SourceAnchor::capture(&publication) != SourceAnchor::capture(&self.publication)
            || SourceAnchor::capture(&pointer) != SourceAnchor::capture(&self.pointer)
        {
            return Err(refused("reference rebuild changed its retained artifact"));
        }
        traversal::ensure_audience(tx, self.actor, &record.metadata.label)?;
        traversal::ensure_audience(
            tx,
            self.actor,
            &source(tx, &profile.native_authority, &profile.producer_context)?,
        )?;
        verify_reference_ready(tx, &self.reference.scope)
    }
}

/// The enclosing owning read has already authenticated its serving transaction.
/// A missing or historical-only marker is never interpreted as empty custody.
pub(in crate::admission_operation_store) fn verify_reference_ready(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<(), AdmissionOperationStoreError> {
    super::references::ready_reference_account(tx, scope)?.verify_current(tx)
}

/// The immutable first aggregate is separately matched against protected
/// history by the index reader. This verifies its typed source and the exact
/// governed version pointer without rewriting a historical envelope.
pub(in crate::admission_operation_store) fn verify_reference_baseline(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
    baseline: &ReferenceBaselineSource,
) -> Result<(), AdmissionOperationStoreError> {
    let ready = super::references::ready_reference_account(tx, &reference.scope)?;
    let (_, publication, pointer) = retained_reference_artifact(tx, reference)?;
    match baseline {
        ReferenceBaselineSource::NewArtifact { source } => {
            source.validate_ordinary()?;
            source.verify_historical_identity(tx)?;
            if source.record_key() != publication.record_key()
                || source.scope_key() != publication.scope_key()
                || !source.not_after(&SourceAnchor::capture(&publication))
                || source.global_commit_sequence() <= ready.cutoff().sequence()
                || pointer.global_commit_sequence() <= ready.cutoff().sequence()
            {
                return Err(refused(
                    "new reference baseline changed its metadata source",
                ));
            }
        }
        ReferenceBaselineSource::Cold {
            cutoff,
            cohort_digest,
            ..
        } => {
            cutoff.verify(tx)?;
            if cutoff != ready.cutoff()
                || cohort_digest != ready.cohort_digest()
                || pointer.global_commit_sequence() > cutoff.sequence()
            {
                return Err(refused(
                    "cold reference baseline changed its complete cohort",
                ));
            }
        }
    }
    Ok(())
}

fn retained_reference_artifact(
    tx: &Connection,
    reference: &ArtifactVersionRefV1,
) -> Result<
    (
        NativeArtifactRecordV1,
        protected::ProtectedSourceReference,
        protected::ProtectedSourceReference,
    ),
    AdmissionOperationStoreError,
> {
    let key = version_key(reference)?;
    let pointer: String =
        load(tx, &key)?.ok_or_else(|| refused("reference baseline version disappeared"))?;
    let record: NativeArtifactRecordV1 =
        load(tx, &pointer)?.ok_or_else(|| refused("reference baseline publication disappeared"))?;
    record.metadata.validate().map_err(refused)?;
    let publication = protected::source_reference(tx, &pointer)?;
    let version = protected::source_reference(tx, &key)?;
    let scope = scope_key(&reference.scope)?;
    if record_publication_key(&record)? != pointer
        || artifact_version_reference(&record.metadata).map_err(refused)? != *reference
        || publication.kind() != "command"
        || publication.scope_key() != scope
        || version.kind() != "command"
        || version.scope_key() != scope
        || version.version() != 1
        || !protected::matches_historical_command_payload(
            tx,
            &key,
            &scope,
            1,
            &protected::encode(&pointer)?,
        )?
    {
        return Err(refused(
            "reference baseline changed its full governed version",
        ));
    }
    Ok((record, publication, version))
}

impl std::fmt::Debug for VerifiedKnowledgeReferenceRebuildAuthority<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgeReferenceRebuildAuthority([redacted])")
    }
}
