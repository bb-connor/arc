//! An admitted release proves its own next finite delivery outcome.
use super::encoding::{canonical, ORIGINAL_RELEASE_VERSION};
use super::*;
use crate::admission_operation_store::knowledge::encoding::chunks::EncodingOwner;
use crate::admission_operation_store::knowledge::encoding::write::EncodingAdmission;
use std::ops::Deref;

/// Only the actual release owner can mint this affine source. It has no Clone,
/// Deserialize, caller-selected purpose, independent writer or credit. Every
/// outcome it proves advances an already admitted release record.
pub(in crate::admission_operation_store) struct AuthenticatedReleaseOutcomeEncodingSource<
    'tx,
    'conn,
> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    profile: &'tx NativeKnowledgeInstallationV1,
    fence: &'tx StoreMutationFence,
    now: u64,
    key: String,
    current_root: protected::ProtectedSourceReference,
    handle: protected::ProtectedSourceReference,
    next: ReleaseRecord,
}

/// The actor's own admitted release and its next finite delivery state, under
/// the exact original purpose, permission, capability, handle and recipient.
/// An ordinary artifact release keeps its execution readiness requirement. A
/// repeat or any outcome after Delivered has no pending write.
#[allow(clippy::too_many_arguments)]
pub(super) fn prepare_release_outcome<'tx, 'conn>(
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    profile: &'tx NativeKnowledgeInstallationV1,
    fence: &'tx StoreMutationFence,
    now: u64,
    request: &RequestId,
    intent: &ArtifactReleaseIntentV1,
    delivered: bool,
) -> Result<
    Option<AuthenticatedReleaseOutcomeEncodingSource<'tx, 'conn>>,
    AdmissionOperationStoreError,
> {
    let (key, current_root, record) = release_root_for_actor(transaction, actor, request)?
        .ok_or_else(|| refused("release absent"))?;
    let handle_key = authorize_outcome(transaction, actor, profile, fence, &record)?;
    let mut admitted = record.intent.clone();
    admitted.state = intent.state;
    if admitted != *intent {
        return Err(refused("release ack changed"));
    }
    let next_state = if delivered {
        ArtifactDeliveryStateV1::Delivered
    } else {
        ArtifactDeliveryStateV1::Uncertain
    };
    if !forward(record.intent.state, next_state) {
        return Ok(None);
    }
    let mut next = record;
    next.intent.state = next_state;
    let source = AuthenticatedReleaseOutcomeEncodingSource {
        transaction,
        actor,
        profile,
        fence,
        now,
        key,
        current_root,
        handle: protected::source_reference(transaction, &handle_key)?,
        next,
    };
    source.verify(transaction)?;
    Ok(Some(source))
}

/// Admitted to Uncertain or Delivered, and Uncertain to Delivered only.
fn forward(current: ArtifactDeliveryStateV1, next: ArtifactDeliveryStateV1) -> bool {
    matches!(
        (current, next),
        (
            ArtifactDeliveryStateV1::Admitted,
            ArtifactDeliveryStateV1::Uncertain | ArtifactDeliveryStateV1::Delivered
        ) | (
            ArtifactDeliveryStateV1::Uncertain,
            ArtifactDeliveryStateV1::Delivered
        )
    )
}

/// The existing release acknowledgement authority: purpose and permission,
/// readiness for an artifact release, original capability, handle principal
/// and current recipient selection. Returns the bound handle key.
fn authorize_outcome(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &NativeKnowledgeInstallationV1,
    fence: &StoreMutationFence,
    record: &ReleaseRecord,
) -> Result<String, AdmissionOperationStoreError> {
    if !matches!(
        (&record.purpose, actor.permission()),
        (ReleasePurpose::Artifact, RecoveryPermission::KnowledgeRead)
            | (
                ReleasePurpose::RetainedArchiveFrame { .. },
                RecoveryPermission::KnowledgeAdmin
            )
    ) {
        return Err(refused("release acknowledgement purpose"));
    }
    if record.purpose == ReleasePurpose::Artifact {
        super::super::super::setup::require_ready(tx, actor.scope(), fence)?;
    }
    let handle_key = handle_key(actor.scope(), &record.handle.handle)?;
    let handle = super::load_handle(tx, actor.scope(), &record.handle.handle)?;
    if record.capability != authority_digest(actor)?
        || handle.principal != *actor.principal()
        || record.intent.recipient
            != selected(profile, &record.intent.recipient.recipient)?.recipient
    {
        return Err(refused("release ack changed"));
    }
    Ok(handle_key)
}

impl<'tx, 'conn> AuthenticatedReleaseOutcomeEncodingSource<'tx, 'conn> {
    /// Recheck the same writer, current actor, installation and fence, the
    /// unchanged release root and handle heads, the strict forward transition
    /// from the actual current record, and the exact original admission bytes.
    pub(in crate::admission_operation_store) fn verify(
        &self,
        transaction: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(transaction)) {
            return Err(refused("release outcome changed its physical writer"));
        }
        let now = schema::authority_validation_time(transaction, self.now)?;
        let deployment = protected::deployment_tx(transaction, self.actor.scope())?;
        super::super::super::recovery::verify_actor(transaction, self.actor, &deployment, now)?;
        let current = installation(transaction, self.actor.scope())?;
        validate_installation(transaction, &deployment, &current)?;
        if protected::encode(&current)? != protected::encode(self.profile)? {
            return Err(refused("release outcome lost its current installation"));
        }
        protected::verify_source_reference(transaction, &self.current_root)?;
        protected::verify_source_reference(transaction, &self.handle)?;
        let (root, previous) = load_release_record(transaction, &self.key)?
            .ok_or_else(|| refused("release outcome lost its admitted record"))?;
        let handle_key =
            authorize_outcome(transaction, self.actor, self.profile, self.fence, &previous)?;
        let mut unchanged = previous.clone();
        unchanged.intent.state = self.next.intent.state;
        if root.record_key() != self.current_root.record_key()
            || root.version() != self.current_root.version()
            || handle_key != self.handle.record_key()
            || !forward(previous.intent.state, self.next.intent.state)
            || canonical(&unchanged)? != canonical(&self.next)?
        {
            return Err(refused("release outcome changed its monotone custody"));
        }
        let mut original = self.next.clone();
        original.intent.state = ArtifactDeliveryStateV1::Admitted;
        if !protected::matches_historical_source_command_payload(
            transaction,
            &self.current_root,
            ORIGINAL_RELEASE_VERSION,
            &protected::encode(&original)?,
        )? {
            return Err(refused("release outcome changed its original admission"));
        }
        Ok(())
    }

    /// The complete intended record; the shared writer frames it inline when
    /// it fits one row and as fresh immutable chunks otherwise.
    pub(in crate::admission_operation_store) fn verify_stored_body(
        &self,
        body: &[u8],
    ) -> Result<(), AdmissionOperationStoreError> {
        if canonical(&self.next)? != body {
            return Err(refused("release outcome changed its exact record"));
        }
        Ok(())
    }
    pub(in crate::admission_operation_store) fn body(
        &self,
    ) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        canonical(&self.next)
    }
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.transaction
    }
    pub(in crate::admission_operation_store) fn owner(&self) -> EncodingOwner {
        EncodingOwner::Release {
            scope: self.actor.scope().clone(),
            record_key: self.key.clone(),
            release: self.next.intent.release.clone(),
        }
    }
    pub(in crate::admission_operation_store) fn expected_root(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        Some(&self.current_root)
    }
    pub(in crate::admission_operation_store) fn original_version(&self) -> u64 {
        ORIGINAL_RELEASE_VERSION
    }
    /// Every release outcome advances an already admitted record.
    pub(in crate::admission_operation_store) fn admission(&self) -> EncodingAdmission {
        EncodingAdmission::AdmittedOutcome
    }
    pub(super) fn delivers(&self) -> bool {
        self.next.intent.state == ArtifactDeliveryStateV1::Delivered
    }
    pub(super) fn key(&self) -> &str {
        &self.key
    }
}
