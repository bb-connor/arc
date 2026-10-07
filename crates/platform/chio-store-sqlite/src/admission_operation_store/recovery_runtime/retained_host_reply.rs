//! Exact retained host artifacts are replies under current read authority.
//! This opaque role grants no issue, signing, process debit or native admission.
use super::*;
use chio_core_types::recovery::{RecoveryGrantBodyV2, SignedRecoveryGrantV2};
use std::ops::Deref;

pub(super) enum RetainedHostReplyRequest<'input> {
    Review,
    Materialization(&'input ActionIntentV1),
    Reservation(&'input RecoveryProcessReservationV1),
    Issuance(&'input RecoveryGrantBodyV2),
    Signature(&'input SignedRecoveryGrantV2),
    Envelope {
        envelope: &'input FinalizedRequestEnvelopeV1,
        identity: &'input RecoveryNativeIdentity,
    },
}

#[derive(Clone, Copy)]
enum HostReplyPurpose {
    Review,
    Materialization,
    Reservation,
    Issuance,
    Signature,
    Envelope,
}

/// Owned DATA emitted only after the same readonly snapshot consumes the role.
/// It is not another host command, actor, executable envelope or dispatch grant.
pub(super) enum RetainedHostReplyData {
    Review(Box<ApprovalIntentV1>),
    Materialization(Box<RecoveryWorkflowRecordV1>),
    Reservation,
    Issuance(Box<RecoveryGrantBodyV2>),
    Signature,
    Envelope,
}

/// Only a current actor, exact physical source and matching retained artifact
/// can mint this nonserialized role. It cannot turn a historical reply into a
/// current original owner or executable Prepared/envelope/capture permission.
pub(super) struct VerifiedRetainedHostReply<'authority, 'tx, 'conn> {
    tx: &'tx Transaction<'conn>,
    owner: &'authority SqliteServingOwner,
    actor: &'authority AuthenticatedRecoveryActor,
    profile: &'authority RecoveryDeploymentV1,
    now: u64,
    source: ProtectedSourceReference,
    purpose: HostReplyPurpose,
}

fn require_permission(
    actor: &AuthenticatedRecoveryActor,
    purpose: HostReplyPurpose,
) -> Result<(), AdmissionOperationStoreError> {
    let valid = match purpose {
        HostReplyPurpose::Review => actor.permission() == RecoveryPermission::Approve,
        HostReplyPurpose::Materialization | HostReplyPurpose::Reservation => matches!(
            actor.permission(),
            RecoveryPermission::Create | RecoveryPermission::Select | RecoveryPermission::Resume,
        ),
        HostReplyPurpose::Issuance | HostReplyPurpose::Signature => matches!(
            actor.permission(),
            RecoveryPermission::Approve | RecoveryPermission::Resume,
        ),
        HostReplyPurpose::Envelope => actor.permission() == RecoveryPermission::Resume,
    };
    if !valid {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    Ok(())
}

fn current_source(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    record: &RecoveryWorkflowRecordV1,
    now: u64,
) -> Result<ProtectedSourceReference, AdmissionOperationStoreError> {
    verify_actor(tx, actor, profile, now)?;
    if encode(&deployment_tx(tx, actor.scope())?)? != encode(profile)? {
        return Err(invariant(
            "retained host reply requires the actual current deployment",
        ));
    }
    verify_status(actor, profile, record)?;
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let row = raw_checked(tx, &key)?
        .ok_or_else(|| invariant("retained host reply lost its physical workflow"))?;
    let source = source_reference(tx, &key)?;
    if row.kind != "workflow"
        || row.scope != scope_key(&record.scope)?
        || row.version != record.revision.get()
        || source.kind() != "workflow"
        || source.version() != row.version
        || source.scope_key() != row.scope
        || row.payload != encode(record)?
    {
        return Err(invariant(
            "retained host reply requires exact physical source bytes",
        ));
    }
    Ok(source)
}

/// The owning canonical preview joins the current inherited labels and the
/// retained original flow before applying the freshly authorized clearance.
/// Matching its physical bytes binds that audience decision to this source.
pub(super) fn require_current_preview(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    physical: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let preview = Box::new(workflow_preview_tx(
        tx,
        actor,
        profile,
        &physical.workflow_id,
    )?);
    if encode(&preview)? != encode(physical)? {
        return Err(invariant("retained host audience changed physical source"));
    }
    Ok(())
}

/// Missing artifact is returned only as a private fresh-path selection. It
/// never authorizes a fresh write. Every caller then runs its existing active,
/// original-owner, time, basis, issuer, capture and resource checks.
pub(super) fn authenticate_retained_host_reply<'authority, 'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &'authority SqliteServingOwner,
    actor: &'authority AuthenticatedRecoveryActor,
    profile: &'authority RecoveryDeploymentV1,
    now: u64,
    record: &RecoveryWorkflowRecordV1,
    request: RetainedHostReplyRequest<'_>,
) -> Result<Option<VerifiedRetainedHostReply<'authority, 'tx, 'conn>>, AdmissionOperationStoreError>
{
    schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    let purpose = match &request {
        RetainedHostReplyRequest::Review => HostReplyPurpose::Review,
        RetainedHostReplyRequest::Materialization(_) => HostReplyPurpose::Materialization,
        RetainedHostReplyRequest::Reservation(_) => HostReplyPurpose::Reservation,
        RetainedHostReplyRequest::Issuance(_) => HostReplyPurpose::Issuance,
        RetainedHostReplyRequest::Signature(_) => HostReplyPurpose::Signature,
        RetainedHostReplyRequest::Envelope { .. } => HostReplyPurpose::Envelope,
    };
    require_permission(actor, purpose)?;
    let source = current_source(tx, actor, profile, record, now)?;
    // A fresh first Action gets its source from the owning observation and
    // verifies that materialized audience before persistence. A retained
    // Action is always checked before any artifact comparison or reply.
    if record.action.is_some() {
        require_current_preview(tx, actor, profile, record)?;
    }
    let matches = match request {
        // Review preparation has always returned its retained original review
        // before interpreting a newly drafted request. It issues no new review.
        RetainedHostReplyRequest::Review => {
            if record.review.is_none() {
                return Ok(None);
            }
            true
        }
        RetainedHostReplyRequest::Materialization(action) => {
            let Some(existing) = &record.action else {
                return Ok(None);
            };
            encode(existing)? == encode(action)?
        }
        RetainedHostReplyRequest::Reservation(reservation) => {
            let Some(existing) = &record.process_reservation else {
                return Ok(None);
            };
            existing.as_str().as_bytes() == encode(reservation)?.as_slice()
        }
        RetainedHostReplyRequest::Issuance(body) => {
            let Some(existing) = &record.issuance else {
                return Ok(None);
            };
            existing == body
        }
        RetainedHostReplyRequest::Signature(grant) => {
            let Some(existing) = &record.signed_grant else {
                return Ok(None);
            };
            if existing != grant || record.issuance.as_ref() != Some(grant.body()) {
                false
            } else {
                grant
                    .verify_signature()
                    .map_err(|_| invariant("retained host signature is invalid"))?
            }
        }
        RetainedHostReplyRequest::Envelope { envelope, identity } => {
            let Some(existing) = &record.envelope else {
                return Ok(None);
            };
            encode(existing)? == encode(envelope)?
                && record.admission.as_ref().is_some_and(|intent| {
                    intent.native_binding == identity.binding().to_persisted()
                })
        }
    };
    if !matches {
        return Err(invariant(
            "retained host artifact conflicts with its exact source",
        ));
    }
    require_current_preview(tx, actor, profile, record)?;
    Ok(Some(VerifiedRetainedHostReply {
        tx,
        owner,
        actor,
        profile,
        now,
        source,
        purpose,
    }))
}

impl VerifiedRetainedHostReply<'_, '_, '_> {
    pub(super) fn verify_current(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.tx), Deref::deref(tx)) {
            return Err(invariant(
                "retained host reply changed its actual transaction",
            ));
        }
        schema::verify_active_owner(tx, self.owner, Some(&self.owner.fence))?;
        require_permission(self.actor, self.purpose)?;
        verify_source_reference(tx, &self.source)?;
        let row = raw_checked(tx, self.source.record_key())?
            .ok_or_else(|| invariant("retained host reply physical source disappeared"))?;
        let record: Box<RecoveryWorkflowRecordV1> = decode(&row.payload)?;
        let current = current_source(tx, self.actor, self.profile, &record, self.now)?;
        if current.record_key() != self.source.record_key()
            || current.scope_key() != self.source.scope_key()
            || current.kind() != self.source.kind()
            || current.version() != self.source.version()
            || current.digest() != self.source.digest()
            || current.event_sequence() != self.source.event_sequence()
            || current.global_commit_sequence() != self.source.global_commit_sequence()
        {
            return Err(invariant("retained host reply current source changed"));
        }
        require_current_preview(tx, self.actor, self.profile, &record)?;
        Ok(())
    }
}

impl SqliteAdmissionOperationStore {
    /// Exact retained replies need a current authenticated readonly snapshot,
    /// not a fresh intake/resource allocation. An absent artifact still enters
    /// the ordinary fenced writer and rechecks its closed source there.
    pub(super) fn read_retained_host_reply(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        request: RetainedHostReplyRequest<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<Option<RetainedHostReplyData>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        schema::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let profile = deployment_tx(&tx, actor.scope())?;
        verify_actor(&tx, actor, &profile, now)?;
        let record: Box<RecoveryWorkflowRecordV1> = Box::new(
            workflow_tx(&tx, actor.scope(), workflow).map_err(|error| match error {
                AdmissionOperationStoreError::NotFound => {
                    AdmissionOperationStoreError::RecoveryAuthorityDenied
                }
                error => error,
            })?,
        );
        historical_holds::require_unheld(&tx, &record)?;
        let data = if let Some(reply) = authenticate_retained_host_reply(
            &tx,
            &self.serving_owner,
            actor,
            &profile,
            now,
            &record,
            request,
        )? {
            reply.verify_current(&tx)?;
            Some(match reply.purpose {
                HostReplyPurpose::Review => RetainedHostReplyData::Review(Box::new(
                    record
                        .review
                        .ok_or_else(|| invariant("retained review disappeared"))?,
                )),
                HostReplyPurpose::Materialization => RetainedHostReplyData::Materialization(record),
                HostReplyPurpose::Reservation => RetainedHostReplyData::Reservation,
                HostReplyPurpose::Issuance => RetainedHostReplyData::Issuance(Box::new(
                    record
                        .issuance
                        .ok_or_else(|| invariant("retained issuance disappeared"))?,
                )),
                HostReplyPurpose::Signature => RetainedHostReplyData::Signature,
                HostReplyPurpose::Envelope => RetainedHostReplyData::Envelope,
            })
        } else {
            None
        };
        tx.commit().map_err(sqlite_error)?;
        Ok(data)
    }
}
