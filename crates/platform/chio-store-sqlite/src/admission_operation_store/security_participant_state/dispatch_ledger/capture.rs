//! Dedicated native capture evidence, valid only in the physical transaction.
use super::*;
use chio_kernel::admission_operation::{
    dpop_claim::DpopReplayCredentialV1, governed_approval_claim::GovernedApprovalCredentialV1,
};

#[cfg(feature = "admission-test-support")]
mod expiry_test_support;

pub(crate) struct NativeCaptureBinding<'a> {
    pub custody: chio_kernel::admission_operation::NativeSecurityEgressContext<'a>,
    pub credentials: &'a chio_kernel::VerifiedNativeDispatchCredentials<'a>,
    pub ledger: &'a NativeSecurityDispatchLedgerRecordV1,
    pub policy_json: &'a [u8],
}

/// Private fields prevent callers from upgrading an egress or ledger digest.
/// The connection borrow prevents use across transactions or owner handles.
pub(crate) struct VerifiedNativeCapture<'tx> {
    connection: &'tx Connection,
    operation: AdmissionOperationV1,
    ledger: AdmissionDigest,
    policy: policy::Policy,
    observed_at: u64,
    lease_expires_at: u64,
    capability_expires_at_secs: u64,
    runtime_valid_until_unix_ms: Option<u64>,
    nonce_valid_until_unix_ms: Option<u64>,
    approval_credential: Option<GovernedApprovalCredentialV1>,
    dpop_credential: Option<DpopReplayCredentialV1>,
}

impl<'tx> VerifiedNativeCapture<'tx> {
    pub(crate) fn verify(
        tx: &'tx Transaction<'_>,
        owner: &SqliteServingOwner,
        input: &NativeCaptureBinding<'_>,
        grant_index: usize,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let custody = &input.custody;
        let operation = custody.operation;
        require_operation(operation)?;
        let now = observed_time(tx, custody.trusted_now_unix_ms)?;
        verify_participant_recovery_tx(tx, owner, operation, custody.lease, now)?;
        ensure_no_reserved_terminal_stage(tx, operation.binding().operation_id())?;
        let original = retained_request::load_retained_request_tx(tx, operation)?
            .ok_or_else(|| invalid("native capture lost its original request"))?;
        input
            .credentials
            .validate_binding(operation, &original, custody.request, grant_index)?;
        let capability = &custody.request.capability;
        if now / 1000 >= capability.expires_at {
            return Err(invalid("native capture capability expired before capture"));
        }
        for id in std::iter::once(capability.id.as_str()).chain(
            capability
                .delegation_chain
                .iter()
                .map(|link| link.capability_id.as_str()),
        ) {
            let revoked: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
                    [id],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            if revoked {
                return Err(invalid("native capture capability or ancestor is revoked"));
            }
        }
        original.validate_native_security_authority(custody.binding)?;
        original.validate_native_security_context(custody.security_context)?;
        storage::verify_coverage(tx)?;
        let record = storage::load(tx, operation.binding().operation_id().as_str())?
            .ok_or_else(|| invalid("native capture requires its exact preparation ledger"))?;
        if record.evidence()? != *input.ledger
            || record.operation != operation.to_persisted()
            || usize::try_from(record.grant_index).ok() != Some(grant_index)
            || record.live_request_digest
                != super::super::egress::live_request_hash(custody.request)?
            || record.context != *custody.security_context
        {
            return Err(invalid("native capture changed its prepared command"));
        }
        record.validate(tx)?;
        storage::verify_reference(tx, &record)?;
        let (value, policy) = policy::decode(input.policy_json)?;
        if value != record.policy {
            return Err(invalid("native capture changed its live policy evidence"));
        }
        policy.validate_live_declassification(custody.request)?;
        policy.validate_owned_declassification(tx, operation, &value)?;
        if policy.inputs.declassification.is_some() {
            let committed = super::super::egress::load_operation(
                tx,
                operation.binding().operation_id(),
                "committed",
            )?
            .ok_or_else(|| invalid("native capture lost declassification custody"))?;
            let crate::security_state::NativeEgressCommand::CommitDeclassified {
                consumption, ..
            } = committed.command
            else {
                return Err(invalid("native capture lost declassification consumption"));
            };
            crate::security_state::verify_native_pending_declassification(
                tx,
                custody.binding.security_authority_id().as_str(),
                &consumption,
            )
            .map_err(invalid)?;
        }
        policy.validate_current(tx, now).map_err(|error| {
            invalid(format!(
                "native capture policy at transaction entry: {error}"
            ))
        })?;
        let runtime = runtime_participant::dispatch_snapshot(tx, operation, grant_index)?;
        let approval = governed_approval_claim::dispatch_snapshot(tx, operation, grant_index)?;
        let dpop = dpop_claim::dispatch_snapshot(tx, operation, grant_index)?;
        // Presence is part of the proof. Absent claims must not pass merely
        // because the usual freshness helpers validate only present claims.
        if runtime.as_ref() != input.credentials.runtime()
            || approval.as_ref().map(|claim| &claim.reference) != input.credentials.approval()
            || dpop.as_ref().map(|claim| &claim.reference) != input.credentials.dpop()
            || runtime != record.runtime
            || approval != record.approval
            || dpop != record.dpop
        {
            return Err(invalid(
                "native capture lacks its complete verified credential set",
            ));
        }
        governed_approval_claim::verify_fresh_approval_tx(tx, operation, now)?;
        dpop_claim::verify_fresh_dpop_tx(tx, operation, now)?;
        let nonce =
            crate::admission_operation_store::execution_nonce::verify_reservation(tx, operation)?;
        if nonce.as_ref().map(|value| value.canonical_bytes())
            != input
                .credentials
                .execution_nonce()
                .map(|value| value.canonical_bytes())
            || nonce.is_some()
                != operation
                    .binding()
                    .participant_requirements()
                    .execution_nonce
        {
            return Err(invalid(
                "native capture nonce differs from its physical reservation",
            ));
        }
        let nonce_valid_until_unix_ms = nonce
            .as_ref()
            .map(|value| {
                value.require_operation_bound_profile()?;
                u64::try_from(value.signed_nonce().expires_at())
                    .ok()
                    .and_then(|seconds| seconds.checked_mul(1000))
                    .filter(|until| now < *until)
                    .ok_or_else(|| {
                        invalid("native capture execution nonce expired or exceeds bounds")
                    })
            })
            .transpose()?;
        let runtime_valid_until_unix_ms = input
            .credentials
            .runtime_validity()
            .map(|validity| {
                validity.validate_at(now)?;
                Ok::<_, AdmissionOperationStoreError>(validity.valid_until_unix_ms())
            })
            .transpose()?;
        Ok(Self {
            connection: tx,
            operation: operation.clone(),
            ledger: record.digest()?,
            policy,
            observed_at: now,
            lease_expires_at: custody.lease.untrusted_claim().expires_at_unix_ms(),
            capability_expires_at_secs: capability.expires_at,
            runtime_valid_until_unix_ms,
            nonce_valid_until_unix_ms,
            approval_credential: approval.map(|claim| claim.intent.credential().clone()),
            dpop_credential: dpop.map(|claim| claim.intent.credential().clone()),
        })
    }

    pub(crate) fn verify_owner(
        &self,
        tx: &Transaction<'_>,
        operation: &AdmissionOperationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq(self.connection, &**tx) || *operation != self.operation {
            return Err(invalid(
                "native capture witness belongs to another transaction or operation",
            ));
        }
        Ok(())
    }

    pub(crate) fn attachment(&self) -> AdmissionAttachment {
        AdmissionAttachment::NativeDispatchLedgerDigest(self.ledger.clone())
    }

    pub(crate) fn verify_caller_context(
        &self,
        tx: &Transaction<'_>,
        frame: &chio_kernel::admission_operation::AdmissionCallerDispatchContextV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_owner(tx, &self.operation)?;
        let original = retained_request::load_retained_request_tx(tx, &self.operation)?
            .ok_or_else(|| invalid("native caller capture lost original request"))?;
        let custody = frame
            .native_release_custody(&self.operation, &original)?
            .ok_or_else(|| invalid("native caller capture lost release custody"))?;
        let ledger = storage::load(tx, self.operation.binding().operation_id().as_str())?
            .ok_or_else(|| invalid("native caller capture lost ledger"))?;
        if custody.ledger_digest() != &self.ledger
            || custody.ledger_bytes() != ledger.bytes()?
            || custody.security_context() != &ledger.context
            || custody.valid_until_unix_ms() <= self.observed_at
        {
            return Err(invalid(
                "native caller release frame differs from physical capture",
            ));
        }
        // An interval ending here must be valid in every original participant,
        // including credential, policy, lease, capability and nonce deadlines.
        self.validate_time(custody.valid_until_unix_ms() - 1)
    }

    pub(crate) fn verify_transition(
        &self,
        tx: &Transaction<'_>,
        expected: &AdmissionOperationV1,
        updated: &AdmissionOperationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.verify_owner(tx, expected)?;
        if updated.state() != AdmissionOperationState::DispatchCommitted
            || updated.native_dispatch_ledger_digest() != Some(&self.ledger)
            || updated.binding() != expected.binding()
            || updated.version()
                != expected
                    .version()
                    .checked_add(1)
                    .ok_or_else(|| invalid("native capture version overflow"))?
        {
            return Err(invalid(
                "native capture witness differs from its committed successor",
            ));
        }
        Ok(())
    }

    pub(crate) fn verify_deadline(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq(self.connection, &**tx) {
            return Err(invalid("native capture witness changed transactions"));
        }
        let now = observed_time(tx, self.observed_at)?;
        self.validate_time(now)?;
        governed_approval_claim::verify_fresh_approval_tx(tx, &self.operation, now)?;
        dpop_claim::verify_fresh_dpop_tx(tx, &self.operation, now)?;
        self.policy.validate_current(tx, now).map_err(|error| {
            invalid(format!(
                "native capture policy before physical commit: {error}"
            ))
        })?;
        #[cfg(feature = "admission-test-support")]
        let delayed = expiry_test_support::wait_after_verification(
            tx,
            self.runtime_valid_until_unix_ms,
            self.nonce_valid_until_unix_ms,
            self.policy
                .inputs
                .declassification
                .as_ref()
                .and_then(|grant| grant.body.expires_at_unix_seconds().checked_mul(1000)),
        )?;
        // State verification can outlive its initial clock sample. The claims
        // above and the captured credentials name the same immutable episodes
        // in this write transaction. Sample again after state verification,
        // followed only by bounded time checks and the physical commit.
        let commit_now = super::super::super::schema::observe_authority_time(tx)?;
        if commit_now < now {
            return Err(invalid("native capture clock regressed before commit"));
        }
        #[cfg(feature = "admission-test-support")]
        {
            expiry_test_support::annotate_rejection(delayed, self.validate_time(commit_now))
        }
        #[cfg(not(feature = "admission-test-support"))]
        {
            self.validate_time(commit_now)
        }
    }

    fn validate_time(&self, now: u64) -> Result<(), AdmissionOperationStoreError> {
        if now >= self.lease_expires_at {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        if now / 1000 >= self.capability_expires_at_secs {
            return Err(invalid("native capture capability expired before commit"));
        }
        if self
            .runtime_valid_until_unix_ms
            .is_some_and(|until| now >= until)
        {
            return Err(invalid(
                "native capture runtime evidence expired before commit",
            ));
        }
        if self
            .nonce_valid_until_unix_ms
            .is_some_and(|until| now >= until)
        {
            return Err(invalid(
                "native capture execution nonce expired before commit",
            ));
        }
        if let Some(credential) = &self.approval_credential {
            credential.validate_at(now)?;
        }
        if let Some(credential) = &self.dpop_credential {
            credential.validate_at(now)?;
        }
        self.policy.validate_at(now).map_err(|error| {
            invalid(format!(
                "native capture policy before physical commit: {error}"
            ))
        })
    }
}

/// Historical attachment validation never rechecks present policy or grants
/// permission. Later terminal states retain the exact original preparation.
pub(in crate::admission_operation_store) fn verify_capture_attachment(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(digest) = operation.native_dispatch_ledger_digest() else {
        return Ok(());
    };
    let record = storage::load(connection, operation.binding().operation_id().as_str())?
        .ok_or_else(|| invalid("native capture attachment lost its preparation ledger"))?;
    let original = AdmissionOperationV1::from_persisted(record.operation.clone())?;
    let committed = operation
        .dispatch_commit()
        .ok_or_else(|| invalid("native capture attachment has no dispatch commitment"))?;
    if record.digest()? != *digest
        || committed.committed_version
            != original
                .version()
                .checked_add(1)
                .ok_or_else(|| invalid("native capture version overflow"))?
    {
        return Err(invalid(
            "native capture attachment differs from its preparation",
        ));
    }
    record.validate(connection)?;
    storage::verify_reference(connection, &record)
}
