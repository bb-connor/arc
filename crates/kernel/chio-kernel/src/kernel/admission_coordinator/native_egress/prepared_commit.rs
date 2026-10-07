//! Fresh event preparation after bounded acquisition reconciliation.
use super::*;
use crate::admission_operation::NativeSecurityDispatchLedgerRecordV1;
use chio_core::receipt::security::ActiveDefenseReceiptBody;
use chio_security_types::ports::{CanonicalBody, DeclassificationConsumptionEvidenceCommit};

/// An original acquisition and lease, prepared for one exact use record.
/// This is neither a capture permit nor historical evidence that can be restored.
///
/// A prepared commit is consumed once:
/// ```compile_fail
/// use chio_kernel::PreparedNativeSecurityEgressCommit;
/// use chio_security_types::ports::DeclassificationConsumptionEvidenceCommit;
/// fn repeat(commit: PreparedNativeSecurityEgressCommit<'_>, evidence: &DeclassificationConsumptionEvidenceCommit) {
///     let _ = commit.retain_for_declassified_capture(0, b"{}", evidence);
///     let _ = commit.retain_for_declassified_capture(0, b"{}", evidence);
/// }
/// ```
/// It cannot be cloned into a second live owner:
/// ```compile_fail
/// use chio_kernel::PreparedNativeSecurityEgressCommit;
/// fn copy(commit: &PreparedNativeSecurityEgressCommit<'_>) {
///     let _: PreparedNativeSecurityEgressCommit<'_> = Clone::clone(commit);
/// }
/// ```
#[must_use]
pub struct PreparedNativeSecurityEgressCommit<'a> {
    acquired: AcquiredNativeSecurityEgress<'a>,
    lease: AdmissionRecoveryLease,
    trusted_now_unix_ms: u64,
}

impl fmt::Debug for PreparedNativeSecurityEgressCommit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedNativeSecurityEgressCommit")
            .finish_non_exhaustive()
    }
}

impl<'a> AcquiredNativeSecurityEgress<'a> {
    /// Finish bounded original-custody checks, then sample the event clock.
    /// No lock remains held while the resolver constructs the pure use evidence.
    pub fn prepare_commit(self) -> Result<PreparedNativeSecurityEgressCommit<'a>, KernelError> {
        let (lease, trusted_now_unix_ms) = self.prepare_commit_context()?;
        Ok(PreparedNativeSecurityEgressCommit {
            acquired: self,
            lease,
            trusted_now_unix_ms,
        })
    }
}

impl<'a> PreparedNativeSecurityEgressCommit<'a> {
    /// Protected original input, never a replacement request or execution grant.
    pub fn request(&self) -> &ToolCallRequest {
        self.acquired.prepared.request
    }

    /// Lower bound for preparing a new event, not renewing its authority. The
    /// physical writer stamps its actual commitment and unsigned use evidence.
    pub fn trusted_now_unix_ms(&self) -> u64 {
        self.trusted_now_unix_ms
    }

    /// Commit the freshly constructed use and retain its original dispatch data.
    /// The store constructs the first physical event at its own trusted clock
    /// and still refuses expired grants, changed flow, lost acknowledgements
    /// and replaced leases. No connector is invoked.
    pub fn retain_for_declassified_capture(
        self,
        grant_index: usize,
        policy_json: &[u8],
        consumption: &DeclassificationConsumptionEvidenceCommit,
    ) -> Result<
        (
            PreparedNativeSecurityEgress<'a>,
            Option<NativeSecurityEgressHistoryV1>,
            NativeSecurityDispatchLedgerRecordV1,
        ),
        KernelError,
    > {
        self.acquired
            .prepared
            .validate_ledger_input(grant_index, policy_json)?;
        if consumption.consumption.consumed_at_unix_ms != self.trusted_now_unix_ms
            || self
                .acquired
                .prepared
                .request
                .declassification_grant
                .is_none()
        {
            return Err(invalid(
                "native use evidence differs from its prepared event clock",
            ));
        }
        let history = self.acquired.commit_prepared(
            &self.lease,
            self.trusted_now_unix_ms,
            Some(consumption),
        )?;
        let prepared = self.acquired.prepared;
        let ledger = prepared.retain_dispatch_ledger_current(grant_index, policy_json)?;
        Ok((prepared, Some(history), ledger))
    }
}

/// Reconstruct only clock fields to check a first physical acknowledgement.
/// Neither this data comparison nor a retained receipt grants fresh custody.
pub(super) fn consumption_at(
    prepared: &DeclassificationConsumptionEvidenceCommit,
    now: u64,
) -> Result<DeclassificationConsumptionEvidenceCommit, KernelError> {
    let receipt = &prepared.receipt;
    let body: ActiveDefenseReceiptBody = serde_json::from_slice(receipt.canonical_body.as_bytes())
        .map_err(|_| invalid("native use receipt is not typed canonical evidence"))?;
    body.validate()
        .map_err(|_| invalid("native use receipt is invalid"))?;
    if canonical_json_bytes(&body).map_err(|_| invalid("native use receipt is invalid"))?
        != receipt.canonical_body.as_bytes()
        || body
            .body_digest()
            .map_err(|_| invalid("native use receipt is invalid"))?
            != receipt.body_hash
        || body
            .evidence_id()
            .map_err(|_| invalid("native use receipt is invalid"))?
            != receipt.evidence_id
        || body.header().tenant_id != receipt.tenant_id
        || body.header().transition_id != receipt.transition_id
        || body.header().occurred_at_unix_ms != receipt.occurred_at_unix_ms
        || body.kind().as_str() != receipt.evidence_type.as_str()
        || receipt.occurred_at_unix_ms != prepared.consumption.consumed_at_unix_ms
        || now < prepared.consumption.consumed_at_unix_ms
        || now >= prepared.consumption.grant_expires_at_unix_ms
    {
        return Err(invalid(
            "native use receipt differs from its prepared material",
        ));
    }
    let ActiveDefenseReceiptBody::DeclassificationConsumption(mut body) = body else {
        return Err(invalid("native use receipt has another evidence kind"));
    };
    body.header.occurred_at_unix_ms = now;
    let body = ActiveDefenseReceiptBody::DeclassificationConsumption(body);
    body.validate()
        .map_err(|_| invalid("native physical use receipt is invalid"))?;
    let mut expected = prepared.clone();
    expected.consumption.consumed_at_unix_ms = now;
    expected.receipt.occurred_at_unix_ms = now;
    expected.receipt.canonical_body = CanonicalBody::new(
        canonical_json_bytes(&body)
            .map_err(|_| invalid("native physical use receipt is invalid"))?,
    )
    .map_err(|_| invalid("native physical use receipt exceeds bounds"))?;
    expected.receipt.body_hash = body
        .body_digest()
        .map_err(|_| invalid("native physical use receipt is invalid"))?;
    expected.receipt.evidence_id = body
        .evidence_id()
        .map_err(|_| invalid("native physical use receipt is invalid"))?;
    Ok(expected)
}
