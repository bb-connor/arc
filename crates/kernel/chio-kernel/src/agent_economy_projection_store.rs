use chio_core::receipt::body::ChioReceipt;

use crate::receipt_store::{ReceiptStore, ReceiptStoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionBudgetAuthorization {
    pub decision: crate::agent_economy_budget_store::BudgetAuthorizeHoldDecision,
    pub operation: crate::admission_operation::AdmissionOperationV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionBudgetCapture {
    pub decision: crate::agent_economy_budget_store::BudgetInvocationCaptureDecision,
    pub operation: crate::admission_operation::AdmissionOperationV1,
}

#[derive(Debug, Clone, Copy)]
pub struct AdmissionPaymentJournalAdvance<'a> {
    pub operation: &'a crate::admission_operation::AdmissionOperationV1,
    pub recovery_lease: &'a crate::admission_operation::AdmissionRecoveryLease,
    pub expected: &'a crate::agent_economy_payment::PaymentJournalRecord,
    pub transition: &'a crate::agent_economy_payment::PaymentJournalTransition,
    pub release_evidence: Option<&'a crate::tool_outcome::MonetaryReleaseEvidenceV1>,
    pub active_fence: &'a crate::admission_operation::StoreMutationFence,
    pub trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct AdmissionPaymentSettlementBegin<'a> {
    pub operation: &'a crate::admission_operation::AdmissionOperationV1,
    pub recovery_lease: &'a crate::admission_operation::AdmissionRecoveryLease,
    pub expected: &'a crate::agent_economy_payment::PaymentJournalRecord,
    pub transition: Option<&'a crate::agent_economy_payment::PaymentJournalTransition>,
    pub release_evidence: Option<&'a crate::tool_outcome::MonetaryReleaseEvidenceV1>,
    pub budget_reconcile: crate::agent_economy_budget_store::BudgetReconcileHoldRequest,
    pub active_fence: &'a crate::admission_operation::StoreMutationFence,
    pub trusted_now_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionPaymentSettlement {
    pub journal: crate::agent_economy_payment::PaymentJournalRecord,
    pub budget: crate::agent_economy_budget_store::BudgetReconcileHoldDecision,
    pub budget_already_reconciled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionBudgetAuthorizationError {
    #[error("combined admission budget authorization is unavailable: {0}")]
    Unavailable(String),
    #[error("combined admission budget authorization was fenced")]
    Fenced,
    #[error("combined admission budget authorization durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error("combined admission budget authorization invariant failed: {0}")]
    Invariant(String),
    #[error(transparent)]
    Operation(#[from] crate::admission_operation::AdmissionOperationError),
}

#[derive(Debug, thiserror::Error)]
pub enum AdmissionPaymentJournalError {
    #[error("qualified payment journal is unavailable: {0}")]
    Unavailable(String),
    #[error("qualified payment journal mutation was fenced")]
    Fenced,
    #[error("qualified payment journal compare-and-set conflicted: {0}")]
    Conflict(String),
    #[error("qualified payment journal durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error("qualified payment journal invariant failed: {0}")]
    Invariant(String),
}

pub const ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND: &str =
    "chio.admission.terminal-projection.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdApprovalReplayReservationV1 {
    proposal: chio_core::capability::threshold_approval::ThresholdApprovalProposal,
    tokens: Vec<chio_core::capability::governance::GovernedApprovalToken>,
    verified_set: chio_core::capability::threshold_approval::VerifiedApprovalSetBody,
}

impl ThresholdApprovalReplayReservationV1 {
    pub fn new(
        proposal: chio_core::capability::threshold_approval::ThresholdApprovalProposal,
        mut tokens: Vec<chio_core::capability::governance::GovernedApprovalToken>,
        verified_set: chio_core::capability::threshold_approval::VerifiedApprovalSetBody,
    ) -> Result<Self, crate::admission_operation::AdmissionOperationStoreError> {
        use std::collections::HashSet;

        if tokens.is_empty()
            || tokens.len()
                > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
        {
            return Err(
                crate::admission_operation::AdmissionOperationStoreError::Invariant(format!(
                    "threshold approval replay reservation must contain between 1 and {} tokens",
                    chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS
                )),
            );
        }
        if !proposal.verify_signature().map_err(|error| {
            crate::admission_operation::AdmissionOperationStoreError::Invariant(error.to_string())
        })? {
            return Err(
                crate::admission_operation::AdmissionOperationStoreError::Invariant(
                    "threshold approval replay proposal signature is invalid".to_owned(),
                ),
            );
        }
        let proposal_hash = proposal.proposal_hash().map_err(|error| {
            crate::admission_operation::AdmissionOperationStoreError::Invariant(error.to_string())
        })?;
        let mut token_ids = HashSet::new();
        let mut approvers = HashSet::new();
        let mut tokens_with_digests = Vec::with_capacity(tokens.len());
        let proposal_body = proposal.body();
        for token in tokens.drain(..) {
            if token.id.is_empty()
                || token.id.trim() != token.id
                || token.threshold_proposal_hash.as_deref() != Some(proposal_hash.as_str())
                || token.request_id != proposal_body.request_id()
                || token.governed_intent_hash != proposal_body.governed_intent_hash()
                || &token.subject != proposal_body.subject()
                || token.decision
                    != chio_core::capability::governance::GovernedApprovalDecision::Approved
                || token.issued_at < proposal_body.proposal_created_at()
                || token.issued_at >= proposal_body.proposal_deadline()
                || token.expires_at > proposal_body.proposal_deadline()
                || !token_ids.insert(token.id.clone())
                || !approvers.insert(token.approver.to_hex())
            {
                return Err(
                    crate::admission_operation::AdmissionOperationStoreError::Invariant(
                        "threshold approval replay tokens do not form a distinct proposal set"
                            .to_owned(),
                    ),
                );
            }
            if !token.verify_signature().map_err(|error| {
                crate::admission_operation::AdmissionOperationStoreError::Invariant(
                    error.to_string(),
                )
            })? {
                return Err(
                    crate::admission_operation::AdmissionOperationStoreError::Invariant(
                        "threshold approval replay token signature is invalid".to_owned(),
                    ),
                );
            }
            let digest = token.token_digest().map_err(|error| {
                crate::admission_operation::AdmissionOperationStoreError::Invariant(
                    error.to_string(),
                )
            })?;
            tokens_with_digests.push((digest, token));
        }
        tokens_with_digests.sort_by(|left, right| left.0.cmp(&right.0));
        if tokens_with_digests
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
            || tokens_with_digests
                .iter()
                .map(|(digest, _)| digest)
                .ne(verified_set.token_digests().iter())
        {
            return Err(
                crate::admission_operation::AdmissionOperationStoreError::Invariant(
                    "threshold approval replay token digests do not match the verified set"
                        .to_owned(),
                ),
            );
        }
        let reconstructed =
            chio_core::capability::threshold_approval::VerifiedApprovalSetBody::new(
                verified_set.token_digests().to_vec(),
                &proposal,
            )
            .map_err(|error| {
                crate::admission_operation::AdmissionOperationStoreError::Invariant(
                    error.to_string(),
                )
            })?;
        if reconstructed != verified_set {
            return Err(
                crate::admission_operation::AdmissionOperationStoreError::Invariant(
                    "threshold approval replay set does not match its signed proposal".to_owned(),
                ),
            );
        }
        Ok(Self {
            proposal,
            tokens: tokens_with_digests
                .into_iter()
                .map(|(_, token)| token)
                .collect(),
            verified_set,
        })
    }

    #[must_use]
    pub const fn proposal(
        &self,
    ) -> &chio_core::capability::threshold_approval::ThresholdApprovalProposal {
        &self.proposal
    }

    #[must_use]
    pub fn tokens(&self) -> &[chio_core::capability::governance::GovernedApprovalToken] {
        &self.tokens
    }

    #[must_use]
    pub const fn verified_set(
        &self,
    ) -> &chio_core::capability::threshold_approval::VerifiedApprovalSetBody {
        &self.verified_set
    }
}

pub trait QualifiedAdmissionProjectionStore:
    ReceiptStore + crate::admission_operation::QualifiedAdmissionOperationStore
{
    fn load_payment_journal(
        &self,
        operation_id: &str,
        active_fence: &crate::admission_operation::StoreMutationFence,
    ) -> Result<
        Option<crate::agent_economy_payment::PaymentJournalRecord>,
        AdmissionPaymentJournalError,
    >;

    fn advance_payment_journal(
        &self,
        advance: AdmissionPaymentJournalAdvance<'_>,
    ) -> Result<crate::agent_economy_payment::PaymentJournalRecord, AdmissionPaymentJournalError>;

    fn begin_payment_settlement(
        &self,
        begin: AdmissionPaymentSettlementBegin<'_>,
    ) -> Result<AdmissionPaymentSettlement, AdmissionPaymentJournalError>;

    #[allow(clippy::too_many_arguments)]
    fn authorize_budget_and_commit_admission(
        &self,
        operation: &crate::admission_operation::AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        request: crate::agent_economy_budget_store::BudgetAuthorizeHoldRequest,
        payment_journal: Option<crate::agent_economy_payment::PaymentJournalRecord>,
        credit_exposure: Option<chio_credit::obligation::CreditExposureReservationRequest>,
        active_fence: &crate::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBudgetAuthorization, AdmissionBudgetAuthorizationError>;

    fn capture_invocation_and_commit_dispatch(
        &self,
        operation: &crate::admission_operation::AdmissionOperationV1,
        recovery_lease: &crate::admission_operation::AdmissionRecoveryLease,
        request: crate::agent_economy_budget_store::BudgetCaptureInvocationRequest,
        active_fence: &crate::admission_operation::StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBudgetCapture, crate::admission_operation::AdmissionCaptureError>;

    fn reserve_threshold_approval_and_commit_admission(
        &self,
        _command: &crate::admission_operation::AdmissionOperationCommand,
        _reservation: &ThresholdApprovalReplayReservationV1,
        _trusted_now_unix_ms: u64,
    ) -> Result<
        crate::admission_operation::AdmissionCommandResult,
        crate::admission_operation::AdmissionOperationStoreError,
    > {
        Err(
            crate::admission_operation::AdmissionOperationStoreError::Unavailable(
                "durable threshold approval replay reservation is unsupported".to_owned(),
            ),
        )
    }

    fn list_admission_receipts_after(
        &self,
        after_receipt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError>;
}
