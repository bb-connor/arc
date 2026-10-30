//! Client-safe denial codes. A denied tool call reaches an MCP client as one
//! closed code and its fixed text; the signed receipt keeps the denial detail.

use super::*;

/// Closed set of denial families a client may observe. Each code and text is
/// a stable wire string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClientDenialCode {
    EmergencyStop,
    CapabilityInvalid,
    CapabilityRevoked,
    ScopeDenied,
    ToolUnavailable,
    GuardDenied,
    GovernedTransactionDenied,
    BudgetExhausted,
    PaymentUnavailable,
    DeliveryContractUnsupported,
    ReplayDenied,
    RuntimeAdmissionDenied,
    Overloaded,
    KernelUnavailable,
    SessionUnsupported,
    OperationConflict,
    Denied,
}

/// Every client denial code, in wire order.
pub const CLIENT_DENIAL_CODES: [ClientDenialCode; 17] = [
    ClientDenialCode::EmergencyStop,
    ClientDenialCode::CapabilityInvalid,
    ClientDenialCode::CapabilityRevoked,
    ClientDenialCode::ScopeDenied,
    ClientDenialCode::ToolUnavailable,
    ClientDenialCode::GuardDenied,
    ClientDenialCode::GovernedTransactionDenied,
    ClientDenialCode::BudgetExhausted,
    ClientDenialCode::PaymentUnavailable,
    ClientDenialCode::DeliveryContractUnsupported,
    ClientDenialCode::ReplayDenied,
    ClientDenialCode::RuntimeAdmissionDenied,
    ClientDenialCode::Overloaded,
    ClientDenialCode::KernelUnavailable,
    ClientDenialCode::SessionUnsupported,
    ClientDenialCode::OperationConflict,
    ClientDenialCode::Denied,
];

impl ClientDenialCode {
    /// The code a client observes for a verdict. A deny without a family
    /// code observes `Denied`; no other verdict has a code.
    pub fn for_verdict(verdict: crate::Verdict, code: Option<Self>) -> Option<Self> {
        (verdict == crate::Verdict::Deny).then(|| code.unwrap_or(Self::Denied))
    }

    /// The terminal state a client observes under this code: a cancelled or
    /// incomplete state carries the fixed text of the code as its reason.
    pub fn terminal_state(
        self,
        state: &chio_core::session::OperationTerminalState,
    ) -> chio_core::session::OperationTerminalState {
        use chio_core::session::OperationTerminalState;
        match state {
            OperationTerminalState::Completed => OperationTerminalState::Completed,
            OperationTerminalState::Cancelled { .. } => OperationTerminalState::Cancelled {
                reason: self.text().to_owned(),
            },
            OperationTerminalState::Incomplete { .. } => OperationTerminalState::Incomplete {
                reason: self.text().to_owned(),
            },
        }
    }

    /// The stable `(wire code, client text)` pair.
    const fn wire(self) -> (&'static str, &'static str) {
        match self {
            Self::EmergencyStop => ("emergency_stop", "Kernel emergency stop is active"),
            Self::CapabilityInvalid => (
                "capability_invalid",
                "Capability is not valid for this request",
            ),
            Self::CapabilityRevoked => ("capability_revoked", "Capability has been revoked"),
            Self::ScopeDenied => ("scope_denied", "Request is outside the capability scope"),
            Self::ToolUnavailable => ("tool_unavailable", "Tool is not available"),
            Self::GuardDenied => ("guard_denied", "Request denied by policy guard"),
            Self::GovernedTransactionDenied => {
                ("governed_transaction_denied", "Governed transaction denied")
            }
            Self::BudgetExhausted => ("budget_exhausted", "Budget does not cover this request"),
            Self::PaymentUnavailable => ("payment_unavailable", "Payment could not be authorized"),
            Self::DeliveryContractUnsupported => (
                "delivery_contract_unsupported",
                "Delivery contract cannot be enforced for this request",
            ),
            Self::ReplayDenied => (
                "replay_denied",
                "Request was already executed or its nonce is invalid",
            ),
            Self::RuntimeAdmissionDenied => {
                ("runtime_admission_denied", "Runtime admission denied")
            }
            Self::Overloaded => ("overloaded", "Kernel is over capacity"),
            Self::KernelUnavailable => {
                ("kernel_unavailable", "Kernel could not complete admission")
            }
            Self::SessionUnsupported => (
                "session_unsupported",
                "Request is not supported in this session",
            ),
            Self::OperationConflict => (
                "operation_conflict",
                "Request id is bound to a different retained operation",
            ),
            Self::Denied => ("denied", "Request denied"),
        }
    }

    pub const fn code(self) -> &'static str {
        self.wire().0
    }

    pub const fn text(self) -> &'static str {
        self.wire().1
    }

    /// The code whose wire string is `code`, or `None` outside the closed set.
    pub fn from_code(code: &str) -> Option<Self> {
        CLIENT_DENIAL_CODES
            .into_iter()
            .find(|candidate| candidate.code() == code)
    }
}

/// A kernel denial: the client code plus the detail signed into the receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Denial {
    code: ClientDenialCode,
    detail: String,
}

impl Denial {
    pub(crate) fn new(code: ClientDenialCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    pub(crate) fn from_error(error: &KernelError) -> Self {
        Self::new(error.client_denial_code(), error.to_string())
    }

    pub(crate) const fn code(&self) -> ClientDenialCode {
        self.code
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }
}

impl KernelError {
    /// The client-safe family of this error. Exhaustive so every new variant
    /// takes an explicit decision.
    pub fn client_denial_code(&self) -> ClientDenialCode {
        use ClientDenialCode as Code;
        match self {
            Self::GuardDenied(reason) if reason == EMERGENCY_STOP_DENY_REASON => {
                Code::EmergencyStop
            }
            Self::GuardDenied(_) | Self::FindingDenied(_) => Code::GuardDenied,
            Self::UntrustedInput(_)
            | Self::CapabilityExpired
            | Self::CapabilityNotYetValid
            | Self::InvalidSignature
            | Self::UntrustedIssuer
            | Self::RecoveryAuthorityDenied
            | Self::CapabilityIssuanceFailed(_)
            | Self::CapabilityIssuanceDenied(_)
            | Self::SubjectMismatch { .. }
            | Self::DelegationInvalid(_)
            | Self::InvalidConstraint(_)
            | Self::InvalidReceiptMetadata(_)
            | Self::InvalidChildRequestParent
            | Self::Dpop(_)
            | Self::DpopVerificationFailed(_)
            | Self::ReservingAuthorizationRejectsPresentedNonce => Code::CapabilityInvalid,
            Self::CapabilityRevoked(_) | Self::DelegationChainRevoked(_) => Code::CapabilityRevoked,
            Self::OutOfScope { .. }
            | Self::OutOfScopeResource { .. }
            | Self::OutOfScopePrompt { .. }
            | Self::ResourceRootDenied { .. } => Code::ScopeDenied,
            Self::DirectDispatchUnavailable
            | Self::FlowRuntimeUnavailable
            | Self::ToolNotRegistered(_)
            | Self::ResourceNotRegistered(_)
            | Self::PromptNotRegistered(_)
            | Self::ToolServerError(_) => Code::ToolUnavailable,
            Self::GovernedApprovalLifetimeExceeded
            | Self::GovernedTransactionDenied(_)
            | Self::ApprovalRejected(_)
            | Self::ApprovalReplay(_) => Code::GovernedTransactionDenied,
            Self::BudgetExhausted(_) | Self::FinancialBudgetExceeded { .. } => {
                Code::BudgetExhausted
            }
            Self::NoCrossCurrencyOracle { .. }
            | Self::CrossCurrencyOracle(_)
            | Self::Web3EvidenceUnavailable(_)
            | Self::SettlementConfiguration(_)
            | Self::SettlementDrain(_)
            | Self::CredentialReservationCleanup { .. } => Code::PaymentUnavailable,
            Self::CapturedBudgetReplay(_)
            | Self::Session(
                crate::SessionError::ExecutionNonceRetryMismatch { .. }
                | crate::SessionError::DuplicateInflightRequest { .. }
                | crate::SessionError::DuplicateRequestLineage { .. },
            )
            | Self::ExecutionNonce(_)
            | Self::ReplayClockAnomaly { .. } => Code::ReplayDenied,
            Self::RuntimeAdmissionReadinessTimeout { .. } => Code::RuntimeAdmissionDenied,
            Self::OperationConflict { .. } => Code::OperationConflict,
            Self::Overloaded { .. }
            | Self::ExecutionNonceCapacity
            | Self::HotPathDeadlineExceeded { .. }
            | Self::PostEffectEvidenceCapacity => Code::Overloaded,
            Self::RecoveryEncoding(_)
            | Self::RevocationSnapshotFuture
            | Self::RevocationSnapshotStale
            | Self::ResponseDispatchRejected(_)
            | Self::ActiveResponseNeverCommitted(_)
            | Self::ReceiptSigningFailed(_)
            | Self::ReceiptVerificationFailed(_)
            | Self::ReceiptPersistence(_)
            | Self::ReceiptAppendOutcomeUnknown { .. }
            | Self::PostEffectEvidencePending { .. }
            | Self::PostEffectFaultLatched { .. }
            | Self::DurableOutcomePending { .. }
            | Self::DeliveryFailedAfterReceipt { .. }
            | Self::RevocationStore(_)
            | Self::BudgetStore(_)
            | Self::DurableAdmission(_)
            | Self::AdmissionRecovery(_)
            | Self::SecurityDispatchOutcomeRecoveryRequired(_)
            | Self::Clock(_)
            | Self::Internal(_)
            | Self::SyncBridgeIncompatibleWithCurrentThreadRuntime
            | Self::ReceiptWriterUnavailable(_) => Code::KernelUnavailable,
            Self::OutputWithheld
            | Self::UnknownSession(_)
            | Self::SessionAlreadyExists(_)
            | Self::Session(_)
            | Self::RequestIncomplete(_)
            | Self::SamplingNotAllowedByPolicy
            | Self::SamplingNotNegotiated
            | Self::SamplingContextNotSupported
            | Self::SamplingToolUseNotAllowedByPolicy
            | Self::SamplingToolUseNotNegotiated
            | Self::ElicitationNotAllowedByPolicy
            | Self::ElicitationNotNegotiated
            | Self::ElicitationFormNotSupported
            | Self::ElicitationUrlNotSupported
            | Self::UrlElicitationsRequired { .. }
            | Self::RootsNotNegotiated
            | Self::RequestCancelled { .. } => Code::SessionUnsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_denial_wire_strings_are_pinned() {
        let pinned = [
            ("emergency_stop", "Kernel emergency stop is active"),
            (
                "capability_invalid",
                "Capability is not valid for this request",
            ),
            ("capability_revoked", "Capability has been revoked"),
            ("scope_denied", "Request is outside the capability scope"),
            ("tool_unavailable", "Tool is not available"),
            ("guard_denied", "Request denied by policy guard"),
            ("governed_transaction_denied", "Governed transaction denied"),
            ("budget_exhausted", "Budget does not cover this request"),
            ("payment_unavailable", "Payment could not be authorized"),
            (
                "delivery_contract_unsupported",
                "Delivery contract cannot be enforced for this request",
            ),
            (
                "replay_denied",
                "Request was already executed or its nonce is invalid",
            ),
            ("runtime_admission_denied", "Runtime admission denied"),
            ("overloaded", "Kernel is over capacity"),
            ("kernel_unavailable", "Kernel could not complete admission"),
            (
                "session_unsupported",
                "Request is not supported in this session",
            ),
            (
                "operation_conflict",
                "Request id is bound to a different retained operation",
            ),
            ("request_cancelled", "Request was cancelled"),
            ("denied", "Request denied"),
        ];
        assert_eq!(pinned.len(), CLIENT_DENIAL_CODES.len());
        for (variant, pinned) in CLIENT_DENIAL_CODES.iter().zip(pinned) {
            assert_eq!((variant.code(), variant.text()), pinned);
        }
    }

    #[test]
    fn client_denial_codes_and_texts_are_unique() {
        let codes: std::collections::BTreeSet<_> = CLIENT_DENIAL_CODES
            .iter()
            .map(|variant| variant.code())
            .collect();
        let texts: std::collections::BTreeSet<_> = CLIENT_DENIAL_CODES
            .iter()
            .map(|variant| variant.text())
            .collect();
        let variants: std::collections::HashSet<_> = CLIENT_DENIAL_CODES.iter().collect();
        assert_eq!(codes.len(), CLIENT_DENIAL_CODES.len());
        assert_eq!(texts.len(), CLIENT_DENIAL_CODES.len());
        assert_eq!(variants.len(), CLIENT_DENIAL_CODES.len());
    }

    #[test]
    fn from_code_accepts_only_the_closed_wire_codes() {
        for variant in CLIENT_DENIAL_CODES {
            assert_eq!(ClientDenialCode::from_code(variant.code()), Some(variant));
        }
        for unknown in ["", "Denied", "guard_denied ", "Request denied", "unknown"] {
            assert_eq!(ClientDenialCode::from_code(unknown), None, "{unknown:?}");
        }
    }

    #[test]
    fn a_cancelled_request_reports_request_cancelled() {
        let error = KernelError::RequestCancelled {
            request_id: chio_core::session::RequestId::new("cancelled-request"),
            reason: "cancelled by client: user aborted sample".to_string(),
        };
        assert_eq!(error.client_denial_code().code(), "request_cancelled");
    }

    #[test]
    fn only_the_stop_reason_selects_emergency_stop() {
        assert_eq!(
            KernelError::GuardDenied(EMERGENCY_STOP_DENY_REASON.to_string()).client_denial_code(),
            ClientDenialCode::EmergencyStop
        );
        assert_eq!(
            KernelError::GuardDenied(format!("{EMERGENCY_STOP_DENY_REASON}: extra"))
                .client_denial_code(),
            ClientDenialCode::GuardDenied
        );
    }
}
