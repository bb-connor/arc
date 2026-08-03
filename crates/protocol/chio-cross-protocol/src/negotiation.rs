use chio_core::capability::features::{
    CapabilityNegotiation, AGGREGATE_INVOCATION_BUDGET, GOVERNED_ACTIVE_RESPONSE_PLAN,
    SUPPLEMENTAL_BROKER_EXECUTION_QUOTA, THRESHOLD_GOVERNED_APPROVALS,
};
use chio_core::capability::governance::{
    GovernedApprovalToken, GovernedTransactionIntent, GovernedTransactionIntentBody,
};
use chio_core::capability::threshold_approval::ThresholdApprovalProposal;
use chio_core::capability::token::CapabilityToken;
use chio_core::message::OpaqueSupplementalAuthorization;

/// A capability profile computed by a trusted protocol host from both peers'
/// advertised feature sets.
///
/// This wrapper intentionally has no serialization or deserialization surface.
/// A request body can advertise features during its authenticated handshake,
/// but it cannot assert the intersection used for admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPeerNegotiation {
    negotiated: CapabilityNegotiation,
}

impl Default for TrustedPeerNegotiation {
    fn default() -> Self {
        Self {
            negotiated: CapabilityNegotiation::v1_default(),
        }
    }
}

impl TrustedPeerNegotiation {
    /// Compute the exact intersection of locally and remotely advertised
    /// features. Both advertisements are validated before the profile can be
    /// installed at a trusted edge or session boundary.
    pub fn from_advertised_intersection(
        local: &CapabilityNegotiation,
        remote: &CapabilityNegotiation,
    ) -> Result<Self, String> {
        let negotiated = local
            .negotiated_with(remote)
            .map_err(|error| error.to_string())?;
        Ok(Self { negotiated })
    }

    /// Read the negotiated profile. There is deliberately no mutable accessor.
    #[must_use]
    pub fn profile(&self) -> &CapabilityNegotiation {
        &self.negotiated
    }
}

/// Reject extension-bearing authorization before dispatch unless the trusted
/// peer intersection explicitly contains every required feature bit.
pub fn validate_execution_feature_negotiation(
    negotiation: &TrustedPeerNegotiation,
    capability: &CapabilityToken,
    governed_intent: Option<&GovernedTransactionIntent>,
    approval_token: Option<&GovernedApprovalToken>,
    approval_tokens: &[GovernedApprovalToken],
    threshold_approval_proposal: Option<&ThresholdApprovalProposal>,
    supplemental_authorization: Option<&OpaqueSupplementalAuthorization>,
) -> Result<(), String> {
    negotiation
        .profile()
        .validate()
        .map_err(|error| error.to_string())?;

    if capability.aggregate_invocation_budget.is_some() {
        require_feature(negotiation, AGGREGATE_INVOCATION_BUDGET)?;
    }
    let singular_threshold_approval =
        approval_token.is_some_and(|token| token.threshold_proposal_hash.is_some());
    if singular_threshold_approval
        || !approval_tokens.is_empty()
        || threshold_approval_proposal.is_some()
    {
        require_feature(negotiation, THRESHOLD_GOVERNED_APPROVALS)?;
    }
    if governed_intent.is_some_and(|intent| {
        matches!(
            &intent.body,
            GovernedTransactionIntentBody::ActiveResponsePlan(_)
        )
    }) {
        require_feature(negotiation, GOVERNED_ACTIVE_RESPONSE_PLAN)?;
    }
    if supplemental_authorization.is_some() {
        require_feature(negotiation, SUPPLEMENTAL_BROKER_EXECUTION_QUOTA)?;
    }
    Ok(())
}

fn require_feature(negotiation: &TrustedPeerNegotiation, feature: &str) -> Result<(), String> {
    if negotiation.profile().supports(feature) {
        Ok(())
    } else {
        Err(format!(
            "protocol feature `{feature}` is absent from the trusted peer-negotiated intersection"
        ))
    }
}
