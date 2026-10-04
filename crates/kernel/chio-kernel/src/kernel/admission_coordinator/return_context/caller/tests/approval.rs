//! Signed approval material for custody codec models, not physical store custody.

use super::*;
use chio_core::capability::governance::{
    ApprovalSetBody, GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::capability::scope::{Constraint, MonetaryAmount};

#[derive(Clone, Copy, Debug)]
pub(in super::super) enum Approval {
    None,
    Single,
    Threshold,
    CumulativeThreshold,
    CumulativeUnused,
}

impl Approval {
    pub(super) fn required(self) -> bool {
        !matches!(self, Self::None)
    }

    pub(super) fn constraints(self) -> Vec<Constraint> {
        match self {
            Self::None => vec![],
            Self::Single | Self::Threshold => {
                vec![Constraint::RequireApprovalAbove { threshold_units: 0 }]
            }
            Self::CumulativeThreshold | Self::CumulativeUnused => {
                vec![Constraint::RequireCumulativeApprovalAbove {
                    threshold: MonetaryAmount {
                        units: 100,
                        currency: "USD".into(),
                    },
                    approval_budget_id: "caller-context-approval-budget".into(),
                    approval_budget_epoch: 1,
                    cumulative_approval_root_binding: None,
                }]
            }
        }
    }

    pub(super) fn configure(
        self,
        kernel: &mut ChioKernel,
        request: &mut ToolCallRequest,
        key: &chio_core::Keypair,
    ) -> TestResult<Option<crate::ThresholdApprovalReplayReservationV1>> {
        if matches!(self, Self::None) {
            return Ok(None);
        }
        kernel
            .set_governed_approval_policy("caller-context-tenant".into(), vec![key.public_key()])?;
        let mut intent = kernel.bind_tool_approval_intent(request)?;
        intent.max_amount = Some(MonetaryAmount {
            units: if matches!(self, Self::CumulativeUnused) {
                10
            } else {
                100
            },
            currency: "USD".into(),
        });
        let intent_hash = intent.binding_hash()?;
        request.governed_intent = Some(intent);
        if matches!(self, Self::CumulativeUnused) {
            return Ok(None);
        }
        let now = kernel.read_authority_time()?.as_secs();
        let proposal = if matches!(self, Self::Threshold | Self::CumulativeThreshold) {
            Some(ThresholdApprovalProposal::sign(
                ThresholdApprovalProposalBody {
                    schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.into(),
                    proposal_id: "caller-context-threshold-proposal".into(),
                    request_id: request.request_id.clone(),
                    governed_intent_hash: intent_hash.clone(),
                    subject: request.capability.subject.clone(),
                    authorizing_capability_digest: sha256_hex(&canonical_json_bytes(
                        &request.capability,
                    )?),
                    policy_hash: kernel.policy_hash().into(),
                    threshold: 1,
                    eligible_set_digest: sha256_hex(b"caller-context-approver-directory"),
                    proposal_created_at: now,
                    proposal_deadline: now + 60,
                    policy_authority: key.public_key(),
                },
                key,
            )?)
        } else {
            None
        };
        let token = GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "caller-context-approval".into(),
                approver: key.public_key(),
                subject: request.capability.subject.clone(),
                governed_intent_hash: intent_hash,
                request_id: request.request_id.clone(),
                threshold_proposal_hash: proposal
                    .as_ref()
                    .map(ThresholdApprovalProposal::artifact_digest)
                    .transpose()?,
                issued_at: now,
                expires_at: now + 60,
                decision: GovernedApprovalDecision::Approved,
            },
            key,
        )?;
        if let Some(proposal) = proposal {
            let set = ApprovalSetBody::new(vec![token.artifact_digest()?], &proposal)?;
            request.approval_tokens = vec![token.clone()];
            request.threshold_approval_proposal = Some(proposal.clone());
            Ok(Some(crate::ThresholdApprovalReplayReservationV1::new(
                proposal,
                vec![token],
                set,
            )?))
        } else {
            request.approval_token = Some(token);
            assert!(kernel
                .validate_governed_approval_for_dispatch_non_consuming(
                    request,
                    &request.capability,
                    now,
                )?
                .is_some());
            Ok(None)
        }
    }
}
