//! Stable authenticated commands carry data; the host supplies current authority.
//!
//! A registry template identity cannot stand in for a materialized offer.
//! ```compile_fail
//! use chio_security_types::recovery::{RecoveryCommandBodyV1, SafeInteger, TemplateId, WorkflowId};
//! fn select(workflow_id: WorkflowId, revision: SafeInteger, template: TemplateId) -> RecoveryCommandBodyV1 {
//!     RecoveryCommandBodyV1::SelectOffer {
//!         workflow_id,
//!         expected_revision: revision,
//!         offer_id: template,
//!     }
//! }
//! ```
//!
//! A template identity is not an idempotent workflow creation key.
//! ```compile_fail
//! use chio_security_types::recovery::{ProtectedText, RecoveryCommandBodyV1, RecoveryTemplateV1, TemplateId};
//! fn create(template: TemplateId, request_seed: ProtectedText<32768>) -> RecoveryCommandBodyV1 {
//!     RecoveryCommandBodyV1::CreateWorkflow {
//!         creation_key: template,
//!         template: RecoveryTemplateV1::SupportTicketPublicIssue,
//!         request_seed,
//!     }
//! }
//! ```
use super::{CommandId, CreationKey, OfferId, ProtectedText, SafeInteger, VersionV1, WorkflowId};
use serde::{Deserialize, Serialize};

/// Fresh approval bundles follow the protocol's finite signature ceiling.
/// Protected historical custody retains its independently versioned codec.
pub const MAX_RECOVERY_APPROVAL_ATTESTATIONS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryCommandSchema {
    #[serde(rename = "chio.recovery.command.v1")]
    V1,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryTemplateV1 {
    SupportTicketPublicIssue,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCommandV1 {
    pub schema: RecoveryCommandSchema,
    pub version: VersionV1,
    pub command_id: CommandId,
    pub command: RecoveryCommandBodyV1,
}
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryCommandBodyV1 {
    CreateWorkflow {
        creation_key: CreationKey,
        template: RecoveryTemplateV1,
        request_seed: ProtectedText<32768>,
    },
    InspectWorkflow {
        workflow_id: WorkflowId,
    },
    SelectOffer {
        workflow_id: WorkflowId,
        expected_revision: SafeInteger,
        offer_id: OfferId,
    },
    SubmitApproval {
        workflow_id: WorkflowId,
        expected_revision: SafeInteger,
        approval: ProtectedText<32768>,
    },
    ResumeWorkflow {
        workflow_id: WorkflowId,
        expected_revision: SafeInteger,
    },
    CancelWorkflow {
        workflow_id: WorkflowId,
        expected_revision: SafeInteger,
    },
    ReportDecision {
        workflow_id: WorkflowId,
        expected_revision: SafeInteger,
        decision: RecoveryReportedDecision,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReportedDecision {
    Accepted,
    Declined,
    NeedsReview,
}
impl RecoveryCommandBodyV1 {
    pub const fn permission(&self) -> &'static str {
        match self {
            Self::CreateWorkflow { .. } => "create",
            Self::InspectWorkflow { .. } => "inspect",
            Self::SelectOffer { .. } => "select",
            Self::SubmitApproval { .. } => "approve",
            Self::ResumeWorkflow { .. } => "resume",
            Self::CancelWorkflow { .. } => "cancel",
            Self::ReportDecision { .. } => "report",
        }
    }
}
impl core::fmt::Debug for RecoveryCommandV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCommandV1([redacted])")
    }
}
impl core::fmt::Debug for RecoveryCommandBodyV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCommandBodyV1([redacted])")
    }
}

/// The first template accepts only the exact reviewed issue title and body.
/// Sink selection, attachments and credentials are never tool input.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySupportIssueInputV1 {
    pub title: ProtectedText<256>,
    pub body: ProtectedText<16384>,
}
impl core::fmt::Debug for RecoverySupportIssueInputV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoverySupportIssueInputV1([redacted])")
    }
}
