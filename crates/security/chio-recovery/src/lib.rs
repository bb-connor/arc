//! Pure recovery advice. Inputs remain untrusted until the owning authority
//! verifies them. A directive cannot execute, close, settle, sign or release.
//!
//! Advisory evidence cannot become live disclosure authority.
//! ```compile_fail
//! use chio_core_types::recovery::{SignedRecoveryExplanationReportV1, SignedRecoveryGrantV2};
//! fn authorize(report: SignedRecoveryExplanationReportV1) -> SignedRecoveryGrantV2 {
//!     report.into()
//! }
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;
mod decision;
mod evaluation;
mod planning;
mod projection;
mod report;
mod workflow;
pub use decision::{PlanDecision, WorkflowDirective};
pub use evaluation::evaluate_explanation;
pub use planning::{
    plan, CandidatePlanV1, PlannerLimitsV1, PlannerSearchLimit, RecoveryPlanningRegistryV1,
    RegisteredCandidatePlanV1,
};
pub use projection::project_explanation;
pub use report::{
    explanation_report_payload, explanation_view_payload, prepare_explanation_report,
    verify_explanation_report, verify_explanation_view, ExplanationAudience,
    ExplanationExpectedTrust, ExplanationReportInputs,
};
pub use workflow::advise_workflow;
