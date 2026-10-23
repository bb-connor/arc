//! Pure recovery explanations. Inputs remain untrusted claims until the owning
//! authority verifies them, and no explanation can execute, close, settle,
//! sign or release.
//!
//! Advisory evidence has no conversion into execution authority. A signed
//! report cannot become a recovery grant:
//! ```compile_fail
//! use chio_core_types::recovery::{SignedRecoveryExplanationReportV1, SignedRecoveryGrant};
//! fn authorize(report: SignedRecoveryExplanationReportV1) -> SignedRecoveryGrant {
//!     report.into()
//! }
//! ```
//! A signed view cannot become a disclosure grant:
//! ```compile_fail
//! use chio_core_types::recovery::{SignedDisclosureGrant, SignedRecoveryExplanationViewV1};
//! fn disclose(view: SignedRecoveryExplanationViewV1) -> SignedDisclosureGrant {
//!     view.into()
//! }
//! ```
//! The same paths resolve, and a real recovery grant does convert, so each
//! refusal above comes only from the missing evidence conversion:
//! ```
//! use chio_core_types::recovery::{
//!     SignedDisclosureGrant, SignedRecoveryExplanationReportV1, SignedRecoveryExplanationViewV1,
//!     SignedRecoveryGrant,
//! };
//! fn evidence(
//!     report: SignedRecoveryExplanationReportV1,
//!     view: SignedRecoveryExplanationViewV1,
//! ) -> (SignedRecoveryExplanationReportV1, SignedRecoveryExplanationViewV1) {
//!     (report, view)
//! }
//! fn authorize(grant: SignedRecoveryGrant) -> SignedRecoveryGrant {
//!     grant
//! }
//! fn disclose(grant: SignedRecoveryGrant) -> SignedDisclosureGrant {
//!     grant.into()
//! }
//! let _ = (evidence, authorize, disclose);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod evaluation;
mod projection;
mod report;

pub use evaluation::evaluate_explanation;
pub use projection::project_explanation;
pub use report::{
    explanation_report_payload, explanation_view_payload, prepare_explanation_report,
    verify_explanation_report, verify_explanation_view, ExplanationAudience,
    ExplanationExpectedTrust, ExplanationReportInputs,
};
