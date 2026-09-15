//! Research baselines for Chio's cross-organization and outcome experiments.
//!
//! The parts are the ones a skeptical reader names, and each is a shipped
//! format with a published specification: a tool call as the Model Context
//! Protocol defines it, carried in a message as the Agent2Agent protocol
//! defines it, from a workload whose identity is a SPIFFE verifiable identity
//! document, accompanied by a delegated credential an OAuth 2.0 token exchange
//! issued. `src/spec.rs` names the document and section behind every field on
//! the wire, and the corpora check the serialized request against that
//! inventory. That inventory is this project's selected profile, not a bound
//! on application extensions or other valid deployments of those standards.
//!
//! Two wirings of the same parts run over the same code. The `composed` wiring
//! is what the parts produce when each is used the way its specification
//! documents. The `hardened` wiring is the same parts with every check an
//! operator added in this experiment. These modes are historical experimental
//! configurations, not the limits of an ordinary composition.
//!
//! `outcome_ledger` is a separate, equally stateful alternative. It permits
//! application-defined outcome evidence, receiver-issued opaque handles and a
//! durable logical effect budget. It is not restricted by the older carrier
//! inventory and does not depend on Chio's runtime checker or storage layer.

pub mod carriers;
pub mod harness;
pub mod jose;
pub mod measure;
pub mod negative;
pub mod outcome_ledger;
pub mod properties;
pub mod receiver;
pub mod receiver_state;
pub mod request;
pub mod scenario;
pub mod spec;
pub mod store;
pub mod substitution;
