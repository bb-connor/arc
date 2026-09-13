//! The strongest alternative a competent engineer assembles today from parts
//! that already exist, put through the same corpora as the Chio
//! cross-organization receiver.
//!
//! The parts are the ones a skeptical reader names, and each is a shipped
//! format with a published specification: a tool call as the Model Context
//! Protocol defines it, carried in a message as the Agent2Agent protocol
//! defines it, from a workload whose identity is a SPIFFE verifiable identity
//! document, accompanied by a delegated credential an OAuth 2.0 token exchange
//! issued. `src/spec.rs` names the document and section behind every field on
//! the wire, and the corpora check the serialized request against that
//! inventory, so no shape here is one this project chose.
//!
//! Two wirings of the same parts run over the same code. The `composed` wiring
//! is what the parts produce when each is used the way its specification
//! documents. The `hardened` wiring is the same parts with every check an
//! operator could reasonably add written in. Reporting both is the honest form
//! of the result: several properties turn on which wiring an operator happens
//! to have, and nothing in the composition records which one that is.

pub mod carriers;
pub mod harness;
pub mod jose;
pub mod measure;
pub mod negative;
pub mod properties;
pub mod receiver;
pub mod receiver_state;
pub mod request;
pub mod scenario;
pub mod spec;
pub mod store;
pub mod substitution;
