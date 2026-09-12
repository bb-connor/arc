//! The strongest alternative a competent engineer assembles today from parts
//! that already exist, put through the same corpora as the Chio
//! cross-organization receiver.
//!
//! The parts are the ones a skeptical reader names: a tool-call server, a
//! caller identity authenticated by a key pinned out of band (which is what a
//! federated workload-identity trust bundle installs, with the issuance
//! mechanism left out because the property at stake is peer authentication),
//! a policy engine that evaluates the request against a local rule set and
//! signs its decision, and a receiver-side replay table keyed by a request
//! identifier.
//!
//! Two wirings of the same parts run over the same code. The `composed` wiring
//! is what the parts produce when each is used the way it documents itself. The
//! `hardened` wiring is the same parts with every check an operator could
//! reasonably add written in. Reporting both is the honest form of the result:
//! several properties turn on which wiring an operator happens to have, and
//! nothing in the composition records which one that is.

pub mod harness;
pub mod measure;
pub mod negative;
pub mod properties;
pub mod receiver;
pub mod receiver_state;
pub mod request;
pub mod scenario;
pub mod store;
pub mod substitution;
