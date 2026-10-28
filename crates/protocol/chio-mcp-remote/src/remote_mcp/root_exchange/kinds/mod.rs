//! Verifiers of the kept anchor kinds. Each turns its input into one
//! [`AnchorEvidence`](super::AnchorEvidence) for
//! [`RootExchange::prepare`](super::RootExchange::prepare).

mod bearer_jws;
pub mod entra_jwt;
pub mod local_as;
pub mod oauth_introspection;
pub mod oidc_jwt;
pub mod operator_key;
pub mod operator_static_bearer;
mod sender;
