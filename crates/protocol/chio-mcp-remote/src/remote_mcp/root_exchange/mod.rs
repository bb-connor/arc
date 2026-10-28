//! The customer-hosted root exchange.
//!
//! Every anchor kind has one verifier that turns its input into
//! [`AnchorEvidence`]: the Identity Assertion JWT Authorization Grant
//! (ID-JAG, draft-ietf-oauth-identity-assertion-authz-grant-04) here, and
//! the kept kinds in [`kinds`]. [`RootExchange::prepare`] then matches
//! exactly one root policy rule of that kind and prepares the anchored root:
//! the unsigned root capability body, its `root_anchor` and the delegation
//! context it binds. [`RootExchange::spend_replay_key`] spends the replay key.
//!
//! A confidential client presents an ID-JAG with a `private_key_jwt` client
//! assertion; the exchange verifies the client and then the ID-JAG against a
//! key pinned for its provider record.
//!
//! The draft presents an ID-JAG to the resource authorization server with the
//! `jwt-bearer` grant. This module also admits it as an RFC 8693
//! `subject_token` of type `urn:ietf:params:oauth:token-type:id-jag`, a Chio
//! extension that applies the same rules.

mod claims;
pub mod client_auth;
#[cfg(test)]
mod commitment_vectors_tests;
pub mod error;
pub mod evidence;
pub mod exchange;
pub mod grant;
pub mod id_jag;
pub mod jws;
pub mod key_lookup;
pub mod kinds;
pub mod provider;
pub mod replay;
#[cfg(test)]
mod tests;

pub use client_auth::{
    authenticate_client, AuthenticatedClient, ClientAuthContext, ClientCredentials, ClientRegistry,
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
};
pub use error::{
    OAuthErrorCode, RootExchangeConfigError, RootExchangeError, SenderConstraintFailure,
};
pub use evidence::{AnchorEvidence, JwsEvidence};
pub use exchange::{
    ContextOpening, ExchangeServices, PreparedAnchoredRoot, RootExchange, RootExchangeConfig,
    REPLAY_RETENTION_SKEW_SECS,
};
pub use grant::{IdJagGrant, RequestedTokenType};
pub use id_jag::ID_JAG_MEDIA_TYPE;
pub use key_lookup::{IdpKey, IdpKeyLookup};
pub use provider::ProviderRecord;
pub use replay::{ExchangeReplayStore, ReplayBinding, ReplayKey, ReplayNamespace};
