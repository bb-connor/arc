//! The customer-hosted root exchange for Identity Assertion JWT
//! Authorization Grants (ID-JAG).
//!
//! A confidential client presents an ID-JAG with a `private_key_jwt` client
//! assertion. The exchange verifies the client, verifies the ID-JAG against
//! a key pinned for its provider record, matches exactly one root policy rule,
//! spends the replay keys and prepares the anchored root: the unsigned root
//! capability body, its `root_anchor` and the delegation context it binds.

mod claims;
pub mod client_auth;
pub mod error;
pub mod exchange;
pub mod grant;
pub mod id_jag;
pub mod jws;
pub mod key_lookup;
pub mod provider;
pub mod replay;

pub use client_auth::{
    authenticate_client, AuthenticatedClient, ClientAuthContext, ClientCredentials, ClientRegistry,
    ConfidentialClient, CLIENT_ASSERTION_TYPE_JWT_BEARER,
};
pub use error::{OAuthErrorCode, RootExchangeError};
pub use exchange::{
    ContextOpening, ExchangeEntropy, ExchangeServices, PreparedAnchoredRoot, RootExchange,
};
pub use grant::IdJagGrant;
pub use id_jag::ID_JAG_MEDIA_TYPE;
pub use key_lookup::{IdpKey, IdpKeyLookup};
pub use provider::ProviderRecord;
pub use replay::{ExchangeReplayStore, ReplayBinding, ReplayKey, ReplayNamespace};
