//! A standard resource subscription as the signed resume record carries it.
use super::*;

/// A client subscription the resume record carries across restore.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PersistedSubscription {
    /// A standard MCP `resources/subscribe`, keyed by URI within the session.
    Standard { uri: String, capability_id: String },
}
