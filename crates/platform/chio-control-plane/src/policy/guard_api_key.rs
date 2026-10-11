//! Secret custody for policy-configured external guard credentials.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

/// An external guard API key whose owned storage wipes on drop.
///
/// Policy serialization preserves the configured credential for private policy
/// custody. Diagnostic rendering never exposes it. Guard construction explicitly
/// borrows the secret before handing it to the provider's secret owner.
#[derive(Clone)]
pub struct GuardApiKey(Zeroizing<String>);

impl GuardApiKey {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for GuardApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GuardApiKey([REDACTED])")
    }
}

impl Serialize for GuardApiKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose_secret())
    }
}

impl<'de> Deserialize<'de> for GuardApiKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl From<String> for GuardApiKey {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for GuardApiKey {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}
