//! Enterprise provider records as seen by the exchange.

use chio_core::enterprise_provider::EnterpriseProviderRecord;
use chio_core::root_authority::{EnterpriseProviderIdentity, Sha256Digest};

use super::error::RootExchangeError;

/// A provider record that a root policy rule may reference, with its
/// identity projection. The projection and its digest are computed together
/// at construction and cannot be changed apart.
#[derive(Debug, Clone)]
pub struct ProviderRecord {
    identity: EnterpriseProviderIdentity,
    identity_digest: Sha256Digest,
    enabled: bool,
}

impl ProviderRecord {
    /// The record's `chio.enterprise-provider-identity.v1` projection and
    /// its digest. A record the projection refuses is invalid here.
    pub fn from_record(record: &EnterpriseProviderRecord) -> Result<Self, RootExchangeError> {
        let identity =
            record
                .root_identity()
                .map_err(|refusal| RootExchangeError::ProviderRecordInvalid {
                    record: record.provider_id.clone(),
                    reason: refusal.to_string(),
                })?;
        let identity_digest = identity
            .digest()
            .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
        Ok(Self {
            identity,
            identity_digest,
            enabled: record.enabled,
        })
    }
}

impl ProviderRecord {
    #[must_use]
    pub fn identity(&self) -> &EnterpriseProviderIdentity {
        &self.identity
    }

    /// `provider_identity_digest` of [`Self::identity`].
    #[must_use]
    pub fn identity_digest(&self) -> &Sha256Digest {
        &self.identity_digest
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}
