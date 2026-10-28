//! The root exchange's [`IdpKeyLookup`] over pinned key sources.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use chio_core::root_authority::{EnterpriseProviderIdentity, JwsAlgorithm};

use super::fetch::JwksFetcher;
use super::source::{
    ExchangeSigner, IdpKeySourceError, KeyResolutionError, KeySnapshotSink, PinnedIdpKeys,
    RefreshPolicy,
};
use crate::root_exchange::{IdpKey, IdpKeyLookup, RootExchangeError};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdpKeySourcesError {
    #[error("provider record `{0}` is listed twice")]
    DuplicateProvider(String),
    #[error("issuer `{0}` is pinned by more than one provider record")]
    DuplicateIssuer(String),
    #[error("provider record `{provider}` has no usable key source: {error}")]
    Source {
        provider: String,
        error: IdpKeySourceError,
    },
}

struct PinnedProvider {
    identity: EnterpriseProviderIdentity,
    keys: PinnedIdpKeys,
}

/// One pinned key source per provider record, keyed by `provider_id`. Each
/// issuer is pinned by exactly one record, so the fetch rate limit holds per
/// issuer.
pub struct IdpKeySources {
    providers: BTreeMap<String, PinnedProvider>,
}

impl IdpKeySources {
    /// Build a key source for every `oidc_jwks` record in `identities`.
    pub fn from_providers(
        identities: &[EnterpriseProviderIdentity],
        fetcher: Arc<dyn JwksFetcher>,
        signer: &ExchangeSigner,
        sink: Arc<dyn KeySnapshotSink>,
        policy: RefreshPolicy,
    ) -> Result<Self, IdpKeySourcesError> {
        let mut providers = BTreeMap::new();
        let mut issuers = BTreeSet::new();
        for identity in identities {
            let provider = identity.provider_id.as_str().to_owned();
            if providers.contains_key(&provider) {
                return Err(IdpKeySourcesError::DuplicateProvider(provider));
            }
            if !issuers.insert(identity.issuer.as_str().to_owned()) {
                return Err(IdpKeySourcesError::DuplicateIssuer(
                    identity.issuer.as_str().to_owned(),
                ));
            }
            let keys = PinnedIdpKeys::from_provider(
                identity,
                Arc::clone(&fetcher),
                signer.clone(),
                Arc::clone(&sink),
                policy,
            )
            .map_err(|error| IdpKeySourcesError::Source {
                provider: provider.clone(),
                error,
            })?;
            providers.insert(
                provider,
                PinnedProvider {
                    identity: identity.clone(),
                    keys,
                },
            );
        }
        Ok(Self { providers })
    }

    /// The key source pinned for `provider_id`.
    #[must_use]
    pub fn get(&self, provider_id: &str) -> Option<&PinnedIdpKeys> {
        self.providers.get(provider_id).map(|pinned| &pinned.keys)
    }
}

fn exchange_error(error: KeyResolutionError) -> RootExchangeError {
    match error {
        KeyResolutionError::UnknownKid => RootExchangeError::UnknownKid,
        KeyResolutionError::KeyAlgorithmMismatch | KeyResolutionError::KeyTypeMismatch => {
            RootExchangeError::KeyAlgorithmMismatch
        }
        other => RootExchangeError::KeysUnavailable(other.to_string()),
    }
}

#[async_trait]
impl IdpKeyLookup for IdpKeySources {
    async fn resolve(
        &self,
        provider: &EnterpriseProviderIdentity,
        kid: &str,
        alg: JwsAlgorithm,
        now: u64,
    ) -> Result<IdpKey, RootExchangeError> {
        let provider_id = provider.provider_id.as_str();
        let pinned = self
            .providers
            .get(provider_id)
            .ok_or_else(|| RootExchangeError::ProviderRecordMissing(provider_id.to_owned()))?;
        if &pinned.identity != provider {
            return Err(RootExchangeError::ProviderIdentityMismatch(
                provider_id.to_owned(),
            ));
        }
        let resolved = pinned
            .keys
            .resolve(kid, alg, now)
            .await
            .map_err(exchange_error)?;
        let snapshot_digest = resolved
            .snapshot
            .digest()
            .map_err(|error| RootExchangeError::Canonicalization(error.to_string()))?;
        Ok(IdpKey {
            jwk: resolved.key,
            snapshot_digest,
        })
    }
}
