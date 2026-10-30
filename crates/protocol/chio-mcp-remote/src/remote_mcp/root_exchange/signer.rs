//! The exchange signer: the key that signs anchored roots and IdP key
//! snapshots.
//!
//! The binary that owns the key custody builds the signing backend and hands
//! it to [`ExchangeSigner::new`]; this crate opens no key material. The
//! exchange key is the key the backend reports. Roots sign through the
//! capability token's own signing method and snapshots through
//! `IdpKeySnapshot`'s, both on the signing wrapper, and both signing paths
//! verify the signature under the exchange key before the artifact exists.
//! No path falls back to a generated key.

use std::sync::Arc;

use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::{sign_wrapped_for_identity, PublicKey, SigningBackend};
use chio_core::root_authority::idp_key_snapshot::IdpKeySnapshotSigningBody;
use chio_core::root_authority::{
    IdpKeySnapshot, IdpKeySnapshotFields, Jwk, KeySnapshotSource, Uri, CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
};

use crate::idp_keys::{KeyResolutionError, SnapshotNotSigned};

/// Why the exchange signer refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeSignerError {
    #[error("exchange signing backend cannot report its key")]
    BackendKeyUnavailable,
    #[error("root issuer is not the exchange key")]
    IssuerNotExchangeKey,
    #[error("exchange signer could not sign the root")]
    RootNotSigned,
}

/// The exchange signing backend and the exchange key it signs as.
#[derive(Clone)]
pub struct ExchangeSigner {
    backend: Arc<dyn SigningBackend>,
    key: PublicKey,
}

impl std::fmt::Debug for ExchangeSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExchangeSigner")
            .field("key", &self.key.to_hex())
            .finish_non_exhaustive()
    }
}

impl ExchangeSigner {
    /// Sign as the key `backend` reports.
    pub fn new(backend: Arc<dyn SigningBackend>) -> Result<Self, ExchangeSignerError> {
        let key = backend
            .public_key()
            .map_err(|_| ExchangeSignerError::BackendKeyUnavailable)?;
        Ok(Self { backend, key })
    }

    /// The exchange key every artifact is signed as.
    #[must_use]
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// Sign an anchored root body whose issuer is the exchange key.
    pub fn sign_root(
        &self,
        body: CapabilityTokenBody,
    ) -> Result<CapabilityToken, ExchangeSignerError> {
        if body.issuer != self.key {
            return Err(ExchangeSignerError::IssuerNotExchangeKey);
        }
        CapabilityToken::sign_with_backend(body, self.backend.as_ref())
            .map_err(|_| ExchangeSignerError::RootNotSigned)
    }

    /// Sign a `chio.idp-key-snapshot.v1` over `keys` as observed at `observed_at`.
    pub fn sign_snapshot(
        &self,
        issuer: &Uri,
        source: &KeySnapshotSource,
        keys: Vec<Jwk>,
        observed_at: u64,
    ) -> Result<IdpKeySnapshot, KeyResolutionError> {
        let (outcome, _) = sign_wrapped_for_identity(
            self.backend.as_ref(),
            &self.key,
            CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
            &IdpKeySnapshotSigningBody {
                schema: CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
                issuer,
                source,
                keys: &keys,
                observed_at,
                exchange_key: &self.key,
            },
        )
        .map_err(|_| SnapshotNotSigned)?;
        IdpKeySnapshot::new(IdpKeySnapshotFields {
            schema: CHIO_IDP_KEY_SNAPSHOT_SCHEMA.to_owned(),
            issuer: issuer.clone(),
            source: source.clone(),
            keys,
            observed_at,
            exchange_key: self.key.clone(),
            signature: outcome.signature,
        })
        .map_err(KeyResolutionError::SnapshotInvalid)
    }
}
