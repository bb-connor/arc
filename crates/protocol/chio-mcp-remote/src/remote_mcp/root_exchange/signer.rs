//! The exchange signer: the key that signs anchored roots and IdP key
//! snapshots.
//!
//! [`ExchangeSigner`] is closed. `SeedFile` holds a local Ed25519 key read
//! from a seed file with private custody (a regular, singly linked file of
//! this user, mode 0600 or stricter); any other file refuses at load. Roots
//! sign through the capability token's own signing method and snapshots
//! through `IdpKeySnapshot`'s, both on the signing wrapper, and every
//! signature is verified against the signer's key before the artifact is
//! returned. No path falls back to a generated key.

use std::path::Path;
use std::sync::Arc;

use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody, CHIO_CAPABILITY_SCHEMA};
use chio_core::crypto::{
    sign_wrapped_for_identity, verify_wrapped, Ed25519Backend, PublicKey, SigningBackend,
};
use chio_core::root_authority::idp_key_snapshot::IdpKeySnapshotSigningBody;
use chio_core::root_authority::{
    IdpKeySnapshot, IdpKeySnapshotFields, Jwk, KeySnapshotSource, Uri, CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
};

use crate::idp_keys::{KeyResolutionError, SnapshotNotSigned};

/// Why the exchange signer refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeSignerError {
    #[error("exchange signer seed file is refused: {0}")]
    SeedFileRefused(String),
    #[error("root issuer is not the exchange key")]
    IssuerNotExchangeKey,
    #[error("exchange signer could not sign the root")]
    RootNotSigned,
    #[error("signed root does not verify under the exchange key")]
    RootSignatureInvalid,
}

/// The exchange signing backend.
#[derive(Clone)]
pub enum ExchangeSigner {
    /// A local Ed25519 key from a private seed file.
    SeedFile(SeedFileSigner),
}

/// The backend a seed file yields and the exchange key it signs as.
#[derive(Clone)]
pub struct SeedFileSigner {
    backend: Arc<dyn SigningBackend>,
    key: PublicKey,
}

impl ExchangeSigner {
    /// Load the seed file at `path` under the authority seed custody rules.
    pub fn seed_file(path: &Path) -> Result<Self, ExchangeSignerError> {
        let keypair = chio_control_plane::load_existing_authority_keypair(path)
            .map_err(|error| ExchangeSignerError::SeedFileRefused(error.to_string()))?;
        let key = keypair.public_key();
        Ok(Self::SeedFile(SeedFileSigner {
            backend: Arc::new(Ed25519Backend::new(keypair)),
            key,
        }))
    }

    /// A seed-file signer over `backend`, for tests that need a backend
    /// which fails or signs under another key.
    #[cfg(test)]
    pub(crate) fn seed_file_backend(backend: Arc<dyn SigningBackend>, key: PublicKey) -> Self {
        Self::SeedFile(SeedFileSigner { backend, key })
    }

    /// The exchange key every artifact is signed as.
    #[must_use]
    pub fn key(&self) -> &PublicKey {
        match self {
            Self::SeedFile(signer) => &signer.key,
        }
    }

    fn backend(&self) -> &dyn SigningBackend {
        match self {
            Self::SeedFile(signer) => signer.backend.as_ref(),
        }
    }

    /// Sign an anchored root body whose issuer is the exchange key.
    pub fn sign_root(
        &self,
        body: CapabilityTokenBody,
    ) -> Result<CapabilityToken, ExchangeSignerError> {
        if &body.issuer != self.key() {
            return Err(ExchangeSignerError::IssuerNotExchangeKey);
        }
        let root = CapabilityToken::sign_with_backend(body, self.backend())
            .map_err(|_| ExchangeSignerError::RootNotSigned)?;
        verify_wrapped(
            self.key(),
            CHIO_CAPABILITY_SCHEMA,
            &root.signing_body(),
            &root.signature,
        )
        .map_err(|_| ExchangeSignerError::RootSignatureInvalid)?;
        Ok(root)
    }

    /// Sign a `chio.idp-key-snapshot.v1` over `keys` as observed at `observed_at`.
    pub fn sign_snapshot(
        &self,
        issuer: &Uri,
        source: &KeySnapshotSource,
        keys: Vec<Jwk>,
        observed_at: u64,
    ) -> Result<IdpKeySnapshot, KeyResolutionError> {
        let key = self.key();
        let (outcome, _) = sign_wrapped_for_identity(
            self.backend(),
            key,
            CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
            &IdpKeySnapshotSigningBody {
                schema: CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
                issuer,
                source,
                keys: &keys,
                observed_at,
                exchange_key: key,
            },
        )
        .map_err(|_| SnapshotNotSigned)?;
        let snapshot = IdpKeySnapshot::new(IdpKeySnapshotFields {
            schema: CHIO_IDP_KEY_SNAPSHOT_SCHEMA.to_owned(),
            issuer: issuer.clone(),
            source: source.clone(),
            keys,
            observed_at,
            exchange_key: key.clone(),
            signature: outcome.signature,
        })
        .map_err(KeyResolutionError::SnapshotInvalid)?;
        snapshot
            .verify_signature(key)
            .map_err(|_| SnapshotNotSigned)?;
        Ok(snapshot)
    }
}
