//! Governed parent issuance and verification for the explicit broker host.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_control_plane::KeyringRuntimeComposition;
use chio_core_types::canonical_json_bytes;
use chio_core_types::capability::token::CapabilityToken;
use chio_keyring::{
    KeyLogPolicyDocument, KeyringArtifactSignature, SignedArtifactTimeAnchor,
    SqlitePinnedKeyLogVerifier, SystemTrustedClock,
};
use serde::{Deserialize, Serialize};

use super::state::error;
use crate::CliError;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    pub runtime_config: PathBuf,
    pub authority_seed_file: PathBuf,
    pub receipt_anchor_directory: PathBuf,
    pub verification_policy: KeyLogPolicyDocument,
}

impl Config {
    pub fn validate(&self) -> Result<(), CliError> {
        if !self.runtime_config.is_absolute()
            || !self.authority_seed_file.is_absolute()
            || !self.receipt_anchor_directory.is_absolute()
        {
            return Err(error("keyring host paths must be absolute"));
        }
        self.verification_policy
            .clone()
            .into_policy()
            .map_err(error)?;
        Ok(())
    }

    pub fn verifier(&self, path: &Path) -> Result<SqlitePinnedKeyLogVerifier, CliError> {
        SqlitePinnedKeyLogVerifier::open(
            path,
            self.verification_policy
                .clone()
                .into_policy()
                .map_err(error)?,
            Arc::new(SystemTrustedClock),
        )
        .map_err(|cause| error(format!("cannot open pinned key-log verifier: {cause}")))
    }
}

pub(super) struct HostKeyring {
    pub runtime: KeyringRuntimeComposition,
    pub verifier: SqlitePinnedKeyLogVerifier,
}

impl HostKeyring {
    pub fn authority(&self) -> Result<Box<dyn chio_kernel::CapabilityAuthority>, CliError> {
        Ok(Box::new(ParentAuthority {
            inner: self.runtime.capability_authority()?,
            verification_keys: self.runtime.authority_status()?.witnessed_verification_keys,
        }))
    }

    pub fn open(config: &Config, directory: &Path, initializing: bool) -> Result<Self, CliError> {
        config.validate()?;
        // This loader completes an existing rotation handoff or refuses a stale
        // seed. Never replace governed signing with the host's receipt key.
        let (_, runtime) = chio_control_plane::load_keyring_runtime_from_authority_seed(
            &config.runtime_config,
            &config.authority_seed_file,
        )?;
        runtime.startup_readiness()?;
        let path = directory.join("keylog-verifier.db");
        let verifier = if initializing {
            SqlitePinnedKeyLogVerifier::provision(
                &path,
                config
                    .verification_policy
                    .clone()
                    .into_policy()
                    .map_err(error)?,
                Arc::new(SystemTrustedClock),
            )
            .map_err(error)?
        } else {
            config.verifier(&path)?
        };
        let base = verifier.pin().map_err(error)?;
        verifier
            .apply_sync(&runtime.key_log_synchronization_response(base.as_ref())?)
            .map_err(error)?;
        // Preserve the original audit signer. These authority receipts cannot
        // enter the kernel's single-signer call checkpoint stream.
        let receipts = Arc::new(
            chio_store_sqlite::SqliteReceiptStore::open_for_finding_pool(
                directory.join("keyring-receipts.db"),
                &config.receipt_anchor_directory,
            )?,
        );
        receipts.wait_for_writer_ready(std::time::Duration::from_secs(30))?;
        runtime.attach_receipt_store(receipts)?;
        Ok(Self { runtime, verifier })
    }

    pub fn evidence(&self, capability: &CapabilityToken) -> Result<Evidence, CliError> {
        let original = self.runtime.capability_signing_evidence(capability)?;
        let evidence = Evidence {
            signature: original.evidence,
            time_anchor: original
                .time_anchor
                .ok_or_else(|| error("governed capability has no original trusted-time anchor"))?,
        };
        evidence.verify(capability, &self.verifier)?;
        Ok(evidence)
    }
}

struct ParentAuthority {
    inner: chio_kernel::GovernedCapabilityAuthority,
    verification_keys: Vec<chio_core_types::PublicKey>,
}

impl chio_kernel::CapabilityAuthority for ParentAuthority {
    fn authority_public_key(&self) -> chio_core_types::PublicKey {
        self.inner.authority_public_key()
    }

    fn trusted_public_keys(&self) -> Vec<chio_core_types::PublicKey> {
        self.verification_keys.clone()
    }

    fn issue_capability(
        &self,
        subject: &chio_core_types::PublicKey,
        scope: chio_core_types::capability::scope::ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.inner.issue_capability(subject, scope, ttl_seconds)
    }

    fn issue_aggregate_family_root(
        &self,
        subject: &chio_core_types::PublicKey,
        scope: chio_core_types::capability::scope::ChioScope,
        ttl_seconds: u64,
        max_invocations: u32,
    ) -> Result<CapabilityToken, chio_kernel::KernelError> {
        self.inner
            .issue_aggregate_family_root(subject, scope, ttl_seconds, max_invocations)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    signature: KeyringArtifactSignature,
    time_anchor: SignedArtifactTimeAnchor,
}

impl Evidence {
    pub fn verify(
        &self,
        capability: &CapabilityToken,
        verifier: &SqlitePinnedKeyLogVerifier,
    ) -> Result<(), CliError> {
        capability.validate_schema().map_err(error)?;
        let key = verifier
            .verify_artifact_signing_evidence(
                &canonical_json_bytes(&capability.signing_body()).map_err(error)?,
                &self.signature,
                &self.time_anchor,
            )
            .map_err(error)?;
        if key.public_key != capability.issuer
            || self.signature.artifact_signature != capability.signature
            || capability
                .issued_at
                .checked_mul(1000)
                .is_none_or(|issued| self.time_anchor.body.anchored_at < issued)
            || capability
                .expires_at
                .checked_mul(1000)
                .is_none_or(|expires| self.time_anchor.body.anchored_at >= expires)
        {
            return Err(error(
                "keyring evidence differs from the original capability signature",
            ));
        }
        Ok(())
    }
}
