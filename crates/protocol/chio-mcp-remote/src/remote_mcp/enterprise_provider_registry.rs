//! The enterprise provider registry file, read once per use through the
//! control plane's bounded reader.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_control_plane::enterprise_federation::EnterpriseProviderRegistry;
use chio_control_plane::CliError;
use chio_core::canonical::{canonical_json_bytes, UntrustedJsonError};
use chio_core::crypto::sha256_hex;
use chio_errors::_generated::error_codes::CLI_IO;

/// The only source of provider identity: bearer admission and the resume
/// binding each read the file, and no parsed copy outlives one read.
#[derive(Clone, Debug)]
pub(crate) struct EnterpriseProviderRegistryFile {
    path: Arc<PathBuf>,
}

impl EnterpriseProviderRegistryFile {
    pub(crate) fn new(path: &Path) -> Self {
        Self {
            path: Arc::new(path.to_path_buf()),
        }
    }

    pub(crate) fn load(
        &self,
    ) -> Result<EnterpriseProviderRegistry, EnterpriseProviderRegistryRefusal> {
        EnterpriseProviderRegistry::load(&self.path)
            .map_err(EnterpriseProviderRegistryRefusal::from)
    }

    /// Digest of the registry as it reads now, over its canonical validated
    /// form, so any provider change yields a different digest.
    pub(crate) fn digest(&self) -> Result<String, EnterpriseProviderRegistryRefusal> {
        let encoded = canonical_json_bytes(&self.load()?)
            .map_err(|error| EnterpriseProviderRegistryRefusal::Invalid(error.into()))?;
        Ok(sha256_hex(&encoded))
    }
}

/// Why a read of the enterprise provider registry admitted nothing. The
/// message is the whole client-visible body; the cause stays local.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnterpriseProviderRegistryRefusal {
    #[error("enterprise provider registry is unreadable")]
    Unreadable(#[source] CliError),
    #[error("enterprise provider registry exceeds the bounded read limit")]
    Oversized(#[source] CliError),
    #[error("enterprise provider registry is invalid")]
    Invalid(#[source] CliError),
}

impl From<CliError> for EnterpriseProviderRegistryRefusal {
    fn from(cause: CliError) -> Self {
        match &cause {
            CliError::SignedJson(UntrustedJsonError::TooLarge { .. }) => Self::Oversized(cause),
            CliError::Chio(error) if error.code().as_str() == CLI_IO.urn => Self::Unreadable(cause),
            _ => Self::Invalid(cause),
        }
    }
}

impl From<EnterpriseProviderRegistryRefusal> for CliError {
    fn from(refusal: EnterpriseProviderRegistryRefusal) -> Self {
        match refusal {
            EnterpriseProviderRegistryRefusal::Unreadable(cause)
            | EnterpriseProviderRegistryRefusal::Oversized(cause)
            | EnterpriseProviderRegistryRefusal::Invalid(cause) => cause,
        }
    }
}
