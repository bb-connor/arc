//! The enterprise provider registry file, read once per use through the
//! control plane's bounded reader.

use std::error::Error as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_control_plane::enterprise_federation::EnterpriseProviderRegistry;
use chio_control_plane::CliError;
use chio_core::canonical::{canonical_json_bytes, UntrustedJsonError};
use chio_core::crypto::sha256_hex;
use chio_errors::_generated::error_codes::{CLI_IO, CLI_JSON};
use tracing::{info, warn};

/// The only source of provider identity: bearer admission and the resume
/// binding each read the file, and no parsed copy outlives one read.
#[derive(Clone, Debug)]
pub(crate) struct EnterpriseProviderRegistryFile {
    path: Arc<PathBuf>,
    /// The health last reported by `load_for_health`, shared by every clone.
    health: Arc<Mutex<RegistryHealth>>,
}

/// What one registry read observed; health polling logs only its changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistryHealth {
    Readable,
    Unreadable,
    Oversized,
    Invalid,
}

impl EnterpriseProviderRegistryFile {
    /// Startup has validated the file, so its first reported health is readable.
    pub(crate) fn new(path: &Path) -> Self {
        Self {
            path: Arc::new(path.to_path_buf()),
            health: Arc::new(Mutex::new(RegistryHealth::Readable)),
        }
    }

    fn read(&self) -> Result<EnterpriseProviderRegistry, EnterpriseProviderRegistryRefusal> {
        EnterpriseProviderRegistry::load(&self.path)
            .map_err(EnterpriseProviderRegistryRefusal::from)
    }

    /// Every refused admission or binding read is logged once with its local
    /// cause; callers send only the refusal message to peers.
    pub(crate) fn load(
        &self,
    ) -> Result<EnterpriseProviderRegistry, EnterpriseProviderRegistryRefusal> {
        self.read()
            .map_err(EnterpriseProviderRegistryRefusal::logged)
    }

    /// Digest of the registry as it reads now, over its canonical validated
    /// form, so any provider change yields a different digest.
    pub(crate) fn digest(&self) -> Result<String, EnterpriseProviderRegistryRefusal> {
        self.read()
            .and_then(|registry| {
                canonical_json_bytes(&registry)
                    .map_err(|error| EnterpriseProviderRegistryRefusal::Invalid(error.into()))
            })
            .map(|encoded| sha256_hex(&encoded))
            .map_err(EnterpriseProviderRegistryRefusal::logged)
    }

    /// A health poll reads like `load` but logs only a change of health.
    pub(crate) fn load_for_health(
        &self,
    ) -> Result<EnterpriseProviderRegistry, EnterpriseProviderRegistryRefusal> {
        let result = self.read();
        let observed = match &result {
            Ok(_) => RegistryHealth::Readable,
            Err(refusal) => refusal.health(),
        };
        if self.record_health(observed) {
            match &result {
                Ok(_) => info!("enterprise provider registry is readable again"),
                Err(refusal) => refusal.log(),
            }
        }
        result
    }

    /// Records `observed` and reports whether it differs from the last report.
    fn record_health(&self, observed: RegistryHealth) -> bool {
        match self.health.lock() {
            Ok(mut last) => std::mem::replace(&mut *last, observed) != observed,
            Err(_) => true,
        }
    }
}

/// Why a read of the enterprise provider registry admitted nothing. The
/// message is the whole peer-visible text; the cause stays local.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnterpriseProviderRegistryRefusal {
    #[error("enterprise provider registry is unreadable")]
    Unreadable(#[source] CliError),
    #[error("enterprise provider registry exceeds the bounded read limit")]
    Oversized(#[source] CliError),
    #[error("enterprise provider registry is invalid")]
    Invalid(#[source] CliError),
}

impl EnterpriseProviderRegistryRefusal {
    fn log(&self) {
        warn!(refusal = %self, cause = %self.cause(), "enterprise provider registry read refused");
    }

    fn logged(self) -> Self {
        self.log();
        self
    }

    fn health(&self) -> RegistryHealth {
        match self {
            Self::Unreadable(_) => RegistryHealth::Unreadable,
            Self::Oversized(_) => RegistryHealth::Oversized,
            Self::Invalid(_) => RegistryHealth::Invalid,
        }
    }

    pub(crate) fn cause(&self) -> &CliError {
        match self {
            Self::Unreadable(cause) | Self::Oversized(cause) | Self::Invalid(cause) => cause,
        }
    }

    /// The local cause, for operator-facing startup errors only.
    pub(crate) fn into_cause(self) -> CliError {
        match self {
            Self::Unreadable(cause) | Self::Oversized(cause) | Self::Invalid(cause) => cause,
        }
    }

    /// The refusal carried anywhere in `error`'s source chain.
    pub(crate) fn find(error: &CliError) -> Option<&Self> {
        let mut source: Option<&(dyn std::error::Error + 'static)> = error.source();
        while let Some(current) = source {
            if let Some(refusal) = current.downcast_ref::<Self>() {
                return Some(refusal);
            }
            source = current.source();
        }
        None
    }
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

/// Carries the refusal as a private, downcastable source: the error's text is
/// its registry code, never the cause, which names the registry path.
impl From<EnterpriseProviderRegistryRefusal> for CliError {
    fn from(refusal: EnterpriseProviderRegistryRefusal) -> Self {
        let spec = match refusal {
            EnterpriseProviderRegistryRefusal::Unreadable(_) => &CLI_IO,
            EnterpriseProviderRegistryRefusal::Oversized(_)
            | EnterpriseProviderRegistryRefusal::Invalid(_) => &CLI_JSON,
        };
        CliError::with_source(spec, refusal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_polling_reports_only_changes() {
        let file = EnterpriseProviderRegistryFile::new(Path::new("enterprise-providers.json"));
        let observed = [
            (RegistryHealth::Readable, false),
            (RegistryHealth::Unreadable, true),
            (RegistryHealth::Unreadable, false),
            (RegistryHealth::Oversized, true),
            (RegistryHealth::Invalid, true),
            (RegistryHealth::Invalid, false),
            (RegistryHealth::Readable, true),
            (RegistryHealth::Readable, false),
        ];
        for (health, changed) in observed {
            assert_eq!(file.record_health(health), changed, "{health:?}");
        }
        assert!(
            !file.clone().record_health(RegistryHealth::Readable),
            "a clone kept its own health"
        );
    }
}
