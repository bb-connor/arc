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

use crate::RemoteClock;

/// A change to the file's last status change time later than this many
/// milliseconds lands on a later timestamp tick on every supported filesystem.
const SETTLE_MILLIS: u64 = 2_000;

/// The only source of provider identity: bearer admission and the resume
/// binding each read the file, and no parsed copy outlives one read. Only the
/// digest is kept, and only for the file identity it was read under.
#[derive(Clone, Debug)]
pub(crate) struct EnterpriseProviderRegistryFile {
    path: Arc<PathBuf>,
    /// The health last reported by `load_for_health`, shared by every clone.
    health: Arc<Mutex<RegistryHealth>>,
    /// The last settled digest, shared by every clone.
    digest_cache: Arc<Mutex<Option<CachedDigest>>>,
}

#[derive(Clone, Debug)]
struct CachedDigest {
    identity: FileIdentity,
    digest: String,
}

/// What one stat of the file observed. Every write, in place or by rename,
/// changes the inode or the status change time, which no writer can set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl FileIdentity {
    #[cfg(unix)]
    fn of(path: &Path) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path).ok()?;
        Some(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }

    #[cfg(not(unix))]
    fn of(_path: &Path) -> Option<Self> {
        None
    }

    /// True when the last status change is at least `SETTLE_MILLIS` before
    /// `now_millis`, so any later write yields a different identity.
    fn settled_at(&self, now_millis: u64) -> bool {
        let (seconds, nanos) = self.ctime;
        let (Ok(seconds), Ok(nanos)) = (u64::try_from(seconds), u64::try_from(nanos)) else {
            return false;
        };
        seconds
            .checked_mul(1_000)
            .and_then(|millis| millis.checked_add(nanos / 1_000_000))
            .and_then(|millis| millis.checked_add(SETTLE_MILLIS))
            .is_some_and(|settled| settled <= now_millis)
    }
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
            digest_cache: Arc::new(Mutex::new(None)),
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
    /// form, so any provider change yields a different digest. A digest is
    /// reused only while a stat shows the settled identity it was read under;
    /// a failed stat reads the file, so an unusable registry always refuses.
    pub(crate) fn digest(
        &self,
        clock: &RemoteClock,
    ) -> Result<String, EnterpriseProviderRegistryRefusal> {
        let before = FileIdentity::of(&self.path);
        if let Some(digest) = before.and_then(|identity| self.cached_digest(identity)) {
            return Ok(digest);
        }
        let digest = self.read_digest()?;
        if let (Some(identity), Ok(now)) = (before, clock.millis()) {
            if identity.settled_at(now) && FileIdentity::of(&self.path) == Some(identity) {
                self.store_digest(identity, &digest);
            }
        }
        Ok(digest)
    }

    fn cached_digest(&self, identity: FileIdentity) -> Option<String> {
        let cache = self.digest_cache.lock().ok()?;
        cache
            .as_ref()
            .filter(|cached| cached.identity == identity)
            .map(|cached| cached.digest.clone())
    }

    fn store_digest(&self, identity: FileIdentity, digest: &str) {
        if let Ok(mut cache) = self.digest_cache.lock() {
            *cache = Some(CachedDigest {
                identity,
                digest: digest.to_owned(),
            });
        }
    }

    fn read_digest(&self) -> Result<String, EnterpriseProviderRegistryRefusal> {
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
    use chio_security_types::clock::{
        Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis,
    };
    use std::io::Write as _;

    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn read(&self) -> Result<ClockReading, ClockError> {
            Ok(ClockReading::new(
                UnixMillis::new(self.0),
                MonotonicInstant::from_nanos(1),
            ))
        }
    }

    /// A clock reading `offset` milliseconds after the file's status change.
    fn clock_after_change(path: &Path, offset: u64) -> RemoteClock {
        let identity = FileIdentity::of(path).unwrap();
        let change = u64::try_from(identity.ctime.0).unwrap() * 1_000
            + u64::try_from(identity.ctime.1).unwrap() / 1_000_000;
        RemoteClock::new(Arc::new(FixedClock(change + offset)))
    }

    /// A one-provider registry; issuers of equal length give equal file lengths.
    fn registry_bytes(issuer: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "version": "chio.enterprise-providers.v1",
            "providers": {
                "enterprise-login": {
                    "provider_id": "enterprise-login",
                    "kind": "oidc_jwks",
                    "enabled": true,
                    "provenance": {
                        "configured_from": "manual",
                        "source_ref": "operator",
                        "trust_material_ref": "jwks:enterprise-login",
                        "subject_mapping_source": "manual"
                    },
                    "trust_boundary": {
                        "allowed_issuers": [issuer],
                        "allowed_tenants": ["tenant-123"],
                        "allowed_organizations": ["org-789"]
                    },
                    "issuer": issuer,
                    "jwks_url": "https://issuer.enterprise.example/jwks",
                    "tenant_id": "tenant-123",
                    "organization_id": "org-789",
                    "subject_mapping": {
                        "principal_source": "sub",
                        "tenant_id_field": "tid",
                        "organization_id_field": "org_id",
                        "groups_field": "groups",
                        "roles_field": "roles"
                    }
                }
            }
        }))
        .unwrap()
    }

    fn cached(file: &EnterpriseProviderRegistryFile) -> Option<String> {
        file.digest_cache
            .lock()
            .unwrap()
            .as_ref()
            .map(|cached| cached.digest.clone())
    }

    #[test]
    fn digest_is_kept_only_for_a_settled_identity() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        std::fs::write(&path, registry_bytes("https://issuer-a.example")).unwrap();
        let file = EnterpriseProviderRegistryFile::new(&path);

        let fresh = file
            .digest(&clock_after_change(&path, SETTLE_MILLIS - 1))
            .unwrap();
        assert_eq!(cached(&file), None, "an unsettled identity was cached");

        let settled = clock_after_change(&path, SETTLE_MILLIS);
        assert_eq!(file.digest(&settled).unwrap(), fresh);
        assert_eq!(cached(&file), Some(fresh.clone()));
        assert_eq!(file.clone().digest(&settled).unwrap(), fresh);
    }

    #[test]
    fn an_in_place_rewrite_with_the_same_length_and_mtime_is_read_again() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        let original = registry_bytes("https://issuer-a.example");
        let rewritten = registry_bytes("https://issuer-b.example");
        assert_eq!(original.len(), rewritten.len());
        std::fs::write(&path, &original).unwrap();
        let file = EnterpriseProviderRegistryFile::new(&path);
        let settled = clock_after_change(&path, SETTLE_MILLIS);
        let before = file.digest(&settled).unwrap();
        assert_eq!(cached(&file), Some(before.clone()));
        let admitted = FileIdentity::of(&path).unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();

        // The settle interval separates the rewrite from the admitted change.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut handle = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        handle.write_all(&rewritten).unwrap();
        handle.set_modified(modified).unwrap();
        drop(handle);
        let rewritten_identity = FileIdentity::of(&path).unwrap();
        assert_eq!(
            (rewritten_identity.dev, rewritten_identity.ino),
            (admitted.dev, admitted.ino)
        );
        assert_eq!(rewritten_identity.len, admitted.len);
        assert_eq!(rewritten_identity.mtime, admitted.mtime);

        let after = file.digest(&settled).unwrap();
        assert_ne!(
            after, before,
            "a rewrite under the cached identity was missed"
        );
        assert_eq!(
            after,
            EnterpriseProviderRegistryFile::new(&path)
                .digest(&RemoteClock::new(Arc::new(FixedClock(0))))
                .unwrap()
        );
    }

    #[test]
    fn a_removed_registry_refuses_after_a_cached_digest() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        std::fs::write(&path, registry_bytes("https://issuer-a.example")).unwrap();
        let file = EnterpriseProviderRegistryFile::new(&path);
        let settled = clock_after_change(&path, SETTLE_MILLIS);
        file.digest(&settled).unwrap();
        assert!(cached(&file).is_some());

        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            file.digest(&settled),
            Err(EnterpriseProviderRegistryRefusal::Unreadable(_))
        ));
    }

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
