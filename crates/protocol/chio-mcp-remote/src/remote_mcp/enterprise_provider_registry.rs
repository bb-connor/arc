//! The enterprise provider registry file, read once per use through the
//! control plane's bounded reader.

use std::error::Error as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chio_control_plane::enterprise_federation::EnterpriseProviderRegistry;
use chio_control_plane::CliError;
use chio_core::canonical::{canonical_json_bytes, UntrustedJsonError};
use chio_core::crypto::sha256_hex;
use chio_errors::_generated::error_codes::{
    CLI_IO, CLI_JSON, TRANSPORT_PROVIDER_REGISTRY_INVALID, TRANSPORT_PROVIDER_REGISTRY_OVERSIZED,
    TRANSPORT_PROVIDER_REGISTRY_UNREADABLE,
};
use tracing::{info, warn};

use crate::RemoteClock;

#[path = "enterprise_provider_scope.rs"]
mod scope;
pub(crate) use scope::RegistryDigestScope;

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
    scope: RegistryDigestScope,
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

    /// Digest of registry globals and the validated provider selection cohort.
    /// A cached digest binds the complete selection scope and the settled file
    /// identity; a failed stat reads the file and preserves reader refusals.
    pub(crate) fn digest(
        &self,
        scope: &RegistryDigestScope,
        clock: &RemoteClock,
    ) -> Result<String, EnterpriseProviderRegistryRefusal> {
        let before = FileIdentity::of(&self.path);
        if let Some(digest) = before.and_then(|identity| self.cached_digest(identity, scope)) {
            return Ok(digest);
        }
        let digest = self.read_digest(scope)?;
        if let (Some(identity), Ok(now)) = (before, clock.millis()) {
            if identity.settled_at(now) && FileIdentity::of(&self.path) == Some(identity) {
                self.store_digest(identity, scope, &digest);
            }
        }
        Ok(digest)
    }

    fn cached_digest(&self, identity: FileIdentity, scope: &RegistryDigestScope) -> Option<String> {
        let cache = self.digest_cache.lock().ok()?;
        cache
            .as_ref()
            .filter(|cached| cached.identity == identity && &cached.scope == scope)
            .map(|cached| cached.digest.clone())
    }

    fn store_digest(&self, identity: FileIdentity, scope: &RegistryDigestScope, digest: &str) {
        if let Ok(mut cache) = self.digest_cache.lock() {
            *cache = Some(CachedDigest {
                identity,
                scope: scope.clone(),
                digest: digest.to_owned(),
            });
        }
    }

    fn read_digest(
        &self,
        scope: &RegistryDigestScope,
    ) -> Result<String, EnterpriseProviderRegistryRefusal> {
        self.read()
            .and_then(|mut registry| {
                if scope
                    .selected_provider()
                    .is_some_and(|id| !registry.providers.contains_key(id))
                {
                    return Err(EnterpriseProviderRegistryRefusal::Invalid(
                        CliError::cli_other_error("session enterprise provider record is absent"),
                    ));
                }
                scope.retain_cohort(&mut registry);
                canonical_json_bytes(&("enterprise-provider-selection", scope, &registry))
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
/// message is the whole peer-visible text, a registered URN; the cause stays
/// local.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnterpriseProviderRegistryRefusal {
    #[error("{}", TRANSPORT_PROVIDER_REGISTRY_UNREADABLE.urn)]
    Unreadable(#[source] CliError),
    #[error("{}", TRANSPORT_PROVIDER_REGISTRY_OVERSIZED.urn)]
    Oversized(#[source] CliError),
    #[error("{}", TRANSPORT_PROVIDER_REGISTRY_INVALID.urn)]
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn each_refusal_answers_its_registered_urn() {
        let cause = || CliError::cli_io_error("/srv/chio/enterprise-providers.json");
        for (refusal, urn, string_code) in [
            (
                EnterpriseProviderRegistryRefusal::Unreadable(cause()),
                "urn:chio:error:transport:provider-registry-unreadable",
                "CHIO-TRANSPORT-PROVIDER-REGISTRY-UNREADABLE",
            ),
            (
                EnterpriseProviderRegistryRefusal::Oversized(cause()),
                "urn:chio:error:transport:provider-registry-oversized",
                "CHIO-TRANSPORT-PROVIDER-REGISTRY-OVERSIZED",
            ),
            (
                EnterpriseProviderRegistryRefusal::Invalid(cause()),
                "urn:chio:error:transport:provider-registry-invalid",
                "CHIO-TRANSPORT-PROVIDER-REGISTRY-INVALID",
            ),
        ] {
            assert_eq!(refusal.to_string(), urn);
            let spec = chio_errors::lookup_error_code(urn).unwrap();
            assert_eq!(spec.domain, chio_errors::Domain::Transport);
            assert_eq!(spec.severity, chio_errors::Severity::Error);
            assert_eq!(spec.string_code, string_code);
            assert!(spec.consumed_by.contains(&"chio-mcp-remote"));
        }
    }

    fn test_scope(selected: Option<&str>) -> RegistryDigestScope {
        match selected {
            Some(id) => RegistryDigestScope::OAuth {
                issuer: Some("https://issuer-a.example".to_string()),
                provider_kind: Some("oidc_jwks".to_string()),
                selected_provider: Some(id.to_string()),
            },
            None => RegistryDigestScope::Globals,
        }
    }

    #[test]
    fn digest_is_kept_only_for_a_settled_identity() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        std::fs::write(&path, registry_bytes("https://issuer-a.example")).unwrap();
        let file = EnterpriseProviderRegistryFile::new(&path);

        let fresh = file
            .digest(
                &test_scope(Some("enterprise-login")),
                &clock_after_change(&path, SETTLE_MILLIS - 1),
            )
            .unwrap();
        assert_eq!(cached(&file), None, "an unsettled identity was cached");

        let settled = clock_after_change(&path, SETTLE_MILLIS);
        assert_eq!(
            file.digest(&test_scope(Some("enterprise-login")), &settled)
                .unwrap(),
            fresh
        );
        assert_eq!(cached(&file), Some(fresh.clone()));
        assert_eq!(
            file.clone()
                .digest(&test_scope(Some("enterprise-login")), &settled)
                .unwrap(),
            fresh
        );
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
        let before = file
            .digest(&test_scope(Some("enterprise-login")), &settled)
            .unwrap();
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

        let after = file
            .digest(&test_scope(Some("enterprise-login")), &settled)
            .unwrap();
        assert_ne!(
            after, before,
            "a rewrite under the cached identity was missed"
        );
        assert_eq!(
            after,
            EnterpriseProviderRegistryFile::new(&path)
                .digest(
                    &test_scope(Some("enterprise-login")),
                    &RemoteClock::new(Arc::new(FixedClock(0)))
                )
                .unwrap()
        );
    }

    /// A digest of `path` read by a handle that holds no cached entry.
    fn fresh_digest(path: &Path) -> String {
        EnterpriseProviderRegistryFile::new(path)
            .digest(
                &test_scope(Some("enterprise-login")),
                &RemoteClock::new(Arc::new(FixedClock(0))),
            )
            .unwrap()
    }

    #[test]
    fn a_rename_replace_with_the_same_length_and_mtime_is_read_again() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        let staged = directory.path().join("enterprise-providers.json.next");
        let original = registry_bytes("https://issuer-a.example");
        let replacement = registry_bytes("https://issuer-b.example");
        assert_eq!(original.len(), replacement.len());
        std::fs::write(&path, &original).unwrap();
        let file = EnterpriseProviderRegistryFile::new(&path);
        let settled = clock_after_change(&path, SETTLE_MILLIS);
        let before = file
            .digest(&test_scope(Some("enterprise-login")), &settled)
            .unwrap();
        assert_eq!(cached(&file), Some(before.clone()));
        let admitted = FileIdentity::of(&path).unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();

        std::fs::write(&staged, &replacement).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&staged)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        std::fs::rename(&staged, &path).unwrap();
        let replaced = FileIdentity::of(&path).unwrap();
        assert_ne!(replaced.ino, admitted.ino);
        assert_eq!(
            (replaced.dev, replaced.len, replaced.mtime),
            (admitted.dev, admitted.len, admitted.mtime)
        );

        let after = file
            .digest(&test_scope(Some("enterprise-login")), &settled)
            .unwrap();
        assert_ne!(
            after, before,
            "a rename-replace under the cached digest was missed"
        );
        assert_eq!(after, fresh_digest(&path));
    }

    #[test]
    fn a_delete_and_recreate_within_one_second_is_read_again() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        let original = registry_bytes("https://issuer-a.example");
        let recreated = registry_bytes("https://issuer-b.example");
        assert_eq!(original.len(), recreated.len());
        std::fs::write(&path, &original).unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let settled = clock_after_change(&path, SETTLE_MILLIS);
        // A cached identity is at least the settle interval old, so its
        // ctime differs from any later write whether or not the inode is reused.
        std::thread::sleep(std::time::Duration::from_millis(SETTLE_MILLIS + 100));
        let file = EnterpriseProviderRegistryFile::new(&path);
        let before = file
            .digest(&test_scope(Some("enterprise-login")), &settled)
            .unwrap();
        assert_eq!(cached(&file), Some(before.clone()));
        let admitted = FileIdentity::of(&path).unwrap();

        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, &recreated).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
        let recreated_identity = FileIdentity::of(&path).unwrap();
        assert_eq!(
            (recreated_identity.len, recreated_identity.mtime),
            (admitted.len, admitted.mtime)
        );
        assert_ne!(recreated_identity.ctime, admitted.ctime);

        let after = file
            .digest(&test_scope(Some("enterprise-login")), &settled)
            .unwrap();
        assert_ne!(
            after, before,
            "a recreated registry under the cached digest was missed"
        );
        assert_eq!(after, fresh_digest(&path));
    }

    #[test]
    fn a_removed_registry_refuses_after_a_cached_digest() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        std::fs::write(&path, registry_bytes("https://issuer-a.example")).unwrap();
        let file = EnterpriseProviderRegistryFile::new(&path);
        let settled = clock_after_change(&path, SETTLE_MILLIS);
        file.digest(&test_scope(Some("enterprise-login")), &settled)
            .unwrap();
        assert!(cached(&file).is_some());

        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            file.digest(&test_scope(Some("enterprise-login")), &settled),
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

    #[test]
    fn settled_digest_cache_is_scoped_to_each_provider_and_registry_globals() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        let mut registry: serde_json::Value =
            serde_json::from_slice(&registry_bytes("https://issuer-a.example")).unwrap();
        let mut other = registry["providers"]["enterprise-login"].clone();
        other["provider_id"] = serde_json::json!("other-login");
        registry["providers"]["other-login"] = other;
        std::fs::write(&path, serde_json::to_vec(&registry).unwrap()).unwrap();
        let clock = clock_after_change(&path, SETTLE_MILLIS);
        let file = EnterpriseProviderRegistryFile::new(&path);
        let first = file
            .digest(&test_scope(Some("enterprise-login")), &clock)
            .unwrap();
        let other = file
            .digest(&test_scope(Some("other-login")), &clock)
            .unwrap();
        let globals = file.digest(&test_scope(None), &clock).unwrap();
        assert_ne!(first, other);
        assert_ne!(first, globals);
        assert_ne!(other, globals);
        for (selection, expected) in [
            (Some("other-login"), other),
            (Some("enterprise-login"), first),
            (None, globals),
        ] {
            assert_eq!(
                file.digest(&test_scope(selection), &clock).unwrap(),
                expected
            );
            assert_eq!(
                file.clone().digest(&test_scope(selection), &clock).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn a_missing_selected_provider_refuses_even_with_a_settled_cached_digest() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        std::fs::write(&path, registry_bytes("https://issuer-a.example")).unwrap();
        let clock = clock_after_change(&path, SETTLE_MILLIS);
        let file = EnterpriseProviderRegistryFile::new(&path);
        file.digest(&test_scope(Some("enterprise-login")), &clock)
            .unwrap();
        let error = file
            .digest(&test_scope(Some("missing-login")), &clock)
            .unwrap_err();
        assert!(matches!(
            error,
            EnterpriseProviderRegistryRefusal::Invalid(_)
        ));
        assert_eq!(
            error.to_string(),
            "urn:chio:error:transport:provider-registry-invalid"
        );
        file.digest(&test_scope(None), &clock).unwrap();
    }
    #[test]
    fn oauth_cohort_cache_binds_issuer_kind_and_empty_selection() {
        let directory = chio_test_support::private_tempdir().unwrap();
        let path = directory.path().join("enterprise-providers.json");
        std::fs::write(&path, registry_bytes("https://issuer-a.example/")).unwrap();
        let clock = clock_after_change(&path, SETTLE_MILLIS);
        let file = EnterpriseProviderRegistryFile::new(&path);
        let oauth = |issuer: &str, kind: &str| RegistryDigestScope::OAuth {
            issuer: Some(crate::canonicalize_federated_issuer(issuer)),
            provider_kind: Some(kind.to_string()),
            selected_provider: None,
        };
        let selected = oauth("https://issuer-a.example", "oidc_jwks");
        let equivalent = oauth("https://issuer-a.example/", "oidc_jwks");
        let other_issuer = oauth("https://issuer-b.example", "oidc_jwks");
        let other_kind = oauth("https://issuer-a.example", "oauth_introspection");
        let first = file.digest(&selected, &clock).unwrap();
        assert_eq!(file.digest(&equivalent, &clock).unwrap(), first);
        let scopes = [RegistryDigestScope::Globals, other_issuer, other_kind];
        let mut digests = vec![first.clone()];
        for scope in &scopes {
            let digest = file.digest(scope, &clock).unwrap();
            assert!(!digests.contains(&digest));
            digests.push(digest);
            assert_eq!(file.digest(&selected, &clock).unwrap(), first);
        }
        let mut registry: serde_json::Value =
            serde_json::from_slice(&registry_bytes("https://issuer-a.example/")).unwrap();
        registry["providers"]["enterprise-login"]["enabled"] = false.into();
        std::fs::write(&path, serde_json::to_vec(&registry).unwrap()).unwrap();
        assert_ne!(file.digest(&selected, &clock).unwrap(), first);
        for (scope, expected) in scopes.iter().zip(&digests[1..]) {
            assert_eq!(file.digest(scope, &clock).unwrap(), *expected);
        }
    }
}
