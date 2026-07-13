use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_core_types::{canonical_json_bytes, PublicKey};
use serde::{Deserialize, Serialize};

use crate::authority_ipc::{
    AuthorityRpcClient, AuthorityRpcClientConfig, BrokerAdmissionAuthority,
};
use crate::budget::BrokerExecutionBudget;
use crate::daemon::{BrokerDaemonHandler, SystemDaemonClock};
use crate::generic_https::GenericHttpsExecutor;
use crate::provider::{CredentialPlacement, GenericCredentialProvider};
use crate::provision::{GovernedAdminAuthorizer, GovernedAdminPolicy, SystemAdminClock};
use crate::receipt::SqliteBrokerReceiptSink;
use crate::revocation::{BrokerRevocations, CapabilityLiveness};
#[cfg(unix)]
use crate::service::UnixBrokerEndpoint;
use crate::service::{BrokerIpcHandler, BrokerService, BrokerServiceConfig};
use crate::sqlite::SqliteAttemptStore;
use crate::{
    validate_identifier, BrokerError, EncryptedBlobSecretBackend, Result, SealedKeyFd,
    SealedSigningKeyFd,
};

pub const BROKER_DAEMON_CONFIG_SCHEMA: &str = "chio.secret-brokerd.runtime-config.v1";
const MAX_CONFIG_BYTES: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPlacementConfig {
    BearerAuthorization,
    ApiKeyHeader,
}

impl ProviderPlacementConfig {
    fn into_placement(self) -> CredentialPlacement {
        match self {
            Self::BearerAuthorization => CredentialPlacement::BearerAuthorization,
            Self::ApiKeyHeader => CredentialPlacement::ApiKeyHeader,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDaemonDatabaseConfig {
    pub secret_database_path: PathBuf,
    pub attempt_database_path: PathBuf,
    pub admin_replay_database_path: PathBuf,
    pub receipt_database_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDaemonAdminConfig {
    pub trusted_approvers: Vec<PublicKey>,
    pub subject: PublicKey,
    pub threshold: usize,
    pub maximum_token_lifetime_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerDaemonConfig {
    pub schema: String,
    pub tenant_scope: String,
    pub ipc_socket_path: PathBuf,
    pub authority_socket_path: PathBuf,
    pub trusted_capability_issuer: PublicKey,
    pub trusted_authority: PublicKey,
    pub broker_identity: PublicKey,
    pub broker_audience: String,
    pub parent_audience: String,
    pub provider_adapter_id: String,
    pub provider_adapter_version: u32,
    pub provider_placement: ProviderPlacementConfig,
    pub expected_key_owner_uid: u32,
    pub authority_timeout_ms: u64,
    pub maximum_clock_skew_seconds: u64,
    pub maximum_liveness_snapshot_age_seconds: u64,
    pub maximum_revocation_snapshot_age_seconds: u64,
    pub databases: BrokerDaemonDatabaseConfig,
    pub admin: BrokerDaemonAdminConfig,
}

impl BrokerDaemonConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            BrokerError::Storage(format!("daemon config metadata failed: {error}"))
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_CONFIG_BYTES
        {
            return Err(BrokerError::Storage(
                "daemon config is not a bounded regular file".to_string(),
            ));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(BrokerError::Storage(
                "daemon config permissions are not service-private".to_string(),
            ));
        }
        let bytes = fs::read(path)
            .map_err(|error| BrokerError::Storage(format!("daemon config read failed: {error}")))?;
        let config: Self = serde_json::from_slice(&bytes).map_err(|error| {
            BrokerError::InvalidRequest(format!("daemon config decoding failed: {error}"))
        })?;
        let canonical = canonical_json_bytes(&config).map_err(|error| {
            BrokerError::InvalidRequest(format!("daemon config encoding failed: {error}"))
        })?;
        if canonical != bytes {
            return Err(BrokerError::InvalidRequest(
                "daemon config is not canonical JSON".to_string(),
            ));
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != BROKER_DAEMON_CONFIG_SCHEMA {
            return Err(BrokerError::InvalidRequest(
                "daemon config schema is invalid".to_string(),
            ));
        }
        for (value, label) in [
            (&self.tenant_scope, "daemon tenant scope"),
            (&self.broker_audience, "broker audience"),
            (&self.parent_audience, "parent audience"),
            (&self.provider_adapter_id, "provider adapter id"),
        ] {
            validate_identifier(value, label, 512)?;
        }
        if self.provider_adapter_version == 0
            || self.authority_timeout_ms == 0
            || self.authority_timeout_ms > 30_000
            || self.maximum_clock_skew_seconds == 0
            || self.maximum_clock_skew_seconds > 30
            || self.maximum_liveness_snapshot_age_seconds == 0
            || self.maximum_liveness_snapshot_age_seconds > 60
            || self.maximum_revocation_snapshot_age_seconds == 0
            || self.maximum_revocation_snapshot_age_seconds > 60
        {
            return Err(BrokerError::InvalidRequest(
                "daemon provider or authority limits are invalid".to_string(),
            ));
        }
        validate_socket_path(&self.ipc_socket_path, "broker IPC socket")?;
        validate_socket_path(&self.authority_socket_path, "authority IPC socket")?;
        if self.ipc_socket_path == self.authority_socket_path {
            return Err(BrokerError::InvalidRequest(
                "broker and authority sockets must be distinct".to_string(),
            ));
        }
        let database_paths = [
            &self.databases.secret_database_path,
            &self.databases.attempt_database_path,
            &self.databases.admin_replay_database_path,
            &self.databases.receipt_database_path,
        ];
        for path in database_paths {
            validate_database_path(path)?;
        }
        for (index, path) in database_paths.iter().enumerate() {
            if database_paths[index + 1..]
                .iter()
                .any(|candidate| *candidate == *path)
            {
                return Err(BrokerError::InvalidRequest(
                    "daemon database paths must be distinct".to_string(),
                ));
            }
        }
        GovernedAdminPolicy {
            trusted_approvers: self.admin.trusted_approvers.clone(),
            subject: self.admin.subject.clone(),
            threshold: self.admin.threshold,
            maximum_token_lifetime_seconds: self.admin.maximum_token_lifetime_seconds,
        }
        .validate_for_runtime()?;
        Ok(())
    }
}

#[cfg(unix)]
pub struct BrokerDaemonRuntime {
    endpoint: UnixBrokerEndpoint,
}

#[cfg(not(unix))]
pub struct BrokerDaemonRuntime;

impl BrokerDaemonRuntime {
    #[cfg(unix)]
    pub fn build(
        config: BrokerDaemonConfig,
        master_key_file: File,
        signing_key_file: File,
    ) -> Result<Self> {
        config.validate()?;
        validate_distinct_key_files(&master_key_file, &signing_key_file)?;
        prepare_socket_parent(&config.ipc_socket_path)?;
        let signing_key = SealedSigningKeyFd::from_inherited_file(
            signing_key_file,
            config.expected_key_owner_uid,
        )
        .into_keypair()?;
        if signing_key.public_key() != config.broker_identity {
            return Err(BrokerError::Custody(
                "sealed signing key does not match the configured broker identity".to_string(),
            ));
        }
        let backend = Arc::new(EncryptedBlobSecretBackend::open(
            &config.databases.secret_database_path,
            config.tenant_scope.clone(),
            SealedKeyFd::from_inherited_file(master_key_file, config.expected_key_owner_uid),
        )?);
        let attempts = Arc::new(SqliteAttemptStore::open(
            &config.databases.attempt_database_path,
        )?);
        let receipt_sink = Arc::new(SqliteBrokerReceiptSink::open(
            &config.databases.receipt_database_path,
            signing_key.public_key(),
        )?);
        let admin = Arc::new(GovernedAdminAuthorizer::open(
            &config.databases.admin_replay_database_path,
            GovernedAdminPolicy {
                trusted_approvers: config.admin.trusted_approvers.clone(),
                subject: config.admin.subject.clone(),
                threshold: config.admin.threshold,
                maximum_token_lifetime_seconds: config.admin.maximum_token_lifetime_seconds,
            },
            Arc::new(SystemAdminClock),
        )?);
        let authority = Arc::new(AuthorityRpcClient::connect(
            AuthorityRpcClientConfig {
                socket_path: config.authority_socket_path.clone(),
                trusted_authority: config.trusted_authority.clone(),
                timeout_ms: config.authority_timeout_ms,
                maximum_clock_skew_seconds: config.maximum_clock_skew_seconds,
            },
            signing_key.clone(),
        )?);
        let provider = Arc::new(GenericCredentialProvider::new(
            config.provider_adapter_id.clone(),
            config.provider_adapter_version,
            config.provider_placement.into_placement(),
        )?);
        let https = Arc::new(GenericHttpsExecutor::production()?);
        let budget: Arc<dyn BrokerExecutionBudget> = authority.clone();
        let liveness: Arc<dyn CapabilityLiveness> = authority.clone();
        let revocations: Arc<dyn BrokerRevocations> = authority.clone();
        let service = Arc::new(BrokerService::new(
            BrokerServiceConfig {
                production: true,
                audience: config.broker_audience.clone(),
                parent_audience: config.parent_audience,
                maximum_clock_skew_seconds: config.maximum_clock_skew_seconds,
                maximum_liveness_snapshot_age_seconds: config.maximum_liveness_snapshot_age_seconds,
                maximum_revocation_snapshot_age_seconds: config
                    .maximum_revocation_snapshot_age_seconds,
            },
            config.trusted_capability_issuer.clone(),
            Arc::clone(&backend),
            provider,
            https,
            attempts,
            budget,
            liveness,
            revocations,
            receipt_sink,
            signing_key,
        )?);
        let admission: Arc<dyn BrokerAdmissionAuthority> = authority;
        let handler: Arc<dyn BrokerIpcHandler> = Arc::new(BrokerDaemonHandler::new(
            config.tenant_scope,
            config.broker_audience,
            config.trusted_capability_issuer,
            service,
            admission,
            admin,
            backend,
            Arc::new(SystemDaemonClock),
        )?);
        let endpoint = UnixBrokerEndpoint::bind(&config.ipc_socket_path, handler)?;
        Ok(Self { endpoint })
    }

    #[cfg(not(unix))]
    pub fn build(
        _config: BrokerDaemonConfig,
        _master_key_file: File,
        _signing_key_file: File,
    ) -> Result<Self> {
        Err(BrokerError::AuthorityUnavailable(
            "secret broker daemon requires Unix process isolation".to_string(),
        ))
    }

    #[cfg(unix)]
    pub fn serve(&self) -> Result<()> {
        loop {
            self.endpoint.serve_one()?;
        }
    }

    #[cfg(not(unix))]
    pub fn serve(&self) -> Result<()> {
        Err(BrokerError::AuthorityUnavailable(
            "secret broker daemon requires Unix process isolation".to_string(),
        ))
    }
}

#[cfg(unix)]
fn validate_distinct_key_files(master_key: &File, signing_key: &File) -> Result<()> {
    let master = master_key
        .metadata()
        .map_err(|error| BrokerError::Custody(format!("master key metadata failed: {error}")))?;
    let signing = signing_key
        .metadata()
        .map_err(|error| BrokerError::Custody(format!("signing key metadata failed: {error}")))?;
    if master.dev() == signing.dev() && master.ino() == signing.ino() {
        return Err(BrokerError::Custody(
            "master and signing keys must use distinct sealed descriptors".to_string(),
        ));
    }
    Ok(())
}

pub fn open_inherited_key_fd(fd: u32, label: &str) -> Result<File> {
    if fd < 3 || fd > 65_535 {
        return Err(BrokerError::Custody(format!(
            "{label} inherited descriptor number is invalid"
        )));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let path = PathBuf::from(format!("/dev/fd/{fd}"));
    OpenOptions::new().read(true).open(path).map_err(|error| {
        BrokerError::Custody(format!("{label} inherited descriptor open failed: {error}"))
    })
}

fn validate_socket_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > 100
    {
        return Err(BrokerError::InvalidRequest(format!(
            "{label} path is not absolute or exceeds the Unix socket limit"
        )));
    }
    Ok(())
}

fn validate_database_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().is_empty()
        || path.to_string_lossy().starts_with("file:")
        || path.to_string_lossy() == ":memory:"
    {
        return Err(BrokerError::InvalidRequest(
            "daemon database path must be an absolute filesystem path".to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_socket_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        BrokerError::Storage("broker IPC socket has no parent directory".to_string())
    })?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder
        .create(parent)
        .map_err(|error| BrokerError::Storage(format!("IPC directory creation failed: {error}")))?;
    let metadata = fs::symlink_metadata(parent)
        .map_err(|error| BrokerError::Storage(format!("IPC directory metadata failed: {error}")))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(BrokerError::Storage(
            "IPC directory is not a service-private regular directory".to_string(),
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn key_custody_requires_distinct_underlying_files() {
        let master = tempfile::NamedTempFile::new().expect("master fixture");
        let duplicate = File::open(master.path()).expect("duplicate fixture");
        assert!(validate_distinct_key_files(master.as_file(), &duplicate).is_err());

        let signing = tempfile::NamedTempFile::new().expect("signing fixture");
        validate_distinct_key_files(master.as_file(), signing.as_file())
            .expect("distinct key files");
    }
}
