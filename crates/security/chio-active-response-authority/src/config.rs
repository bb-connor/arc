use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use chio_core::PublicKey;
use chio_secure_ipc::{PeerIdentity, MAX_UNIX_SOCKET_PATH_BYTES};
use chio_security_types::ports::Digest32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AuthorityError, Result};

pub const AUTHORITY_RUNTIME_CONFIG_SCHEMA: &str =
    "chio.active-response-authority.runtime-config.v1";
pub const ACTIVE_DEFENSE_DEPLOYMENT_CONFIG_SCHEMA: &str =
    "chio.active-defense.deployment-config.v1";
const ACTIVE_DEFENSE_DEPLOYMENT_DIGEST_DOMAIN: &[u8] =
    b"chio.active-defense.deployment-config.digest.v1\0";
const MAX_RUNTIME_CONFIG_BYTES: u64 = 1_048_576;
const ACTIVE_RESPONSE_AUTHORITY_PROTOCOL: &str = "chio.active-response-policy-authority.v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityRuntimeConfig {
    pub schema: String,
    pub protocol: String,
    pub socket_path: PathBuf,
    pub store_path: PathBuf,
    pub trusted_service_uid: u32,
    pub service_identity: PeerIdentity,
    pub expected_client_peer: PeerIdentity,
    pub trusted_client: PublicKey,
    pub authority_identity: PublicKey,
    pub deployment_digest: Digest32,
    pub store_digest: Digest32,
    pub timeout_ms: u64,
    pub maximum_clock_skew_seconds: u64,
    pub maximum_replay_entries: usize,
    pub worker_count: usize,
    pub queue_capacity: usize,
}

impl AuthorityRuntimeConfig {
    pub fn validate(&self) -> Result<()> {
        self.validate_with_deployment_digest(true)
    }

    fn validate_with_deployment_digest(&self, require_deployment_digest: bool) -> Result<()> {
        if self.schema != AUTHORITY_RUNTIME_CONFIG_SCHEMA
            || self.protocol != ACTIVE_RESPONSE_AUTHORITY_PROTOCOL
            || (require_deployment_digest && self.deployment_digest.is_zero())
            || self.store_digest.is_zero()
            || self.service_identity.process_id == 0
            || self.expected_client_peer.process_id == 0
            || self.service_identity == self.expected_client_peer
            || self.service_identity.user_id != self.trusted_service_uid
            || self.authority_identity == self.trusted_client
            || self.timeout_ms == 0
            || self.timeout_ms > 30_000
            || self.maximum_clock_skew_seconds == 0
            || self.maximum_clock_skew_seconds > 30
            || self.maximum_replay_entries == 0
            || self.maximum_replay_entries > 65_536
            || self.worker_count == 0
            || self.worker_count > 64
            || self.queue_capacity < self.worker_count
            || self.queue_capacity > 1_024
        {
            return Err(AuthorityError::InvalidConfig(
                "runtime schema, identity, digest, deadline, replay, or worker bounds are invalid"
                    .to_string(),
            ));
        }
        validate_absolute_path(&self.socket_path, true, "socket")?;
        validate_absolute_path(&self.store_path, false, "store")?;
        if self.socket_path == self.store_path {
            return Err(AuthorityError::InvalidConfig(
                "socket and store paths must be distinct".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_current_process(&self) -> Result<()> {
        self.validate()?;
        #[cfg(target_os = "linux")]
        if self.service_identity.process_id != std::process::id()
            || self.service_identity.user_id != rustix::process::geteuid().as_raw()
            || self.service_identity.group_id != rustix::process::getegid().as_raw()
        {
            return Err(AuthorityError::Custody(
                "runtime service identity does not match the current process".to_string(),
            ));
        }
        #[cfg(not(target_os = "linux"))]
        return Err(AuthorityError::Custody(
            "runtime process identity validation requires Linux".to_string(),
        ));
        #[cfg(target_os = "linux")]
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveDefenseDeploymentStage {
    Disabled,
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretBrokerDeploymentBinding {
    pub service_identity: PeerIdentity,
    pub active_response_client_identity: PublicKey,
    pub receipt_signing_identity: PublicKey,
    pub normal_socket_path: PathBuf,
    pub audit_socket_path: PathBuf,
    pub database_paths: Vec<PathBuf>,
    pub stage: ActiveDefenseDeploymentStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveDefenseDeploymentConfig {
    pub schema: String,
    pub deployment_digest: Digest32,
    pub response_authority: AuthorityRuntimeConfig,
    pub secret_broker: SecretBrokerDeploymentBinding,
}

impl ActiveDefenseDeploymentConfig {
    pub fn compute_deployment_digest(&self) -> Result<Digest32> {
        self.validate_structure(false)?;
        let mut normalized = self.clone();
        normalized.deployment_digest = Digest32::new([0; 32]);
        normalized.response_authority.deployment_digest = Digest32::new([0; 32]);
        let canonical = chio_core::canonical_json_bytes(&normalized).map_err(|error| {
            AuthorityError::InvalidConfig(format!("deployment encoding failed: {error}"))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(ACTIVE_DEFENSE_DEPLOYMENT_DIGEST_DOMAIN);
        hasher.update(canonical);
        Ok(Digest32::new(hasher.finalize().into()))
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_structure(true)?;
        if self.compute_deployment_digest()? != self.deployment_digest {
            return Err(AuthorityError::InvalidConfig(
                "deployment digest does not match the normalized configuration".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_structure(&self, require_deployment_digest: bool) -> Result<()> {
        self.response_authority
            .validate_with_deployment_digest(require_deployment_digest)?;
        if self.schema != ACTIVE_DEFENSE_DEPLOYMENT_CONFIG_SCHEMA
            || (require_deployment_digest && self.deployment_digest.is_zero())
            || (require_deployment_digest
                && self.response_authority.deployment_digest != self.deployment_digest)
            || self.secret_broker.service_identity != self.response_authority.expected_client_peer
            || self.secret_broker.active_response_client_identity
                != self.response_authority.trusted_client
            || self.secret_broker.receipt_signing_identity
                == self.response_authority.authority_identity
            || self.secret_broker.receipt_signing_identity
                == self.secret_broker.active_response_client_identity
        {
            return Err(AuthorityError::InvalidConfig(
                "deployment digest, process bindings, or signing roles are inconsistent"
                    .to_string(),
            ));
        }
        validate_absolute_path(
            &self.secret_broker.normal_socket_path,
            true,
            "broker normal socket",
        )?;
        validate_absolute_path(
            &self.secret_broker.audit_socket_path,
            true,
            "broker audit socket",
        )?;
        let mut paths = vec![
            self.response_authority.socket_path.clone(),
            self.response_authority.store_path.clone(),
            self.secret_broker.normal_socket_path.clone(),
            self.secret_broker.audit_socket_path.clone(),
        ];
        if self.secret_broker.database_paths.is_empty()
            || self.secret_broker.database_paths.len() > 32
        {
            return Err(AuthorityError::InvalidConfig(
                "broker database path inventory is empty or oversized".to_string(),
            ));
        }
        paths.extend(self.secret_broker.database_paths.iter().cloned());
        for path in &self.secret_broker.database_paths {
            validate_absolute_path(path, false, "broker database")?;
        }
        paths.sort();
        if paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AuthorityError::InvalidConfig(
                "deployment paths must not alias across privileged roles".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn load_runtime_config(path: &Path) -> Result<AuthorityRuntimeConfig> {
    if !path.is_absolute() {
        return Err(AuthorityError::InvalidConfig(
            "runtime config path must be absolute".to_string(),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| AuthorityError::Custody(format!("config open failed: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| AuthorityError::Custody(format!("config metadata failed: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RUNTIME_CONFIG_BYTES
    {
        return Err(AuthorityError::Custody(
            "runtime config must be a bounded regular file".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .map_err(|_| AuthorityError::Custody("runtime config size is invalid".to_string()))?,
    );
    file.by_ref()
        .take(MAX_RUNTIME_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| AuthorityError::Custody(format!("config read failed: {error}")))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(AuthorityError::Custody(
            "runtime config changed while it was read".to_string(),
        ));
    }
    let config: AuthorityRuntimeConfig = serde_json::from_slice(&bytes)
        .map_err(|error| AuthorityError::InvalidConfig(format!("config decode failed: {error}")))?;
    config.validate()?;
    #[cfg(unix)]
    if metadata.uid() != config.trusted_service_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(AuthorityError::Custody(
            "runtime config ownership or permissions are invalid".to_string(),
        ));
    }
    let canonical = chio_core::canonical_json_bytes(&config).map_err(|error| {
        AuthorityError::InvalidConfig(format!("config canonicalization failed: {error}"))
    })?;
    if canonical != bytes {
        return Err(AuthorityError::InvalidConfig(
            "runtime config is not canonical JSON".to_string(),
        ));
    }
    Ok(config)
}

fn validate_absolute_path(path: &Path, socket: bool, label: &str) -> Result<()> {
    let encoded = path.as_os_str().as_encoded_bytes();
    let normalized = path.components().all(|component| {
        matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )
    });
    let length = encoded.len();
    if !path.is_absolute()
        || length == 0
        || path.file_name().is_none()
        || encoded.contains(&0)
        || !normalized
        || (socket && length > MAX_UNIX_SOCKET_PATH_BYTES)
        || (!socket && path.to_string_lossy().starts_with("file:"))
        || (!socket && path.to_string_lossy() == ":memory:")
    {
        return Err(AuthorityError::InvalidConfig(format!(
            "{label} path is invalid"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
