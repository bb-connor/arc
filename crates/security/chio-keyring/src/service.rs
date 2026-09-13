use std::collections::BTreeMap;
use std::fs::Metadata;
use std::io::BufRead;
use std::path::Path;

use chio_core_types::{Ed25519Backend, Keypair, PublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    AnchorId, AuthorityId, CheckpointGossip, KeyLogPin, KeyLogPolicy, KeyLogPolicyConfig,
    KeyLogSyncResponse, KeyringError, LogId, RecoveryAuthorizerId, RecoveryPolicyId, Result,
    SignedKeyLogCheckpoint, WitnessId, WitnessRosterId,
};

pub const KEY_LOG_POLICY_DOCUMENT_SCHEMA: &str = "chio.key-log.policy.v1";
pub const KEY_LOG_WITNESS_REQUEST_SCHEMA: &str = "chio.key-log.witness-request.v1";
pub const KEY_LOG_WITNESS_RESPONSE_SCHEMA: &str = "chio.key-log.witness-response.v1";
pub const KEY_LOG_AUDIT_COMMAND_SCHEMA: &str = "chio.key-log.audit-command.v1";
pub const KEY_LOG_AUDIT_RESPONSE_SCHEMA: &str = "chio.key-log.audit-response.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogPolicyDocument {
    pub schema: String,
    pub log_id: String,
    pub authority_id: String,
    pub bootstrap_public_key: String,
    pub operator_public_key: String,
    pub witness_roster_id: String,
    pub witness_public_keys: BTreeMap<String, String>,
    pub recovery_policy_id: String,
    #[serde(default)]
    pub recovery_public_keys: BTreeMap<String, String>,
    pub recovery_threshold: usize,
    pub artifact_time_public_keys: BTreeMap<String, String>,
    pub auditor_public_keys: BTreeMap<String, String>,
    pub max_checkpoint_future_skew_millis: u64,
}

impl KeyLogPolicyDocument {
    pub fn into_policy(self) -> Result<KeyLogPolicy> {
        if self.schema != KEY_LOG_POLICY_DOCUMENT_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(self.schema));
        }
        if self.artifact_time_public_keys.is_empty() {
            return Err(KeyringError::InvalidArtifactTimeEvidence);
        }
        let witnesses = parse_public_keys(self.witness_public_keys, WitnessId::new)?;
        let recovery = parse_public_keys(self.recovery_public_keys, RecoveryAuthorizerId::new)?;
        let artifact_time = parse_public_keys(self.artifact_time_public_keys, AnchorId::new)?;
        let auditors = self
            .auditor_public_keys
            .into_iter()
            .map(|(identifier, key)| Ok((identifier, PublicKey::from_hex(&key)?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        KeyLogPolicy::new(KeyLogPolicyConfig {
            log_id: LogId::new(self.log_id)?,
            authority_id: AuthorityId::new(self.authority_id)?,
            bootstrap_key: PublicKey::from_hex(&self.bootstrap_public_key)?,
            operator_key: PublicKey::from_hex(&self.operator_public_key)?,
            witness_roster_id: WitnessRosterId::new(self.witness_roster_id)?,
            witness_keys: witnesses,
            recovery_policy_id: RecoveryPolicyId::new(self.recovery_policy_id)?,
            recovery_keys: recovery,
            recovery_threshold: self.recovery_threshold,
            max_checkpoint_future_skew: self.max_checkpoint_future_skew_millis,
        })?
        .with_artifact_time_roots(artifact_time)?
        .with_auditor_roots(auditors)
    }
}

fn parse_public_keys<I, F>(
    values: BTreeMap<String, String>,
    identifier: F,
) -> Result<BTreeMap<I, PublicKey>>
where
    I: Ord,
    F: Fn(String) -> Result<I>,
{
    values
        .into_iter()
        .map(|(name, key)| Ok((identifier(name)?, PublicKey::from_hex(&key)?)))
        .collect()
}

pub fn load_key_log_policy(path: impl AsRef<Path>) -> Result<KeyLogPolicy> {
    let (bytes, _) = read_bounded_regular_file(path.as_ref(), crate::MAX_CANONICAL_RECORD_BYTES)?;
    let document: KeyLogPolicyDocument = serde_json::from_slice(&bytes)?;
    document.into_policy()
}

pub fn load_witness_seed_backend(path: impl AsRef<Path>) -> Result<Ed25519Backend> {
    let path = path.as_ref();
    let (mut bytes, metadata) = read_bounded_regular_file(path, 32)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(KeyringError::StateInvariant(
                "witness seed must have mode 0600 or stricter and one hard link",
            ));
        }
    }
    if bytes.len() != 32 {
        bytes.fill(0);
        return Err(KeyringError::StateInvariant(
            "witness seed must contain exactly 32 bytes",
        ));
    }
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.fill(0);
    let keypair = Keypair::from_seed(&seed);
    seed.fill(0);
    Ok(Ed25519Backend::new(keypair))
}

pub(crate) fn read_bounded_regular_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<(Vec<u8>, Metadata)> {
    crate::read_custody_sensitive_file_with_metadata(path, maximum_bytes)
}

pub fn read_bounded_json_line<R, T>(reader: &mut R) -> Result<Option<T>>
where
    R: BufRead,
    T: serde::de::DeserializeOwned,
{
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            break;
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > crate::MAX_CANONICAL_RECORD_BYTES {
            return Err(KeyringError::Canonical(
                "key-log service request exceeds 1048576 bytes".to_string(),
            ));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.last() == Some(&b'\n') {
            break;
        }
    }
    while line
        .last()
        .is_some_and(|byte| matches!(*byte, b'\n' | b'\r'))
    {
        line.pop();
    }
    if line.is_empty() {
        return Err(KeyringError::Canonical(
            "key-log service request is empty".to_string(),
        ));
    }
    Ok(Some(serde_json::from_slice(&line)?))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogWitnessRequest {
    pub schema: String,
    pub candidate: SignedKeyLogCheckpoint,
    pub synchronization: KeyLogSyncResponse,
}

impl KeyLogWitnessRequest {
    pub fn validate(&self) -> Result<()> {
        if self.schema != KEY_LOG_WITNESS_REQUEST_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(self.schema.clone()));
        }
        self.synchronization.validate_bounds()
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogWitnessResponse {
    pub schema: String,
    pub gossip: CheckpointGossip,
    pub pin: KeyLogPin,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyLogAuditCommandKind {
    Synchronize { response: KeyLogSyncResponse },
    ImportGossip { gossip: Box<CheckpointGossip> },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogAuditCommand {
    pub schema: String,
    #[serde(flatten)]
    pub kind: KeyLogAuditCommandKind,
}

impl KeyLogAuditCommand {
    pub fn validate(&self) -> Result<()> {
        if self.schema != KEY_LOG_AUDIT_COMMAND_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(self.schema.clone()));
        }
        if let KeyLogAuditCommandKind::Synchronize { response } = &self.kind {
            response.validate_bounds()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogAuditResponse {
    pub schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<KeyLogPin>,
    pub conflict_count: usize,
    pub gossip_observation_count: usize,
}
