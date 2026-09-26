use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chio_core_types::{
    canonical_json_bytes, Hash, PublicKey, Signature, SigningAlgorithm, SigningBackend,
};
use serde::{Deserialize, Serialize};

use crate::{
    CheckpointGossip, KeyLogPin, KeyLogPolicy, KeyLogSyncResponse, KeyLogWitnessClient,
    KeyringError, Result, SignedKeyLogCheckpoint, WitnessId, WitnessSignature,
    MAX_CANONICAL_RECORD_BYTES,
};

pub const KEY_LOG_WITNESS_SERVICE_CONFIG_SCHEMA: &str = "chio.key-log.witness-service-config.v1";
pub const KEY_LOG_AUDIT_SERVICE_CONFIG_SCHEMA: &str = "chio.key-log.audit-service-config.v1";
pub const KEY_LOG_WITNESS_IPC_REQUEST_SCHEMA: &str = "chio.key-log.witness-ipc-request.v1";
pub const KEY_LOG_WITNESS_IPC_RESPONSE_SCHEMA: &str = "chio.key-log.witness-ipc-response.v1";
pub const KEY_LOG_WITNESS_READINESS_SCHEMA: &str = "chio.key-log.witness-readiness.v1";
pub const KEY_LOG_AUDIT_IPC_REQUEST_SCHEMA: &str = "chio.key-log.audit-ipc-request.v1";
pub const KEY_LOG_AUDIT_IPC_RESPONSE_SCHEMA: &str = "chio.key-log.audit-ipc-response.v1";
pub const KEY_LOG_AUDIT_READINESS_SCHEMA: &str = "chio.key-log.audit-readiness.v1";

const WITNESS_READINESS_DOMAIN: &[u8] = b"chio.key-log.witness-readiness.v1\0";
const AUDIT_READINESS_DOMAIN: &[u8] = b"chio.key-log.audit-readiness.v1\0";
const IPC_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_NONCE_BYTES: usize = 256;
pub const MAX_KEY_LOG_IPC_FRAME_BYTES: usize = 4_194_304;
const MAX_GOSSIP_PAGE_ITEMS: usize = 2;
const MAX_GOSSIP_PAGES: usize = 4_096;
const MAX_GOSSIP_SNAPSHOT_ATTEMPTS: usize = 8;
const GOSSIP_SNAPSHOT_CHANGED: &str = "witness state changed during paginated retrieval";
static READINESS_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceConfig {
    pub schema: String,
    pub policy_path: PathBuf,
    pub database_path: PathBuf,
    pub socket_path: PathBuf,
    pub witness_id: String,
    pub seed_file_path: PathBuf,
    #[serde(default)]
    pub provision: bool,
}

impl WitnessServiceConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema != KEY_LOG_WITNESS_SERVICE_CONFIG_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(self.schema.clone()));
        }
        WitnessId::new(self.witness_id.clone())?;
        require_absolute_paths([
            self.policy_path.as_path(),
            self.database_path.as_path(),
            self.socket_path.as_path(),
            self.seed_file_path.as_path(),
        ])?;
        if self.database_path == self.socket_path || self.database_path == self.seed_file_path {
            return Err(KeyringError::StateInvariant(
                "witness service paths must identify separate resources",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditServiceConfig {
    pub schema: String,
    pub policy_path: PathBuf,
    pub database_path: PathBuf,
    pub operator_database_path: PathBuf,
    pub socket_path: PathBuf,
    pub monitor_id: String,
    pub seed_file_path: PathBuf,
    pub witness_sockets: BTreeMap<String, PathBuf>,
    pub poll_interval_millis: u64,
    #[serde(default)]
    pub provision: bool,
}

impl AuditServiceConfig {
    pub fn validate(&self) -> Result<()> {
        if self.schema != KEY_LOG_AUDIT_SERVICE_CONFIG_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(self.schema.clone()));
        }
        validate_service_identifier(&self.monitor_id, "audit monitor identifier")?;
        if !(10..=60_000).contains(&self.poll_interval_millis) {
            return Err(KeyringError::StateInvariant(
                "audit poll interval must be between 10 and 60000 milliseconds",
            ));
        }
        if self.witness_sockets.len() != 3 {
            return Err(KeyringError::StateInvariant(
                "audit service requires exactly three witness endpoints",
            ));
        }
        require_absolute_paths([
            self.policy_path.as_path(),
            self.database_path.as_path(),
            self.operator_database_path.as_path(),
            self.socket_path.as_path(),
            self.seed_file_path.as_path(),
        ])?;
        if self.database_path == self.operator_database_path
            || self.database_path == self.socket_path
            || self.operator_database_path == self.socket_path
            || self.database_path == self.seed_file_path
            || self.operator_database_path == self.seed_file_path
            || self.socket_path == self.seed_file_path
        {
            return Err(KeyringError::StateInvariant(
                "audit service paths must identify separate resources",
            ));
        }
        let mut endpoints = BTreeSet::new();
        for (witness_id, endpoint) in &self.witness_sockets {
            WitnessId::new(witness_id.clone())?;
            if !endpoint.is_absolute() || !endpoints.insert(endpoint) {
                return Err(KeyringError::StateInvariant(
                    "audit witness endpoints must be absolute and distinct",
                ));
            }
        }
        Ok(())
    }
}

pub fn load_witness_service_config(path: impl AsRef<Path>) -> Result<WitnessServiceConfig> {
    let config: WitnessServiceConfig = load_bounded_json_file(path.as_ref())?;
    config.validate()?;
    Ok(config)
}

pub fn load_audit_service_config(path: impl AsRef<Path>) -> Result<AuditServiceConfig> {
    let config: AuditServiceConfig = load_bounded_json_file(path.as_ref())?;
    config.validate()?;
    Ok(config)
}

fn load_bounded_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let (bytes, _) = crate::service::read_bounded_regular_file(path, MAX_CANONICAL_RECORD_BYTES)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn require_absolute_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Result<()> {
    if paths.into_iter().any(|path| !path.is_absolute()) {
        return Err(KeyringError::StateInvariant(
            "service configuration paths must be absolute",
        ));
    }
    Ok(())
}

pub(crate) fn validate_service_identifier(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(KeyringError::InvalidIdentifier {
            kind,
            reason: "value contains unsupported characters or has an invalid length",
        });
    }
    Ok(())
}

pub fn write_canonical_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: Write,
    T: Serialize,
{
    let canonical = canonical_json_bytes(value)?;
    if canonical.is_empty() || canonical.len() > MAX_KEY_LOG_IPC_FRAME_BYTES {
        return Err(KeyringError::Canonical(
            "canonical IPC record has an invalid length".to_string(),
        ));
    }
    let length = u32::try_from(canonical.len()).map_err(|_| KeyringError::NumericRange)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&canonical)?;
    writer.flush()?;
    Ok(())
}

pub fn read_canonical_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: Read,
    T: serde::de::DeserializeOwned + Serialize,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| KeyringError::NumericRange)?;
    if length == 0 || length > MAX_KEY_LOG_IPC_FRAME_BYTES {
        return Err(KeyringError::Canonical(
            "canonical IPC frame has an invalid length".to_string(),
        ));
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes)?;
    let value: T = serde_json::from_slice(&bytes)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err(KeyringError::Canonical(
            "IPC frame payload is not canonical JSON".to_string(),
        ));
    }
    Ok(value)
}

pub fn read_single_canonical_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: Read,
    T: serde::de::DeserializeOwned + Serialize,
{
    let value = read_canonical_frame(reader)?;
    let mut trailing = [0_u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(KeyringError::Canonical(
            "IPC connection contains bytes after its single frame".to_string(),
        ));
    }
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceReadinessBody {
    pub schema: String,
    pub witness_id: WitnessId,
    pub configuration_binding: Hash,
    pub nonce: String,
    pub process_id: u32,
    pub storage_identity: Hash,
    pub started_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<KeyLogPin>,
    pub conflict_count: usize,
    pub gossip_observation_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceReadinessProof {
    pub body: WitnessServiceReadinessBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

impl WitnessServiceReadinessProof {
    pub fn sign(body: WitnessServiceReadinessBody, backend: &dyn SigningBackend) -> Result<Self> {
        validate_nonce(&body.nonce)?;
        let outcome = backend.sign_bytes_with_identity(&readiness_signing_bytes(&body)?)?;
        let algorithm = outcome.algorithm;
        let signature = outcome.signature;
        if signature.algorithm() != algorithm {
            return Err(KeyringError::AlgorithmMismatch);
        }
        Ok(Self {
            body,
            algorithm,
            signature,
        })
    }

    pub fn verify(
        &self,
        expected_witness_id: &WitnessId,
        expected_public_key: &PublicKey,
        expected_configuration_binding: Hash,
        expected_nonce: &str,
    ) -> Result<()> {
        validate_nonce(expected_nonce)?;
        if self.body.schema != KEY_LOG_WITNESS_READINESS_SCHEMA
            || &self.body.witness_id != expected_witness_id
            || self.body.configuration_binding != expected_configuration_binding
            || self.body.nonce != expected_nonce
            || self.body.process_id == 0
            || self.body.storage_identity == Hash::zero()
            || self.body.started_at == 0
            || self.algorithm != expected_public_key.algorithm()
            || self.signature.algorithm() != self.algorithm
            || !expected_public_key.verify(&readiness_signing_bytes(&self.body)?, &self.signature)
        {
            return Err(KeyringError::InvalidSignature);
        }
        Ok(())
    }
}

fn readiness_signing_bytes(body: &WitnessServiceReadinessBody) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(body)?;
    let mut bytes = Vec::with_capacity(WITNESS_READINESS_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(WITNESS_READINESS_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn validate_nonce(nonce: &str) -> Result<()> {
    if nonce.is_empty()
        || nonce.len() > MAX_NONCE_BYTES
        || nonce.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(KeyringError::StateInvariant(
            "service readiness nonce has an invalid length or character",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum WitnessServiceOperation {
    Readiness {
        nonce: String,
    },
    Pin,
    SignCandidate {
        candidate: Box<SignedKeyLogCheckpoint>,
        synchronization: Box<KeyLogSyncResponse>,
    },
    State {
        nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<GossipCursor>,
    },
    ImportGossip {
        gossip: Box<CheckpointGossip>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GossipCursor {
    pub checkpoint_sequence: u64,
    pub witness_id: WitnessId,
}

impl GossipCursor {
    #[must_use]
    pub fn from_gossip(gossip: &CheckpointGossip) -> Self {
        Self {
            checkpoint_sequence: gossip.checkpoint.body.checkpoint_sequence,
            witness_id: gossip.witness_signature.witness_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceRequest {
    pub schema: String,
    pub operation: WitnessServiceOperation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceState {
    pub proof: WitnessServiceReadinessProof,
    pub witness_id: WitnessId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<KeyLogPin>,
    pub gossip: Vec<CheckpointGossip>,
    pub gossip_observation_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<GossipCursor>,
    pub conflict_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum WitnessServiceResult {
    Readiness {
        proof: WitnessServiceReadinessProof,
    },
    Pin {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pin: Option<KeyLogPin>,
    },
    Signed {
        signature: WitnessSignature,
        pin: KeyLogPin,
    },
    State {
        state: WitnessServiceState,
    },
    Imported,
    Failure {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceResponse {
    pub schema: String,
    pub result: WitnessServiceResult,
}

pub fn gossip_page(
    observations: &[CheckpointGossip],
    after: Option<&GossipCursor>,
) -> (Vec<CheckpointGossip>, Option<GossipCursor>) {
    let mut eligible = observations
        .iter()
        .filter(|gossip| after.is_none_or(|cursor| &GossipCursor::from_gossip(gossip) > cursor))
        .cloned();
    let page = eligible
        .by_ref()
        .take(MAX_GOSSIP_PAGE_ITEMS)
        .collect::<Vec<_>>();
    let has_more = eligible.next().is_some();
    let next_cursor = if has_more {
        page.last().map(GossipCursor::from_gossip)
    } else {
        None
    };
    (page, next_cursor)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessServiceView {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<KeyLogPin>,
    pub process_id: u32,
    pub storage_identity: Hash,
    pub conflict_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditServiceReadinessBody {
    pub schema: String,
    pub monitor_id: String,
    pub configuration_binding: Hash,
    pub nonce: String,
    pub process_id: u32,
    pub storage_identity: Hash,
    pub started_at: u64,
    pub last_successful_poll_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<KeyLogPin>,
    pub operator_head: KeyLogPin,
    pub witness_views: BTreeMap<WitnessId, WitnessServiceView>,
    pub witness_proofs: BTreeMap<WitnessId, WitnessServiceReadinessProof>,
    pub conflict_count: usize,
}

impl AuditServiceReadinessBody {
    pub fn validate(
        &self,
        expected_monitor_id: &str,
        expected_configuration_binding: Hash,
        expected_nonce: &str,
    ) -> Result<()> {
        validate_service_identifier(expected_monitor_id, "audit monitor identifier")?;
        validate_nonce(expected_nonce)?;
        if self.schema != KEY_LOG_AUDIT_READINESS_SCHEMA
            || self.monitor_id != expected_monitor_id
            || self.configuration_binding != expected_configuration_binding
            || self.nonce != expected_nonce
            || self.process_id == 0
            || self.storage_identity == Hash::zero()
            || self.started_at == 0
            || self.last_successful_poll_at == 0
        {
            return Err(KeyringError::StateInvariant(
                "audit readiness response does not match its challenge",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditServiceReadinessProof {
    pub body: AuditServiceReadinessBody,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

impl AuditServiceReadinessProof {
    pub fn sign(body: AuditServiceReadinessBody, backend: &dyn SigningBackend) -> Result<Self> {
        body.validate(&body.monitor_id, body.configuration_binding, &body.nonce)?;
        let outcome = backend.sign_bytes_with_identity(&audit_readiness_signing_bytes(&body)?)?;
        let algorithm = outcome.algorithm;
        let signature = outcome.signature;
        if signature.algorithm() != algorithm {
            return Err(KeyringError::AlgorithmMismatch);
        }
        Ok(Self {
            body,
            algorithm,
            signature,
        })
    }

    pub fn verify(
        &self,
        expected_monitor_id: &str,
        expected_public_key: &PublicKey,
        expected_configuration_binding: Hash,
        expected_nonce: &str,
    ) -> Result<()> {
        self.body.validate(
            expected_monitor_id,
            expected_configuration_binding,
            expected_nonce,
        )?;
        if self.algorithm != expected_public_key.algorithm()
            || self.signature.algorithm() != self.algorithm
            || !expected_public_key
                .verify(&audit_readiness_signing_bytes(&self.body)?, &self.signature)
        {
            return Err(KeyringError::InvalidSignature);
        }
        Ok(())
    }
}

fn audit_readiness_signing_bytes(body: &AuditServiceReadinessBody) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(body)?;
    let mut bytes = Vec::with_capacity(AUDIT_READINESS_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(AUDIT_READINESS_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditServiceOperation {
    Readiness { nonce: String },
    PollNow,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditServiceRequest {
    pub schema: String,
    pub operation: AuditServiceOperation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuditServiceResult {
    Readiness {
        proof: Box<AuditServiceReadinessProof>,
    },
    PollAccepted,
    Unready {
        reason: String,
    },
    Failure {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditServiceResponse {
    pub schema: String,
    pub result: AuditServiceResult,
}

#[derive(Clone, Debug)]
pub struct UnixKeyLogWitnessClient {
    socket_path: PathBuf,
    witness_id: WitnessId,
    public_key: PublicKey,
    configuration_binding: Hash,
}

impl UnixKeyLogWitnessClient {
    pub fn new(
        socket_path: PathBuf,
        witness_id: WitnessId,
        public_key: PublicKey,
        configuration_binding: Hash,
    ) -> Result<Self> {
        if !socket_path.is_absolute() {
            return Err(KeyringError::StateInvariant(
                "witness service endpoint must be absolute",
            ));
        }
        Ok(Self {
            socket_path,
            witness_id,
            public_key,
            configuration_binding,
        })
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn witness_id(&self) -> &WitnessId {
        &self.witness_id
    }

    pub fn readiness(&self, nonce: &str) -> Result<WitnessServiceReadinessProof> {
        validate_nonce(nonce)?;
        let response = self.exchange(WitnessServiceOperation::Readiness {
            nonce: nonce.to_string(),
        })?;
        match response.result {
            WitnessServiceResult::Readiness { proof } => {
                proof.verify(
                    &self.witness_id,
                    &self.public_key,
                    self.configuration_binding,
                    nonce,
                )?;
                Ok(proof)
            }
            WitnessServiceResult::Failure { .. } => Err(KeyringError::StateInvariant(
                "external witness service rejected readiness",
            )),
            _ => Err(KeyringError::StateInvariant(
                "external witness service returned the wrong response",
            )),
        }
    }

    pub fn state(&self) -> Result<WitnessServiceState> {
        for _ in 0..MAX_GOSSIP_SNAPSHOT_ATTEMPTS {
            let nonce = format!("{}.state", readiness_nonce_prefix()?);
            match self.state_snapshot(&nonce) {
                Err(KeyringError::StateInvariant(GOSSIP_SNAPSHOT_CHANGED)) => continue,
                result => return result,
            }
        }
        Err(KeyringError::StateInvariant(GOSSIP_SNAPSHOT_CHANGED))
    }

    fn state_snapshot(&self, nonce: &str) -> Result<WitnessServiceState> {
        let mut cursor = None;
        let mut combined: Option<WitnessServiceState> = None;
        for _ in 0..MAX_GOSSIP_PAGES {
            let response = self.exchange(WitnessServiceOperation::State {
                nonce: nonce.to_string(),
                after: cursor.clone(),
            })?;
            let state = match response.result {
                WitnessServiceResult::State { state } if state.witness_id == self.witness_id => {
                    state
                }
                WitnessServiceResult::Failure { .. } => {
                    return Err(KeyringError::StateInvariant(
                        "external witness service rejected state query",
                    ));
                }
                _ => {
                    return Err(KeyringError::StateInvariant(
                        "external witness service returned the wrong response",
                    ));
                }
            };
            state.proof.verify(
                &self.witness_id,
                &self.public_key,
                self.configuration_binding,
                nonce,
            )?;
            if state.proof.body.pin != state.pin
                || state.proof.body.conflict_count != state.conflict_count
                || state.proof.body.gossip_observation_count != state.gossip_observation_count
            {
                return Err(KeyringError::InvalidSignature);
            }
            for gossip in &state.gossip {
                if gossip.witness_signature.witness_id == self.witness_id {
                    gossip
                        .witness_signature
                        .verify(&gossip.checkpoint, &self.public_key)?;
                }
            }
            if let Some(current) = &mut combined {
                if current.pin != state.pin
                    || current.conflict_count != state.conflict_count
                    || current.gossip_observation_count != state.gossip_observation_count
                    || current.proof.body.process_id != state.proof.body.process_id
                    || current.proof.body.storage_identity != state.proof.body.storage_identity
                {
                    return Err(KeyringError::StateInvariant(GOSSIP_SNAPSHOT_CHANGED));
                }
                current.gossip.extend(state.gossip);
                current.next_cursor = state.next_cursor.clone();
            } else {
                combined = Some(state.clone());
            }
            match state.next_cursor {
                Some(next) if cursor.as_ref().is_none_or(|previous| previous < &next) => {
                    cursor = Some(next);
                }
                Some(_) => {
                    return Err(KeyringError::StateInvariant(
                        "witness gossip cursor did not advance",
                    ));
                }
                None => {
                    let complete = combined.ok_or(KeyringError::StateInvariant(
                        "witness state response is missing",
                    ))?;
                    if complete.gossip.len() != complete.gossip_observation_count {
                        return Err(KeyringError::StateInvariant(
                            "witness gossip pagination did not return its declared snapshot",
                        ));
                    }
                    return Ok(complete);
                }
            }
        }
        Err(KeyringError::StateInvariant(
            "witness gossip retrieval exceeded its page limit",
        ))
    }

    pub fn import_gossip(&self, gossip: &CheckpointGossip) -> Result<()> {
        let response = self.exchange(WitnessServiceOperation::ImportGossip {
            gossip: Box::new(gossip.clone()),
        })?;
        match response.result {
            WitnessServiceResult::Imported => Ok(()),
            WitnessServiceResult::Failure { .. } => Err(KeyringError::EquivocationDetected),
            _ => Err(KeyringError::StateInvariant(
                "external witness service returned the wrong response",
            )),
        }
    }

    fn exchange(&self, operation: WitnessServiceOperation) -> Result<WitnessServiceResponse> {
        let request = WitnessServiceRequest {
            schema: KEY_LOG_WITNESS_IPC_REQUEST_SCHEMA.to_string(),
            operation,
        };
        let response: WitnessServiceResponse = exchange_unix(&self.socket_path, &request)?;
        if response.schema != KEY_LOG_WITNESS_IPC_RESPONSE_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(response.schema));
        }
        Ok(response)
    }
}

impl KeyLogWitnessClient for UnixKeyLogWitnessClient {
    fn witness_id(&self) -> &WitnessId {
        &self.witness_id
    }

    fn pin(&self) -> Result<Option<KeyLogPin>> {
        let response = self.exchange(WitnessServiceOperation::Pin)?;
        match response.result {
            WitnessServiceResult::Pin { pin } => Ok(pin),
            WitnessServiceResult::Failure { .. } => Err(KeyringError::StateInvariant(
                "external witness service rejected pin query",
            )),
            _ => Err(KeyringError::StateInvariant(
                "external witness service returned the wrong response",
            )),
        }
    }

    fn sign_candidate(
        &self,
        candidate: &SignedKeyLogCheckpoint,
        synchronization: &KeyLogSyncResponse,
    ) -> Result<WitnessSignature> {
        let response = self.exchange(WitnessServiceOperation::SignCandidate {
            candidate: Box::new(candidate.clone()),
            synchronization: Box::new(synchronization.clone()),
        })?;
        match response.result {
            WitnessServiceResult::Signed { signature, pin } => {
                if signature.witness_id != self.witness_id
                    || pin.checkpoint_hash != candidate.checkpoint_hash()?
                    || pin.checkpoint_sequence != candidate.body.checkpoint_sequence
                    || pin.tree_size != candidate.body.tree_size
                    || pin.root_hash != candidate.body.root_hash
                {
                    return Err(KeyringError::InvalidSignature);
                }
                signature.verify(candidate, &self.public_key)?;
                Ok(signature)
            }
            WitnessServiceResult::Failure { .. } => Err(KeyringError::StateInvariant(
                "external witness service rejected checkpoint",
            )),
            _ => Err(KeyringError::StateInvariant(
                "external witness service returned the wrong response",
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UnixKeyLogAuditClient {
    socket_path: PathBuf,
    monitor_id: String,
    public_key: PublicKey,
    configuration_binding: Hash,
}

impl UnixKeyLogAuditClient {
    pub fn new(
        socket_path: PathBuf,
        monitor_id: String,
        public_key: PublicKey,
        configuration_binding: Hash,
    ) -> Result<Self> {
        if !socket_path.is_absolute() {
            return Err(KeyringError::StateInvariant(
                "audit service endpoint must be absolute",
            ));
        }
        validate_service_identifier(&monitor_id, "audit monitor identifier")?;
        Ok(Self {
            socket_path,
            monitor_id,
            public_key,
            configuration_binding,
        })
    }

    #[must_use]
    pub fn monitor_id(&self) -> &str {
        &self.monitor_id
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn readiness(&self, nonce: &str) -> Result<AuditServiceReadinessProof> {
        validate_nonce(nonce)?;
        let request = AuditServiceRequest {
            schema: KEY_LOG_AUDIT_IPC_REQUEST_SCHEMA.to_string(),
            operation: AuditServiceOperation::Readiness {
                nonce: nonce.to_string(),
            },
        };
        let response: AuditServiceResponse = exchange_unix(&self.socket_path, &request)?;
        if response.schema != KEY_LOG_AUDIT_IPC_RESPONSE_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(response.schema));
        }
        match response.result {
            AuditServiceResult::Readiness { proof } => {
                proof.verify(
                    &self.monitor_id,
                    &self.public_key,
                    self.configuration_binding,
                    nonce,
                )?;
                Ok(*proof)
            }
            AuditServiceResult::Unready { .. } | AuditServiceResult::Failure { .. } => Err(
                KeyringError::StateInvariant("independent audit monitor is not ready"),
            ),
            AuditServiceResult::PollAccepted => Err(KeyringError::StateInvariant(
                "audit service returned the wrong response",
            )),
        }
    }

    pub fn poll_now(&self) -> Result<()> {
        let request = AuditServiceRequest {
            schema: KEY_LOG_AUDIT_IPC_REQUEST_SCHEMA.to_string(),
            operation: AuditServiceOperation::PollNow,
        };
        let response: AuditServiceResponse = exchange_unix(&self.socket_path, &request)?;
        if response.schema != KEY_LOG_AUDIT_IPC_RESPONSE_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(response.schema));
        }
        match response.result {
            AuditServiceResult::PollAccepted => Ok(()),
            _ => Err(KeyringError::StateInvariant(
                "audit service rejected an immediate poll request",
            )),
        }
    }
}

#[cfg(unix)]
fn exchange_unix<T, U>(socket_path: &Path, request: &T) -> Result<U>
where
    T: Serialize,
    U: serde::de::DeserializeOwned + Serialize,
{
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)?;
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    stream.set_write_timeout(Some(IPC_TIMEOUT))?;
    write_canonical_frame(&mut stream, request)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    read_single_canonical_frame(&mut stream)
}

#[cfg(not(unix))]
fn exchange_unix<T, U>(_socket_path: &Path, _request: &T) -> Result<U>
where
    T: Serialize,
    U: serde::de::DeserializeOwned + Serialize,
{
    Err(KeyringError::StateInvariant(
        "Unix key-log IPC is unavailable on this platform",
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndependentOperationReadiness {
    pub witness_proofs: Vec<WitnessServiceReadinessProof>,
    pub audit_proofs: Vec<AuditServiceReadinessProof>,
    pub witness_process_ids: BTreeSet<u32>,
    pub audit_process_ids: BTreeSet<u32>,
    pub durable_storage_identities: HashSet<Hash>,
    pub observed_pin: Option<KeyLogPin>,
    pub observed_operator_head: Option<KeyLogPin>,
}

#[derive(Debug)]
pub struct IndependentKeyLogServices {
    witnesses: Vec<UnixKeyLogWitnessClient>,
    auditors: Vec<UnixKeyLogAuditClient>,
    configuration_binding: Hash,
}

impl IndependentKeyLogServices {
    pub fn connect_and_validate(
        policy: &KeyLogPolicy,
        witness_endpoints: BTreeMap<WitnessId, PathBuf>,
        audit_endpoints: BTreeMap<String, PathBuf>,
        expected_accepted_pin: &KeyLogPin,
        expected_operator_head: &KeyLogPin,
    ) -> Result<(Self, IndependentOperationReadiness)> {
        if witness_endpoints.len() != 3
            || audit_endpoints.len() != 2
            || policy.auditor_public_keys().len() != 2
            || audit_endpoints.keys().collect::<BTreeSet<_>>()
                != policy.auditor_public_keys().keys().collect::<BTreeSet<_>>()
            || witness_endpoints.keys().cloned().collect::<BTreeSet<_>>()
                != policy
                    .witness_public_keys()
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>()
        {
            return Err(KeyringError::StateInvariant(
                "external service endpoints do not match the production topology",
            ));
        }
        let configuration_binding = policy.configuration_binding()?;
        let witnesses = witness_endpoints
            .into_iter()
            .map(|(witness_id, socket_path)| {
                let public_key = policy
                    .witness_public_key(&witness_id)
                    .ok_or(KeyringError::InvalidSignature)?
                    .clone();
                UnixKeyLogWitnessClient::new(
                    socket_path,
                    witness_id,
                    public_key,
                    configuration_binding,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let auditors = audit_endpoints
            .into_iter()
            .map(|(monitor_id, socket_path)| {
                let public_key = policy
                    .auditor_public_keys()
                    .get(&monitor_id)
                    .ok_or(KeyringError::InvalidSignature)?
                    .clone();
                UnixKeyLogAuditClient::new(
                    socket_path,
                    monitor_id,
                    public_key,
                    configuration_binding,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let services = Self {
            witnesses,
            auditors,
            configuration_binding,
        };
        let readiness =
            services.refresh_readiness(policy, expected_accepted_pin, expected_operator_head)?;
        Ok((services, readiness))
    }

    #[must_use]
    pub fn configuration_binding(&self) -> Hash {
        self.configuration_binding
    }

    #[must_use]
    pub fn witnesses(&self) -> &[UnixKeyLogWitnessClient] {
        &self.witnesses
    }

    #[must_use]
    pub fn auditors(&self) -> &[UnixKeyLogAuditClient] {
        &self.auditors
    }

    pub fn refresh_readiness(
        &self,
        policy: &KeyLogPolicy,
        expected_accepted_pin: &KeyLogPin,
        expected_operator_head: &KeyLogPin,
    ) -> Result<IndependentOperationReadiness> {
        if policy.configuration_binding()? != self.configuration_binding {
            return Err(KeyringError::StateInvariant(
                "external key-log services use a different policy binding",
            ));
        }
        let nonce_prefix = readiness_nonce_prefix()?;
        let witness_challenges = self
            .witnesses
            .iter()
            .enumerate()
            .map(|(index, witness)| {
                (
                    witness.witness_id().clone(),
                    format!("{nonce_prefix}.witness.{index}"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let witness_proofs = self
            .witnesses
            .iter()
            .map(|witness| {
                witness.readiness(witness_challenges.get(witness.witness_id()).ok_or(
                    KeyringError::StateInvariant("witness readiness challenge is missing"),
                )?)
            })
            .collect::<Result<Vec<_>>>()?;
        let audit_challenges = self
            .auditors
            .iter()
            .enumerate()
            .map(|(index, audit)| {
                (
                    audit.monitor_id().to_string(),
                    format!("{nonce_prefix}.audit.{index}"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let audit_proofs = self
            .auditors
            .iter()
            .map(|audit| {
                audit.readiness(audit_challenges.get(audit.monitor_id()).ok_or(
                    KeyringError::StateInvariant("audit readiness challenge is missing"),
                )?)
            })
            .collect::<Result<Vec<_>>>()?;
        validate_independent_operation_readiness(
            policy,
            &witness_proofs,
            &audit_proofs,
            &witness_challenges,
            &audit_challenges,
            Some(expected_accepted_pin),
            Some(expected_operator_head),
        )
    }

    pub fn audit_quorum_at_pin(
        &self,
        policy: &KeyLogPolicy,
        expected_operator_pin: &KeyLogPin,
    ) -> Result<()> {
        if policy.configuration_binding()? != self.configuration_binding || self.auditors.len() != 2
        {
            return Err(KeyringError::StateInvariant(
                "external audit services use a different production topology",
            ));
        }
        let nonce_prefix = readiness_nonce_prefix()?;
        let proofs = self
            .auditors
            .iter()
            .enumerate()
            .map(|(index, audit)| {
                audit.readiness(&format!("{nonce_prefix}.activation-audit.{index}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let expected_witnesses = policy
            .witness_public_keys()
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut monitor_ids = BTreeSet::new();
        let mut process_ids = BTreeSet::new();
        let mut storage_identities = HashSet::new();
        let mut observed_witness_instances = None;
        for proof in proofs {
            let body = &proof.body;
            if body.configuration_binding != self.configuration_binding
                || body.schema != KEY_LOG_AUDIT_READINESS_SCHEMA
                || body.conflict_count != 0
                || body.pin.as_ref() != Some(expected_operator_pin)
                || &body.operator_head != expected_operator_pin
                || !monitor_ids.insert(body.monitor_id.clone())
                || body.process_id == std::process::id()
                || !process_ids.insert(body.process_id)
                || !storage_identities.insert(body.storage_identity)
                || body.witness_views.keys().cloned().collect::<BTreeSet<_>>() != expected_witnesses
                || body.witness_proofs.keys().cloned().collect::<BTreeSet<_>>()
                    != expected_witnesses
            {
                return Err(KeyringError::StateInvariant(
                    "independent audit quorum has a stale or aliased view",
                ));
            }
            let mut witness_processes = BTreeSet::new();
            let mut witness_storage = HashSet::new();
            for (witness_id, witness_proof) in &body.witness_proofs {
                let key = policy
                    .witness_public_key(witness_id)
                    .ok_or(KeyringError::InvalidSignature)?;
                witness_proof.verify(
                    witness_id,
                    key,
                    self.configuration_binding,
                    &witness_proof.body.nonce,
                )?;
                let view = body
                    .witness_views
                    .get(witness_id)
                    .ok_or(KeyringError::InvalidSignature)?;
                if witness_proof.body.process_id != view.process_id
                    || witness_proof.body.storage_identity != view.storage_identity
                    || witness_proof.body.pin != view.pin
                    || witness_proof.body.conflict_count != view.conflict_count
                    || witness_proof.body.process_id == body.process_id
                    || witness_proof.body.storage_identity == body.storage_identity
                    || !witness_processes.insert(witness_proof.body.process_id)
                    || !witness_storage.insert(witness_proof.body.storage_identity)
                {
                    return Err(KeyringError::InvalidSignature);
                }
            }
            let matching = body
                .witness_views
                .values()
                .filter(|view| {
                    view.conflict_count == 0 && view.pin.as_ref() == Some(expected_operator_pin)
                })
                .count();
            if matching < policy.witness_threshold()? {
                return Err(KeyringError::InvalidWitnessActivation);
            }
            let instances = body
                .witness_proofs
                .iter()
                .map(|(witness_id, witness_proof)| {
                    (
                        witness_id.clone(),
                        (
                            witness_proof.body.process_id,
                            witness_proof.body.storage_identity,
                            witness_proof.body.pin.clone(),
                            witness_proof.body.started_at,
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            if observed_witness_instances
                .as_ref()
                .is_some_and(|observed| observed != &instances)
            {
                return Err(KeyringError::StateInvariant(
                    "independent auditors observed different witness instances",
                ));
            }
            observed_witness_instances = Some(instances);
        }
        if monitor_ids != policy.auditor_public_keys().keys().cloned().collect() {
            return Err(KeyringError::StateInvariant(
                "independent audit quorum does not match policy-owned trust roots",
            ));
        }
        Ok(())
    }

    pub fn request_audit_poll(&self) -> Result<()> {
        if self.auditors.len() != 2 {
            return Err(KeyringError::StateInvariant(
                "production audit service set is incomplete",
            ));
        }
        for audit in &self.auditors {
            audit.poll_now()?;
        }
        Ok(())
    }
}

fn readiness_nonce_prefix() -> Result<String> {
    let counter = READINESS_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| KeyringError::InvalidTimeOrdering)?;
    #[cfg(unix)]
    let entropy = {
        let mut random = [0_u8; 32];
        std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/urandom")?
            .read_exact(&mut random)?;
        chio_core_types::sha256(&random).to_string()
    };
    #[cfg(not(unix))]
    let entropy = "platform-no-urandom";
    Ok(format!(
        "readiness.{}.{}.{}.{}",
        std::process::id(),
        elapsed.as_nanos(),
        counter,
        entropy
    ))
}

pub fn validate_independent_operation_readiness(
    policy: &KeyLogPolicy,
    witness_proofs: &[WitnessServiceReadinessProof],
    audit_proofs: &[AuditServiceReadinessProof],
    expected_witness_challenges: &BTreeMap<WitnessId, String>,
    expected_audit_challenges: &BTreeMap<String, String>,
    expected_accepted_pin: Option<&KeyLogPin>,
    expected_operator_head: Option<&KeyLogPin>,
) -> Result<IndependentOperationReadiness> {
    let audit_public_keys = policy.auditor_public_keys();
    if policy.witness_public_keys().len() != 3
        || audit_public_keys.len() != 2
        || witness_proofs.len() != 3
        || audit_proofs.len() != 2
        || expected_witness_challenges.keys().collect::<BTreeSet<_>>()
            != policy.witness_public_keys().keys().collect::<BTreeSet<_>>()
        || expected_audit_challenges.keys().collect::<BTreeSet<_>>()
            != audit_public_keys.keys().collect::<BTreeSet<_>>()
        || expected_accepted_pin.is_some() != expected_operator_head.is_some()
    {
        return Err(KeyringError::StateInvariant(
            "production key-log readiness requires three witnesses and two auditors",
        ));
    }
    let configuration_binding = policy.configuration_binding()?;
    let mut witness_ids = BTreeSet::new();
    let mut witness_process_ids = BTreeSet::new();
    let mut audit_process_ids = BTreeSet::new();
    let mut durable_storage_identities = HashSet::new();
    let mut witness_instances = BTreeMap::new();
    for proof in witness_proofs {
        let key = policy
            .witness_public_key(&proof.body.witness_id)
            .ok_or(KeyringError::InvalidSignature)?;
        let expected_nonce = expected_witness_challenges
            .get(&proof.body.witness_id)
            .ok_or(KeyringError::InvalidSignature)?;
        proof.verify(
            &proof.body.witness_id,
            key,
            configuration_binding,
            expected_nonce,
        )?;
        if proof.body.conflict_count != 0
            || proof.body.process_id == std::process::id()
            || !witness_ids.insert(proof.body.witness_id.clone())
            || !witness_process_ids.insert(proof.body.process_id)
            || !durable_storage_identities.insert(proof.body.storage_identity)
        {
            return Err(KeyringError::StateInvariant(
                "witness readiness is conflicting or not independently durable",
            ));
        }
        witness_instances.insert(
            proof.body.witness_id.clone(),
            (
                proof.body.process_id,
                proof.body.storage_identity,
                proof.body.pin.clone(),
                proof.body.started_at,
            ),
        );
        if let (Some(accepted), Some(operator_head)) =
            (expected_accepted_pin, expected_operator_head)
        {
            if let Some(pin) = proof.body.pin.as_ref() {
                if pin != accepted && pin != operator_head {
                    return Err(KeyringError::InvalidWitnessActivation);
                }
            }
        }
    }
    if witness_ids != policy.witness_public_keys().keys().cloned().collect() {
        return Err(KeyringError::StateInvariant(
            "witness service roster does not match configured trust roots",
        ));
    }
    if expected_operator_head.is_some() {
        let matching = witness_proofs
            .iter()
            .filter(|proof| {
                let pin = proof.body.pin.as_ref();
                pin == expected_accepted_pin || pin == expected_operator_head
            })
            .count();
        if matching < policy.witness_threshold()? {
            return Err(KeyringError::InvalidWitnessActivation);
        }
    }

    let mut monitor_ids = BTreeSet::new();
    for proof in audit_proofs {
        let audit_key = audit_public_keys
            .get(&proof.body.monitor_id)
            .ok_or(KeyringError::InvalidSignature)?;
        let expected_nonce = expected_audit_challenges
            .get(&proof.body.monitor_id)
            .ok_or(KeyringError::InvalidSignature)?;
        proof.verify(
            &proof.body.monitor_id,
            audit_key,
            configuration_binding,
            expected_nonce,
        )?;
        let body = &proof.body;
        if body.configuration_binding != configuration_binding
            || body.schema != KEY_LOG_AUDIT_READINESS_SCHEMA
            || body.conflict_count != 0
            || body.last_successful_poll_at == 0
            || body.process_id == std::process::id()
            || !monitor_ids.insert(body.monitor_id.clone())
            || !audit_process_ids.insert(body.process_id)
            || witness_process_ids.contains(&body.process_id)
            || !durable_storage_identities.insert(body.storage_identity)
            || body.pin.as_ref() != expected_accepted_pin
            || Some(&body.operator_head) != expected_operator_head
        {
            return Err(KeyringError::StateInvariant(
                "audit readiness is stale, conflicting, or not independently durable",
            ));
        }
        if body.witness_views.len() != 3
            || body.witness_views.keys().cloned().collect::<BTreeSet<_>>() != witness_ids
            || body.witness_proofs.keys().cloned().collect::<BTreeSet<_>>() != witness_ids
        {
            return Err(KeyringError::StateInvariant(
                "audit monitor has not compared the complete witness roster",
            ));
        }
        for (witness_id, view) in &body.witness_views {
            let Some((process_id, storage_identity, pin, started_at)) =
                witness_instances.get(witness_id)
            else {
                return Err(KeyringError::StateInvariant(
                    "audit monitor referenced an unknown witness instance",
                ));
            };
            if view.process_id != *process_id
                || view.storage_identity != *storage_identity
                || &view.pin != pin
            {
                return Err(KeyringError::StateInvariant(
                    "audit monitor view does not match the challenged witness instance",
                ));
            }
            let embedded = body
                .witness_proofs
                .get(witness_id)
                .ok_or(KeyringError::InvalidSignature)?;
            let key = policy
                .witness_public_key(witness_id)
                .ok_or(KeyringError::InvalidSignature)?;
            embedded.verify(witness_id, key, configuration_binding, &embedded.body.nonce)?;
            if embedded.body.process_id != view.process_id
                || embedded.body.storage_identity != view.storage_identity
                || embedded.body.pin != view.pin
                || embedded.body.conflict_count != view.conflict_count
                || embedded.body.started_at != *started_at
            {
                return Err(KeyringError::InvalidSignature);
            }
        }
        if expected_operator_head.is_some() {
            let matching = body
                .witness_views
                .values()
                .filter(|view| {
                    let pin = view.pin.as_ref();
                    view.conflict_count == 0
                        && (pin == expected_accepted_pin || pin == expected_operator_head)
                })
                .count();
            if matching < policy.witness_threshold()? {
                return Err(KeyringError::InvalidWitnessActivation);
            }
        }
        let view_processes = body
            .witness_views
            .values()
            .map(|view| view.process_id)
            .collect::<BTreeSet<_>>();
        let view_storage = body
            .witness_views
            .values()
            .map(|view| view.storage_identity)
            .collect::<HashSet<_>>();
        if view_processes.len() != 3 || view_storage.len() != 3 {
            return Err(KeyringError::StateInvariant(
                "audit monitor observed aliased witness services",
            ));
        }
    }
    if monitor_ids != audit_public_keys.keys().cloned().collect() {
        return Err(KeyringError::StateInvariant(
            "audit service roster does not match configured trust roots",
        ));
    }
    Ok(IndependentOperationReadiness {
        witness_proofs: witness_proofs.to_vec(),
        audit_proofs: audit_proofs.to_vec(),
        witness_process_ids,
        audit_process_ids,
        durable_storage_identities,
        observed_pin: expected_accepted_pin.cloned(),
        observed_operator_head: expected_operator_head.cloned(),
    })
}

pub fn durable_storage_identity(path: &Path) -> Result<Hash> {
    let storage_file = crate::open_durable_sqlite_file(path, false, false)?;
    Ok(storage_file.identity())
}

#[cfg(unix)]
pub fn bind_private_unix_listener(path: &Path) -> Result<std::os::unix::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};

    if !path.is_absolute() {
        return Err(KeyringError::StateInvariant(
            "service socket path must be absolute",
        ));
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() || metadata.file_type().is_symlink() {
            return Err(KeyringError::StateInvariant(
                "service socket path is occupied by a non-socket",
            ));
        }
        if UnixStream::connect(path).is_ok() {
            return Err(KeyringError::StateInvariant(
                "service socket already has a live listener",
            ));
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}
