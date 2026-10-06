use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
    Ok(chio_core_types::canonical::UntrustedJsonText::from_wire(
        &bytes,
        MAX_CANONICAL_RECORD_BYTES,
    )?
    .decode_signed()?)
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
    Ok(chio_core_types::canonical::UntrustedJsonText::from_wire(
        &bytes,
        MAX_KEY_LOG_IPC_FRAME_BYTES,
    )?
    .decode_canonical()?)
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
            || !expected_public_key
                .verify_strict(&readiness_signing_bytes(&self.body)?, &self.signature)
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
                .verify_strict(&audit_readiness_signing_bytes(&self.body)?, &self.signature)
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
    service_uid: u32,
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
            service_uid: current_effective_uid(),
        })
    }

    /// Expect the service at this endpoint to run as `service_uid` instead of
    /// this process's effective user.
    #[must_use]
    pub fn with_service_uid(mut self, service_uid: u32) -> Self {
        self.service_uid = service_uid;
        self
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
        let response: WitnessServiceResponse =
            exchange_unix(&self.socket_path, self.service_uid, &request)?;
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
    service_uid: u32,
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
            service_uid: current_effective_uid(),
        })
    }

    /// Expect the service at this endpoint to run as `service_uid` instead of
    /// this process's effective user.
    #[must_use]
    pub fn with_service_uid(mut self, service_uid: u32) -> Self {
        self.service_uid = service_uid;
        self
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
        let response: AuditServiceResponse =
            exchange_unix(&self.socket_path, self.service_uid, &request)?;
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
        let response: AuditServiceResponse =
            exchange_unix(&self.socket_path, self.service_uid, &request)?;
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
fn current_effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

#[cfg(not(unix))]
fn current_effective_uid() -> u32 {
    0
}

/// Refuse a connection unless its peer runs as this service's effective user.
/// The private socket directory already keeps other users from reaching the
/// socket; this check authenticates each accepted connection from the
/// kernel's record of the connecting process before any request is read.
#[cfg(unix)]
pub fn require_service_peer(stream: &std::os::unix::net::UnixStream) -> Result<()> {
    require_peer_uid(stream, current_effective_uid())
}

#[cfg(unix)]
fn require_peer_uid(stream: &std::os::unix::net::UnixStream, service_uid: u32) -> Result<()> {
    if unix_peer_uid(stream)? != service_uid {
        return Err(KeyringError::StateInvariant(
            "key-log service peer runs as a different user",
        ));
    }
    Ok(())
}

/// The effective user the kernel recorded for the process at the other end of
/// a connected Unix socket when the connection was made.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn unix_peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .map(|credentials| credentials.uid.as_raw())
        .map_err(|error| KeyringError::Io(error.into()))
}

#[cfg(target_vendor = "apple")]
fn unix_peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<u32> {
    use std::os::fd::AsRawFd;
    use std::os::raw::c_int;

    unsafe extern "C" {
        fn getpeereid(socket: c_int, euid: *mut u32, egid: *mut u32) -> c_int;
    }
    let mut euid = u32::MAX;
    let mut egid = u32::MAX;
    // SAFETY: `stream` owns a live socket descriptor for the whole call, and
    // both out-pointers name writable storage of Darwin's 32-bit `uid_t` and
    // `gid_t`. The call does not retain either pointer.
    let result = unsafe { getpeereid(stream.as_raw_fd(), &raw mut euid, &raw mut egid) };
    if result != 0 {
        return Err(KeyringError::Io(std::io::Error::last_os_error()));
    }
    Ok(euid)
}

#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
fn unix_peer_uid(_stream: &std::os::unix::net::UnixStream) -> Result<u32> {
    Err(KeyringError::StateInvariant(
        "key-log service peer credentials are unavailable on this platform",
    ))
}

/// One request and its response over a fresh connection, bounded by a single
/// deadline from connect to the end of the response. The request is sent only
/// after the kernel reports that the endpoint is served by `service_uid`.
#[cfg(unix)]
fn exchange_unix<T, U>(socket_path: &Path, service_uid: u32, request: &T) -> Result<U>
where
    T: Serialize,
    U: serde::de::DeserializeOwned + Serialize,
{
    let mut stream = DeadlineUnixStream::connect(socket_path, KEY_LOG_IPC_REQUEST_DEADLINE)?;
    require_peer_uid(&stream.stream, service_uid)?;
    write_canonical_frame(&mut stream, request)?;
    stream.stream.shutdown(std::net::Shutdown::Write)?;
    read_single_canonical_frame(&mut stream)
}

#[cfg(not(unix))]
fn exchange_unix<T, U>(_socket_path: &Path, _service_uid: u32, _request: &T) -> Result<U>
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
    let now = crate::Clock::unix_millis(&crate::SystemClock)?;
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
        now.get(),
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

/// Total time a service exchange has for its request and response, on both
/// the client and the service side.
pub const KEY_LOG_IPC_REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// A bound service socket and the lifecycle lock that keeps another instance
/// from unlinking it.
#[cfg(unix)]
pub struct PrivateUnixListener {
    listener: std::os::unix::net::UnixListener,
    _lifecycle_lock: std::fs::File,
}

#[cfg(unix)]
impl std::ops::Deref for PrivateUnixListener {
    type Target = std::os::unix::net::UnixListener;

    fn deref(&self) -> &Self::Target {
        &self.listener
    }
}

/// Bind a service socket in a directory only the service user can enter, so
/// no other user can connect, even before the socket's own mode is set, or
/// replace the socket. The directory is opened through the keyring's trusted
/// directory chain, so no other user can swap it or any ancestor, and its
/// descriptor is held for the lock, stale-socket and bind steps. bind(2) has
/// no descriptor-relative form, so after binding the path must still resolve
/// to the held directory and name a socket owned by the service user in it. A
/// lifecycle lock serializes instances, so one cannot unlink another's live
/// socket.
#[cfg(unix)]
pub fn bind_private_unix_listener(path: &Path) -> Result<PrivateUnixListener> {
    bind_private_unix_listener_with(path, || Ok(()))
}

#[cfg(unix)]
fn bind_private_unix_listener_with(
    path: &Path,
    before_bind: impl FnOnce() -> std::io::Result<()>,
) -> Result<PrivateUnixListener> {
    use std::os::unix::net::UnixListener;

    use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};

    if !path.is_absolute() {
        return Err(KeyringError::StateInvariant(
            "service socket path must be absolute",
        ));
    }
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(KeyringError::StateInvariant(
            "service socket path has no parent directory",
        ))?;
    let socket_name = path.file_name().ok_or(KeyringError::StateInvariant(
        "service socket path has no file name",
    ))?;
    let parent = open_private_socket_directory(parent_path)?;
    let mut lock_name = socket_name.to_os_string();
    lock_name.push(".lock");
    let lifecycle_lock = std::fs::File::from(
        rustix::fs::openat(
            &parent,
            lock_name.as_os_str(),
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(std::io::Error::from)?,
    );
    if !lifecycle_lock.metadata()?.file_type().is_file() {
        return Err(KeyringError::StateInvariant(
            "service socket lock must be a regular file",
        ));
    }
    match rustix::fs::flock(&lifecycle_lock, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(rustix::io::Errno::WOULDBLOCK) => {
            return Err(KeyringError::StateInvariant(
                "another service instance holds this socket",
            ));
        }
        Err(error) => return Err(KeyringError::Io(error.into())),
    }
    match rustix::fs::statat(&parent, socket_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(existing) => {
            if FileType::from_raw_mode(existing.st_mode) != FileType::Socket {
                return Err(KeyringError::StateInvariant(
                    "service socket path is occupied by a non-socket",
                ));
            }
            let live = match connect_unix_without_waiting(path) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => true,
                Err(error)
                    if error.raw_os_error()
                        == Some(rustix::io::Errno::CONNREFUSED.raw_os_error()) =>
                {
                    false
                }
                Err(error) => return Err(KeyringError::Io(error)),
            };
            if live {
                return Err(KeyringError::StateInvariant(
                    "service socket already has a live listener",
                ));
            }
            rustix::fs::unlinkat(&parent, socket_name, AtFlags::empty())
                .map_err(std::io::Error::from)?;
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => return Err(KeyringError::Io(error.into())),
    }
    before_bind()?;
    let listener = UnixListener::bind(path)?;
    validate_bound_socket(&parent, parent_path, socket_name)?;
    rustix::fs::chmodat(
        &parent,
        socket_name,
        Mode::RUSR | Mode::WUSR,
        AtFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    Ok(PrivateUnixListener {
        listener,
        _lifecycle_lock: lifecycle_lock,
    })
}

/// Connect once without waiting for room in the listen queue. Only a refused
/// connection shows that no listener is bound, so only it marks an existing
/// socket stale. Linux reports a live listener's full queue as `EAGAIN`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn connect_unix_without_waiting(path: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    rustix::net::connect(&socket, &SocketAddrUnix::new(path)?)?;
    Ok(std::os::unix::net::UnixStream::from(socket))
}

/// BSD-derived kernels refuse a connection to a full listen queue instead of
/// waiting, so a blocking connect returns at once. They report that refusal as
/// `ECONNREFUSED`, the same as a socket with no listener.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn connect_unix_without_waiting(path: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(path)
}

/// Open a socket directory through the keyring's trusted directory chain,
/// which refuses symlinked components, foreign owners, untrusted write bits
/// and extended ACL grants on every component. The directory itself must also
/// be owned by the service user with no group or other access, because
/// connecting needs only search permission on it.
#[cfg(unix)]
fn open_private_socket_directory(parent_path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::MetadataExt;

    let directory =
        crate::open_trusted_unix_directory_chain(parent_path).map_err(|error| match error {
            KeyringError::StateInvariant(_) => KeyringError::StateInvariant(
                "service socket directory path must consist of directories owned by the service or root that grant no untrusted write access or extended ACL",
            ),
            other => other,
        })?;
    let metadata = directory.metadata()?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(KeyringError::StateInvariant(
            "service socket directory must be private to the service user",
        ));
    }
    Ok(directory)
}

/// Require the socket path to still resolve to the held directory and the
/// bound name in it to be a socket owned by the service user.
#[cfg(unix)]
fn validate_bound_socket(
    parent: &std::fs::File,
    parent_path: &Path,
    socket_name: &std::ffi::OsStr,
) -> Result<()> {
    let current = open_private_socket_directory(parent_path)?;
    if !crate::unix_metadata_identity_matches(&parent.metadata()?, &current.metadata()?) {
        return Err(KeyringError::StateInvariant(
            "service socket directory changed while the socket was bound",
        ));
    }
    let bound = rustix::fs::statat(parent, socket_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(std::io::Error::from)?;
    if rustix::fs::FileType::from_raw_mode(bound.st_mode) != rustix::fs::FileType::Socket
        || bound.st_uid != rustix::process::geteuid().as_raw()
    {
        return Err(KeyringError::StateInvariant(
            "service socket path does not name the bound socket",
        ));
    }
    Ok(())
}

/// A service connection with one absolute deadline for its request and
/// response. A per-read timeout alone lets a peer that trickles bytes hold a
/// single-threaded service indefinitely.
#[cfg(unix)]
pub struct DeadlineUnixStream {
    stream: std::os::unix::net::UnixStream,
    deadline: std::time::Instant,
}

#[cfg(unix)]
impl DeadlineUnixStream {
    pub fn new(
        stream: std::os::unix::net::UnixStream,
        budget: std::time::Duration,
    ) -> std::io::Result<Self> {
        Ok(Self {
            stream,
            deadline: deadline_after(budget)?,
        })
    }

    /// Connect to a service socket under one deadline that also bounds the
    /// request and the full response.
    pub fn connect(path: &Path, budget: std::time::Duration) -> std::io::Result<Self> {
        let deadline = deadline_after(budget)?;
        let stream = connect_unix_within(path, remaining_until(deadline)?)?;
        Ok(Self { stream, deadline })
    }

    fn remaining(&self) -> std::io::Result<std::time::Duration> {
        remaining_until(self.deadline)
    }
}

#[cfg(unix)]
fn deadline_after(budget: std::time::Duration) -> std::io::Result<std::time::Instant> {
    std::time::Instant::now()
        .checked_add(budget)
        .ok_or_else(|| std::io::Error::other("request deadline overflows"))
}

#[cfg(unix)]
fn remaining_until(deadline: std::time::Instant) -> std::io::Result<std::time::Duration> {
    deadline
        .checked_duration_since(std::time::Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline elapsed")
        })
}

/// Linux waits for room in a full listen queue for up to the socket's send
/// timeout, so the timeout is set before connecting.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn connect_unix_within(
    path: &Path,
    timeout: std::time::Duration,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};

    let socket = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )?;
    // The kernel rejects a microsecond field of one million, which rounding a
    // sub-microsecond remainder up produces, so only whole microseconds pass.
    let timeout =
        std::time::Duration::from_micros(u64::try_from(timeout.as_micros()).unwrap_or(u64::MAX))
            .max(std::time::Duration::from_micros(1));
    rustix::net::sockopt::set_socket_timeout(
        &socket,
        rustix::net::sockopt::Timeout::Send,
        Some(timeout),
    )?;
    rustix::net::connect(&socket, &SocketAddrUnix::new(path)?)?;
    Ok(std::os::unix::net::UnixStream::from(socket))
}

/// BSD-derived kernels refuse a connection to a full listen queue instead of
/// waiting, so connecting cannot outlast the deadline.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn connect_unix_within(
    path: &Path,
    _timeout: std::time::Duration,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    std::os::unix::net::UnixStream::connect(path)
}

#[cfg(unix)]
impl Read for DeadlineUnixStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        bound_operation(
            &self.stream,
            self.stream.set_read_timeout(Some(self.remaining()?)),
        )?;
        self.stream.read(buffer)
    }
}

#[cfg(unix)]
impl Write for DeadlineUnixStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        bound_operation(
            &self.stream,
            self.stream.set_write_timeout(Some(self.remaining()?)),
        )?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        bound_operation(
            &self.stream,
            self.stream.set_write_timeout(Some(self.remaining()?)),
        )?;
        self.stream.flush()
    }
}

/// Darwin refuses socket options once both directions of a socket are shut
/// down, which happens when a peer closes after a half-closed request. Such a
/// socket is made non-blocking instead, so the next operation returns buffered
/// data, end of stream or an error without waiting past the deadline.
#[cfg(unix)]
fn bound_operation(
    stream: &std::os::unix::net::UnixStream,
    timeout_set: std::io::Result<()>,
) -> std::io::Result<()> {
    match timeout_set {
        Err(error)
            if cfg!(target_vendor = "apple")
                && error.raw_os_error() == Some(rustix::io::Errno::INVAL.raw_os_error()) =>
        {
            stream.set_nonblocking(true)
        }
        other => other,
    }
}

#[cfg(all(test, unix))]
mod listener_tests;
