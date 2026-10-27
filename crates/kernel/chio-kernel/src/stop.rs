//! Durable kernel stop (`chio.stop-epoch.v1`).
//!
//! A stop is an append-only, hash-chained sequence of [`StopEpochV1`]
//! records per [`StopScope`], written by the admission serving writer.
//! [`StopHeads`] holds the verified head of each chain together with the
//! process-local host latch. Every kernel a host constructs reads one shared
//! [`StopHeads`], so a stop reaches all of them. [`StopControl`] is the only
//! writer of operator stops and resumes.
//!
//! Fail closed: a chain that cannot be loaded or verified installs a stopped
//! view, and a stop whose durable append fails stays in force in this process.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use arc_swap::ArcSwap;
use chio_core_types::StoreMutationFence;
use serde::{Deserialize, Serialize};

use crate::admission_operation::AdmissionOperationStoreError;

pub const STOP_EPOCH_SCHEMA: &str = "chio.stop-epoch.v1";
pub const STOP_ZERO_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// Upper bound on the canonical encoding of one record.
pub const MAX_STOP_RECORD_BYTES: usize = 4 * 1024;
/// Upper bound on operator reason text kept beside the chain.
pub const MAX_STOP_REASON_BYTES: usize = 1024;
/// Records one chain generation may hold.
pub const STOP_CHAIN_GENERATION_BOUND: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StopScope {
    /// The serving authority that owns the admission store.
    Kernel,
}

impl StopScope {
    /// Stable storage key of the scope's chain.
    #[must_use]
    pub fn key(&self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopTransition {
    Stop,
    Resume,
}

impl StopTransition {
    #[must_use]
    pub fn resulting_state(self) -> StopState {
        match self {
            Self::Stop => StopState::Stopped,
            Self::Resume => StopState::Running,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopState {
    Stopped,
    Running,
}

/// A position in a scope's chain, ordered by generation and then epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopEpochId {
    pub chain_generation: u32,
    pub epoch: u64,
}

impl StopEpochId {
    /// The position a scope's first record is decided against.
    pub const GENESIS: Self = Self {
        chain_generation: 1,
        epoch: 0,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "unix_ms", rename_all = "snake_case")]
pub enum DecisionTime {
    /// Authority time observed inside the appending transaction.
    Observed(u64),
    /// Authority time was unavailable. Valid for `Stop` only.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StopAuthorizer {
    /// A shared control credential authorized the transition. Only the
    /// credential is known, not a principal.
    SharedCredential { credential_id_hash: String },
}

impl StopAuthorizer {
    /// Name a shared control credential by a stable, non-secret identifier.
    #[must_use]
    pub fn shared_credential(credential_id: &str) -> Self {
        let mut material = b"chio.stop-credential-id.v1\0".to_vec();
        material.extend_from_slice(credential_id.as_bytes());
        Self::SharedCredential {
            credential_id_hash: chio_core_types::sha256_hex(&material),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StopRequestPath {
    Route { host_id: String },
    ControlSocket,
    OfflineCli,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopEpochV1 {
    pub schema: String,
    pub authority_id: String,
    pub scope: StopScope,
    pub chain_generation: u32,
    pub epoch: u64,
    pub transition: StopTransition,
    pub state: StopState,
    pub expected_epoch: StopEpochId,
    /// SHA-256 of the salt and the reason text, both kept outside the chain.
    pub reason_commitment: String,
    pub authorizer: StopAuthorizer,
    pub decided_at: DecisionTime,
    /// Persisted trusted-time floor read in the appending transaction.
    pub trusted_floor_at_commit: u64,
    /// Digest of the scope's prior record, or the zero digest.
    pub previous: String,
    pub allow_containment: bool,
    pub requested_via: StopRequestPath,
}

impl StopEpochV1 {
    #[must_use]
    pub fn id(&self) -> StopEpochId {
        StopEpochId {
            chain_generation: self.chain_generation,
            epoch: self.epoch,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StopChainError> {
        chio_core_types::canonical_json_bytes(self)
            .map_err(|error| StopChainError(format!("stop record is not canonical: {error}")))
    }

    pub fn digest(&self) -> Result<String, StopChainError> {
        Ok(chio_core_types::sha256_hex(&self.canonical_bytes()?))
    }

    /// Check one record against its predecessor in the same scope.
    pub fn verify_successor(
        &self,
        authority_id: &str,
        scope: StopScope,
        previous: Option<&StopEpochV1>,
    ) -> Result<(), StopChainError> {
        if self.schema != STOP_EPOCH_SCHEMA {
            return Err(chain_error("stop record schema is not chio.stop-epoch.v1"));
        }
        if self.authority_id.is_empty() || self.authority_id != authority_id {
            return Err(chain_error("stop record belongs to another authority"));
        }
        if self.scope != scope {
            return Err(chain_error("stop record belongs to another scope"));
        }
        if self.chain_generation != 1 {
            return Err(chain_error("stop record chain generation is unsupported"));
        }
        if self.canonical_bytes()?.len() > MAX_STOP_RECORD_BYTES {
            return Err(chain_error("stop record exceeds its size bound"));
        }
        if self.state != self.transition.resulting_state() {
            return Err(chain_error(
                "stop record state does not follow its transition",
            ));
        }
        require_digest(&self.reason_commitment, "reason commitment")?;
        require_digest(&self.previous, "previous digest")?;
        match &self.authorizer {
            StopAuthorizer::SharedCredential { credential_id_hash } => {
                require_digest(credential_id_hash, "credential id hash")?;
            }
        }
        if let StopRequestPath::Route { host_id } = &self.requested_via {
            if host_id.is_empty() || host_id.len() > 256 {
                return Err(chain_error("stop record route host id is invalid"));
            }
        }
        if self.transition == StopTransition::Resume
            && !matches!(self.decided_at, DecisionTime::Observed(_))
        {
            return Err(chain_error("a resume requires observed authority time"));
        }
        let (expected_id, expected_previous, prior_state) = match previous {
            None => (
                StopEpochId::GENESIS,
                STOP_ZERO_DIGEST.to_owned(),
                StopState::Running,
            ),
            Some(previous) => (previous.id(), previous.digest()?, previous.state),
        };
        if self.expected_epoch != expected_id || self.previous != expected_previous {
            return Err(chain_error("stop record does not extend its predecessor"));
        }
        let next_epoch = expected_id
            .epoch
            .checked_add(1)
            .ok_or_else(|| chain_error("stop chain epoch overflowed"))?;
        if self.epoch != next_epoch || self.epoch > STOP_CHAIN_GENERATION_BOUND {
            return Err(chain_error("stop chain epoch is not contiguous"));
        }
        if prior_state == self.state {
            return Err(chain_error("stop record repeats its predecessor's state"));
        }
        if self.transition == StopTransition::Resume
            && self.epoch >= STOP_CHAIN_GENERATION_BOUND - 1
        {
            return Err(chain_error("a resume may not take the chain's last slots"));
        }
        Ok(())
    }
}

/// Verify a whole chain in epoch order and return its head.
pub fn verify_stop_chain<'a>(
    authority_id: &str,
    scope: StopScope,
    records: &'a [StopEpochV1],
) -> Result<Option<&'a StopEpochV1>, StopChainError> {
    let mut head = None;
    for record in records {
        record.verify_successor(authority_id, scope, head)?;
        head = Some(record);
    }
    Ok(head)
}

/// SHA-256 commitment to an operator reason under a fresh salt.
#[must_use]
pub fn stop_reason_commitment(salt: &[u8], reason: &str) -> String {
    let mut material = salt.to_vec();
    material.extend_from_slice(reason.as_bytes());
    chio_core_types::sha256_hex(&material)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("stop chain is invalid: {0}")]
pub struct StopChainError(pub String);

fn chain_error(detail: &str) -> StopChainError {
    StopChainError(detail.to_owned())
}

fn require_digest(value: &str, label: &str) -> Result<(), StopChainError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(StopChainError(format!(
            "stop record {label} is not a SHA-256 digest"
        )))
    }
}

/// A transition the serving writer is asked to append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopTransitionRequest {
    pub scope: StopScope,
    pub transition: StopTransition,
    /// Required for `Resume`: the head the operator decided against.
    pub expected_epoch: Option<StopEpochId>,
    pub reason: String,
    pub authorizer: StopAuthorizer,
    pub requested_via: StopRequestPath,
    pub allow_containment: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DurableStopError {
    /// A resume was decided against a head that has since moved.
    #[error("stop head moved")]
    HeadMoved { head: Option<StopEpochId> },
    /// A resume needs authority time and none was available.
    #[error("authority time is unavailable for a resume")]
    TimeUnavailable,
    #[error("stop chain is invalid: {0}")]
    Chain(#[from] StopChainError),
    #[error(transparent)]
    Store(#[from] AdmissionOperationStoreError),
}

/// The admission serving writer's stop chain.
pub trait DurableStopStore: Send + Sync {
    /// Load and verify the scope's whole chain, returning its head.
    fn load_stop_head(&self, scope: StopScope) -> Result<Option<StopEpochV1>, DurableStopError>;

    /// Append a transition in one writer transaction and return the head
    /// after it. A `Stop` over a stopped head and a `Resume` over a running
    /// head append nothing and return the current head.
    fn append_stop_transition(
        &self,
        request: &StopTransitionRequest,
        fence: &StoreMutationFence,
    ) -> Result<Option<StopEpochV1>, DurableStopError>;

    /// Count the returned operations whose output release is pending. While
    /// a stop holds, each one keeps its output in durable custody.
    fn withheld_operations(&self) -> Result<u64, DurableStopError>;
}

/// Where the durable view came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopDurability {
    /// No durable store is attached; stops last only for this process.
    ProcessLocal,
    /// Heads were loaded from a verified durable chain.
    Durable,
    /// The durable chain could not be loaded or verified. Fails closed.
    Unverified { reason: String },
}

#[derive(Debug, Clone)]
struct StopHeadsSnapshot {
    durability: StopDurability,
    head: Option<StopEpochV1>,
    /// An operator stop this process holds without a durable record.
    process_stop: Option<String>,
}

impl StopHeadsSnapshot {
    fn stopped(&self) -> bool {
        matches!(self.durability, StopDurability::Unverified { .. })
            || self.process_stop.is_some()
            || self
                .head
                .as_ref()
                .is_some_and(|head| head.state == StopState::Stopped)
    }
}

/// Stop state shared by every kernel bound to one store in a process.
#[derive(Debug)]
pub struct StopHeads {
    snapshot: ArcSwap<StopHeadsSnapshot>,
    host_latched: AtomicBool,
    host_latched_since: AtomicU64,
    host_reason: ArcSwap<Option<String>>,
}

impl StopHeads {
    fn new(durability: StopDurability, head: Option<StopEpochV1>) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(StopHeadsSnapshot {
                durability,
                head,
                process_stop: None,
            }),
            host_latched: AtomicBool::new(false),
            host_latched_since: AtomicU64::new(0),
            host_reason: ArcSwap::from_pointee(None),
        }
    }

    /// Whether any applicable head or latch stops execution.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.host_latched.load(Ordering::SeqCst) || self.snapshot.load().stopped()
    }

    /// Engage the process-local host latch. The latch is published
    /// before the caller reads any clock.
    pub fn latch_host(&self, reason: &str) {
        self.host_latched_since.store(0, Ordering::SeqCst);
        self.host_reason.store(Arc::new(Some(reason.to_owned())));
        self.host_latched.store(true, Ordering::SeqCst);
    }

    /// Record when the host latch engaged, once trusted time is available.
    pub fn record_host_latch_time(&self, unix_secs: u64) {
        if self.host_latched.load(Ordering::SeqCst) {
            self.host_latched_since.store(unix_secs, Ordering::SeqCst);
        }
    }

    pub fn release_host_latch(&self) {
        self.host_latched.store(false, Ordering::SeqCst);
        self.host_latched_since.store(0, Ordering::SeqCst);
        self.host_reason.store(Arc::new(None));
    }

    #[must_use]
    pub fn host_latched(&self) -> bool {
        self.host_latched.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn host_latched_since(&self) -> Option<u64> {
        if !self.host_latched() {
            return None;
        }
        match self.host_latched_since.load(Ordering::SeqCst) {
            0 => None,
            since => Some(since),
        }
    }

    #[must_use]
    pub fn host_reason(&self) -> Option<String> {
        if !self.host_latched() {
            return None;
        }
        self.host_reason.load_full().as_ref().clone()
    }

    fn update(&self, change: impl FnOnce(&mut StopHeadsSnapshot)) {
        let mut next = self.snapshot.load_full().as_ref().clone();
        change(&mut next);
        self.snapshot.store(Arc::new(next));
    }
}

/// Readiness of a stop-bearing host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StopReadiness {
    Ready,
    ReadyStopped,
    NotReady { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopHeadStatus {
    pub chain_generation: u32,
    pub epoch: u64,
    pub state: StopState,
    pub authorizer: StopAuthorizer,
    pub decided_at: DecisionTime,
    pub allow_containment: bool,
    pub requested_via: StopRequestPath,
}

/// Operator-visible stop status for one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopStatus {
    pub scope: StopScope,
    pub stopped: bool,
    pub readiness: StopReadiness,
    /// `durable`, `process_local`, `process_only` or `unverified`.
    pub durability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<StopHeadStatus>,
    pub host_latch: bool,
    /// Returned operations whose output stays in durable custody until
    /// resume. Present while a stop holds over a readable durable store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withheld_operations: Option<u64>,
}

/// Body of a stop request on every operator control surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopRequestBody {
    pub reason: String,
    /// Whether governed containment stays available while stopped.
    #[serde(default = "allow_containment_by_default")]
    pub allow_containment: bool,
}

fn allow_containment_by_default() -> bool {
    true
}

/// Body of a resume request on every operator control surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeRequestBody {
    /// The stopped head the operator decided to resume.
    pub expected_epoch: StopEpochId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopCommand {
    pub reason: String,
    pub authorizer: StopAuthorizer,
    pub requested_via: StopRequestPath,
    pub allow_containment: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeCommand {
    pub expected_epoch: Option<StopEpochId>,
    pub authorizer: StopAuthorizer,
    pub requested_via: StopRequestPath,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StopControlError {
    #[error("invalid stop request: {0}")]
    BadRequest(String),
    /// The stop holds in this process, but no durable record committed.
    #[error("stop is not durable: {detail}")]
    NotDurable {
        detail: String,
        status: Box<StopStatus>,
    },
    #[error("stop head moved")]
    HeadMoved { head: Option<StopEpochId> },
    #[error("stop control is not ready: {0}")]
    NotReady(String),
    #[error("resume refused: {0}")]
    Refused(String),
}

impl StopControlError {
    /// Stable machine-readable result code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::NotDurable { .. } => "stop_not_durable",
            Self::HeadMoved { .. } => "stop_head_moved",
            Self::NotReady(_) => "stop_not_ready",
            Self::Refused(_) => "resume_refused",
        }
    }

    /// HTTP status for this result on a mounted route.
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::HeadMoved { .. } => 409,
            Self::NotDurable { .. } | Self::NotReady(_) | Self::Refused(_) => 503,
        }
    }

    /// Wire body for this result. A non-durable stop still reports the
    /// stop it holds.
    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        let (message, urn) = match self {
            Self::BadRequest(_) => (
                "Invalid stop request.",
                "urn:chio:error:kernel:stop-bad-request",
            ),
            Self::NotDurable { .. } => (
                "Stop holds in this process but could not be made durable.",
                "urn:chio:error:kernel:stop-not-durable",
            ),
            Self::HeadMoved { .. } => ("Stop head moved.", "urn:chio:error:kernel:stop-head-moved"),
            Self::NotReady(_) => (
                "Stop control is not ready.",
                "urn:chio:error:kernel:stop-not-ready",
            ),
            Self::Refused(_) => (
                "Resume was refused.",
                "urn:chio:error:kernel:resume-refused",
            ),
        };
        let mut body = serde_json::Map::new();
        body.insert("error".into(), self.code().into());
        body.insert("message".into(), message.into());
        body.insert("urn".into(), urn.into());
        let detail = match self {
            Self::NotDurable { status, .. } => Some(("status", serde_json::to_value(status))),
            Self::HeadMoved { head } => Some(("head", serde_json::to_value(head))),
            _ => None,
        };
        if let Some((field, value)) = detail {
            body.insert(field.into(), value.unwrap_or(serde_json::Value::Null));
        }
        serde_json::Value::Object(body)
    }
}

const STOP_STORE_CLOSED: &str = "stop store is closed";

struct DurableStopBinding {
    store: Weak<dyn DurableStopStore>,
    fence: StoreMutationFence,
    transitions: Mutex<()>,
}

/// Operator stop and resume for the kernel scope of one store.
///
/// Clones share one [`StopHeads`] and one durable binding, so every kernel
/// and every control surface of a host observes and drives the same stop.
#[derive(Clone)]
pub struct StopControl {
    heads: Arc<StopHeads>,
    durable: Option<Arc<DurableStopBinding>>,
}

impl std::fmt::Debug for StopControl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StopControl")
            .field("heads", &self.heads)
            .field("durable", &self.durable.is_some())
            .finish()
    }
}

impl Default for StopControl {
    fn default() -> Self {
        Self::process_local()
    }
}

impl StopControl {
    /// Stop control with no durable store. A stop lasts for this process.
    #[must_use]
    pub fn process_local() -> Self {
        Self {
            heads: Arc::new(StopHeads::new(StopDurability::ProcessLocal, None)),
            durable: None,
        }
    }

    /// Bind to a durable chain and load its verified head. A chain that
    /// cannot be loaded or verified installs a stopped, not-ready view.
    ///
    /// The control does not keep the store open; its owner does. Once the
    /// owner closes the store, a stop holds only in this process and a resume
    /// is refused.
    #[must_use]
    pub fn durable<S: DurableStopStore + 'static>(
        store: &Arc<S>,
        fence: StoreMutationFence,
    ) -> Self {
        let (durability, head) = match store.load_stop_head(StopScope::Kernel) {
            Ok(head) => (StopDurability::Durable, head),
            Err(error) => {
                tracing::error!(error = %error, "stop chain unverified; failing closed");
                (
                    StopDurability::Unverified {
                        reason: "stop_chain_unverified".to_owned(),
                    },
                    None,
                )
            }
        };
        let owned: Weak<S> = Arc::downgrade(store);
        let store: Weak<dyn DurableStopStore> = owned;
        Self {
            heads: Arc::new(StopHeads::new(durability, head)),
            durable: Some(Arc::new(DurableStopBinding {
                store,
                fence,
                transitions: Mutex::new(()),
            })),
        }
    }

    #[must_use]
    pub fn heads(&self) -> &Arc<StopHeads> {
        &self.heads
    }

    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.durable.is_some()
    }

    /// Stop the kernel scope. The stop takes effect in this process before
    /// the durable append, and stays in force if that append fails.
    pub fn stop(&self, command: StopCommand) -> Result<StopStatus, StopControlError> {
        validate_reason(&command.reason)?;
        self.heads
            .update(|snapshot| snapshot.process_stop = Some(command.reason.clone()));
        let Some(durable) = &self.durable else {
            return Ok(self.status());
        };
        let Some(store) = durable.store.upgrade() else {
            return Err(StopControlError::NotDurable {
                detail: STOP_STORE_CLOSED.to_owned(),
                status: Box::new(self.status()),
            });
        };
        let _transition = durable
            .transitions
            .lock()
            .map_err(|_| StopControlError::NotReady("stop control lock poisoned".to_owned()))?;
        let request = StopTransitionRequest {
            scope: StopScope::Kernel,
            transition: StopTransition::Stop,
            expected_epoch: None,
            reason: command.reason,
            authorizer: command.authorizer,
            requested_via: command.requested_via,
            allow_containment: command.allow_containment,
        };
        match store.append_stop_transition(&request, &durable.fence) {
            Ok(head) => {
                self.heads.update(|snapshot| {
                    snapshot.head = head;
                    snapshot.process_stop = None;
                });
                Ok(self.status())
            }
            Err(error) => {
                tracing::error!(error = %error, "durable stop append failed; holding the stop in this process");
                Err(StopControlError::NotDurable {
                    detail: error.to_string(),
                    status: Box::new(self.status()),
                })
            }
        }
    }

    /// Resume the kernel scope. Nothing clears until the resume commits.
    pub fn resume(&self, command: ResumeCommand) -> Result<StopStatus, StopControlError> {
        let Some(durable) = &self.durable else {
            self.heads.update(|snapshot| snapshot.process_stop = None);
            return Ok(self.status());
        };
        if let StopDurability::Unverified { reason } = self.durability() {
            return Err(StopControlError::NotReady(reason));
        }
        let Some(store) = durable.store.upgrade() else {
            return Err(StopControlError::NotReady(STOP_STORE_CLOSED.to_owned()));
        };
        let _transition = durable
            .transitions
            .lock()
            .map_err(|_| StopControlError::NotReady("stop control lock poisoned".to_owned()))?;
        let request = StopTransitionRequest {
            scope: StopScope::Kernel,
            transition: StopTransition::Resume,
            expected_epoch: command.expected_epoch,
            reason: String::new(),
            authorizer: command.authorizer,
            requested_via: command.requested_via,
            allow_containment: false,
        };
        match store.append_stop_transition(&request, &durable.fence) {
            Ok(head) => {
                self.heads.update(|snapshot| {
                    snapshot.head = head;
                    snapshot.process_stop = None;
                });
                Ok(self.status())
            }
            Err(DurableStopError::HeadMoved { head }) => Err(StopControlError::HeadMoved { head }),
            Err(DurableStopError::TimeUnavailable) => {
                tracing::warn!("durable resume refused because authority time is unavailable");
                Err(StopControlError::Refused(
                    "authority time is unavailable".to_owned(),
                ))
            }
            Err(error) => {
                tracing::error!(error = %error, "durable resume append failed");
                Err(StopControlError::Refused(error.to_string()))
            }
        }
    }

    #[must_use]
    pub fn status(&self) -> StopStatus {
        let snapshot = self.heads.snapshot.load_full();
        let stopped = self.heads.is_stopped();
        let readiness = match &snapshot.durability {
            StopDurability::Unverified { reason } => StopReadiness::NotReady {
                reason: reason.clone(),
            },
            _ if stopped => StopReadiness::ReadyStopped,
            _ => StopReadiness::Ready,
        };
        let durability = match (&snapshot.durability, snapshot.process_stop.is_some()) {
            (StopDurability::Unverified { .. }, _) => "unverified",
            (StopDurability::ProcessLocal, _) => "process_local",
            (StopDurability::Durable, true) => "process_only",
            (StopDurability::Durable, false) => "durable",
        };
        StopStatus {
            scope: StopScope::Kernel,
            stopped,
            readiness,
            durability: durability.to_owned(),
            head: snapshot.head.as_ref().map(|head| StopHeadStatus {
                chain_generation: head.chain_generation,
                epoch: head.epoch,
                state: head.state,
                authorizer: head.authorizer.clone(),
                decided_at: head.decided_at,
                allow_containment: head.allow_containment,
                requested_via: head.requested_via.clone(),
            }),
            host_latch: self.heads.host_latched(),
            withheld_operations: if stopped {
                self.withheld_operations()
            } else {
                None
            },
        }
    }

    fn withheld_operations(&self) -> Option<u64> {
        let store = self.durable.as_ref()?.store.upgrade()?;
        match store.withheld_operations() {
            Ok(count) => Some(count),
            Err(error) => {
                tracing::error!(error = %error, "withheld operation count is unavailable");
                None
            }
        }
    }

    fn durability(&self) -> StopDurability {
        self.heads.snapshot.load().durability.clone()
    }
}

fn validate_reason(reason: &str) -> Result<(), StopControlError> {
    if reason.trim().is_empty() {
        return Err(StopControlError::BadRequest(
            "a stop requires a reason".to_owned(),
        ));
    }
    if reason.len() > MAX_STOP_REASON_BYTES {
        return Err(StopControlError::BadRequest(
            "stop reason is too long".to_owned(),
        ));
    }
    if reason.chars().any(char::is_control) {
        return Err(StopControlError::BadRequest(
            "stop reason contains control characters".to_owned(),
        ));
    }
    Ok(())
}

#[path = "stop/config.rs"]
pub mod config;

#[cfg(test)]
#[path = "stop/tests.rs"]
mod tests;
