//! One ingress reservation follows each message through inbox and deferred storage.
//! The reserved control share is part of the original aggregate ceiling.
use super::budget::{AccountedMessage, Footprint, IngressBudget, IngressUsage};
use crate::AdapterError;
use serde::Deserialize;
use serde_json::{value::RawValue, Value};
use std::sync::{mpsc, Arc, Mutex};

const CONTROL_WIRE: usize = 1024 * 1024;
const CONTROL_NODES: usize = 64 * 1024;
const IDENTITY_BYTES: usize = 512;

pub(crate) enum ClientInbound {
    Accounted(AccountedMessage),
    HostProtocolRefusal(Box<HostProtocolRefusal>),
    #[cfg(test)]
    Message(Value),
    ParseError(AdapterError),
    #[cfg(test)]
    ReadError(String),
    #[cfg(test)]
    Closed,
}

/// This variant has no JSON decoder or peer-callable method.
pub(crate) struct HostProtocolRefusal {
    pub(crate) summary: chio_kernel::ProtocolRefusalSummary,
    pub(crate) reservation: super::budget::FrameReservation,
    pub(crate) acknowledgement:
        mpsc::SyncSender<Result<chio_core::receipt::body::ChioReceipt, chio_kernel::KernelError>>,
}

pub type ProtocolRefusalAcknowledgement =
    mpsc::Receiver<Result<chio_core::receipt::body::ChioReceipt, chio_kernel::KernelError>>;

#[derive(Default)]
struct ControlState {
    reply: Option<Value>,
    parent: Option<Value>,
    task: Option<String>,
    closed: bool,
}

#[derive(Clone)]
pub(crate) struct InboxAdmission {
    ordinary: IngressBudget,
    control: IngressBudget,
    state: Arc<Mutex<ControlState>>,
}

impl InboxAdmission {
    pub(crate) fn new() -> Self {
        let ordinary = IngressBudget::for_inbox(
            Footprint {
                wire_bytes: 8 * 1024 * 1024 - CONTROL_WIRE,
                nodes: 1024 * 1024 - CONTROL_NODES,
                text_bytes: 8 * 1024 * 1024 - CONTROL_WIRE,
            },
            128,
        );
        Self {
            control: ordinary.control_share(),
            ordinary,
            state: Arc::new(Mutex::new(ControlState::default())),
        }
    }

    fn budget(&self, value: &Value) -> Result<&IngressBudget, AdapterError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AdapterError::ConnectionFailed("MCP inbox state is poisoned".into()))?;
        if state.closed {
            return Err(AdapterError::ConnectionFailed("MCP inbox is closed".into()));
        }
        Ok(if matches_control(&state, value) {
            &self.control
        } else {
            &self.ordinary
        })
    }

    pub(crate) fn admit_value(&self, value: Value) -> Result<AccountedMessage, AdapterError> {
        self.budget(&value)?.admit_value(value)
    }

    pub(crate) fn begin_wait(&self, reply: Value) -> Result<ControlGuard, AdapterError> {
        if !bounded_id(&reply) {
            return Err(AdapterError::IngressCapacity);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| AdapterError::ConnectionFailed("MCP inbox state is poisoned".into()))?;
        if state.reply.is_some() || state.closed {
            return Err(AdapterError::ConnectionFailed(
                "MCP client wait is unavailable".into(),
            ));
        }
        state.reply = Some(reply);
        Ok(ControlGuard {
            state: self.state.clone(),
            reply: true,
        })
    }

    pub(crate) fn begin_operation(
        &self,
        parent: &Value,
        task: Option<&str>,
    ) -> Result<ControlGuard, AdapterError> {
        if !bounded_id(parent) || task.is_some_and(|task| task.len() > IDENTITY_BYTES) {
            return Err(AdapterError::IngressCapacity);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| AdapterError::ConnectionFailed("MCP inbox state is poisoned".into()))?;
        if state.parent.is_some() || state.closed {
            return Err(AdapterError::ConnectionFailed(
                "MCP operation control is unavailable".into(),
            ));
        }
        state.parent = Some(parent.clone());
        state.task = task.map(str::to_owned);
        Ok(ControlGuard {
            state: self.state.clone(),
            reply: false,
        })
    }

    fn decode(&self, bytes: &[u8], bound: usize) -> Result<AccountedMessage, AdapterError> {
        chio_core::canonical::UntrustedJsonText::from_wire(bytes, bound)?;
        // Borrow the envelope slices, projecting only bounded control identities.
        // Structural admission still precedes the full unsigned/signed-proof DOM.
        let identity = control_identity(bytes);
        let budget = self.budget(&identity)?;
        let wire = std::str::from_utf8(bytes)
            .map_err(chio_core::canonical::UntrustedJsonError::NotUtf8)?;
        let reservation = budget.admit(wire)?;
        let value = super::decode_mcp_request(bytes, bound)?;
        Ok(AccountedMessage { value, reservation })
    }

    pub(crate) fn owns(&self, message: &AccountedMessage) -> bool {
        self.ordinary.owns(message) || self.control.owns(message)
    }

    pub(crate) fn usage(&self) -> Result<IngressUsage, AdapterError> {
        self.ordinary.usage()
    }
}

pub(crate) struct ControlGuard {
    state: Arc<Mutex<ControlState>>,
    reply: bool,
}
impl Drop for ControlGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            if self.reply {
                state.reply = None;
            } else {
                state.parent = None;
                state.task = None;
            }
        }
    }
}

fn bounded_id(value: &Value) -> bool {
    match value {
        Value::String(text) => text.len() <= IDENTITY_BYTES,
        Value::Number(_) | Value::Null => true,
        _ => false,
    }
}

fn matches_control(state: &ControlState, value: &Value) -> bool {
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return false;
    }
    match value.get("method").and_then(Value::as_str) {
        None => {
            value.get("method").is_none()
                && state
                    .reply
                    .as_ref()
                    .is_some_and(|reply| value.get("id") == Some(reply))
        }
        Some("notifications/cancelled") => value.pointer("/params/requestId").is_some_and(|id| {
            state.reply.as_ref() == Some(id) || state.parent.as_ref() == Some(id)
        }),
        Some("tasks/cancel") => {
            value.get("id").is_some_and(bounded_id)
                && state.task.as_deref().is_some_and(|task| {
                    value.pointer("/params/taskId").and_then(Value::as_str) == Some(task)
                })
        }
        _ => false,
    }
}

#[derive(Deserialize)]
struct Envelope<'a> {
    #[serde(default, borrow, deserialize_with = "raw_member")]
    jsonrpc: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "raw_member")]
    id: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "raw_member")]
    method: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "raw_member")]
    params: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct Params<'a> {
    #[serde(default, borrow, rename = "requestId", deserialize_with = "raw_member")]
    request: Option<&'a RawValue>,
    #[serde(default, borrow, rename = "taskId", deserialize_with = "raw_member")]
    task: Option<&'a RawValue>,
}

fn raw_member<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<&'de RawValue>, D::Error> {
    <&'de RawValue>::deserialize(decoder).map(Some)
}
fn scalar(raw: Option<&RawValue>) -> Option<Value> {
    let raw = raw.filter(|raw| raw.get().len() <= IDENTITY_BYTES)?;
    let value: Value = serde_json::from_str(raw.get()).ok()?;
    bounded_id(&value).then_some(value)
}
fn control_identity(bytes: &[u8]) -> Value {
    let Ok(envelope) = serde_json::from_slice::<Envelope<'_>>(bytes) else {
        return Value::Null;
    };
    let params = envelope
        .params
        .and_then(|params| serde_json::from_str::<Params<'_>>(params.get()).ok());
    let mut identity = serde_json::Map::new();
    for (key, raw) in [
        ("jsonrpc", envelope.jsonrpc),
        ("id", envelope.id),
        ("method", envelope.method),
    ] {
        if raw.is_some() {
            identity.insert(key.into(), scalar(raw).unwrap_or(Value::Bool(false)));
        }
    }
    if let Some(params) = params {
        let mut values = serde_json::Map::new();
        for (key, raw) in [("requestId", params.request), ("taskId", params.task)] {
            if raw.is_some() {
                values.insert(key.into(), scalar(raw).unwrap_or(Value::Bool(false)));
            }
        }
        identity.insert("params".into(), Value::Object(values));
    }
    Value::Object(identity)
}

/// Nonblocking sender whose capacity includes queued, active and deferred messages.
#[derive(Clone)]
pub struct McpInboxSender {
    sender: mpsc::Sender<ClientInbound>,
    admission: InboxAdmission,
}
impl std::fmt::Debug for McpInboxSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("McpInboxSender")
            .finish_non_exhaustive()
    }
}
impl McpInboxSender {
    /// Decode original ingress bytes only after reserving their aggregate footprint.
    pub fn decode(&self, bytes: &[u8], bound: usize) -> Result<AccountedMessage, AdapterError> {
        self.admission.decode(bytes, bound)
    }
    /// Already-decoded in-process callers remain bounded; their external source
    /// queue and unavailable original wire bytes are outside this contract.
    pub fn account(&self, value: Value) -> Result<AccountedMessage, AdapterError> {
        self.admission.admit_value(value)
    }
    pub fn send(&self, message: AccountedMessage) -> Result<(), AdapterError> {
        if !self.admission.owns(&message) {
            return Err(AdapterError::IngressCapacity);
        }
        self.sender
            .send(ClientInbound::Accounted(message))
            .map_err(|_| AdapterError::ConnectionFailed("MCP inbox receiver is unavailable".into()))
    }
    /// Submit a trusted host observation using the original message reservation.
    /// The receiver acknowledges only after the owning kernel persistence call.
    pub fn record_protocol_refusal(
        &self,
        message: AccountedMessage,
        summary: chio_kernel::ProtocolRefusalSummary,
    ) -> Result<ProtocolRefusalAcknowledgement, AdapterError> {
        if !self.admission.owns(&message)
            || message.request_digest() != Some(summary.request_digest())
        {
            return Err(AdapterError::IngressCapacity);
        }
        let (value, reservation) = message.into_parts();
        drop(value);
        let (acknowledgement, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(ClientInbound::HostProtocolRefusal(Box::new(
                HostProtocolRefusal {
                    summary,
                    reservation,
                    acknowledgement,
                },
            )))
            .map_err(|_| {
                AdapterError::ConnectionFailed("MCP inbox receiver is unavailable".into())
            })?;
        Ok(receiver)
    }
    pub fn usage(&self) -> Result<IngressUsage, AdapterError> {
        self.admission.usage()
    }
    pub(crate) fn error(&self, error: AdapterError) {
        let _ = self.sender.send(ClientInbound::ParseError(error));
    }
}

pub struct McpInboxReceiver {
    pub(crate) receiver: mpsc::Receiver<ClientInbound>,
    pub(crate) admission: InboxAdmission,
    _lifetime: ReceiverLifetime,
}
impl McpInboxReceiver {
    /// Receive without blocking, retaining the message's accounting ownership.
    pub fn try_recv(&self) -> Result<Option<AccountedMessage>, AdapterError> {
        match self.receiver.try_recv() {
            Ok(ClientInbound::Accounted(message)) => Ok(Some(message)),
            Ok(ClientInbound::HostProtocolRefusal(command)) => {
                let _ = command
                    .acknowledgement
                    .send(Err(chio_kernel::KernelError::Internal(
                        "host refusal requires the owning kernel worker".into(),
                    )));
                Err(AdapterError::ConnectionFailed(
                    "host refusal requires the owning worker".into(),
                ))
            }
            #[cfg(test)]
            Ok(ClientInbound::Message(value)) => self.admission.admit_value(value).map(Some),
            Ok(ClientInbound::ParseError(error)) => Err(error),
            #[cfg(test)]
            Ok(ClientInbound::ReadError(error)) => Err(AdapterError::ConnectionFailed(error)),
            #[cfg(test)]
            Ok(ClientInbound::Closed) => {
                Err(AdapterError::ConnectionFailed("MCP inbox is closed".into()))
            }
            Err(mpsc::TryRecvError::Disconnected) => Err(AdapterError::ConnectionFailed(
                "MCP inbox is disconnected".into(),
            )),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
        }
    }
}
struct ReceiverLifetime(Arc<Mutex<ControlState>>);
impl Drop for ReceiverLifetime {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.closed = true;
        }
    }
}
/// Ordinary admission stops at 128 retained messages, leaving eight additional
/// slots and a resource share for active-identity control delivery (136 total).
/// including messages consumed from this channel but retained in deferred work.
pub fn mcp_inbox() -> (McpInboxSender, McpInboxReceiver) {
    let admission = InboxAdmission::new();
    let (sender, receiver) = mpsc::channel();
    (
        McpInboxSender {
            sender,
            admission: admission.clone(),
        },
        McpInboxReceiver {
            receiver,
            _lifetime: ReceiverLifetime(admission.state.clone()),
            admission,
        },
    )
}

#[cfg(test)]
mod tests;
