//! Per-transport ingress compatibility limits, shared by both queues and the
//! current decoded frame: 8 MiB wire, 1,048,576 JSON nodes, 8 MiB decoded text.
//!
//! Admission counts structure before canonical DOM decoding. These bounds limit
//! expansion and retention, not exact allocator RSS. The single reader also has
//! one bounded 4 MiB wire buffer and bounded string-unescape scratch. Ownership
//! handed to a transport caller is outside this budget. No reservation is cloned.

use std::fmt::{self, Write as _};
use std::io::BufRead;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use super::framing::read_document_frame_with_admission;
use crate::AdapterError;

mod admission;
mod response_scope;
pub use response_scope::{McpRequestGeneration, McpResponseContext, McpResponseScope};
#[cfg(test)]
mod tests;

const MAX_RETAINED_WIRE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RETAINED_NODES: usize = 1024 * 1024;
const MAX_RETAINED_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIAGNOSTIC_COMPONENT_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Footprint {
    pub(super) wire_bytes: usize,
    pub(super) nodes: usize,
    pub(super) text_bytes: usize,
}

impl Footprint {
    fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            wire_bytes: self.wire_bytes.checked_add(other.wire_bytes)?,
            nodes: self.nodes.checked_add(other.nodes)?,
            text_bytes: self.text_bytes.checked_add(other.text_bytes)?,
        })
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        Some(Self {
            wire_bytes: self.wire_bytes.checked_sub(other.wire_bytes)?,
            nodes: self.nodes.checked_sub(other.nodes)?,
            text_bytes: self.text_bytes.checked_sub(other.text_bytes)?,
        })
    }

    fn exceeded(self) -> Option<&'static str> {
        self.exceeded_at(Self {
            wire_bytes: MAX_RETAINED_WIRE_BYTES,
            nodes: MAX_RETAINED_NODES,
            text_bytes: MAX_RETAINED_TEXT_BYTES,
        })
    }

    fn exceeded_at(self, limits: Self) -> Option<&'static str> {
        if self.wire_bytes > limits.wire_bytes {
            Some("wire bytes")
        } else if self.nodes > limits.nodes {
            Some("JSON nodes")
        } else if self.text_bytes > limits.text_bytes {
            Some("decoded strings and keys")
        } else {
            None
        }
    }
}

struct BoundedDiagnostic(String);

impl BoundedDiagnostic {
    fn new(message: impl fmt::Display) -> Self {
        let mut diagnostic = Self(String::with_capacity(MAX_DIAGNOSTIC_COMPONENT_BYTES));
        let _ = write!(&mut diagnostic, "{message}");
        diagnostic
    }
}

impl fmt::Write for BoundedDiagnostic {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = MAX_DIAGNOSTIC_COMPONENT_BYTES.saturating_sub(self.0.len());
        let mut length = remaining.min(value.len());
        while !value.is_char_boundary(length) {
            length -= 1;
        }
        self.0.push_str(&value[..length]);
        if length == value.len() {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

struct TerminalFailure {
    primary: BoundedDiagnostic,
    cleanup: Option<BoundedDiagnostic>,
}

impl TerminalFailure {
    fn error(&self) -> AdapterError {
        let mut message = self.primary.0.clone();
        if let Some(cleanup) = &self.cleanup {
            message.push_str("; terminal receipt cleanup failed: ");
            message.push_str(&cleanup.0);
        }
        AdapterError::ConnectionFailed(message)
    }
}

#[derive(Default)]
struct BudgetState {
    retained: Footprint,
    messages: usize,
    failure: Option<TerminalFailure>,
    next_generation: u64,
    response_generation: Option<McpRequestGeneration>,
}

#[derive(Clone)]
pub struct IngressBudget {
    state: Arc<Mutex<BudgetState>>,
    shutdown_requested: Arc<AtomicBool>,
    limits: Footprint,
    max_messages: Option<usize>,
    terminal_capacity: bool,
}

impl IngressBudget {
    pub fn diagnostic(message: impl fmt::Display) -> String {
        BoundedDiagnostic::new(message).0
    }

    pub fn new(shutdown_requested: Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::new(Mutex::new(BudgetState::default())),
            shutdown_requested,
            limits: Footprint {
                wire_bytes: MAX_RETAINED_WIRE_BYTES,
                nodes: MAX_RETAINED_NODES,
                text_bytes: MAX_RETAINED_TEXT_BYTES,
            },
            max_messages: None,
            terminal_capacity: true,
        }
    }

    pub(super) fn for_inbox(limits: Footprint, max_messages: usize) -> Self {
        let mut budget = Self::new(Arc::new(AtomicBool::new(false)));
        budget.limits = limits;
        budget.max_messages = Some(max_messages);
        budget.terminal_capacity = false;
        budget
    }

    pub(super) fn control_share(&self) -> Self {
        let mut budget = self.clone();
        budget.limits = Footprint {
            wire_bytes: MAX_RETAINED_WIRE_BYTES,
            nodes: MAX_RETAINED_NODES,
            text_bytes: MAX_RETAINED_TEXT_BYTES,
        };
        budget.max_messages = Some(136);
        budget
    }

    fn exhausted(&self, reason: impl fmt::Display) -> AdapterError {
        if self.terminal_capacity {
            self.fail(reason)
        } else {
            AdapterError::IngressCapacity
        }
    }

    pub(super) fn admit_value(&self, value: Value) -> Result<AccountedMessage, AdapterError> {
        self.ensure_open()?;
        let footprint = admission::measure_value(&value).map_err(|error| match error {
            admission::AdmissionError::Limit(_) => {
                self.exhausted("MCP ingress value capacity exceeded")
            }
            admission::AdmissionError::Input(error) => {
                chio_core::canonical::UntrustedJsonError::Decode(error).into()
            }
        })?;
        let digest = chio_kernel::ProtocolRequestDigest::from_decoded_json(&value)
            .map_err(|_| AdapterError::IngressCapacity)?;
        let mut reservation = self.reserve(footprint)?;
        reservation.request_digest = Some(digest);
        Ok(AccountedMessage { value, reservation })
    }

    pub(super) fn owns(&self, message: &AccountedMessage) -> bool {
        self.owns_reservation(&message.reservation)
    }

    pub(super) fn owns_reservation(&self, reservation: &FrameReservation) -> bool {
        Arc::ptr_eq(&self.state, &reservation.budget.state)
    }

    pub(super) fn response_context(&self) -> McpResponseContext {
        McpResponseContext::new(self.clone())
    }

    pub(super) fn enter_response_scope(
        &self,
        reservation: &FrameReservation,
    ) -> Result<McpResponseScope, AdapterError> {
        response_scope::enter(self, reservation)
    }

    /// Current retained ownership, including messages moved into deferred storage.
    pub fn usage(&self) -> Result<IngressUsage, AdapterError> {
        let state = self.state.lock().map_err(|_| self.lock_error())?;
        Ok(IngressUsage {
            wire_bytes: state.retained.wire_bytes,
            nodes: state.retained.nodes,
            text_bytes: state.retained.text_bytes,
            messages: state.messages,
        })
    }

    pub fn read_message(
        &self,
        reader: &mut impl BufRead,
    ) -> Result<AccountedMessage, AdapterError> {
        let (value, reservation) =
            read_document_frame_with_admission(reader, 4 * 1024 * 1024, |text| self.admit(text))?
                .ok_or_else(|| {
                AdapterError::ConnectionFailed("MCP server closed stdout (EOF)".into())
            })?;
        Ok(AccountedMessage { value, reservation })
    }

    pub(super) fn admit(&self, text: &str) -> Result<FrameReservation, AdapterError> {
        self.ensure_open()?;
        let footprint = match admission::measure(text) {
            Ok(footprint) => footprint,
            Err(admission::AdmissionError::Limit(dimension)) => {
                return Err(self.exhausted(format_args!(
                    "upstream MCP ingress budget exceeded: {dimension}"
                )));
            }
            Err(admission::AdmissionError::Input(error)) => {
                return Err(chio_core::canonical::UntrustedJsonError::Decode(error).into());
            }
        };
        let mut reservation = self.reserve(footprint)?;
        reservation.request_digest = Some(chio_kernel::ProtocolRequestDigest::from_wire_bytes(
            text.as_bytes(),
        ));
        Ok(reservation)
    }

    pub(super) fn reserve(&self, footprint: Footprint) -> Result<FrameReservation, AdapterError> {
        let mut state = self.state.lock().map_err(|_| self.lock_error())?;
        if let Some(failure) = &state.failure {
            return Err(failure.error());
        }
        let Some(combined) = state.retained.checked_add(footprint) else {
            drop(state);
            return Err(self.exhausted("upstream MCP ingress accounting overflow"));
        };
        if let Some(dimension) = combined.exceeded_at(self.limits) {
            drop(state);
            return Err(self.exhausted(format_args!(
                "upstream MCP ingress budget exceeded: {dimension}"
            )));
        }
        let messages = state
            .messages
            .checked_add(1)
            .ok_or(AdapterError::IngressCapacity)?;
        if self.max_messages.is_some_and(|maximum| messages > maximum) {
            drop(state);
            return Err(self.exhausted("MCP ingress message capacity exceeded"));
        }
        let generation = state
            .next_generation
            .checked_add(1)
            .ok_or(AdapterError::IngressCapacity)?;
        state.next_generation = generation;
        state.retained = combined;
        state.messages = messages;
        Ok(FrameReservation {
            budget: self.clone(),
            footprint,
            request_digest: None,
            generation: McpRequestGeneration::new(generation),
        })
    }

    pub fn terminal_error(&self) -> Result<Option<AdapterError>, AdapterError> {
        let state = self.state.lock().map_err(|_| self.lock_error())?;
        Ok(state.failure.as_ref().map(TerminalFailure::error))
    }

    pub fn ensure_open(&self) -> Result<(), AdapterError> {
        match self.terminal_error()? {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub fn fail(&self, reason: impl fmt::Display) -> AdapterError {
        let primary = BoundedDiagnostic::new(reason);
        let Ok(mut state) = self.state.lock() else {
            return self.lock_error();
        };
        let failure = state.failure.get_or_insert(TerminalFailure {
            primary,
            cleanup: None,
        });
        self.shutdown_requested.store(true, Ordering::Release);
        failure.error()
    }

    pub fn note_cleanup(&self, cleanup: &Result<(), AdapterError>) {
        if let Err(error) = cleanup {
            let diagnostic = BoundedDiagnostic::new(error);
            if let Ok(mut state) = self.state.lock() {
                if let Some(failure) = &mut state.failure {
                    failure.cleanup = Some(diagnostic);
                }
            }
        }
    }

    fn lock_error(&self) -> AdapterError {
        self.shutdown_requested.store(true, Ordering::Release);
        AdapterError::ConnectionFailed("upstream MCP ingress accounting lock poisoned".into())
    }
}

pub struct FrameReservation {
    budget: IngressBudget,
    footprint: Footprint,
    request_digest: Option<chio_kernel::ProtocolRequestDigest>,
    generation: McpRequestGeneration,
}

impl FrameReservation {
    /// Trusted local origin, assigned once by this reservation's accounting owner.
    pub fn request_generation(&self) -> McpRequestGeneration {
        self.generation
    }
    /// Original ingress identity travels with its sealed accounting ownership.
    pub fn request_digest(&self) -> Option<&chio_kernel::ProtocolRequestDigest> {
        self.request_digest.as_ref()
    }
}

impl Drop for FrameReservation {
    fn drop(&mut self) {
        let Ok(mut state) = self.budget.state.lock() else {
            self.budget
                .shutdown_requested
                .store(true, Ordering::Release);
            return;
        };
        if let Some(retained) = state.retained.checked_sub(self.footprint) {
            if let Some(messages) = state.messages.checked_sub(1) {
                state.messages = messages;
                state.retained = retained;
            } else {
                drop(state);
                self.budget
                    .fail("MCP ingress message accounting invariant failed");
            }
        } else {
            drop(state);
            self.budget
                .fail("upstream MCP ingress accounting invariant failed");
        }
    }
}

pub struct AccountedMessage {
    pub(super) value: Value,
    pub(super) reservation: FrameReservation,
}

impl AccountedMessage {
    pub fn request_generation(&self) -> McpRequestGeneration {
        self.reservation.request_generation()
    }
    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn request_digest(&self) -> Option<&chio_kernel::ProtocolRequestDigest> {
        self.reservation.request_digest()
    }

    pub(crate) fn into_accounted_result(mut self) -> Result<Self, AdapterError> {
        self.value = self
            .value
            .as_object_mut()
            .and_then(|value| value.remove("result"))
            .ok_or_else(|| AdapterError::ParseError("response missing 'result' field".into()))?;
        Ok(self)
    }

    pub fn into_result(mut self) -> Result<Value, AdapterError> {
        self.value
            .as_object_mut()
            .and_then(|object| object.remove("result"))
            .ok_or_else(|| AdapterError::ParseError("response missing 'result' field".into()))
    }

    /// Retain all batch reservations until all values are ready for handoff.
    pub fn into_values(messages: Vec<Self>) -> Vec<Value> {
        let (values, reservations): (Vec<_>, Vec<_>) = messages
            .into_iter()
            .map(|message| (message.value, message.reservation))
            .unzip();
        drop(reservations);
        values
    }
}

/// Aggregate resource accounting; these are compatibility ceilings, not RSS estimates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngressUsage {
    pub wire_bytes: usize,
    pub nodes: usize,
    pub text_bytes: usize,
    pub messages: usize,
}

impl AccountedMessage {
    /// Move the value while keeping its opaque reservation alive through handling.
    pub fn into_parts(self) -> (Value, FrameReservation) {
        (self.value, self.reservation)
    }
}
impl std::ops::Deref for AccountedMessage {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.value
    }
}
impl fmt::Debug for AccountedMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountedMessage")
            .finish_non_exhaustive()
    }
}
