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

use crate::edge::AdapterError;
use crate::framing::read_jsonrpc_frame_with_admission;

mod admission;
#[cfg(test)]
mod tests;

const MAX_RETAINED_WIRE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RETAINED_NODES: usize = 1024 * 1024;
const MAX_RETAINED_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIAGNOSTIC_COMPONENT_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Footprint {
    wire_bytes: usize,
    nodes: usize,
    text_bytes: usize,
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
        if self.wire_bytes > MAX_RETAINED_WIRE_BYTES {
            Some("wire bytes")
        } else if self.nodes > MAX_RETAINED_NODES {
            Some("JSON nodes")
        } else if self.text_bytes > MAX_RETAINED_TEXT_BYTES {
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
    failure: Option<TerminalFailure>,
}

#[derive(Clone)]
pub(super) struct IngressBudget {
    state: Arc<Mutex<BudgetState>>,
    shutdown_requested: Arc<AtomicBool>,
}

impl IngressBudget {
    pub(super) fn diagnostic(message: impl fmt::Display) -> String {
        BoundedDiagnostic::new(message).0
    }

    pub(super) fn new(shutdown_requested: Arc<AtomicBool>) -> Self {
        Self {
            state: Arc::new(Mutex::new(BudgetState::default())),
            shutdown_requested,
        }
    }

    pub(super) fn read_message(
        &self,
        reader: &mut impl BufRead,
    ) -> Result<AccountedMessage, AdapterError> {
        let (value, reservation) =
            read_jsonrpc_frame_with_admission(reader, |text| self.admit(text))?.ok_or_else(
                || AdapterError::ConnectionFailed("MCP server closed stdout (EOF)".into()),
            )?;
        Ok(AccountedMessage { value, reservation })
    }

    fn admit(&self, text: &str) -> Result<FrameReservation, AdapterError> {
        self.ensure_open()?;
        let footprint = match admission::measure(text) {
            Ok(footprint) => footprint,
            Err(admission::AdmissionError::Limit(dimension)) => {
                return Err(self.fail(format_args!(
                    "upstream MCP ingress budget exceeded: {dimension}"
                )));
            }
            Err(admission::AdmissionError::Input(error)) => {
                return Err(chio_core::canonical::UntrustedJsonError::Decode(error).into());
            }
        };
        self.reserve(footprint)
    }

    fn reserve(&self, footprint: Footprint) -> Result<FrameReservation, AdapterError> {
        let mut state = self.state.lock().map_err(|_| self.lock_error())?;
        if let Some(failure) = &state.failure {
            return Err(failure.error());
        }
        let Some(combined) = state.retained.checked_add(footprint) else {
            drop(state);
            return Err(self.fail("upstream MCP ingress accounting overflow"));
        };
        if let Some(dimension) = combined.exceeded() {
            drop(state);
            return Err(self.fail(format_args!(
                "upstream MCP ingress budget exceeded: {dimension}"
            )));
        }
        state.retained = combined;
        Ok(FrameReservation {
            budget: self.clone(),
            footprint,
        })
    }

    pub(super) fn terminal_error(&self) -> Result<Option<AdapterError>, AdapterError> {
        let state = self.state.lock().map_err(|_| self.lock_error())?;
        Ok(state.failure.as_ref().map(TerminalFailure::error))
    }

    pub(super) fn ensure_open(&self) -> Result<(), AdapterError> {
        match self.terminal_error()? {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub(super) fn fail(&self, reason: impl fmt::Display) -> AdapterError {
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

    pub(super) fn note_cleanup(&self, cleanup: &Result<(), AdapterError>) {
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

struct FrameReservation {
    budget: IngressBudget,
    footprint: Footprint,
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
            state.retained = retained;
        } else {
            drop(state);
            self.budget
                .fail("upstream MCP ingress accounting invariant failed");
        }
    }
}

pub(super) struct AccountedMessage {
    value: Value,
    reservation: FrameReservation,
}

impl AccountedMessage {
    pub(super) fn value(&self) -> &Value {
        &self.value
    }

    pub(super) fn into_result(mut self) -> Result<Value, AdapterError> {
        self.value
            .as_object_mut()
            .and_then(|object| object.remove("result"))
            .ok_or_else(|| AdapterError::ParseError("response missing 'result' field".into()))
    }

    /// Retain all batch reservations until all values are ready for handoff.
    pub(super) fn into_values(messages: Vec<Self>) -> Vec<Value> {
        let (values, reservations): (Vec<_>, Vec<_>) = messages
            .into_iter()
            .map(|message| (message.value, message.reservation))
            .unzip();
        drop(reservations);
        values
    }
}
