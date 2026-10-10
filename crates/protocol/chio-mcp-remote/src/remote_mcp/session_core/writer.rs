//! Bounded session output and actor-origin event projection.

use super::*;

pub(super) struct BroadcastJsonRpcWriter {
    event_tx: broadcast::Sender<RemoteSessionEvent>,
    retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
    next_event_id: Arc<AtomicU64>,
    session_id: String,
    response_context: McpResponseContext,
    buffer: Vec<u8>,
    line_bound: usize,
}

impl BroadcastJsonRpcWriter {
    pub(super) fn new(
        event_tx: broadcast::Sender<RemoteSessionEvent>,
        retained_notification_events: Arc<StdMutex<VecDeque<RetainedRemoteSessionEvent>>>,
        next_event_id: Arc<AtomicU64>,
        session_id: String,
        response_context: McpResponseContext,
    ) -> Self {
        Self {
            event_tx,
            retained_notification_events,
            next_event_id,
            session_id,
            response_context,
            buffer: Vec::new(),
            line_bound: MAX_SESSION_JSON_BYTES,
        }
    }

    /// Bounds each session output line by `line_bound` instead of
    /// `MAX_SESSION_JSON_BYTES`.
    #[cfg(test)]
    pub(super) fn with_line_bound(mut self, line_bound: Option<usize>) -> Self {
        if let Some(line_bound) = line_bound {
            self.line_bound = line_bound.min(MAX_SESSION_JSON_BYTES);
        }
        self
    }

    pub(super) fn next_event(&self, message: Value) -> std::io::Result<RemoteSessionEvent> {
        let next =
            crate::clock::next_counter(&self.next_event_id).map_err(std::io::Error::other)?;
        let event_id = format!("{}-{next}", self.session_id);
        let generation = self
            .response_context
            .request_generation()
            .map_err(std::io::Error::other)?;
        let kind = classify_remote_session_event(&message, generation.is_some());
        let request_generation = match kind {
            RemoteSessionEventKind::RequestCorrelated => generation,
            _ => None,
        };
        if kind.is_session_owned() {
            if let Ok(mut retained) = self.retained_notification_events.lock() {
                retained.push_back(RetainedRemoteSessionEvent {
                    seq: next,
                    event_id: event_id.clone(),
                    message: message.clone(),
                });
                while retained.len() > DEFAULT_NOTIFICATION_REPLAY_WINDOW {
                    retained.pop_front();
                }
            }
        }

        Ok(RemoteSessionEvent {
            seq: next,
            event_id,
            kind,
            request_generation,
            message,
        })
    }

    fn flush_complete_lines(&mut self) -> io::Result<()> {
        while let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let mut line = self.buffer.drain(..=position).collect::<Vec<_>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }

            let message: Value = decode_json(&line, MAX_SESSION_JSON_BYTES)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let _ = self.event_tx.send(self.next_event(message)?);
        }

        Ok(())
    }
}

impl Write for BroadcastJsonRpcWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        for fragment in buf.split_inclusive(|byte| *byte == b'\n') {
            if fragment.len() > self.line_bound.saturating_sub(self.buffer.len()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    chio_core::canonical::UntrustedJsonError::TooLarge {
                        bytes: self.buffer.len().saturating_add(fragment.len()),
                        bound: self.line_bound,
                    },
                ));
            }
            self.buffer.extend_from_slice(fragment);
            self.flush_complete_lines()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_complete_lines()
    }
}
