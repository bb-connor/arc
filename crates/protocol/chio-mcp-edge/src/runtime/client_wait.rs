use super::*;
use crate::ingress::{AccountedMessage, ClientInbound, InboxAdmission};
use chio_security_types::clock::{AuthorityDeadline, Clock, ClockError, UnixMillis};

const CLIENT_REPLY_TIMEOUT_MILLIS: u64 = 30_000;

pub(super) struct ClientReplyDeadline {
    clock: Arc<dyn Clock>,
    deadline: AuthorityDeadline,
    task: Option<AuthorityDeadline>,
}
impl ClientReplyDeadline {
    pub(super) fn new(
        clock: Arc<dyn Clock>,
        expires_at: Option<UnixMillis>,
        task: Option<AuthorityDeadline>,
    ) -> Result<Self, AdapterError> {
        let now = clock.read()?;
        let expiry = now.unix_millis().checked_add(CLIENT_REPLY_TIMEOUT_MILLIS)?;
        let expiry = expires_at.map_or(expiry, |cap| UnixMillis::new(expiry.get().min(cap.get())));
        if expiry <= now.unix_millis() {
            return Err(ClockError::Expired.into());
        }
        Ok(Self {
            clock,
            deadline: AuthorityDeadline::new(now.unix_millis(), expiry, now)?,
            task,
        })
    }
    fn remaining(&mut self) -> Result<Duration, AdapterError> {
        let reading = self.clock.read()?;
        let remaining = self.deadline.remaining(reading)?;
        Ok(match self.task.as_mut() {
            Some(task) => remaining.min(task.remaining(reading)?),
            None => remaining,
        })
    }
    pub(super) fn receive(
        &mut self,
        receiver: &mut mpsc::Receiver<ClientInbound>,
        _admission: &InboxAdmission,
        mut on_refusal: impl FnMut(Box<crate::ingress::HostProtocolRefusal>),
    ) -> Result<AccountedMessage, AdapterError> {
        loop {
            let remaining = self.remaining()?;
            let received = receiver.recv_timeout(remaining.min(CLIENT_IDLE_POLL_INTERVAL));
            // Recheck after the wake, including a matching reply. Peer traffic
            // and wall-clock stalls never renew the original absolute deadline.
            self.remaining()?;
            match received {
                Ok(ClientInbound::Accounted(message)) => return Ok(message),
                Ok(ClientInbound::HostProtocolRefusal(command)) => on_refusal(command),
                #[cfg(test)]
                Ok(ClientInbound::Message(value)) => return _admission.admit_value(value),
                Ok(ClientInbound::ParseError(error)) => return Err(error),
                #[cfg(test)]
                Ok(ClientInbound::ReadError(error)) => {
                    return Err(AdapterError::ConnectionFailed(error))
                }
                #[cfg(test)]
                Ok(ClientInbound::Closed) => {
                    return Err(AdapterError::ConnectionFailed(
                        "MCP client closed an active wait".into(),
                    ));
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AdapterError::ConnectionFailed(
                        "MCP client closed an active wait".into(),
                    ));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

pub(super) fn borrowed_reader_refusal() -> AdapterError {
    AdapterError::ConnectionFailed(
        "borrowed MCP readers cannot enforce client reply deadlines; use an owned inbox".into(),
    )
}
