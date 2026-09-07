use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ProcessError;

/// A channel is a capability-addressable endpoint, not a sender identity.
/// Its send, receive and acknowledge tools have independent scope grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxConfig {
    pub id: String,
    #[serde(default)]
    pub limits: MailboxLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailboxLimits {
    pub max_pending_messages: u32,
    pub max_pending_bytes: u32,
    pub max_message_bytes: u32,
    /// Includes acknowledged tombstones. Keys and sequence numbers are never recycled.
    pub max_messages: u32,
}

impl Default for MailboxLimits {
    fn default() -> Self {
        Self {
            max_pending_messages: 32,
            max_pending_bytes: 1_048_576,
            max_message_bytes: 65_536,
            max_messages: 256,
        }
    }
}

impl MailboxConfig {
    pub fn validate(&self) -> Result<(), ProcessError> {
        if self.id.is_empty()
            || self.id.len() > 32
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(ProcessError::Invalid(
                "mailbox id requires 1-32 ASCII letters, digits, underscores or hyphens",
            ));
        }
        let limits = self.limits;
        if limits.max_pending_messages == 0
            || limits.max_pending_messages > 256
            || limits.max_messages < limits.max_pending_messages
            || limits.max_messages > 100_000
            || limits.max_message_bytes == 0
            || limits.max_message_bytes > 65_536
            || limits.max_pending_bytes < limits.max_message_bytes
            || limits.max_pending_bytes > 8_388_608
        {
            return Err(ProcessError::Invalid("invalid mailbox limits"));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Send {
    pub message_key: String,
    pub payload: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receive {
    pub after_sequence: String,
    /// A bounded non-consuming read. Use a new logical poll after an empty result.
    pub limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Acknowledge {
    pub through_sequence: String,
}

/// Bounds on a delivery lease. The floor keeps a lease from expiring inside
/// the claimant's own call; the ceiling bounds how long a dead claimant can
/// keep a message out of the pool.
pub(super) const MIN_LEASE_MS: u64 = 1_000;
pub(super) const MAX_LEASE_MS: u64 = 300_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Claim {
    /// A bounded claim of the oldest pending messages no live lease holds.
    pub limit: u32,
    pub lease_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Complete {
    pub sequence: String,
    /// The claim generation returned with the message.
    pub claim: String,
}

pub(super) fn sequence(value: &str) -> Result<u32, ProcessError> {
    decimal(value, "invalid mailbox sequence")
}

pub(super) fn claim_generation(value: &str) -> Result<u32, ProcessError> {
    decimal(value, "invalid mailbox claim")
}

fn decimal(value: &str, invalid: &'static str) -> Result<u32, ProcessError> {
    let number: u32 = value.parse().map_err(|_| ProcessError::Invalid(invalid))?;
    if number.to_string() != value {
        return Err(ProcessError::Invalid(invalid));
    }
    Ok(number)
}
