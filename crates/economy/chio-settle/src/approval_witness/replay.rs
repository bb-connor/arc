use std::collections::HashMap;
use std::sync::Mutex;

use chio_security_types::clock::ClockError;

use super::{clock_error, refused, valid_identifier};
use chio_settle_types::SettlementError;

const DEFAULT_CAPACITY: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalReplayOutcome {
    Fresh,
    Replayed,
}

pub trait ApprovalReplayStore: Send + Sync {
    fn record_if_fresh(
        &self,
        request_id: &str,
        intent_hash: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<ApprovalReplayOutcome, SettlementError>;
}

#[derive(Default)]
struct State {
    entries: HashMap<(String, String), u64>,
    high_water: u64,
}

pub struct InMemoryApprovalReplayStore {
    state: Mutex<State>,
    capacity: usize,
}

impl Default for InMemoryApprovalReplayStore {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            capacity: DEFAULT_CAPACITY,
        }
    }
}

impl InMemoryApprovalReplayStore {
    pub fn with_capacity(capacity: usize) -> Result<Self, SettlementError> {
        if capacity == 0 || capacity > DEFAULT_CAPACITY {
            return Err(refused("settlement replay capacity invalid"));
        }
        Ok(Self {
            state: Mutex::new(State::default()),
            capacity,
        })
    }
}

impl ApprovalReplayStore for InMemoryApprovalReplayStore {
    fn record_if_fresh(
        &self,
        request_id: &str,
        intent_hash: &str,
        expires_at_unix_ms: u64,
        now_unix_ms: u64,
    ) -> Result<ApprovalReplayOutcome, SettlementError> {
        if !valid_identifier(request_id)
            || intent_hash.len() != 64
            || !intent_hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(refused("settlement replay identity malformed"));
        }
        if expires_at_unix_ms <= now_unix_ms {
            return Err(clock_error(ClockError::Expired));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("settlement replay store unavailable"))?;
        if now_unix_ms < state.high_water {
            return Err(clock_error(ClockError::WallClockRegression));
        }
        state.high_water = now_unix_ms;
        state.entries.retain(|_, expiry| *expiry > now_unix_ms);
        let key = (request_id.to_string(), intent_hash.to_string());
        if state.entries.contains_key(&key) {
            return Ok(ApprovalReplayOutcome::Replayed);
        }
        if state.entries.len() >= self.capacity {
            return Err(refused("settlement replay capacity exhausted"));
        }
        state.entries.insert(key, expires_at_unix_ms);
        Ok(ApprovalReplayOutcome::Fresh)
    }
}
