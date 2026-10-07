use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum LogLevel {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
    Alert,
    Emergency,
}

impl LogLevel {
    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "debug" => Some(Self::Debug),
            "info" => Some(Self::Info),
            "notice" => Some(Self::Notice),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            "critical" => Some(Self::Critical),
            "alert" => Some(Self::Alert),
            "emergency" => Some(Self::Emergency),
            _ => None,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
            Self::Alert => "alert",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) enum EdgeState {
    Uninitialized,
    WaitingForInitialized { session_id: SessionId },
    Ready { session_id: SessionId },
}

/// Where queued client-directed actions are serviced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PendingActionRoute {
    /// Every write reaches the client, so actions are serviced once queued.
    Immediate,
    /// Writes reach the client only on a client request's own response
    /// stream, so actions are serviced on the next client request, before
    /// that request is dispatched.
    NextClientRequest,
}

#[derive(Debug, Clone)]
pub(super) enum EdgeAction {
    RefreshRoots {
        session_id: SessionId,
        reason: &'static str,
    },
}
