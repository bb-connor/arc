use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeReplayParticipantKind {
    DestructiveLease,
    TreatyContinuation,
    SwarmContinuation,
}

impl RuntimeReplayParticipantKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DestructiveLease => "destructive_lease",
            Self::TreatyContinuation => "treaty_continuation",
            Self::SwarmContinuation => "swarm_continuation",
        }
    }
}
