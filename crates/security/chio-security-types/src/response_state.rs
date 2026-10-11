//! Pure response transition and rollback guards used by the durable state machine.

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ResponseState {
    Planned,
    AwaitingApproval,
    Applying,
    Active,
    ApplyPartial,
    Expiring,
    RollingBack,
    RollbackPartial,
    Cancelled,
    Expired,
    Failed,
    Lifted,
}

impl ResponseState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Applying => "applying",
            Self::Active => "active",
            Self::ApplyPartial => "apply_partial",
            Self::Expiring => "expiring",
            Self::RollingBack => "rolling_back",
            Self::RollbackPartial => "rollback_partial",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Lifted => "lifted",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Expired | Self::Failed | Self::Lifted
        )
    }
}

#[must_use]
pub const fn is_legal_response_transition(from: ResponseState, to: ResponseState) -> bool {
    matches!(
        (from, to),
        (ResponseState::Planned, ResponseState::AwaitingApproval)
            | (ResponseState::Planned, ResponseState::Applying)
            | (ResponseState::Planned, ResponseState::Cancelled)
            | (ResponseState::Planned, ResponseState::Expired)
            | (ResponseState::Planned, ResponseState::Failed)
            | (ResponseState::AwaitingApproval, ResponseState::Applying)
            | (ResponseState::AwaitingApproval, ResponseState::Cancelled)
            | (ResponseState::AwaitingApproval, ResponseState::Expired)
            | (ResponseState::AwaitingApproval, ResponseState::Failed)
            | (ResponseState::Applying, ResponseState::Applying)
            | (ResponseState::Applying, ResponseState::Active)
            | (ResponseState::Applying, ResponseState::ApplyPartial)
            | (ResponseState::Applying, ResponseState::Failed)
            | (ResponseState::ApplyPartial, ResponseState::RollingBack)
            | (ResponseState::Active, ResponseState::Expiring)
            | (ResponseState::Active, ResponseState::RollingBack)
            | (ResponseState::Expiring, ResponseState::RollingBack)
            | (ResponseState::RollingBack, ResponseState::Lifted)
            | (ResponseState::RollingBack, ResponseState::RollbackPartial)
            | (ResponseState::RollbackPartial, ResponseState::RollingBack)
    )
}

/// A clean rollback can remove only restrictions this action applied.
#[must_use]
pub const fn rollback_effect_is_restored(reversible: bool, applied: bool, restored: bool) -> bool {
    !reversible || !applied || restored
}
