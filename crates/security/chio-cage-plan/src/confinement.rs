use chio_core_types::receipt::kinds::ToolOrigin;
use serde::{Deserialize, Serialize};

/// Closed set of launch backends whose records may claim confinement.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinementBackendKind {
    LinuxCage,
    FirecrackerGuest,
    ProcessContainer,
    AgentHostBwrap,
    Seatbelt,
}

/// Why a receipt has no verified launch record, derived from its signed `tool_origin`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnconfinedReason {
    InProcess,
    CallerExecuted,
    HostExecuted,
}

impl From<ToolOrigin> for UnconfinedReason {
    fn from(origin: ToolOrigin) -> Self {
        match origin {
            ToolOrigin::ChioInternal => Self::InProcess,
            ToolOrigin::CallerExecuted => Self::CallerExecuted,
            ToolOrigin::HostExecutedProviderReported | ToolOrigin::HostExecutedUnmediated => {
                Self::HostExecuted
            }
        }
    }
}

/// Tool-server confinement disclosure for one tool-call receipt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum ConfinementDisclosure {
    Confined(ConfinementBackendKind),
    Unconfined(UnconfinedReason),
}

impl ConfinementDisclosure {
    #[must_use]
    pub fn is_confined(self) -> bool {
        matches!(self, Self::Confined(_))
    }
}

impl std::fmt::Display for ConfinementDisclosure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Confined(ConfinementBackendKind::LinuxCage) => "confined by Chio (Linux cage)",
            Self::Confined(ConfinementBackendKind::FirecrackerGuest) => {
                "confined by Chio (Firecracker guest)"
            }
            Self::Confined(ConfinementBackendKind::ProcessContainer) => {
                "confined by Chio (process container)"
            }
            Self::Confined(ConfinementBackendKind::AgentHostBwrap) => {
                "confined by Chio (agent host bubblewrap)"
            }
            Self::Confined(ConfinementBackendKind::Seatbelt) => "confined by Chio (macOS Seatbelt)",
            Self::Unconfined(UnconfinedReason::InProcess) => {
                "unconfined: in-process tool; not sandboxed by Chio"
            }
            Self::Unconfined(UnconfinedReason::CallerExecuted) => {
                "unconfined: caller-executed; not sandboxed by Chio"
            }
            Self::Unconfined(UnconfinedReason::HostExecuted) => {
                "unconfined: host-executed; not sandboxed by Chio"
            }
        })
    }
}
