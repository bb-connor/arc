use super::RecoveryEffectContractV1;
use crate::ToolServerConnection;

/// A tool server that explicitly opts into recovery effects. The kernel
/// registers it through `ChioKernel::register_recovery_tool_server` as the
/// same connection that dispatches its tools; any later registration of its
/// server id withdraws this binding. Actor authentication compares the
/// returned contract with the installed deployment's effect contract.
pub trait RecoveryToolServerConnection: ToolServerConnection {
    fn recovery_effect_contract(&self) -> RecoveryEffectContractV1;
}
