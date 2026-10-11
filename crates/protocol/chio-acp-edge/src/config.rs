// Edge configuration controlling permission defaults and categorization.

/// Configuration for the ACP edge.
#[derive(Debug, Clone)]
pub struct AcpEdgeConfig {
    /// Authenticated peer profile established by the embedding host. Absent
    /// extensions remain disabled; invocation metadata cannot change this.
    pub peer_capabilities: chio_core::capability::features::CapabilityNegotiation,
    /// Whether to require explicit permission for all tools.
    pub require_permission: bool,
    /// Default ACP category for unmapped tools.
    pub default_category: AcpCategory,
}

impl Default for AcpEdgeConfig {
    fn default() -> Self {
        Self {
            peer_capabilities: Default::default(),
            require_permission: true,
            default_category: AcpCategory::Tool,
        }
    }
}
