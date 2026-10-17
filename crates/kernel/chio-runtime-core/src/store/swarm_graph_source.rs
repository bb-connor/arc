use chio_swarm_authority::SwarmAuthorityBundle;

use crate::ChioRuntimeError;

/// Read-only view of the qualified S1 graph issuer. Runtime admission resolves
/// swarm authority only through this view; no runtime store holds swarm graphs.
pub trait SwarmGraphSource: std::fmt::Debug + Send + Sync {
    /// The issued bundle for `graph_id` whose task graph digest is
    /// `graph_sha256`, whether it is the current head or an archived version.
    fn swarm_graph(
        &self,
        graph_id: &str,
        graph_sha256: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError>;
}
