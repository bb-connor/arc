//! Runtime admission resolves swarm authority from the qualified S1 issuer.
use std::fmt;

use chio_store_sqlite::work_graph_store::SqliteWorkGraphStore;
use chio_store_sqlite::SqliteAuthorityStore;

use crate::{RuntimeCoreError, SwarmAuthorityBundle};

/// Issued swarm graphs of one serving authority, current and archived.
pub struct IssuedSwarmGraphs(SqliteWorkGraphStore);

impl IssuedSwarmGraphs {
    #[must_use]
    pub fn new(authority: &SqliteAuthorityStore) -> Self {
        Self(authority.work_graph_store())
    }
}

impl fmt::Debug for IssuedSwarmGraphs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedSwarmGraphs")
            .finish_non_exhaustive()
    }
}

impl chio_runtime_core::SwarmGraphSource for IssuedSwarmGraphs {
    fn swarm_graph(
        &self,
        graph_id: &str,
        graph_sha256: &str,
    ) -> Result<Option<SwarmAuthorityBundle>, RuntimeCoreError> {
        self.0
            .version(graph_id, graph_sha256)
            .map_err(|error| RuntimeCoreError::Store(error.to_string()))
    }
}
