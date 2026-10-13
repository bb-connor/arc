use super::*;

/// The one budget authority behind mediation. Durable admission reserves,
/// starts and settles operations inside its co-located authority, so it never
/// shares accounting with an operator-configured store.
pub(crate) enum MediationBudget {
    Durable(DurableAdmissionStores),
    Configured(Arc<dyn BudgetStore>),
}

impl MediationBudget {
    pub(crate) fn store(&self) -> Arc<dyn BudgetStore> {
        match self {
            Self::Durable(durable) => Arc::clone(&durable.budget_store),
            Self::Configured(store) => Arc::clone(store),
        }
    }
}

/// Build the configured budget authority, preferring local SQLite when present.
pub(crate) fn build_budget_store(
    config: &ProtectConfig,
    clock: Arc<dyn chio_security_types::clock::Clock>,
) -> Result<Option<Arc<dyn BudgetStore>>, ProtectError> {
    if let Some(path) = config.budget_db.as_deref() {
        let store =
            chio_store_sqlite::budget_store::SqliteBudgetStore::open_with_clock(path, clock)
                .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(Arc::new(store)));
    }
    if let Some(control_url) = config.control_url.as_deref() {
        let token = config.control_token.as_deref().unwrap_or("");
        let store =
            chio_control_plane::trust_control::service_runtime::budget::build_remote_budget_store(
                control_url,
                token,
            )
            .map_err(|error| ProtectError::Config(error.to_string()))?;
        return Ok(Some(Arc::from(store)));
    }
    Ok(None)
}
