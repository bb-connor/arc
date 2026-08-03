use std::sync::{Arc, OnceLock};

use chio_security_types::ports::{PortError, UnverifiedSecurityEvent};

use crate::security::{
    ActiveDefenseServiceRegistry, ActiveDefenseServices, CorrelationConsumerReport,
    ProductionActiveDefenseHost, ProductionActiveDefenseHostConfig,
    ProductionActiveDefenseHostError, ProductionActiveDefenseOrchestrator, ResponseWorkerHealth,
    ResponseWorkerTickError,
};

static ACTIVE_DEFENSE_SERVICE_REGISTRY: OnceLock<Arc<ActiveDefenseServiceRegistry>> =
    OnceLock::new();

/// Closed selection for the trust-control active-defense lifetime owner.
///
/// Enabled operation requires the complete production host configuration. The
/// selection cannot represent a partially configured worker or an ephemeral
/// response and overlay store.
#[derive(Clone)]
pub(crate) enum TrustControlActiveDefenseRuntimeConfig {
    Disabled,
    Enabled(Box<ProductionActiveDefenseHostConfig>),
}

#[derive(Clone, Default)]
pub(crate) struct TrustControlActiveDefenseService {
    orchestrator: Option<Arc<ProductionActiveDefenseOrchestrator>>,
    services: Option<Arc<dyn ActiveDefenseServices>>,
}

impl TrustControlActiveDefenseService {
    #[must_use]
    pub(crate) const fn disabled() -> Self {
        Self {
            orchestrator: None,
            services: None,
        }
    }

    #[must_use]
    pub(crate) const fn is_enabled(&self) -> bool {
        self.services.is_some()
    }

    pub(crate) fn worker_health(&self) -> Option<ResponseWorkerHealth> {
        self.services
            .as_ref()
            .map(|services| services.worker_health())
    }

    pub(crate) fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.services
            .as_ref()
            .ok_or(ResponseWorkerTickError::RuntimeAdmissionClosed)?
            .ensure_ready()
    }

    #[cfg(test)]
    pub(crate) fn from_services_for_test(services: Arc<dyn ActiveDefenseServices>) -> Self {
        Self {
            orchestrator: None,
            services: Some(services),
        }
    }

    pub(crate) fn consume(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> Result<CorrelationConsumerReport, PortError> {
        self.orchestrator
            .as_ref()
            .ok_or_else(PortError::unavailable)?
            .consume(event)
    }
}

/// Owns the active-defense host for the complete trust-control serve lifetime.
pub(crate) struct TrustControlActiveDefenseRuntime {
    _registry: Arc<ActiveDefenseServiceRegistry>,
    host: Option<ProductionActiveDefenseHost>,
}

impl TrustControlActiveDefenseRuntime {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn disabled() -> Self {
        Self {
            _registry: production_registry(),
            host: None,
        }
    }

    pub(crate) async fn start(
        config: TrustControlActiveDefenseRuntimeConfig,
    ) -> Result<Self, ProductionActiveDefenseHostError> {
        Self::start_with_registry(production_registry(), config).await
    }

    pub(super) async fn start_with_registry(
        registry: Arc<ActiveDefenseServiceRegistry>,
        config: TrustControlActiveDefenseRuntimeConfig,
    ) -> Result<Self, ProductionActiveDefenseHostError> {
        match config {
            TrustControlActiveDefenseRuntimeConfig::Disabled => Ok(Self {
                _registry: registry,
                host: None,
            }),
            TrustControlActiveDefenseRuntimeConfig::Enabled(config) => {
                let host =
                    ProductionActiveDefenseHost::start(Arc::clone(&registry), *config).await?;
                Ok(Self {
                    _registry: registry,
                    host: Some(host),
                })
            }
        }
    }

    #[must_use]
    pub(crate) const fn is_enabled(&self) -> bool {
        self.host.is_some()
    }

    #[must_use]
    pub(crate) fn service(&self) -> TrustControlActiveDefenseService {
        TrustControlActiveDefenseService {
            orchestrator: self
                .host
                .as_ref()
                .map(|host| Arc::clone(host.orchestrator())),
            services: self.host.as_ref().map(|host| {
                let services: Arc<dyn ActiveDefenseServices> = host.orchestrator().clone();
                services
            }),
        }
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), ProductionActiveDefenseHostError> {
        let Some(host) = self.host.as_mut() else {
            return Ok(());
        };
        host.shutdown().await
    }

    #[cfg(test)]
    pub(crate) fn published_services(&self) -> Option<Arc<dyn ActiveDefenseServices>> {
        self._registry.snapshot()
    }

    #[cfg(test)]
    pub(crate) fn owned_services(&self) -> Option<Arc<dyn ActiveDefenseServices>> {
        self.host.as_ref().map(|host| {
            let services: Arc<dyn ActiveDefenseServices> = host.orchestrator().clone();
            services
        })
    }
}

fn production_registry() -> Arc<ActiveDefenseServiceRegistry> {
    Arc::clone(
        ACTIVE_DEFENSE_SERVICE_REGISTRY
            .get_or_init(|| Arc::new(ActiveDefenseServiceRegistry::default())),
    )
}
