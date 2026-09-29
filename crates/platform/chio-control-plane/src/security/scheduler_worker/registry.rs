#[cfg(test)]
use std::sync::Mutex;
use super::ResponseWorkerTickError;

use super::PortError;
use super::Arc;
use super::RwLock;
use super::watch;

use super::ResponseWorkerHealth;




pub trait ActiveDefenseServices: Send + Sync {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError>;

    fn ensure_bootstrap_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.ensure_ready()
    }

    fn worker_health(&self) -> ResponseWorkerHealth;
}

#[derive(Default)]
pub(super) enum ActiveDefenseRegistryState {
    #[default]
    Vacant,
    Reserved(Arc<dyn ActiveDefenseServices>),
    Published(Arc<dyn ActiveDefenseServices>),
}

pub struct ActiveDefenseServiceRegistry {
    state: RwLock<ActiveDefenseRegistryState>,
    changes: watch::Sender<u64>,
    #[cfg(test)]
    reservation_pause: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

impl Default for ActiveDefenseServiceRegistry {
    fn default() -> Self {
        Self {
            state: RwLock::new(ActiveDefenseRegistryState::default()),
            changes: watch::channel(0).0,
            #[cfg(test)]
            reservation_pause: Mutex::new(None),
        }
    }
}

impl ActiveDefenseServiceRegistry {
    pub fn publish(
        &self,
        services: Arc<dyn ActiveDefenseServices>,
    ) -> Result<(), ResponseWorkerTickError> {
        self.reserve_exact(Arc::clone(&services))?;
        match self.commit_reserved_exact(&services) {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.cancel_reserved_exact(&services);
                Err(error)
            }
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<Arc<dyn ActiveDefenseServices>> {
        self.state.read().ok().and_then(|state| match &*state {
            ActiveDefenseRegistryState::Published(services) => Some(Arc::clone(services)),
            ActiveDefenseRegistryState::Vacant | ActiveDefenseRegistryState::Reserved(_) => None,
        })
    }

    pub async fn wait_until_vacant(&self) -> Result<(), ResponseWorkerTickError> {
        let mut changes = self.changes.subscribe();
        loop {
            let vacant = self
                .state
                .read()
                .map_err(|_| PortError::unavailable())
                .map(|state| matches!(&*state, ActiveDefenseRegistryState::Vacant))?;
            if vacant {
                return Ok(());
            }
            changes
                .changed()
                .await
                .map_err(|_| ResponseWorkerTickError::WorkerStopped)?;
        }
    }

    pub(in crate::security) fn reserve_exact(
        &self,
        services: Arc<dyn ActiveDefenseServices>,
    ) -> Result<(), ResponseWorkerTickError> {
        services.ensure_bootstrap_ready()?;
        let mut state = self.state.write().map_err(|_| PortError::unavailable())?;
        if !matches!(&*state, ActiveDefenseRegistryState::Vacant) {
            return Err(ResponseWorkerTickError::ServicesAlreadyPublished);
        }
        services.ensure_bootstrap_ready()?;
        *state = ActiveDefenseRegistryState::Reserved(services);
        drop(state);
        #[cfg(test)]
        self.pause_after_reservation_for_test();
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::security) fn pause_next_reservation_for_test(
        &self,
    ) -> (Arc<std::sync::Barrier>, Arc<std::sync::Barrier>) {
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        if let Ok(mut pause) = self.reservation_pause.lock() {
            *pause = Some((Arc::clone(&reached), Arc::clone(&release)));
        }
        (reached, release)
    }

    #[cfg(test)]
    fn pause_after_reservation_for_test(&self) {
        let pause = self
            .reservation_pause
            .lock()
            .ok()
            .and_then(|mut pause| pause.take());
        if let Some((reached, release)) = pause {
            reached.wait();
            release.wait();
        }
    }

    fn commit_reserved_exact(
        &self,
        services: &Arc<dyn ActiveDefenseServices>,
    ) -> Result<(), ResponseWorkerTickError> {
        self.commit_reserved_exact_with_release(services, || Ok(()))
    }

    pub(in crate::security) fn commit_reserved_exact_with_release(
        &self,
        services: &Arc<dyn ActiveDefenseServices>,
        release: impl FnOnce() -> Result<(), ResponseWorkerTickError>,
    ) -> Result<(), ResponseWorkerTickError> {
        let mut state = self.state.write().map_err(|_| PortError::unavailable())?;
        let ActiveDefenseRegistryState::Reserved(reserved) = &*state else {
            return Err(ResponseWorkerTickError::ServicesOwnershipMismatch);
        };
        if !Arc::ptr_eq(reserved, services) {
            return Err(ResponseWorkerTickError::ServicesOwnershipMismatch);
        }
        services.ensure_bootstrap_ready()?;
        let reserved = Arc::clone(reserved);
        *state = ActiveDefenseRegistryState::Published(Arc::clone(services));
        if let Err(error) = release() {
            *state = ActiveDefenseRegistryState::Reserved(reserved);
            return Err(error);
        }
        self.notify_change();
        Ok(())
    }

    pub(in crate::security) fn cancel_reserved_exact(
        &self,
        services: &Arc<dyn ActiveDefenseServices>,
    ) -> Result<(), ResponseWorkerTickError> {
        let mut state = self.state.write().map_err(|_| PortError::unavailable())?;
        let ActiveDefenseRegistryState::Reserved(reserved) = &*state else {
            return Err(ResponseWorkerTickError::ServicesOwnershipMismatch);
        };
        if !Arc::ptr_eq(reserved, services) {
            return Err(ResponseWorkerTickError::ServicesOwnershipMismatch);
        }
        *state = ActiveDefenseRegistryState::Vacant;
        self.notify_change();
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn unpublish_exact(
        &self,
        services: &Arc<dyn ActiveDefenseServices>,
    ) -> Result<(), ResponseWorkerTickError> {
        self.unpublish_exact_with_release(services, || Ok(()))
    }

    pub(in crate::security) fn unpublish_exact_with_release(
        &self,
        services: &Arc<dyn ActiveDefenseServices>,
        release: impl FnOnce() -> Result<(), ResponseWorkerTickError>,
    ) -> Result<(), ResponseWorkerTickError> {
        let mut state = self.state.write().map_err(|_| PortError::unavailable())?;
        let ActiveDefenseRegistryState::Published(published) = &*state else {
            return Err(ResponseWorkerTickError::ServicesOwnershipMismatch);
        };
        if !Arc::ptr_eq(published, services) {
            return Err(ResponseWorkerTickError::ServicesOwnershipMismatch);
        }
        release()?;
        *state = ActiveDefenseRegistryState::Vacant;
        self.notify_change();
        Ok(())
    }

    fn notify_change(&self) {
        let next = (*self.changes.borrow()).saturating_add(1);
        let _ = self.changes.send_replace(next);
    }
}
