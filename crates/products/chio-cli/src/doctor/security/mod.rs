//! Probes behind `chio security preflight`: what a host, its credentials, its
//! signed launch material and its durable stores must satisfy before the
//! confined reference runtime is trusted to start.

pub mod launch;
pub mod platform;
pub mod roles;
pub mod stores;

pub use launch::{LaunchMaterial, NativeLaunchProbe};
pub use platform::PlatformProbe;
pub use roles::BearerRoleProbe;
pub use stores::{DurableStoreProbe, NamedStore};

use super::{DoctorRunner, ProbeConfig};

/// What one preflight checks.
pub struct PreflightRequest {
    /// Treat a host that cannot enforce the cage, or launch material that
    /// does not confine, as an error rather than a warning.
    pub require_enforcement: bool,
    pub launch: Option<LaunchMaterial>,
    pub stores: Vec<NamedStore>,
}

/// The preflight runner in its canonical probe order: platform, bearer roles,
/// signed launch material, durable stores.
#[must_use]
pub fn preflight_runner(config: ProbeConfig, request: PreflightRequest) -> DoctorRunner {
    DoctorRunner::new(config)
        .with_probe(Box::new(PlatformProbe::host(request.require_enforcement)))
        .with_probe(Box::new(BearerRoleProbe::from_environment()))
        .with_probe(Box::new(NativeLaunchProbe::new(
            request.launch,
            request.require_enforcement,
        )))
        .with_probe(Box::new(DurableStoreProbe::new(request.stores)))
}
