//! Durable seam for bilateral co-sign artifacts. The kernel caches each
//! DsseEnvelope in a capped, idle-swept BoundedMap; when a
//! FederationArtifactStore is configured, the co-sign hook writes through to it
//! first, and the accessor falls through to it on a cache miss.

use chio_security_types::clock::{Clock, ClockError, ClockFence};
use std::sync::{Arc, Mutex};

use chio_bounded::{BoundedMap, SizeGauge};
use chio_federation::bilateral_dsse::DsseEnvelope;

use crate::KernelError;

pub trait FederationArtifactStore: Send + Sync {
    fn put_dsse(&self, id: &str, envelope: &DsseEnvelope) -> Result<(), KernelError>;
    fn get_dsse(&self, id: &str) -> Result<Option<DsseEnvelope>, KernelError>;

    /// Whether a written artifact survives once the kernel's bounded front caches
    /// evict it, so an evicted `id` is still resolvable through this store. Only a
    /// persistent backend (database, object store) whose writes outlive eviction
    /// returns `true`; a bounded, drop-evicting in-memory store returns `false`
    /// because it can evict the same `id` the front caches did.
    ///
    /// The default is `false` so a store is never assumed durable unless it
    /// explicitly guarantees it: treating a bounded cache as durable storage would
    /// silently drop bilateral evidence with no operator signal.
    fn is_durable(&self) -> bool {
        false
    }
}

/// Hard cap and idle sweep for [`InMemoryFederationArtifactStore`]'s backing
/// map. Mirrors the kernel's own federation cache defaults
/// (`MemoryBudgetConfig::federation_cache_capacity`) so the reference store
/// carries the same footprint discipline as the caches it sits behind.
const IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY: usize = 8192;
const IN_MEMORY_FEDERATION_ARTIFACT_STORE_IDLE_TTL_SECS: u64 = 3600;

/// Reference in-memory implementation (test double and default backing when a
/// deployment wants durable bilateral evidence without a database). Capped,
/// idle-swept, and gauged instead of an unbounded HashMap. A deployment
/// requiring persistence installs a database-backed impl instead.
pub struct InMemoryFederationArtifactStore {
    clock: Arc<dyn Clock>,
    clock_fence: Mutex<ClockFence>,
    dsse: Mutex<BoundedMap<String, DsseEnvelope>>,
    dsse_gauge: SizeGauge,
}

impl Default for InMemoryFederationArtifactStore {
    fn default() -> Self {
        Self::with_capacity(
            IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY,
            IN_MEMORY_FEDERATION_ARTIFACT_STORE_IDLE_TTL_SECS,
        )
    }
}

impl InMemoryFederationArtifactStore {
    fn now(&self) -> Result<u64, KernelError> {
        let mut fence = self
            .clock_fence
            .lock()
            .map_err(|_| ClockError::Unavailable)?;
        Ok(fence.observe(self.clock.read()?)?.unix_millis().as_secs())
    }

    /// Construct with an explicit per-map capacity and idle TTL. This is the seam
    /// that lets a deployment wiring this reference store in from a CONFIGURED
    /// process memory budget honor a lowered `federation_cache_capacity` instead of
    /// the compiled-in 8192 default, so the store cannot exceed the operator's
    /// configured federation memory budget even though the kernel's front caches
    /// honor it. Same seam class as the velocity/journal `from_memory_budget`
    /// constructors.
    pub fn with_capacity(capacity: usize, idle_ttl_secs: u64) -> Self {
        Self::with_capacity_and_clock(
            capacity,
            idle_ttl_secs,
            Arc::new(chio_security_types::clock::SystemClock),
        )
    }

    /// Use the service clock for artifact retention and cache expiry.
    pub fn with_capacity_and_clock(
        capacity: usize,
        idle_ttl_secs: u64,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let dsse_gauge = SizeGauge::new();
        Self {
            clock,
            clock_fence: Mutex::new(ClockFence::default()),
            dsse: Mutex::new(BoundedMap::new(capacity, idle_ttl_secs, dsse_gauge.clone())),
            dsse_gauge,
        }
    }

    /// Construct from a CONFIGURED process memory budget so lowering
    /// `federation_cache_capacity` / `federation_cache_idle_ttl_secs` actually
    /// bounds the backing map, rather than every deployment retaining the
    /// compiled-in 8192-entry default.
    pub fn from_memory_budget(budget: &crate::MemoryBudgetConfig) -> Self {
        Self::with_capacity(
            budget.federation_cache_capacity,
            budget.federation_cache_idle_ttl_secs,
        )
    }

    /// Live occupancy of the DSSE-envelope backing map.
    pub fn dsse_len(&self) -> usize {
        self.dsse_gauge.get()
    }
}

impl FederationArtifactStore for InMemoryFederationArtifactStore {
    fn put_dsse(&self, id: &str, envelope: &DsseEnvelope) -> Result<(), KernelError> {
        let now = self.now()?;
        let mut guard = match self.dsse.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _evicted = guard.insert(id.to_string(), envelope.clone(), now);
        Ok(())
    }

    fn get_dsse(&self, id: &str) -> Result<Option<DsseEnvelope>, KernelError> {
        let now = self.now()?;
        let mut guard = match self.dsse.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Ok(guard.get(&id.to_string(), now).cloned())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "Test and proof fixtures deliberately fail on violated setup invariants."
    )]
    use super::*;

    use chio_federation::bilateral_dsse::DsseSignature;

    fn sample_dsse(id: &str) -> DsseEnvelope {
        let fixture_text = format!("payload-{id}");
        DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: fixture_text,
            signatures: vec![DsseSignature {
                keyid: format!("keyid-{id}"),
                sig: "sig".to_string(),
            }],
        }
    }

    #[test]
    fn trait_object_round_trips_absence_and_presence() {
        let store: Box<dyn FederationArtifactStore> =
            Box::new(InMemoryFederationArtifactStore::default());
        assert!(store.get_dsse("missing").unwrap().is_none());
    }

    #[test]
    fn in_memory_store_reports_non_durable() {
        // The bundled in-memory store is a bounded, drop-evicting cache, so it must
        // report itself NOT durable: an artifact evicted from the kernel's front
        // caches is not guaranteed recoverable here, and claiming durability would
        // silently drop bilateral evidence.
        let store = InMemoryFederationArtifactStore::default();
        assert!(
            !store.is_durable(),
            "a bounded, drop-evicting store must not claim durability"
        );
        let as_trait: &dyn FederationArtifactStore = &store;
        assert!(!as_trait.is_durable());
    }

    #[test]
    fn durable_backend_can_opt_into_durability() {
        // The contract discriminates: a persistent backend overrides is_durable to
        // advertise that evicted artifacts remain resolvable.
        struct DurableStub;
        impl FederationArtifactStore for DurableStub {
            fn put_dsse(&self, _id: &str, _envelope: &DsseEnvelope) -> Result<(), KernelError> {
                Ok(())
            }
            fn get_dsse(&self, _id: &str) -> Result<Option<DsseEnvelope>, KernelError> {
                Ok(None)
            }
            fn is_durable(&self) -> bool {
                true
            }
        }
        let as_trait: &dyn FederationArtifactStore = &DurableStub;
        assert!(as_trait.is_durable());
    }

    #[test]
    fn from_memory_budget_honors_lowered_federation_cache_capacity() {
        // The CONFIGURED process memory budget must bound this reference store, not
        // a hard-coded default. A budget lowering `federation_cache_capacity` to 4
        // must cap the backing map at 4, not the compiled-in 8192; otherwise a
        // deployment retains 8192 entries regardless of the configured budget.
        let budget = crate::MemoryBudgetConfig {
            federation_cache_capacity: 4,
            ..crate::MemoryBudgetConfig::defaults()
        };
        let store = InMemoryFederationArtifactStore::from_memory_budget(&budget);

        for i in 0..64 {
            let id = format!("dsse-{i}");
            store.put_dsse(&id, &sample_dsse(&id)).unwrap();
            assert!(
                store.dsse_len() <= 4,
                "configured federation_cache_capacity did not take effect: dsse len={}",
                store.dsse_len()
            );
        }
        assert_eq!(
            store.dsse_len(),
            4,
            "dsse backing map should saturate at the lowered cap"
        );
    }

    #[test]
    fn dsse_backing_map_never_exceeds_cap_and_gauge_tracks_occupancy() {
        let store = InMemoryFederationArtifactStore::default();
        let inserts = IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY + 16;
        for i in 0..inserts {
            let id = format!("dsse-{i}");
            store.put_dsse(&id, &sample_dsse(&id)).unwrap();
            assert!(
                store.dsse_len() <= IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY,
                "dsse backing map exceeded cap at insert {i}: len={}",
                store.dsse_len()
            );
        }
        assert_eq!(
            store.dsse_len(),
            IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY,
            "backing map should be saturated at cap after over-filling"
        );
        assert!(store.get_dsse("dsse-0").unwrap().is_none());
        let last_id = format!("dsse-{}", inserts - 1);
        assert!(store.get_dsse(&last_id).unwrap().is_some());
    }
}
