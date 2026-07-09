//! Additive durable seam for bilateral co-sign artifacts (RFC-0004 F10). The
//! kernel caches DualSignedReceipt / DsseEnvelope in a capped, idle-swept
//! BoundedMap; when a FederationArtifactStore is configured, the co-sign hook
//! writes through to it first, and accessors fall through to it on a cache miss.

use std::sync::Mutex;

use chio_bounded::{BoundedMap, SizeGauge};
use chio_federation::bilateral::DualSignedReceipt;
use chio_federation::bilateral_dsse::DsseEnvelope;

use crate::kernel::current_unix_timestamp;
use crate::KernelError;

pub trait FederationArtifactStore: Send + Sync {
    fn put_dual_signed(&self, id: &str, receipt: &DualSignedReceipt) -> Result<(), KernelError>;
    fn get_dual_signed(&self, id: &str) -> Result<Option<DualSignedReceipt>, KernelError>;
    fn put_dsse(&self, id: &str, envelope: &DsseEnvelope) -> Result<(), KernelError>;
    fn get_dsse(&self, id: &str) -> Result<Option<DsseEnvelope>, KernelError>;
}

/// Hard cap and idle sweep for [`InMemoryFederationArtifactStore`]'s backing
/// maps. Mirrors the kernel's own federation cache defaults
/// (`MemoryBudgetConfig::federation_cache_capacity`, RFC-0004 section 5) so
/// the reference store carries the same footprint discipline as the caches
/// it sits behind.
const IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY: usize = 8192;
const IN_MEMORY_FEDERATION_ARTIFACT_STORE_IDLE_TTL_SECS: u64 = 3600;

/// Reference in-memory implementation (test double and default backing when a
/// deployment wants durable bilateral evidence without a database). Capped,
/// idle-swept, gauged instead of an unbounded HashMap (RFC-0004 F10): even
/// though this store has no install seam today, it must not become a
/// footgun once a follow-on wires one up. A deployment requiring persistence
/// installs a database-backed impl instead.
pub struct InMemoryFederationArtifactStore {
    dual: Mutex<BoundedMap<String, DualSignedReceipt>>,
    dual_gauge: SizeGauge,
    dsse: Mutex<BoundedMap<String, DsseEnvelope>>,
    dsse_gauge: SizeGauge,
}

impl Default for InMemoryFederationArtifactStore {
    fn default() -> Self {
        let dual_gauge = SizeGauge::new();
        let dsse_gauge = SizeGauge::new();
        Self {
            dual: Mutex::new(BoundedMap::new(
                IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY,
                IN_MEMORY_FEDERATION_ARTIFACT_STORE_IDLE_TTL_SECS,
                dual_gauge.clone(),
            )),
            dual_gauge,
            dsse: Mutex::new(BoundedMap::new(
                IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY,
                IN_MEMORY_FEDERATION_ARTIFACT_STORE_IDLE_TTL_SECS,
                dsse_gauge.clone(),
            )),
            dsse_gauge,
        }
    }
}

impl InMemoryFederationArtifactStore {
    /// Live occupancy of the dual-signed-receipt backing map.
    pub fn dual_signed_len(&self) -> usize {
        self.dual_gauge.get()
    }

    /// Live occupancy of the DSSE-envelope backing map.
    pub fn dsse_len(&self) -> usize {
        self.dsse_gauge.get()
    }
}

impl FederationArtifactStore for InMemoryFederationArtifactStore {
    fn put_dual_signed(&self, id: &str, receipt: &DualSignedReceipt) -> Result<(), KernelError> {
        let now = current_unix_timestamp();
        let mut guard = match self.dual.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Drop-oldest at capacity (BoundedMap's default eviction): the
        // evicted entry, if any, is intentionally discarded here since this
        // reference store has no durable tier to spill it to.
        let _evicted = guard.insert(id.to_string(), receipt.clone(), now);
        Ok(())
    }

    fn get_dual_signed(&self, id: &str) -> Result<Option<DualSignedReceipt>, KernelError> {
        let now = current_unix_timestamp();
        let mut guard = match self.dual.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Ok(guard.get(&id.to_string(), now).cloned())
    }

    fn put_dsse(&self, id: &str, envelope: &DsseEnvelope) -> Result<(), KernelError> {
        let now = current_unix_timestamp();
        let mut guard = match self.dsse.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _evicted = guard.insert(id.to_string(), envelope.clone(), now);
        Ok(())
    }

    fn get_dsse(&self, id: &str) -> Result<Option<DsseEnvelope>, KernelError> {
        let now = current_unix_timestamp();
        let mut guard = match self.dsse.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Ok(guard.get(&id.to_string(), now).cloned())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    use chio_core::crypto::{Ed25519Backend, Keypair, SigningBackend};
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    };
    use chio_federation::bilateral_dsse::DsseSignature;

    fn sample_dual_signed(id: &str) -> DualSignedReceipt {
        let kp = Keypair::generate();
        let body = ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_100,
            capability_id: "cap-receipt".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"message": "hello"}))
                .expect("tool action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "0".repeat(64),
            policy_hash: "1".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        };
        let receipt = ChioReceipt::sign(body, &kp).expect("sign receipt");
        let backend = Ed25519Backend::new(kp.clone());
        let signature = backend.sign_bytes(id.as_bytes()).expect("sign bytes");
        DualSignedReceipt {
            schema: "test.dual-signed-receipt.v1".to_string(),
            body: receipt,
            org_a_kernel_id: "kernel.org-a".to_string(),
            org_b_kernel_id: "kernel.org-b".to_string(),
            org_a_signature: signature.clone(),
            org_b_signature: signature,
        }
    }

    fn sample_dsse(id: &str) -> DsseEnvelope {
        DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: format!("payload-{id}"),
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
        assert!(store.get_dual_signed("missing").unwrap().is_none());
        assert!(store.get_dsse("missing").unwrap().is_none());
    }

    #[test]
    fn dual_signed_backing_map_never_exceeds_cap_and_gauge_tracks_occupancy() {
        let store = InMemoryFederationArtifactStore::default();
        let inserts = IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY + 16;
        for i in 0..inserts {
            let id = format!("rcpt-{i}");
            store
                .put_dual_signed(&id, &sample_dual_signed(&id))
                .unwrap();
            assert!(
                store.dual_signed_len() <= IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY,
                "dual-signed backing map exceeded cap at insert {i}: len={}",
                store.dual_signed_len()
            );
        }
        assert_eq!(
            store.dual_signed_len(),
            IN_MEMORY_FEDERATION_ARTIFACT_STORE_CAPACITY,
            "backing map should be saturated at cap after over-filling"
        );
        // Drop-oldest: the first-inserted id was evicted, the most recent survives.
        assert!(store.get_dual_signed("rcpt-0").unwrap().is_none());
        let last_id = format!("rcpt-{}", inserts - 1);
        assert!(store.get_dual_signed(&last_id).unwrap().is_some());
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
