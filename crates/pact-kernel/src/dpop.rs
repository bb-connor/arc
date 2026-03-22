//! DPoP (Demonstration of Proof-of-Possession) for PACT tool invocations.
//!
//! A DPoP proof is an Ed25519-signed canonical JSON object that binds a
//! single tool invocation to the agent's keypair. It prevents stolen-token
//! replay by requiring the agent to prove possession of the private key
//! corresponding to `capability.subject` on every invocation.
//!
//! Proof fields:
//! - `schema`:        constant `"pact.dpop_proof.v1"` (forward-compat guard)
//! - `capability_id`: token ID of the capability being invoked
//! - `tool_server`:   server_id of the target tool server
//! - `tool_name`:     name of the tool being called
//! - `action_hash`:   SHA-256 hash of the serialized tool arguments
//! - `nonce`:         caller-chosen random string (replay prevention)
//! - `issued_at`:     Unix seconds when the proof was created
//! - `agent_key`:     hex-encoded Ed25519 public key of the signer
//!
//! Verification steps (in order):
//! 1. Schema check -- must equal `DPOP_SCHEMA`
//! 2. Sender constraint -- `agent_key` must equal `capability.subject`
//! 3. Binding fields -- capability_id, tool_server, tool_name, action_hash all match
//! 4. Freshness -- `issued_at + proof_ttl_secs >= now` and `issued_at <= now + max_clock_skew_secs`
//! 5. Signature -- Ed25519 over canonical JSON of the proof body
//! 6. Nonce replay -- nonce must not have been seen within the TTL window

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lru::LruCache;
use pact_core::canonical::canonical_json_bytes;
use pact_core::capability::CapabilityToken;
use pact_core::crypto::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::KernelError;

/// Schema identifier for PACT DPoP proofs (forward-compatibility guard).
pub const DPOP_SCHEMA: &str = "pact.dpop_proof.v1";

// ---------------------------------------------------------------------------
// DpopProofBody
// ---------------------------------------------------------------------------

/// The signable body of a DPoP proof.
///
/// This is the canonical-JSON-serialized message that the agent signs.
/// All fields are included in the signature; none are mutable after signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProofBody {
    /// Schema identifier. Must equal `DPOP_SCHEMA`.
    pub schema: String,
    /// ID of the capability token being used for this invocation.
    pub capability_id: String,
    /// `server_id` of the tool server being called.
    pub tool_server: String,
    /// Name of the tool being invoked.
    pub tool_name: String,
    /// SHA-256 hex of the serialized tool arguments (action binding).
    pub action_hash: String,
    /// Caller-chosen random string; must be unique within the TTL window.
    pub nonce: String,
    /// Unix seconds when this proof was created.
    pub issued_at: u64,
    /// Hex-encoded Ed25519 public key of the signer (must equal capability.subject).
    pub agent_key: PublicKey,
}

// ---------------------------------------------------------------------------
// DpopProof
// ---------------------------------------------------------------------------

/// A signed DPoP proof ready for transmission.
///
/// The `signature` covers the canonical JSON of `body`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProof {
    /// The proof body that was signed.
    pub body: DpopProofBody,
    /// Ed25519 signature over `canonical_json_bytes(&body)`.
    pub signature: Signature,
}

impl DpopProof {
    /// Sign a proof body with the agent's keypair.
    ///
    /// The `keypair` must be the one corresponding to `body.agent_key`.
    /// The signature covers the canonical JSON of the body.
    pub fn sign(body: DpopProofBody, keypair: &Keypair) -> Result<DpopProof, KernelError> {
        let body_bytes = canonical_json_bytes(&body).map_err(|e| {
            KernelError::DpopVerificationFailed(format!("failed to serialize proof body: {e}"))
        })?;
        let signature = keypair.sign(&body_bytes);
        Ok(DpopProof { body, signature })
    }
}

// ---------------------------------------------------------------------------
// DpopConfig
// ---------------------------------------------------------------------------

/// Configuration for DPoP proof verification.
#[derive(Debug, Clone)]
pub struct DpopConfig {
    /// How many seconds a proof is valid after `issued_at`. Default: 300.
    pub proof_ttl_secs: u64,
    /// How many seconds of future-dated clock skew to tolerate. Default: 30.
    pub max_clock_skew_secs: u64,
    /// Maximum number of entries in the nonce replay cache. Default: 8192.
    pub nonce_store_capacity: usize,
}

impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            proof_ttl_secs: 300,
            max_clock_skew_secs: 30,
            nonce_store_capacity: 8192,
        }
    }
}

// ---------------------------------------------------------------------------
// DpopNonceStore
// ---------------------------------------------------------------------------

/// In-memory LRU nonce replay store.
///
/// Keys are `(nonce, capability_id)` pairs. Values are the `Instant` when
/// the nonce was first seen. A nonce is rejected if it is still within the
/// TTL window when seen a second time.
///
/// This is intentionally synchronous (no async) and uses `std::sync::Mutex`
/// so it integrates cleanly into the `Guard` pipeline.
pub struct DpopNonceStore {
    inner: Mutex<LruCache<(String, String), Instant>>,
    ttl: Duration,
}

impl DpopNonceStore {
    /// Create a new nonce store.
    ///
    /// `capacity` is the maximum number of (nonce, capability_id) pairs to
    /// remember. `ttl` is how long a nonce is considered "live" after first
    /// use. After the TTL elapses, the same nonce can be used again.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        // NonZeroUsize::new returns None for 0; fall back to 1024 in that case.
        let nz = NonZeroUsize::new(capacity).unwrap_or_else(|| {
            // SAFETY: 1024 is a compile-time constant greater than zero.
            NonZeroUsize::new(1024).unwrap_or(NonZeroUsize::MIN)
        });
        Self {
            inner: Mutex::new(LruCache::new(nz)),
            ttl,
        }
    }

    /// Check a nonce and insert it if not already live.
    ///
    /// Returns `true` if the nonce is fresh (accepted).
    /// Returns `false` if the nonce was already used within the TTL window
    /// (rejected -- replay detected).
    pub fn check_and_insert(&self, nonce: &str, capability_id: &str) -> bool {
        let key = (nonce.to_string(), capability_id.to_string());
        let mut cache = self.inner.lock().unwrap_or_else(|p| p.into_inner());

        if let Some(first_seen) = cache.peek(&key) {
            if first_seen.elapsed() < self.ttl {
                // Nonce is still live -- replay detected.
                return false;
            }
            // TTL has elapsed; remove the stale entry so we can re-insert.
            cache.pop(&key);
        }

        cache.put(key, Instant::now());
        true
    }
}

// ---------------------------------------------------------------------------
// verify_dpop_proof
// ---------------------------------------------------------------------------

/// Verify a DPoP proof against the given capability and invocation context.
///
/// All six verification steps must pass; the first failure returns an error.
///
/// # Arguments
///
/// * `proof` - the signed DPoP proof from the agent
/// * `capability` - the capability token being used for this invocation
/// * `expected_tool_server` - `server_id` the kernel expects
/// * `expected_tool_name` - tool name the kernel expects
/// * `expected_action_hash` - SHA-256 hex of the serialized tool arguments
/// * `nonce_store` - shared replay-rejection store
/// * `config` - TTL and clock-skew bounds
pub fn verify_dpop_proof(
    proof: &DpopProof,
    capability: &CapabilityToken,
    expected_tool_server: &str,
    expected_tool_name: &str,
    expected_action_hash: &str,
    nonce_store: &DpopNonceStore,
    config: &DpopConfig,
) -> Result<(), KernelError> {
    // Step 1: Schema check.
    if proof.body.schema != DPOP_SCHEMA {
        return Err(KernelError::DpopVerificationFailed(format!(
            "unknown DPoP schema: expected {DPOP_SCHEMA}, got {}",
            proof.body.schema
        )));
    }

    // Step 2: Sender constraint -- agent_key must equal capability.subject.
    if proof.body.agent_key != capability.subject {
        return Err(KernelError::DpopVerificationFailed(
            "agent_key does not match capability subject (sender constraint violated)".to_string(),
        ));
    }

    // Step 3: Binding fields.
    if proof.body.capability_id != capability.id
        || proof.body.tool_server != expected_tool_server
        || proof.body.tool_name != expected_tool_name
        || proof.body.action_hash != expected_action_hash
    {
        return Err(KernelError::DpopVerificationFailed(
            "binding fields do not match: capability_id, tool_server, tool_name, or action_hash mismatch".to_string(),
        ));
    }

    // Step 4: Freshness check.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Proof must not be expired: issued_at + ttl >= now
    if proof.body.issued_at + config.proof_ttl_secs < now_secs {
        return Err(KernelError::DpopVerificationFailed(format!(
            "proof expired: issued_at={} ttl={} now={}",
            proof.body.issued_at, config.proof_ttl_secs, now_secs
        )));
    }

    // Proof must not be future-dated beyond clock skew tolerance: issued_at <= now + skew
    if proof.body.issued_at > now_secs + config.max_clock_skew_secs {
        return Err(KernelError::DpopVerificationFailed(format!(
            "proof issued_at={} is too far in the future (now={}, skew={})",
            proof.body.issued_at, now_secs, config.max_clock_skew_secs
        )));
    }

    // Step 5: Signature verification.
    let body_bytes = canonical_json_bytes(&proof.body).map_err(|e| {
        KernelError::DpopVerificationFailed(format!("failed to serialize proof body: {e}"))
    })?;
    if !proof.body.agent_key.verify(&body_bytes, &proof.signature) {
        return Err(KernelError::DpopVerificationFailed(
            "proof signature verification failed".to_string(),
        ));
    }

    // Step 6: Nonce replay check.
    if !nonce_store.check_and_insert(&proof.body.nonce, &proof.body.capability_id) {
        return Err(KernelError::DpopVerificationFailed(
            "nonce replayed: this nonce has already been used within the TTL window".to_string(),
        ));
    }

    Ok(())
}
