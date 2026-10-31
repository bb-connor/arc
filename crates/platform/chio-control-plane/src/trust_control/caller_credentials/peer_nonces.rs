use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};

use chio_store_sqlite::{ClusterPeerReplayStoreError, SqliteClusterPeerReplayStore};

use super::peer::PeerAuthError;

/// A peer request is fresh only while its `issued_at` is at most this many
/// seconds before the highest receiver time its nonce cache has observed.
pub const CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS: i64 = 60;

/// A peer request is fresh only while its `issued_at` is at most this many
/// seconds after the highest receiver time its nonce cache has observed.
///
/// Clock-skew contract: a peer clock may lead the receiver clock by at most
/// this many seconds. A request from a peer leading by more is refused as
/// stale. A receiver refuses a request from a peer it has no stored
/// high-water mark for when the request is issued at or before its start plus
/// this lead.
pub const CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS: i64 = 5;

/// Upper bound on remembered peer nonces. A full cache refuses new peer
/// requests rather than forgetting a nonce inside its freshness window. Each
/// pinned peer may hold at most an equal share of it.
pub const CLUSTER_PEER_NONCE_CACHE_CAPACITY: usize = 65_536;

/// Remembers each `(node id, nonce)` an accepted peer request used, decides
/// which issue times are fresh, and keeps every peer's durable `issued_at`
/// high-water mark.
///
/// The acceptance window is `[high_water - MAX_AGE, high_water + MAX_LEAD]`,
/// where `high_water` is the highest receiver time the cache has observed.
/// Both bounds only rise. An entry is pruned only once its issue time is below
/// the lower bound, so every request the window admits is checked against
/// every nonce that request could reuse, and a backward clock step never
/// reopens a pruned nonce.
///
/// Each peer also has a restart floor, fixed when the cache opens: the
/// peer's stored high-water mark, or `start + MAX_LEAD` for a peer without
/// one, where `start` is the receiver time the cache opened at. A request
/// issued at or below its peer's floor is refused. Before a request is
/// admitted, its peer's stored mark is raised to its issue time whenever the
/// issue time is above it, and a store that cannot be raised refuses the
/// request. Every request an earlier process on the same store accepted is
/// therefore at or below its peer's floor, whatever the receiver clock reads
/// after a restart. A peer without a stored mark keeps the clock-based bound:
/// a missing or reset store never admits more than that bound does.
///
/// Within one process the floor stays fixed, and distinct nonces issued in
/// the same second are admitted; the stored mark only rises.
///
/// The cache holds at most `CLUSTER_PEER_NONCE_CACHE_CAPACITY` entries and
/// each pinned peer at most an equal share of them. A full cache or a full
/// share refuses the request; a live entry is never evicted.
#[derive(Debug)]
pub struct PeerNonceCache {
    state: Mutex<NonceState>,
    store: Arc<SqliteClusterPeerReplayStore>,
    capacity: usize,
    per_peer_capacity: usize,
}

#[derive(Debug)]
struct NonceState {
    start: Option<i64>,
    high_water: i64,
    floors: HashMap<String, i64>,
    stored: HashMap<String, i64>,
    seen: HashSet<(String, String)>,
    by_expiry: BTreeSet<(i64, String, String)>,
    per_peer: HashMap<String, usize>,
}

impl NonceState {
    /// Fold `now_secs` into the high-water time and return the inclusive
    /// acceptance window for `node_id`, pruning every entry below the window.
    fn observe(&mut self, node_id: &str, now_secs: i64) -> (i64, i64) {
        self.high_water = self.high_water.max(now_secs);
        let start = *self.start.get_or_insert(now_secs);
        let window_start = self
            .high_water
            .saturating_sub(CLUSTER_PEER_SIGNATURE_MAX_AGE_SECS);
        let floor = self
            .floors
            .get(node_id)
            .copied()
            .unwrap_or_else(|| start.saturating_add(CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS));
        let latest = self
            .high_water
            .saturating_add(CLUSTER_PEER_SIGNATURE_MAX_LEAD_SECS);
        while let Some((issued_at, _, _)) = self.by_expiry.first() {
            if *issued_at >= window_start {
                break;
            }
            if let Some((_, node, nonce)) = self.by_expiry.pop_first() {
                if let Some(count) = self.per_peer.get_mut(&node) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.per_peer.remove(&node);
                    }
                }
                self.seen.remove(&(node, nonce));
            }
        }
        (window_start.max(floor.saturating_add(1)), latest)
    }
}

impl PeerNonceCache {
    /// A cache for a receiver pinning `pinned_peers` peers, holding every
    /// peer high-water mark in `store`. `start_secs` is the receiver time the
    /// cache starts at; when the receiver clock cannot be read at
    /// construction, the first observed time becomes the start.
    pub fn open(
        store: Arc<SqliteClusterPeerReplayStore>,
        start_secs: Option<i64>,
        pinned_peers: usize,
    ) -> Result<Self, ClusterPeerReplayStoreError> {
        Self::with_capacity(
            store,
            start_secs,
            pinned_peers,
            CLUSTER_PEER_NONCE_CACHE_CAPACITY,
        )
    }

    /// As [`PeerNonceCache::open`], holding at most `capacity` entries.
    pub fn with_capacity(
        store: Arc<SqliteClusterPeerReplayStore>,
        start_secs: Option<i64>,
        pinned_peers: usize,
        capacity: usize,
    ) -> Result<Self, ClusterPeerReplayStoreError> {
        let floors: HashMap<String, i64> = store.high_waters()?.into_iter().collect();
        Ok(Self {
            state: Mutex::new(NonceState {
                start: start_secs,
                high_water: start_secs.unwrap_or(i64::MIN),
                stored: floors.clone(),
                floors,
                seen: HashSet::new(),
                by_expiry: BTreeSet::new(),
                per_peer: HashMap::new(),
            }),
            store,
            capacity,
            per_peer_capacity: capacity / pinned_peers.max(1),
        })
    }

    /// Lock the cache and refuse `issued_at` outside `node_id`'s acceptance
    /// window at `now_secs`.
    fn fresh_state(
        &self,
        node_id: &str,
        issued_at: i64,
        now_secs: i64,
    ) -> Result<MutexGuard<'_, NonceState>, PeerAuthError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PeerAuthError::ReplayCacheUnavailable)?;
        let (earliest, latest) = state.observe(node_id, now_secs);
        if issued_at < earliest || issued_at > latest {
            return Err(PeerAuthError::Stale);
        }
        Ok(state)
    }

    pub(super) fn check_fresh(
        &self,
        node_id: &str,
        issued_at: i64,
        now_secs: i64,
    ) -> Result<(), PeerAuthError> {
        self.fresh_state(node_id, issued_at, now_secs).map(drop)
    }

    pub(super) fn record(
        &self,
        node_id: &str,
        nonce: &str,
        issued_at: i64,
        now_secs: i64,
    ) -> Result<(), PeerAuthError> {
        let mut state = self.fresh_state(node_id, issued_at, now_secs)?;
        let key = (node_id.to_string(), nonce.to_string());
        if state.seen.contains(&key) {
            return Err(PeerAuthError::ReplayedNonce);
        }
        if state.seen.len() >= self.capacity {
            return Err(PeerAuthError::ReplayCacheUnavailable);
        }
        if state.per_peer.get(node_id).copied().unwrap_or(0) >= self.per_peer_capacity {
            return Err(PeerAuthError::PeerNonceQuotaExhausted);
        }
        if state
            .stored
            .get(node_id)
            .is_none_or(|stored| issued_at > *stored)
        {
            self.store
                .advance(node_id, issued_at)
                .map_err(|_| PeerAuthError::PeerReplayStoreUnavailable)?;
            state.stored.insert(key.0.clone(), issued_at);
        }
        *state.per_peer.entry(key.0.clone()).or_insert(0) += 1;
        state
            .by_expiry
            .insert((issued_at, key.0.clone(), key.1.clone()));
        state.seen.insert(key);
        Ok(())
    }
}
