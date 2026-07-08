use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;

use crate::SizeGauge;

struct Timestamped<V> {
    value: V,
    last_seen_secs: u64,
}

/// Capacity-bounded, optionally TTL-swept map for caches and rate-limit tables.
/// Eviction order is oldest-insert (approximate LRU: `get` refreshes the idle
/// timestamp but does not reorder). `insert` returns any (key, value) evicted
/// for capacity so the caller can persist-before-drop. `capacity == 0` disables
/// the cache, mirroring `Ring`.
pub struct BoundedMap<K, V> {
    inner: HashMap<K, Timestamped<V>>,
    order: VecDeque<K>,
    capacity: usize,
    idle_ttl_secs: u64,
    sweep_interval: usize,
    inserts_since_sweep: usize,
    gauge: SizeGauge,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    pub fn new(capacity: usize, idle_ttl_secs: u64, gauge: SizeGauge) -> Self {
        Self {
            inner: HashMap::new(),
            order: VecDeque::new(),
            capacity,
            idle_ttl_secs,
            sweep_interval: 256,
            inserts_since_sweep: 0,
            gauge,
        }
    }

    pub fn insert(&mut self, key: K, value: V, now_secs: u64) -> Option<(K, V)> {
        if self.capacity == 0 {
            return Some((key, value));
        }
        self.inserts_since_sweep = self.inserts_since_sweep.saturating_add(1);
        if self.inserts_since_sweep >= self.sweep_interval {
            self.sweep_idle(now_secs);
            self.inserts_since_sweep = 0;
        }
        let mut evicted = None;
        if !self.inner.contains_key(&key) && self.inner.len() >= self.capacity {
            evicted = self.evict_oldest();
        }
        self.inner.insert(
            key.clone(),
            Timestamped {
                value,
                last_seen_secs: now_secs,
            },
        );
        self.order.push_back(key);
        if self.order.len() > self.capacity.saturating_mul(2) {
            self.compact_order();
        }
        self.gauge.set(self.inner.len());
        evicted
    }

    pub fn get(&mut self, key: &K, now_secs: u64) -> Option<&V> {
        match self.inner.get_mut(key) {
            Some(entry) => {
                entry.last_seen_secs = now_secs;
                Some(&entry.value)
            }
            None => None,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn compact_order(&mut self) {
        let mut seen = HashSet::with_capacity(self.inner.len());
        let mut compacted = VecDeque::with_capacity(self.inner.len());
        while let Some(key) = self.order.pop_back() {
            if self.inner.contains_key(&key) && seen.insert(key.clone()) {
                compacted.push_front(key);
            }
        }
        self.order = compacted;
    }

    fn sweep_idle(&mut self, now_secs: u64) {
        if self.idle_ttl_secs == 0 {
            return;
        }
        let floor = now_secs.saturating_sub(self.idle_ttl_secs);
        self.inner.retain(|_, entry| entry.last_seen_secs > floor);
        self.order.retain(|k| self.inner.contains_key(k));
        self.gauge.set(self.inner.len());
    }

    fn evict_oldest(&mut self) -> Option<(K, V)> {
        while let Some(candidate) = self.order.pop_front() {
            if let Some(entry) = self.inner.remove(&candidate) {
                self.gauge.set(self.inner.len());
                return Some((candidate, entry.value));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{BoundedMap, SizeGauge};

    #[test]
    fn insert_evicts_oldest_at_cap_and_returns_it() {
        let gauge = SizeGauge::new();
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(2, 0, gauge.clone());
        assert_eq!(map.insert(1, 10, 0), None);
        assert_eq!(map.insert(2, 20, 0), None);
        assert_eq!(map.len(), 2);
        // At cap: inserting a new key evicts the oldest-inserted (key 1).
        assert_eq!(map.insert(3, 30, 0), Some((1, 10)));
        assert_eq!(map.len(), 2);
        assert_eq!(gauge.get(), 2);
        assert_eq!(map.get(&1, 0), None);
        assert_eq!(map.get(&3, 0), Some(&30));
    }

    #[test]
    fn sweep_idle_drops_expired_keeps_fresh() {
        let gauge = SizeGauge::new();
        // capacity high so eviction never fires; idle_ttl 10s; sweep every 256.
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(4096, 10, gauge.clone());
        map.insert(1, 10, 100); // last_seen 100
        map.insert(2, 20, 100);
        // Refresh key 2 at t=105 so it survives a sweep at t=115.
        assert_eq!(map.get(&2, 105), Some(&20));
        // Force a sweep by driving 256 inserts at t=115; floor = 115 - 10 = 105.
        for k in 1000..1256u32 {
            map.insert(k, k, 115);
        }
        // Key 1 (last_seen 100 <= 105 floor) is swept; key 2 (last_seen 105) is
        // NOT > floor 105, so it is also swept. Refresh key 2 later to prove the
        // keep path independently.
        assert_eq!(map.get(&1, 115), None);

        let gauge2 = SizeGauge::new();
        let mut map2: BoundedMap<u32, u32> = BoundedMap::new(4096, 10, gauge2);
        map2.insert(1, 10, 100);
        assert_eq!(map2.get(&1, 200), Some(&10)); // refresh last_seen to 200
        for k in 1000..1256u32 {
            map2.insert(k, k, 205); // floor 195; key 1 last_seen 200 > 195 survives
        }
        assert_eq!(map2.get(&1, 205), Some(&10));
    }

    #[test]
    fn zero_capacity_disables_and_hands_pair_back() {
        let gauge = SizeGauge::new();
        let mut map: BoundedMap<u32, u32> = BoundedMap::new(0, 0, gauge.clone());
        assert_eq!(map.insert(1, 10, 0), Some((1, 10)));
        assert_eq!(map.len(), 0);
        assert_eq!(gauge.get(), 0);
    }
}

#[cfg(test)]
mod prop {
    use crate::{BoundedMap, SizeGauge};
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
        Insert(u8, u8, u64),
        Get(u8, u64),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            (any::<u8>(), any::<u8>(), 0u64..1000).prop_map(|(k, v, t)| Op::Insert(k, v, t)),
            (any::<u8>(), 0u64..1000).prop_map(|(k, t)| Op::Get(k, t)),
        ]
    }

    proptest! {
        #[test]
        fn gauge_tracks_len_and_len_never_exceeds_capacity(
            cap in 1usize..64,
            ttl in 0u64..50,
            ops in prop::collection::vec(op_strategy(), 0..500),
        ) {
            let gauge = SizeGauge::new();
            let mut map: BoundedMap<u8, u8> = BoundedMap::new(cap, ttl, gauge.clone());
            for op in ops {
                match op {
                    Op::Insert(k, v, t) => { let _ = map.insert(k, v, t); }
                    Op::Get(k, t) => { let _ = map.get(&k, t); }
                }
                prop_assert!(map.len() <= cap, "len {} exceeded cap {}", map.len(), cap);
                prop_assert_eq!(map.len(), gauge.get(), "gauge desynced from len");
            }
        }
    }
}
