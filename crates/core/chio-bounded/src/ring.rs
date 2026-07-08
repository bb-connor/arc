use std::collections::VecDeque;

use crate::SizeGauge;

/// Fixed-capacity append-only ring for process-local mirrors. `capacity == 0`
/// means "disabled" (stores nothing, hands each item straight back), the
/// correct default when a durable store is authoritative.
///
/// `Clone` produces a read-only snapshot sharing the same `SizeGauge` handle;
/// the clone is never appended to, so the shared gauge is only ever written by
/// the owning structure.
#[derive(Clone, Debug)]
pub struct Ring<T> {
    buf: VecDeque<T>,
    capacity: usize,
    gauge: SizeGauge,
}

impl<T> Ring<T> {
    pub fn with_capacity(capacity: usize, gauge: SizeGauge) -> Self {
        Self {
            buf: VecDeque::new(),
            capacity,
            gauge,
        }
    }

    /// Push, evicting the oldest entry when at capacity. Returns the evicted
    /// item (if any) so callers may act before it drops. Never grows past
    /// `capacity`.
    pub fn push(&mut self, item: T) -> Option<T> {
        if self.capacity == 0 {
            return Some(item);
        }
        let evicted = if self.buf.len() >= self.capacity {
            self.buf.pop_front()
        } else {
            None
        };
        self.buf.push_back(item);
        self.gauge.set(self.buf.len());
        evicted
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.buf.iter()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use crate::{Ring, SizeGauge};

    #[test]
    fn push_never_exceeds_capacity_and_returns_evicted() {
        let gauge = SizeGauge::new();
        let mut ring: Ring<u32> = Ring::with_capacity(3, gauge.clone());
        assert_eq!(ring.push(1), None);
        assert_eq!(ring.push(2), None);
        assert_eq!(ring.push(3), None);
        assert_eq!(ring.len(), 3);
        assert_eq!(gauge.get(), 3);
        // At capacity: the oldest (1) is evicted and returned.
        assert_eq!(ring.push(4), Some(1));
        assert_eq!(ring.len(), 3);
        assert_eq!(gauge.get(), 3);
        let items: Vec<u32> = ring.iter().copied().collect();
        assert_eq!(items, vec![2, 3, 4]);
    }

    #[test]
    fn zero_capacity_stores_nothing_and_hands_item_back() {
        let gauge = SizeGauge::new();
        let mut ring: Ring<u32> = Ring::with_capacity(0, gauge.clone());
        assert_eq!(ring.push(7), Some(7));
        assert_eq!(ring.len(), 0);
        assert!(ring.is_empty());
        assert_eq!(gauge.get(), 0);
    }
}
