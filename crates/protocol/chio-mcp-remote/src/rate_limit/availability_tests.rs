//! Cache capacity must not deny every previously unseen direct peer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use chio_security_types::clock::{ClockReading, MonotonicInstant, UnixMillis};
use std::sync::atomic::{AtomicU64, Ordering};

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let now = self.0.load(Ordering::SeqCst);
        Ok(ClockReading::new(
            UnixMillis::new(now),
            MonotonicInstant::from_nanos(now * 1_000_000),
        ))
    }
}

#[test]
fn full_live_peer_cache_admits_new_peer_by_bounded_oldest_eviction() {
    let clock = Arc::new(TestClock(AtomicU64::new(120_000)));
    let limiter = McpRateLimiter::new(RemoteClock::new(clock.clone()));
    for index in 0..MCP_RATE_LIMIT_MAX_KEYS {
        clock.0.store(120_000 + index as u64, Ordering::SeqCst);
        assert!(limiter.check(format!("peer:{index}")).is_ok());
    }
    clock.0.store(125_000, Ordering::SeqCst);
    assert!(
        limiter.check("new-legitimate-peer".into()).is_ok(),
        "a full unauthenticated peer cache denied every new client"
    );
    let windows = limiter.windows.lock().unwrap();
    assert_eq!(windows.len(), MCP_RATE_LIMIT_MAX_KEYS);
    assert!(windows.contains_key("new-legitimate-peer"));
    assert!(!windows.contains_key("peer:0"));
}

#[test]
fn admitting_new_peer_preserves_existing_peer_limit_and_original_deadline() {
    let clock = Arc::new(TestClock(AtomicU64::new(120_000)));
    let limiter = McpRateLimiter::new(RemoteClock::new(clock.clone()));
    for index in 0..MCP_RATE_LIMIT_MAX_KEYS - 1 {
        assert!(limiter.check(format!("older-peer:{index}")).is_ok());
    }
    clock.0.store(121_000, Ordering::SeqCst);
    for _ in 0..MCP_RATE_LIMIT_MAX_REQUESTS {
        assert!(limiter.check("limited-peer".into()).is_ok());
    }
    clock.0.store(122_000, Ordering::SeqCst);
    assert!(limiter.check("new-peer".into()).is_ok());
    assert!(matches!(
        limiter.check("limited-peer".into()),
        Err(Rejection::Limited(59))
    ));
    assert_eq!(
        limiter.windows.lock().unwrap()["limited-peer"].count,
        MCP_RATE_LIMIT_MAX_REQUESTS
    );
    assert_eq!(
        limiter.windows.lock().unwrap().len(),
        MCP_RATE_LIMIT_MAX_KEYS
    );
    clock.0.store(181_000, Ordering::SeqCst);
    assert!(limiter.check("limited-peer".into()).is_ok());
}

#[test]
fn ipv6_peer_keys_share_only_their_subnet_and_mapped_ipv4_keeps_address_identity() {
    let key = |address: &str| mcp_rate_limit_key(address.parse().unwrap());
    assert_eq!(
        key("[2001:db8:1234:5678::1]:123"),
        key("[2001:db8:1234:5678:abcd::2]:456")
    );
    assert_ne!(
        key("[2001:db8:1234:5678::1]:123"),
        key("[2001:db8:1234:5679::1]:123")
    );
    assert_eq!(key("192.0.2.1:123"), key("192.0.2.1:456"));
    assert_ne!(key("192.0.2.1:123"), key("192.0.2.2:123"));
    assert_eq!(key("[::ffff:192.0.2.1]:123"), key("192.0.2.1:123"));
}
