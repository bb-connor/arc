//! Bounded rate windows share the service clock and never prune on clock failure.
use crate::{clock, RemoteClock};
use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use chio_security_types::clock::{AuthorityDeadline, Clock, ClockError};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

const MCP_RATE_LIMIT_MAX_REQUESTS: u32 = 600;
const MCP_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MCP_RATE_LIMIT_MAX_KEYS: usize = 4096;

#[derive(Clone)]
pub(crate) struct McpRateLimiter {
    clock: RemoteClock,
    windows: Arc<Mutex<HashMap<String, McpRateWindow>>>,
}
struct McpRateWindow {
    deadline: AuthorityDeadline,
    count: u32,
}
#[derive(Debug)]
enum Rejection {
    Clock(ClockError),
    Limited(u64),
}
impl From<ClockError> for Rejection {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}
impl McpRateLimiter {
    pub(crate) fn new(clock: RemoteClock) -> Self {
        Self {
            clock,
            windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    fn check(&self, key: String) -> Result<(), Rejection> {
        let mut windows = self.windows.lock().map_err(|_| ClockError::Unavailable)?;
        let now = self.clock.read()?;
        let deadline = AuthorityDeadline::for_timeout_ms(now, 60_000)?;
        let mut expired = Vec::new();
        for (key, window) in windows.iter_mut() {
            match window.deadline.remaining(now) {
                Err(ClockError::Expired) => expired.push(key.clone()),
                Err(error) => return Err(error.into()),
                Ok(_) => {}
            }
        }
        for key in expired {
            windows.remove(&key);
        }
        if let Some(window) = windows.get_mut(&key) {
            if window.count >= MCP_RATE_LIMIT_MAX_REQUESTS {
                let remaining = window.deadline.remaining(now)?;
                return Err(Rejection::Limited(
                    remaining
                        .as_secs()
                        .checked_add(u64::from(remaining.subsec_nanos() > 0))
                        .ok_or(ClockError::Overflow)?,
                ));
            }
            window.count = window.count.checked_add(1).ok_or(ClockError::Overflow)?;
        } else if windows.len() >= MCP_RATE_LIMIT_MAX_KEYS {
            return Err(Rejection::Limited(MCP_RATE_LIMIT_WINDOW.as_secs()));
        } else {
            windows.insert(key, McpRateWindow { deadline, count: 1 });
        }
        Ok(())
    }
}
pub(crate) fn mcp_rate_limit_key(remote_addr: SocketAddr) -> String {
    format!("ip:{}", remote_addr.ip())
}
pub(crate) async fn rate_limit_mcp_request(
    axum::extract::ConnectInfo(chio_http_serve::CappedPeerAddr(remote_addr)): axum::extract::ConnectInfo<chio_http_serve::CappedPeerAddr>,
    State(limiter): State<McpRateLimiter>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    match limiter.check(mcp_rate_limit_key(remote_addr)) {
        Ok(()) => next.run(request).await,
        Err(Rejection::Clock(error)) => clock::rejection(error),
        Err(Rejection::Limited(retry_after)) => {
            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                "MCP request rate limit exceeded",
            )
                .into_response();
            if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
                response
                    .headers_mut()
                    .insert(HeaderName::from_static("retry-after"), value);
            }
            response
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_security_types::clock::{ClockReading, MonotonicInstant, UnixMillis};
    use std::sync::atomic::{AtomicU64, Ordering};
    struct TestClock(AtomicU64);
    impl Clock for TestClock {
        fn read(&self) -> Result<ClockReading, ClockError> {
            let millis = self.0.load(Ordering::SeqCst);
            Ok(ClockReading::new(
                UnixMillis::new(millis),
                MonotonicInstant::from_nanos(millis * 1_000_000),
            ))
        }
    }
    #[test]
    fn window_budget_exact_expiry_and_rollback() {
        let source = Arc::new(TestClock(AtomicU64::new(120_000)));
        let limiter = McpRateLimiter::new(RemoteClock::new(source.clone()));
        for _ in 0..MCP_RATE_LIMIT_MAX_REQUESTS {
            assert!(limiter.check("session".into()).is_ok());
        }
        assert!(matches!(
            limiter.check("session".into()),
            Err(Rejection::Limited(60))
        ));
        source.0.store(119_000, Ordering::SeqCst);
        assert!(matches!(
            limiter.check("session".into()),
            Err(Rejection::Clock(ClockError::WallClockRegression))
        ));
        assert_eq!(
            limiter.windows.lock().unwrap()["session"].count,
            MCP_RATE_LIMIT_MAX_REQUESTS
        );
        source.0.store(180_000, Ordering::SeqCst);
        assert!(limiter.check("session".into()).is_ok());
    }
    #[test]
    fn tracked_keys_are_bounded() {
        let limiter = McpRateLimiter::new(RemoteClock::new(Arc::new(TestClock(AtomicU64::new(
            120_000,
        )))));
        for idx in 0..MCP_RATE_LIMIT_MAX_KEYS {
            assert!(limiter.check(format!("session:{idx}")).is_ok());
        }
        assert!(matches!(
            limiter.check("overflow".into()),
            Err(Rejection::Limited(60))
        ));
        assert!(limiter.check("session:0".into()).is_ok());
    }
}
