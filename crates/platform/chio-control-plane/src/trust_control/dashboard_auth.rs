use super::*;
use axum::http::header::{COOKIE, SET_COOKIE};
use rand_core::{OsRng, RngCore};

pub(crate) const DASHBOARD_SESSION_COOKIE: &str = "__Host-chio_dashboard";
pub(crate) const DASHBOARD_SESSION_TTL_SECONDS: u64 = 15 * 60;
pub(crate) const DASHBOARD_SESSION_CAPACITY: usize = 1_024;
pub(crate) const DASHBOARD_READ_TOKEN_MAX_BYTES: usize = 2_048;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DashboardSessionRequest {
    token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DashboardSessionResponse {
    authenticated: bool,
    expires_at: u64,
    relay_reports: super::dashboard_reports::DashboardReportAvailability,
}

#[derive(Clone)]
pub(crate) struct DashboardSessionStore {
    sessions: Arc<Mutex<HashMap<[u8; 32], u64>>>,
    capacity: usize,
    ttl_seconds: u64,
}

impl DashboardSessionStore {
    pub(crate) fn production() -> Self {
        Self::new(DASHBOARD_SESSION_CAPACITY, DASHBOARD_SESSION_TTL_SECONDS)
    }

    pub(crate) fn new(capacity: usize, ttl_seconds: u64) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            capacity: capacity.max(1),
            ttl_seconds: ttl_seconds.max(1),
        }
    }

    fn create_at(&self, now: u64) -> Result<(String, u64), Response> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            dashboard_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard session authority is unavailable",
            )
        })?;
        sessions.retain(|_, expires_at| *expires_at > now);
        if sessions.len() >= self.capacity {
            return Err(dashboard_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard session capacity is exhausted",
            ));
        }

        let mut session_bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut session_bytes).map_err(|_| {
            dashboard_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard session entropy is unavailable",
            )
        })?;
        let session_id = hex::encode(session_bytes);
        let digest = dashboard_session_digest(&session_bytes);
        if sessions.contains_key(&digest) {
            return Err(dashboard_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard session identifier collision",
            ));
        }
        let expires_at = now.checked_add(self.ttl_seconds).ok_or_else(|| {
            dashboard_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard session expiry exceeds the supported range",
            )
        })?;
        sessions.insert(digest, expires_at);
        Ok((session_id, expires_at))
    }

    fn authenticate_at(&self, session_id: &str, now: u64) -> Result<Option<u64>, Response> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            dashboard_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard session authority is unavailable",
            )
        })?;
        sessions.retain(|_, expires_at| *expires_at > now);
        let Some(digest) = dashboard_session_digest_from_id(session_id) else {
            return Ok(None);
        };
        Ok(sessions.get(&digest).copied())
    }

    fn delete(&self, session_id: &str) -> Result<(), Response> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            dashboard_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard session authority is unavailable",
            )
        })?;
        if let Some(digest) = dashboard_session_digest_from_id(session_id) {
            sessions.remove(&digest);
        }
        Ok(())
    }
}

fn dashboard_session_digest(session_bytes: &[u8; 32]) -> [u8; 32] {
    *chio_core::sha256(session_bytes).as_bytes()
}

fn dashboard_session_digest_from_id(session_id: &str) -> Option<[u8; 32]> {
    if session_id.len() != 64
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return None;
    }
    let mut session_bytes = [0u8; 32];
    hex::decode_to_slice(session_id, &mut session_bytes).ok()?;
    Some(dashboard_session_digest(&session_bytes))
}

fn configured_dashboard_token_matches(provided: &str, configured: &str) -> bool {
    let provided_digest = *chio_core::sha256(provided.as_bytes()).as_bytes();
    let configured_digest = *chio_core::sha256(configured.as_bytes()).as_bytes();
    bool::from(provided_digest.ct_eq(&configured_digest))
}

fn dashboard_session_cookie(headers: &HeaderMap) -> Option<&str> {
    let mut cookie_headers = headers.get_all(COOKIE).iter();
    let header = cookie_headers.next()?;
    if cookie_headers.next().is_some() {
        return None;
    }
    let mut matched = None;
    let value = header.to_str().ok()?;
    for cookie in value.split(';') {
        let cookie = cookie.trim();
        let Some((name, value)) = cookie.split_once('=') else {
            continue;
        };
        if name != DASHBOARD_SESSION_COOKIE {
            continue;
        }
        if value.is_empty() || matched.is_some() {
            return None;
        }
        matched = Some(value);
    }
    matched
}

fn session_cookie_value(session_id: &str, max_age: u64) -> String {
    format!(
        "{DASHBOARD_SESSION_COOKIE}={session_id}; Path=/; Max-Age={max_age}; Secure; HttpOnly; SameSite=Strict"
    )
}

fn clear_session_cookie_value() -> String {
    format!(
        "{DASHBOARD_SESSION_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict"
    )
}

fn add_no_store(response: &mut Response) {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
}

pub(crate) fn with_dashboard_no_store(mut response: Response) -> Response {
    add_no_store(&mut response);
    response
}

fn dashboard_error(status: StatusCode, message: &str) -> Response {
    let mut response = plain_http_error(status, message);
    add_no_store(&mut response);
    response
}

fn dashboard_auth_error() -> Response {
    dashboard_error(
        StatusCode::UNAUTHORIZED,
        "missing or invalid dashboard session",
    )
}

fn dashboard_timestamp_at(time: SystemTime) -> Result<u64, Response> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            dashboard_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "dashboard session clock is unavailable",
            )
        })
}

fn dashboard_timestamp_now() -> Result<u64, Response> {
    dashboard_timestamp_at(SystemTime::now())
}

pub(crate) fn validate_dashboard_session(
    headers: &HeaderMap,
    state: &TrustServiceState,
) -> Result<(), Response> {
    let session_id = dashboard_session_cookie(headers).ok_or_else(dashboard_auth_error)?;
    let now = dashboard_timestamp_now()?;
    match state.dashboard_sessions.authenticate_at(session_id, now)? {
        Some(_) => Ok(()),
        None => Err(dashboard_auth_error()),
    }
}

pub(crate) async fn handle_create_dashboard_session(
    State(state): State<TrustServiceState>,
    Json(request): Json<DashboardSessionRequest>,
) -> Response {
    let Some(configured) = state.config.dashboard_read_token.as_deref() else {
        return dashboard_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "dashboard read credential is not configured",
        );
    };
    if request.token.len() > DASHBOARD_READ_TOKEN_MAX_BYTES {
        return dashboard_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "dashboard read credential exceeds its byte limit",
        );
    }
    if !configured_dashboard_token_matches(&request.token, configured) {
        return dashboard_error(
            StatusCode::UNAUTHORIZED,
            "invalid dashboard read credential",
        );
    }
    let now = match dashboard_timestamp_now() {
        Ok(now) => now,
        Err(response) => return response,
    };
    let (session_id, expires_at) = match state.dashboard_sessions.create_at(now) {
        Ok(session) => session,
        Err(response) => return response,
    };
    let cookie = match HeaderValue::from_str(&session_cookie_value(
        &session_id,
        DASHBOARD_SESSION_TTL_SECONDS,
    )) {
        Ok(cookie) => cookie,
        Err(_) => {
            return dashboard_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "dashboard session cookie could not be encoded",
            );
        }
    };
    let mut response = Json(DashboardSessionResponse {
        authenticated: true,
        expires_at,
        relay_reports: super::dashboard_reports::DashboardReportAvailability::from_bridge(
            state.dashboard_report_bridge.as_ref(),
        ),
    })
    .into_response();
    response.headers_mut().insert(SET_COOKIE, cookie);
    add_no_store(&mut response);
    response
}

pub(crate) async fn handle_get_dashboard_session(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    let Some(session_id) = dashboard_session_cookie(&headers) else {
        return dashboard_auth_error();
    };
    let now = match dashboard_timestamp_now() {
        Ok(now) => now,
        Err(response) => return response,
    };
    let expires_at = match state.dashboard_sessions.authenticate_at(session_id, now) {
        Ok(Some(expires_at)) => expires_at,
        Ok(None) => return dashboard_auth_error(),
        Err(response) => return response,
    };
    let mut response = Json(DashboardSessionResponse {
        authenticated: true,
        expires_at,
        relay_reports: super::dashboard_reports::DashboardReportAvailability::from_bridge(
            state.dashboard_report_bridge.as_ref(),
        ),
    })
    .into_response();
    add_no_store(&mut response);
    response
}

pub(crate) async fn handle_delete_dashboard_session(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
) -> Response {
    if let Some(session_id) = dashboard_session_cookie(&headers) {
        if let Err(response) = state.dashboard_sessions.delete(session_id) {
            return response;
        }
    }
    let clear_cookie = match HeaderValue::from_str(&clear_session_cookie_value()) {
        Ok(cookie) => cookie,
        Err(_) => {
            return dashboard_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "dashboard session cookie could not be cleared",
            );
        }
    };
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(SET_COOKIE, clear_cookie);
    add_no_store(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn dashboard_session_store_is_bounded_and_prunes_expired_entries() {
        let store = DashboardSessionStore::new(1, 10);
        let (first, first_expiry) = store.create_at(100).test_unwrap();
        assert_eq!(first_expiry, 110);
        assert_eq!(store.authenticate_at(&first, 109).test_unwrap(), Some(110));
        assert_eq!(
            store.create_at(109).test_unwrap_err().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        let (second, second_expiry) = store.create_at(110).test_unwrap();
        assert_eq!(second_expiry, 120);
        assert_eq!(store.authenticate_at(&first, 110).test_unwrap(), None);
        assert_eq!(store.authenticate_at(&second, 110).test_unwrap(), Some(120));
        assert_eq!(
            store.create_at(u64::MAX).test_unwrap_err().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn dashboard_session_delete_invalidates_only_the_digest() {
        let store = DashboardSessionStore::new(2, 10);
        let (session_id, _) = store.create_at(100).test_unwrap();
        store.delete(&session_id).test_unwrap();
        assert_eq!(store.authenticate_at(&session_id, 100).test_unwrap(), None);
    }

    #[test]
    fn dashboard_cookie_has_the_host_only_security_contract() {
        let cookie = session_cookie_value("session-id", DASHBOARD_SESSION_TTL_SECONDS);
        assert_eq!(
            cookie,
            "__Host-chio_dashboard=session-id; Path=/; Max-Age=900; Secure; HttpOnly; SameSite=Strict"
        );
        assert!(!cookie.contains("Domain="));
        assert_eq!(
            clear_session_cookie_value(),
            "__Host-chio_dashboard=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Strict"
        );
    }

    #[test]
    fn dashboard_token_comparison_hashes_both_sides_to_fixed_width() {
        assert!(configured_dashboard_token_matches(
            "dashboard-secret",
            "dashboard-secret"
        ));
        assert!(!configured_dashboard_token_matches(
            "dashboard-secret",
            "dashboard-secret-2"
        ));
        assert!(!configured_dashboard_token_matches("x", "dashboard-secret"));
    }

    #[test]
    fn dashboard_session_clock_fails_closed_before_the_unix_epoch() {
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .test_expect("time before epoch");
        let response = dashboard_timestamp_at(before_epoch).test_unwrap_err();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(axum::http::header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }

    #[test]
    fn dashboard_cookie_parser_rejects_duplicate_headers_and_pairs() {
        let mut duplicate_headers = HeaderMap::new();
        duplicate_headers.append(
            COOKIE,
            HeaderValue::from_static("__Host-chio_dashboard=first"),
        );
        duplicate_headers.append(COOKIE, HeaderValue::from_static("unrelated=value"));
        assert_eq!(dashboard_session_cookie(&duplicate_headers), None);

        let mut duplicate_pairs = HeaderMap::new();
        duplicate_pairs.insert(
            COOKIE,
            HeaderValue::from_static("__Host-chio_dashboard=first; __Host-chio_dashboard=second"),
        );
        assert_eq!(dashboard_session_cookie(&duplicate_pairs), None);
    }

    #[test]
    fn dashboard_session_id_parser_rejects_unbounded_or_noncanonical_cookie_values() {
        assert!(dashboard_session_digest_from_id(&"a".repeat(64)).is_some());
        for invalid in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            assert!(dashboard_session_digest_from_id(&invalid).is_none());
        }
    }
}
