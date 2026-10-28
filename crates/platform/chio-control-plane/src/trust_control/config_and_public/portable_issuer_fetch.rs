//! Trust-before-fetch, strict HTTPS transport with pinned DNS, bounded
//! offload and post-wait acceptance time for OID4VP portable-issuer key and
//! passport-lifecycle resolution.
use super::*;

use chio_egress_contract::HttpEgressContract;
use std::time::Instant;

use crate::bounded_worker_pool::{BoundedWorkerPool, DeadlinePassed};

/// Read trusted whole-second time from an injected clock, preserving the clock
/// port's regression and failure semantics. Used where acceptance time must be
/// sampled from the request-handling state clock rather than a direct system
/// read, so a slow remote wait cannot carry a stale timestamp.
pub(crate) fn clock_unix_secs(
    clock: &dyn chio_security_types::clock::Clock,
) -> Result<u64, chio_security_types::clock::ClockError> {
    clock.unix_millis().map(|now| now.as_secs())
}

/// Bounds concurrent blocking portable-issuer and lifecycle fetches so a slow
/// or unreachable remote cannot pin more than this many Tokio workers. Permits
/// are never queued: a fetch that finds no free permit is refused at once.
pub(crate) const PORTABLE_ISSUER_FETCH_PERMITS: usize = 16;

/// Transport bounds for every outbound portable-issuer or lifecycle fetch.
/// The total deadline bounds the caller's wait for DNS and HTTP together.
/// A started fetch may retain its physical worker after that deadline; the
/// fixed pool below bounds those workers independently of the waiting callers.
const PORTABLE_ISSUER_FETCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PORTABLE_ISSUER_FETCH_READ_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const PORTABLE_ISSUER_FETCH_TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Fetch workers, and fetches that may queue behind them. A started fetch cannot
/// be cancelled, so a peer trickling its TLS handshake holds one worker for as
/// long as it keeps feeding it; once every worker and queue slot is held, each
/// further fetch is refused at once.
const PORTABLE_ISSUER_FETCH_WORKERS: usize = PORTABLE_ISSUER_FETCH_PERMITS;

/// Response-body ceiling for a portable-issuer JWKS or lifecycle document. The
/// buffered decode stops here, so an endpoint cannot stream an unbounded body.
const PORTABLE_ISSUER_FETCH_MAX_BODY_BYTES: usize = 512 * 1024;

static PORTABLE_ISSUER_FETCH_LANE: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(PORTABLE_ISSUER_FETCH_PERMITS)));

/// The process-wide portable-issuer fetch admission lane.
pub(crate) fn portable_issuer_fetch_lane() -> Arc<tokio::sync::Semaphore> {
    Arc::clone(&PORTABLE_ISSUER_FETCH_LANE)
}

pub(super) static PORTABLE_ISSUER_FETCH_POOL: LazyLock<BoundedWorkerPool> = LazyLock::new(|| {
    BoundedWorkerPool::new(PORTABLE_ISSUER_FETCH_WORKERS, PORTABLE_ISSUER_FETCH_WORKERS)
});

/// The single monotonic deadline of one portable fetch. The caller fixes it
/// before submitting the fetch, and every blocking phase samples only the time
/// left before it.
#[derive(Clone, Copy)]
pub(crate) struct PortableFetchDeadline(Instant);

impl PortableFetchDeadline {
    pub(crate) fn start() -> Result<Self, CliError> {
        Self::starting_at(Instant::now())
    }

    pub(super) fn starting_at(start: Instant) -> Result<Self, CliError> {
        start
            .checked_add(PORTABLE_ISSUER_FETCH_TOTAL_TIMEOUT)
            .map(Self)
            .ok_or_else(portable_fetch_deadline_exceeded)
    }

    /// The time left, sampled now. A passed deadline refuses the next phase.
    pub(super) fn remaining(&self) -> Result<Duration, CliError> {
        self.0
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(portable_fetch_deadline_exceeded)
    }
}

fn portable_fetch_deadline_exceeded() -> CliError {
    CliError::cli_other_error("portable issuer fetch exceeded its deadline")
}

/// Run one whole portable fetch on `pool` against `deadline`. DNS, pinning,
/// TLS, body and decode run as a single job on one worker, which never submits
/// work back to the pool. The caller waits only until the deadline and accepts
/// only an outcome observed before it; a fetch still running then keeps its
/// worker until it returns.
pub(super) fn run_portable_fetch<T>(
    pool: &BoundedWorkerPool,
    deadline: PortableFetchDeadline,
    fetch: impl FnOnce(PortableFetchDeadline) -> Result<T, CliError> + Send + 'static,
) -> Result<T, CliError>
where
    T: Send + 'static,
{
    pool.run_until(deadline.0, move || fetch(deadline))
        .map_err(|DeadlinePassed| portable_fetch_deadline_exceeded())?
}

/// Why a bounded portable-issuer fetch produced no transport outcome.
pub(crate) enum PortableFetchRefusal {
    /// Every fetch permit was held, so the attempt never started.
    AtCapacity,
    /// The blocking fetch panicked or its runtime shut down.
    Aborted(tokio::task::JoinError),
}

impl PortableFetchRefusal {
    pub(crate) fn into_response(self, error: fn(StatusCode, &str) -> Response) -> Response {
        match self {
            Self::AtCapacity => error(
                StatusCode::SERVICE_UNAVAILABLE,
                "portable issuer resolution is at capacity",
            ),
            Self::Aborted(join_error) => {
                // The join error can carry a panic payload. Keep the cause in
                // the local log and return only a fixed public message.
                tracing::warn!(error = %join_error, "portable issuer resolution did not complete");
                error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "portable issuer resolution did not complete",
                )
            }
        }
    }
}

/// Runs one blocking portable-issuer fetch on Tokio's blocking pool against the
/// supplied admission lane.
///
/// Admission never waits: without a free permit the attempt is refused before
/// any network I/O. The permit moves into the blocking closure and is released
/// only when that closure returns, so a request future dropped mid-fetch keeps
/// its permit until the closure has actually ended.
pub(crate) async fn run_portable_issuer_fetch_with_lane<T>(
    lane: Arc<tokio::sync::Semaphore>,
    fetch: impl FnOnce() -> T + Send + 'static,
) -> Result<T, PortableFetchRefusal>
where
    T: Send + 'static,
{
    let permit = lane
        .try_acquire_owned()
        .map_err(|_| PortableFetchRefusal::AtCapacity)?;
    tokio::task::spawn_blocking(move || {
        let outcome = fetch();
        drop(permit);
        outcome
    })
    .await
    .map_err(PortableFetchRefusal::Aborted)
}

/// Runs one blocking portable-issuer fetch against the process-wide lane.
pub(crate) async fn run_portable_issuer_fetch<T>(
    fetch: impl FnOnce() -> T + Send + 'static,
) -> Result<T, PortableFetchRefusal>
where
    T: Send + 'static,
{
    run_portable_issuer_fetch_with_lane(portable_issuer_fetch_lane(), fetch).await
}

/// Where the keys that verify a presented portable credential come from.
pub(crate) enum PortableIssuerResolution {
    /// The credential was issued by this verifier's own advertised issuer, so
    /// it is verified with local authority keys and needs no network fetch.
    Local(Vec<PublicKey>),
    /// The credential issuer is explicitly allowlisted by the signed verifier
    /// request, so its keys may be fetched over the bounded strict transport.
    Remote(RemotePortableIssuerFetch),
    /// The credential issuer is neither local nor allowlisted. No key material
    /// is resolved and no network I/O is attempted.
    Untrusted,
}

/// A trusted remote portable-issuer JWKS fetch whose transport is pinned to the
/// addresses that passed the strict HTTPS address policy.
pub(crate) struct RemotePortableIssuerFetch {
    jwks_url: String,
    contract: HttpEgressContract,
}

impl RemotePortableIssuerFetch {
    pub(crate) fn resolve(self) -> Result<Vec<PublicKey>, CliError> {
        run_portable_fetch(
            &PORTABLE_ISSUER_FETCH_POOL,
            PortableFetchDeadline::start()?,
            move |deadline| self.fetch(&deadline),
        )
    }

    fn fetch(self, deadline: &PortableFetchDeadline) -> Result<Vec<PublicKey>, CliError> {
        let url = Url::parse(&self.jwks_url).map_err(|error| {
            CliError::cli_other_error(format!("portable issuer JWKS URL is invalid: {error}"))
        })?;
        let pinned = pin_checked_https_addrs(&self.contract, &url, system_resolve_host)?;
        let agent = build_portable_fetch_agent(pinned, true, deadline)?;
        fetch_portable_issuer_jwks(&agent, &self.jwks_url)
    }
}

/// Decide which keys verify a presented portable credential, performing no
/// network I/O. Trust is fixed before any fetch: our own advertised issuer uses
/// local keys, every other issuer must appear in the signed verifier request's
/// issuer allowlist, and an empty allowlist trusts only the local issuer.
pub(crate) fn plan_portable_issuer_keys(
    config: &TrustServiceConfig,
    issuer: &str,
    allowed_issuers: &BTreeSet<String>,
    clock: &Arc<dyn chio_security_types::clock::Clock>,
) -> Result<PortableIssuerResolution, CliError> {
    if config.advertise_url.as_deref() == Some(issuer) {
        return Ok(PortableIssuerResolution::Local(
            resolve_public_oid4vp_verifier_trusted_public_keys(config, clock)?,
        ));
    }
    if !allowed_issuers.contains(issuer) {
        return Ok(PortableIssuerResolution::Untrusted);
    }
    let jwks_url = format!("{issuer}{OID4VCI_JWKS_PATH}");
    let contract = strict_portable_fetch_contract(&jwks_url, "control-plane.portable-issuer-jwks")?;
    Ok(PortableIssuerResolution::Remote(
        RemotePortableIssuerFetch { jwks_url, contract },
    ))
}

/// Parse an issuer JWKS body (bounded and non-reflected) into its public keys.
fn fetch_portable_issuer_jwks(agent: &Agent, jwks_url: &str) -> Result<Vec<PublicKey>, CliError> {
    let response = agent
        .get(jwks_url)
        .call()
        .map_err(|error| portable_fetch_transport_error("portable issuer JWKS endpoint", error))?;
    let jwks: chio_credentials::PortableJwkSet =
        crate::json_input::read(response.into_reader(), PORTABLE_ISSUER_FETCH_MAX_BODY_BYTES)?;
    let mut public_keys = Vec::with_capacity(jwks.keys.len());
    for entry in &jwks.keys {
        public_keys.push(
            entry
                .jwk
                .to_public_key()
                .map_err(|error| CliError::cli_other_error(error.to_string()))?,
        );
    }
    if public_keys.is_empty() {
        return Err(CliError::cli_other_error(
            "portable issuer JWKS did not publish any keys".to_string(),
        ));
    }
    Ok(public_keys)
}

/// How a presented portable credential's lifecycle is resolved.
pub(crate) enum PassportLifecyclePlan {
    /// The lifecycle is known without any network I/O: either from the local
    /// status registry, or because the credential carries no status reference.
    Resolved(Option<PassportLifecycleResolution>),
    /// The lifecycle must be fetched from a remote resolver over the bounded
    /// strict transport.
    Remote(RemotePassportLifecycleFetch),
}

/// A remote passport-lifecycle fetch whose transport is pinned to the addresses
/// that passed the strict HTTPS address policy.
pub(crate) struct RemotePassportLifecycleFetch {
    url: String,
    contract: HttpEgressContract,
}

impl RemotePassportLifecycleFetch {
    pub(crate) fn resolve(self) -> Result<PassportLifecycleResolution, CliError> {
        run_portable_fetch(
            &PORTABLE_ISSUER_FETCH_POOL,
            PortableFetchDeadline::start()?,
            move |deadline| self.fetch(&deadline),
        )
    }

    fn fetch(
        self,
        deadline: &PortableFetchDeadline,
    ) -> Result<PassportLifecycleResolution, CliError> {
        let parsed = Url::parse(&self.url).map_err(|error| {
            CliError::cli_other_error(format!(
                "portable passport lifecycle URL is invalid: {error}"
            ))
        })?;
        let pinned = pin_checked_https_addrs(&self.contract, &parsed, system_resolve_host)?;
        let agent = build_portable_fetch_agent(pinned, true, deadline)?;
        let response = agent.get(&self.url).call().map_err(|error| {
            portable_fetch_transport_error("portable passport lifecycle endpoint", error)
        })?;
        let lifecycle: PassportLifecycleResolution =
            crate::json_input::read(response.into_reader(), PORTABLE_ISSUER_FETCH_MAX_BODY_BYTES)?;
        lifecycle
            .validate()
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        Ok(lifecycle)
    }
}

/// Decide how a presented portable credential's lifecycle is resolved, doing no
/// network I/O. A remote resolve URL is only ever fetched over the bounded
/// strict transport by [`RemotePassportLifecycleFetch::resolve`].
pub(crate) fn plan_oid4vp_passport_lifecycle(
    config: &TrustServiceConfig,
    passport_id: &str,
    status_ref: Option<&chio_credentials::Oid4vciChioPassportStatusReference>,
    clock_now: u64,
) -> Result<PassportLifecyclePlan, CliError> {
    if let Some(path) = config.passport_statuses_file.as_deref() {
        return Ok(PassportLifecyclePlan::Resolved(Some(
            resolve_registered_lifecycle(path, passport_id, clock_now)?,
        )));
    }
    let Some(status_ref) = status_ref else {
        return Ok(PassportLifecyclePlan::Resolved(None));
    };
    let resolve_url = status_ref
        .distribution
        .resolve_urls
        .first()
        .cloned()
        .ok_or_else(|| {
            CliError::cli_other_error(
                "OID4VP passport status validation requires at least one resolve URL".to_string(),
            )
        })?;
    let url = format!(
        "{}/{}",
        resolve_url.trim_end_matches('/'),
        utf8_percent_encode(passport_id, NON_ALPHANUMERIC)
    );
    let contract =
        strict_portable_fetch_contract(&url, "control-plane.portable-passport-lifecycle")?;
    Ok(PassportLifecyclePlan::Remote(
        RemotePassportLifecycleFetch { url, contract },
    ))
}

fn resolve_registered_lifecycle(
    path: &Path,
    passport_id: &str,
    now: u64,
) -> Result<PassportLifecycleResolution, CliError> {
    let registry = PassportStatusRegistry::load(path)?;
    let resolution = registry.resolve_at(passport_id, now);
    crate::passport_revocation::check_registered_passport_revocation(path, &registry, &resolution)?;
    Ok(resolution)
}

/// Judge an OID4VP lifecycle answer again at the door's acceptance instant.
/// A local registry is resolved again at `accept_now`. A remote answer holds
/// until `requested_at` plus the cache TTL that the signed status reference
/// grants, and a reference without a TTL grants none.
pub(crate) fn recheck_oid4vp_passport_lifecycle(
    config: &TrustServiceConfig,
    passport_id: &str,
    status_ref: Option<&chio_credentials::Oid4vciChioPassportStatusReference>,
    lifecycle: Option<PassportLifecycleResolution>,
    requested_at: u64,
    accept_now: u64,
) -> Result<Option<PassportLifecycleResolution>, CliError> {
    if let Some(path) = config.passport_statuses_file.as_deref() {
        return resolve_registered_lifecycle(path, passport_id, accept_now).map(Some);
    }
    let Some(status_ref) = status_ref else {
        return Ok(lifecycle);
    };
    let held_until = status_ref
        .distribution
        .cache_ttl_secs
        .and_then(|ttl| requested_at.checked_add(ttl))
        .ok_or_else(|| {
            CliError::cli_other_error(
                "OID4VP passport status reference grants no cache TTL for its remote lifecycle"
                    .to_string(),
            )
        })?;
    if accept_now > held_until {
        return Err(CliError::cli_other_error(
            "remote passport lifecycle is older than its cache TTL at acceptance".to_string(),
        ));
    }
    Ok(lifecycle)
}

/// Build the strict HTTPS egress contract for a portable-issuer or lifecycle
/// fetch. HTTPS is required and loopback, link-local, unique-local and other
/// private or special-use targets are denied, so an attacker-chosen URL cannot
/// reach an internal address. HTTP or private explicit issuers are refused here
/// before any network I/O.
fn strict_portable_fetch_contract(
    url: &str,
    namespace: &str,
) -> Result<HttpEgressContract, CliError> {
    let parsed = Url::parse(url).map_err(|error| {
        CliError::cli_other_error(format!("egress URL `{url}` is invalid: {error}"))
    })?;
    crate::anchor_egress::strict_https_contract(
        &parsed,
        namespace,
        crate::integer::count(PORTABLE_ISSUER_FETCH_MAX_BODY_BYTES),
    )
    .map_err(CliError::cli_other_error)
}

/// Resolve a host once, check every resolved address against the strict policy,
/// and return the exact checked addresses. Pinning these into the fetch agent's
/// resolver closes the validate-then-re-resolve gap that DNS rebinding exploits.
pub(super) fn pin_checked_https_addrs<R>(
    contract: &HttpEgressContract,
    url: &Url,
    resolve: R,
) -> Result<Vec<SocketAddr>, CliError>
where
    R: Fn(&str, u16) -> std::io::Result<Vec<SocketAddr>>,
{
    contract
        .enforce_url(url.as_str(), 0)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| CliError::cli_other_error("egress URL must include a host".to_string()))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| CliError::cli_other_error("egress URL must declare a port".to_string()))?;
    let resolved = resolve(host, port).map_err(|error| {
        CliError::cli_other_error(format!("failed to resolve egress host `{host}`: {error}"))
    })?;
    let mut checked = Vec::with_capacity(resolved.len());
    for addr in resolved {
        contract
            .enforce_resolved_address(host, addr)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
        checked.push(addr);
    }
    if checked.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "egress host `{host}` resolved to no addresses"
        )));
    }
    Ok(checked)
}

pub(super) fn system_resolve_host(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(|iter| iter.collect())
}

/// Build the bounded fetch agent. The resolver returns only the pre-checked
/// pinned addresses, redirects are disabled, and connect, read and overall
/// deadlines bound every attempt. The fetch deadline's remainder, sampled here
/// immediately before the request, is the overall deadline and also caps the
/// connect stage, which ureq otherwise times from its own start.
/// `require_https` enforces HTTPS on the one production transport; the
/// loopback test seam supplies plaintext.
pub(crate) fn build_portable_fetch_agent(
    pinned: Vec<SocketAddr>,
    require_https: bool,
    deadline: &PortableFetchDeadline,
) -> Result<Agent, CliError> {
    let remaining = deadline.remaining()?;
    // CHIO_EGRESS_LINT_ALLOW_DIRECT_UREQ: strict portable issuer fetch: the resolver returns only
    // the addresses pinned and checked before the fetch, and redirects are off
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(remaining.min(PORTABLE_ISSUER_FETCH_CONNECT_TIMEOUT))
        .timeout_read(PORTABLE_ISSUER_FETCH_READ_TIMEOUT)
        .timeout(remaining)
        .redirects(0)
        .resolver(move |_netloc: &str| Ok(pinned.clone()));
    if require_https {
        builder = builder.https_only(true);
    }
    Ok(builder.build())
}

/// Map a transport error to a fail-closed message that never echoes the fetched
/// body or any resolved internal address back to the caller.
pub(super) fn portable_fetch_transport_error(endpoint: &str, error: ureq::Error) -> CliError {
    match error {
        ureq::Error::Status(status, _response) => {
            CliError::cli_other_error(format!("{endpoint} returned HTTP {status}"))
        }
        ureq::Error::Transport(_transport) => {
            CliError::cli_other_error(format!("{endpoint} was unreachable"))
        }
    }
}

#[cfg(test)]
#[path = "portable_issuer_fetch_tests.rs"]
mod tests;
