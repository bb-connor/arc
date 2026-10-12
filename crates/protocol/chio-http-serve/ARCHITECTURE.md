# chio-http-serve architecture

## Responsibility and boundary

The crate owns serving helpers and transport preparation. The host owns routes,
application authorization, acknowledged-write durability, and the flush hook. A
configuration value takes effect only through the corresponding helper.

Provides shared Axum request hygiene, connection caps, TLS transport preparation,
shutdown signaling, and bounded drain with a flush hook.

## Structure

`hygiene` builds router layers, `listener` wraps accepted I/O, `signal` fans
shutdown through watch channels, and `drain` bounds teardown. `transport` prepares
TLS and listeners; `private_pem` validates private-key framing.

`ServeHygieneConfig` holds request timeout, concurrent request and connection
limits, an optional body-extractor ceiling, and post-signal drain timeout.
`ShutdownController` shares a watch-channel signal across serving and drain.
`DrainOutcome` distinguishes Clean from Forced; ServeError distinguishes serve I/O
failures from post-drain flush failures.

## Data and control flow

Prepare and validate transport configuration before binding. Wrap the listener with
`MaxConnListener`, apply router hygiene, and pass the same shutdown controller to
graceful serving and drain handling. The drain timer starts after shutdown, and the
flush hook runs after a clean or forced outcome.

`apply_server_hygiene` installs DefaultBodyLimit first, then timeout, then
HandleError(LoadShed(GlobalConcurrencyLimit(router))) as the outer stack. Load
shedding returns 503 for excess concurrent work; request timeout returns 408. Other
errors in the fallible load-shed stack map to 500. DefaultBodyLimit constrains
compatible extractors instead of every arbitrary body-consuming handler. Connection
permits live with the wrapped I/O object.

## Trust and invariants

Default limits are 20-second request timeout, 1,024 concurrent requests, 2,048
connections, and 25-second drain. Global body cap defaults to absent; Axum
DefaultBodyLimit governs compatible extractors. Forced drain drops the serve future
while detached handlers may continue, so flush must tolerate concurrent writers.
Transport config validation is explicit; default prepared transport can bind
plaintext directly.

`apply_server_hygiene` installs configured timeout and concurrency layers.
`MaxConnListener` holds a permit for each connection lifetime. `run_until_drained`
bounds post-signal waiting and propagates serve/flush errors.

SIGTERM handling is Unix-specific; Ctrl-C handling is available across platforms.
Signal-install failures log and leave the affected branch pending. TLS handshakes
have a five-second deadline and never downgrade to plaintext.

`run_until_drained` serves without a drain timer until shutdown arrives. A clean
completion yields Clean; a post-signal deadline yields Forced and drops the owned
serve future before flushing. Serve I/O errors return immediately. After either
successful outcome the flush hook can still fail with ServeError::Flush. Forced
drain cannot join detached connection handlers, so acknowledged-write durability
must be established in the handler and flush must permit concurrent writers.

## Dependencies

Axum supplies Router and Listener traits. Tower supplies load shedding and
concurrency control; tower-http supplies timeouts. Tokio supplies signals, channels,
sockets, and timers. Rustls with AWS-LC and tokio-rustls supply server TLS.

## Verification

`src/tests.rs` covers timeout, overload, body extraction, connection permits, manual
shutdown, and drain outcomes. `src/transport_tests.rs` covers TLS identity,
handshake behavior, and transport configuration.

Run focused library tests from the workspace root:

```bash
cargo test -p chio-http-serve
```

`load_shed_returns_503_over_concurrency_limit` checks the layer ordering.
`drain_deadline_forces_close_and_still_flushes` checks forced-drain cleanup.
`flush_error_surfaces_as_serve_error` checks post-drain error propagation.
`slow_request_times_out_cleanly_inside_the_drain_window` checks compatible
timeout/drain defaults. TLS fixtures test malformed identities and handshakes.
