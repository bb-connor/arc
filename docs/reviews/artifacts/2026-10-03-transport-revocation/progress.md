# Transport and revocation execution

Base: aaa413406d63cc109f6aeda14de4e517a6d574a6 (published and verified).

Executing AP7/AP8 inline under existing authorization. One integrated independent review after implementation.

Pre-flight: Task 1 exposes a prepared profile consumed by Task 2; private file custody stays in control-plane to avoid a dependency cycle. Task 3 shares Task 2 control client validation. All are applied before final qualification.
Task 1: shared-transport-red failed because new API/dependencies were absent. shared-transport-green passed 16 tests including real TLS, private-key shape, timeout, cap and socket identity.
Task 2: control-transport-red reproduced both unsafe non-loopback endpoint acceptance and cross-authority redirects. Three service compositions and CLI flags now wired. Production startup and TLS controls are awaiting the integrated owner run.
Task 3: first two attempts caught fixture import and ephemeral-policy setup mistakes. revocation-red-ephemeral-fixture reproduced HTTP 200/top-level true with one unrevoked capability for both remote and SQLite write failures. Replacement executes one backend batch on a blocking worker, preserves failures, checks write identity and readback identity, returns 503 for partial progress.
Ruling: use HTTP/1.1 ALPN only because this shared server profile does not enable HTTP/2. Cost if wrong: an HTTP/2-only client needs a separately qualified profile.
Ruling: API listener addresses are numeric SocketAddr values, matching the other services and preventing DNS from changing a loopback decision. Cost if wrong: embedders using hostname bind strings must use an explicit IP.
Ruling: the chio start alias receives the same flags and correct printed scheme because it starts API-protect too. Cost if wrong: one additional CLI parsing surface; parser and all-target compile cover it.
Ruling: preserve all negative runs and test fixture repairs. One final source snapshot and terminal checks determine qualification; earlier failures remain failures.

Final review: one fresh GPT-6 Astra review returned With fixes, two Important findings and no Critical/Minor findings. Both accepted. Ownership and diagnostic regressions are retained in docs/reviews/artifacts/2026-10-03-transport-revocation.
Final fix pass: private PEM iterator replaced with fixed zeroizing scratch, immediately guarded DER and direct AWS-LC wiping handoff. Marker-in-debug regression failed, then passed with the full shared 19-test suite. Production wrapper regression is included for final qualification. No re-review requested.
Ruling: preserve tokio-rustls0.26.4 from the preexisting lock. Initial draft's0.26.5 assumption accidentally selected0.26.6; restore base version and requalify, avoiding an unrelated dependency upgrade.
Ruling: private PEM errors contain typed syntax categories and no native input-bearing parser fields. Native TLS/provider failures remain typed; retaining malformed private lines would defeat custody. Cost: less detailed PEM syntax diagnostics, deliberately preferred to secret disclosure.
Ruling: accept one unencrypted PKCS8/PKCS1/SEC1 PEM block with whitespace/CRLF, rejecting extra records and trailing text before DER creation. Cost: operators must export a plain PEM key without ancillary records.
Final: no minor deferrals. Declined review boundaries and costs are retained in independent-review.md: hosted/platform/release; FIPS/mTLS/automation/deployed proxy; preexisting background tasks and earlier authority work; cluster convergence/inflight cancellation; root-owned terminal checks.

Integration correction: final-http-owner caught a preexisting shutdown-test scheduling race: its20ms sleep did not establish request admission before triggering shutdown, yielding ConnectionReset. Replace the sleep with handler-entry Notify, preserving the required408 and Clean-drain assertions. This is fixture synchronization, with the failed campaign retained. Final CLI parser's first filter matched zero tests; it is not acceptance. Correct module filter executed20 passing tests.

Native binary startup controls passed for trust serve, MCP serve-http, API-protect and chio start: every unsafe public plaintext start exits before creating receipt state. The negative-assertion ratchet initially identified5 weak new assertions. They now assert custody rule/typed redirect-reader rejection, without changing the1254-entry baseline. Final ratchet passes.

Final runtime qualification: API-protect245, remote MCP129, shared HTTP19, focused control-plane transport/client27 and CLI parsing20 pass. The repaired HTTP fixture and strengthened control-plane assertions were rebuilt and rerun. Native startup controls4 pass. Five owner test targets and the native CLI compile with --locked. No full control-plane/CLI/workspace runtime pass is claimed.
Final contract gates pass:476 constructors,85 tenant tables,170 SQL contracts;426 clock observations and38 compositions with no additions;1254 unchanged weak-assertion baseline; no raised Rust hygiene caps. Final formatting passes.

Final strict workspace/all-target Clippy passes with --locked and -D warnings after the last test changes (fixture-qualified-clippy, exit 0). Formatting also passes (fixture-qualified-format). All local plan qualification steps are complete; source and evidence are ready for the authorized commit/push.
