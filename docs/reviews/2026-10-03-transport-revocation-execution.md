# Transport and revocation execution, October 3, 2026

Published source `ccf902c7f198dcf96d7cbaf74dd2ca528c0de703` on
`packet/3-retention-accounting`; the origin branch matched that SHA after push.
Publication metadata follows in a documentation-only commit. The source is based on
`aaa413406d63cc109f6aeda14de4e517a6d574a6`. That parent completes the AP4-AP6 and
threshold-reader batch. This record owns AP7 and AP8; it does not change the
historical qualification boundaries of earlier batches.

## Implemented boundaries

AP7 gives trust-control, remote MCP and API-protect one rustls server profile.
Both library composition and native CLI validate the listener posture and load
private identity before opening stores, discovering policy/specs or launching
upstreams. Non-loopback plaintext requires explicit `--allow-plaintext`; paired
`--tls-cert` and `--tls-key` enable TLS. The `chio start` alias shares the flags.
Private files use existing bounded, no-follow, owner-only custody. The PEM parser
uses fixed zeroizing scratch and guarded DER, and emits payload-free typed errors.
The explicit AWS-LC provider validates matching certificate/key material.

Each connection's timed handshake lives inside its connection permit. Slow TLS
clients cannot serialize the accept loop; real socket peers survive the wrapper.
The profile advertises HTTP/1.1 and preserves the existing bounded drain path.
Implicit MCP resource URLs use HTTPS under TLS. Control clients accept HTTPS or
literal loopback HTTP, canonicalize URLs, redact invalid endpoint context, and
refuse every HTTP redirect. Existing explicit cluster leader selection remains.

AP8 opens one backend per session-revocation batch on a blocking worker. Every
capability needs a successful write and an identity-bound, positive readback.
Partial progress returns 503 with per-capability status and a safe failure phase;
unknown state is null. Backend initialization also fails non-2xx. Already-revoked
records and retry after partial success are idempotent. Typed local failures are
retained in response extensions; backend details do not enter the JSON response.

The [operator guide](../security/http-transport.md) documents migration and flags.

## Verification and review

Terminal commands, logs and source/binary identities are retained in
[the command index](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-transport-revocation/README.md).
The final runtime results are:

| Boundary | Passing controls | Retained command |
| --- | ---: | --- |
| API-protect complete library suite | 245 | `final-api-owner` |
| Remote MCP complete library suite | 129 | `final-mcp-owner` |
| Shared HTTP complete library suite | 19 | `fixture-qualified-http` |
| Control-plane transport and client tests | 27 | `fixture-qualified-control` |
| CLI parsing module | 20 | `final-cli-parsing-qualified` |
| Native CLI startup rejection | 4 | `native-cli-startup` |

These are owner/scoped runs, not a full workspace runtime campaign. The
control-plane and CLI counts cover the named filters only. The five changed
owners' library/binary tests compile with `--locked`; the native CLI also builds.
The API, MCP and CLI runtime passes precede only a test synchronization repair
and stronger control-plane assertions. The affected HTTP/control-plane suites
were rebuilt and rerun after those test-only changes.

The initial controls reproduced unsafe public HTTP control endpoints, followed
redirects, and false HTTP 200 revocation success under both remote 500 and actual
SQLite trigger-induced write failure. Fixture/compile failures remain retained.
`final-http-owner` failed one existing shutdown test because a fixed sleep did
not establish request admission before shutdown. A handler-entry signal now
synchronizes that test while preserving its 408 and clean-drain assertions; the
subsequent full 19-test run passes. `final-cli-parser` matched zero tests and is
not acceptance; the corrected module filter executed 20. The first lint run and
the negative-assertion gate also failed before repair and retain those exits.

The trust-boundary, security-clock, negative-assertion and Rust file-hygiene
gates pass without new debt entries, lint allowances or raised size caps. The
inventories remain 476 constructors, 85 tenant tables, 170 SQL principal
contracts, 426 clock observations and 38 pinned clock compositions. Five weak
new assertions were strengthened rather than added to the 1,254-entry baseline.
Strict `cargo clippy --workspace --all-targets --locked --keep-going -- -D warnings`
and `cargo fmt --all -- --check` pass after the final test changes
(`fixture-qualified-clippy`, `fixture-qualified-format`).

One independent integrated review returned **With fixes**, with two Important
findings and no Critical or Minor findings: private PEM parsing left secret
copies unwiped and native errors retained private input for debug/source output.
Both were accepted and repaired in one pass. A diagnostic regression failed on
private marker byte arrays before the change and passed afterward. The
[private-key ownership audit](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-transport-revocation/private-key-ownership.md)
accounts for successful and failing scratch/DER paths; it does not claim a
post-free memory probe or a native crypto-library audit. The
[review and dispositions](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-transport-revocation/independent-review.md)
retain the original verdict and declined boundaries. There was no second review.

## Decisions and limits

API bind addresses are numeric socket addresses; hostname bind callers must
migrate. HTTP/2-only clients need a separately qualified profile. Private PEM is
one unencrypted PKCS8, PKCS1 or SEC1 block; ancillary records and trailing text
must be removed. PEM diagnostic detail is intentionally reduced so secret input
cannot survive in error objects. The existing locked tokio-rustls 0.26.4 is
preserved; an incidental early resolver upgrade was reversed before final checks.

This is local Linux source qualification. Hosted CI, deployment, release,
non-Linux private custody and upstream audit acceptance are separate. FIPS,
direct client-certificate authentication and certificate automation are not
provided. AP6 proxy sanitation/authentication is still required for header-based
identity. TLS drain tests do not qualify every preexisting background task.
Revocation confirms the selected backend, without claiming cluster convergence
or cancellation of already-running operations. Earlier bearer compatibility,
volatile proof replay and unsupported proof projections keep their earlier limits.

## Next substantial batch

AP9 and AP10 remain confirmed in the source: API-protect uses `INSERT OR REPLACE`
for HTTP/tool receipt rows and labels operator submissions as mediated decisions.
Move durable receipts and mediated kernel events into the append-only evidence
log; require stable private signing custody; distinguish operator observations
from mediated authorization; include both in truthful exports; wire retention to
archive-aware reads using the earlier SR1/SR6 repairs. Other key/guard findings,
remaining reader semantics and hosted/release gates stay in the roadmap afterward.
