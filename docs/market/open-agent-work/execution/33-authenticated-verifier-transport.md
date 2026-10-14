# Authenticated verifier transport on original funded identities

The provider can deliver its retained public verification request to the original
enrolled verifier over TLS 1.3. A provider signature binds the entire request,
verifier enrollment digest and selected HTTPS origin. The receiver chooses its
own read-only observer socket and checker, and commits the existing signed
decision in SQLite before responding. Provider import still reobserves the claim
before settlement on the original native operation and hold.

This slice builds on `cc664fae68a736ead4e03838836ef53987539b34` in the isolated
`feat/funded-native-admission` worktree. The [qualification manifest](34-peer-verifier-evidence.json)
records source, executable, check and public artifact hashes. Earlier evidence
remains historical. Qualification is local; it does not establish independent
administration, public RPC finality or public activation.

## Protocol and local selection

`chio.experimental.funded-verifier-call.v1` is a signed envelope with exact body
fields `schema`, `origin`, `enrollmentSha256` and `request`. The request is the
existing public verifier handoff. Enrollment commits the original jointly signed
agreement, funding domain, authority UUID, implementation, provider/verifier keys
and Finding acceptance policy. No capability, observer URL or observation
transcript enters the call. The receiver authenticates against the enrollment in
its existing custody database. It never takes its peer keys from the call.

The first call is retained as `verifier-call` in the original funding journal
before publication. Its origin and canonical bytes cannot change on retry. A new
call cannot be created after a decision has been chosen. Completed exact retries
preserve historical custody, including after a decision. An origin migration is
not an implicit retry; it requires a future explicit migration procedure.

The sender's locally selected endpoint has schema
`chio.experimental.funded-verifier-endpoint.v1` and fields `origin`, `address`
(an explicit IP socket address) and `caPem`. These files and the public verifier
enrollment are operator-selected trust inputs. Do not bootstrap them from an
untrusted incoming request. The address port must match the HTTPS origin. The
Rust client uses only those CA certificates, verifies the origin hostname,
connects only to the selected address, and performs no DNS resolution, redirects,
proxy discovery or system-root fallback. Explicit loopback addresses support the
local reproduction. Deployment must select appropriate addresses and ingress
rules under its own administrative policy.

```sh
target/debug/chio-federated-work experimental-verifier-call PROVIDER REQUEST_ID PROVIDER_OBSERVER.sock https://verifier.example:8443 CALL.json
target/debug/chio-federated-work experimental-verifier-serve VERIFIER VERIFIER_OBSERVER.sock 0.0.0.0:8443 https://verifier.example:8443 CERT.pem KEY.pem
target/debug/chio-federated-work experimental-verifier-send ENDPOINT.json VERIFIER_ENROLLMENT.json CALL.json DECISION.json
target/debug/chio-federated-work experimental-verifier-import PROVIDER REQUEST_ID PROVIDER_OBSERVER.sock DECISION.json
```

Initialize verifier custody through the existing `experimental-verifier-init`
command first. Serving never initializes missing custody. Service readiness prints
only the bound HTTPS origin. The TLS certificate and private key are separately
provisioned; the qualification fixture generates a short-lived CA and a proper
server leaf, and never writes the CA private key. Restarting the same service
requires TLS key material even when a cached decision no longer needs its
Ed25519 signing seed.

## Transport and receiver boundaries

The only supported route is `POST /v1/funded-work/verify`. TLS 1.3 terminates into
the existing private Unix HTTP backend. The verifier path limits raw headers to
8 KiB and body to 256 KiB before the general HTTP parser receives plaintext. It
requires one canonical content length and `Connection: close`, rejects transfer
encoding, content encoding, `Expect`, ambiguous framing,
and forwards at most one complete request per TLS connection. Role/schema/content
validation then uses bounded raw-first canonical typed JSON. Unknown fields,
duplicate JSON keys, trailing bytes and substituted signatures fail closed.

The listener retains its existing 32 connection permits, five-second handshake
limit and 30-second request/response transport limit. The client uses one absolute
30-second deadline, with at most five seconds for its pinned connect. A dropped
connection can leave an already admitted verification running; it cannot cancel
or replace durable custody. These are transport limits, not a sustained
multi-tenant availability or denial-of-service qualification.

An OS file lock prevents two live services from replacing the same private HTTP
backend socket. Process death releases the lock. Application decisions remain
serialized by the existing SQLite immediate transaction and immutable custody.
The server's observer wrapper implements observation only: transaction preparation
and broadcast use denying defaults, even if the configured socket is broader.
Neither call data nor a TLS certificate can select the receiver's observation
source. Invalid transport calls return a bounded generic error without exposing
private state. Unavailable observation/checking produces no financial decision.

The receiver uses the existing verifier path: reconstruct original public native
authority, observe the prepared claim, run the pinned Python checker, reobserve
before signing, validate current context/window, and commit first-response
custody. Exact replay authenticates the provider call again and verifies original
historical custody without the verifier seed, observer or checker. The client
verifies the returned decision signature, original Finding/native bindings and
claim transaction before exclusive file publication. A valid TLS endpoint cannot
forge a decision. Historical transport replay does not refresh authority or
replace the provider's fresh observation required by import.

## Qualification and remaining work

The owned-chain peer lifecycle runs real Rust service/client processes for correct
and rejected output, including service SIGKILL after decision commit and response
loss. It checks canonical/signature/origin/enrollment rejection, raw HTTP bounds,
TLS trust and hostname failures, plaintext downgrade, unavailable observation and
checker, exclusive listener ownership, immutable output publication, forged TLS
responses and redirects. Final payout/refund must retain one execution, original
operation/hold/authorization/allocation and one terminal financial event. The
public Python checker independently verifies the resulting execution witness.

The [evidence directory](peer-verifier-evidence/) retains final command logs and
public artifacts. The [inline review](peer-verifier-evidence/review.md) records the
integration findings and validation scope. No role seeds, TLS private keys,
private native requests or journals are published as qualification artifacts.

This peer reproduction uses the earlier authority lifecycle fixture and separate
local processes on one trusted host. It is distinct from the retained five-domain
namespace lifecycle, which is rerun as a regression and keeps its network
isolation unchanged. This slice does not claim that the HTTPS service/client have
been composed into that namespace topology. Both use an owned mock chain and one
trusted chain fixture; the verifier socket is separately selected and read-only,
but the observers are not independently administered.

Next: compose the peer transport into the isolated role topology with explicitly
controlled ingress/egress, then run provider and verifier observers under separate
administration against a selected shared chain. Qualify observer disagreement,
stale/reorganized receipts, outages and recovery on the original identities.
A2A profile negotiation, public-chain finality, multi-allocation service routing,
external revocation/rollback anchors and public deployment remain separate gates.
