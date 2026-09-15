# Separately provisioned HTTPS participants

The Python buyer can also retrieve [verifiable unresolved incidents](INCIDENTS.md)
over this connection. Such a result preserves its reservation and explicitly
reports unsettled credit.

The Rust provider can now serve the checked-work profile over TLS 1.3. The
Python buyer activates a provider-signed enrollment artifact against an
operator-selected provider key and HTTPS origin. Each participant generates and
retains its own signing seed. Enrollment transfers public certificates and a
proof-of-possession-bound capability, without a shared bearer secret.

This is an executable deployment interface, tested on one host. It does not
establish independent operator adoption, a wide-area deployment or external
payment. The profile still supports one configured buyer per provider state,
the bounded OpenAPI declaration check, and provider-local test credit.

## Operator setup

Use persistent private state directories outside the source checkout. Build the
Rust executable and install the Python buyer's hash-pinned environment using
the [participant instructions](python_buyer/README.md). The commands below run
on their respective operators' machines; paths and public identities are
operator-selected configuration.

On the buyer's machine:

```sh
python python_buyer/client.py init "$BUYER_STATE"
```

On the provider's machine:

```sh
chio-federated-work init "$PROVIDER_STATE"
```

Each prints only its public application key. Exchange those public keys through
the organizations' chosen authenticated provisioning channel. The provider
creates `peers.json` in its private state with these public values:

```json
{"buyer":"<buyer public key>","provider":"<provider public key>"}
```

The provider supplies a certificate chain and matching private key for its
chosen HTTPS name, plus the public CA certificates the buyer should trust for
that endpoint. Application identity and TLS identity are separate keys. The
following command uses a fixed listening port, so process recovery keeps the
same origin:

```sh
chio-federated-work serve-https "$PROVIDER_STATE" 0.0.0.0:8443 \
  https://provider.example:8443 server-chain.pem server-key.pem none
```

The listener supports IPv4 or IPv6 socket addresses. The advertised origin must
be canonical HTTPS with the bound port and no credentials, route, query or
fragment. A zero port is supported for local test allocation; it is replaced
with the actual listening port before publication. A non-loopback bind makes
the service reachable subject to the operator's network policy. It is an
explicit operator action, not part of running the local harness.

In another provider terminal, issue the public enrollment packet:

```sh
chio-federated-work enrollment "$PROVIDER_STATE" "$BUYER_PUBLIC_KEY" \
  https://provider.example:8443 ca-certificates.pem > enrollment.json
```

Only parsed certificates are re-encoded into the packet. Private-key PEM blocks
reject, and comments or unrelated file contents are not copied. The artifact
uses the existing Chio signed export envelope and binds:

| Field | Meaning |
| --- | --- |
| `schema` | `chio.example.https-enrollment.v1` |
| `profile` | The version 3 checked-review agreement |
| `buyer`, `provider` | The configured application public keys |
| `origin` | The precise HTTPS endpoint selected for this relationship |
| `caPem` | The public TLS certificates selected for trust |
| `session` | Provider-signed negotiation capability requiring the buyer's key |

Transfer this public artifact to the buyer. The buyer supplies the provider key
and endpoint it selected through its provisioning process, rather than deriving
those expectations from the received artifact:

```sh
python python_buyer/client.py enroll "$BUYER_STATE" "$PROVIDER_PUBLIC_KEY" \
  https://provider.example:8443 enrollment.json
```

Activation verifies both signatures, the buyer's own identity, exact peer and
origin bindings, live credential validity, the supported work profile, the
bounded negotiation scope and TLS trust parsing. It atomically writes a private
`connection.json`. Ordinary work treats that configuration as read-only. The
remote Agent Card cannot activate roots, change the origin or replace a peer.

The buyer supplies `agreement.json` and `input.json` as described in the main
README, then runs:

```sh
python python_buyer/client.py work "$BUYER_STATE" https://provider.example:8443
```

The active connection replaces the legacy `peers.json` and `session.json`
inputs on the buyer. The harness removes those legacy files and completes work
using only the buyer's private identity, activated public enrollment, agreement,
input and own journal. No provider private key is copied to the buyer.

Negotiation credentials last approximately one hour. The provider can issue a
fresh signed enrollment; the buyer explicitly activates it with `enroll`.
Existing state cannot switch application peers. An operator may select a new
origin or certificate set under the same peer keys, while preserving the
agreement journal. Discovery never performs this renewal. Expired credentials
cannot authorize HTTP requests, but retained public evidence can still be
verified offline. Changing hosts also requires preserving the provider's
authoritative stores; a new empty database cannot establish that prior work
did not happen.

## Transport and authority

The server uses the repository's Rustls and Tokio TLS stack. It accepts TLS 1.3
and advertises HTTP/1.1. The HTTP edge listens on a private Unix socket inside
the provider state, with no plaintext TCP backend. The TLS adapter forwards
bytes to that socket after a successful handshake. It bounds concurrent
connections to 32, handshakes to five seconds and connection lifetime to
30 seconds. These are limits for this bounded example, not general long-running
agent-job service limits or an internet-facing availability qualification.

The Python client uses an explicit `PROTOCOL_TLS_CLIENT` context with only the
locally activated roots, certificate and hostname verification, TLS 1.3 minimum,
and no common-name fallback. It does not use proxy environment variables,
follow redirects, downgrade to HTTP or enable environment-driven TLS key logging.
The selected Agent Card interface must still be the active origin's `/rpc`.
The underlying certificate and hostname checks use
[Python's SSL context API](https://docs.python.org/3.12/library/ssl.html#ssl.SSLContext).

Every capability accepted on the HTTPS route must require proof of possession.
The public negotiation token authorizes only `quote`, `accept`, `status` and
`delivery`, with a 256 KiB argument bound. The paid `review` capability is
negotiated separately and remains limited to one call and 100 test units.
For each request the buyer signs the native Chio sender proof over the token,
server, tool, exact argument digest, fresh nonce and timestamp. The kernel checks
the signature against the capability subject before execution. These are Chio
sender proofs, not a claim of OAuth DPoP wire compatibility or mutual TLS.

TLS authenticates the selected transport endpoint; the application signatures
bind the work agreement and evidence. The receiver's local enrollment decision
connects those identities. Neither an unsigned Agent Card nor a token carried
in an invocation can change that local decision.

## Reproduce the qualification

```sh
python3 examples/federated-work/https_smoke.py \
  --python-env /tmp/chio-python-buyer-env --output /tmp/chio-https-run
```

The suite runs all 16 Python-to-Rust work and recovery scenarios over HTTPS,
then an additional transport/enrollment scenario. It checks forged enrollment
bindings, misconfigured trusted roots, certificate hostname mismatch, downgrade
attempts, accidental private-key export, and callers holding only the public
enrollment with absent or incorrect sender proofs. Configuration failures leave
zero reservations, reviews, captures and expenses. Correcting the local
configuration permits one normal job. Public-only Python and Rust verification
still succeeds for the completed work and checked-rejection artifacts.

Certificate fixtures are generated inside the provider's mount namespace and
remain private except for their certificates. The fixture utility is not a
deployment PKI. The launcher still controls both participants and can access
their state. This experiment does not claim separate administrative control,
public traffic, power-loss recovery, hostile storage rollback, public
non-equivocation, real funds transfer or authorization across jurisdictions.
