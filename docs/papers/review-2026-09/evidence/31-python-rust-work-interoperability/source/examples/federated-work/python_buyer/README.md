# Python buyer for checked interorganization work

This is a separately implemented participant for the example's version 3
security-review agreement. It creates its own identity, signs native market
artifacts, sends A2A requests, verifies returned evidence and maintains its own
SQLite journal. Neither the buyer nor its public verifier calls Chio Rust code,
Chio FFI, a Chio SDK, or a verifier subprocess. The provider uses the existing Rust
market, A2A edge, kernel, Finding and SQLite payment implementation.

The implementations share a project author, host and experiment launcher. This
is implementation interoperability under one operator, not independent company
adoption. Payment is explicitly provider-local test credit. The Python buyer
does not add an external escrow or independently observe real funds.

## Run

Python 3.12 on Linux and Bubblewrap are required for the process experiment.
Create a private environment outside the source tree. `requirements.txt` pins
all four packages and their distribution hashes; `requirements.in` records the
two direct dependencies. Signing uses
[cryptography's Ed25519 implementation](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)
and canonicalization uses [rfc8785](https://pypi.org/project/rfc8785/).

```sh
uv venv --python /usr/bin/python3 /tmp/chio-python-buyer-env
uv pip sync --python /tmp/chio-python-buyer-env/bin/python --require-hashes \
  --index-url https://pypi.org/simple \
  examples/federated-work/python_buyer/requirements.txt
CARGO_TARGET_DIR=target cargo build --locked --offline \
  --manifest-path examples/federated-work/Cargo.toml
python3 examples/federated-work/python_smoke.py \
  --python-env /tmp/chio-python-buyer-env
/tmp/chio-python-buyer-env/bin/python -B -m unittest discover \
  -s examples/federated-work/python_buyer -v
```

The launcher gives the Python buyer only its private state, read-only code and
dependencies, and loopback network access. The provider has a different mount
namespace and state directory. A third namespace verifies public artifacts
without either signing seed. The Python mounts contain no Chio executable.
The launcher separately invokes the Rust verifier to cross-check the same public
package; the Python verifier never invokes it.

The supported commands are:

```sh
python client.py init STATE
python client.py buyer STATE http://127.0.0.1:PORT
python client.py work STATE http://127.0.0.1:PORT
python client.py snapshot STATE
python client.py verify-work PEERS_JSON PUBLIC_JSON
```

Provision `peers.json`, `agreement.json`, `session.json` and `input.json` in the
private buyer state before negotiating. The launcher demonstrates this provisioning.
Peer keys come from operator configuration, never the provider's Agent Card or
the package being verified. Provision generated Ed25519 identities, not arbitrary
unvalidated curve encodings. The negotiation capability is a private bearer
credential; the paid work capability requires a fresh signed proof of possession.
Do not export role directories. Public work packages disclose the whole input.

## Supported wire contract

The contract is deliberately bounded. It does not implement all native Chio
artifact variants or every A2A feature. Unknown fields in signed agreement,
market, capability, receipt and Finding profiles reject unless explicitly
allowed by `protocol.py`. JSON objects reject duplicate keys. Integers used by
the agreement and market profile are in the interoperable range through
2^53 - 1. JSON packages are bounded to 1 MiB and disclosed review input to 64 KiB.
Canonical JSON bytes use RFC 8785; hashes use SHA-256 and signatures Ed25519.
Hashes and keys use lowercase hexadecimal; Merkle `Hash` values have `0x`
prefixes, while artifact digests and receipt ids do not.

The literal profile names are:

| Binding | Value |
| --- | --- |
| Agreement | `chio.example.security-review-agreement.v3` |
| Credit | `provider-local-credit-checked-or-zero-v1` |
| Provider server | `security-review-provider` |
| Listing | `security-review-v1` |
| Checker | `openapi-explicit-auth-v1` |
| Price | `{"currency":"TST","units":100}` |

An agreement has exactly `profile`, `creditProfile`, `buyer`, `provider`,
`jobId`, `inputSha256`, `checker`, `subcontracting`, `priceCeiling`, `deadline`.
The peers are configured Ed25519 keys, the job id is 1..128 ASCII letters,
digits, underscores or hyphens, and the input digest binds exact UTF-8 bytes.
Subcontracting must be false. The price ceiling is 100..1,000 test units.
The deadline is Unix seconds. A new bid and acceptance must be live; previously
signed delivery evidence remains verifiable after expiry.

The HTTP adapter first obtains `/.well-known/agent-card.json` without a
credential, then accepts only the configured origin's `/rpc` interface using
`protocolBinding: "JSONRPC"` and `protocolVersion: "1.0"`. Only literal
`http://127.0.0.1:PORT` URLs are supported. It does not follow redirects or use
proxy environment variables. This transport is for local experiments and is
not a deployment transport between companies.

Requests use the A2A 1.0 `SendMessage` method, a fresh correlated JSON-RPC id,
`message.role: "ROLE_USER"`, and one `message.parts[].data` argument object.
`configuration.returnImmediately` is false, output mode is `application/json`,
and `metadata.chio.targetSkillId` names `quote`, `accept`, `status`, `review` or
`delivery`. The Chio metadata field is an application routing extension; it
does not confer authority. Version and completion semantics follow the
[A2A specification](https://a2a-protocol.org/latest/specification/#322-sendmessageconfiguration).
Headers are `A2A-Version: 1.0`, `Content-Type: application/json`, and
`Authorization: Bearer <capability JSON>`.

For `review`, `Chio-Sender-Proof` carries a `{body,signature}` object. Its body
contains `schema: "chio.dpop_proof.v1"`, `capability_id`, `tool_server`,
`tool_name`, `action_hash`, a fresh 32-byte hexadecimal `nonce`, `issued_at`
and the buyer's `agent_key`. The action hash binds the complete argument object.
The buyer signs the canonical body; the native provider verifies the proof and
retains nonce replay protection.

Each completed A2A reply has one task artifact containing one data part.
`task.metadata.chio.receipt` carries the native receipt. The buyer checks its
provider key, tool, capability, exact parameters and signature. Task completion
must agree with a signed Allow decision; the artifact digest must match the
receipt. Failed tasks supply no successful payload to the buyer.

## Agreement, delivery and signing preimages

The `quote` arguments are `{agreement,bid}`. The bid is a signed native
`chio.marketplace.bid-request.v1`. Its requested scope binds server, `review`,
one invocation and `tools:security-review:<agreement digest>`. The provider's
signed ask binds the bid **body** digest, buyer, listing, price, validity window
and offered capability. The capability authorizes exactly one `invoke` of
`review`, requires proof of possession and caps both per-call and total cost
at 100 test units. It has no additional grants or constraints in this profile.

The buyer signs a native reservation receipt under its selected local credit
profile, then a native accepted bid. `accept` and `status` receive
`{quote,ask,reservation,accepted}`. The reservation binds the ask **body** digest
and `hold-<agreement digest>` id. The accepted bid binds bid and ask body
digests, reservation id, price, accepted time and offered token id, subject and
expiry. `protocol.py` specifies the exact field sets and preimages through
`bid_body`, `reservation_body` and `accepted_body`.

The provider's signed acknowledgement binds the agreement digest and the
**whole signed accepted-bid envelope** digest, plus job id and `state: accepted`.
Its `workExecuted: false` and `settled: false` describe acknowledgement of the
agreement, not the current eventual work outcome.

`review` receives `{acceptance,input}`. The checker inventories authentication
declarations for a bounded, inline OpenAPI 3.1.0 document; the example's main
README defines the accepted document subset. The Python buyer independently
recomputes every observation. It does not establish deployed API security.
`delivery` receives the acceptance and returns retained terminal evidence.

| Artifact | Signature preimage and content address |
| --- | --- |
| Bid, ask, reservation, acceptance, acknowledgement, report | `{body,signature,signerKey}` envelope; sign canonical `body` |
| Capability | Flat object; sign canonical object with `signature` omitted |
| Receipt | Remove `id` and `signature` to obtain body; id is its canonical SHA-256; sign canonical `{id,body}` |
| Checkpoint | `{body,signature}`; sign canonical `body` |
| Finding | Flat object; id hashes canonical object with both `finding_id` and `signature` empty; signature covers canonical object with only `signature` empty |

A successful delivery contains `finding`, `report`, `receipt`, `checkpoint`,
`inclusion`. The receipt's content hash commits the canonical reveal envelope
`{media_type:"application/json",payload_b64:BASE64(canonical signed report)}`.
The Finding references that content hash, receipt id and **whole signed
checkpoint** digest. It asserts deterministic replay and observed evidence,
with explicitly `unbacked:` bond and `local-job:` status references. The verifier
accepts no additional assurance claims.

A checked rejection instead contains `schema`, `agreementSha256`,
`acceptedBidSha256`, `receipt`, `checkpoint`, `inclusion`. Its schema is
`chio.example.checked-review-rejection.v1`. The signed decision is Deny with
guard `checked_output` and reason `returned output failed the agreed zero-charge check`.
The content hash is SHA-256 of the literal bytes
`chio.output-guard-rejection.redacted.v1` followed by one NUL byte. There is no
public rejected report or Finding. The signed financial metadata must state
zero charged and a completed hold release. Successful work requires 100 charged.
Both cases require retained terminal admission evidence and the configured
provider's checkpoint inclusion proof.

Merkle leaves hash `0x00 || canonical complete receipt`; internal nodes hash
`0x01 || left hash || right hash`. Trees use RFC 6962's left-balanced shape.
The inclusion path runs from leaf to root; its index, size, receipt sequence,
batch interval, checkpoint sequence and root must agree. This verifier checks
receipt membership in one signed checkpoint, not checkpoint-chain consistency,
public transparency, non-equivocation, honest accounting or collateral.

## Durable local decisions

The Python journal persists the exact quote before requesting an offer. One
transaction reserves 100 local units and stores the exact signed acceptance.
It commits an attempted state before sending `accept`. After an uncertain
send it uses only `status`, retaining the reservation even if the provider
has no acceptance. There is no timeout-based cancellation or automatic resend.

The buyer persists the exact work request and attempted flag before sending
`review`. Later invocations only retrieve `delivery`; they never repeat work.
A crash before the actual send is deliberately indistinguishable from a lost
reply, so it also preserves uncertainty and the reservation.

After verification, one SQLite transaction fixes the terminal, enforces one
receipt across all jobs, and either records one expense or restores one
reservation. Concurrent recovery cannot apply either outcome twice or replace
the first outcome. SQLite uses WAL and synchronous FULL. These experiments
qualify process death and restart, not power loss or hostile storage rollback.
Local account summaries are unsigned journal observations, not evidence of
external payment. The provider's checked-or-zero contract trusts its kernel,
checker and local reversible rail; the buyer's later verification is not an
independent escrow release condition.

The next deployment boundary is a separately operated participant with its own
provisioning, confidential transport and chosen settlement authority, doing a
useful non-fixture job. The current artifacts make that test reviewable; they
do not claim it has occurred.
