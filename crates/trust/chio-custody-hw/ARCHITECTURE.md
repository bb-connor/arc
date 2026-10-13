# Architecture

## Responsibility and boundary

The crate owns `PasskeyCapability`, a WebAuthn relying-party wrapper,
`IssuerService`, replay and revocation interfaces, mobile verifiers, and
server-owned mobile challenge state. Capability signing uses an injected
core signing backend; physical key protection depends on that backend.

`VerifiedAssertion` is publicly constructible. `mint_capability` trusts that
its caller obtained this evidence through the correct authentication ceremony.
The issuer also accepts requested scopes directly; caller policy must choose
and authorize that scope set before issuance.

## Structure

| Module | Responsibility |
| --- | --- |
| `capability`, `mint` | Sorted scopes, canonical envelope, detached hex signature |
| `verifier` | WebAuthn assertion and ceremony replay verification |
| `issuer`, `rate_limit` | Audience/UV gates, optional stores, signing pipeline |
| `nonce_store` | Bounded replay keys, retention, explicit garbage collection |
| `revocation` | Dependency cascade and sparse-Merkle revocation state |
| `attestation` | Apple root, App Attest, Play Integrity, receipt envelopes |
| `mobile_challenge` | Challenge issuance, verified consumption, counter storage |
| `error` | Custody rejection variants and stable error URNs |

SQLite implementations are gated by `sqlite-store`. The passkey wrapper is
gated by `passkey`; mobile verifier APIs remain available without that feature.

## Data and control flow

The passkey verifier finishes authentication against configured RP id/origin
and server-issued state, then records the credential/challenge pair.
Its default replay store is in memory. Applications persist ceremony state
and choose a shared durable verifier replay store when required.

Issuer minting checks audience and user verification, validates credential
and nonce transport strings, then applies rate limit, configured revocation,
and configured nonce store. It constructs expiry at caller time plus 300
seconds, records replay state before signing, and fills the hex signature.
A signing failure can leave that nonce consumed; no transaction spans signing.

`with_signer` attaches the default rate limiter, with no revocation or nonce
store. Feature availability does not attach these gates.
`with_durable_stores` opens sibling SQLite stores and returns the same
revocation instance read by the issuer. Separate instances have separate
caches. `enforce_revocation_replay` checks that both gate handles exist.

Mobile challenges bind random nonce, application/platform, audience, and
expiry. Verification loads active state, verifies platform evidence, then
consumes it with the prior snapshot. App Attest counters advance with consume.

## Trust and invariants

`sign_capability` clears `signature`, canonicalizes the envelope, invokes the
backend, and writes its hex encoding. Parsing bounds capability JSON to 64 KiB
and requires canonical typed bytes. `require_live` checks only `now < exp`;
full signature, issuer, audience, scope, issuance-time, and revocation admission
remain consumer checks.

Revocation stages a dependency closure before committing cache/state changes.
Nonce stores reject any retained duplicate until explicit expiration cleanup.
Default skew is 30 seconds. Stores have capacity bounds and return errors on
unavailable state rather than admitting a replay.

App Attest verifies certificate signatures to the pinned Apple root, nonce,
app hash, credential key/id, environment AAGUID, and optional prior counter.
The raw API's `production` flag is a caller choice. The challenge authority
sets it true and disables compact fixtures. Play Integrity enforces ES256,
issuer/audience/expiry, nonce, package, and integrity claims. Its production
key-selection guard currently rejects the committed synthetic pin.

## Dependencies

WebAuthn supplies passkey cryptography; X.509 parsing verifies Apple chains.
JWT/COSE decode mobile evidence; core types provide signing and strict input.
`chio-revocation-oracle` supplies the Merkle substrate. Rusqlite and custody
file identity helpers support feature-gated durable state.

## Verification

Run `cargo test -p chio-custody-hw` and
`cargo test -p chio-custody-hw --no-default-features`.
Tests cover signed minting, replay, audience confusion, cascade atomicity,
canonical JSON, and synthetic mobile evidence. The self dev-dependency enables
`dev-fixtures` during tests, so these runs do not exercise a deployed Google
trust anchor. Play Integrity unit tests separately check placeholder refusal.

[README](README.md) | [Protocol](../../../spec/PROTOCOL.md#9-trust-control-contract)
