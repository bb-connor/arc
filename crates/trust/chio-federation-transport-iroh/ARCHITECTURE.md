# chio-federation-transport-iroh architecture

## Responsibility and boundary

This adapter owns transport identity bindings, an endpoint admission hook,
framing, lane handlers, catch-up downloads, and transport telemetry.
`lib.rs` exports `identity`, `admission`, `lanes`, `catchup`, `metrics`, and
`observability`. Long-term trust decisions and tool execution remain with
federation verifiers and embedding runtimes.

Iroh proves possession of an endpoint's transport key during QUIC/TLS.
`VerifiedDirectory` maps that endpoint to a passport identity authorized by
a pinned directory issuer. The passport key and transport key have separate
roles and can rotate independently through a successor directory bundle.

## Structure

| Module | Public surface and responsibility |
| --- | --- |
| `identity` | Directory documents, issuer trust inputs, endorsement preimages, verified indices. |
| `admission` | `DirectoryGate`, current snapshot swaps, and post-handshake rejection. |
| `lanes::pheromone` | Directed batch handler, durable enqueue, and outbox drain over QUIC. |
| `lanes::revocation` | Signed-root push, catch-up RPC, signer directory, and root sink seam. |
| `lanes::fanout` | Treaty topic derivation, gossip subscription, and origin-verified frames. |
| `lanes::bilateral` | `IrohBilateralCoSigner`, address/key seams, and co-sign handler. |
| `lanes::limits` | Timeouts, global/per-peer permits, bounded I/O, and connection teardown. |
| `catchup` | Blob publisher, manifests, bounded downloads, and verified-root history. |
| `metrics`, `observability` | Registered counter names, snapshots, and structured trace targets. |

The direct lane ALPNs are `chio/federation/pheromone-batch/1`,
`chio/federation/revocation-root/1`, and
`chio/federation/bilateral-dsse-cosign/1`. Fan-out uses `iroh_gossip::ALPN`;
content downloads use `iroh_blobs::ALPN`.

## Data and control flow

1. `verify_bundle` checks the v2 directory body and canonical directory digest
   against caller-supplied issuer and rollback pins. Active entries must carry
   domain-separated passport endorsements for their endpoints and oracle keys.
2. The resulting directory derives endpoint, passport, oracle-signer, and
   treaty-party indices together. Tombstones suppress admission and signing
   authority. Removed entries do not need valid endorsements.
3. `DirectoryGate::after_handshake` decides admission before a mounted handler
   runs. Direct handlers resolve the authenticated endpoint again and apply
   their lane checks before handing accepted data to application collaborators.
4. Directed pheromone traffic uses `RelayBatchReceiver` and the SQLite relay
   store. Inbox reservations serialize concurrent delivery of the same batch;
   stored verdicts support redelivery without repeating receiver mutations.
5. Revocation push verifies an entire batch before returning its signed roots.
   The handler passes roots to `RevocationRootSink`; its implementation owns
   monotone installation and persistence in the application's revocation view.
6. Blob catch-up fetches canonical signed-root bytes, validates them, and
   returns a contiguous verified run. `BlobBackedHistory` retains roots in a
   process-local map for subsequent history queries.

## Trust and invariants

The trust inputs include exact issuer/key IDs, public keys, a strictly lower
version floor, expected predecessor digest, and caller time. Those pins are
caller-owned state. `DirectoryGate::swap` publishes an already verified
snapshot through `ArcSwap`; it does not independently compare successor
versions. `authorize` checks endpoint membership and tombstones, without
consulting a clock. The embedding reloader must reject expired snapshots,
preserve rollback state, and install `empty_deny_all` when required.
`RevocationHandler` and `BlobCatchupClient` hold fixed directory `Arc`s;
applications must replace those collaborators when their trust snapshot changes.
A gate swap alone does not update their signer bindings.

Oracle bindings accept Ed25519 root keys and require a separate passport
over-oracle endorsement. `RevocationHandler::verify_batch` checks that each
signer belongs to the authenticated sender endpoint and that the batch names
its responder. Structural `validate_envelope` alone does not verify a root.

`BlobBackedHistory::from_verified` trusts its input contract; it performs no
cryptographic or order checks. Fetch paths verify BLAKE3 addresses and oracle
signatures and cap a requested range at 4,096 epochs. They inspect completed
blob size before reading bytes into memory, with a one-MiB per-blob cap. The
blob download itself has already written into the follower store at that point.

Pheromone frames cap declared lengths at eight MiB before allocation;
bilateral frames cap lengths at four MiB. Revocation reads cap at sixteen MiB.
`AcceptLimiter` bounds stream acceptance, reads, writes, lingering, and global
and per-peer concurrency. Endpoint QUIC stream/window settings remain wiring
responsibilities; the crate exposes recommended values.

Fan-out derives deterministic treaty topics and verifies deposit signatures
against the origin passport key. A forwarding neighbor is not the author.
Subscription checks the local authenticated endpoint's treaty membership;
receive checks the origin membership and swarm/treaty binding. Inbound gossip
joins lack an upstream per-topic authorization callback, leaving passive
observation possible for an admitted non-party. The lane is experimental.

`BilateralCoSignHandler::cosign` checks the request address, endpoint identity,
directory passport binding, matching co-sign allowlist key, and remote
signature before signing the supplied opaque PAE bytes. It does not parse or
admit the invocation represented by those bytes; the application must apply
its operational verifier and co-sign policy separately.

## Dependencies and integration

Iroh provides authenticated QUIC endpoints; `iroh-gossip` provides fan-out,
and `iroh-blobs` provides content-addressed storage and downloads.
`chio-core-types` supplies canonical JSON and cryptography;
`chio-federation` supplies frame and DSSE contracts;
`chio-revocation-oracle` supplies pinned root verification.
`chio-pheromone-relay` supplies receiver and SQLite delivery state.
Tokio, bytes, `n0-future`, `arc-swap`, and tracing support asynchronous I/O,
shared directory snapshots, and telemetry.

The CLI mounts only directed pheromone traffic when Iroh is enabled.
Its serve path runs alongside the HTTP relay; its tick path drains one chosen
transport. The CLI defaults to direct addressing with relays disabled and
accepts explicit relay URLs. Library endpoint configuration remains the
caller's responsibility. Revocation and bilateral selection fails at the CLI
lane parser because that relay process does not supply their collaborators.

## Verification

Run `cargo test -p chio-federation-transport-iroh` from the workspace root.
Identity and admission tests cover signature/hash tampering, expiry, rollback,
endorsement binding, tombstones, and snapshot swaps. Lane tests exercise
loopback QUIC, bounded frames and timeouts, origin pins, recipient mismatches,
co-sign responses, inbox recovery, and catch-up ordering.

`lanes/fanout/tests.rs` covers treaty checks and origin verification, including
relayed delivery. `lanes/limits_loom.rs` contains additional concurrency models
under the custom `chio_iroh_transport_loom` test configuration. Default test
execution does not enable that configuration. The examples in `examples/`
exercise individual lanes; they are separate from the CLI-supported path.
