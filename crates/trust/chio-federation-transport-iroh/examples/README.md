# Runnable examples: chio-federation-transport-iroh

Most examples are self-contained, deterministic demos that stand up two (or three)
in-process iroh endpoints over loopback (`RelayMode::Disabled`, `127.0.0.1:0`,
fixed seeds) and drive ONE lane end-to-end with the crate's real APIs. Each is
also a living doc and a smoke test: it prints the flow, asserts the fail-closed
invariant, and exits non-zero if the invariant is violated.

`federated_call_pair` is the exception and is documented separately below: it is
a multi-process experiment with generated keys and flag-supplied addresses, not a
single deterministic run.

Run one with (the `-p` flag is required; a bare `cargo build` pulls the whole
workspace):

```bash
cargo run -p chio-federation-transport-iroh --example <name>
```

| Example | Lane | Demonstrates |
| --- | --- | --- |
| `admission_gate` | accept-time gate (all lanes) | An admitted `EndpointId` completes a request/response; an unadmitted one is `Reject(403)` at `after_handshake`, before any handler runs. |
| `pheromone_exchange` | a: directed batches | Operator A delivers a `PheromoneGossipBatch`; B resolves the authenticated sender via the gate and feeds that `kernel_id` into the real per-frame verifier, which accepts. An unadmitted sender is rejected at the gate. |
| `revocation_catchup` | e: content-addressed catch-up | An authority publishes signed epoch roots over iroh-blobs; a follower fetches and verifies against a PINNED signer key. A forged root (same `signer_id`, different key) is rejected `BadSignature`: BLAKE3 integrity is not authenticity. |
| `bilateral_cosign` | d: bidi DSSE co-sign | Org B requests; Org A verifies `org_b_signature` over `pae_bytes` and binds the authenticated `EndpointId` to the claimed `org_b_kernel_id`, then co-signs the exact bytes. An Org B claiming a different kernel id is refused without a signature. |
| `federated_call_pair` | d + b, plus an experiment-only request lane | Two separately administered kernels as two OS processes: a cross-organization tool call admitted or denied by the receiving kernel, both co-sign hops and the revocation clock over the network. See below. |
| `fanout_gossip` | c: cross-operator fan-out | Three admitted nodes join a per-treaty gossip topic (A -> B -> C). A self-signed deposit broadcast by A reaches C RELAYED through B, and is origin-verified from the payload alone. A tampered frame from the admitted relay B is rejected: `delivered_from` never launders a frame. |

## Notes

- These mirror the crate's own tests and the validated iroh PoCs (signed
  directory verify -> admission gate -> lane handler + client path).
- `revocation_catchup` uses the iroh-blobs catch-up substrate (ADAPTER-SPEC lane e)
  rather than the direct revocation-lane QUIC push: the direct
  `RevocationHandler::accept` returns without awaiting `conn.closed()`, so on
  loopback the reply frame truncates before the dialer reads it. Both paths share
  the same pinned-signer authenticity check.
- `pheromone_exchange` uses a small in-example acceptor (mirroring the crate's own
  `CannedReportHandler` test double) because the real `PheromoneBatchHandler`
  requires a `RelayBatchReceiver` whose report type lives in `chio-pheromone-runtime`,
  which is not a dependency here. The gate, the wire client, and the per-frame
  verifier it drives are all the real crate APIs.

## `federated_call_pair`

Two organizations, two OS processes, one host or two. Org A (`origin`) holds only
Org A's keys and runs the two co-sign handlers plus the revocation epoch ticker.
Org B (`receiver`) holds only Org B's keys and runs a `ChioKernel` behind the
runtime admission hook with its own SQLite receipt and revocation stores. A third
party signs the transport directory that binds them. `send` is Org A's agent-side
driver; it authors every byte of the request and holds no kernel.

```bash
cargo run --release -p chio-federation-transport-iroh --example federated_call_pair -- \
  keygen --kernel-id did:chio:org-a --dir /tmp/org-a
```

`docs/papers/programmable-sovereignty/bench/run-federated-pair.sh` drives the
whole sequence (keys, directory, both processes, the admitted and denied
scenarios, the revoke measurement, and the cut measurement) and writes the
results the paper cites.

Generalizing to two hosts is a change of flags: `--bind HOST:PORT` and
`--peer KERNEL_ID=HOST:PORT` on both sides. Relays are disabled, so both hosts
need direct UDP reachability at the addresses they advertise. The script does
that split through `CHIO_FED_ROLES`: it is run once per machine with disjoint
roles and a `CHIO_FED_STATE_DIR` both machines can read, and it records the host
count from the roles it actually started, refusing to start a role whose address
is not this machine's. A run that starts every role records one host whatever the
address flags say.

### Who holds which key

This experiment collapses three trust roles into the directory issuer: it signs
the transport directory, it holds the capability-issuing authority key, and it
holds the runtime-policy verifier key whose signatures the receiver's admission
hook requires. Both organizations hold only their own transport and passport
keys, and Org A additionally holds its revocation-oracle key. A deployment would
separate the three issuer roles; keeping them together here is what lets one
`directory` subcommand stand up the whole trust fabric.

### What crosses the network, and what does not

Over the lanes that ship today:

- the receiver's kernel asks Org A to co-sign the canonical `CoSigningBody` of
  the receipt it just signed (lane d, receipt profile);
- the receiver's kernel asks Org A for the DSSE PAE signature (lane d, DSSE
  profile);
- Org A publishes a signed epoch root to the receiver every tick (lane b), and
  the receiver installs it through `RevocationViewSink`.

Over an experiment-only lane, because no shipped Chio lane carries one:

- the `ToolCallRequest` itself, and the receiver's verdict.

The experiment lane holds no trust of its own, and it is bound the same way the
shipped lanes are: the handler re-resolves the authenticated `EndpointId`
through the verified directory and requires the resolved kernel id to be the
party the treaty names for that frame (the sender for a call, a preparation or a
stats read; Org A for a revoked-subject announcement), and a call must declare
Org A as its federated origin before the kernel spends an admission on it. Every
peer-dependent await on both halves of the lane is bounded, and the handler holds
one in-flight permit per peer, so a stalled or noisy peer fails closed rather
than pinning a task. What the request BODY claims is still only a claim: the
receiver believes it only against its own store and Org A's live co-signature.

Two limits to state plainly rather than paper over.

**The revocation lane carries a root, not a leaf set.** `SignedEpochRoot` carries
an epoch, a root hash, a leaf count, and an issue time; it does not carry the
revoked subjects, and adding them would change a wire type every existing
consumer depends on. `RevocationViewSink` therefore bridges the root and its
freshness faithfully: that alone is enough for the cut measurement, because the
receiver's kernel denies every delegated call once the installed snapshot ages
past its freshness window. To name a revoked capability the example adds a
separate origin-signed announcement on the experiment lane, gated on the epoch
that carries it. That announcement is experiment-only; a deployment would pull
inclusion proofs against the signed root instead.

**The consuming kernel reads its clock in whole seconds.** `consult_revocation_view`
compares the installed snapshot against a whole-second clock while its staleness
bound is 500 ms, so the only snapshot that satisfies it for a full second is one
stamped at that second's boundary. Org A therefore stamps each root at the second
it publishes in and aligns its ticker so a root lands immediately after every
boundary. A short prefix of each second is still covered only by the previous
second's root, which the kernel reads as stale; the driver classifies those
denials separately, counts them, and never measures them.

**Org A signs bytes it does not parse.** Both co-sign profiles hand Org A opaque
bytes with Org B's signature over them, which is the shipped lane's contract. The
receiver assembles the per-call treaty evidence and asks Org A for the second
signature; a co-signature is therefore evidence that Org A was reachable, held
its key, and agreed to sign for this peer, not that Org A evaluated the call.
This is the same assumption the negative corpus records as PS-A-01.

### What the negative corpus reaches over the wire

Seven denial cases are driven end to end by a remote sender mutating the request
it authors: `chio_treaty_scope_hash_mismatch`, `chio_treaty_missing_scope`,
`chio_treaty_missing_intersection`, `chio_treaty_intersection_mismatch`,
`chio_treaty_missing_required_evidence`, `request_smuggled_trust_root` and
`request_smuggled_dynamic_trust`. Each asserts the same fail-closed property: the
receiver's tool-server dispatch counter does not move.

The rest of the corpus is not reachable this way, and the reason is structural
rather than an omission. The `chio-federation` verifier cases are offline
envelope checks on the buyer side and never cross a transport at all. Of the
remaining receiver-hook codes, `chio_treaty_stale` depends on the receiver's own
clock rather than on anything a sender can write, `chio_treaty_policy_denied`
turns on the verifier-signed policy inputs the receiver holds, and
`chio_treaty_continuation_replay` is answered idempotently because the receiver
mints each call's continuation itself.

### What the driver discards, and what it records

A call the receiver denies because its revocation snapshot fell outside the
kernel's freshness window is the clock, not the treaty. The driver classifies
those denials, retries them, and never lets them into a latency distribution;
every summary it writes carries the count it absorbed, and the benchmark script
carries those counts into the retained artifact, so a reader can see how many
observations the distributions exclude.

The per-call co-sign hop count is measured rather than asserted: the receiver
reports the connections its co-signer opened to Org A when a call's preparation
began and again once it had decided, and a run whose calls did not all cost the
same number fails closed instead of averaging them. An admitted call costs three
connections and a denied one costs a single connection, which pins the
decomposition: one hop mints the preparation's DSSE signature, and the admission
decision itself makes the kernel's receipt co-sign hop and its DSSE hop.
