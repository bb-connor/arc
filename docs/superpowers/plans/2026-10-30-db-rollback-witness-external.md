# DB Rollback Witness Tier 2 Implementation Plan: External Monotonic Witness

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A runtime source database that was restored together with its local rollback anchor (a whole-host restore or a shared-volume snapshot) refuses to open. Each runtime authority head is published to an independent witness that the runtime operator cannot roll back. Before the runtime source opens, and before any authority write is acknowledged, a fresh read from that witness must show a head at or below the database head and on the database's own chain.

**Recommendation:** Option A, a quorum of trust-control cluster peers that keep a durable per-source witnessed head. Option B (checkpoint transparency) is kept as an audit export and does not gate open. The comparison is in "Options" below.

**Depends on (Tier 1, design `lead2/db-rollback-witness-design.md`, arc-63 rulings F1 to F5):**
- #1944: `chio-rollback-anchor` crate with the shared two-slot codec.
- The head-digest PR stacked on #1944: `GenerationRecord` carries the head digest, the 512-byte `CHIOG1OK` layout is redefined in place, and an old-layout slot refuses as `Corrupt`.
- Tier 1 GREEN: the `runtime_authority_commits` chain in the runtime source database (genesis bound to the qualification digest), the local runtime rollback anchor, the typed `RollbackAnchorError`, and the explicit `witness_root: Option<&Path>` on every `open` caller.

Tier 2 adds no second chain. It publishes the Tier 1 chain head (`authority_seq`, `authority_digest`) to the external witness and reads it back.

## Threat model

**Adversary:** the runtime operator, or anyone with write access to the runtime host's storage. They can:
- restore any earlier image of the host, including the runtime source database, its WAL, the Tier 1 witness root and the runtime's local configuration, all at once;
- stop and start the runtime at will, and delay or drop its network traffic.

They cannot:
- sign with the runtime authority key without the runtime (or with it, but only for heads the runtime would itself publish);
- write to a quorum of the witness peers' storage, or sign with their node keys.

**Effects to prevent** (the same as Tier 1, now under a whole-host restore):
- `runtime_trust_floors` moves back, so a downgraded trust bundle or a revoked checkpoint is accepted again;
- a consumed `runtime_admission_bundles` id is admitted twice;
- a revoked or superseded treaty epoch becomes current again.

**Covered:**
- whole-host, VM snapshot and shared-volume restores that roll back the database and the Tier 1 anchor together;
- a restored image driven forward along a different history to a higher sequence (a fork);
- a restore of a minority of witness peers (fewer than the quorum). Restored peers catch up from the runtime chain;
- a minority of peers that answer with a fabricated or stale head. A head counts only if the runtime signed it.

**Not covered** (these limits must appear in public copy):
- the same principal controlling a quorum of witness peers. Chio records the operator split in signed configuration, but cannot verify custody;
- compromise of the runtime authority key without the runtime host. Recovery is an operator re-pin on the peers;
- a runtime that never configures Tier 2 (process host without a cluster). It keeps the Tier 1 claim: "refuses a restored runtime DB image".

**Liveness:** with Tier 2 configured, the runtime source does not open, and authority writes are not acknowledged, while fewer than a quorum of peers answer. This is fail-closed by design. The open path has no offline override.

## Options

### Option A: cluster peer witness (recommended)

Each witness peer is a trust-control node. It keeps one row per runtime source in a new SQLite store, built like `SqliteClusterPeerReplayStore` from #1911 (one STRICT table, rows validated on open, a bounded row count, an IMMEDIATE transaction per advance, no in-memory or `file:` paths). The row holds the witnessed head:
- `source_id`, `runtime_authority_key`, `qualification_digest`;
- `authority_seq`, `authority_digest`;
- the signed advance record.

**Advance rule:** the runtime sends the commit entries since the last witnessed head: `(seq, kind, payload_digest)` per entry, signed by the runtime authority key. The peer recomputes the chain from its stored digest and accepts only when the new head extends it. A fork cannot be published, even at a higher sequence, because the peer checks the chain itself.

**Read rule:** the runtime sends a fresh 32-byte nonce. The peer returns the nonce and the last advance it stored, embedded byte for byte as the runtime-signed envelope, signed by its pinned node key. The runtime counts a head only if it verifies under its own pinned authority key. A peer therefore cannot invent a head; it can only replay one the runtime really published.

**Catch-up rule:** a peer can fall behind. It may have missed advances while the quorum moved on, or it may have restored its own witness database. When an advance's `fromSeq`/`fromDigest` does not match the peer's stored head, the peer refuses with `runtime_witness_behind` and returns its stored head. If that head is on the runtime's chain, the runtime re-sends the entries from it, in advances of at most 256 entries each, until the peer reaches the current head. A peer with no row starts from genesis. A peer whose stored head is not on the runtime's chain is refused with `runtime_witness_diverged` and is never caught up automatically. The quorum counts only peers that stored the new head. Lagging peers catch up during the same publish, and the acknowledgement does not wait for them.

Why A:
- **Freshness:** a peer read costs one RTT. The runtime can demand a fresh read at every open and verify the nonce.
- **Monotonicity:** the peer has a CAS store, and the #1911 shape already handles restart and corruption refusal.
- **Write path:** a commit can be acknowledged only after a quorum stores it, with RTT-bound latency.
- **Reuse:** cluster peer authentication (PROTOCOL 9.2), node key pinning and peer scopes all exist.

### Option B: checkpoint transparency

Fold each authority head into a kernel checkpoint statement (`chio.checkpoint_statement.v1` RFC 6962 chain) and anchor it through `chio-anchor` (Rekor, OTS, chain lanes).

Why not as the gate:
- **Freshness:** Rekor inclusion takes seconds, and OTS takes hours. An authority write acknowledged before inclusion is not covered, and holding acknowledgements for inclusion puts a public log on the admission path.
- **"Latest head" reads:** a transparency log proves inclusion and consistency, not "this is the newest entry for source S". Finding the newest entry means trusting a search index, or scanning the log from a known point.
- **Offline open:** open would depend on reaching a public service.

Its value is after-the-fact audit. A verifier can check the published heads for a fork or a rollback using `chio.checkpoint_consistency_proof.v1` and `chio.checkpoint_equivocation.v1`. This plan exports Tier 2 advance records into the checkpoint stream as a follow-up row (RUNTIME-WITNESS-TRANSPARENCY-EXPORT). That export does not gate open.

## Protocol and wire changes

New signed artifacts, all signed through the signing wrapper and registered in `spec/schemas/registry.json`, `schema_specs.rs` and the PROTOCOL 4.5 table:

| Artifact | Wrapper schema id | Signer |
|---|---|---|
| Witness advance | `chio.runtime-rollback-witness-advance.v1` | runtime authority key |
| Witness read response | `chio.runtime-rollback-witness-attestation.v1` | witness peer node key |
| Witness key rotation | `chio.runtime-rollback-witness-key-rotation.v1` | previous and next runtime authority keys |

**Advance body:**
- `schema`, `deploymentId`, `sourceId`, `qualificationDigest`;
- `fromSeq`, `fromDigest` (the head the runtime believes is witnessed; genesis for the first advance);
- `entries`: up to 256 of `{ seq, kind, payloadDigest }`;
- `toSeq`, `toDigest`, `issuedAt`.

The peer recomputes `toDigest` from `fromDigest` and the entries using the Tier 1 chain digest function. That function moves into `chio-core-types` so both sides share one definition.

**Attestation body:**
- `schema`, `deploymentId`, `witnessNodeId`, `sourceId`, `qualificationDigest`;
- `advance`: the stored advance envelope, signed by the runtime authority (absent when `state` is `unknown`). Its `toSeq`/`toDigest` are the witnessed head;
- `nonce` (the runtime's 32 bytes, hex), `observedAt`;
- `state`: `witnessed`, or `unknown` when the peer holds no row for the source.

**Key rotation body** (`chio.runtime-rollback-witness-key-rotation.v1`):
- `schema`, `deploymentId`, `sourceId`, `qualificationDigest`;
- `previousKey`, `nextKey`, and `atSeq`/`atDigest` (the witnessed head at rotation);
- `issuedAt`.

The rotation is signed twice, once by each key: two wrapper signatures over the same body, under the same id. A peer accepts it only when `atSeq`/`atDigest` equal its stored head. It then replaces the pin in the same transaction. After that, advances signed by `previousKey` refuse with `runtime_witness_key_mismatch`.

When the old key is lost or compromised, the runtime cannot sign a rotation. The witness-quorum operator re-pins on each peer through trust-control admin configuration, never through a runtime request.

New wire schemas under `spec/schemas/chio-wire/v1/trust-control/`:
- `runtime-rollback-witness-advance-v1` (body and envelope);
- `runtime-rollback-witness-read-request-v1`;
- `runtime-rollback-witness-attestation-v1` (body and envelope).

New trust-control routes:
- `POST /internal/runtime-witness/advance`;
- `POST /internal/runtime-witness/read`;
- `POST /internal/runtime-witness/rotate-key`.

All three are authenticated as cluster peer requests or as a pinned runtime client, under a new `Scope::RuntimeWitness`. An advance from a key not pinned for the source refuses. Refusal codes are typed:
- `runtime_witness_not_extension`;
- `runtime_witness_behind` (carries the peer's stored head);
- `runtime_witness_diverged`;
- `runtime_witness_unknown_source`;
- `runtime_witness_key_mismatch`;
- `runtime_witness_store_unavailable`.

**PROTOCOL:**
- Add section 9.3 "Runtime Rollback Witness": the advance and read rules, the quorum rule, nonce freshness, and the refusal codes.
- Add the two wrapper ids to the 4.5 table.
- Section 8 (Runtime Surfaces) states the open-time rule and the write-acknowledgement rule.

**Configuration:**
- Runtime: required `--runtime-witness-peers` (node id, URL and pinned node key per peer) and `--runtime-witness-quorum`. They are recorded in the signed host record next to `--runtime-witness-root`. The quorum must be greater than half the peer count and at least 2, and peers must have distinct node keys, or init refuses. Each peer entry also carries its declared witness operator, and the host record carries the declared runtime operator (the operator split, see Release gates).
- Peer: required `--runtime-witness-db` when the node serves witness routes, the pinned runtime authority key per `sourceId`, and the declared witness operator. The path joins the distinct-database-paths check.

## Runtime rules

**Open** (`SqliteRuntimeOrchestrationStore::open_with_clock`, after the Tier 1 checks):
1. Read every peer with a fresh nonce. Verify each attestation under the pinned node key, checking schema, deployment, source, qualification digest and nonce. Then verify the embedded advance under the runtime's own pinned authority key (current or rotated-from, along the rotation chain). An attestation whose embedded advance does not verify is not counted.
2. Wait for a quorum of valid attestations, then take the highest `toSeq` among their embedded advances as the witnessed head W. Every head here was signed by the runtime itself, so a minority peer cannot push W above the real head.
3. Open only if `W.seq <= db.seq` and the database chain holds `W.digest` at `W.seq`.
4. Otherwise refuse:
   - `runtime_source_rolled_back`, when W is ahead of the database or off its chain;
   - `runtime_source_witness_unreachable`, when fewer than a quorum answer.

   An `unknown` state from a quorum on a source that is already qualified refuses as `runtime_source_witness_missing`.
5. If the database is ahead of W (a crash after commit, before publish), the runtime publishes the missing entries before it opens. This is the same reconciliation Tier 1 does for its local anchor.
6. Peers that answered behind W, or `unknown`, are caught up by the catch-up rule after the quorum check. They do not gate the open.

**Write** (every authority-advancing write: trust floor CAS, `insert_bundle`, treaty epoch head CAS):
1. Commit to the database with the chain append, then write the Tier 1 anchor, then publish the advance to the peers.
2. Return Ok only after a quorum has stored the new head.
3. Concurrent writes coalesce into one advance (group commit), so admission throughput costs one quorum RTT per batch, not one per bundle.
4. If the quorum fails, the call returns `Unavailable`, and further authority writes refuse until a reopen reconciles. This matches the Tier 1 anchor-failure rule.

**Live verify** (`verify_runtime_source`, reached at admission): compare the database against the last quorum-confirmed head held in memory. No network read happens per admission. A swap under a live process is caught through the Tier 1 path, and at the next open through Tier 2.

**Self-key rules:**
- A peer verifies advances only under the runtime authority key pinned for the source, never a key carried in the record.
- The runtime verifies attestations only under the configured peer node keys.
- The runtime verifies an advance embedded in an attestation only under its own pinned authority key, or a key on its signed rotation chain.
- A peer accepts a key rotation only with signatures from both the previous and the next key.
- Every one of these sites is added to `scripts/check-self-key-verify.py` as PINNED.

## Release gates

- **`docs/release/RELEASE_AUDIT.md`:**
  - Under operator deployment and backup/restore, state that a restored runtime source refuses to open when Tier 2 is configured, and that without Tier 2 only a restore of the database image alone is refused.
  - State the quorum-custody assumption.
- **`docs/release/QUALIFICATION.md`:** add a row for the whole-host restore lane (RED 1 and RED 2 below), with its command and the evidence it produces.
- **`docs/standards/CHIO_BOUNDED_OPERATIONAL_PROFILE.md`:**
  - A deployment may claim "restore-safe runtime authority" only when it has Tier 2 configured and a declared operator split.
  - The operator split works as follows: the signed host record names the runtime operator, each witness peer's configuration names its witness operator, and the runtime operator is not the operator of a quorum of the configured peers. Init refuses a Tier 2 configuration whose declared operators fail that rule.
  - The declaration is an attested claim, not something Chio can verify, and the profile says so.
  - A single-node process host stays at the Tier 1 claim.
- **Claims:** no public copy may claim full rollback protection without Tier 2 configured. README and runbooks change only when Connor asks.
- **Gates:** check-trust-boundaries (new decoders for advance and attestation), check-security-clocks (peer `observedAt` and runtime nonce timing use the clock seam), self-key, wire schemas, schema registry, wrapper vectors, formal mirrors if any Tier 1 mirrored symbol changes, COVERAGE last.

## RED tests (each fails on main plus Tier 1, with the stated reason)

**Runtime-core store tests, with an in-process peer harness of 3 peers and quorum 2:**
1. `whole_host_restore_with_anchor_refuses_open`: qualify, then floor v1. Snapshot the database and the witness root together. Set floor v2 (witnessed). Restore both. Reopen gives `runtime_source_rolled_back`. Tier 1 alone opens, which is the RED.
2. `whole_host_restore_cannot_readmit_consumed_bundle`: snapshot, `insert_bundle(X)` acknowledged, restore the database and anchor. Open refuses, and X is never admitted twice.
3. `forked_history_at_higher_seq_is_refused_by_peer`: fork from the snapshot and advance past the witnessed head on another chain. The advance gives `runtime_witness_not_extension`, and open refuses.
4. `stale_attestation_nonce_refuses`: replaying an attestation from an earlier read (wrong nonce) does not count toward the quorum.
5. `minority_peer_restore_does_not_lower_witnessed_head`: restore one peer's witness database. The quorum maximum still holds the head, and open of a rolled-back runtime refuses.
6. `quorum_unreachable_refuses_open_and_writes`: with 2 of 3 peers down, open gives `runtime_source_witness_unreachable`, and an authority write returns `Unavailable` with nothing acknowledged.
7. `db_ahead_of_witness_after_crash_is_published_then_opens`: drop the advance after commit. Reopen publishes the missing entries and opens.
8. `attestation_under_unpinned_key_is_refused` and `advance_under_unpinned_runtime_key_is_refused`.
9. `qualified_source_with_unknown_witness_state_refuses`: a quorum answering `unknown` for a qualified source gives `runtime_source_witness_missing`.

10. `minority_peer_fake_higher_head_is_ignored`: one peer returns an attestation, under its valid node key, that embeds a head the runtime never signed (seq beyond the database head). Open succeeds on the honest quorum and does not refuse as `runtime_source_rolled_back`. A reader that takes the highest head from any valid attestation refuses here, which is the RED.
11. `lagging_peer_catches_up_in_chunks`: one peer is down for 600 commits, then returns. The next publish gets `runtime_witness_behind`, re-sends 3 advances (256, 256 and 88 entries), and the peer reaches the current head. A peer restored to an earlier witness image catches up the same way. A peer with a head off the runtime chain gets `runtime_witness_diverged` and is not caught up.
12. `rotated_runtime_key_is_pinned_and_old_key_refused`: a rotation signed by both keys at the stored head is accepted. A later advance under the previous key refuses with `runtime_witness_key_mismatch`. A rotation that is signed only by the next key, or whose `atSeq` is not the stored head, refuses.
13. `tier2_init_refuses_without_operator_split`: init refuses when the declared runtime operator is also the declared operator of a quorum of peers.

**Witness store tests (chio-store-sqlite):**

14. Strictly-extending advance only, a capacity bound, corrupt-row refusal on open, and an `IMMEDIATE` transaction. The test shapes come from #1911.

**Trust-control route tests:**

15. Scope enforcement, an unpinned runtime key, an unknown source, and a store error mapping to 503.

**Integration** (`chio-runtime/tests/runtime_boundary`, the native lane runs it post-merge):

16. Two operation-owned admissions with a whole-host restore between them. The second open refuses, and no tool is invoked. Once TREATY-REVOCATION-EPOCH lands: revoke, restore a pre-revocation host image, and confirm the open refuses.

## PR sequence

1. **Spec and wire** (docs, schemas, registry, PROTOCOL 9.3, wrapper vector regen). No behavior.
2. **Shared chain digest** moved to `chio-core-types`, with Tier 1 callers updated. Formal mirrors are blessed if mirrored.
3. **Witness store and trust-control routes** (advance, read, rotate-key, catch-up refusals), with tests 14 and 15. RED first.
4. **Runtime open and write rules, config and CLI** (`--runtime-witness-peers`, `--runtime-witness-quorum`, signed host record, every caller and fixture), with tests 1 to 13. RED first.
5. **Integration test 16 and release-gate document rows.** COVERAGE last in each PR.

Implementation touches Root-held runtime-core store files. As with Tier 1, PRs 4 and 5 need an explicit Root handoff or a Root-owned PR.

## Open owner decisions

These are open. arc-63 is taking them to Connor; the plan does not assume an answer.


1. Option A as the gate, with Option B as a follow-up audit export. (Recommended.)
2. Quorum rule: majority and at least 2. Single-peer witnessing is refused. (Recommended: a single peer is one restore away from the same failure.)
3. Acknowledgement after quorum store, with group commit. The alternative is a bounded window of unwitnessed acknowledged writes, which leaves exactly that window open to replay. (Recommended: acknowledge after quorum.)
4. Whether the witness role may run on the trust-control nodes the runtime already uses for cluster replication, or must be a distinct set. (Recommended: same nodes allowed, with the custody assumption stated in the profile.)
