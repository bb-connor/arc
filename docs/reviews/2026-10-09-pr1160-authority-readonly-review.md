# Independent authority public-read repair review

Verdict: no new actionable security or correctness defect found in this immutable repair chain. The source is sufficient for the assigned SQLite authority write-amplification repair. Final producer handoff, V25 integration, and composed qualification remain separate acceptance boundaries.

Reviewed Source base: `3b0760cfe7c8bdd286fac137663872ab6ebc1e1d`.
Reviewed commits:

- `5320c191afe5cb91d57970ea514070344b6053a1`: existing-only authority inspection.
- `cbb002cfb748cfcab1f586f2771a047ee76c9916`: public authority readers.
- `20369e255f532d1fd474c88bd156947505f33c13`: trusted CLI database startup provisioning.

Reviewed head tree: `95c8f2c3d4e14e5a6408e8b1b65584f8726d6b9f`.
Worktree: `/home/connor/lanes/claude-fix-authority-readonly`. Reads used `git show` at the exact head. No Cargo, builds, source edits, mailbox/ledger edits, or subagents were used. `git diff --check` passed for the immutable range.

## Source assessment

- `authority/custody/filesystem.rs:78-131` inspects existing parent/database entries without creation or permission repair, then opens READ_ONLY/NOFOLLOW/private-cache SQLite storage. Existing parent/file/sidecar checks and the actual SQLite descriptor identity check remain in force before SQL and at the end of each inspection. No URI flags or immutable mode bypass WAL visibility.
- `authority/read_only.rs:81-101` uses a fresh connection and one Deferred transaction. Schema checks, persisted time floor, head membership, and the selected status/key result share that transaction. It never invokes the writable authority constructor or `observe_time`.
- The shared `check_schema_version` helper can stamp an unstamped database, but this reader rejects `application_id == 0` first, within the same pinned transaction (`read_only.rs:116-131`). That writing branch is unreachable here. Wrong/future/old revisions, absent bootstrap, and non-WAL storage refuse without migration, seeding, or journal-mode changes.
- `status()` derives head/lifecycle/live keys from the pinned view using existing lifecycle validation. Fresh reads observe later committed rotations and revocations without a stale cached authority. A concurrent writer holding BEGIN IMMEDIATE does not force this reader into the authority write-lock queue. An in-flight transaction retains its coherent earlier view; the code does not promise a response-wide snapshot across the separate signer/metadata/generation inspections used by a discovery builder.
- `validate_time_floor` preserves the writable owner's existing regression checks. Writable `observe_time` still validates and advances the floor; inspection only validates it. The new reader does not write an observed-time floor or change ordinary mutation behavior.
- Public issuer/verifier metadata, JWKS, discovery/transparency, generic registry, request-object verification, token redemption metadata, and SQLite health select the existing-only helpers. Absence produces refusal, not authority provisioning. Keyring health retains its existing owner path. Store key selection preserves a follower's local signing seed rather than silently replacing it with the replicated head's key.
- Commit `20369e255f` provisions a configured SQLite authority once in trusted `chio trust serve` startup when keyring mode is absent. Public traffic does not acquire that constructor. Existing authenticated authority/admin mutation workflows retain their writable paths.

## Seed fallback and CLI boundary

The new public signing-key helpers use bounded, descriptor-checked `load_existing_authority_keypair`, including an explicit missing-seed refusal. They never call `load_or_create_authority_keypair`.

The seed-only status/JWKS fallback still calls the existing `authority_status_for_config -> authority_public_key_from_seed_file` path, and seed health retains the same raw `fs::read_to_string` path. That baseline reader does not provide the signing loader's bounded no-follow/custody guarantees. This repair does not establish uniform descriptor custody for every seed-status read. It preserves an existing boundary; no raw-seed migration or additional offload was requested or reviewed.

CLI startup now provisions a database only. A configured but missing seed is intentionally refused by public signing readers until an existing operator seed/admin workflow provisions it. Those authorized workflows still call their existing create-capable helpers. This is the stated public no-create behavior, not a new requirement that ordinary startup create a seed. The review found no additional CLI seed regression beyond that intentional boundary.

## Evidence and integration limits

Inspected tests cover zero authority commits using WAL commit frames/data_version, unchanged persisted rows/schema/floor, absence without path creation, write-lock coexistence, rotation/revocation visibility, clock regression, custody refusal without repair, issuer metadata parity, public request verification, and token redemption. The CLI test covers configured database provisioning and subsequent public no-write reads.

The lifecycle tests mutate then read, and the contention tests hold a write transaction; they do not force a lifecycle commit at every individual point inside a public reader. Transactional coherence is established by source inspection, not a claimed deterministic concurrent-lifecycle campaign. No newly introduced unsafe schedule was identified.

Existing producer logs under `claude-pr1160-evidence/vfix/authority-readonly/` retain actual original write/creation failures. The early CLI rotation log has a 409 issuer-metadata failure; the later passport log reports 30 passes after startup provisioning. These logs have not been treated here as exact final-head owning qualification: the owner is still preparing its final handoff. No tests were run by this reviewer.

Root's merge-tree reports one textual integration conflict: `handle_public_generic_listings` must preserve both the V25 retained receipt-store argument and this repair's injected clock argument. The new route fixture uses the existing `metrics_state`. The V25 OID local-issuer resolution read-only swap is a known pending owner patch absent from this Source-based chain, not a new finding. Generic GET offload remains the separate post-merge family. The previously reviewed response-finalization repair is outside this review and remains accepted.

No hosted, merge, release, native-platform, or activation readiness is claimed.

## Exact reviewed production hashes

SHA-256 from committed blobs at `20369e255f532d1fd474c88bd156947505f33c13`:

| File | SHA-256 |
|---|---|
| `crates/platform/chio-store-sqlite/src/authority/read_only.rs` | `e51d65f4b6f9417cd0323d58ad8ad21e937cca83e5ac07e6d613affa1036ebcb` |
| `crates/platform/chio-store-sqlite/src/authority/custody/filesystem.rs` | `4da1513a0b044906dd1a0bbee6b676097213630f3c70a25cf5cef049698a67b3` |
| `crates/platform/chio-store-sqlite/src/authority/lifecycle.rs` | `91b09c6a15972406ce704fe8c32957506b0a15ceca14e7f30dac47f91e46b25f` |
| `crates/platform/chio-control-plane/src/trust_control/config_and_public/public_authority_read.rs` | `bb1cf2edb4eb92344a788c16ac401f93b9e4f66bbd872a9275c918d91a423411` |
| `crates/platform/chio-control-plane/src/trust_control/config_and_public.rs` | `b2bd8bda1d0ebe4a4113762616327b00aa3813c2c595b91198ba28cc6f80938b` |
| `crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs` | `848923fa21e133df72c505490687c18d2fb5b621f94a1b2bfa7f810f3473fdfe` |
| `crates/products/chio-cli/src/cli/runtime.rs` | `4903db0bd5527c268da257b30f38bc0692f86532213e5b4316a2319899266c62` |
