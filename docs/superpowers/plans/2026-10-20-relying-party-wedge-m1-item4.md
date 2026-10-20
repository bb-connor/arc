# Relying-Party Wedge M1 Item 4 Implementation Plan: Exchange Store, Kept Kinds, Mount and Migration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish M1 item 4 of the relying-party wedge on top of part 1 (#1709, the ID-JAG exchange with confidential client authentication) and #1713 (the pinned IdP key source). After this plan:
- Every `serve-http` authentication path ends in an exchange-issued anchored root, and that root is stored durably in the state directory.
- The kept kinds (`operator_static_bearer`, `oidc_jwt`, `oauth_introspection`, `entra_jwt`, `chio_local_as` with re-exchange, `chio_operator_key`) and the trust-control exchange signer are live.
- The token endpoint and bearer intake are mounted.
- Every path that section 2.4 deletes is gone, together with its callers.

**Architecture:**
- **Store:** one new store module in `chio-store-sqlite` holds the exchange state in the state-directory database, behind the existing serving writer. The tables are replay keys, anchored roots, bearer token roots, IdP key snapshots, the root policies and provider identity projections retained by digest, and the tenant index key fingerprint.
- **Kinds:** each kept kind has one verifier that turns its input (a JWS, an introspection response, a static bearer token, a local AS token or an operator request) into one `AnchorEvidence` value. The rule matcher, scope projection and context builder that part 1 wrote for ID-JAG then serve every kind unchanged.
- **Mint:** after the exchange signer has signed the root, minting runs one IMMEDIATE transaction through the serving writer, under the serving-owner fence:
  - item 5's transaction-bound revocation check;
  - the replay bind;
  - the anchored-root insert with its authorization projection;
  - the root context openings, under disclosure custody;
  - for bearer intake, the token-digest mapping;
  - one global commit.
  The root is released only after the SQL commit and the authority-anchor sync both succeed (the durable-owner protocol, Task A).
- **Mount:** the local authorization server routes the `jwt-bearer` and `token-exchange` grants to the exchange. Bearer intake resolves a token to its stored root by token digest. Admission resolves the `chio_root` claim or the token digest to a stored root and verifies it with item 3's anchored-root resolver.
- **Deletions:** each deleted `serve-http` path is removed together with its callers in the PR that mounts its replacement, so no dual path exists on `main`.

**Spec:** `docs/superpowers/specs/2026-10-17-relying-party-wedge-design.md`:
- 2.2 (D1, D4, D5, D14, D17), 2.4 (keep-or-delete table), 2.5 (G17, G18);
- 6.1, 6.2, 6.3, 6.5;
- 7.2, 7.3, 7.4, 7.11, 7.12;
- 8.1, 8.2, 8.3;
- 9.1, 9.2, 9.3, 9.5;
- 10.5, 10.7, 10.8;
- 13.2 item 4 (L, 27-38), 13.3 step 4.

PROTOCOL 5.6 (merged) is normative for wire behaviour.

**Plans this one depends on (on `main`):**
- Item 1, the signing wrapper: `docs/superpowers/plans/2026-10-20-m1-item1-signing-wrapper.md`.
- Item 2, committed receipts, including P-a, the fallible `Rng`: `2026-10-20-m1-item2-committed-receipts.md`.
- Item 5, revocation target kinds, which states the `anchored_roots` contract and the index-key fingerprint: `2026-10-20-relying-party-wedge-m1-item5.md`.
- Item 6, verifier and export, which states the Decision 3 retention by digest and the receipt tenant tag: `2026-10-20-m1-item6-verifier-export.md`.

**Reviews applied:** Root-2 `ws2:~/lanes/claude-pr1160-evidence/root2/review-1731-f114a1bbdc-root2.md`. Changes:
- O3 decided as a side table, with its contract;
- O2 kept pending the owner, with item 5's Q4 refusal retained until the replacement lands;
- repairs 1 to 6: a required revocation checker, the durable-owner release protocol, a full authorization projection in the global commit, persisted root openings, deterministic bearer expiry and retention, and SCIM alias closure with #1728 (P-g);
- the held-file release list for PR A.

**Census base:** the code facts below were read at `origin/main` `fcc31d25fb`, `feat/root-exchange-id-jag` `ab4baa15a4` (#1709) and #1726 (P-a, open). Task 0 re-reads every cited site at each PR's base.

## Facts this plan builds on

| # | Fact | Source |
|---|---|---|
| F1 | The global flags `--receipt-db`, `--revocation-db`, `--authority-seed-file`, `--authority-db`, `--budget-db` and `--session-db`, and `--control-url`, `--control-token`, `--control-authority-public-key` and `--control-authority-trusted-public-keys`, live on `Cli`. The auth flags live on `McpCommands::ServeHttp`. `cmd_mcp_serve_http` copies them into `RemoteServeHttpConfig`. | `chio-cli/src/cli/types.rs:123-180`; `types/runtime.rs:730-850`; `dispatch/api_mcp.rs:52-57,110,154`; `cli/runtime.rs:1220,1292,1307-1354`; `chio-mcp-remote/src/remote_mcp/session_core.rs:170-221` |
| F2 | Auth modes: `RemoteAuthMode::StaticBearer` (`session_core.rs:810`, built at `http_service_auth.rs:443,490`), `JwtBearerVerifier` (`session_core.rs:851`, `oauth/bearer_auth.rs:394`) and `IntrospectionBearerVerifier` (`session_core.rs:862`, `bearer_auth.rs:598`). The AzureAd principal mapping is at `session_identity.rs:374,393,579,584`. | as cited |
| F3 | The local authorization server: `oauth/local_server.rs` holds `exchange_token` (294), `exchange_authorization_code` (313), `exchange_subject_token` (426), `validate_subject_token` (513) and `sign_access_token` (593). The token and JWKS routes are at `http_service.rs:149-150`. `OAuthClientRegistration` (`session_core.rs:149`) holds `client_id` and one redirect URI. | as cited |
| F4 | Bypass issuance: `session_core/factory.rs::configure_session_capability_authority` (213) calls `chio_control_plane::configure_capability_authority` (`chio-control-plane/src/lib.rs:344`). | as cited |
| F5 | Seed-derived keys: `derive_federated_agent_keypair` (`session_identity.rs:674`; callers `session_resume.rs:442,773`) and `derive_enterprise_subject_key` (`session_identity.rs:467`; caller 547, inside `build_enterprise_identity_context`, called from `bearer_auth.rs:554,821`). The control-plane copy in `chio-control-plane/src/scim_lifecycle.rs:452`, used at 432 and by `chio-cli/tests/federated_issue.rs`, derives SCIM principal-hash aliases. Its closure belongs to #1728 (P-g), a coordinated predecessor (Decision 9). | as cited; Root-2 review of #1731, repair 6 |
| F17 | Serving-owner durability: `SqliteServingOwnerError::OutcomeUnknown` (`serving_owner.rs:164`). After an authority-anchor sync failure, `sync_authority_anchor` poisons the owner and returns `OutcomeUnknown` (`serving_owner.rs:184-236`). | `serving_owner.rs` at `bc5579aaf4` |
| F18 | Item 2 P-c `receipt_openings`: salts stored as `BLOB(32)`, state `present` or `erased`, erasure by tombstone. Openings are written in the receipt append transaction, and imported atomically with receipt deltas and snapshots. | item 2 plan Task 4 (lines 410-450, 503-506) |
| F19 | Receipt append, import and retention files: `chio-store-sqlite/src/receipt_store/{append.rs,strict_append.rs,evidence_retention.rs,evidence_retention/dispatch.rs,support/retention_watermark.rs,support/store_impl.rs}` and `chio-control-plane/src/trust_control/cluster/{snapshots.rs,partition.rs}`. | `origin/main` `bc5579aaf4` |
| F6 | The enterprise provider registry file: `remote_mcp/enterprise_provider_registry.rs` (`load` 49, `digest` 58, `load_for_health` 69). It is read once per bearer request (`bearer_auth.rs:538-540,805`) and by admin health (`admin.rs:85-87`). | as cited |
| F7 | Admin: `POST /admin/authority` (`admin.rs:189`, `SqliteCapabilityAuthority::open` at 218) rotates and issues authority. `POST /admin/revocations` is at 513, and `open_revocation_store` (819) falls back to a path open. | as cited |
| F8 | Serving owner: `SqliteServingOwner` (`chio-store-sqlite/src/serving_owner.rs:171`) and the public `SqliteAuthorityStore` (301; `provision` 334, `open_serving_with_clock` 594). `DurableAdmissionRuntime::open_with_clock` (`chio-control-plane/src/durable_admission.rs:65`) opens it on the session-db path. `serving_owner.rs` is a Root-2 held file. | as cited; `pr1160-coord/claims.md` 2026-10-18T18:16:25Z |
| F9 | #1709 (part 1) has these pieces: `root_exchange::{grant, client_auth, jws, id_jag, provider, replay, key_lookup, exchange}`. `RootExchange::exchange_id_jag` returns a `PreparedAnchoredRoot` with private fields; its unsigned body is `pub(super)`. The ID-JAG replay key is bound through `ExchangeReplayStore::bind` as the last step of preparation. `ExchangeEntropy::fill` returns `Result<(), EntropyFailure>`. `IdpKeyLookup::resolve(identity, kid, alg, now) -> IdpKey { jwk, snapshot_digest }`. | #1709 `ab4baa15a4` |
| F10 | #1713 implements `IdpKeyLookup` as `idp_keys::IdpKeySources`, built from provider identities, a fetcher, an `ExchangeSigner`, a `KeySnapshotSink` and a `RefreshPolicy`. It reports `snapshot_digest = IdpKeySnapshot::digest()`. | jwkspin, #1713 `b38fbeda53` |
| F11 | #1726 (P-a, open) moves `Rng` into `chio-core-types` with `fn fill_bytes(&self, dest) -> Result<(), RngError>`. `OsEntropyRng` is planned in `chio-kernel/src/rng.rs` (item 2 plan Task 2). `Rng` carries no `Send + Sync` bound. | #1726 diff; item 2 plan lines 135-136 |
| F12 | The `anchored_roots` contract that item 5 requires: `capability_id TEXT PRIMARY KEY`, `root_policy_rule_id TEXT NOT NULL`, `subject_tag TEXT NOT NULL`, `tenant_tag TEXT` (NULL when the rule has no tenant), `replay_key_digest TEXT NOT NULL` and `expires_at INTEGER NOT NULL`, with one index on each of the four target columns. Rows are retained as long as any receipt under the root is retained. The index-key fingerprint is `hex(HMAC-SHA256(index_key, "chio.tenant-index-key-fingerprint.v1"))` in a singleton row, and startup refuses a mismatch with `tenant index key does not match the state directory`. Item 5 PR 3 calls `refuse_revoked_root` inside item 4's insert transaction. | item 5 plan Task 5 (lines 362-366, 380, 395-399) |
| F13 | Item 6 reads, never writes: historical root policies and provider identity projections by digest, IdP key snapshots by digest, delegation contexts, tags, bearer roots and the receipt tenant tag (Decision 3). | item 6 plan lines 133, 150, 456-458, 482 |
| F14 | Item 5 Q4: with remote durable admission (`control_url`), target kinds other than `capability_id` cannot be linearized, because anchored roots live in the local state directory. If item 4 forbids remote durable admission under a root policy, the 409 path is deleted. | item 5 plan line 593 |
| F15 | `REMOTE-AUTHORITY-LIFECYCLE-BACKENDS` (owner decision, open). Remote clients of keyring-backed and seed-file-backed trust services cannot tell rotations apart (`issuer_state` is absent). The two options are (1) align keyring grace to 3600 s and persist the seed-file generation, then require `issuer_state`; or (2) refuse remote authority for those backends in v1. The decision is needed before the trust-control exchange signer. | `lead2/backlog.md:303` |
| F16 | `ITEM4-MOUNT-FOLLOWUPS` (arc-5b on #1709 r2):<br>1. Refuse `client_secret` alongside `private_key_jwt` (RFC 6749 section 2.3).<br>2. An empty duplicate parameter counts as a duplicate.<br>3. Return `scope` in the token response.<br>4. Reject an `idp_scope_projection` value without `/` at policy load.<br>5. Narrow the prepared-root body accessors when the sign path is wired. | `lead2/lanes.md:228` |

## Decisions

1. **Remote durable admission under a root policy (F14; O2, pending the owner).**
   - **Proposed** (Root-2 endorses it technically): `serve-http` with a root policy refuses to start when remote durable admission is configured. Mint, revocation and admission then share one local serving writer.
   - **Until the owner records O2:**
     - this plan does not delete item 5's Q4 refusal (409 for non-`capability_id` targets under remote admission);
     - the replacement startup restriction lands atomically with that deletion, in PR E.
   - **Distinct configuration paths:**
     - The exchange signer is configured only by `--exchange-signer trust-control` with its own `--exchange-signer-url` and `--exchange-signer-authority-key`.
     - Supplying `--control-url` never selects the remote exchange signer.
     - Supplying `--exchange-signer-url` never selects remote durable admission.
     - This departs from spec 10.8, which reuses `--control-url` and `--control-authority-public-key` for the signer; the PR records the departure.
2. **The replay bind moves into the mint transaction.**
   - In part 1, preparation binds the ID-JAG replay key through `ExchangeReplayStore::bind`. In this plan, preparation records the replay key without binding it, and the mint transaction binds it together with the root insert, so a root exists exactly when its replay key is bound.
   - A signer failure before the transaction spends no exchange replay key.
   - A concurrent mint of the same assertion loses with `AssertionReplay`, and its signed root is dropped unreleased.
   - The client-assertion `jti` stays bound at client authentication, separately and intentionally, as part 1 does.
   - Release follows the durable-owner protocol in Task A.
3. **Replay retention uses the maximum skew.** A replay row is retained until `exp + 60` (the load-time cap on `max_clock_skew_secs`), whatever the rule's own skew. A policy reload that raises the skew therefore cannot reopen a window (arc-5b P3-13 on #1709).
4. **The tenant tag for `oidc_jwt` and `entra_jwt` without a tenant claim.** A provider record always names `subject_mapping.tenant_id_field` (G17, enforced by the identity projection), so every provider-backed root has a tenant tag. `tenant_tag` is NULL only for `chio_operator_key` roots whose request names no tenant. `operator_static_bearer` uses the rule's `tenant_value`, and `chio_local_as` uses the local AS tenant (Decision 5).
5. **`chio_local_as` identity.** The principal is the local AS subject (`auth_subject`, F1). The tenant value is the local AS issuer, under the fixed issuer `urn:chio:local-as`. `assertion_exp` equals the local access token's `exp`.
6. **`chio_operator_key` requests.** `POST /admin/roots` accepts a request body signed by a pinned operator key (`--operator-key`), carrying `request_id`, `principal`, `tenant_value` (optional), `scope`, `holder` and `expires_at`. The replay key is the request id. The signature uses item 1's wrapper under a new schema id, `chio.operator-root-request.v1`, registered in the same PR (G11). `POST /admin/authority` stops issuing capabilities; key rotation stays on its own route.
7. **No successful mint without a revocation checker.** `mint_anchored_root` takes a `&dyn MintRevocationCheck` bound to the open transaction. It has no default, no no-op implementation and no optional parameter. Item 5 PR 3 provides the only production implementation. Until it exists, no production caller of `mint_anchored_root` exists: PR E is the only caller, and item 5 PR 3 is a PR E predecessor. Tests use a checker that refuses or admits explicitly. PR A's additive schema, reads and replay store can land earlier, because none of them authorizes or mints.
8. **Root context openings are persisted under disclosure custody.**
   - **What is stored:** the salts of a root's delegation-context commitments (`anchor.sub`, `anchor.tenant` and every committed claim, F9's `ContextOpening`) go into `root_context_openings`.
   - **Table shape:** it has the same DDL checks and the same erasure-by-tombstone contract as item 2's `receipt_openings` (F18), keyed `(capability_id, salt_ref)`. The key namespace is separate from receipt ids, so a root opening is never read as a receipt opening.
   - **Atomicity:** the openings are inserted in the mint transaction.
   - **No plaintext:** only the salt is stored, never the opened value. The tenant knows its own principal and tenant value, so a `caller` bundle needs only the salt, and an `auditor_hash_only` bundle carries none (spec 9.4). Raw principal and tenant values are never written to any store row.
   - **Reads and erasure:** openings are read only through the scoped disclosure read that item 6 uses for the root's tenant, and erased by `erase_root_openings(capability_id)`. Erasure makes the context commitments permanently hiding and leaves the root valid.
   - **Retention:** openings are retained with their `anchored_roots` row. A tombstone outlives the row it erased, as in F18.
   - **Marker test scope:** the Review Focus 3 property test covers the ordinary state tables. The disclosure tables are protected storage and are checked separately for salts only, with no values.
9. **SCIM alias closure is coordinated with #1728 (P-g).** PR E deletes the `chio-mcp-remote` derivations (F5). The control-plane `derive_enterprise_subject_key` and the SCIM principal-hash aliases it produces close under #1728 (P-g), which is a named predecessor of PR E's identity closure. The Review Focus 5 grep is scoped to `chio-mcp-remote` and the `serve-http` CLI path, and does not claim the symbol vanishes repository-wide.

## Global constraints

- **Coder rules:**
  - Coder lanes run light checks only: `cargo check`, focused tests, `clippy -p`, fmt, the cheap gates (clocks, trust-boundaries, hygiene, escape-hatches, wire-schemas, error-urn-registry, negative-assertions, http-egress-contract, domain-separation), and proof-coverage gen and `--check` last.
  - Integrators run the full `chio-mcp-remote`, `chio-store-sqlite` and `chio-control-plane` suites and the native-cage `chio-cli` and `chio-conformance` runs.
  - Targets are under `/home/connor/lanes/targets/<lane>`; every cargo command runs through `~/lanes/cslot.sh` with `CARGO_INCREMENTAL=0`.
- **House rules:**
  - v1 only, fail-closed, no compat, and no dual path on `main` between PRs.
  - No em dashes, no narrative comments, and no `unwrap` or `expect` outside tests.
  - Every refusal has an exact-error test.
  - Clock reads only through the injected authority clock.
- **Public-path rule:** files under `crates/`, `spec/`, `tests/`, `scripts/` and `docs/adr/` do not mention milestones, the wedge or the spec path.
- **Root-held files** need Root-2's ACK on `sync.md` before the PR opens:
  - `chio-store-sqlite/src/serving_owner.rs` (PR A registers the new tables with the serving owner and the global commit chain);
  - **PR A's held-edit release** waits on three things:
    - Root-2's store queue;
    - the serial schema-adoption cleanup, so the new tables use the resulting fresh-only v1 catalog contract;
    - Root-2's review of the proposed `anchored_root` global-commit kind. This plan does not approve a new kind or adopt any table speculatively.
  - **PR A's exact held-file list:**
    - `serving_owner.rs`, `serving_owner/global_commit_chain.rs`;
    - the v1 catalog registration that the schema cleanup names;
    - `receipt_store/append.rs`, `receipt_store/strict_append.rs` (receipt tenant tag in the append transaction);
    - `receipt_store/support/store_impl.rs`;
    - `receipt_store/evidence_retention.rs`, `receipt_store/evidence_retention/dispatch.rs`, `receipt_store/support/retention_watermark.rs` (tag and root retention with receipts);
    - `chio-control-plane/src/trust_control/cluster/snapshots.rs`, `cluster/partition.rs` (tags imported and exported with receipt deltas and snapshots, F19).
  - SQLite `admission_operation_store` (PR E admission-time root lookup, if it reads there);
  - `chio-http-core/src/receipt.rs` (not touched);
  - `chio-control-plane/src/evidence_export/verification.rs` (not touched).
- **Shared surfaces:** a PR that touches `chio-core-types`, `chio-control-plane`, `spec/PROTOCOL.md`, `spec/schemas/registry.json` or `spec/errors/registry.yaml` posts `REVIEW? #N` on `sync.md`. Core-types, store and control-plane source merges follow the MERGING window.
- **New hash and HMAC domains** are registered in `scripts/check-domain-separation.py`:
  - `chio.anchored-root-projection.v1`
  - `chio.tenant-tag.v1`
  - `chio.subject-tag.v1`
  - `chio.tenant-index-key-fingerprint.v1`
  - `chio.root-exchange.bearer-token.v1`, the token-digest domain.
- **New error codes** are registered in `spec/errors/registry.yaml` under `transport` (exchange), `capability` (admission) and `policy` (load) (G12). The codes come from the staged verdict-matrix scenarios under `docs/superpowers/specs/relying-party-wedge/verdict-matrix/anchored_root/`.

## Review focus

1. **A root that exists without its replay key bound, or the reverse, or a root released before it is durable.**
   - Expected: one IMMEDIATE transaction binds the replay key and inserts the root, so a failure of either rolls back both.
   - The root is released only after the commit and the authority-anchor sync.
   - A post-commit anchor-sync failure is `OutcomeUnknown`, never a definite refusal and never a retried fresh mint.
   - Pinned in PR A by `mint_rolls_back_root_when_replay_bound`, `mint_rolls_back_replay_when_root_insert_fails`, `anchor_sync_failure_reports_outcome_unknown`, `retry_after_unknown_recovers_the_committed_root` and `crash_after_commit_before_release_recovers_the_committed_root`.
2. **A bearer token mapped to two roots, or a second token reusing a replay key.** Expected: `bearer_token_roots.token_digest` is the primary key. Exchange refuses a second root while the first is live (Entra one root per `uti`, D5). A different token with a bound replay key refuses `AssertionReplay`. Pinned in PR C and PR E.
3. **Plaintext principal, tenant or token in the state directory or logs.** Expected: ordinary state tables hold only tags, digests and salted commitments, and the static bearer token is held as a SHA-256 in memory only. The disclosure tables (`root_context_openings`, item 2's `receipt_openings`) are protected storage and hold salts only, never opened values (Decision 8). Pinned by a marker property test that scans every ordinary table and the tracing output, and a second test that the disclosure tables carry 32-byte salts and no marker value (PR E).
4. **A provider identity that changed without a re-signed policy.** Expected: exchange and admission each load the registry once per request and refuse a record whose recomputed identity digest differs from the rule's (G17). Pinned by the moved staged scenarios 017 to 021 (PR E).
5. **A deleted path still reachable.** Expected: after PR E, `git grep` scoped to `crates/protocol/chio-mcp-remote` and the `serve-http` CLI path (`chio-cli/src/cli/{types.rs,types/runtime.rs,dispatch/api_mcp.rs,runtime.rs}`) finds no:
  - `configure_session_capability_authority`, `derive_federated_agent_keypair` or `derive_enterprise_subject_key`;
  - `JwtProviderProfile`, `auth_jwt_public_key`, `auth_jwt_discovery_url`, `auth_jwt_issuer`, `auth_jwt_audience` or `auth_introspection_url`;
  - `receipt_db_path`, `revocation_db_path`, `authority_db_path`, `budget_db_path` or `session_db_path` in `chio-mcp-remote` and the `serve-http` CLI path.
  The control-plane `derive_enterprise_subject_key` is outside the grep and closes under #1728 (P-g) (Decision 9). Pinned by a grep step in Task E-final and by the conformance peers running on `--state-dir`.
6. **An authorization field changed after mint.** Expected: the global commit binds the canonical authorization projection: every authorization column of the root row and the digests of its blobs. Reading or opening a row recomputes the projection and refuses a mismatch. Pinned in PR A by one mutation test per column (`root_policy_rule_id`, `subject_tag`, `tenant_tag`, `replay_key_digest`, `expires_at`, `holder`, `anchor_kind`, `root_policy_digest`, `provider_identity_digest`, `key_snapshot_digest`, `context_digest`, the context blob and the capability blob).

## File structure

| Path | PR | Responsibility |
|---|---|---|
| `crates/platform/chio-store-sqlite/src/root_exchange_store.rs` (new) and `root_exchange_store/{schema,mint,replay,bearer,retention,tenant_index,openings,projection}.rs` | A | tables, the mint transaction and release protocol, `ExchangeReplayStore`, `KeySnapshotSink`, retention by digest, root openings, the authorization projection |
| `receipt_store/{append.rs,strict_append.rs,evidence_retention.rs,evidence_retention/dispatch.rs,support/retention_watermark.rs,support/store_impl.rs}`, `chio-control-plane/src/trust_control/cluster/{snapshots.rs,partition.rs}` | A | the receipt tenant tag, derived in the append transaction, imported with receipts, retained with receipts (Root-held list) |
| `crates/platform/chio-store-sqlite/src/serving_owner.rs`, `serving_owner/global_commit_chain.rs` | A | register the store with the serving owner; `projection_kind = 'anchored_root'` (Root-held) |
| `crates/core/chio-core-types/src/rng.rs` (from #1726) | B | consumer only |
| `crates/core/chio-core-types/src/root_authority/root_policy.rs` | B | projection value must contain `/` at load (F16 item 4) |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/{exchange,grant,client_auth}.rs` | B, C, E | entropy migration, mount follow-ups, `AnchorEvidence` generalization |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/kinds/{oidc_jwt,entra_jwt,introspection,static_bearer,local_as,operator_key}.rs` (new) | C | one verifier per kept kind |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/signer.rs` (new) | D | `ExchangeSigner`: seed-file and trust-control |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/oauth/{local_server,bearer_auth}.rs`, `http_service.rs`, `http_service_auth.rs`, `session_core.rs`, `session_core/factory.rs`, `session_identity.rs`, `session_resume.rs`, `admin.rs`, `enterprise_provider_registry.rs` | E | mount, admission resolution, deletions |
| `crates/platform/chio-control-plane/src/enterprise_federation.rs`, trust-control provider admin and tests | E | delete `provider_profile`; optional inline `jwks` on `oidc_jwks` records |
| `crates/products/chio-cli/src/cli/{types.rs,types/runtime.rs,dispatch/api_mcp.rs,runtime.rs}` and the `serve-http` tests | E | flags in and out; startup refusals |
| `examples/**`, `deploy/**`, `scripts/check-sdk-publication-examples.sh`, `scripts/check-sdk-release.sh`, `scripts/acceptance/session-credentials.py`, the conformance peers (`chio-conformance/src/runner.rs` and the cpp, js, go and python peers), the progressive tutorial, `docs/reference/IDENTITY_FEDERATION_GUIDE.md`, `docs/release/OPERATIONS_RUNBOOK.md` | E | callers move to `--state-dir`, a root policy file and provider records |
| `crates/tooling/chio-conformance/verdict_matrix/scenarios/anchored_root/` (moved from staging), `SCENARIOS.md`, `manifest.toml` | E | 24 scenarios live |
| `spec/errors/registry.yaml`, `scripts/check-domain-separation.py`, `spec/schemas/registry.json` (operator root request), `spec/PROTOCOL.md` (5.6 status line), `spec/schemas/chio-wire/v1/root_authority/operator-root-request.schema.json` (new) | C, E | registrations |

## PR slicing and order

| PR | Title | Depends on | Signs? | Size (days) |
|---|---|---|---|---|
| A | `feat(store): root exchange state: replay keys, anchored roots, bearer roots, snapshots and retention` | #1706, #1709, #1713, Root-2's store queue and the serial schema-adoption cleanup | no | 6-8 |
| B | `refactor(mcp-remote): exchange entropy from the core Rng seam and token request follow-ups` | #1726 (P-a), #1709 | no | 1-1.5 |
| C | `feat(mcp-remote): verify the kept anchor kinds into one exchange` | #1709, #1713, B | no | 6-8 |
| D | `feat(mcp-remote): seed-file and trust-control exchange signers` | item 1, F15 decision | yes (item 1 wrapper) | 2-3 |
| E | `feat(mcp-remote): mount the root exchange in serve-http and delete the bypass paths` (one PR, or a stacked series merged in one MERGING window, L2) | A, C, D, item 3 part 2 (`root_anchor` in the signed body), item 5 PR 3 (the production revocation checker), #1728 P-g (SCIM alias closure), the O2 owner decision | yes | 11-15 |

PRs A, B and C sign nothing and may land before item 1. PR A authorizes and mints nothing in production; `mint_anchored_root` has no production caller before PR E (Decision 7). PR D waits for item 1, because the exchange signer signs through `sign_wrapped`, and for the F15 owner decision. PR E waits for item 3 part 2: a root is only issuable with `root_anchor` inside the signed capability body, and item 3 part 2 also returns the anchored-root resolver that admission calls. PR E is the only PR that mounts anything, and it carries every section 2.4 deletion, so `main` never has two issuance paths.

The planning total is 26-35.5 days for parts 2 onward. PR A grew by 2-3 days for the release protocol, the authorization projection, the root openings and the receipt tenant tag contract. Part 1 (#1709) took about 5, so item 4 as a whole sits at 31-40.5, up to 2.5 days above 13.2's 27-38. Waiting time is not counted: items 1 and 3, item 5 PR 3, #1728, Root-2's store queue, the schema cleanup, and the O1 and O2 decisions.

## Tasks

### Task 0: Census and preconditions (every PR)

- [ ] **Step 1:** `gh pr view <N> --repo bb-connor/arc --json state` for every predecessor in the PR's row. A missing predecessor holds the PR; it does not reorder.
- [ ] **Step 2:** Re-read every fact row this PR cites at its base, and record any drift in the PR body.
- [ ] **Step 3:** For PR A and PR E, post the Root-held file list on `sync.md` and wait for Root-2's ACK.

### Task A: Root exchange store (PR A)

**Schema** (schema key `root_exchange`, version 1, in the state-directory database, opened only through the serving owner, under the fresh-only v1 catalog contract that the serial schema-adoption cleanup establishes):

```sql
CREATE TABLE exchange_replay (
  replay_key_digest TEXT PRIMARY KEY,      -- 64 hex, ReplayKey::digest()
  namespace TEXT NOT NULL,                 -- anchor kind or client_assertion
  bound_at INTEGER NOT NULL,
  retain_until INTEGER NOT NULL            -- exp + 60
);
CREATE INDEX exchange_replay_retain ON exchange_replay(retain_until);

CREATE TABLE anchored_roots (
  capability_id TEXT PRIMARY KEY,
  root_policy_rule_id TEXT NOT NULL,
  subject_tag TEXT NOT NULL,
  tenant_tag TEXT,
  replay_key_digest TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  anchor_kind TEXT NOT NULL,
  holder TEXT NOT NULL CHECK (holder IN ('edge_session','caller')),
  root_policy_digest TEXT NOT NULL,
  provider_identity_digest TEXT,
  key_snapshot_digest TEXT,
  context_digest TEXT NOT NULL,
  delegation_context BLOB NOT NULL,        -- canonical JSON
  root_capability BLOB NOT NULL,           -- canonical JSON of the signed root
  minted_at INTEGER NOT NULL,
  release_state TEXT NOT NULL CHECK (release_state IN ('committed','released')),
  authorization_projection_digest TEXT NOT NULL  -- SHA-256 of the canonical projection below
);
-- one index each on root_policy_rule_id, subject_tag, tenant_tag, replay_key_digest (F12)

CREATE TABLE bearer_token_roots (
  token_digest TEXT PRIMARY KEY,           -- SHA-256("chio.root-exchange.bearer-token.v1\0" || token)
  capability_id TEXT NOT NULL REFERENCES anchored_roots(capability_id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE idp_key_snapshots (
  snapshot_digest TEXT PRIMARY KEY,        -- IdpKeySnapshot::digest()
  issuer TEXT NOT NULL,
  observed_at INTEGER NOT NULL,
  snapshot BLOB NOT NULL                   -- canonical JSON, signed
);

CREATE TABLE retained_root_policies (
  root_policy_digest TEXT PRIMARY KEY,
  policy BLOB NOT NULL                     -- canonical signed JSON
);

CREATE TABLE retained_provider_identities (
  provider_identity_digest TEXT PRIMARY KEY,
  identity BLOB NOT NULL                   -- canonical chio.enterprise-provider-identity.v1
);

CREATE TABLE root_context_openings (       -- disclosure custody, same checks as receipt_openings (F18)
  capability_id TEXT NOT NULL,
  salt_ref TEXT NOT NULL,                  -- anchor.sub, anchor.tenant, anchor.claims.<name>
  state TEXT NOT NULL CHECK (state IN ('present','erased')),
  salt BLOB,                               -- 32 bytes when present, NULL when erased
  state_at INTEGER NOT NULL,
  PRIMARY KEY (capability_id, salt_ref)
);

CREATE TABLE receipt_tenant_tags (
  artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('tool','child')),
  receipt_id TEXT NOT NULL,
  root_capability_id TEXT NOT NULL,
  tenant_tag TEXT,                         -- copied from anchored_roots, never from the request
  PRIMARY KEY (artifact_kind, receipt_id)
);

CREATE TABLE tenant_index_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  key_fingerprint TEXT NOT NULL
);
```

- **Mint and release protocol.** `mint_anchored_root(MintRequest, &dyn MintRevocationCheck) -> MintOutcome`. The exchange signs the root before the call (PR E). Steps:
  1. Open an IMMEDIATE transaction through the serving writer; the serving-owner fence and authority-anchor checks run at begin, as for every serving write.
  2. Run the transaction-bound revocation check (Decision 7). A match refuses with the item 5 entry id. A checker error rolls back and denies.
  3. Bind the replay key. An existing unexpired binding is resolved in this order:
     - a committed root for the same replay key, the same artifact digest and the same authenticated client is a recovery (step 9);
     - anything else refuses `AssertionReplay`.
  4. Insert the `anchored_roots` row with `release_state = 'committed'` and its `authorization_projection_digest`.
  5. Insert the root's `root_context_openings` rows (Decision 8).
  6. For bearer intake, insert or replace the `bearer_token_roots` row under the per-kind rules in Bearer expiry.
  7. Insert the retained policy, provider identity and key snapshot rows by verified digest (Retention by digest).
  8. Append one global commit. Its reference digest is the `authorization_projection_digest`, under a proposed `projection_kind = 'anchored_root'` that needs Root-2's review.
  9. COMMIT, then `sync_authority_anchor`. Only after both succeed is the row set to `release_state = 'released'` and the root returned.
- **Outcome rules:**
  - **Definite refusal (rolled back before COMMIT):** a revocation match, `AssertionReplay`, a constraint or digest failure, or a definite commit failure. No replay key is bound and nothing is released.
  - **`OutcomeUnknown`:** a failure after COMMIT, during the anchor sync, poisons the serving owner (F17). The token endpoint answers 503 `temporarily_unavailable` with no description.
    - The outcome is never reported as "replay unspent", and the request is never retried as a fresh mint.
    - After the owner reopens, `recover_committed_roots` reads every row with `release_state = 'committed'`, verifies its projection, and marks it `released` when the global commit is present. A row without its global commit is removed with its replay binding in one transaction.
    - A client that retries the same assertion then gets the recovered root through step 3.
  - **Signer failure:** a failure before step 1 spends no exchange replay key. The client-assertion `jti` is spent at client authentication, by design.
- **Authorization projection.** The canonical JSON of:
  - `capability_id`, `root_policy_rule_id`, `subject_tag`, `tenant_tag`, `replay_key_digest`, `expires_at`, `holder` and `anchor_kind`;
  - `root_policy_digest`, `provider_identity_digest`, `key_snapshot_digest` and `context_digest`;
  - `SHA-256(delegation_context)`, `SHA-256(root_capability)` and `minted_at`.
  `authorization_projection_digest` is the SHA-256 of that JSON under the domain `chio.anchored-root-projection.v1`.
- **Row check on read.** Every read that authorizes, revokes or exports recomputes the projection digest and checks it against the row and against the global commit chain. It also checks that:
  - the stored capability decodes;
  - its `id`, `issuer`, `expires_at` and scope hash agree with the row and with the context's `effective_root_scope_hash`;
  - the context digest recomputes.
  A mismatch refuses (`AnchoredRootTampered { capability_id }`).
- **Retention by digest.** `retained_root_policies`, `retained_provider_identities` and `idp_key_snapshots` take canonical bytes and recompute the digest from them; a supplied digest is never trusted.
  - Insert-if-absent with identical bytes is a no-op.
  - Different bytes under an existing digest refuse `RetainedDigestMismatch`, and so does a supplied digest that differs from the recomputed one.
  - Reads re-verify the digest of the bytes they return.
- **Replay keys.** `ExchangeReplayStore` for the client-assertion `jti` is a separate, single-statement IMMEDIATE transaction (Decision 2). Exchange replay keys are bound only inside step 3.
- **Bearer expiry, per kind.** One live root per token holds under concurrent first sight: the second transaction finds the first's mapping and replay binding, returns the existing root and drops its own signed root unreleased. A mapping whose root names a policy digest other than the loaded policy is not live.

  | Kind | Before the root expires | After root expiry, mapping present | After the mapping is pruned |
  |---|---|---|---|
  | `entra_jwt`, `oidc_jwt` with `jti` | the mapped root | 401 `invalid_token` (the replay key `(issuer, uti or jti)` stays bound until `exp + 60`) | the token is itself past `exp`, so its verifier refuses `AssertionExpired`: also 401 `invalid_token` |
  | `oidc_jwt` without `jti`, `oauth_introspection` | the mapped root | 401 `invalid_token` (the replay key is the token digest, bound until `exp + 60`) | as above |
  | `operator_static_bearer` | the mapped root | a fresh root, minted in one transaction that replaces the mapping; the replay key includes the new `expires_at` | a fresh root, through the same transaction |

  - **Mapping retention:** a mapping row is retained until `max(root expires_at, token exp) + 60` and then pruned. Pruning therefore never changes the answer for a token that a verifier still accepts.
- **Root retention.** An `anchored_roots` row and its openings are retained while the root is live (`expires_at > now`), whether or not a receipt references it. After expiry they are retained while any receipt, custody record or revocation entry references the root, through the receipt retention join. They are pruned only when the root is expired and unreferenced. Admission refuses at `now >= expires_at` (half-open).
- **Snapshots.** `KeySnapshotSink` (#1713) writes `idp_key_snapshots` by verified digest in its own transaction, before #1713 installs the new key set.
- **Retention reads** for item 6: `root_policy(digest)`, `provider_identity(digest)`, `idp_key_snapshot(digest)`, `anchored_root(capability_id)` (projection-checked) and `root_openings(capability_id)` (disclosure-scoped).
- **Tenant index.** `TenantIndex::open(index_key, store)` records the fingerprint on first open and refuses a mismatch with `tenant index key does not match the state directory` (F12). It exposes `subject_tag(issuer, subject)` and `tenant_tag(issuer, tenant)`, and refuses NUL in either input.
- **Receipt tenant tag (O3, Root-2: side table).** `receipt_tenant_tags` is authoritative derived state.
  - **How it is written:** only the serving-owner receipt append transaction writes it (F19). That transaction reads the receipt's root capability id from the verified receipt's capability chain, reads the row's `tenant_tag` from the projection-checked `anchored_roots` row, and writes it.
  - **No other writer:** no caller metadata, request field or separate tagging API writes it.
  - **Keying:** the key is `(artifact_kind, receipt_id)`, so tool and child receipt id namespaces cannot collide. Task 0 also checks that receipt ids are unique within each kind.
  - **Replication:** replicated imports and snapshot imports write the tag row in the same transaction as the receipt row and the cursor advance (`cluster/snapshots.rs`, `cluster/partition.rs`), re-deriving it from the imported root row. They never accept the tag value from the source.
  - **Retention:** receipt retention deletes the tag row with its receipt.
  - **Fail closed:** a receipt without a tag row, a tag that disagrees with its root row, or a tag row for an unknown receipt refuses tenant export (`ReceiptTenantTagMissing`, `ReceiptTenantTagConflict`). It never broadens the selection.

- [ ] **Step 1: Failing tests** in `root_exchange_store/tests.rs` (joint serving-owner fixture, fixed `ClockScope`). Every refusal is pinned to its exact error.
  - Atomicity and protocol:
    - `mint_inserts_root_replay_openings_and_bearer_mapping_atomically`
    - `mint_rolls_back_root_when_replay_bound`
    - `mint_rolls_back_replay_when_root_insert_fails`
    - `mint_requires_a_revocation_checker` (a compile-time signature, plus `refusing_checker_denies_with_entry_id` and `checker_error_rolls_back`)
    - `anchor_sync_failure_reports_outcome_unknown`
    - `commit_failure_is_a_definite_refusal`
    - `crash_after_commit_before_release_recovers_the_committed_root`
    - `retry_after_unknown_recovers_the_committed_root`
    - `committed_row_without_global_commit_is_removed_with_its_replay_binding`
    - `signer_failure_spends_no_replay_key`
  - Projection: one `<column>_mutation_refuses` per projection member, `context_blob_mutation_refuses`, `capability_blob_mutation_refuses` and `capability_scope_disagreeing_with_context_refuses`.
  - Retention by digest:
    - `retained_policy_bytes_under_wrong_digest_refuse`
    - `retained_identity_bytes_under_wrong_digest_refuse`
    - `snapshot_bytes_under_wrong_digest_refuse`
    - `identical_retained_bytes_are_a_no_op`
  - Openings:
    - `openings_written_in_mint_salts_only`
    - `opening_row_refuses_value_column` (DDL has none)
    - `erase_root_openings_tombstones`
    - `root_openings_namespace_never_reads_as_receipt_openings`
  - Bearer and root retention:
    - `bearer_token_digest_maps_to_one_root`
    - `simultaneous_first_seen_mints_one_root`
    - `static_bearer_expired_root_is_replaced_in_one_transaction`
    - `entra_token_after_root_expiry_is_invalid_token_before_and_after_pruning`
    - `admission_refuses_at_expires_at`
    - `live_root_without_receipts_is_retained`
    - `expired_root_referenced_by_a_receipt_is_retained`
    - `expired_unreferenced_root_is_pruned_with_openings`
    - `mapping_for_another_policy_digest_is_not_live`
  - Receipt tenant tags:
    - `tenant_tag_derived_from_root_in_append`
    - `caller_supplied_tenant_metadata_is_ignored`
    - `tool_and_child_ids_do_not_collide`
    - `replicated_import_writes_receipt_tag_and_cursor_atomically`
    - `snapshot_import_rederives_tags`
    - `receipt_retention_deletes_its_tag`
    - `missing_tag_refuses_tenant_export`
    - `conflicting_tag_refuses_tenant_export`
    - `no_receipt_of_another_tenant_in_selection` (marker principals)
  - Other:
    - `expired_replay_row_is_pruned_and_rebindable_only_after_retention`
    - `snapshot_sink_records_before_install`
    - `startup_refuses_a_different_index_key`
    - `tag_inputs_refuse_nul`
    - `restored_snapshot_missing_a_root_refuses_open`
- [ ] **Step 2:** Implement after the held-edit release (Global constraints). Register the domains (`chio.anchored-root-projection.v1` in addition to the four listed) and, after Root-2's review, the `anchored_root` projection kind. Run the light checks, and regenerate COVERAGE last.

### Task B: Entropy migration and token request follow-ups (PR B)

- **Entropy.** `ExchangeEntropy` is deleted. `ExchangeServices.entropy` becomes `&'a (dyn chio_core_types::rng::Rng + Send + Sync)`, and `random::<N>` maps `RngError` to `RootExchangeError::EntropyUnavailable`. The production source is `chio_kernel::rng::OsEntropyRng` (item 2 P-a). Tests use `chio-fixture-rng`'s `FixtureRng` or a local failing `Rng`. Entropy is still drawn before the durable bind (Decision 2 keeps the bind in the mint transaction).
- **F16 item 1.** A token request that carries `client_secret` (body or HTTP Basic) together with `client_assertion` refuses `ClientAuthenticationAmbiguous` (RFC 6749 section 2.3: one method per request).
- **F16 item 2.** A recognized parameter that appears twice refuses `MalformedRequest("repeated parameter")` even when one occurrence is empty. A single empty occurrence counts as omitted (RFC 6749 section 3.1).
- **F16 item 4.** `RootPolicyRule::validate` refuses an `idp_scope_projection` value without `/` (`RootAuthorityShapeError::Pattern { field: "idp_scope_projection", expected: "server/tool" }`). This is a `chio-core-types` change, with `REVIEW?` on `sync.md`.

- [ ] **Step 1: Failing tests:**
  - `failing_rng_denies_before_any_bind`
  - `client_secret_with_client_assertion_refuses`
  - `empty_duplicate_parameter_refuses`
  - `single_empty_parameter_is_omitted`
  - `projection_value_without_slash_rejects_at_load`
- [ ] **Step 2:** Implement and run the light checks.

### Task C: Kept kinds into one exchange (PR C)

- **Shared evidence.** `AnchorEvidence` is produced only by a kind verifier. It holds:
  - the kind, issuer and principal;
  - the tenant value (optional only for `chio_operator_key`);
  - `token_iat` and `token_exp`;
  - the replay key;
  - for JWS kinds: `key_snapshot_digest`, `kid`, `alg` and `artifact_digest`;
  - the recordable claims;
  - the provider record (provider-backed kinds).
- **One preparation path.** `RootExchange::prepare(evidence, holder, now, services)` takes over the second half of today's `exchange_id_jag`: rule match by kind, provider digest pin, scope projection, holder, lifetime `min(now + ttl, exp, valid_until)`, context and anchor. `exchange_id_jag` becomes client authentication, then `id_jag::verify`, then `prepare`.
- **Kind verifiers** (each in `kinds/`, each with exact-error tests for every refusal in 8.1 that names it):
  - `oidc_jwt`: `CompactJws::parse`, then `IdpKeyLookup::resolve`, then `verify_with`.
    - `iss` equals the record issuer; `aud` is in the record's `audiences`.
    - Time rules as for ID-JAG, without the assertion-lifetime bound.
    - Replay key `(oidc_jwt, issuer, jti)` when `jti` is present, else the bearer token digest.
    - A rule whose record has a Microsoft Entra issuer refuses at policy load: `login.microsoftonline.com/<tenant>/v2.0` and `sts.windows.net/<tenant>/` are matched by host, against the registry at startup.
  - `entra_jwt`: as `oidc_jwt`, plus:
    - the issuer must be tenant-specific, so `common`, `organizations`, `consumers` and `{tenantid}` refuse `IssuerNotTenantSpecific`;
    - the replay key is `(entra_jwt, issuer, uti)`, and `uti` is required;
    - no `max_assertion_lifetime_secs`, and the principal comes from `subject_mapping.principal_source` (D14, G17).
    - The pin is the Microsoft identity platform access token reference (v2 tokens), recorded in the module doc.
  - `oauth_introspection`:
    - an RFC 7662 POST to the record's `introspection_url` through `HttpEgressContract`, narrowed to `https` and a bounded response;
    - the edge's own client credentials (`--auth-introspection-client-id`, `CHIO_MCP_AUTH_INTROSPECTION_CLIENT_SECRET`), sent as HTTP Basic;
    - `active` must be `true`, and `exp` is required;
    - the principal and tenant come from the record mapping over the response members;
    - the evidence is the response digest, and the replay key is the bearer token digest.
  - `operator_static_bearer`:
    - a constant-time comparison of `SHA-256(token)` with the configured digest;
    - the principal and tenant come from the rule;
    - issuer `urn:chio:operator`;
    - the replay key is `(operator_static_bearer, urn:chio:operator, token_digest || ":" || root expires_at)`, so exactly one live root exists per token and a fresh root follows expiry.
  - `chio_local_as`:
    - the input is a local AS access token verified against the local AS key;
    - the replay key is the local token `jti`;
    - `assertion_exp` is the token `exp`.
    - **Re-exchange** (RFC 8693, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`):
      - It consumes the subject token's `jti` once.
      - It narrows scope and `resource` to a subset of the subject root's, refusing `ReExchangeWidens` otherwise.
      - It inherits the subject root's `assertion_exp`.
      - It is open to the client the subject token was issued to, including public clients.
  - `chio_operator_key`:
    - the input is an operator root request (Decision 6), verified against `--operator-key` under the wrapper (signature verification lands in PR D with item 1; PR C verifies the body shape and replay key);
    - the replay key is the request id.
- **Client registry.** `ClientRegistry` folds into `OAuthClientRegistration`: a client gains an optional public JWK and `token_endpoint_auth_method` (`none` or `private_key_jwt`). Public clients keep `authorization_code` and local re-exchange, and are refused for `jwt-bearer` and external `token-exchange` (part 1 rule, spec 6.2 step 2).

- [ ] **Step 1: Failing tests** per kind. In addition:
  - `oidc_jwt_rule_with_entra_issuer_rejects_at_load`
  - `entra_common_issuer_refuses`
  - `entra_second_token_same_uti_refuses`
  - `static_bearer_wrong_token_refuses_in_constant_time_path`
  - `static_bearer_one_live_root_per_token`
  - `local_reexchange_widening_refuses`
  - `local_reexchange_twice_refuses`
  - `introspection_inactive_refuses`
  - `introspection_without_exp_refuses`
  - `every_kind_reaches_the_same_prepare` (a table test over one rule per kind)
- [ ] **Step 2:** Implement and run the light checks, including `check-http-egress-contract.sh` for introspection.

### Task D: Exchange signers (PR D)

- **The signer.** `ExchangeSigner` is a closed enum:
  - `SeedFile` (local Ed25519; the file is mode 0600 and owned by the process user, or startup refuses);
  - `TrustControl` (the pinned remote authority).
  Both sign the root capability body through `sign_wrapped(CHIO_CAPABILITY_SCHEMA, ..)` (item 1), and every returned signature is verified against the pinned exchange key before the root is released.
- **Trust-control** follows the F15 decision:
  - Under option 1, the signer requires `issuer_state` and refuses a status without it.
  - Under option 2, it refuses keyring-backed and seed-file-backed trust services at startup (`trust-control exchange signer requires lifecycle state`).
  - An unreachable trust-control, or a signature that fails against `--exchange-signer-authority-key`, fails the mint (8.1). No signer falls back to a local or generated key (PROTOCOL 5.6.9).
  - The signer reads only `--exchange-signer-url` and `--exchange-signer-authority-key` (Decision 1). It never reads `--control-url`, and its configuration never enables remote durable admission. Tests:
    - `control_url_alone_does_not_select_the_exchange_signer`
    - `exchange_signer_url_does_not_enable_remote_admission`
- **Operator root requests.** PR D also verifies `chio.operator-root-request.v1` signatures (Decision 6) through `verify_wrapped`.
- **Snapshots.** It also signs IdP key snapshots for #1713 through the same `ExchangeSigner` (#1713 holds the type today; PR D moves it into `root_exchange::signer` and #1713 rebases).

- [ ] **Step 1: Failing tests:**
  - `seed_file_group_readable_refuses`
  - `trust_control_signature_failing_pin_refuses_mint`
  - `trust_control_unreachable_refuses_mint`
  - `trust_control_without_lifecycle_state_refuses` (the option chosen)
  - `operator_request_signed_by_unpinned_key_refuses`
- [ ] **Step 2:** Implement and run the light checks. The integrator runs the trust-control remote authority tests against keyring-backed and seed-file-backed services (the missing round-1 test from `review-1674-r2-claude.md:76`).

### Task E: Mount, admission and deletions (PR E)

**Mint and release:**
- `RootExchange::issue(prepared, signer, store, revocation)` signs the body with `root_anchor` (item 3 part 2), then calls `mint_anchored_root` with item 5's transaction-bound checker, and returns the root only on `MintOutcome::Released` or `Recovered`. `OutcomeUnknown` answers 503 `temporarily_unavailable` (Task A).
- The prepared-root body accessor narrows: `pub(super) body` is consumed by `issue` and is unreachable afterwards (F16 item 5).

**Token endpoint** (`oauth/local_server.rs::exchange_token`):
- `jwt-bearer` with an ID-JAG goes to `exchange_id_jag`.
- `token-exchange` dispatches on `subject_token_type`:
  - `id-jag` goes to the ID-JAG exchange;
  - `jwt` goes to `entra_jwt` or `oidc_jwt` by matched rule;
  - `access_token` goes to the `chio_local_as` re-exchange.
- `requested_token_type`:
  - absent, or `access_token`: returns a local AS EdDSA JWT with `chio_root` and `exp` equal to the root's `expires_at`;
  - `urn:chio:params:oauth:token-type:capability-v1`: returns the canonical root capability JSON, `issued_token_type` echoed, `token_type` `N_A` (6.3).
- The response carries `scope` when it differs from the request (F16 item 3).
- No refresh token is issued.
- Errors use `RootExchangeError::oauth_error` and `client_description` (part 1).
- The AS metadata advertises the `jwt-bearer` grant, the supported subject and requested token types, and `private_key_jwt`.

**Bearer intake** (`oauth/bearer_auth.rs`):
- A bearer token is looked up by token digest in `bearer_token_roots`. A live root is used.
- An unknown token runs its kind verifier, then `prepare`, `issue` and the mapping insert. Expired roots follow Task A's per-kind table: 401 `error="invalid_token"` for the IdP kinds (6.3) and a fresh root for `operator_static_bearer`, the same before and after pruning.
- The per-request registry load (#1535) feeds both the exchange and the admission provider check (G17).
- `RemoteAuthMode::StaticBearer`, `JwtBearer` and `IntrospectionBearer` collapse into the exchange; no session authority is created any other way (D1).

**Local AS login.** `authorization_code` mints a `chio_local_as` root at code exchange, and the access token carries `chio_root`.

**Admin:**
- `POST /admin/roots` (Decision 6).
- `POST /admin/authority` stops issuing.
- `/admin/revocations` keeps item 5's targets.
- `open_revocation_store`'s path fallback is deleted (item 5 notes this is a no-op if item 4 deletes `revocation_db_path` first).

**Admission:**
- The edge resolves `chio_root`, or the bearer token digest, to the stored root.
- It verifies the root with item 3 part 2's anchored-root resolver against the loaded policy and the pinned exchange keys, and checks the provider record by identity digest per request (G17).
- A session-held root is usable only from the token that produced it (9.3).
- **Configuration and startup.**
  - New flags: `--state-dir`, `--root-policy`, `--root-policy-key`, `--exchange-signer seed-file:<path>|trust-control` (with `--exchange-signer-url` and `--exchange-signer-authority-key` for `trust-control`, Decision 1), `--kernel-signer seed-file:<path>`, `--tenant-index-key` and `--operator-key`.
  - Kept: `--auth-token`, `--enterprise-providers-file`, `--auth-introspection-client-id` and the secret env.
  - Startup refusals: the full 8.3 list, plus the F12 fingerprint refusal. When the owner confirms O2, Decision 1's refusal of remote durable admission under a root policy lands here, atomically with the deletion of item 5's Q4 refusal. Until then, item 5's Q4 refusal stays.
  - Startup also refuses when item 5's production revocation checker is not wired (Decision 7).
  - The state-directory lock: `flock` on `<state-dir>/LOCK` before any store opens, held for the process lifetime. A network filesystem (`statfs` magic on Linux, `MNT_LOCAL` on macOS) refuses.
  - Every store opens under `--state-dir` through the serving owner.
- **Deletions, each with every caller:**
  - **Bypass issuance and seed-derived keys:**
    - `configure_session_capability_authority` and its call into `chio_control_plane::configure_capability_authority` from `serve-http`;
    - `derive_federated_agent_keypair` and the `chio-mcp-remote` `derive_enterprise_subject_key`, with `session_resume.rs`'s resume derivation. Resume binds to the stored root id instead. The control-plane SCIM derivation and its principal-hash aliases close under #1728 (P-g), which merges first (Decision 9).
  - **Provider identity outside the registry:**
    - `JwtProviderProfile` with its `AzureAd` mapping;
    - the record member `provider_profile` (`enterprise_federation.rs`, trust-control provider admin and its tests);
    - the provider verification flags and fields (2.4).
  - **Per-store paths:** the per-store database flags and `RemoteServeHttpConfig` path fields for `serve-http`. `chio trust serve` flags are unchanged.
- **Callers that move to `--state-dir`, a root policy file and provider records:**
  - 8 crate files, including `chio-cli/tests/mcp_serve_http.rs`, `tests/mcp_serve_http/token_passthrough.rs`, `tests/mcp_auth_server.rs` and `chio-conformance/src/runner.rs`;
  - 3 deploy units (`deploy/reference-runtime/systemd/chio-mcp-edge.service`, `deploy/cloud-run/service.yaml`, `deploy/sidecar/Dockerfile`);
  - 8 example files (agent-commerce-network, docker, both internet-of-agents networks, reference-swarm);
  - `scripts/check-sdk-publication-examples.sh`, `scripts/check-sdk-release.sh` and `scripts/acceptance/session-credentials.py`;
  - the cpp, js, go and python conformance peers and the progressive tutorial;
  - 18 docs files, led by `IDENTITY_FEDERATION_GUIDE.md` and `OPERATIONS_RUNBOOK.md`.
  Task 0 re-counts these at the PR base.
- **Scenarios.** Move the 24 staged `anchored_root` scenarios into `chio-conformance/verdict_matrix/scenarios/anchored_root/`, add the enum value and `SCENARIOS.md` row, register their reason URNs and re-pin `manifest.toml`. Remove the PROTOCOL 5.6 status line for the parts now implemented.

- [ ] **Step 1: Failing tests:**
  - token endpoint: one per grant and token-type combination, and the capability-v1 response shape;
  - bearer intake: first sight mints, the second request reuses, an expired root gives 401 `invalid_token`;
  - admission: an unknown `chio_root` denies, and a root from a different token denies;
  - startup: one exact test per 8.3 refusal, the fingerprint, the missing revocation checker, and (after O2) Decision 1;
  - the state-directory lock: a held lock refuses, and a crash releases it;
  - the marker property test (Review Focus 3);
  - the staged scenarios 001 to 024 passing in the `rust-mcp-serve-http` driver.
- [ ] **Step 2:** Implement in commit order:
  1. mint and release;
  2. the token endpoint;
  3. bearer intake;
  4. local AS;
  5. admin;
  6. admission;
  7. configuration and startup;
  8. deletions;
  9. caller migration;
  10. scenarios.
- [ ] **Step 3 (Task E-final):** The Review Focus 5 grep returns no matches. The light checks pass. The integrator runs the full `chio-mcp-remote`, `chio-store-sqlite`, `chio-control-plane` and native-cage `chio-cli` and `chio-conformance` suites and the hosted-edge qualification lane (item 7 owns the live Okta and Entra runs). COVERAGE is regenerated last.

## Recorded decisions

- **R1 (was O3), Root-2 decision.** The receipt tenant tag is the side table `receipt_tenant_tags`: authoritative derived state, with the contract in Task A.

- **L1 (was O4), lead decision 2026-10-20.** `POST /admin/roots` with its own signed request schema, `chio.operator-root-request.v1` (Decision 6). `/admin/authority` is not extended: an operator root request and an authority rotation are different trust objects.
- **L2 (was O5), lead decision 2026-10-20.** PR E is one PR, so `main` never has two issuance paths. If it grows past reviewable size, it splits by caller group inside a stacked series whose members merge together in one MERGING window. A separately landed half is not allowed.

## Open decisions

| # | Owner | Question | Default in this plan |
|---|---|---|---|
| O1 | owner (Connor) | F15: lifecycle state for keyring and seed-file trust services, or refuse them as remote exchange signers in v1 | PR D implements whichever is chosen; it does not open until the decision is recorded |
| O2 | owner (Connor) | Decision 1: refuse remote durable admission under a root policy | proposed refusal (Root-2 endorses it technically); item 5's Q4 refusal stays until the replacement startup restriction lands atomically in PR E |

## Spec traceability

| Spec | PR |
|---|---|
| 6.2 steps 2-8 (token endpoint, `chio_root`, no refresh) | C, E |
| 6.3 (Entra bearer and explicit RFC 8693; one root per `uti`; 401 after expiry) | C, E |
| 6.5 (session-held versus caller-held) | C (holder), E (cross-token refusal) |
| 7.2 (every kind and its replay key) | C |
| 7.4 (policy load against the registry, Entra issuer on `oidc_jwt`) | B, C |
| 7.11 (anchored root target columns) | A |
| 7.12 (tags, `index_key`) | A |
| 8.1 (exchange refusals) | B, C, D |
| 8.2 (admission refusals) | E |
| 8.3 (startup refusals) | D (seed files), E |
| 9.1 to 9.3, 9.5 | A, C, D, E |
| 10.5, 10.7, 10.8 | A to E |
| D4 (single instance, state-directory lock) | E |
| G17 (registry as the one provider identity source, per-request reads) | C, E |
| 2.4 deletions | E |
