# Relying-Party Wedge M1 Item 4 Implementation Plan: Exchange Store, Kept Kinds, Mount and Migration

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish M1 item 4 of the relying-party wedge on top of part 1 (#1709, the ID-JAG exchange with confidential client authentication) and #1713 (the pinned IdP key source). After this plan:
- Every `serve-http` authentication path ends in an exchange-issued anchored root, and that root is stored durably in the state directory.
- The kept kinds (`operator_static_bearer`, `oidc_jwt`, `oauth_introspection`, `entra_jwt`, `chio_local_as` with re-exchange, `chio_operator_key`) and the trust-control exchange signer are live.
- The token endpoint and bearer intake are mounted.
- Every path that section 2.4 deletes is gone, together with its callers.

**Architecture:**
- **Store:** one new store module in `chio-store-sqlite` holds the exchange state in the state-directory database, behind the existing serving writer. The tables are replay keys, anchored roots, bearer token roots, IdP key snapshots, the root policies and provider identity projections retained by digest, root context openings, and the tenant tag generation pin.
- **Kinds:** each kept kind has one verifier that turns its input (a JWS, an introspection response, a static bearer token, a local AS token or an operator request) into one `AnchorEvidence` value. The rule matcher, scope projection and context builder that part 1 wrote for ID-JAG then serve every kind unchanged.
- **Mint:** after the exchange signer has signed the root, minting runs one IMMEDIATE transaction through the serving writer, under the serving-owner fence:
  - item 5's transaction-bound revocation check;
  - the replay bind;
  - the anchored-root insert with its authorization projection;
  - the root context openings, under disclosure custody;
  - for bearer intake, the token-digest mapping;
  - one global commit.
  A root is returned only once the owner's synced authority anchor covers its global commit (the durable-owner protocol, Task A). Release is derived from verified durable state; no second write marks it.
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

PROTOCOL 5.6 (merged) is normative for wire behaviour. This plan departs from the spec in four places (2.4 trust-control row, the last 8.3 refusal, 10.5 `factory.rs`, 10.8 signer flags); a separate docs PR amends them for owner sign-off before PR D2 and PR E open.

**Plans this one depends on (on `main`):**
- Item 1, the signing wrapper: `docs/superpowers/plans/2026-10-20-m1-item1-signing-wrapper.md`.
- Item 2, committed receipts, including P-a, the fallible `Rng`: `2026-10-20-m1-item2-committed-receipts.md`.
- Item 5, revocation target kinds, which states the `anchored_roots` contract and the index-key continuity refusal: `2026-10-20-relying-party-wedge-m1-item5.md`.
- Item 6, verifier and export, which states the Decision 3 retention by digest and the receipt tenant tag: `2026-10-20-m1-item6-verifier-export.md`.

**Reviews applied:**
- Root-2 r1 (`ws2:~/lanes/claude-pr1160-evidence/root2/review-1731-f114a1bbdc-root2.md`): O3 decided as a side table; O2 kept pending the owner; repairs 1 to 6 (a required revocation checker, the durable-owner release protocol, a full authorization projection, persisted root openings, deterministic bearer expiry and retention, SCIM alias closure with #1728 P-g); the held-file list.
- Root-2 r2 (`root2/review-1731-5038a60e38-root2.md`): a committed root without its global commit refuses as corruption and is never deleted; the retry binding (client, artifact digest, request digest) is persisted and projected; release is derived from verified durable state, with no second write; each tenant tag row is bound to its exact signed receipt on read.
- arc-5b r1 and r2 (`lead2/review-1731-arc5b.md`), with lead decisions 2026-10-20:
  - item 2's shared tenant index key set (#1728, #1733): `tenant-tag` and `subject-tag` purposes with all-generation match;
  - a new trust-control route that signs edge-built root and snapshot bodies;
  - the `--exchange-signer trust-control:<url>` value with a scoped P-f credential file and a rotating trusted-key set;
  - the stores `--control-url` drives today, all removed from `serve-http` in PR E with the O2 restriction and the item 2 and item 5 amendments;
  - D split into D1 (seed file) and D2 (trust-control);
  - the receipt tenant tag append moved to its own PR after item 2 F and P-c; `serve-http` receipts never leave the state directory;
  - DDL checks, the exempt-signing allowlist, the operator request registration in D1, and the `serve-http` identity after E.

**Census base:** the code facts below were read at `origin/main` `fcc31d25fb` and `bc5579aaf4`, `feat/root-exchange-id-jag` `ab4baa15a4` (#1709), #1726 `38150d69fb` (P-a, open) and #1728 `4193c35bbb` (item 2 A1 and P-g, open). Task 0 re-reads every cited site at each PR's base.

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
| F11 | #1726 (P-a, open) moves `Rng` into `chio-core-types` with `fn fill_bytes(&self, dest) -> Result<(), RngError>`, and ships `OsEntropyRng` in `chio-kernel/src/rng.rs`. `Rng` carries no `Send + Sync` bound. | #1726 `38150d69fb` |
| F12 | The `anchored_roots` contract that item 5 requires: `capability_id TEXT PRIMARY KEY`, `root_policy_rule_id TEXT NOT NULL`, `subject_tag TEXT NOT NULL`, `tenant_tag TEXT` (NULL when the rule has no tenant), `replay_key_digest TEXT NOT NULL` and `expires_at INTEGER NOT NULL`, with one index on each of the four target columns. Rows are retained as long as any receipt under the root is retained. Item 5 records an index-key fingerprint `hex(HMAC-SHA256(index_key, "chio.tenant-index-key-fingerprint.v1"))` and refuses a mismatch with `tenant index key does not match the state directory`; Decision 10 replaces the fingerprint with per-value `key_id`s under all-generation match and keeps the refusal text for a missing referenced generation. Item 5 PR 3 calls `refuse_revoked_root` inside item 4's insert transaction. | item 5 plan Task 5 (lines 362-366, 380, 395-399) |
| F13 | Item 6 reads, never writes, through plain inherent methods of `SqliteRootExchangeStore` (no trait): `presentation(root_capability_id)`, `delegation_context(digest)`, `root_policy(digest)`, `provider_identity(digest)`, `idp_key_snapshot(digest)`, `context_openings(context_digest)` and `receipts_for_tenant(tags, query)`, each returning `chio-core-types` types and `RootExchangeStoreError`. Item 5's `SqliteRevocationStore::revocations_covering` is the eighth read. A missing row is a typed `RootExchangeStoreError` variant, never `Option`; for roots it is `AnchoredRootMissing { capability_id }`. | item 6 plan Task 8 Interfaces |
| F20 | What `--control-url` drives for `serve-http` today: remote durable admission (`DurableAdmissionRuntime::open_remote`), the receipt store (`configure_receipt_store`), the revocation and budget stores when durable admission is off (`configure_revocation_store`, `configure_budget_store`), the session capability authority (`factory.rs:229`, `authority_mode.rs`), the admin forwarding of `/admin/revocations` (`admin.rs:777`) and the admin health members `proxied`, `revocationsConfigured` and `budgetsConfigured` (`admin.rs:148-162`), and the resume fingerprint (`session_resume.rs:298-299`). `--control-token` is the shared service token. Item 2 adds the remote opening read (E-k, A/E) and the `receipt-openings:read` grant to `serve-http` under `--control-url`. | `session_core/factory.rs:48-110,404-440,612-645`; item 2 plan lines 274-275, 420, 432, 436 |
| F21 | `POST /v1/capabilities/issue` (`authority_handlers.rs:112-170`, `IssueCapabilityRequest { subject_public_key, scope, ttl_seconds, runtime_attestation }`) builds its own body: its own id, `issued_at` and `expires_at`, and no `root_anchor`. It forwards to the cluster leader and runs under the authority mutation fence and term check. Item 2 P-f maps it to a `deployment` credential with `capabilities:issue`. | `authority_handlers.rs`, `service_types/paths.rs:12`, `router.rs:54`, `json_ingress.rs:78,100`; item 2 plan line 713 |
| F22 | Item 2 P-b, #1728, #1733 and #1734 (merged): one `TenantIndexKeySet { active, retired }` per deployment (`--tenant-index-keys <dir>`), HKDF purpose subkeys over a closed label set (`tenant-binding` `tb`, `tenant-tag` `tt`, `subject-tag` `st`, `enterprise-subject` `esk`, `active-defense-digest` `ad`), rotation modes fixed per purpose (`tenant-tag` and `subject-tag`: all-generation match), `KeyedIndexValue { key_id, value }` and the exact string form `<prefix>1.<hex key_id>.<hex value>`. `derive` uses the active generation; verification selects by `key_id` and refuses an unknown one. | item 2 plan, Task 5, "Key set and provisioning" and "Purpose subkeys" (`8344047caa`) |
| F23 | #1728 P-g (merged): `esk = derive(EnterpriseSubject, "chio.enterprise-subject.v1" || 0x00 || len32(provider_scope) || provider_scope || len32(canonical_principal) || canonical_principal)`; one function replaces both `derive_enterprise_subject_key` copies, and F switches every producer. | item 2 plan, "Identity closure: P-g" |
| F24 | Item 1's `check-signing-exemptions.py` pins exempt sites by `(file, fn, ExemptFormat, count)`, including `(root_exchange/jws.rs, VerifyingKey::verify, JwsSigningInput, 1)`, `(remote_mcp/session_identity.rs, verify_ed25519_jwt_signature, JwsSigningInput, 1)` and the local AS signer in `oauth/helpers.rs`. Every Chio-operated signing endpoint accepts only pinned routes and carries the `remote_signing_*` tests. | item 1 plan lines 334-339, 374-392 |
| F14 | Item 5 Q4: with remote durable admission (`control_url`), target kinds other than `capability_id` cannot be linearized, because anchored roots live in the local state directory. If item 4 forbids remote durable admission under a root policy, the 409 path is deleted. | item 5 plan line 593 |
| F15 | `REMOTE-AUTHORITY-LIFECYCLE-BACKENDS` (owner decision, open). Remote clients of keyring-backed and seed-file-backed trust services cannot tell rotations apart (`issuer_state` is absent). The two options are (1) align keyring grace to 3600 s and persist the seed-file generation, then require `issuer_state`; or (2) refuse remote authority for those backends in v1. The decision is needed before the trust-control exchange signer. | `lead2/backlog.md:303` |
| F16 | `ITEM4-MOUNT-FOLLOWUPS` (arc-5b on #1709 r2):<br>1. Refuse `client_secret` alongside `private_key_jwt` (RFC 6749 section 2.3).<br>2. An empty duplicate parameter counts as a duplicate.<br>3. Return `scope` in the token response.<br>4. Reject an `idp_scope_projection` value without `/` at policy load.<br>5. Narrow the prepared-root body accessors when the sign path is wired. | `lead2/lanes.md:228` |

## Decisions

1. **`serve-http` has no remote store (F14, F20; O2, pending the owner).**
   - **Rule, flag-level and testable:** after PR E, `serve-http` refuses to start when `--control-url` or `--control-token` is set (`serve-http keeps every store in --state-dir; --control-url is not accepted`). Admission, receipts and their openings, budgets, revocations and anchored roots all open under `--state-dir` through one local serving writer. `control_url` and `control_token` are deleted from `RemoteServeHttpConfig` with every caller: the remote branches in `factory.rs` (`open_remote`, the receipt, revocation and budget store arguments, the remote authority at 229), `authority_mode.rs`, the admin forwarding at `admin.rs:777`, the health members `proxied`, `controlUrl`, `controlTokenConfigured`, `revocationsConfigured` and `budgetsConfigured`, and the two resume fingerprint members. `chio mcp serve`, `chio run` and `chio trust serve` keep `--control-url`.
   - **Before PR E:** `--control-url` drives for `serve-http` exactly the stores in F20. Nothing in PRs A to D2 changes that set or reads `--control-url`.
   - **O2:** the owner records the rule before PR E opens. Root-2 endorses it technically. If the owner refuses it, PR E holds and this plan is revised.
   - **Amendments that land in PR E, with the rule:**
     - item 5: delete the 409 row `revocation target kind requires the local admission store` (L456) and the 409 row for a missing local serving-owner store (L457, unreachable once startup requires the state directory); close Q4 as resolved by this decision; delete R8's trust-control forwarding for `serve-http`;
     - item 2: drop `serve-http` from the remote trust-control append (L420) and from the `receipt-openings:read` grant (L432); delete the A/E internal-read branch in `completed_result.rs` (its only host is `serve-http`; Task 0 confirms); E-k's remote path stays for `chio mcp serve` and `chio run`; `remote_store_*` tests keep only those hosts.
   - **The signer is a separate setting (lead decision):** `--exchange-signer trust-control:<url>` (Decision 11). It never reads `--control-url` or `--control-token`, and it never opens a store.
2. **The replay bind moves into the mint transaction.**
   - In part 1, preparation binds the ID-JAG replay key through `ExchangeReplayStore::bind`. In this plan, preparation records the replay key without binding it, and the mint transaction binds it together with the root insert, so a root exists exactly when its replay key is bound.
   - A signer failure before the transaction spends no exchange replay key.
   - A concurrent mint of the same assertion loses with `AssertionReplay`, and its signed root is never returned.
   - The client-assertion `jti` stays bound at client authentication, separately and intentionally, as part 1 does. A retry after `OutcomeUnknown` therefore carries a fresh client assertion with a new `jti`.
   - **Retry binding, persisted and projected:** each root row stores the authenticated `client_id`, the `artifact_digest` (SHA-256 of the presented assertion or token) and the `request_digest` (part 1's `IdJagGrant::request_digest`, or the kind's canonical request digest). All three are members of the authorization projection. A retry recovers the stored root only when the replay key, client, artifact digest and request digest all match; anything else refuses `AssertionReplay`.
   - Release follows the durable-owner protocol in Task A.
3. **Replay retention uses the maximum skew.** A replay row is retained until `exp + 60` (the load-time cap on `max_clock_skew_secs`), whatever the rule's own skew. A policy reload that raises the skew therefore cannot reopen a window (arc-5b P3-13 on #1709).
4. **The tenant tag for `oidc_jwt` and `entra_jwt` without a tenant claim.** A provider record always names `subject_mapping.tenant_id_field` (G17, enforced by the identity projection), so every provider-backed root has a tenant tag. `tenant_tag` is NULL only for `chio_operator_key` roots whose request names no tenant. `operator_static_bearer` rules require `tenant_value` at policy load, and `chio_local_as` uses the local AS tenant (Decision 5).
5. **`chio_local_as` identity.** The principal is the local AS subject (`auth_subject`, F1). The tenant value is the local AS issuer, under the fixed issuer `urn:chio:local-as`. `assertion_exp` equals the local access token's `exp`.
6. **`chio_operator_key` requests.** `POST /admin/roots` accepts a request body signed by a pinned operator key (`--operator-key`), carrying `request_id`, `principal`, `tenant_value` (optional), `scope`, `holder` and `expires_at`. The replay key is the request id, and the root's issuer string is `urn:chio:operator-key`. The signature uses item 1's wrapper under a new schema id, `chio.operator-root-request.v1`. PR D1, the first PR that verifies it, registers the id with its schema, its `wrapper_cases` vector and codegen (G11), and adds the operator-side signer `chio mcp root-request sign --operator-seed-file <path>`, which reads the request JSON on stdin and writes the signed request. PR C checks only the body shape. `POST /admin/authority` stops issuing capabilities; key rotation stays on its own route.
7. **No successful mint without a revocation checker.** `mint_anchored_root` takes a `&dyn MintRevocationCheck` bound to the open transaction. It has no default, no no-op implementation and no optional parameter. Item 5 PR 3 provides the only production implementation. Until it exists, no production caller of `mint_anchored_root` exists: PR E is the only caller, and item 5 PR 3 is a PR E predecessor. Tests use a checker that refuses or admits explicitly. PR A's additive schema, reads and replay store can land earlier, because none of them authorizes or mints.
8. **Root context openings are persisted under disclosure custody.**
   - **What is stored:** the salts of a root's delegation-context commitments (`anchor.sub`, `anchor.tenant` and every committed claim, F9's `ContextOpening`) go into `root_context_openings`.
   - **Table shape:** it has the same DDL checks and the same erasure-by-tombstone contract as item 2's `receipt_openings` (F18), keyed `(capability_id, salt_ref)`. The key namespace is separate from receipt ids, so a root opening is never read as a receipt opening.
   - **Atomicity:** the openings are inserted in the mint transaction.
   - **No plaintext:** only the salt is stored, never the opened value. The tenant knows its own principal and tenant value, so a `caller` bundle needs only the salt, and an `auditor_hash_only` bundle carries none (spec 9.4). Raw principal and tenant values are never written to any store row.
   - **Reads and erasure:** openings are read only through the scoped disclosure read that item 6 uses for the root's tenant, `context_openings(context_digest)`, which resolves the digest through the UNIQUE index on `anchored_roots.context_digest`. They are erased by `erase_root_openings(capability_id)`. After erasure the store never discloses the salts again, and the root stays valid. Erasure does not revoke a salt or opening already given to a party.
   - **Retention, with no foreign key:** `root_context_openings` has no FK to `anchored_roots`, because an erased tombstone must outlive a pruned root. The contract is enforced explicitly, and foreign keys stay on for every other table:
     - a `present` row exists only while its root row exists: the root prune transaction deletes the root's `present` rows and keeps its `erased` rows;
     - open validates the table and refuses `RootOpeningOrphaned { capability_id }` for a `present` row without a root row;
     - an insert for a `(capability_id, salt_ref)` that holds a tombstone refuses `RootOpeningErased`, so a salt is never resurrected, including by a later root reusing the id;
     - tombstones are not pruned in v1. Growth is one row per erased salt, and erasure is operator-initiated. `serve-http` state never replicates (Decision 12), so no cross-node horizon applies.
   - **Marker test scope:** the Review Focus 3 property test covers the ordinary state tables. The disclosure tables are protected storage and are checked separately for salts only, with no values.
9. **SCIM alias closure is coordinated with #1728 (P-g).** PR E deletes the `chio-mcp-remote` derivations (F5). The control-plane `derive_enterprise_subject_key` and the SCIM principal-hash aliases it produces close under #1728 (P-g), which is a named predecessor of PR E's identity closure. The Review Focus 5 grep is scoped to `chio-mcp-remote` and the `serve-http` CLI path, and does not claim the symbol vanishes repository-wide.
   - **P-g's `chio-mcp-remote` half:** merged #1728 keys both copies through one function (F23). PR E then deletes the `chio-mcp-remote` caller with `build_enterprise_identity_context`; the shared function stays for the control plane.
10. **Tags use item 2's shared tenant index key set (lead decision; #1728 and #1733, merged).**
   - **Scheme:** the one rotating `--tenant-index-keys <dir>` set, its HKDF purpose subkeys, `key_id` and `KeyedIndexValue`, and the rotation modes, exactly as `docs/superpowers/plans/2026-10-20-m1-item2-committed-receipts.md`, "Task 5: P-d, guard evidence declarations and the metadata key registry", paragraphs "Key set and provisioning" and "Purpose subkeys" (labels, key id and "Rotation modes"). This plan defines no derivation, flag or key file of its own.
   - **Values:** `tenant_tag` under the `tenant-tag` purpose (prefix `tt`) over `"chio.tenant-tag.v1" || 0x00 || issuer || 0x00 || tenant_value`; `subject_tag` under the `subject-tag` purpose (prefix `st`) over `"chio.subject-tag.v1" || 0x00 || issuer || 0x00 || principal`, where `principal` is the raw value of the record's `subject_mapping.principal_source` claim (item 5's admin request carries the same value). Inputs containing NUL refuse. The receipt tenant tag (PR A2) copies the root's `(key_id, value)`.
   - **Rotation, all-generation match** (the mode #1733 fixes for both purposes): the store keeps no plaintext, so stored tags are never re-derived.
     - New tags are derived under the active generation, and every stored tag carries its `key_id` (`anchored_roots.tag_key_id`, one per row because both tags of a root are derived together; `receipt_tenant_tags.tag_key_id`; item 5's tag-kind entries).
     - A lookup or revocation match computes the candidate tag from the plaintext it holds (the exchange evidence at mint; the admin request or `chio mcp revoke` stdin for a revocation) under every loaded generation, active and retired, and matches on `(key_id, value)`. Candidates come from `TenantIndexKeySet::derive_in(key_id, purpose, preimage)` over `key_ids()`, both in the item 2 key-set section (#1734); `derive_in` refuses an unknown `key_id` with `TenantIndexKeyUnknown`. So the mint check catches an entry recorded under an older generation, and a revocation fans out to roots tagged under any loaded generation.
     - **No path compares keyed values across generations without a preimage.** Every tag match recomputes candidates from plaintext the path holds. Paths without plaintext never match tags: admission, capture and the receipt checks read item 5's `revoked_capabilities` by capability id, which the revocation fan-out has already marked. A root minted under generation N and revoked after rotation to N+1 is caught by the fan-out (the admin plaintext gives candidates under N and N+1). A revocation recorded under N and a mint under N+1 is caught by the mint check (the exchange evidence gives candidates under N and N+1), so that root is never minted. Bearer reuse of an existing mapping and session-held tokens resolve to a root by id and reach the same `revoked_capabilities` read. Recovery (Task A step 3) reruns the mint check with the retry's evidence. No other path reads tags for authorization.
     - A retired generation stays loaded while any stored tag or entry references its `key_id`. Startup refuses `tenant index key does not match the state directory` when a referenced `key_id` is not loaded. A presented value under an unknown `key_id` refuses `TenantIndexKeyUnknown`.
   - **Item 5 amendment:** the fingerprint row and its HMAC domain `chio.tenant-index-key-fingerprint.v1` are dropped. A tag-kind entry id changes across a rotation: the same subject revoked again under a new generation records a second entry and reports `newly_revoked` again; both entries deny. Tag-kind entries store `key_id` beside the value. The target indexes become `(tag_key_id, subject_tag)` and `(tag_key_id, tenant_tag)`. The mint check and the fan-out match `(key_id, value)` over the candidates of every loaded generation. `startup_refuses_a_different_index_key` becomes PR A's `startup_refuses_a_missing_referenced_generation`, so item 5 PR 3 drops its copy and its 0.25 day.
11. **The trust-control exchange signer has its own route (lead decision; F21).**
   - **Configuration:** `--exchange-signer trust-control:<url>`, with `--exchange-signer-credential-file <path>` (a P-f `deployment` credential secret, mode 0600 and owned by the process user, scope `root-exchange:sign`; never `--control-token`) and `--exchange-signer-trusted-public-keys <hex,...>` (the rotating set of exchange keys trust-control may sign with, as `--control-authority-trusted-public-keys` is for the authority). Both are required with `trust-control:` and refused without it.
   - **Route:** `POST /v1/root-exchange/sign` on trust-control's public listener, `deployment` credential, scope `root-exchange:sign`, tenant authority Deployment only. P-f's credential rules apply unchanged, including the refusal of a credential of another deployment and of every `peer` credential. It forwards to the cluster leader and runs under the authority mutation fence and term check, as `/v1/capabilities/issue` does.
   - **Request, a closed tagged union** (`chio.root-exchange-sign-request.v1`, `deny_unknown_fields` at every level; any other `kind` refuses before parsing the body):
     - `{"kind": "anchored_root", "body": <unsigned capability body>, "delegation_context": <context>, "root_policy": <signed root policy>}`;
     - `{"kind": "idp_key_snapshot", "provider_record_id": <id>, "provider_identity_digest": <the edge's record digest>, "body": <unsigned IdP key snapshot body>}`.
     It never takes a message or bytes: trust-control canonicalizes the body itself and signs it through the artifact's own signing method under the id the kind fixes (`chio.capability.v1` or `chio.idp-key-snapshot.v1`). Typed data alone authorizes nothing; the checks below are the authorization.
   - **Response** (`chio.root-exchange-sign-response.v1`): `{"kind": <the request kind>, "schema": <that kind's signing id>, "artifact": <the signed artifact>}`. The edge accepts it only when `kind` and `schema` equal the request's, the artifact's canonical unsigned body is byte-equal to the body it sent, its signer field (`issuer` for a root, `exchange_key` for a snapshot) is in `--exchange-signer-trusted-public-keys`, and the signature verifies under that key. A cross-kind response, a substituted or altered body, or a signer outside the set refuses the mint.
   - **Checks before any signing call, each an exact refusal:**
     - `anchored_root`: `root_anchor` present and `check_root_consistency` passes; `issuer` is trust-control's current exchange key; `delegation_chain` empty; `root_policy` verifies against trust-control's pinned `--root-policy-key`, its digest equals `root_anchor.root_policy_digest`, and its `exchange_keys` contain `issuer`; the context's digest equals `root_anchor.context_digest`, its rule id names a rule of that policy, the body's scope hash equals the context's `effective_root_scope_hash` and the scope is within the rule's scope ceiling, and `expires_at` is at most `issued_at` plus the rule's TTL, the policy's `valid_until` and `root_anchor.assertion_exp`; `issued_at` is within 60 s of trust-control's clock. For a provider-backed kind, the context's `provider_record_id` names an enabled record in trust-control's provider registry and its `provider_identity_digest` equals that record's identity digest.
     - `idp_key_snapshot`: the body validates as `IdpKeySnapshot` fields (closed JWK set, `kid` grammar); `provider_record_id` names an enabled record in trust-control's provider registry, served to the caller's deployment, whose identity digest equals `provider_identity_digest`; the body's `issuer` equals the record's issuer; its `source` equals the record's trust material (the `jwks_url`, or the inline `jwks`, in which case `keys` must equal the record's keys exactly); `exchange_key` is trust-control's current exchange key; `observed_at` is within 60 s of trust-control's clock. The response's snapshot digest (`IdpKeySnapshot::digest()`) is what the edge records.
     - **Key rotation:** a root is only signable under a key the policy lists, so rotating trust-control's exchange key needs a re-signed root policy that lists the new key (and the edge's `--exchange-signer-trusted-public-keys` updated) before the new key signs; until then the route refuses `exchange key not in root policy`.
     - **Registry source:** trust-control's provider registry is the `chio.enterprise-providers.v1` file its own provider admin writes, loaded through `chio trust serve --enterprise-providers-file` and read once per request (G17). It is provisioned with the same records as the edge's registry; a record or identity digest that differs from the edge's refuses the request, so drift fails closed.
     - **Limitation, unchanged:** for a `jwks_url` source, trust-control signs the keys the edge observed; it does not fetch the JWKS itself. A signed snapshot is the provider's statement of what it observed, not independent IdP evidence.
   - **Item 1 pinned-route rule:** the route has no raw-byte or message path. `remote_signing_accepts_pinned_root_exchange_kinds` and `remote_signing_refuses_arbitrary_bytes` (raw bytes, a wrapper message, an unknown kind and a valid body under the other kind each refuse, and the backend records no signing call) live in D2.
   - **P-f:** `root-exchange:sign` joins the closed scope set, and the route table gains the row (`POST`, `/v1/root-exchange/sign`, public, deployment, `root-exchange:sign`, Deployment only) through `scope_rules.tsv` and a regenerated `routes-<rev>.tsv`. `REVIEW?` on item 2 P-f.
12. **`serve-http` receipts never leave the state directory.** After PR E there is no remote receipt store (Decision 1), and no trust-control or cluster node imports `serve-http` receipts. `receipt_tenant_tags` and `anchored_roots` exist only in a `serve-http` state directory. The trust-control cluster files (`cluster/snapshots.rs`, `cluster/partition.rs`) are therefore not touched, and nothing re-derives tags on import.
13. **`serve-http` identity after PR E.**
   - Item 4 adds no receipt metadata key.
   - Sessions carry the stored root's capability id and its `DelegationContext` commitments. `enterprise_identity` is deleted from the `serve-http` session (`bearer_auth.rs:553-581`, `session_core.rs:663`), and no plaintext principal or tenant is held past the exchange.
   - `attribution.subject_key` on an anchored session's receipts is the root capability's `subject` public key (the session-held or caller-held Ed25519 key, spec 6.5). It is a real key in P-g's census classes, not a derived enterprise identifier. Enterprise principal joins use `subject_tag`, which never appears on a receipt.
   - Task 0 of PR E checks against the reserved-key registry that nothing `serve-http` still writes becomes unregistered.

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
    - `serving_owner.rs` (the new tables and a read-only accessor for the synced authority anchor's covered sequence, if Task 0 finds none), `serving_owner/global_commit_chain.rs`;
    - the v1 catalog registration that the schema cleanup names.
  - **PR A2's exact held-file list** (the receipt tenant tag and root retention with receipts):
    - `receipt_store/append.rs`, `receipt_store/strict_append.rs`, `receipt_store/support/store_impl.rs`;
    - `receipt_store/evidence_retention.rs`, `receipt_store/evidence_retention/dispatch.rs`, `receipt_store/support/retention_watermark.rs`.
    - The trust-control cluster files are not touched (Decision 12).
  - **Order against item 2:** item 2 P-c and F edit `append.rs`, `strict_append.rs` and the retention files. PR A touches none of them and may land before both. PR A2 lands after F (and so after P-c), on F's append and tenant rule, and before PR E.
  - SQLite `admission_operation_store` (PR E admission-time root lookup, if it reads there);
  - `chio-http-core/src/receipt.rs` (not touched);
  - `chio-control-plane/src/evidence_export/verification.rs` (not touched).
- **Shared surfaces:** a PR that touches `chio-core-types`, `chio-control-plane`, `spec/PROTOCOL.md`, `spec/schemas/registry.json` or `spec/errors/registry.yaml` posts `REVIEW? #N` on `sync.md`. Core-types, store and control-plane source merges follow the MERGING window.
- **New hash and HMAC domains** are registered in `scripts/check-domain-separation.py`:
  - `chio.anchored-root-projection.v1`
  - `chio.tenant-tag.v1` and `chio.subject-tag.v1`, the value domains of Decision 10 (PR A; item 2 names the labels, not these domains)
  - `chio.root-exchange.bearer-token.v1`, the token-digest domain.
- **Exempt signing sites (F24):** all local AS JWT signing stays in `oauth/helpers.rs::sign_jwt`. Local AS tokens and every EdDSA bearer JWT are verified only through `root_exchange/jws.rs::VerifyingKey::verify`, the allowlisted site, so PR C adds no exempt site. PR E deletes `session_identity.rs::verify_ed25519_jwt_signature` and its allowlist entry in the same commit. A PR that lands after item 1 and moves, adds or removes an exempt call updates the allowlist in that commit.
- **New error codes** are registered in `spec/errors/registry.yaml` under `transport` (exchange), `capability` (admission) and `policy` (load) (G12). The codes come from the staged verdict-matrix scenarios under `docs/superpowers/specs/relying-party-wedge/verdict-matrix/anchored_root/`.

## Review focus

1. **A root that exists without its replay key bound, or the reverse, or a root returned before it is durable.**
   - Expected: one IMMEDIATE transaction binds the replay key and inserts the root, so a failure of either rolls back both.
   - A root is returned only when the owner's synced authority anchor covers its global commit; no request path, including a concurrent first sight, returns a root that is committed but not yet covered.
   - A post-commit anchor-sync failure is `OutcomeUnknown`, never a definite refusal and never a retried fresh mint.
   - A committed root without its global commit is corruption: open refuses and every row is kept.
   - Pinned in PR A by `mint_rolls_back_root_when_replay_bound`, `mint_rolls_back_replay_when_root_insert_fails`, `anchor_sync_failure_reports_outcome_unknown`, `retry_after_unknown_recovers_the_committed_root`, `crash_after_commit_before_anchor_sync_recovers_after_reopen`, `concurrent_first_sight_never_returns_an_uncovered_root` and `committed_root_without_global_commit_refuses_open_and_keeps_rows`.
2. **A bearer token mapped to two roots, or a second token reusing a replay key.** Expected: `bearer_token_roots.token_digest` is the primary key. Exchange refuses a second root while the first is live (Entra one root per `uti`, D5). A different token with a bound replay key refuses `AssertionReplay`. Pinned in PR C and PR E.
3. **Plaintext principal, tenant or token in the state directory or logs.** Expected: ordinary state tables hold only tags, digests and salted commitments, and the static bearer token is held as a SHA-256 in memory only. The disclosure tables (`root_context_openings`, item 2's `receipt_openings`) are protected storage and hold salts only, never opened values (Decision 8). Pinned by a marker property test that scans every ordinary table and the tracing output, and a second test that the disclosure tables carry 32-byte salts and no marker value (PR E).
4. **A provider identity that changed without a re-signed policy.** Expected: exchange and admission each load the registry once per request and refuse a record whose recomputed identity digest differs from the rule's (G17). Pinned by the moved staged scenarios 017 to 021 (PR E).
5. **A deleted path still reachable.** Expected: after PR E, `git grep` scoped to `crates/protocol/chio-mcp-remote` and the `serve-http` CLI path (`chio-cli/src/cli/{types.rs,types/runtime.rs,dispatch/api_mcp.rs,runtime.rs}`) finds no:
  - `configure_session_capability_authority`, `derive_federated_agent_keypair` or `derive_enterprise_subject_key`;
  - `JwtProviderProfile`, `auth_jwt_public_key`, `auth_jwt_discovery_url`, `auth_jwt_issuer`, `auth_jwt_audience` or `auth_introspection_url`;
  - `receipt_db_path`, `revocation_db_path`, `authority_db_path`, `budget_db_path` or `session_db_path` in `chio-mcp-remote` and the `serve-http` CLI path;
  - `control_url`, `control_token` or `open_remote` in `chio-mcp-remote` (Decision 1).
  The control-plane `derive_enterprise_subject_key` is outside the grep and closes under #1728 (P-g) (Decision 9). Pinned by a grep step in Task E-final and by the conformance peers running on `--state-dir`.
6. **An authorization field changed after mint.** Expected: the global commit binds the canonical authorization projection: every authorization column of the root row and the digests of its blobs. Reading or opening a row recomputes the projection and refuses a mismatch. Pinned in PR A by one mutation test per column (`root_policy_rule_id`, `tag_key_id` (including replacement with another loaded generation), `subject_tag`, `tenant_tag`, `replay_key_digest`, `replay_bound_at`, `client_id`, `artifact_digest`, `request_digest`, `expires_at`, `holder`, `anchor_kind`, `root_policy_digest`, `provider_identity_digest`, `key_snapshot_digest`, `context_digest`, the context blob and the capability blob).
7. **A receipt relabeled to another tenant.** Expected: tenant export reads each tag row with its exact signed receipt and refuses unless the verified receipt's root capability id equals the row's, and the row's tag equals that root's projection-checked tag. Pinned in PR A2 by `swapping_root_id_and_tag_together_refuses_tenant_export`.

## File structure

| Path | PR | Responsibility |
|---|---|---|
| `crates/platform/chio-store-sqlite/src/root_exchange_store.rs` (new) and `root_exchange_store/{schema,mint,replay,bearer,retention,tenant_index,openings,projection}.rs` | A | tables, the mint transaction and release protocol, `ExchangeReplayStore`, `KeySnapshotSink`, retention by digest, root openings, the authorization projection |
| `receipt_store/{append.rs,strict_append.rs,evidence_retention.rs,evidence_retention/dispatch.rs,support/retention_watermark.rs,support/store_impl.rs}` | A2 | the receipt tenant tag, derived in the append transaction and retained with receipts; root retention joined to receipt retention (Root-held list) |
| `crates/platform/chio-store-sqlite/src/serving_owner.rs`, `serving_owner/global_commit_chain.rs` | A | register the store with the serving owner; `projection_kind = 'anchored_root'` (Root-held) |
| `crates/core/chio-core-types/src/rng.rs` (from #1726) | B | consumer only |
| `crates/core/chio-core-types/src/root_authority/root_policy.rs` | B | projection value must contain `/` at load (F16 item 4) |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/{exchange,grant,client_auth}.rs` | B, C, E | entropy migration, mount follow-ups, `AnchorEvidence` generalization |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/kinds/{oidc_jwt,entra_jwt,introspection,static_bearer,local_as,operator_key}.rs` (new) | C | one verifier per kept kind |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/root_exchange/signer.rs` (new), `idp_keys/source.rs` (#1713, its `ExchangeSigner` moves here) | D1, D2 | `ExchangeSigner`: seed file (D1), trust-control client (D2) |
| `crates/products/chio-cli/src/cli/dispatch/root_request.rs` (new) and its `types.rs` subcommand | D1 | `chio mcp root-request sign` |
| `crates/platform/chio-control-plane/src/trust_control/root_exchange_signing.rs` (new), `service_types/paths.rs`, `service_runtime/router.rs`, `json_ingress.rs`, `service_runtime/client/operations.rs`, `service_types/config.rs` (pinned `--root-policy-key`, current exchange key); `chio trust serve` flags in `chio-cli`; the P-f `scope_rules.tsv` and regenerated route table | D2 | `POST /v1/root-exchange/sign`; `REVIEW?` on `chio-control-plane` and item 2 P-f |
| `crates/protocol/chio-mcp-remote/src/remote_mcp/oauth/{local_server,bearer_auth}.rs`, `http_service.rs`, `http_service_auth.rs`, `session_core.rs`, `session_core/factory.rs`, `session_identity.rs`, `session_resume.rs`, `admin.rs`, `enterprise_provider_registry.rs` | E | mount, admission resolution, deletions |
| `crates/platform/chio-control-plane/src/enterprise_federation.rs`, trust-control provider admin and tests | E | delete `provider_profile`; optional inline `jwks` on `oidc_jwks` records |
| `crates/products/chio-cli/src/cli/{types.rs,types/runtime.rs,dispatch/api_mcp.rs,runtime.rs}` and the `serve-http` tests | E | flags in and out; startup refusals |
| `examples/**`, `deploy/**`, `scripts/check-sdk-publication-examples.sh`, `scripts/check-sdk-release.sh`, `scripts/acceptance/session-credentials.py`, the conformance peers (`chio-conformance/src/runner.rs` and the cpp, js, go and python peers), the progressive tutorial, `docs/reference/IDENTITY_FEDERATION_GUIDE.md`, `docs/release/OPERATIONS_RUNBOOK.md` | E | callers move to `--state-dir`, a root policy file and provider records |
| `crates/tooling/chio-conformance/verdict_matrix/scenarios/anchored_root/` (moved from staging), `SCENARIOS.md`, `manifest.toml` | E | 24 scenarios live |
| `spec/schemas/registry.json` and `KNOWN_SIGNED_ARTIFACT_SCHEMAS` (operator root request), `spec/schemas/chio-wire/v1/root_authority/operator-root-request.schema.json` (new), the item 1 `wrapper_cases` vector, codegen | D1 | operator root request registration |
| `spec/schemas/chio-wire/v1/root_authority/root-exchange-sign-{request,response}.schema.json` (new), their `registry.json` rows | D2 | sign route request and response |
| `spec/errors/registry.yaml`, `scripts/check-domain-separation.py`, `scripts/check-signing-exemptions.py` allowlist (E), `spec/PROTOCOL.md` (5.6 status line) | A, C, D1, D2, E | registrations |

## PR slicing and order

| PR | Title | Depends on | Signs? | Size (days) |
|---|---|---|---|---|
| A | `feat(store): root exchange state: replay keys, anchored roots, bearer roots, snapshots and openings` | #1706, #1709, #1713, item 2 P-b (`TenantIndexKeySet`), Root-2's store queue and the serial schema-adoption cleanup | no | 5.5-7 |
| A2 | `feat(store): receipt tenant tags and root retention with receipts` | A, item 2 F (and so P-c) | no | 1.5-2 |
| B | `refactor(mcp-remote): exchange entropy from the core Rng seam and token request follow-ups` | #1726 (P-a), #1709 | no | 1-1.5 |
| C | `feat(mcp-remote): verify the kept anchor kinds into one exchange` | #1709, #1713, B | no | 6-8 |
| D1 | `feat(mcp-remote): seed-file exchange signer and signed operator root requests` | item 1 | yes (item 1 wrapper) | 2-2.5 |
| D2 | `feat(trust-control): sign edge-built anchored roots and key snapshots` | D1, item 2 P-f, the O1 owner decision | yes (item 1 wrapper) | 3.5-4.5, plus 1.5-2.5 under O1 option 1 |
| E | `feat(mcp-remote): mount the root exchange in serve-http and delete the bypass paths` (one PR, or a stacked series merged in one MERGING window, L2) | A, A2, C, D1, item 3 part 2 (`root_anchor` in the signed body), item 5 PR 3 merged (the production revocation checker), #1728 P-g (SCIM alias closure), the O2 owner decision, the spec amendment | yes | 11-15 |

PRs A, A2, B and C sign nothing, but only B and C may land before item 1: PR A waits for item 2 P-b, and A2 for item 2 F, and item 2 orders P-a to P-d and F after item 1. Item 5 PR 3 waits for PR A, so it moves with A on the M1 path. PR A authorizes and mints nothing in production; `mint_anchored_root` has no production caller before PR E (Decision 7). PR D1 waits for item 1, because the signers sign through the wrapper. Only PR D2 waits for O1, so O1 gates neither PR E nor item 6 6c. PR E waits for item 3 part 2: a root is only issuable with `root_anchor` inside the signed capability body, and item 3 part 2 also returns the anchored-root resolver that admission calls. PR E is the only PR that mounts anything, and it carries every section 2.4 deletion, so `main` never has two issuance paths.

If PR E lands before D2, `serve-http` accepts only `--exchange-signer seed-file:<path>` until D2, and PR E moves the trust-control callers of F20 (the reference-runtime unit, the SDK publication script, the example networks) to a seed file. D2 then adds `trust-control:` with its own caller updates. This is a feature not yet present, never a second path.

**O1 option 1 work (D2, only if chosen):** keyring grace aligned to 3600 s, a persisted seed-file generation, and deletion of the `None` branch in `remote_authority/lifecycle.rs` (backlog L303), in `chio-control-plane` and `chio-keyring`, owned by this lane with `REVIEW?` to Root-2. Under either option the edge-side check is the same, a status without `issuer_state` refuses, so `trust_control_without_lifecycle_state_refuses` is one test under both.

The planning total is 30.5-40.5 days for parts 2 onward, or 32-43 under O1 option 1. Against r2 (26-35.5): D grows from 2-3 to 5.5-7 (D1 with the operator request registration and signer, and D2 with the new route and trust-control's provider registry), and A with A2 grows from 6-8 to 7-9 (the DDL checks, the extra reads and the receipt-bound tag read). Part 1 (#1709) took about 5, so item 4 as a whole sits at 35.5-45.5, up to 7.5 days above 13.2's 27-38 (up to 10 under option 1). Waiting time is not counted: items 1, 2 P-b, 2 F and 3, item 5 PR 3, #1728, Root-2's store queue, the schema cleanup, and the O1 and O2 decisions.

## Tasks

### Task 0: Census and preconditions (every PR)

- [ ] **Step 1:** `gh pr view <N> --repo bb-connor/arc --json state` for every predecessor in the PR's row. A missing predecessor holds the PR; it does not reorder.
- [ ] **Step 2:** Re-read every fact row this PR cites at its base, and record any drift in the PR body.
- [ ] **Step 3:** For PR A, PR A2 and PR E, post the Root-held file list on `sync.md` and wait for Root-2's ACK. For D2, post `REVIEW?` for `chio-control-plane` and item 2 P-f.

### Task A: Root exchange store (PR A and PR A2)

**Schema** (schema key `root_exchange`, version 1, in the state-directory database, opened only through the serving owner, under the fresh-only v1 catalog contract that the serial schema-adoption cleanup establishes; open validates the catalog and refuses any other layout). The checks follow item 2's `receipt_openings` bar. `HEX64(c)` below stands for `typeof(c) = 'text' AND length(c) = 64 AND c NOT GLOB '*[^0-9a-f]*'`, written out in the DDL. Every TEXT column also carries `instr(c, char(0)) = 0`, and every BLOB column `typeof(c) = 'blob'`; they are omitted below for length.

```sql
CREATE TABLE exchange_replay (
  replay_key_digest TEXT PRIMARY KEY CHECK (HEX64(replay_key_digest)),  -- ReplayKey::digest()
  namespace TEXT NOT NULL CHECK (namespace IN (<the eight AnchorKind values>, 'client_assertion')),
  bound_at INTEGER NOT NULL CHECK (typeof(bound_at) = 'integer'),
  retain_until INTEGER NOT NULL CHECK (typeof(retain_until) = 'integer' AND retain_until > bound_at),  -- exp + 60
  capability_id TEXT CHECK ((namespace = 'client_assertion') = (capability_id IS NULL))  -- the root this binding issued; no FK (the root may outlive the row, never the reverse)
);
CREATE INDEX exchange_replay_retain ON exchange_replay(retain_until);

CREATE TABLE anchored_roots (
  capability_id TEXT PRIMARY KEY,
  root_policy_rule_id TEXT NOT NULL,
  subject_tag TEXT NOT NULL CHECK (HEX64(subject_tag)),
  tenant_tag TEXT CHECK (tenant_tag IS NULL OR HEX64(tenant_tag)),
  tag_key_id TEXT NOT NULL CHECK (HEX64(tag_key_id)),      -- generation key_id of both tags
  replay_key_digest TEXT NOT NULL CHECK (HEX64(replay_key_digest)),
  replay_bound_at INTEGER NOT NULL CHECK (typeof(replay_bound_at) = 'integer'),  -- exchange_replay.bound_at of the binding that issued this root
  client_id TEXT NOT NULL,                 -- authenticated client (retry binding)
  artifact_digest TEXT NOT NULL CHECK (HEX64(artifact_digest)),
  request_digest TEXT NOT NULL CHECK (HEX64(request_digest)),
  expires_at INTEGER NOT NULL CHECK (typeof(expires_at) = 'integer'),
  anchor_kind TEXT NOT NULL CHECK (anchor_kind IN (<the eight AnchorKind values>)),
  holder TEXT NOT NULL CHECK (holder IN ('edge_session','caller')),
  root_policy_digest TEXT NOT NULL CHECK (HEX64(root_policy_digest)),        -- RootPolicy::digest()
  provider_identity_digest TEXT CHECK (provider_identity_digest IS NULL OR HEX64(provider_identity_digest)),
  key_snapshot_digest TEXT CHECK (key_snapshot_digest IS NULL OR HEX64(key_snapshot_digest)),
  context_digest TEXT NOT NULL UNIQUE CHECK (HEX64(context_digest)),        -- DelegationContext::digest()
  delegation_context BLOB NOT NULL,        -- canonical JSON
  root_capability BLOB NOT NULL,           -- canonical JSON of the signed root
  minted_at INTEGER NOT NULL CHECK (typeof(minted_at) = 'integer' AND minted_at < expires_at),
  authorization_projection_digest TEXT NOT NULL CHECK (HEX64(authorization_projection_digest))
);
-- indexes on root_policy_rule_id, (tag_key_id, subject_tag), (tag_key_id, tenant_tag), tag_key_id and replay_key_digest (F12, Decision 10);
CREATE UNIQUE INDEX anchored_roots_replay_binding ON anchored_roots(replay_key_digest, replay_bound_at);  -- one root per replay binding

CREATE TABLE bearer_token_roots (
  token_digest TEXT PRIMARY KEY CHECK (HEX64(token_digest)),  -- SHA-256("chio.root-exchange.bearer-token.v1\0" || token)
  capability_id TEXT NOT NULL REFERENCES anchored_roots(capability_id),
  retain_until INTEGER NOT NULL CHECK (typeof(retain_until) = 'integer')  -- max(root expires_at, token exp) + 60
);

CREATE TABLE idp_key_snapshots (
  snapshot_digest TEXT PRIMARY KEY CHECK (HEX64(snapshot_digest)),  -- IdpKeySnapshot::digest()
  issuer TEXT NOT NULL,
  observed_at INTEGER NOT NULL CHECK (typeof(observed_at) = 'integer'),
  snapshot BLOB NOT NULL                   -- canonical JSON, signed
);

CREATE TABLE retained_root_policies (
  root_policy_digest TEXT PRIMARY KEY CHECK (HEX64(root_policy_digest)),  -- RootPolicy::digest()
  policy BLOB NOT NULL                     -- canonical signed JSON
);

CREATE TABLE retained_provider_identities (
  provider_identity_digest TEXT PRIMARY KEY CHECK (HEX64(provider_identity_digest)),  -- ProviderRecord::identity_digest()
  identity BLOB NOT NULL                   -- canonical chio.enterprise-provider-identity.v1
);

CREATE TABLE root_context_openings (       -- disclosure custody; no FK: erased tombstones outlive their root
  capability_id TEXT NOT NULL,
  salt_ref TEXT NOT NULL,                  -- SaltRef grammar: anchor.sub, anchor.tenant, anchor.claims.<name>
  state TEXT NOT NULL CHECK (state IN ('present','erased')),
  salt BLOB CHECK ((state = 'present' AND typeof(salt) = 'blob' AND length(salt) = 32)
                OR (state = 'erased' AND salt IS NULL)),
  state_at INTEGER NOT NULL CHECK (typeof(state_at) = 'integer'),
  PRIMARY KEY (capability_id, salt_ref)
);

```

PR A2 adds, under the same rules:

```sql
CREATE TABLE receipt_tenant_tags (
  artifact_kind TEXT NOT NULL CHECK (artifact_kind IN ('tool','child')),
  receipt_id TEXT NOT NULL,
  root_capability_id TEXT NOT NULL REFERENCES anchored_roots(capability_id),
  tag_key_id TEXT NOT NULL CHECK (HEX64(tag_key_id)),
  tenant_tag TEXT CHECK (tenant_tag IS NULL OR HEX64(tenant_tag)),  -- (key_id, value) copied from anchored_roots, never from the request
  PRIMARY KEY (artifact_kind, receipt_id)
);
CREATE INDEX receipt_tenant_tags_tag ON receipt_tenant_tags(tag_key_id, tenant_tag);
```

Every digest column is lowercase hex of a `Sha256Digest`; reads decode it to `Sha256Digest` and refuse a row that does not decode. The catalog validation and the CHECKs are probed with `/usr/bin/sqlite3` on the DDL as item 2 did (`EXPLAIN` of each read, and one rejected insert per CHECK), recorded in the PR body.

- **Mint and release protocol.** `mint_anchored_root(MintRequest, &dyn MintRevocationCheck) -> MintOutcome`. The exchange signs the root before the call (PR E). Steps:
  1. Open an IMMEDIATE transaction through the serving writer; the serving-owner fence and authority-anchor checks run at begin, as for every serving write.
  2. Run the transaction-bound revocation check (Decision 7) over the root's rule id, replay key and candidate tags under every loaded generation (Decision 10). A match refuses with the item 5 entry id. A checker error rolls back and denies.
  3. Bind the replay key. An existing unexpired binding is resolved in this order:
     - the live binding names its root (`exchange_replay.capability_id`); that root, and only that root, is a recovery candidate when its `client_id`, `artifact_digest` and `request_digest` all equal the request's: the transaction rolls back its own rows and goes to Release with it. Recovery never looks a root up by replay key alone, so a retained historical root is never selected;
     - anything else refuses `AssertionReplay`.
     For bearer intake the client is the fixed value `bearer_intake`, so concurrent first sights of one token take the recovery branch.
  4. Insert the `anchored_roots` row with its retry binding, `replay_bound_at` equal to the new binding's `bound_at`, and `authorization_projection_digest`; the replay row records the root's `capability_id`.
     **Replay keys are rebindable after retention.** Once a binding passes `retain_until` and is pruned, the same replay key may bind again (the artifact it came from is past `exp`, so only a new authenticated artifact can present it). The new root gets a new `replay_bound_at`, so it never collides with a retained old root, and item 5's `replay_key` revocation, which matches `replay_key_digest`, covers both.
  5. Insert the root's `root_context_openings` rows (Decision 8).
  6. For bearer intake, insert or replace the `bearer_token_roots` row under the per-kind rules in Bearer expiry.
  7. Insert the retained policy, provider identity and key snapshot rows by verified digest (Retention by digest).
  8. Append one global commit. Its reference digest is the `authorization_projection_digest`, under a proposed `projection_kind = 'anchored_root'` that needs Root-2's review.
  9. COMMIT, then `sync_authority_anchor`.
- **Release, derived from durable state.** There is no `release_state` column and no write after COMMIT. A root is returnable when:
  - its row passes the row check on read;
  - its global commit is present in the verified chain with projection coverage (`global_commit_chain.rs`);
  - the owner's synced authority anchor covers that global commit's sequence.
  A root that is committed but not yet covered is never returned, from any path: the token endpoint and bearer intake answer 503 `temporarily_unavailable` with no description, and admission refuses. A retry after the anchor sync completes gets the root through step 3.
- **Outcome rules:**
  - **Definite refusal (rolled back before COMMIT):** a revocation match, `AssertionReplay`, a constraint or digest failure, or a definite commit failure. No replay key is bound and nothing is returned.
  - **`OutcomeUnknown`:** a failure after COMMIT, during the anchor sync, poisons the serving owner (F17). The token endpoint answers 503 `temporarily_unavailable` with no description.
    - The outcome is never reported as "replay unspent", and the request is never retried as a fresh mint.
    - The owner's existing reopen path verifies the chain head, references and projection coverage against the authority anchor (F17). This plan adds no repair or adoption path.
    - **Corruption:** a root row whose global commit is absent from the verified chain cannot come from a crash, because steps 3 to 8 share one SQL transaction. Open refuses `AnchoredRootWithoutGlobalCommit { capability_id }` and keeps every row, including the replay binding.
    - A client that retries the same assertion, with a fresh client assertion, gets the stored root through step 3 once it is returnable.
  - **Recovery runs the current authorization checks.** A root returned through step 3 must still be unexpired (`now < expires_at`), pass the revocation check of step 2 in the same transaction, name the loaded policy's digest, and, for provider-backed kinds, match the registry record's current identity digest. Otherwise the request refuses with the same error a fresh mint would get.
  - **Signer failure:** a failure before step 1 spends no exchange replay key. The client-assertion `jti` is spent at client authentication, by design.
- **Authorization projection.** The canonical JSON of:
  - `capability_id`, `root_policy_rule_id`, `tag_key_id`, `subject_tag`, `tenant_tag`, `replay_key_digest`, `replay_bound_at`, `expires_at`, `holder` and `anchor_kind`;
  - the retry binding: `client_id`, `artifact_digest` and `request_digest`;
  - `root_policy_digest`, `provider_identity_digest`, `key_snapshot_digest` and `context_digest`;
  - `SHA-256(delegation_context)`, `SHA-256(root_capability)` and `minted_at`.
  `authorization_projection_digest` is the SHA-256 of that JSON under the domain `chio.anchored-root-projection.v1`.
- **Row check on read.** Every read that authorizes, revokes, recovers or exports recomputes the projection digest and checks it against the row and against the global commit chain. It also checks that:
  - the stored capability decodes;
  - its `id`, `issuer`, `expires_at` and scope hash agree with the row and with the context's `effective_root_scope_hash`;
  - the context digest recomputes, and the context's `artifact_digest`, `request_digest` and `replay_key_digest` equal the row's.
  A mismatch refuses (`AnchoredRootTampered { capability_id }`).
- **Retention by digest.** `retained_root_policies`, `retained_provider_identities` and `idp_key_snapshots` take canonical bytes and recompute the digest from them; a supplied digest is never trusted. The digest functions are `RootPolicy::digest()` (the value in `root_anchor.root_policy_digest`), `ProviderRecord::identity_digest()` and `IdpKeySnapshot::digest()`; `context_digest` is `DelegationContext::digest()`.
  - Insert-if-absent with identical bytes is a no-op.
  - Different bytes under an existing digest refuse `RetainedDigestMismatch`, and so does a supplied digest that differs from the recomputed one.
  - Reads re-verify the digest of the bytes they return and refuse a mismatch with `RetainedDigestMismatch`.
- **Replay keys.** `ExchangeReplayStore` for the client-assertion `jti` is a separate, single-statement IMMEDIATE transaction (Decision 2). Exchange replay keys are bound only inside step 3.
- **Bearer expiry, per kind.** One live root per token holds under concurrent first sight: the second transaction takes step 3's recovery branch and returns the existing root only once it is returnable, else 503 (Release). A mapping whose root names a policy digest other than the loaded policy is not live.

  | Kind | Before the root expires | After root expiry, mapping present | After the mapping is pruned |
  |---|---|---|---|
  | `entra_jwt`, `oidc_jwt` with `jti` | the mapped root | 401 `invalid_token` (the replay key `(issuer, uti or jti)` stays bound until `exp + 60`) | the token is itself past `exp`, so its verifier refuses `AssertionExpired`: also 401 `invalid_token` |
  | `oidc_jwt` without `jti`, `oauth_introspection` | the mapped root | 401 `invalid_token` (the replay key is the token digest, bound until `exp + 60`) | as above |
  | `operator_static_bearer` | the mapped root | a fresh root, minted in one transaction that replaces the mapping; the replay key includes the new `expires_at` | a fresh root, through the same transaction |

  - **Mapping retention:** a mapping row is retained until `retain_until = max(root expires_at, token exp) + 60` and then pruned. Pruning therefore never changes the answer for a token that a verifier still accepts.
- **Root retention.** In PR A no `anchored_roots` row is pruned; nothing mints in production before PR E. PR A2 adds the rule: a row and its `present` openings are retained while the root is live (`expires_at > now`), whether or not a receipt references it. After expiry they are retained while any receipt, custody record or revocation entry references the root, and they are pruned only when the root is expired and unreferenced, in the same transaction as the receipt prune that removes the last reference. The same transaction deletes the root's expired `bearer_token_roots` rows; a mapping still inside its `retain_until` counts as a reference. Admission refuses at `now >= expires_at` (half-open). Erased tombstones outlive the root (Decision 8).
- **Snapshots.** `KeySnapshotSink` (#1713) writes `idp_key_snapshots` by verified digest in its own transaction, before #1713 installs the new key set.
- **Reads for item 6** (F13): plain inherent methods of `SqliteRootExchangeStore`, with the exact signatures in item 6's Task 8 Interfaces block. chio-store-sqlite cannot implement a chio-control-plane trait (control-plane depends on it), so there is no trait; chio-control-plane's export code calls these methods. Each returns `chio-core-types` types and a typed `RootExchangeStoreError` missing-row variant, never `Option`:
  - `presentation(root_capability_id: &str) -> Result<CapabilityPresentation, RootExchangeStoreError>`: the projection-checked stored root and its delegation context; a missing row is `AnchoredRootMissing { capability_id }`, the variant item 5's `RevocationStoreError` also carries;
  - `delegation_context(digest: &Sha256Digest) -> Result<DelegationContext, RootExchangeStoreError>`: through the UNIQUE `context_digest` index, projection-checked;
  - `root_policy`, `provider_identity`, `idp_key_snapshot` by `&Sha256Digest`, returning `RootPolicy`, `EnterpriseProviderIdentity` and `IdpKeySnapshot`; a missing row is a typed variant that item 6 maps to `attest:export-evidence-incomplete`;
  - `context_openings(context_digest: &Sha256Digest) -> Result<ContextOpenings, RootExchangeStoreError>`: disclosure-scoped, present, erased or unknown;
  - `receipts_for_tenant(tags: &[KeyedIndexValue], query: &EvidenceExportQuery) -> Result<Vec<EvidenceToolReceiptRecord>, RootExchangeStoreError>`: PR A2. The set holds one `KeyedIndexValue` per loaded generation (`key_ids()` with `derive_in(TenantTag, ..)` over the caller's issuer and tenant value), and the read selects every row whose `(tag_key_id, tenant_tag)` is in it, so an export after a rotation includes receipts tagged under retired generations.
- **Tenant index.** `TenantIndex::open(&TenantIndexKeySet, store)` checks at open that every `key_id` referenced by `anchored_roots`, `receipt_tenant_tags` or item 5's tag-kind revocation entries is loaded (a generation referenced only by a revocation entry counts), and refuses `tenant index key does not match the state directory` otherwise (Decision 10). It exposes `derive_tags(issuer, subject, tenant)` under the active generation and `candidate_tags(issuer, subject, tenant)` under every loaded generation for matching, through `TenantIndexKeySet::derive` and `derive_in` (Decision 10), and refuses NUL in any input.

**PR A2: receipt tenant tag (R1, Root-2: side table).** `receipt_tenant_tags` is authoritative derived state in the `serve-http` state directory only (Decision 12).
  - **How it is written:** only the serving-owner receipt append transaction writes it, on item 2 F's append (F19). That transaction reads the receipt's root capability id from the verified receipt's capability chain (in M1 the chain depth is 0, so it is the receipt's `capability_id`), reads `tenant_tag` from the projection-checked `anchored_roots` row, and writes it.
  - **No other writer:** no caller metadata, request field or separate tagging API writes it, and no import path exists (Decision 12).
  - **Keying:** the key is `(artifact_kind, receipt_id)`, so tool and child receipt id namespaces cannot collide. Task 0 also checks that receipt ids are unique within each kind.
  - **Read binding:** `receipts_for_tenant` reads each tag row together with its stored signed receipt, verifies the receipt, and accepts the row only when the verified receipt's root capability id equals `root_capability_id` and the full pair `(tag_key_id, tenant_tag)` equals that root's projection-checked pair. Changing both columns together to another valid root, or the `key_id` alone to another loaded generation, therefore refuses.
  - **Retention:** receipt retention deletes the tag row with its receipt, and prunes expired unreferenced roots (Root retention).
  - **Fail closed:** a receipt without a tag row, a row that fails the read binding, or a tag row for an unknown receipt refuses tenant export (`ReceiptTenantTagMissing`, `ReceiptTenantTagConflict`). It never broadens the selection.

- [ ] **Step 1: Failing tests** in `root_exchange_store/tests.rs` (joint serving-owner fixture, fixed `ClockScope`). Every refusal is pinned to its exact error.
  - Atomicity and protocol:
    - `mint_inserts_root_replay_openings_and_bearer_mapping_atomically`
    - `mint_rolls_back_root_when_replay_bound`
    - `mint_rolls_back_replay_when_root_insert_fails`
    - `mint_requires_a_revocation_checker` (a compile-time signature, plus `refusing_checker_denies_with_entry_id` and `checker_error_rolls_back`)
    - `anchor_sync_failure_reports_outcome_unknown`
    - `commit_failure_is_a_definite_refusal`
    - `crash_after_commit_before_anchor_sync_recovers_after_reopen`
    - `crash_after_anchor_sync_before_response_recovers_after_reopen`
    - `retry_after_unknown_recovers_the_committed_root`
    - `committed_root_without_global_commit_refuses_open_and_keeps_rows`
    - `concurrent_first_sight_never_returns_an_uncovered_root`
    - `signer_failure_spends_no_replay_key`
  - Retry binding:
    - `retry_with_changed_artifact_refuses_replay`
    - `retry_from_another_client_refuses_replay`
    - `retry_with_changed_request_refuses_replay`
    - `recovery_of_an_expired_root_refuses`
    - `recovery_of_a_revoked_root_refuses_with_entry_id`
    - `recovery_under_another_policy_digest_refuses`
  - Projection: one `<column>_mutation_refuses` per projection member, `context_blob_mutation_refuses`, `capability_blob_mutation_refuses` and `capability_scope_disagreeing_with_context_refuses`.
  - DDL: one rejected insert per CHECK (`non_hex_digest_refuses`, `uppercase_hex_refuses`, `nul_in_text_refuses`, `unknown_anchor_kind_refuses`, `present_salt_of_31_bytes_refuses`, `erased_row_with_salt_refuses`), and `foreign_catalog_layout_refuses_open`.
  - Retention by digest:
    - `retained_policy_bytes_under_wrong_digest_refuse`
    - `retained_identity_bytes_under_wrong_digest_refuse`
    - `snapshot_bytes_under_wrong_digest_refuse`
    - `identical_retained_bytes_are_a_no_op`
    - `stored_bytes_mutated_under_digest_refuse_on_read`
  - Reads:
    - `presentation_of_unknown_root_is_anchored_root_missing`
    - `delegation_context_by_digest_is_projection_checked`
    - `missing_policy_is_export_evidence_incomplete`
  - Openings:
    - `openings_written_in_mint_salts_only`
    - `opening_row_refuses_value_column` (DDL has none)
    - `erase_root_openings_tombstones`
    - `context_openings_by_digest_reads_present_erased_or_unknown`
    - `root_openings_namespace_never_reads_as_receipt_openings`
  - Bearer:
    - `bearer_token_digest_maps_to_one_root`
    - `simultaneous_first_seen_mints_one_root`
    - `static_bearer_expired_root_is_replaced_in_one_transaction`
    - `entra_token_after_root_expiry_is_invalid_token_before_and_after_pruning`
    - `admission_refuses_at_expires_at`
    - `mapping_for_another_policy_digest_is_not_live`
  - Tenant index:
    - `tag_from_generation_n_still_matches_after_rotation_to_n_plus_1` (mint check and revocation fan-out both)
    - `revoke_under_n_then_mint_under_n_plus_1_refuses` (subject and tenant kinds)
    - `root_under_n_revoked_after_rotation_denies_at_admission` (admission holds no plaintext; it reads `revoked_capabilities`)
    - `revoke_under_n_then_bearer_reuse_after_rotation_denies` (an existing mapping, no verifier run)
    - `revoke_under_n_then_recovery_under_n_plus_1_refuses`
    - `new_tags_use_the_active_generation`
    - `startup_refuses_a_missing_referenced_generation` (a retired generation still referenced by a stored tag is removed from the set)
    - `startup_refuses_when_only_a_revocation_entry_references_a_generation` (no root or receipt tag uses it; removing it would let a revoked subject mint again)
    - `tag_under_unknown_key_id_refuses`
    - `tenant_tag_never_verifies_as_subject_tag` (purpose isolation over one preimage and generation)
    - `subject_tag_never_verifies_as_tenant_tag`
    - `tag_inputs_refuse_nul`
  - Other:
    - `expired_replay_row_is_pruned_and_rebindable_only_after_retention`
    - `retained_old_root_expired_replay_new_artifact_mints_a_second_root` (both roots kept, distinct `replay_bound_at`)
    - `recovery_selects_only_the_root_named_by_the_live_replay_row`
    - `replay_key_revocation_covers_old_and_rebound_roots`
    - `client_assertion_replay_row_names_no_root`
    - `pruning_expired_unreferenced_root_keeps_erased_tombstones`
    - `present_opening_without_root_refuses_open`
    - `opening_insert_over_tombstone_refuses`
    - `root_prune_waits_for_a_live_bearer_mapping`
    - `snapshot_sink_records_before_install`
    - `restored_snapshot_missing_a_root_refuses_open`
  - PR A2:
    - `tenant_tag_derived_from_root_in_append`
    - `caller_supplied_tenant_metadata_is_ignored`
    - `tool_and_child_ids_do_not_collide`
    - `swapping_root_id_and_tag_together_refuses_tenant_export`
    - `receipt_tag_key_id_replaced_with_another_loaded_generation_refuses_tenant_export`
    - `receipt_retention_deletes_its_tag`
    - `missing_tag_refuses_tenant_export`
    - `conflicting_tag_refuses_tenant_export`
    - `no_receipt_of_another_tenant_in_selection` (marker principals)
    - `caller_export_after_rotation_includes_receipts_tagged_under_the_retired_generation`
    - `tenant_tag_set_omits_no_loaded_generation`
    - `live_root_without_receipts_is_retained`
    - `expired_root_referenced_by_a_receipt_is_retained`
    - `expired_unreferenced_root_is_pruned_with_openings`
- [ ] **Step 2:** Implement after the held-edit release (Global constraints), PR A first and PR A2 on item 2 F. Register the domains and, after Root-2's review, the `anchored_root` projection kind. Run the light checks, and regenerate COVERAGE last.

### Task B: Entropy migration and token request follow-ups (PR B)

- **Entropy.** `ExchangeEntropy` is deleted. `ExchangeServices.entropy` becomes `&'a (dyn chio_core_types::rng::Rng + Send + Sync)`, and `random::<N>` maps `RngError` to `RootExchangeError::EntropyUnavailable`. The production source is `chio_kernel::rng::OsEntropyRng` (item 2 P-a). Tests use `chio-fixture-rng`'s `FixtureRng` or a local failing `Rng`. Entropy is still drawn before the durable bind (Decision 2 keeps the bind in the mint transaction).
- **F16 item 1.** A token request that carries `client_secret` (body or HTTP Basic) together with `client_assertion` refuses `ClientAuthenticationAmbiguous` (RFC 6749 section 2.3: one method per request).
- **F16 item 2.** A recognized parameter that appears twice refuses `MalformedRequest("repeated parameter")` even when one occurrence is empty. A single empty occurrence counts as omitted (RFC 6749 section 3.1).
- **F16 item 4.** `RootPolicyRule::validate` refuses an `idp_scope_projection` value without `/` (`RootAuthorityShapeError::Pattern { field: "idp_scope_projection", expected: "server/tool" }`). This is a `chio-core-types` change, with `REVIEW?` on `sync.md`.

- [ ] **Step 1: Failing tests:**
  - `failing_rng_denies_before_the_replay_bind_and_root_insert` (the client-assertion `jti` is spent, as in part 1)
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
    - the input is an operator root request (Decision 6), verified against `--operator-key` under the wrapper (signature verification lands in PR D1 with item 1; PR C verifies the body shape and replay key);
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

### Task D1: Seed-file signer and operator root requests (PR D1)

- **The signer.** `ExchangeSigner` is a closed enum in `root_exchange::signer`; D1 adds `SeedFile` (local Ed25519; the file is mode 0600 and owned by the process user, or startup refuses). It signs the root through the capability token's own signing method and IdP key snapshots through `IdpKeySnapshot`'s, both on item 1's wrapper (one signing body per artifact). Every signature is verified against the seed file's public key before the root is returned.
- **#1713's type moves.** #1713 is merged by then, so D1 changes its `ExchangeSigner` struct in `idp_keys/source.rs` in place: the type moves into `root_exchange::signer` and every caller changes in the same PR. #1713's `sign_canonical_with_backend_for_identity` site converts to the wrapper here; if #1713 merges before item 1, item 1's census gains that row (raised on item 1).
- **Operator root requests (Decision 6).** D1 registers `chio.operator-root-request.v1` (schema file, `registry.json`, `KNOWN_SIGNED_ARTIFACT_SCHEMAS`, the `wrapper_cases` vector, codegen), verifies requests through `verify_wrapped` against `--operator-key`, and adds `chio mcp root-request sign --operator-seed-file <path>`.

- [ ] **Step 1: Failing tests:**
  - `seed_file_group_readable_refuses`
  - `seed_file_signature_verifies_against_pinned_exchange_key`
  - `operator_request_signed_by_unpinned_key_refuses`
  - `operator_request_under_another_schema_id_refuses`
  - `root_request_sign_output_verifies` (the CLI signer round trip)
- [ ] **Step 2:** Implement and run the light checks, including the item 1 wrapper vector check.

### Task D2: Trust-control exchange signer (PR D2)

- **Edge side.** `ExchangeSigner::TrustControl`, configured by `--exchange-signer trust-control:<url>`, `--exchange-signer-credential-file` and `--exchange-signer-trusted-public-keys` (Decision 11). It calls `POST /v1/root-exchange/sign` with the P-f credential and verifies every returned artifact against the trusted set before the root is returned.
  - An unreachable trust-control, a refused request, or a signature outside the trusted set fails the mint (8.1). No signer falls back to a local or generated key (PROTOCOL 5.6.9).
  - O1 (F15): under option 1 the signer requires `issuer_state` and refuses a status without it; under option 2 it refuses keyring-backed and seed-file-backed trust services at startup (`trust-control exchange signer requires lifecycle state`). The edge check is the same test under both.
  - It never reads `--control-url` or `--control-token`, and its configuration never opens a store.
- **Trust-control side.** The route, request union, checks and P-f row of Decision 11, in `trust_control/root_exchange_signing.rs`. `chio trust serve` gains `--root-policy-key` and loads an enterprise provider registry (`--enterprise-providers-file`, the format its provider admin already writes, read once per request as G17 requires) for the snapshot and provider-digest checks. Without either the route refuses `root exchange signing is not configured`. It signs with its current authority key, which must be in the edge's trusted set; the edge checks that per mint (8.5), with no startup probe.

- [ ] **Step 1: Failing tests:**
  - edge: `trust_control_signature_outside_trusted_set_refuses_mint`, `trust_control_unreachable_refuses_mint`, `trust_control_without_lifecycle_state_refuses`, `exchange_signer_credential_file_group_readable_refuses`, `trust_control_signer_requires_credential_file`, `control_url_never_selects_the_exchange_signer`, `rotated_exchange_key_in_trusted_set_verifies`;
  - response binding (edge): `sign_response_of_another_kind_refuses`, `sign_response_with_substituted_body_refuses`, `sign_response_signed_outside_trusted_set_refuses`;
  - route, each refusal exact and each asserting no signing call: `sign_root_issuer_not_in_policy_exchange_keys_refuses`, `rotated_trust_control_key_signs_after_policy_resign`, `sign_snapshot_record_digest_differs_from_edge_refuses`, `sign_request_unknown_kind_refuses`, `sign_request_unknown_member_refuses`, `sign_root_provider_digest_mismatch_refuses`, `sign_snapshot_unknown_provider_record_refuses`, `sign_snapshot_disabled_record_refuses`, `sign_snapshot_issuer_mismatch_refuses`, `sign_snapshot_source_mismatch_refuses`, `sign_snapshot_inline_keys_mismatch_refuses`, `sign_snapshot_foreign_exchange_key_refuses`, `sign_from_other_deployment_credential_refuses`, `sign_root_without_root_anchor_refuses`, `sign_root_with_foreign_issuer_refuses`, `sign_root_with_delegation_chain_refuses`, `sign_root_policy_not_signed_by_pinned_key_refuses`, `sign_root_policy_digest_mismatch_refuses`, `sign_root_context_digest_mismatch_refuses`, `sign_root_unknown_rule_refuses`, `sign_root_scope_above_rule_ceiling_refuses`, `sign_root_lifetime_above_ceiling_refuses`, `sign_root_issued_at_outside_skew_refuses`, `sign_snapshot_invalid_body_refuses`;
  - item 1: `remote_signing_accepts_pinned_root_exchange_kinds`, `remote_signing_refuses_arbitrary_bytes`;
  - P-f: `root_exchange_sign_requires_its_scope`, `tenant_credential_refused_on_root_exchange_sign`, and `route_table_covers_every_router_route` with the new row;
  - cluster: `root_exchange_sign_forwards_to_leader`, `root_exchange_sign_refuses_under_stale_term`;
  - registry: `sign_route_without_provider_registry_refuses`, `sign_route_reads_registry_per_request` (a record disabled between two requests refuses the second).
- [ ] **Step 2:** Implement and run the light checks. The integrator runs the `chio-control-plane` suite and the trust-control remote authority tests against keyring-backed and seed-file-backed services (the missing round-1 test from `review-1674-r2-claude.md:76`).

### Task E: Mount, admission and deletions (PR E)

**Mint and release:**
- `RootExchange::issue(prepared, signer, store, revocation)` signs the body with `root_anchor` (item 3 part 2), then calls `mint_anchored_root` with item 5's transaction-bound checker, and returns the root only when it is returnable (Task A Release): `MintOutcome::Returnable` for a fresh or recovered root. `OutcomeUnknown` and `NotYetCovered` answer 503 `temporarily_unavailable` (Task A).
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
- `/admin/revocations` keeps item 5's targets and always writes the local store; its trust-control forwarding is deleted (Decision 1).
- The admin health output drops `proxied`, `controlUrl`, `controlTokenConfigured`, `revocationsConfigured` and `budgetsConfigured` (Decision 1).
- `open_revocation_store`'s path fallback is deleted (item 5 notes this is a no-op if item 4 deletes `revocation_db_path` first).

**Admission:**
- The edge resolves `chio_root`, or the bearer token digest, to the stored root.
- It verifies the root with item 3 part 2's anchored-root resolver against the loaded policy and the exchange key set (the seed file's key, or `--exchange-signer-trusted-public-keys` under D2), and checks the provider record by identity digest per request (G17).
- A session-held root is usable only from the token that produced it (9.3).
- **Session identity (Decision 13).** `enterprise_identity` leaves the `serve-http` session; sessions carry the root capability id and its context commitments, and `attribution.subject_key` is the root's subject public key.
- **Configuration and startup.**
  - New flags: `--state-dir`, `--root-policy`, `--root-policy-key`, `--exchange-signer seed-file:<path>` (`trust-control:<url>` with its credential file and trusted keys arrives in D2, Decision 11), `--kernel-signer seed-file:<path>`, `--tenant-index-keys <dir>` (item 2's key set, Decision 10) and `--operator-key`.
  - Kept: `--auth-token`, `--enterprise-providers-file`, `--auth-introspection-client-id` and the secret env.
  - Startup refusals: the full 8.3 list as amended, plus the missing referenced generation refusal (Decision 10) and Decision 1's refusal of `--control-url` and `--control-token`. Decision 1's item 5 and item 2 amendments land in this PR, atomically with the refusal.
  - Startup also refuses when item 5's production revocation checker is not wired (Decision 7).
  - The state-directory lock: `flock` on `<state-dir>/LOCK` before any store opens, held for the process lifetime. A network filesystem (`statfs` magic on Linux, `MNT_LOCAL` on macOS) refuses.
  - Every store opens under `--state-dir` through the serving owner; none is remote (Decision 1).
- **Deletions, each with every caller:**
  - **Bypass issuance and seed-derived keys:**
    - `configure_session_capability_authority` and its call into `chio_control_plane::configure_capability_authority` from `serve-http`;
    - `derive_federated_agent_keypair` and the `chio-mcp-remote` `derive_enterprise_subject_key`, with `session_resume.rs`'s resume derivation. Resume binds to the stored root id instead. The control-plane SCIM derivation and its principal-hash aliases close under #1728 (P-g), which merges first (Decision 9).
  - **Provider identity outside the registry:**
    - `JwtProviderProfile` with its `AzureAd` mapping;
    - the record member `provider_profile` (`enterprise_federation.rs`, trust-control provider admin and its tests);
    - the provider verification flags and fields (2.4).
  - **Per-store paths and the remote store mode:** the per-store database flags and `RemoteServeHttpConfig` path fields for `serve-http`, and `control_url` and `control_token` with every caller listed in Decision 1. `chio trust serve` flags are unchanged apart from D2's.
  - **Exempt site:** `session_identity.rs::verify_ed25519_jwt_signature` and its item 1 allowlist entry, in one commit (Global constraints).
- **Callers that move to `--state-dir`, a root policy file and provider records:**
  - 8 crate files, including `chio-cli/tests/mcp_serve_http.rs`, `tests/mcp_serve_http/token_passthrough.rs`, `tests/mcp_auth_server.rs` and `chio-conformance/src/runner.rs`;
  - 3 deploy units (`deploy/reference-runtime/systemd/chio-mcp-edge.service`, `deploy/cloud-run/service.yaml`, `deploy/sidecar/Dockerfile`); the `--control-url` callers of F20 move to a seed-file signer until D2;
  - 8 example files (agent-commerce-network, docker, both internet-of-agents networks, reference-swarm);
  - `scripts/check-sdk-publication-examples.sh`, `scripts/check-sdk-release.sh` and `scripts/acceptance/session-credentials.py`;
  - the cpp, js, go and python conformance peers and the progressive tutorial;
  - 18 docs files, led by `IDENTITY_FEDERATION_GUIDE.md` and `OPERATIONS_RUNBOOK.md`.
  Task 0 re-counts these at the PR base.
- **Scenarios.** Move the 24 staged `anchored_root` scenarios into `chio-conformance/verdict_matrix/scenarios/anchored_root/`, add the enum value and `SCENARIOS.md` row, register their reason URNs and re-pin `manifest.toml`. Remove the PROTOCOL 5.6 status line for the parts now implemented.

- [ ] **Step 1: Failing tests:**
  - token endpoint: one per grant and token-type combination, and the capability-v1 response shape;
  - bearer intake: first sight mints, the second request reuses, an expired root gives 401 `invalid_token` for the IdP kinds and a fresh root for `operator_static_bearer`;
  - admission: an unknown `chio_root` denies, and a root from a different token denies;
  - startup: one exact test per 8.3 refusal, a missing referenced generation, the missing revocation checker, and Decision 1 (`control_url_refuses_serve_http_start`, `control_token_refuses_serve_http_start`);
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

- **R1 (was O3), Root-2 decision.** The receipt tenant tag is the side table `receipt_tenant_tags`: authoritative derived state, with the contract in Task A (PR A2).
- **L3, lead decision 2026-10-20.** Tags use the merged tenant index key set (#1728) with the `tenant-tag` and `subject-tag` purposes and all-generation match (#1733); no second scheme (Decision 10).
- **L4, lead decision 2026-10-20.** A new trust-control route signs edge-built bodies (Decision 11).
- **L5, lead decision 2026-10-20.** `--exchange-signer trust-control:<url>` with a scoped P-f credential file and `--exchange-signer-trusted-public-keys` (Decision 11).

- **L1 (was O4), lead decision 2026-10-20.** `POST /admin/roots` with its own signed request schema, `chio.operator-root-request.v1` (Decision 6). `/admin/authority` is not extended: an operator root request and an authority rotation are different trust objects.
- **L2 (was O5), lead decision 2026-10-20.** PR E is one PR, so `main` never has two issuance paths. If it grows past reviewable size, it splits by caller group inside a stacked series whose members merge together in one MERGING window. A separately landed half is not allowed.

## Open decisions

| # | Owner | Question | Default in this plan |
|---|---|---|---|
| O1 | owner (Connor) | F15: lifecycle state for keyring and seed-file trust services, or refuse them as remote exchange signers in v1 | PR D2 implements whichever is chosen; it does not open until the decision is recorded. Nothing else waits on O1 |
| O2 | owner (Connor) | Decision 1: `serve-http` has no remote store and refuses `--control-url` | proposed (Root-2 endorses it technically); item 5's Q4 refusal stays until PR E lands the rule and both amendments atomically |
| O6 | owner (Connor) | Sign off the spec amendment (2.4 trust-control row, the last 8.3 refusal, 10.5 `factory.rs`, 10.8 signer flags) | separate docs PR; gates PR D2 and PR E |

## Cross-plan amendments

Each lands in the named PR or is raised on the owning plan; none changes this plan's slicing.

| Plan | Amendment | Lands |
|---|---|---|
| item 2 key set | the `subject-tag` label and the all-generation rotation mode for `tenant-tag` and `subject-tag` | resolved by #1733 (merged) |
| item 2 key set | `derive_in(key_id, purpose, preimage)` and `key_ids()` (Decision 10) | resolved by #1734 (merged) |
| item 2 P-f | `root-exchange:sign` in the closed scope set and the `/v1/root-exchange/sign` route row (Decision 11) | D2, `REVIEW?` on P-f |
| item 2 Task 4 | drop `serve-http` from the remote append (L420) and the `receipt-openings:read` grant (L432); delete A/E's internal-read branch; E-k's remote path stays for `chio mcp serve` and `chio run` (Decision 1) | E |
| item 2 P-g | the `chio-mcp-remote` copy that P-g keys is deleted by PR E with `build_enterprise_identity_context` (Decision 9) | E |
| item 5 | the fingerprint becomes `tag_key_id` (no `chio.tenant-index-key-fingerprint.v1`); PR 3 drops `startup_refuses_a_different_index_key` and 0.25 day; delete the L456 and L457 409 rows, close Q4, delete R8's `serve-http` forwarding (Decisions 1, 10) | fingerprint: A; 409, Q4, R8: E |
| item 5 | `oidc_jwt` without `jti` joins the L455 422 row (its replay key is the bearer token digest, not an assertion id) | raised on item 5 |
| item 5 | tag-kind entry ids are not idempotent across a rotation: revoking the same subject again under a new generation records a second entry and reports `newly_revoked` again. Both entries deny, so behaviour stays correct; item 5 either states it or first looks up an existing entry under every loaded generation | raised on item 5 |
| item 6 | the manifest and `ExportDisclosure::Caller` carry `tenant_tags: Vec<KeyedIndexValue>` (one per loaded generation, sorted by `key_id`) in place of one `TenantTag`; the schema change moves atomically with item 6's callers and verifier, with no singleton compatibility form | resolved by #1735 (merged) |
| item 2 Task 5c | the `root-exchange:sign` scope and route row in P-f | arc-5b amends item 2 |
| item 6 | `context_openings(context_digest)` resolves through the UNIQUE `context_digest` index (no Task 8 change); drop "bearer roots" from L133 (item 6 exports no bearer role) | raised on item 6 |
| item 1 | census row for #1713's snapshot signer if #1713 merges before item 1; the D2 route under the pinned-route rule (F24) | raised on item 1; D2 |
| spec | 2.4 trust-control row, the last 8.3 refusal, 10.5 `factory.rs`, 10.8 signer flags | separate docs PR (O6) |

## Spec traceability

| Spec | PR |
|---|---|
| 6.2 steps 2-8 (token endpoint, `chio_root`, no refresh) | C, E |
| 6.3 (Entra bearer and explicit RFC 8693; one root per `uti`; 401 after expiry) | C, E |
| 6.5 (session-held versus caller-held) | C (holder), E (cross-token refusal) |
| 7.2 (every kind and its replay key) | C |
| 7.4 (policy load against the registry, Entra issuer on `oidc_jwt`) | B, C |
| 7.11 (anchored root target columns) | A |
| 7.12 (tags, `index_key`) | A (Decision 10) |
| 8.1 (exchange refusals) | B, C, D1, D2 |
| 8.2 (admission refusals) | E |
| 8.3 (startup refusals) | D1 (seed files), D2 (signer), E |
| 9.1 to 9.3, 9.5 | A, A2, C, D1, E |
| 10.5, 10.7, 10.8 | A to E |
| D4 (single instance, state-directory lock) | E |
| G17 (registry as the one provider identity source, per-request reads) | C, E |
| 2.4 deletions | E |
