# Session-id keyed handle

Status: design for backlog row SESSION-ID-KEYED-HANDLE. arc-63 ruled on D1-D8 on 2026-10-30 (section 9). Implementation not started. Base `936ecc1e1f7c0393cfc6c4febeebb294186f244f`. Line numbers below are from that base.

## 1. Intent

Signed receipts carry a session identifier in three metadata members: `acp.sessionId`, `receipt_context.session_id` and `protocol_refusal.session_id`. Each holds the raw identifier the session started with. Two readers join receipts into a session on it: the retained-session reader behind `chio cert` and the ACP compliance verifier.

This design replaces the raw identifier in every signed receipt and every session certificate with a session handle. The handle is a keyed value under the deployment's tenant index key set, computed by the receipt signer and covered by the receipt signature. Both readers join on the handle. The raw identifier leaves the signed bytes. There is no dual field, no fallback reader and no version bump: every schema stays at v1.

## 2. Threat

The raw identifier is a poor join key for signed, exportable evidence.

- **Correlation leak.** Receipts leave the deployment in compliance bundles, evidence exports, replication and SIEM pipelines. The raw ACP `sessionId` is the identifier the agent also uses in its own transport, logs and telemetry. Any holder of a receipt can link it to those external records and to every other receipt of the session. The registry description of all three members accepts this today (`key_registry.rs:185,209,537`).
- **Attacker-chosen value.** ACP session ids are minted by the ACP agent. Kernel session ids are random (`session_ops.rs:51-61`) except where a host opens a session with a chosen id: `open_session_with_id` (`session_ops.rs:108`), called from `chio-mcp-edge` `runtime.rs:358` and `runtime/requests.rs:174`, and the remote restore path, which derives `sess-restore-` plus 16 hex characters of an unkeyed SHA-256 of the client's session header (`chio-mcp-remote` `http_service.rs:1178-1181`). A chosen value can be low-entropy and guessable, so a receipt holder can confirm a guessed id.
- **Cross-signer linkage and collision.** Both readers already refuse a session whose receipts come from more than one signer (`compliance/bundle.rs:238`, `session_certificate_read.rs:295`). A raw id still links sessions across signers for any receipt holder, and two agents behind signers that share a key and pick the same id (`session-1`) land in one session.

A handle closes the first two because a holder without the key set cannot compute or test it. Binding the signer into the preimage (section 4.3) removes cross-signer linkage. Same-key collisions are a known limit (section 9.2).

## 3. Current producers and readers

### 3.1 Writers of the three members

| Member | Writer | Value source |
|---|---|---|
| `acp.sessionId` | `chio-acp-proxy` `kernel_signer.rs:512` | `AcpToolCallAuditEntry.session_id`, agent-minted |
| `receipt_context.session_id` (ACP form) | `chio-acp-proxy` `kernel_signer.rs:534` | same |
| `protocol_refusal.session_id` | `chio-kernel` `session_ops/protocol_refusal.rs:233`, struct at `:182-192`, block at `:266` | kernel `SessionAnchorSnapshot.session_id` (`session.rs:761,994`) |
| `acp.sessionId` (target projection, not yet wired) | `chio-core-types` `receipt/metadata/acp.rs:41,119` (`AcpReceiptProjection`, `AcpReceiptFields.session_id` at `:23`) | writer input |

Callers that reach the refusal writer: `chio-mcp-edge` `runtime/refusals.rs:10-22` (from `requests.rs:448,561,751,856`, `tool_calls.rs:380`, `runtime.rs:666`, `runtime_flow.rs:367`) and `chio-mcp-remote` `remote_mcp/session_core/session.rs:99-117` (from `protocol_refusal_http.rs:25`).

### 3.2 Other signed carriers of the same raw ACP id

These carry the same value on the ACP authorization path. They are in scope because leaving any one of them defeats the handle.

| Carrier | Site |
|---|---|
| ACP receipt `capability_id` fallback `acp-session:<id>` | `kernel_signer.rs:496` |
| Kernel authorization receipt `action.parameters.session_id` | `kernel_checker.rs:237`; checked at `kernel_signer.rs:290-296` and `chio-kernel` `admission_operation/projection/authorization.rs:101-104` |
| Kernel authorization receipt `source_receipt_context.session_id` | source envelope `kernel_checker.rs:267`, copied by `chio-cross-protocol` `execution.rs:238-250` |
| Source envelope `sessionId` and protocol context | `kernel_checker.rs:258`, `:92` (`protocol_context`) |
| Cross-protocol `origin_request_id` `acp-guard-<id>-<hash>` | `kernel_checker.rs:350`; carried at `chio-cross-protocol` `orchestrator.rs:385,410`, `execution.rs:217` |
| Authorization request hash input | `kernel_checker.rs:328` (hashed only; no change needed once the input is the handle) |
| `AuthorizationReceiptConsumption.session_id` | `chio-kernel` `receipt_store.rs:327`; built at `kernel_signer.rs:362,576` (`VerifiedAuthorizationContext.session_id`, `:57`) |
| Signed admission terminal projection `authorizationConsumption.sessionId` | `spec/schemas/chio-wire/v1/kernel/signed-admission-terminal-projection.schema.json:34,53` |
| ACP compliance certificate body `session_id` | `chio-acp-proxy` `compliance.rs:252`; coverage `compliance/bundle/coverage.rs:14`; schema `spec/schemas/chio-wire/v1/compliance/certificate.schema.json:25,143,184`; examples `spec/schemas/signed-artifact-examples/chio.compliance.certificate.v1/captured-{1,2,3}.json` |
| Kernel session compliance certificate body `session_id` | `chio-kernel` `compliance_certificate.rs:47` (issue `:141`, verify `:190`); schema `spec/schemas/chio-wire/v1/kernel/session-compliance-certificate.schema.json:13,31` |

### 3.3 Readers

| Reader | Site | Use |
|---|---|---|
| Retained-session reader | `chio-store-sqlite` `receipt_store/session_certificate_read.rs:381-425` (`signed_membership`), used at `:304`; input check `:185`; coverage `RetainedSessionSnapshotCoverage.session_id` `:42` | reads all three members, requires agreement, joins on equality with the requested id |
| ACP compliance verifier | `chio-acp-proxy` `compliance.rs:345-375` (`receipt_session_id`), used at `:419`; `SessionMismatch` `:80-85`; bundle `compliance/bundle.rs:183-310`, `bundle/bounds.rs:160-214` | same three members, same rule, independent copy |
| `chio cert generate` and `chio cert verify` | `chio-cli` `cert.rs:25,73-99,171-173,234`; `cert/session_receipts.rs:12,22,52`; argument `cli/types.rs:1163-1167` | passes the operator's raw id to the reader; prints it |
| ACP signer authorization check | `kernel_signer.rs:290-296` | compares the authorization receipt's `action.parameters.session_id` with the audit entry |
| Durable admission authorization projection | `admission_operation/projection/authorization.rs:101-104,121` | compares `action.parameters.session_id` with the consumption row |
| OTel export | `chio-acp-proxy` `telemetry.rs:383-384` (`cert.session_id`), `:418-436` (`chio.session_id` span attribute), `:445-449` (`derive_trace_id`, unkeyed SHA-256 of the raw id) | outside receipts; follow-up row SESSION-HANDLE-TELEMETRY (section 9.3) |

### 3.4 SDKs, spec and wire schemas

- **SDKs.** No SDK reads any of the three members. The generated types that change are the two certificate bodies: `sdks/python/chio-sdk-python/src/chio_sdk/_generated/compliance/certificate_schema.py`, `.../kernel/session_compliance_certificate_schema.py`, `sdks/go/chio-go-http/types.go`, `sdks/typescript/packages/conformance/src/_generated/index.ts`, and the signed-artifact schema tables `sdks/go/chio-go/invariants/signed_artifact_schemas_gen.go`, `sdks/python/chio-py/src/chio/invariants/_generated_signed_artifact_schemas.py`, `sdks/typescript/chio-ts/src/invariants/_generated/signed_artifact_schemas.ts`. The generated `ReceiptContext` types model only `request_id` and `request_namespace_digest` (`receipt-body.schema.json:4871-4885`), so they do not change.
- **spec/PROTOCOL.md.** 6.4 key table rows `protocol_refusal` (`:1871`), `receipt_context` (`:1874`) and `acp` (`:1915`) render the registry descriptions; `chio-core-types` `tests/receipt_metadata_registry.rs:444-466` pins the table to the registry. The signed-artifact table names `chio.session-compliance-certificate.v1` (`:437`) and `chio.compliance.certificate.v1` (`:538`). PROTOCOL has no normative text for the tenant index key set or its purpose labels.
- **Other spec text.** `spec/COMPLIANCE-CERTIFICATE.md:46,104-107,160,236-271`; `docs/protocols/SESSION-COMPLIANCE-CERTIFICATE.md:21-22,89,220-222,376,388,415,438`.
- **spec/wire-schemas.lock.** Holds `chio.compliance.certificate.v1` (`:1158`) and `chio.session-compliance-certificate.v1` (`:5548`). `chio.session.protocol-refusal.v1` is missing: it is an inline literal at three sites (`protocol_refusal.rs:232`, `session_certificate_read.rs:413`, `compliance.rs:359`) and never declared, so `scripts/check-wire-schemas.py` does not see it.

## 4. Handle construction

### 4.1 Primitive

The handle reuses the tenant index key set (`chio-core-types` `tenant_index/mod.rs`) and `MetadataProjector::keyed` (`receipt/metadata/projector.rs:63-69`), the primitive behind F23's keyed enterprise subject (`enterprise_subject.rs`, #1795). No new key material, loader or rotation machinery is added.

- New purpose `IndexPurpose::SessionHandle`, label `session-handle`, string prefix `sh1`. Its HKDF subkey is `K[session-handle] = HKDF-SHA256(IKM = set key, salt = "chio.tenant-index.v1", info = "chio.tenant-index.v1/session-handle", L = 32)`.
- New domain `IndexDomain::SessionHandle`, constant `SESSION_HANDLE_DOMAIN = b"chio.session-handle.v1\0"`, purpose `SessionHandle`. `IndexPurpose::ALL` and `IndexDomain::ALL` grow by one, so the existing NUL-terminator assertion (`tenant_index/mod.rs:170`) and purpose-isolation test cover it.
- Value: `HMAC-SHA256(K[session-handle], "chio.session-handle.v1\0" || field(origin) || field(signer) || field(session_id))`, with `field(x) = be32(len(x)) || x`. The length-prefixed encoder in `enterprise_subject.rs:62-80` moves to `tenant_index` as one shared `pub(crate)` function taking a slice of named fields; enterprise subject and session handle both call it.
- `origin` is a closed set: `kernel` for a kernel `SessionId`, `acp` for an ACP-Client `sessionId`.
- `signer` is `PublicKey::to_hex()` of the receipt signing key that writes the session's receipts (section 4.3).
- Type: `chio_core_types::session::SessionHandle(KeyedIndexValue)`, serialized as the string form `sh1.<64 hex key_id>.<64 hex value>` (133 bytes), parsed exactly by `KeyedIndexValue::parse_string_form(IndexPurpose::SessionHandle, ..)`. Constructors: `SessionHandle::derive(keys, origin, signer, session_id)` under the active generation, `SessionHandle::derive_in(keys, key_id, origin, signer, session_id)` under a named generation, and `SessionHandle::verify(keys, origin, signer, session_id)`, which selects the generation by `key_id` and compares in constant time. An unknown `key_id` refuses with `TenantBindingError::TenantIndexKeyUnknown`. Equality, ordering and hashing cover `(key_id, value)`.

### 4.2 Length

The value is the full 32-byte HMAC output. Truncation would save 32 hex characters per member and would require a second string-form grammar. The 133-byte string fits every existing bound on these readers (`session_certificate_read.rs:185`, `compliance.rs:475`, `bundle/bounds.rs:184`, all 1024 bytes).

### 4.3 Binding and domain separation

- **Purpose.** A separate HKDF subkey means a session handle never verifies as an enterprise subject, tenant binding, tag or active-defense digest, and the reverse, whatever the preimages.
- **Origin.** A kernel session and an ACP session that share a raw string get distinct handles.
- **Signer.** Two signers that see the same raw id get distinct handles. Both readers already fix the signer: the retained reader pins one trusted kernel key (`session_certificate_read.rs:244-247,295`), and the compliance bundle requires one `kernel_key` across its receipts (`compliance/bundle.rs:238`) from the trusted set (`compliance.rs:409-415`). Signers that share one key are a known limit (section 9.2).
- **Tenant.** The tenant is left out of the preimage. ACP receipts in one session can carry different tenant scope: audit-only entries sign `tenant_id: None` while enforced entries carry the authorization receipt's tenant (`kernel_signer.rs:544-546`). Tenant scoping stays with `tenant_id` and `tenant_binding`.

### 4.4 Generation and rotation

The signer computes a session's handle once, when the session opens, under the active generation. Every receipt of that session carries the same handle, including receipts signed after a rotation; the retired generation stays loaded and still verifies it. Readers therefore join by `(key_id, value)` equality with no all-generation search.

- Kernel: `open_session_with_id` derives the handle and stores it in the session state; `SessionAnchorSnapshot` exposes it beside `session_id`. A restored session is a new open and derives again under the current active generation.
- ACP proxy: `KernelReceiptSigner` derives on the first audit entry of a `sessionId` and keeps a bounded map from `sessionId` to handle for the life of the process. `KernelCapabilityChecker` uses the same map so the authorization path and the audit path agree.
- Lookup from a raw id (section 4.5) runs `derive_in` under every loaded generation, the all-generation match mode the item 2 plan already defines.

A key-set rotation needs a process restart, so a session that spans one is split only across that restart.

### 4.5 Auditor correlation

Any holder groups receipts by handle without learning the raw id. This within-session linkage is what the certificate needs.

A holder of the key set and a raw session id (from the agent's own records) correlates by computing `SessionHandle::derive_in(keys, key_id, origin, signer, session_id)` for each loaded generation and selecting receipts whose handle equals one of them. `chio cert generate --session-id <raw>` does exactly this (section 6). A holder of the key set cannot invert a handle. Receipts from different deployments, and therefore different key sets, never correlate.

## 5. Interaction with in-flight work

- **F23 and ITEM4-PG-SUBJECT-KEY-UNIFY.** That row replaces the two unkeyed `derive_enterprise_subject_key` copies (`chio-mcp-remote` `session_identity.rs:473`, `chio-control-plane` `scim_lifecycle.rs:454`) with the keyed `EnterpriseSubject` in `chio-core-types`. This design adds a sibling purpose to the same set and shares that row's field encoder. The only shared file is `enterprise_subject.rs` (encoder extraction in PR 1), so PR 1 rebases on whichever lands second.
- **Receipt metadata registry.** `key_registry.rs` keeps one row per block. PR 4 rewrites the `protocol_refusal`, `receipt_context` and `acp` descriptions: the session member becomes a keyed session handle that confirms no guessed id without the tenant index key set. The rows stay `Unsafe` because other members are still unsalted or caller-chosen; the session member stops being one of the reasons. PROTOCOL 6.4 regenerates from the registry.
- **PD2 committed metadata (`MetadataCommitter`, `MetadataOpenings`, acpcopy's PD2-F).** The handle is a deterministic keyed value. A salted `MetadataCommitment` would force both readers to hold openings to join, and erasing openings would drop a receipt from its session. It goes through `MetadataProjector::keyed`, so a block built by a projector commits its other members and carries the handle in one pass. PR 1 changes `AcpReceiptFields.session_id` to `session_handle: &SessionHandle` and `AcpReceiptProjection.session_id: String` to `session_handle: SessionHandle`. The projection has no wired writer yet, so this changes no signed bytes. The PD2-F writer flip then writes the handle from its first commit. The `metadata.acp.*` and `metadata.receipt_context.*` salt refs are unchanged; the handle has no salt ref.
- **Tenant index key provisioning (item 2 F Task 6).** The plan provisions `--tenant-index-keys <dir>` to trust-control and the kernel-hosting processes, but no process loads the set on main yet (only `tenant_index/load.rs:125` exists). PR 2 below wires it to the processes this design needs. Rulings D5 and D8.

## 6. Changes

The changes are listed per PR in section 8. The end state:

- `acp.sessionId` becomes `acp.sessionHandle`; `receipt_context.session_id` becomes `receipt_context.session_handle`; `protocol_refusal.session_id` becomes `protocol_refusal.session_handle`. Each holds the `sh1.` string form. The old member names are refused by both readers as a malformed membership block, so a receipt carrying a raw id is never joined.
- One reader, `chio_core_types::receipt::metadata::session_membership(metadata) -> Result<Option<SessionHandle>, SessionMembershipError>`, replaces `signed_membership` (`session_certificate_read.rs:381`) and `receipt_session_id` (`compliance.rs:345`). Both copies are deleted. It reads the three handle members, refuses a non-object container, a non-string or malformed handle, a refusal block whose schema is not `chio.session.protocol-refusal.v1`, a raw-id member (`acp.sessionId`, `receipt_context.session_id`, `protocol_refusal.session_id`), and disagreement among present members.
- `chio.session.protocol-refusal.v1` becomes a declared constant in `chio-core-types` used at all three sites and registered in `spec/wire-schemas.lock`.
- `collect_retained_session_receipts_read_only` takes `&SessionHandle`. `RetainedSessionSnapshotCoverage.session_id` and `ComplianceCoverage::RetainedSnapshotReference.session_id` become `session_handle: SessionHandle`.
- `ComplianceCertificateBody.session_id` (`compliance.rs:252`) and `SessionComplianceCertificateBody.session_id` (`compliance_certificate.rs:47`) become `session_handle`. `SessionMismatch` and `EmptySession` carry the handle. Schemas, signed-artifact examples and generated SDK types regenerate in the same PR.
- ACP authorization path: `kernel_checker.rs:237,258,267,92,350` put the handle where they put the raw id; `kernel_signer.rs:290-296,362,496,576` compare and record the handle; `AuthorizationReceiptConsumption.session_id` becomes `session_handle`, with its schema and the projection check at `authorization.rs:101-104,121`. The `acp-session:` fallback capability id becomes `acp-session:<sh1 string>`.
- `chio cert generate --session-id <raw>` gains `--tenant-index-keys <dir>`, required. It resolves the raw id to the stored handle through section 4.5 with `origin = acp` and the store's trusted kernel key, then reads by handle. `chio cert verify` and `chio cert inspect` print the handle. No CLI path prints or stores a raw id.
- PROTOCOL gains a 6.4 subsection "Session handle" stating the construction in 4.1, the binding in 4.3, the generation rule in 4.4 and the reader rule above. The tenant index purpose label list (which PROTOCOL 6 is to carry per the item 2 plan) includes `session-handle`. `spec/COMPLIANCE-CERTIFICATE.md` and `docs/protocols/SESSION-COMPLIANCE-CERTIFICATE.md` change their field tables, algorithm inputs and CLI examples.

## 7. RED-first test plan

Each test is written first and fails on the base for the stated reason.

PR 1 (`chio-core-types`):

1. `session_handle_string_form_parses_exactly`: `sh1.` round-trips; `esk1.` prefix, uppercase hex, short fields and a third dot refuse. Fails: no `SessionHandle`.
2. `index_value_never_verifies_under_another_purpose` (existing) covers `session-handle` once it is in `IndexPurpose::ALL`; add `session_handle_never_verifies_as_enterprise_subject` with an identical preimage.
3. `session_handle_separates_origin_signer_and_id`: same raw id under `kernel` and `acp`, under two signer keys, and the pairs `("ab","c")` against `("a","bc")` all differ.
4. `session_handle_verifies_after_rotation` and `session_handle_unknown_key_id_refuses`.
5. `acp_projection_carries_no_raw_member` replaces `acp_projection_carries_no_raw_member_but_the_session_id` (`tests/receipt_metadata_blocks.rs:268`): the serialized projection contains no byte substring of the raw session id. Fails: the projection serializes `sessionId`.
6. `session_membership_refuses_raw_id_members` and `session_membership_refuses_conflicting_handles`.

PR 2 (key-set wiring):

7. `mcp_serve_refuses_start_without_tenant_index_keys` (`chio-cli`) with the exact startup error. The ACP constructors take the set by type, so a missing set is a compile error.

PR 4 (flip):

8. `protocol_refusal_receipt_bytes_exclude_raw_session_id` (`chio-kernel` `kernel/tests/protocol_refusal.rs`): canonical receipt bytes do not contain the session id; `protocol_refusal.session_handle` verifies under the fixture key set.
9. `acp_receipt_bytes_exclude_raw_session_id` (`chio-acp-proxy` `tests/attestation_signer.rs`) for an enforced entry and an audit-only entry (covers the `capability_id` fallback at `:181`).
10. `kernel_authorization_receipt_excludes_raw_acp_session_id`: the authorization receipt's `action.parameters`, `source_receipt_context` and route metadata contain no raw id.
11. `retained_session_read_joins_on_handle` and `retained_session_read_refuses_raw_member` (`session_certificate_read/tests.rs`, which today seeds `{"receipt_context":{"session_id":"target"}}` at `:25`).
12. `compliance_bundle_refuses_raw_session_member` (`compliance/bundle_tests.rs`): a receipt whose `acp` block carries `sessionId` fails with the membership error. Fails on the base: the raw member is the join key.
13. `cert_generate_without_tenant_index_keys_refuses` and `cert_generate_resolves_raw_id_across_generations` (`chio-cli` `tests/session_certificate.rs`).
14. `scripts/check-wire-schemas.py` fails before the protocol-refusal constant lands and passes after.

Every existing test that seeds a raw `session_id`, `sessionId` or `acp-session:<raw>` changes to the handle in the same PR: `chio-core-types` `tests/receipt_metadata_blocks.rs`, `tests/security_receipts.rs`; `chio-kernel` `compliance_certificate/tests.rs`, `kernel/tests/{protocol_refusal,reserved_session_metadata,session,post_effect_receipts}.rs`, `kernel/tests/reserved_session_metadata/kernel_written.rs`, `kernel/tests/durable_admission/review_regressions.rs`, `admission_operation_tests/terminal_projection.rs`, `tests/compliance_certificate_hybrid.rs`; `chio-store-sqlite` `receipt_store/session_certificate_read/tests.rs`, `tests/session_certificate_read.rs`, `admission_operation_store_tests/authorization_consumption.rs`; `chio-cli` `cert/session_receipts_tests.rs`, `tests/session_certificate.rs`, `cli/session/tests/pending_approval.rs`; `chio-acp-proxy` `compliance/bundle_tests.rs`, `tests/attestation_{denials,signer,support,compliance,clock,telemetry_transport}.rs`; `chio-acp-edge` `tests/all.rs`; `chio-cross-protocol` `tests.rs`; `chio-mcp-edge` `runtime/nested_flow_tests.rs`, `runtime/source_receipt_tests.rs`, `runtime/runtime_tests/{execution_evidence,stateless_revision}.rs`; `chio-mcp-remote` `remote_mcp/hosted_tests/protocol_refusal.rs`, `remote_mcp/tests.rs`; `chio-http-core` `authority/tests.rs`; `chio-control-plane` `security/active_defense_host_tests/terminal_response_refusal.rs`.

## 8. PR slicing

1. **Primitive** (`chio-core-types` only, no signed bytes). `IndexPurpose::SessionHandle`, `IndexDomain::SessionHandle`, shared field encoder, `SessionHandle`, `session_membership`, the `AcpReceiptProjection` type change and the protocol-refusal schema constant. Tests 1-6. Lands first so PD2-F writes the handle directly.
2. **Key-set wiring** (no signed bytes; after #1996). The directory reader in `tenant_index/load.rs` moves to `chio-secure-ipc` as a module beside `seed_custody`, reusing its owner, mode and no-follow file checks. It returns the 32-byte set keys of the active and retired generations, zeroized on drop, and the host builds `TenantIndexKeySet::new` from them, so `chio-secure-ipc` takes no dependency on `chio-core-types`. The core copy, its `std`-gated module and its `TenantIndexKeyLoadError` are deleted, and the loader tests in `chio-core-types` `tests/tenant_index.rs:363-395` move with it. `Arc<TenantIndexKeySet>` becomes a required argument of `KernelReceiptSigner::new` (`kernel_signer.rs:70`), `KernelCapabilityChecker::new` (`kernel_checker.rs:149`) and the kernel configuration that `open_session_with_id` reads. The `chio mcp` hosts and `chio cert` take `--tenant-index-keys <dir>` and refuse to start without it, local dev flows included. `chio init` and the dev quickstart provision a key set explicitly through `chio keys tenant-index generate`. The kernel never generates one itself. Test 7.
3. **Retained-session statements** (no behaviour change). The SQL in `session_certificate_read.rs:277-281,362-366` and `session_certificate_read/preflight.rs` moves into named `.sql` files beside the reader (section 10.3). The existing reader tests stay green unchanged.
4. **Flip** (signed bytes, one PR). All three writers, both readers through `session_membership`, the authorization-path carriers in 3.2, both certificate bodies, schemas, signed-artifact examples, generated SDK types, `wire-schemas.lock`, registry descriptions, PROTOCOL 6.4, `spec/COMPLIANCE-CERTIFICATE.md`, `docs/protocols/SESSION-COMPLIANCE-CERTIFICATE.md` and the CLI. Writers and readers move together because the reader compares across members and receipts; a split leaves a window where the readers join raw ids against handles. Tests 8-14 and every fixture in section 7. `docs/formal/COVERAGE.md` regenerates last if the proof-coverage check asks for it.

## 9. Decisions

### 9.1 arc-63 rulings (2026-10-30)

- **D1. Member names.** The members are renamed to `sessionHandle` and `session_handle`. The old names are removed.
- **D2. Purpose.** The handle gets a new `session-handle` purpose with its own subkey and the `sh1` prefix.
- **D3. Signer binding.** The preimage binds the receipt signer key. In v1 it does not also bind the agent subject (section 9.2).
- **D4. Generation.** The handle is fixed at session open (section 4.4).
- **D5. Provisioning.** PR 2 provisions the key set. Every flow without a configured key set fails closed, local dev included. `chio init` and the dev quickstart provision a set explicitly, and the kernel never provisions one.
- **D6. Kernel-session carriers.** These are handled by follow-up row SESSION-HANDLE-KERNEL-CARRIERS (section 9.3).
- **D7. Telemetry.** This is handled by follow-up row SESSION-HANDLE-TELEMETRY (section 9.3), outside this PR sequence.
- **D8. Loader location.** PR 2 moves the key-set directory reader from `chio-core-types` into `chio-secure-ipc` beside `seed_custody` (#1996), changes every caller and deletes the core copy. PR 2 starts after #1996 lands.

### 9.2 Known limit: signers that share a key

The handle separates sessions by origin, signer key and raw id. When several ACP proxies sign under one key and their agents pick the same `sessionId`, their receipts get one handle and join one session. The readers cannot tell them apart. Operators avoid this by giving each proxy its own signing key. Binding the authenticated agent subject would close the gap, but audit-only ACP entries carry no capability, so the subject would have to come from proxy configuration. That work is follow-up row SESSION-HANDLE-SHARED-SIGNER.

### 9.3 Follow-up rows

- **SESSION-HANDLE-SHARED-SIGNER.** Bind the authenticated agent subject into the ACP session handle, so that proxies sharing one signing key cannot merge sessions (section 9.2).
- **SESSION-HANDLE-KERNEL-CARRIERS.** Move these to the handle:
  - the session anchor `sessionId` (`chio.session_anchor.v1`, `session/anchor.rs:82,97,151`, schema `kernel/session-anchor.schema.json:191`);
  - the request lineage `session_id` (`receipt/lineage.rs:35,54`).

  Also replace the unkeyed `restored_kernel_session_id` (`chio-mcp-remote` `http_service.rs:1178-1181`) with a keyed derivation.
- **SESSION-HANDLE-TELEMETRY.** OTel export carries the raw id (`telemetry.rs:383-384`, `cert.session_id`; `:435-436`, `chio.session_id`) and an unkeyed SHA-256 trace id (`derive_trace_id`, `:445-449`). This row moves export to the handle and derives the trace id from it.

## 10. Design charter compliance

This section maps the design onto `DESIGN-QUALITY-CHARTER.md` and the R1-R15 checklist in `ARC-DESIGN-RULES.md`.

### 10.1 Persistence

The design persists no handle and no key.

- Handles are derived values. The kernel holds a session's handle in memory for the life of the session and derives it again on restore (section 4.4). The ACP proxy keeps a bounded in-memory map for the life of the process. Neither adds a table, column, schema, migration or row type.
- Receipts carry the handle inside signed metadata, so the existing receipt store persists it as part of the receipt JSON with no schema change.
- Keys stay in the operator-provisioned `--tenant-index-keys <dir>` layout. No crate writes them.
- If a later change needs a handle index (for example, to avoid the full claim-log scan in the retained reader), it lives in `chio-store-sqlite` under its own per-aggregate module behind a port trait owned by the consumer's domain crate. That change is out of scope here.

### 10.2 Crate boundaries (R1, R2, R3)

| Crate | Change | Boundary |
|---|---|---|
| `chio-core-types` | `IndexPurpose`/`IndexDomain` variants, `SessionHandle`, shared field encoder, `session_membership`, `AcpReceiptProjection` type change, protocol-refusal schema constant | pure types and functions; no IO, no storage |
| `chio-kernel` | derive at session open (new module `kernel/session_ops/handle.rs`), refusal writer, consumption field, certificate body | no storage or SQL added |
| `chio-acp-proxy` | signer, checker, compliance verifier, bounded handle map | no storage or SQL added |
| `chio-cross-protocol` | carries the handle in place of the raw id | no storage |
| `chio-store-sqlite` | retained reader takes `&SessionHandle` and calls `session_membership` | persistence stays in the store crate |
| `chio-secure-ipc` | key-set directory reader moved from `chio-core-types` (PR 2) | custody IO stays in the security crate; no dependency on `chio-core-types` |
| `chio-cli` | `--tenant-index-keys`, `chio cert` input and output | host crate; no SQL |
| `chio-control-plane` | none | none |

`tenant_index/load.rs` is existing file IO inside `chio-core-types`. The design adds none, and PR 2 moves it to `chio-secure-ipc` (D8).

### 10.3 Queries (R4)

The design adds no query. The retained-session reader already embeds SQL in its logic: `git grep -c 'SELECT\|INSERT\|UPDATE '` counts 4 lines in `session_certificate_read.rs` and 6 in `session_certificate_read/preflight.rs`. PR 4 edits that reader, so PR 3 first moves those statements into named `.sql` files in `receipt_store/session_certificate_read/` and loads them with `include_str!`, following the `admission_operation_*.sql` convention in the same crate. The files are grouped by the retained-session aggregate.

### 10.4 Abstractions and their payoff (R5)

- `SessionHandle` newtype: it encodes the invariant that a signed session member is never a raw id, and its parser accepts only the `sh1.` form.
- `session_membership`: it removes the duplicated membership readers (`signed_membership`, `receipt_session_id`), which today enforce the same rule in two crates.
- Shared length-prefixed field encoder: it removes the second copy that the session handle would otherwise add next to `enterprise_subject.rs`.
- `IndexPurpose::SessionHandle`: it uses the purpose mechanism the key set already defines.
- No new trait. The retained reader has one consumer (`chio cert`), so a port trait would be a single-use seam. The ACP handle map is a private type with no seam.

### 10.5 File budgets (R11)

Every touched production file stays below the 1,200-line warning level except `chio-kernel` `session.rs` (1,660), `receipt_store.rs` (1,642) and `kernel/session_ops.rs` (1,161, near the warning level). `session.rs` gains one field and one accessor, `receipt_store.rs` renames one field, and derivation goes into the new `kernel/session_ops/handle.rs`, so none of the three grows by more than a few lines. The other touched files are `kernel_signer.rs` (605), `compliance.rs` (797), `kernel_checker.rs` (430), `session_certificate_read.rs` (445), `tenant_index/mod.rs` (497), `metadata.rs` (698) and `key_registry.rs` (723).

### 10.6 Remaining rules

- **Fail-closed (R7):** a missing key set refuses startup. An unknown `key_id`, a malformed handle, a raw-id member or conflicting members refuse membership, and the receipt is excluded with an error. No path falls back to the raw id.
- **No legacy (R6):** the old member names, both reader copies and the raw-id certificate fields are deleted in PR 4, with every caller and fixture in section 7 moved in the same PR. Nothing decodes both forms.
- **v1 only:** every schema id stays at v1.
- **Typed errors (R7, R9):** `SessionMembershipError` is a closed enum, and handle errors reuse `TenantBindingError`. No `String` identifiers are added.
- **Tests (R12, R13):** section 7 covers behaviour and refusal paths. The `sh1.` parser gets one `proptest` (arbitrary strings never panic, and every derived handle round-trips) in place of more hand-written cases, with no harness-only or duplicate cases. Test 14 runs the existing wire-schema gate and adds no script.
- **Spec in the same PR (R14):** PR 4 carries the PROTOCOL 6.4 change with the wire change.
