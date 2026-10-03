# Compliance and product-truth review, October 1, 2026

**October 2 follow-up:** AP1, KG1 and RL1 now have implemented, locally verified
source repairs in the [identity and authority execution record](2026-10-02-identity-authority-release-closure-execution.md).
The historical findings and counts below remain the October 1 snapshot. This
follow-up does not establish deployed migration, hosted keyless signing, release
publication or closure of the other findings. KG2/KG3 and AP2/AP3 now have
bounded local source acceptance in the
[issuer and approval execution record](2026-10-02-issuer-lifecycle-approval-authority-execution.md).
Linux custody, explicit provisioning and unavailable legacy workflows are stated
there. AC4 protected writes and scoped CA3 ingress now have local acceptance in
the [lease and ingress record](2026-10-02-lease-fencing-framework-ingress-execution.md).
AP4-AP6 and the two threshold-reader gaps are implemented in the
[inbound authority record](2026-10-02-inbound-authority-execution.md), with local
qualification tracked there. Bearer compatibility, volatile replay, unsupported
origin-specific proof policy and trusted-proxy deployment remain explicit limits.
AP7 shared TLS/control-client transport and AP8 truthful revocation are implemented
in the [October 3 execution record](2026-10-03-transport-revocation-execution.md),
which owns their local qualification and review boundaries. AP9/AP10 receipt
integrity and the export/retention lifecycle are next. The findings and counts
below retain their historical meaning.

A compliance-documentation review of `main` (`f5566d9a76`) on September 30 and October 1 checked
every compliance, security and supply-chain claim in the repository against the code, the CI
history and the published artifacts. It produced a replacement compliance guidance set on the
separate `docs/compliance-guidance` branch and a list of product defects behind the claims. This
document carries those defects to this branch. Each one was re-verified read-only at `122414b48e`
(this branch's tip on October 1, 786 commits past `f5566d9a76`) by four independent checkers, one per
area below, who traced the code, read the workflow history of `bb-connor/arc` and
`backbay-labs/chio`, and inspected the published release, npm, PyPI and crates.io artifacts.
Findings cite `path:line` at `122414b48e` unless they name another commit. Severity uses the pass 9
scale: High is an exploitable authority or integrity break or a regression that breaks operation;
Medium is a real security or evidence gap with limited preconditions, or a false public claim; Low is
hardening or consistency; Note is an observation.

**Judgment: The branch closed two of the issues found on `main` (loopback approvals and the shared
admin token) and built a real signed-release pipeline, but most of what the compliance review found
is still true at the tip, and none of it is on any plan. Three findings are High: a sidecar subject
key anyone can compute, unsigned cluster authority replication over plain HTTP, and a release
verification guide whose signer identity names an unclaimed GitHub organization. Underneath them
is one pattern: capabilities that exist as libraries or schemas are described, in specs, runbooks,
the README and the compliance mappings, as running in the shipped binaries. Retention, signed
evidence, the session certificate, SIEM export, the emergency stop, several guards, attestation
verification and capability constraints all fall in that gap. No artifact has ever been released
through the signed pipeline, the published v0.1.0 binary carries 27 known advisories and is still
what the installer serves, and four scheduled security lanes have been red for weeks without anyone
noticing.**

## Summary

| Area | Prefix | H | M | L | N | Closed since `main` |
| --- | --- | --:| --:| --:| --:| --- |
| API protection, approvals and control-plane authentication | AP | 1 | 10 | 1 | 0 | 2 (loopback approvals, admin token) |
| Receipts, evidence, retention and SIEM | EV | 0 | 11 | 6 | 1 | 0 |
| Keys, cryptography, guards and policy | KG | 1 | 12 | 5 | 1 | 1 partly (signed manifests on `mcp serve`/`serve-http`) |
| Release, supply chain, CI and public claims | RL | 1 | 10 | 9 | 0 | 0 |
| **Total** | | **3** | **43** | **21** | **2** | |

## The three High findings

| ID | Claim | Since | Verification |
| --- | --- | --- | --- |
| AP1 | `chio api protect` derives each sidecar-minted capability's subject keypair from SHA-256(subject, 0, job_uid); the SDK documents the subject as the agent's public key, so the "private" key is public, DPoP gives no sender binding, and the honest agent's real key never matches | `main` | Traced through both mint routes, the scope alias and `dpop.rs:22` |
| KG1 | Cluster authority replication applies a peer's unsigned snapshot, adding every listed trusted issuer and possibly replacing the head key; peers authenticate with the shared service token over plain HTTP, so a token holder or an on-path attacker can add a capability issuer to every follower | `main` | Traced from `cluster/deltas.rs:643-654` to `authority.rs:188-232` |
| RL1 | `docs/install/VERIFY.md` and `PUBLISHING.md` pin cosign verification to `backbay-industries`, a GitHub name that is unclaimed (404 as organization and as user); anyone can register it and sign artifacts that pass the documented verification | `main` | GitHub API, October 1 |

## API protection, approvals and control-plane authentication (AP)

**AP1, High. Sidecar subject keys are derivable by anyone.**
`crates/products/chio-api-protect/src/proxy/sidecar.rs:1206-1216` seeds `Keypair::from_seed` with
SHA-256(subject || 0x00 || job_uid) for both mint routes (`sidecar.rs:249`, `:588`). The
`/v1/capabilities` alias accepts a caller-supplied `ChioScope`, so grants can carry
`dpop_required: true` (`sidecar.rs:501-503`), and `job_uid` defaults to the empty string there
(`sidecar.rs:548`). The Python SDK documents `subject` as the agent's hex public key
(`sdks/python/chio-sdk-python/src/chio_sdk/client.py:341-365`), so the derived private key is
SHA-256 of a public value. DPoP compares the proof key with `capability.subject`
(`crates/kernel/chio-kernel/src/dpop.rs:22`): whoever holds a stolen token can forge proofs, and the
honest agent's own key never matches. This contradicts `proxy/attenuation.rs:16-17` ("must not hold
or derive that key").
Fix: the subject must be a caller-supplied public key; reject non-key subjects; delete
`derive_sidecar_subject_key`. Test, failing first, through the router: mint with
`dpop_required: true` and subject key A; `/v1/evaluate` denies a proof signed with the derived seed
and allows one signed by A.
Owner: `docs/security/sidecar-control-authority.md`; `launch-execution-plan.md` M4 item 3.

**AP2, Medium. API-protect approvals gate nothing, and approvals need not cover the arguments.**
The branch added `GovernedTransactionIntentBody::BoundToolInvocation {capability_id,
parameters_hash}` (`crates/core/chio-core-types/src/capability/governance.rs:1132-1142`, enforced in
`crates/kernel/chio-kernel/src/kernel/governed_validation.rs:18-49`, `92dc4f45f8`), but only
`chio mcp serve-http` builds it (`crates/protocol/chio-mcp-remote/src/remote_mcp/approvals.rs:230-268`).
The unbound intent is still accepted with an approval token (`governed_validation.rs:24-30`), and on
`/v1/evaluate` both the intent and `request_id` are caller-supplied (`proxy/mediated.rs:241-251`).
`/approvals/submit` takes a caller-supplied `parameter_hash` that operator-respond then signs as the
intent hash (`proxy/approval.rs:154-178`, `:327-337`). No evaluation path reads the API-protect
approval store (`crates/platform/chio-http-core/src/authority.rs:592` is an accessor only), and the
SDK submits SHA-256(args) while the kernel compares `intent.binding_hash()`
(`governed_validation.rs:417`), so those tokens can never be redeemed; waiting for approval is the
agent's choice.
Fix: require `BoundToolInvocation` whenever approval is required; build the intent server-side from
capability, tool and arguments on API protect as serve-http does; wire the approval store into
evaluation or document it as advisory. Tests: approve arguments A, call with B, deny; an unbound
intent under `RequireApprovalAbove` denies.
Owner: `docs/security/threshold-approval-collection.md`; `launch-execution-plan.md` M4 item 3.

**AP3, Medium. Approver identity is not recorded and any trusted key can approve.**
Operator-respond signs with the sidecar's own key and records only a free-text reason
(`proxy/approval.rs:298-353`); submit substitutes the sidecar key when `requested_by` is not a key
(`approval.rs:211-225`). The kernel accepts an approval signed by any CA, capability-authority or
kernel key (`governed_validation.rs:274-305`), with no per-policy approver set. `ApprovalGuard` has
no production constructor. `RequireDualApproval` never matches, so grants carrying it always deny
(`crates/kernel/chio-kernel/src/request_matching.rs:466`). HushSpec parses `approve_above_currency`,
`timeout_seconds` and `on_timeout` (`crates/guards/chio-policy/src/models/rules.rs:333-349`) and
`approve_when` (`models/extensions.rs:96-101`) and enforces none of them, while
`examples/policies/canonical-hushspec.yaml:58-68` presents all four as working.
Fix: approvals signed by configured approver keys and recorded in the receipt; reject unenforced
policy fields at load until implemented; correct the example. Test: loading a policy with
`on_timeout`, `approve_when` or `approve_above_currency` fails.
Owner: `threshold-approval-collection.md`. Related: KG2 (the approver trust set is the issuer set).

**AP4, Medium. API protect allows by default.**
Safe methods get SessionAllow and `x-chio-side-effects: false` gives SessionAllow for any method,
POST included (`crates/protocol/chio-openapi/src/policy.rs:29-63`); unmatched paths fall back to the
method default (`crates/products/chio-api-protect/src/evaluator.rs:446-465`); no session is required
(`evaluator.rs:372`, `chio-http-core/src/authority.rs:251-252`). The spec is discovered from the
protected upstream by default (`proxy/state.rs:472`, `spec_discovery.rs:55-80`), so the protected
service decides which of its operations need a capability. The behavior is pinned by
`evaluator.rs:1472-1501` and stated in `crates/products/chio-api-protect/ARCHITECTURE.md:100-104`.
Fix: deny unmatched routes for every method; anonymous reads only by local opt-in; honor side-effect
overrides only from an operator-pinned spec (path plus hash). Test: GET to an unknown path and a
POST marked `side-effects: false` both return 403 and the upstream sees nothing.
Owner: `launch-execution-plan.md` M4 item 2. Adjacent: PB9.

**AP5, Medium. Capabilities are bearer tokens almost everywhere.**
`check_subject_binding` compares a caller-supplied string (`request_matching.rs:190-203`), and on
`/v1/evaluate` `agent_id` defaults to the capability's own subject (`proxy/mediated.rs:405-407`).
Only that route installs a DPoP nonce store (`mediated.rs:184-200`); other kernels hard-code
`dpop_proof: None` (`session_ops.rs:769`, `chio-http-core/src/authority.rs:1000`), so a
`dpop_required` grant always denies on `chio run`, `chio check`, `chio mcp serve` and `serve-http`,
and HushSpec cannot set `dpop_required` (`chio-policy/src/compiler/scope.rs:75,95,114`). On
serve-http a JWT whose `cnf` carries only RFC 9449 `jkt` deserializes to an empty constraint
(`chio-mcp-remote/src/remote_mcp/session_core.rs:827-845`) and `sender_constraint.rs:95-140` checks
nothing, so the token is accepted as a plain bearer: the binding fails open.
Fix: install DPoP in every long-running kernel and carry proofs on MCP `tools/call` `_meta`; add a
policy field for `dpop_required`; reject unknown or `jkt` confirmation until `jkt` is verified; derive
`agent_id` from the authenticated principal. Test: a `jkt`-only JWT without a DPoP header gets 401.
Owner: `launch-execution-plan.md` M4 item 3; `docs/security/m4-consumer-migration.md:51-54`.

**AP6, Medium. mTLS and attestation sender binding is satisfied by headers the caller sets.**
`sender_constraint.rs:107-126` compares `cnf["x5t#S256"]` and `chioAttestationSha256` with the
request headers `x-chio-mtls-thumbprint-sha256` and `x-chio-runtime-attestation-sha256`
(`session_core.rs:95-96`). The listener is plain HTTP with no trusted-proxy configuration, so the
thief of a certificate-bound token copies the thumbprint from the token into the header.
`spec/PROTOCOL.md:3093-3110` relies on this continuity.
Fix: verify the client certificate on a TLS listener, or accept the header only from a configured
proxy. Test: an x5t-bound token with a self-set header gets 401.
Owner: `launch-execution-plan.md` M4 and M6.

**AP7, Medium. No listener terminates TLS, and clients accept plain HTTP to any host.**
`chio trust serve` (`crates/platform/chio-control-plane/src/trust_control/service_runtime/init.rs:128,227`),
`chio mcp serve-http` (`chio-mcp-remote/src/remote_mcp/http_service.rs:32,168`) and
`chio api protect` (`proxy/state.rs:862,904`) bind plain TCP; trust-control clients accept
`http://` to any host (`service_runtime/client/validation.rs:13-19`). This is what makes KG1 and AP6
exploitable on the network.
Fix: a rustls listener option on all three; refuse a non-loopback bind without TLS unless an
explicit plaintext opt-in is given; clients refuse `http://` to non-loopback hosts. Tests: startup
fails per binary; a client call to `http://10.0.0.1` is refused.
Owner: `sidecar-control-authority.md` ("Migration and limits"); `launch-execution-plan.md` M6 and M9.

**AP8, Medium. Session trust revocation reports success when revocation fails.**
`POST /admin/sessions/{id}/trust` maps each capability revoke with `.unwrap_or(false)`
(`chio-mcp-remote/src/remote_mcp/admin.rs:602`, `:608`) and always returns `"revoked": true`
(`:622`); the per-capability re-read (`:927-974`) can show `false` under the top-level `true`. The
single-capability route handles errors correctly (`:497-533`). This fails open on an
incident-response action.
Fix: non-2xx unless every capability is confirmed revoked. Test: a control plane returning 500 on
revoke, or a read-only revocation store, yields non-2xx.
Owner: `launch-plan.md`, "Dedicated admin credentials at every hosted-MCP launch".

**AP9, Medium. API-protect receipts are mutable and outside the evidence chain.**
`http_receipts` and `tool_receipts` have no sequence column and no triggers
(`proxy/state.rs:123-162`) and are written with `INSERT OR REPLACE` (`state.rs:225-256`); every
mediated `/v1/evaluate` and `/v1/reconcile` receipt lands only there (`mediated.rs:593,748`). The
mediation kernel has no receipt store and `retention_config: None` (`mediated.rs:123-149`). Nothing
exports or checkpoints these tables. Without a seed the signing key is `Keypair::generate()` on every
start (`state.rs:567`), with only a CLI warning (`runtime.rs:269-274`).
Fix: write through the append-only `chio-store-sqlite` log (insert that errors on conflict, update
and delete triggers); give the mediation kernel a receipt store and include its receipts in evidence
export; require a seed in durable mode. Tests: a duplicate receipt id errors; evidence export
includes mediated receipts.
Owner: `launch-execution-plan.md` M8; `kernel-signing-authority.md`.

**AP10, Medium. Operator-submitted records verify as mediated allow decisions.**
`/v1/receipts` signs the submitted record with the sidecar key as Allow, MediatedDecision, Prevent,
Mediated (`proxy/sidecar.rs:432-462`), and verification reports it authorized
(`chio-http-core/src/evaluation.rs:53-63`). Only the route and a policy label distinguish it from a
real decision. It requires the control token.
Fix: a distinct receipt kind and trust level; verification reports it as not authorized. Test: submit
a record, then `/chio/verify` returns `authorized: false`.
Owner: `launch-execution-plan.md` M4 (receipt-origin repairs).

**AP11, Medium. API protect keeps every receipt in memory, and an oversized legacy row stops startup.**
Both receipt tables are loaded at startup (`proxy/state.rs:678-692`) and every receipt is pushed into
an in-memory `Vec` that only tests read (`router.rs:566-567`, `:580-581`), so memory grows without
bound. Since `943482d2cb`, a legacy row over 1 MiB fails startup (`state.rs:184-221`).
Fix: drop the in-memory logs and stop loading history at startup. Tests: memory is flat over N
requests; startup succeeds with an oversized legacy row.
Owner: `launch-execution-plan.md` M8 items 2 and 6.

**AP12, Low. Tenant read tokens can only be passed on the command line.**
`--tenant-read-token` has no environment or file source (`crates/products/chio-cli/src/cli/types/trust.rs:18-23`),
unlike the neighboring service and authority tokens (`:15`, `:28-32`), so tokens appear in the
process list.
Fix: a hidden environment variable or a 0600 tokens file. Owner: `docs/security/tenant-read-contracts.md`.

**Closed since `main`.** Loopback approvals without `CHIO_SIDECAR_CONTROL_TOKEN` are refused
(`f1b6c64d9f`, `cca2117f88`; `proxy/control.rs:131-174`, tests in `proxy/tests/control_auth.rs`).
`chio mcp serve-http` now requires a dedicated `--admin-token` distinct from the session token
(`bc44f87e26`; `http_service_auth.rs:104-140`). Residual note: one shared control token both submits
and approves (AP3).

## Receipts, evidence, retention and SIEM (EV)

**EV1, Medium (High for a deployment that pages on receipts). Receipts carry raw tool arguments everywhere they go.**
`ToolCallAction` stores raw `parameters` beside the hash
(`crates/core/chio-core-types/src/receipt/decision.rs:35-51`), built from the live arguments
(`crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs:660-665`,
`kernel/responses/deny_responses.rs:82-83`) and signed with `redaction_mode: RedactionMode::None`
(`kernel/responses/receipt_persistence.rs:162`); API-protect advisory receipts do the same
(`proxy/sidecar.rs:1137-1158`). The full receipt is stored in `chio_tool_receipts.raw_json` and sent
to OCSF `api.request.data` and `raw_data` (`crates/observability/chio-siem/src/ocsf.rs:149,189`),
Splunk, Elastic, Datadog, Sumo and the webhook (`exporters/splunk.rs:161`, `elastic.rs:172`,
`datadog.rs:255,291`, `sumo_logic.rs:69,175`, `webhook.rs:304`), PagerDuty `custom_details`
(`alerting.rs:327,749`) and OpsGenie `details` (`alerting.rs:576`). A secret-leak deny is ranked
Critical (`alerting.rs:172`), so the page carries the secret that was blocked. `redaction_status`
is never written and CEF reports `unknown` (`exporters/cef.rs:56-57,89-90`). Personal data, PHI or
card numbers passed to a tool therefore land in every receipt sink; `docs/operator-runbook/phi-policy.md:42-49`
and `docs/compliance/pci-dss-v4.md:56` claim otherwise.
Fix: keyed argument commitments in the signed body with payloads in an erasable side store and
`redaction_mode` set to match; SIEM and alert exports send a projection that keeps
`parameter_hash` and drops `parameters`; paging payloads limited to an allowlist; `redaction_status`
derived from the signed mode. Test: a secret-leak deny with a sentinel argument through `ChioKernel`,
`SqliteReceiptStore` and the SIEM manager; the sentinel is absent from `raw_json`, every sink payload
and both paging bodies, and CEF `cs6` is not `unknown`.
Owner: none; needs a design (`spec/PROTOCOL.md:1121` defines `redaction_mode`). Nearest:
`launch-execution-plan.md` M7 step 2. This is a prerequisite for any pilot that handles personal data or PHI.

**EV2, Medium. Admission blobs keep credentials, arguments and raw output forever.**
`RawInvocationOutcomeV1` holds `output` and `request_canonical_json`
(`crates/kernel/chio-kernel/src/tool_outcome.rs:370-399`), the canonical form of the full
`ToolCallRequest` including capability, arguments, DPoP proof and approval tokens
(`tool_outcome.rs:526`; `runtime.rs:62-98`), taken before post-invocation sanitization
(`admission_coordinator/terminal.rs:268-283`, `:378-390`). `compact_retained_invocation_blobs`
(`crates/platform/chio-store-sqlite/src/tool_outcome_store.rs:144`) is called only from tests, and
`SideEffecting` is the default mode (`admission_operation/identity.rs:371-372`). The branch's retained
request strips one-shot credentials (`retained_request.rs:159-178`), so `launch-plan.md:1146-1147`
("one-shot credentials are not retained") is true of that table and false of this one.
Fix: build `request_canonical_json` from the credential-stripped request or store a digest reference
to the retained request; run compaction from a kernel maintenance owner driven by retention
configuration. Test: one durable side-effecting call with a DPoP proof and an approval token leaves no
credential keys in `tool_outcome_blobs`; after trusted time passes the cutoff through the scheduler,
`canonical_bytes` is NULL and the digest remains.
Owner: `launch-execution-plan.md` M8 item 3; `launch-plan.md`, "Atomic original tool request retention".

**EV3, Medium. MCP edge rejections leave no receipt and no operator record.**
`chio mcp serve` and `serve-http` reject calls that no capability covers, including constraint and
model-metadata mismatches, before the kernel and without a receipt
(`crates/protocol/chio-mcp-edge/src/runtime/tool_calls.rs:363-384`); matcher errors are swallowed by
`.unwrap_or(false)` (`runtime/protocol/capabilities.rs:10-21`). The only signal is a `tool_denied`
MCP `notifications/message` to the client (`runtime_flow.rs:339-366`), which the client can suppress
with `logging/setLevel` (`requests.rs:851-880`); the crate has no server-side log and the metric is
recorded only after a kernel response (`tool_calls.rs:232,766`). The branch added more receiptless
pre-kernel rejections in the same function (`:314-357`, `3d3e4b4d9d`; `:388-408`, `348b7ae4c2`).
Uncovered `resources/read` and `prompts/get` are refused without receipts (`requests.rs:459-471`,
`:521-527`, `:692-705`); a session-roots resource denial does produce one (`session_ops.rs:258-300`).
`chio mcp wrap` persists cage lifecycle receipts (`80b632fad2`) but no per-call decisions
(`wrap.rs:711-716`, `:378-396`). `README.md:22`, `crates/protocol/chio-mcp-edge/ARCHITECTURE.md:7-10`
and `spec/PROTOCOL.md:19` say every call is receipted.
Fix: route edge denials to a kernel-signed deny (pass the best candidate capability or add a kernel
deny for an empty or non-matching set, as `chio-tower/src/evaluator.rs:771` does); propagate matcher
errors; log server-side; extend resource-read deny receipts to out-of-scope reads and prompts. Test:
`chio --receipt-db $DB mcp serve` with a constrained grant; the client sets level `error` and sends a
violating `tools/call`; exactly one verifiable Deny receipt is in `$DB` and the deny metric is 1.
Repeat for `resources/read` and `prompts/get`.
Owner: `docs/superpowers/plans/2026-09-29-protocol-authority-boundaries.md`; the wrap part to
`docs/security/consumer-support.md` C13.

**EV4, Medium. serve-http session credentials refuse tools with a bare 403.**
In session-credential mode, a tool outside `allowed_tools` returns HTTP 403 with no log and no
receipt (`chio-mcp-remote/src/remote_mcp/http_service.rs:287-291`; `session_credentials.rs:463-503`;
`7ba06fdd6f`).
Fix and test as EV3. Owner: `2026-09-29-protocol-authority-boundaries.md`.

**EV5, Medium. Retention runs in no shipped binary.**
`retention_config: None` in the shared kernel builder (`crates/platform/chio-control-plane/src/lib.rs:157-175`,
behind `build_kernel` and serve-http's `session_core/factory.rs:323,508`), API protect
(`proxy/mediated.rs:149`), `mcp wrap` (`wrap.rs:393`) and three control-plane paths
(`payment_config.rs:204`, `governed_sim.rs:117`, `finding_operator_purchase.rs:487`).
`chio-config::to_kernel_config` (`crates/platform/chio-config/src/schema.rs:68-102`) is called only by
its own tests; no binary loads `chio.yaml` through it. Nothing calls `archive_receipts_before`; the
only operator command is `chio receipt retention repair`. Rotation copies to an archive and deletes
from the live store (`receipt_store/evidence_retention.rs:1643-1664`) and every read and export path
reads only the live store (EV6), so if it were enabled the 90-day default
(`chio-kernel/src/receipt_store.rs:64-75`) would be the queryable and exportable window, below the
EU AI Act Art. 19(1) and 26(6) six-month minimum. `spec/CONFIGURATION.md:124` and three compliance
mappings claim configurable retention. Because nothing shipped rotates, SR1 hits only library
embedders today; wiring retention must land with SR1 and SR6.
Fix: plumb retention (days, archive path, interval) through policy or flags for `trust serve`,
`mcp serve`, `serve-http` and `api protect`; require an explicit value instead of a silent 90-day
default; give export and query an archive-aware read. Test: start `trust serve` or `mcp serve` with
retention flags over a store of aged receipts; after one interval the archive has rows, the live
store is pruned, the head verifies, and `chio evidence export --since <old>` still returns them or
refuses explicitly.
Owner: `launch-execution-plan.md` M8; `docs/superpowers/specs/2026-07-07-rfc-0007-retention-design.md`.
Related: SR1, SR6.

**EV6, Medium. Evidence packages are unsigned and verify against their own keys.**
`manifest.json`, the root of the file hashes, is written unsigned
(`crates/platform/chio-control-plane/src/evidence_export.rs:1033-1049`). `chio evidence verify`
takes only `--input` (`crates/products/chio-cli/src/cli/types/receipt.rs:237-241`) and passes no trust
input (`evidence_export.rs:1292-1308`); receipts and checkpoints verify against the keys they embed
(`evidence_export/verification.rs:157,196,224`; `chio-kernel/src/checkpoint.rs:1778-1789`). A wholly
fabricated package signed with a fresh key verifies, and so does a package with receipts dropped and
the manifest counts rewritten. Export reads only the live store
(`chio-store-sqlite/src/evidence_export.rs:144`; `:777-844` confirms archived batches are skipped).
Full-bundle certificate verification passes on an empty bundle (`chio-acp-proxy/src/compliance.rs:590-603`).
The branch added a key-pinned `chio receipt verify --trusted-kernel-pubkey` for single receipts
(`3061ec675d`), with no package equivalent.
Fix: wrap the manifest in `SignedExportEnvelope` signed by the kernel key; require
`--trusted-kernel-pubkey` or a trust bundle on `evidence verify` and `import` and refuse signers
outside it; read archives through the watermark ledger; full-bundle verification requires
`receipts.len() == receipt_count > 0` and rechecks chain and timestamps. Tests: a package signed by
`Keypair::generate()` fails against the pinned key; dropping a receipt line and rewriting the
manifest fails; `chio cert verify --full` over zero session rows fails.
Owner: `docs/release/COMPLIANCE_EVIDENCE_EXPORT_PLAN.md:29,157`; `spec/COMPLIANCE-CERTIFICATE.md` section 5.2.
Same root as SR3.

**EV7, Medium. `chio evidence verify` reports `trust_anchored` from an unsigned claim in the package.**
The anchor binding is checked for structure only (`chio-core-types/src/receipt/checkpoint.rs:26-56`);
verify passes no verifier anchor (`evidence_export.rs:1308`), and the kernel accepts the self-declared
anchor (`chio-kernel/src/evidence_export.rs:427-431`; `checkpoint.rs:510-533,1534-1545`). The output
prints `publication_state: trust_anchored` and a `trust_anchor` taken from the package.
Fix: report `trust_anchored` only when a verifier-supplied anchor matches a signed binding. Owner: as EV6.

**EV8, Medium. `chio cert` does not work on a Chio receipt store, and its checks are vacuous.**
`generate` reads table `chio_receipts`/`json_data` (`crates/products/chio-cli/src/cert.rs:228-247`);
Chio stores use `chio_tool_receipts.raw_json` (`chio-store-sqlite/src/receipt_store/bootstrap/open.rs:562`),
so it fails on every store a Chio binary writes; only the stale, unwired smoke script and cert.rs's
own unit tests create that table. The CLI passes empty `required_guards` and `authorized_scopes`
(`cert.rs:38-39,123-124`), so scope and guard checks pass vacuously; guard evidence matches by name
and ignores `verdict` (`chio-acp-proxy/src/compliance.rs:427`); delegation is not checked despite
`compliance.rs:4` and `spec/COMPLIANCE-CERTIFICATE.md:25-33`. No `chio-cli` test invokes `cert`.
`spec/PROTOCOL.md:152-153` and `:2755-2757` describe `chio cert` as TLS certificate tooling.
Fix: read through the `SqliteReceiptStore` API by signed session metadata; derive required guards and
scopes and report "not evaluated" when absent; require passing verdicts; verify delegation from
capability lineage; per-session ordering (EV17). Test: produce session receipts through a real store,
then `cert generate` and `cert verify --full --trusted-kernel-pubkey`; a failing guard verdict and an
empty bundle both fail.
Owner: `docs/superpowers/plans/2026-09-30-cli-authority-proof-readers.md`; `spec/COMPLIANCE-CERTIFICATE.md`.
Related: PR5, PB6.

**EV9, Medium. SIEM export is mislabeled and mostly unwired.**
OCSF `class_uid` 3002 is labeled "Authorization" in category 3 (`chio-siem/src/ocsf.rs:49-55`), and
`type_uid` renders every event as Authentication: Logon (`:101`); class 3002 also requires `user`,
which events lack. `spec/audit-log/export-schema.v1.json:87-92` and
`crates/kernel/chio-kernel-mobile/tests/oracle_round_trip.rs:129,202` enforce the wrong class.
`raw_data` is `serde_json::to_string` (`ocsf.rs:189-191`), not canonical JSON. Nothing emits
`chio.audit-log.export.v1`; CI lints only the schema's shape. The Splunk, Elastic, Datadog, Sumo and
OCSF exporters are constructed only in tests; `chio-wall siem-export` wires the webhook, PagerDuty and
OpsGenie (`crates/products/chio-wall/src/commands.rs:1165-1214`), `chio-wall` is not released, and its
`SiemConfig::default()` trusts no kernel key, so every allow is labeled `Unverified` (`manager.rs:51,73`;
`event.rs:66-82`).
Fix: map to OCSF 6003 API Activity (or 3003 with `user`) and correct schema and fixture; canonical
`raw_data`; build an emitter or mark schema v1 draft; ship the exporters in `chio` or ship
`chio-wall`; require a trusted kernel key. Tests: an OCSF class-table conformance check;
`raw_data == canonical_json_string(receipt)`; `siem-export` without trusted keys exits non-zero.
Owner: ADR-0009 and RFC-0009 part E; `spec/audit-log/export-schema.v1.json`.

**EV10, Medium. Operator runbook steps cannot be performed.**
`docs/operator-runbook/onboarding.md:72` (OCSF export to a SOC sink) and `phi-policy.md:97-103`
require exports and fields nothing produces (EV1, EV9); the HITRUST material on this branch
(`compliance/hitrust/control-mapping.csv:11,18,21`) cites the export schema as evidence.
Fix: correct the runbooks to what ships, or ship it. The `docs/compliance-guidance` branch already
rewrites `phi-policy.md` and removes the HITRUST package (RL11).

**EV11, Medium. There is no operator-reachable emergency stop.**
The stop is an in-memory `AtomicBool` that logs and leaves no signed record
(`crates/kernel/chio-kernel/src/kernel/construction.rs:1654-1703`); the HTTP routes
(`crates/platform/chio-http-core/src/routes.rs:32-39,107-125`) are mounted by no binary; the only
production caller is the native broker's internal fail-closed stop
(`process_host/native_broker/authority.rs:114`). There is no bulk revocation.
`docs/protocols/STRUCTURAL-SECURITY-FIXES.md:1021-1026` says the stop is exposed over HTTP.
Fix: mount the routes behind the admin token on `trust serve`, `serve-http` and `api protect`;
persist a kernel-signed stop and resume record with operator identity and restore the latch on
restart; add bulk revocation by tenant or subject. Test: `serve-http --admin-token`, POST
`/emergency-stop`, a `tools/call` returns a deny receipt, still stopped after restart, a signed stop
record is in the store.
Owner: `STRUCTURAL-SECURITY-FIXES.md` section 5. Related: AC6.

**EV12, Low. Receipt and checkpoint signatures use non-strict Ed25519 verification.**
`ChioReceipt::verify_signature` (`crates/core/chio-core-types/src/receipt/body.rs:491-506`) and
`verify_checkpoint_signature` (`chio-kernel/src/checkpoint.rs:1785-1788`) call the loose verifier
(`crypto.rs:440-444,524-548`; `ed25519_verification.rs:11-22`) although `verify_strict` exists and the
finding verifier uses it; the in-tree test at `ed25519_verification.rs:122-135` shows an identity-key
forgery passing loose verification. Exploitable only where the embedded key is trusted (EV6).
Fix: strict verification and rejection of weak kernel keys. Owner: `docs/security/crypto-wire-decoding.md`. Same root as SF4.

**EV13, Low. Package verification never binds a receipt's `kernel_key` to the checkpoint signer**
(`evidence_export/verification.rs`), although `spec/PROTOCOL.md:3959-3961` says exports keep that binding.
Owner: as EV6.

**EV14, Low. `chio mcp wrap` stamps `_meta.chio_verified` on allowed results (`wrap.rs:690`) with no
durable receipt behind it, and silently ignores the global `--receipt-db`
(`cli/dispatch/api_mcp.rs:44,56`).** Fix: a durable receipt store with a configured key, or refuse the
flag. Owner: `consumer-support.md` C13.

**EV15, Low. Deny alerts page without signature or signer checks** (`alerting.rs:124-147,711-730`),
so a database writer can raise Critical pages with arbitrary text. Owner: as EV9.

**EV16, Low. `CefExporter::export_batch` returns `Ok` without sending** (`exporters/cef.rs:107-113`)
and would satisfy `chio-wall`'s sink check (`commands.rs:1281-1284`). Owner: as EV9.

**EV17, Low. Certificate chain continuity uses global table row ids** (`cert.rs:241`;
`compliance.rs:375-389`), so interleaved sessions fail generation with `ChainDiscontinuity`.
Owner: as EV8.

**EV18, Note. `chio evidence import` accepts a federation policy self-signed by its embedded key**
(`evidence_export.rs:594-613`), and imported shares feed multi-hop issuance
(`trust_control/passport_handlers.rs:1333-1350`). Not traced further.

## Keys, cryptography, guards and policy (KG)

**KG1, High. Cluster authority replication is unsigned.**
A follower passes a peer's authority snapshot to `apply_snapshot`
(`crates/platform/chio-control-plane/src/trust_control/cluster/deltas.rs:643-654`), which adds every
trusted key the peer lists and can replace the head key
(`crates/platform/chio-store-sqlite/src/authority.rs:188-232`). Peers authenticate only with the shared
service token, and peer URLs may be plain `http` (`report_validation.rs:38-45`; AP7). A token holder,
or anyone on the path of a plaintext peer link, can add a capability issuer to every follower, which
then admits capabilities that issuer signs.
Fix: replicate a signed authority chain and verify each step against the current head key; refuse
plaintext peer URLs off loopback. Test, failing first: a follower given a snapshot that adds an
unsigned issuer refuses it, and a capability from that issuer is denied.
Owner: `docs/security/kernel-signing-authority.md`; `launch-execution-plan.md` M6.

**KG2, Medium. Rotation never retires a key, and the kernel key is a trusted issuer with no rotation.**
`SqliteCapabilityAuthority::rotate` only adds the new key to `authority_trusted_keys`
(`chio-store-sqlite/src/authority.rs:138-170,485`); nothing deletes or retires one, and no signed
rotation record is written. Seed-file rotation overwrites the seed and trusts only the new key
(`chio-control-plane/src/lib.rs:460-464`). The kernel adds its receipt-signing key to the trusted
capability issuers even when a remote authority is configured
(`crates/kernel/chio-kernel/src/kernel/validation.rs:330-342`), and trusts it and every unretired
authority key as approval signers (`governed_validation.rs:284-292,308-319`); durable admission
refuses to start if the kernel key changes (`durable_admission.rs:1222-1238`). The opt-in witnessed
keyring (`7ec3bcf594`) adds authorized rotation, but no route writes Retire, Revoke or Recover
(`crates/trust/chio-keyring/src/state.rs:716-739`) and `witnessed_verification_keys` ignores
`verify_until` (`state.rs:797-809`), so rotated-out keys stay trusted indefinitely. Rotation, the
only remedy for a compromise, does not remove the compromised key.
Fix: retired and deadline states for trusted keys; rotation marks the old key verify-only until a
deadline; a signed retire and revoke route; filter keyring keys by `verify_until`; trust the kernel
key as an issuer only when it is the configured local authority, separating the receipt signer from
the capability authority and the approver roster. Tests: issue with A, rotate to B, retire A,
evaluate through `build_kernel`, deny; with a remote authority, a capability signed by the kernel's
receipt key is denied; past `verify_until` the old keyring key leaves the trusted set.
Owner: `kernel-signing-authority.md`; `launch-plan.md:679-689`; enterprise-hardening Phase 9 Task 9.1.

**KG3, Medium. The authority database holding the plaintext seed is created world-readable.**
`SqliteCapabilityAuthority` opens with rusqlite's default mode and sets no permissions
(`authority.rs:52-122,462-466`) while storing `seed_hex` in clear (`:479`); seed files are written
0600 (`durable_admission.rs:1077-1084`). Under umask 022 the seed in the database and its WAL is
readable by every local user.
Fix: create the database 0600 in a 0700 directory and refuse looser modes. Test: open under umask
022 and assert 0600. Owner: `kernel-signing-authority.md`.

**KG4, Medium. Capability constraints can be silently unenforced.**
`ContentReviewTier`, `MaxTransactionAmountUsd` and `RequireDualApproval` never match, so grants
carrying them always deny (`crates/kernel/chio-kernel/src/request_matching.rs:465-466`).
`TableAllowlist`, `ColumnDenylist`, `MaxRowsReturned` and `OperationClass` are admitted as "enforced by
a downstream guard" (`:461-464`), but nothing reads `Constraint::TableAllowlist`: the SQL guard uses
its own configuration list (`crates/guards/chio-data-guards/src/sql_guard.rs:166`); `OperationClass` is
read only by the vector guard (`vector_guard.rs:585`); `ColumnDenylist` and `MaxRowsReturned` only
post-invocation (`result_guard.rs:402,412`). A capability that names `TableAllowlist([orders])` is
enforced nowhere, even with the SQL guard installed. `ensure_capability_issuance_supported` is a
no-op (`chio-kernel/src/authority.rs:93-95`).
Fix: reject at issuance any constraint nothing enforces; deny a grant whose constraints no installed
guard claims; make the SQL guard read `TableAllowlist` and `OperationClass` from the matched grant.
Test: `build_kernel` with the SQL guard, a capability limited to `orders`, and `SELECT * FROM users`
is denied, with and without the guard.
Owner: none; proposed `docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md`.

**KG5, Medium. A HushSpec policy without tool rules grants every tool, and policy hashes do not identify policy.**
No `rules`, no `tool_access`, or a disabled `tool_access` all compile to a `*/*` grant
(`crates/guards/chio-policy/src/compiler/scope.rs:17-28,85-99`). HushSpec cannot set capability TTLs
(fixed 3600 s, `loader.rs:93-95`, `types.rs:249-251`). API protect hashes the constant
`chio_api_protect_mediation_v1` (`proxy/mediated.rs:128-130`, `e44ce720cb`) and `mcp wrap` uses the
literal `mcp-wrap-strict-execution-nonce` (`wrap.rs:383`), contrary to `spec/PROTOCOL.md:1125`; the
runtime hash is SHA-256 over `serde_json::to_vec`, not canonical JSON (`policy/util.rs:65-68`).
Fix: an absent `tool_access` yields an empty scope; a TTL field; hash the real policy material with
canonical JSON. Tests: a rules-less policy grants nothing; two API-protect configurations with
different specs produce different `policy_hash`.
Owner: `spec/PROTOCOL.md`; `sidecar-control-authority.md`. Related: AP4, AP9.

**KG6, Medium. The HushSpec runtime hash omits most rules.**
`policy/util.rs:38-63` hashes neither `velocity`, `human_in_loop`, `computer_use`,
`remote_desktop_channels`, `input_injection`, `browser_automation`, `code_execution`, `detection`,
`runtime_assurance`, `posture`, `origins` nor the `chio` extension, several of which install guards,
so the receipt `policy_hash` does not change when those guards change. Test: two policies differing
only in `rules.velocity` hash differently. Owner: as KG5.

**KG7, Medium. Attestation-gated issuance does not verify attestation.**
`RuntimeAttestationEvidence` has no signature or raw quote
(`chio-core-types/src/capability/runtime_attestation.rs:27-49`); issuance checks only time and
identity fields (`chio-control-plane/src/issuance/attestation.rs:22-52`,
`chio-appraisal/src/appraisal.rs:753-835`) and trust rules compare caller-supplied `schema` and
`verifier` strings (`trust_policy.rs:37-48`). The TEE verifiers in `chio-attest-verify` are not on this
path, and the end-to-end test is `#[ignore]` (`crates/products/chio-cli/tests/trust_cluster.rs:1595`)
and run by no workflow.
Fix: carry the verifier-signed artifact (MAA JWT, Nitro COSE document, GCP token, or an appraisal
signed by a pinned verifier key) and verify it against trust-policy anchors. Test: un-ignore the test
and add forged evidence whose strings match a rule; it is denied.
Owner: none; nearest `docs/security/threat-coverage.md` row `tee_quote_forgery`.

**KG8, Medium. Admission-time attestation is self-asserted by the agent.**
`GovernedTransactionIntent.runtime_attestation` comes from the agent
(`governance.rs:1170-1172`) and passes the same field-only check (`governed_validation.rs:331-386`),
so with a trust policy configured an agent satisfies `MinimumRuntimeAssurance` with forged JSON, and
receipts record it as verified (`receipt_metadata.rs:215-233`). Fix and owner as KG7.

**KG9, Medium. "FIPS 140-3 validated" is still claimed.**
`db8ef7531c` corrected the module header (`crates/core/chio-core-types/src/crypto.rs:15-17`), but
`crypto.rs:1029`, `:1095` and `crates/core/chio-core-types/README.md:127` still say "aws-lc-rs, FIPS
140-3 validated". The `fips` feature requests `aws-lc-rs` with `aws-lc-sys` (`Cargo.toml:43`);
`aws-lc-fips-sys` is locked but never compiled; Ed25519 comes from `ed25519-dalek` and ML-DSA from
`fips204`; release binaries are built without `fips` (`release-binaries.yml:22-23`). FIPS 186-5
approves EdDSA, but no Chio build uses a module validated under FIPS 140-3.
Fix: correct the wording; if validation is wanted, map a feature to `aws-lc-rs/fips` with a startup
`try_fips_mode()` check and route signatures through it. Test: extend
`scripts/tests/check-fips-ci-contract.test.py` to fail on the phrase.
Owner: `crypto-wire-decoding.md:77-78`; `launch-execution-plan.md` M10.

**KG10, Medium. Library-only capabilities are documented as running.**
`ResponseSanitizationGuard`, `DataFlowGuard` and `MemoryGovernanceGuard` are constructed only in
tests; no binary loads WASM guards; no policy key reaches the Bedrock, Vertex, VirusTotal or Snyk
guards (`chio-control-plane/src/policy/guard_config.rs:74-84`); plan evaluation
(`chio-http-core/src/plan.rs:78`) is never mounted; the governed active-response host has only test
callers (`security.rs:415,456`). Signed manifests are now enforced on `mcp serve` and `serve-http`
(`1574d2e45d`). `spec/GUARDS.md:795-803`, `spec/SECURITY.md:303-380`, `README.md:423,678-691`,
`docs/operator-runbook/phi-policy.md:9,98` and `docs/guards/14-EXTERNAL-GUARDS.md:30-41,154-172`
describe them as available. Note that TR2 (VirusTotal breaker) and the Vertex repair concern guards
no shipped binary can instantiate.
Fix: wire each to a policy key with a real-binary test, or label it library-only. Test: every guard
named in `spec/GUARDS.md` has a non-test construction site reachable from `chio-cli`.
Owner: `launch-execution-plan.md:215-226`; `active-defense-rollout.md:142`.

**KG11, Medium. Indirect prompt injection and PHI in tool output reach the agent.**
Injection and jailbreak guards run before invocation over arguments only
(`crates/guards/chio-guards/src/prompt_injection.rs:243-284`, `jailbreak.rs:190-229`); the shipped
`SanitizerHook` registry (`response_sanitization/detectors.rs:78-236`) has no name, address, date of
birth, medical record number, ICD-10 or phone detector; the secret guard handles only file writes and
patches (`secret_leak.rs:336-339`); the Azure guard calls `text:analyze` (harm categories), not prompt
shields (`azure_content_safety.rs:130-136`); external guards send full arguments to the provider
(`chio-external-guards/src/lib.rs:58-64`; Safe Browsing sends only `url`). A tool returning "ignore
previous instructions" or a medical record number reaches the agent unchanged.
Fix: a post-invocation injection hook; PHI patterns in the shipped sanitizer registry. Test: through
a real MCP tool, both outputs are blocked or redacted.
Owner: none for injection; `spec/security/chio-threat-model.v1.json` row `pii_phi_exposure` for PHI.

**KG12, Medium. Two kernel paths install no guards and no output sanitizer**: the `mcp wrap`
strict-nonce kernel (`wrap.rs:378-396`) and the API-protect mediation kernel (`proxy/mediated.rs:124`).
Tool outputs on those paths are neither sanitized nor scanned. Owner: `launch-execution-plan.md` M4. Related: AP9.

**KG13, Medium. The PII and PHI threat row is covered by a test of an unwired guard.**
`crates/tooling/chio-conformance/tests/threats/pii_phi_exposure.rs:18-50` tests
`ResponseSanitizationGuard`, which no binary runs; `spec/security/chio-threat-model.v1.json:292`,
`README.md:678,684` and `threat-coverage.md:119-124` claim the row covered.
Fix: drive the test through `build_kernel` and the post-invocation pipeline so it fails first on a
seven-digit medical record number. Owner: `threat-coverage.md`.

**KG14, Low. Remote signing reaches only the finding-market hosted profile.**
`chio-signing-remote` is used only by `trust_control/finding_hosted_profile.rs:26,540-565`;
`KernelConfig.keypair` is a concrete Ed25519 keypair (`kernel_struct.rs:248`) and the keyring
authority is built from a seed file (`keyring_runtime.rs:371`). No KMS or HSM option exists for the
main keys. Fix: a `SigningBackend` for the kernel signer with CLI flags; route artifact signatures
through `KeyringSigningRouter`. Owner: as KG2.

**KG15, Low. The `aws-lc-rs` fork changes no compiled code but is the only cause of the red cargo-vet.**
`third_party/aws-lc-rs-chio/CHIO-PATCH.patch` changes only `#[cfg(feature = "legacy-des")]` code and
documentation, and no crate enables `legacy-des`; `cargo vet --locked --frozen` fails only on
`aws-lc-rs:1.18.1 missing ["safe-to-deploy"]`. Fix: drop the patch and audit the registry 1.18.1,
or upstream it. Owner: `launch-status.md` M10; `process-security-qualification.md:631`.

**KG16, Low. The external-guards policy example uses `external_guards:`**
(`docs/guards/14-EXTERNAL-GUARDS.md:172`), which the strict loader rejects.

**KG17, Low. The threat model has no prompt-injection row** (`threat-coverage.md:3`).

**KG18, Low. Manifest residuals.** `mcp wrap --strict-execution-nonce` builds its server from the
child's own `tools/list` and stamps the ephemeral kernel key as the manifest key (`wrap.rs:417-431`),
ignoring the verified registry it already loaded (`:168-180`); flow-required signed manifests cannot
be served by any shipped command although `chio mcp provision` still signs them.

**KG19, Note.** TR2 and the Vertex repair are latent for shipped binaries (KG10).

## Release, supply chain, CI and public claims (RL)

**RL1, High. The documented signer identity is an unclaimed GitHub name.**
`docs/install/VERIFY.md:50,59,122,183` (a hard-coded identity regex) and
`docs/install/PUBLISHING.md:114,136,594` pin cosign verification to `backbay-industries`, which
returns 404 as both a GitHub organization and a user. Anyone can register it, sign an artifact
keylessly from a workflow in it, and pass the documented verification. Elsewhere the same docs use
`backbay-labs/chio` (`PUBLISHING.md:284,304`), while every release run so far was in `bb-connor/arc`,
which the `<owner>/chio/` regexes never match (`VERIFY.md:39,81,111,140`).
Fix: register the name defensively today; one canonical signing identity everywhere with exact
`--certificate-identity` pins; a CI check that executes the documented cosign commands against a
signed fixture and refuses unknown owners.
Owner: `docs/superpowers/plans/2026-09-25-security-assurance-closeout.md` Packet 6;
`launch-execution-plan.md` M10 step 6.

**RL2, Medium. Nothing has ever been released through the signed pipeline.**
v0.1.0 in `bb-connor/arc` (2026-04-22) and in `backbay-labs/chio` (2026-09-09, no workflow run, marked
Latest) have byte-identical `SHA256SUMS` and only archives plus `.sha256` files: no signatures, SBOM
or provenance, and the attestations API returns 404 in both. The seven `@chio-protocol/*` npm
packages and ten PyPI packages at 0.1.0 were published by hand without provenance;
`release-npm.yml` and `release-pypi.yml` have never run. 128 `chio-*` crates at 0.1.2 and `chio`
0.1.0 are on crates.io without trusted publishing, with no v0.1.2 tag, while every member is
`publish = false` and `docs/security/rust-preview-packages.md:12-13` says publication is disabled. The
branch's `release-binaries.yml` (`837dc6d367`, `3d2396bc64`, `6bc4d65324`) builds auditable binaries,
attaches SBOMs, signs with cosign, holds the release as a draft until provenance verifies, and has
never run.
Fix: release only through `release-binaries.yml`; take v0.1.0 off Latest and deprecate or yank the
hand-published 0.1.x versions, or record their source; configure trusted publishing on all three
registries. Test: on a tagged release candidate, `cosign verify-blob` with the pinned identity and
`scripts/verify-release-provenance.py verify` pass on downloaded assets; npm `dist.attestations` is
non-null; the PyPI integrity endpoint returns 200.
Owner: `launch-execution-plan.md:561` (M10 step 5); closeout Packets 5 and 6; `launch-status.md:1193`.

**RL3, Medium. The published v0.1.0 binary carries 27 known advisories.**
`cargo audit bin` on the v0.1.0 x86_64 Linux binary reports that it was not built with cargo-auditable
(144 dependencies recovered heuristically) and lists 27 vulnerabilities: wasmtime 29.0.1 (19,
including sandbox escapes RUSTSEC-2026-0095, 0096 and 0269), rustls-webpki 0.103.9 (4), rustls
0.23.37, h2 0.4.13, crossbeam-epoch 0.9.18 and rsa 0.9.10. The wasmtime paths are probably
unreachable because no shipped binary loads WASM guards (KG10); the TLS and HTTP/2 ones are on network
paths.
Fix: replace the release (RL2) and run `cargo audit bin` on every published binary after
publication. Owner: as RL2.

**RL4, Medium. The live installer serves that binary with a same-origin checksum only.**
`https://chio.computer/install.sh` resolves `latest/version` to 0.1.0, downloads the
`backbay-labs/chio` v0.1.0 assets and checks only a `.sha256` fetched from the same base URL
(`install.sh:82-89`). `docs/install/README.md:22-27` still describes the earlier "no releases"
behavior.
Fix: point latest only at provenance-verified releases; verify signatures or pinned per-version
digests in the installer. Owner: `launch-execution-plan.md` M10 step 6.

**RL5, Medium. RUSTSEC-2026-0316 is unrecorded and keeps the required lanes red.**
wasmtime 46.0.3 is affected (fixed in 36.0.16+ and 48.0.3+); the advisory is dated 2026-09-24. It
fails `cargo deny check advisories` in the required job and the release-gating cve-monitor on both
`main` and this branch, and no plan or review records it.
Fix: upgrade wasmtime, or feature-gate it out of shipped binaries (KG10). Owner: closeout Packet 5.
Related: GT1, CA1.

**RL6, Medium. Four scheduled security lanes have been silently broken for weeks.**
- `nightly.yml` failed all 31 scheduled runs in `bb-connor/arc` from 2026-09-01 to 2026-10-01 and all
  22 in `backbay-labs/chio`. Fuzz corpus smoke fails because `fuzz/Cargo.lock` cannot update under
  `--locked` (`cargo metadata --locked --manifest-path fuzz/Cargo.toml` exits 101 at this tip);
  formal qualification fails on the missing `target/formal/trace-validation.json`; coverage dies with a
  linker bus error. All three print `verdict=advisory`.
- `fuzz.yml` last succeeded on schedule on 2026-04-29; since 2026-09-25 every run is cancelled at
  `timeout-minutes: 45` (`fuzz.yml:113`) because 1,800 s of fuzzing plus an ASan build does not fit,
  and the branch adds four targets on the same budget.
- `cve-monitor.yml` last succeeded on 2026-09-08; issue #933 has been open since 2026-06-13; replaying
  its command at this tip reports RUSTSEC-2026-0316.
- `tuf-rebake.yml` failed both runs on "root metadata is expired": the embedded
  `crates/trust/chio-attest-verify/sigstore-root/root.json` (version 14) expired 2026-06-22, so the
  quarterly re-bake claimed at `VERIFY.md:198` has never happened. Half of the recent ClusterFuzzLite
  batch runs in `bb-connor/arc` were cancelled at 60 minutes.
Fix: regenerate `fuzz/Cargo.lock` and add `cargo metadata --locked` for fuzz to the required job;
size fuzz timeouts to build plus fuzz time; fix proof-report artifact production; upgrade wasmtime;
make tuf-rebake update from an expired trusted root, tested on an expired-root fixture; alert on
scheduled-lane failure. Owner: closeout Packet 6; hardening-toolchain spec. Related: GT1, GT3, GT9.

**RL7, Medium. CODEOWNERS requests no reviews, and no rule requires one.**
All 117 `.github/CODEOWNERS` entries name `@backbay-labs/chio-maintainers`; the codeowners errors API
returns 117 errors in both repositories because the team does not exist (and could never apply to the
user-owned `bb-connor/arc`). The `bb-connor/arc` ruleset covers deletion, force-push and four
required checks, with no review rule and no tag rule; `backbay-labs/chio` has no rules at all.
Controls that cite CODEOWNERS gating are unenforced (`releases.toml:100,127,134,137`,
`mutants.yml:35`, `release-binaries.yml:1308`, `fuzz_corpus_sync.yml:8`, `PUBLISHING.md:514`,
`scripts/mutants-gate.sh:42,254`, `scripts/lane-gate.sh:4`), and `scripts/tests/lane-gate.test.sh:1618-1665`
checks only the file text.
Fix: create the team or use user owners; rulesets requiring a pull request, approval and code-owner
review on both repositories, plus tag rules for `v*`, `py/*`, `ts/*` and `cpp/*`; a CI check that the
codeowners errors API returns none. Owner: closeout Packet 6; M10 step 1. Related: CA2, GT10.

**RL8, Medium. Advisory acceptance is unreasoned and self-approved.**
`cve-monitor.yml` ignores 19 advisories (`:99-117`); 8 have a rationale in the workflow and 6 in
`deny.toml:19-43`. RUSTSEC-2025-0141, 2025-0134, 2025-0068, 2026-0097 and 2026-0190 have none; at this
tip four of them are dead ignores, and rand 0.9.2 is still affected by RUSTSEC-2026-0097, a live
ignore without a reason. RUSTSEC-2026-0222, 0247, 0250, 0251, 0194, 0195 and 0204 are dead too. cargo-vet
has 741 exemptions against 277 audits, fails at this tip on `aws-lc-rs` 1.18.1 (KG15), and its
exemption-growth gate accepts a justification comment from the owner
(`.github/workflows/cargo-vet.yml:55-120`).
Fix: one ignore list with reasons in `deny.toml`, read by cve-monitor, with unused ignores an error;
fix or justify rand; finish the `aws-lc-rs` audit; an exemption burn-down ratchet.
Owner: closeout Packet 5; M10 step 2.

**RL9, Medium. The other verification instructions do not work.**
`supply-chain/checksums/README.md:45-48` gives a cosign command with no identity or issuer flags,
which cosign 2.x refuses; `.github/renovate.json` is referenced (`release-npm.yml:723`,
`release-pypi.yml:389`) but missing, and there is no Dependabot configuration; `VERIFY.md:216-219`
and `docs/install/README.md:22-27` are stale. Owner: as RL1.

**RL10, Medium. Public claims that do not hold.**
`integrations/mcp-adapter/registry/server.json:25-29` records `pass_count: 31` from a test that only
asserts a 31-name array has length 31 (`integrations/mcp-adapter/tests/conformance_suite.rs:89-92`); it
declares resources and prompts unsupported (`:15-20`) although the scenarios include them; the registry
returns 404 for `dev.chio/chio-governed-tools`, `mcp.chio.world` has no DNS record, and
`namespace_proof.md:3-7` ties `dev.chio` to `chio.world`, which a reverse-DNS name does not match.
`integrations/aws-bedrock/SUPPORT.md:3-12` promises an SLA with `@chio.world` contacts, and
`chio.world` has no MX record. `deploy/healthcare-design-partner/chio-siem-overrides.yaml` is read by
no code (wiring it as written would page PHI, EV1), and the healthcare heartbeat workflow failed all 22
runs because its secret is empty. The APN blog draft's pilot outcome paragraph
(`docs/distribution/apn-blog/aws-bedrock-mcp-listing.md:69-79`) reports results that were never measured.
Fix: correct the registry record and test name; remove the SLA, contact and pilot claims; delete or
properly wire the overrides and heartbeat. Owner: the `docs/compliance-guidance` branch already
removes the pilot paragraph (RL11); the rest is unowned.

**RL11, Medium. The superseded compliance material and its release guard are still on this branch.**
Compared with `main`, nothing changed under `compliance/`, `docs/external-attestation/`, the six
`docs/compliance/*.md` mappings, `docs/protocols/COMPLIANCE-ROADMAP.md`, the `releases.toml`
`[release_audit]` m08 and m09 entries (`:353-382`), the HITRUST pinning in
`scripts/check-release-inputs.sh:21-71` (run by the required job) or the APN paragraph. These mappings
cite wrong clauses and make claims the code contradicts (EV1, EV5, KG9), and public history contains
fabricated assessment artifacts (a HITRUST certificate and a crypto-review report naming third-party
firms) that the replacement guidance discloses in a dated correction. The replacement lives on
`docs/compliance-guidance` (based on `f5566d9a76`, uncommitted at the time of this review): a
machine-checked control catalog, 24 framework mappings, practitioner guides and a CI gate. Twelve
files change on both sides; `ci.yml` and `crypto.rs` need a hand merge, and
`check-release-inputs.sh`, `releases.toml` and the HITRUST files must change together or the
required job fails. After both land, `cargo xtask compliance check` re-verifies every catalog citation
against the merged tree.
Owner: this review; merge after the branch is split into stacked pull requests (CA9).

**RL12, Low. Provenance cannot be checked with stock tools.** `slsa.yml` now runs inside the tag run
and refuses non-tag refs (`6bc4d65324`), but pins the generator by commit SHA with
`compile-generator: true` (`slsa.yml:77-84`); verification uses `scripts/verify-release-provenance.py`,
which pins the builder by SHA and requires exactly cosign v2.4.1 (`:14-17,170-171`), and stock
slsa-verifier rejects it (`PUBLISHING.md:694-700`). No provenance exists yet (all three runs skipped).
Fix: reference the generator by tag and verify with stock slsa-verifier, or release the policy
verifier as a tool. Owner: closeout Packet 5.

**RL13, Low. Scheduled SBOM generation picks a stray tag.** `sbom.yml` selects the highest `v*.*.*`
tag (`:64-65`), the stray `v3.20.0-trj4`, and has failed all 26 scheduled runs since 2026-05-04. Stray
public tags `v3.20.0-trj4`, `v3.18.1-trj3.1` and `v0.0.0-m03-probe` also triggered release and
reproducible-build runs, and no tag rule prevents more. Fix: select the latest published release;
delete the stray tags (a maintainer decision); tag rules (RL7). Owner: closeout Packet 6.

**RL14, Low. The reproducible build does not reproduce the release.** `reproducible-build.yml`
builds with different flags (`:22,74,77-80`) from the release's `cargo auditable build`
(`release-binaries.yml:188`) and compares two of its own builds (`:189-205`), never the published
binary, yet `release-binaries.yml:1007` and `supply-chain/checksums/README.md:18` state a reproducible
scope. Fix: the identical recipe and a comparison with the published archive, or drop the claim.

**RL15, Low. Every release gate is advisory.** All 15 `[gates.*]` in `releases.toml` and `[mutants]`
(`:316`, zero observed nightly successes) are advisory, and `initial_merge_tag` names a tag that
exists in neither repository (`:320`). With RL6, nothing blocks. Owner: hardening-toolchain spec H6. Related: GT10.

**RL16, Low. The adversarial suite overstates its reach.** The corpus has 70 cases in 37 classes
(`crates/core/chio-adversarial-suite/src/bundled.rs`) while the README and ARCHITECTURE say 40 in 8;
the kernel-core and attest-verify tests still check only the answer key
(`crates/kernel/chio-kernel-core/tests/adversarial_suite.rs:16-65`,
`crates/trust/chio-attest-verify/tests/adversarial_suite.rs:11-66`). Fix: real signed artifacts from
fixed seeds, driven through the real verifiers. Owner: `launch-status.md` M10.

**RL17, Low. Documentation invokes CLI flags that do not exist.** Eighteen invocations in seven files,
including `chio receipt chain` (`docs/protocols/EVENT-STREAMING-INTEGRATION.md:609`),
`receipt list --decision` and `--meta` (`HUMAN-IN-THE-LOOP-PROTOCOL.md:846-855`) and the `cert` flags in
the normative `spec/COMPLIANCE-CERTIFICATE.md:229,239,257`; `docs/guards/10-DATA-LAYER-GUARDS.md` and
`SAAS-COMMUNICATION-INTEGRATION.md` describe a post-invocation `ResponseSanitizationGuard`. Fix: a
documentation test that parses documented commands through clap.

**RL18, Low. The `pypi` and `npm` deployment environments do not exist** although the release
workflows reference them (`release-pypi.yml:456-457`, `release-npm.yml:787-788`); GitHub would create
them unprotected on first use, contrary to pass 8 U9's "Closed". Fix: create them with required
reviewers and a tag-only policy and bind the registry trusted publishers to them.

**RL19, Low. Package metadata points elsewhere.** crates.io `chio` 0.1.0 and PyPI `chio-sdk` 0.1.0
list `github.com/backbay/chio` (404; `backbay` is an unrelated GitHub user), and the PyPI name `chio`
belongs to an unrelated project, so `pip install chio` installs someone else's code. Fix: correct the
metadata in a new version and claim the names.

**RL20, Low. `releases.toml:385-386` says 0.1.0 is unreleased**, while it is published in both repositories.

## Before the next batch

These slot into the working queue after the pass 9 list, which still comes first (green required
job, the High regressions). In order:

1. Close the three High findings: AP1 (caller-supplied subject keys), KG1 (signed authority
   replication, no plaintext peer links), RL1 (claim the signer name, one pinned identity,
   executable verification docs).
2. Clear RL5 by upgrading or gating out wasmtime, so the required `cargo deny` step and the
   release-gating cve-monitor can pass; then repair the dead scheduled lanes (RL6) and make review
   rules real (RL7).
3. Evidence integrity: signed and key-pinned evidence packages with an honest anchor state (EV6,
   EV7, EV13), append-only API-protect receipts inside the evidence chain (AP9), records that cannot
   pass as decisions (AP10), strict signature verification (EV12).
4. Authority: key retirement and a separate kernel signer (KG2, KG3), constraints that are enforced
   or refused (KG4), no wildcard default and policy hashes that identify policy (KG5, KG6), verified
   attestation (KG7, KG8), bound and attributable approvals (AP2, AP3), deny-by-default API protection
   (AP4), real sender constraint (AP5, AP6), truthful revocation responses (AP8), TLS (AP7).
5. Data handling, required before any pilot that touches personal data or PHI: argument commitments
   and sanitized exports and pages (EV1), credential-free and compacted admission blobs (EV2),
   output-side injection and PHI detection (KG11, KG12), retention wired with an archive-aware read
   (EV5, with SR1 and SR6).
6. Evidence completeness: receipts for edge rejections (EV3, EV4, EV14), a working session certificate
   (EV8, EV17), SIEM export that is correctly classed and shipped (EV9, EV15, EV16), an
   operator-reachable emergency stop (EV11).
7. Truth: remove or qualify every claim of a library-only capability (KG9, KG10, KG13, EV10, RL17),
   correct the public records (RL10), and merge the compliance guidance (RL11).
8. Release: the first release through the signed pipeline replaces v0.1.0 and the hand-published
   packages (RL2, RL3, RL4), with RL8, RL9 and RL12 to RL20 alongside.

## Decisions for the maintainer

- Register the `backbay-industries` GitHub name (RL1) before anyone else does.
- Whether to take v0.1.0 off Latest, deprecate or yank the hand-published npm, PyPI and crates.io
  versions, and claim the PyPI name `chio` (RL2, RL19).
- Whether to delete the stray public tags `v3.20.0-trj4`, `v3.18.1-trj3.1` and `v0.0.0-m03-probe` (RL13).
- Whether to correct or withdraw the MCP registry submission and the Bedrock support claims (RL10).

## Verification record

| Area | Findings re-verified at `122414b48e` | Method | Result |
| --- | --- | --- | --- |
| AP | 11 from the `main` review, 3 new | Source trace through routers, kernel and SDK | 2 fixed on this branch, 1 changed shape, 8 present; AP1 raised to High after the SDK's subject contract was traced |
| EV | 9 from the `main` review, 9 new | Source trace; two sub-checkers on SIEM and edge paths, spot-checked | None fixed; the retention claim corrected (rotation archives, it does not delete) |
| KG | 8 from the `main` review, 11 new | Source trace; `cargo vet --locked --frozen`; two sub-checkers on guards, spot-checked | Signed manifests fixed for `mcp serve`/`serve-http`; witnessed keyring added; all else present; KG1 rated High |
| RL | 14 from the `main` review, 8 new | GitHub API for releases, runs, rulesets and CODEOWNERS errors; npm, PyPI and crates.io metadata; `cargo audit bin` on the published binary; `install.sh` | Pipeline built, never run; published state unchanged |

## Where this review attaches

Each document below now ends with a "Compliance and product-truth review (October 1, 2026)" section
listing the findings it owns. The working queue carries the ordered list above.

- [Working queue](2026-09-28-remaining-security-work.md)
- [Pass 9 execution review](2026-10-01-execution-review.md) (cross-reference only)
- [Launch execution plan](../security/launch-execution-plan.md): M4, M6, M7, M8, M9, M10
- [Sidecar control authority](../security/sidecar-control-authority.md): AP1, AP4, AP7, KG5
- [Kernel signing authority](../security/kernel-signing-authority.md): KG1, KG2, KG3, KG14, AP9
- [Threshold approval collection](../security/threshold-approval-collection.md): AP2, AP3, KG4
- [Tenant read contracts](../security/tenant-read-contracts.md): AP12
- [Crypto wire decoding](../security/crypto-wire-decoding.md): KG9, EV12
- [Security assurance closeout plan](../superpowers/plans/2026-09-25-security-assurance-closeout.md): RL1 to RL20
- [Protocol authority boundaries plan](../superpowers/plans/2026-09-29-protocol-authority-boundaries.md): EV3, EV4, AP5, AP6, AP8
- [CLI authority and proof readers plan](../superpowers/plans/2026-09-30-cli-authority-proof-readers.md): EV6, EV7, EV8, EV17
- [Unrepresentable-defects design](../superpowers/specs/2026-09-26-unrepresentable-defects-design.md): KG4, KG5
- [Structural security fixes](../protocols/STRUCTURAL-SECURITY-FIXES.md): EV11
- [Compliance evidence export plan](../release/COMPLIANCE_EVIDENCE_EXPORT_PLAN.md): EV6, EV7, EV13, EV18
- [Consumer support](../security/consumer-support.md): EV3, EV14, KG18
- [RFC-0007 retention design](../superpowers/specs/2026-07-07-rfc-0007-retention-design.md): EV5

`docs/security/threat-coverage.md` is generated from `spec/security/chio-threat-model.v1.json`, so
KG7, KG11, KG13 and KG17 are carried by the launch execution plan (M6, M7, M10) and belong in the
threat model when they are fixed.
