# Execution review: trust, guard, platform and economy readers, October 1, 2026

Scope: the four newest reader batches on `packet/3-retention-accounting`, reviewed
at tip `a2630c20a1` against base `07e963e8f5`. Commits: `90e8f0683b` (trust readers
and relay delivery reports), `377ee5b773` (guard inputs and bounded registry
downloads), `593b642da9` (platform original-input and authority readers) and
`a2630c20a1` (economy authority readers and witness custody, landed this morning
with follow-ups in flight). Plans: `docs/superpowers/plans/2026-09-30-trust-reader-boundaries.md`,
`2026-09-30-guard-security-readers.md`, `2026-10-01-platform-authority-readers.md`
and `2026-10-01-economy-authority-readers.md`. Execution records: the four matching
`docs/reviews/*-execution.md` files and their artifact directories (README,
`review.md`, `reviewed-readers.json`, terminal logs). Contract background:
`docs/security/signed-json-boundaries.md`. Method: each diff read with
`git show`, then the resulting code read at the tip with its callers and
consumers; claims checked against source and the committed terminal evidence.
Two quick `cargo fmt`/`cargo tree` probes were run; no tests were run, because no
High finding depends on runtime behavior (the one High is a deterministic
compile error visible in source and already captured in the committed log).

**Judgment: the reader code in this slice is mostly sound, and several changes
repair defects that were real before it: unbound relay acknowledgements could
retire an outbox batch, OCI pulls and TEE observation lines were read without a
bound, provider responses with missing verdict fields defaulted to Allow, Vertex
allowed a `finishReason: SAFETY` response, an attacker-shaped evidence graph could
exhaust the stack through a recursive walk, and Rekor receipts were not bound to
the signed entry's time. The most important thing wrong is that the committed tip
does not build: `chio-control-plane` fails two exhaustive matches on new
open-market error variants (TR1), which the economy plan records only as an
unchecked box. Second, the guard batch reversed VirusTotal's allow-on-unseen
policy by routing HTTP 404 through the provider-failure path, so ordinary unseen
URLs now feed the circuit breaker (TR2). The cause-retention work, a large share
of the diff, stops at the HTTP boundaries it touched: the hosted edge and the HTTP
authority carry native causes that no code ever logs (TR3). Worth it in part:
the named repairs above justify the batches; roughly 35 of the 121
dispositions read operator-owned data where the new contract adds little, the
helpers were copied per crate by plan decision (TR4), and the evidence
apparatus runs to about six committed lines of logs per line of code.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| Trust T1: attestation, credentials, buyer imports | Complete | Done | `chio-attest-buyer{,-core}/src/input.rs` (16 MiB native), Sigstore/TUF original validation, causes retained |
| Trust T2: custody, TEE, remote signing, federation | Complete | Done | `play_integrity_input.rs` bounds token before base64; `observation_input.rs` bounds each line before allocation; `chio-signing-remote/src/lib.rs` `read_json` uses external I-JSON |
| Trust T3: pheromone runtime/relay, delivery reports | Complete | Done, one asymmetry | `delivery_report.rs:12-42` binds batch digest, recipient, schema, full frame verdicts; HTTP pins sender, Iroh does not (TR7) |
| Trust T4: review, qualification, inventory, commit | Complete | Done, consumers incomplete | `review.md` present; 166 to 131 consistent with `inventory-summary.json`; mobile SDK consumers left on the removed FFI symbol (TR9) |
| Guard T1: provider verdicts, registry, embedding, WASM | Complete | Done, plus an unplanned policy change | Missing fields no longer Allow; VirusTotal 404 now Deny via the failure path (TR2), not in the plan |
| Guard T2: sandbox, quarantine, keyring, decoy | Complete | Done | Temporal rules bounded native; decoy paths share 4096-byte cap (`materialize.rs:224`, `:890`) |
| Guard T3: security-type deserializers | Complete | Done | `BoundedVec` visitor stops at `MAX` and probes with `IgnoredAny` (`ports/bounded.rs:179-188`) |
| Guard T4: review, qualification, inventory | Complete | Done | `review.md` two material gaps, both with controls (`download_boundaries.rs:119`, `reader_boundaries.rs:111`) |
| Platform T1: HTTP authority and transaction evidence | Complete | Done, causes have no sink | Bounds, iterative DFS, fenced clock verified; `capability_input_error` dropped by every consumer (TR3) |
| Platform T2: commerce and exported evidence | Complete | Done, labels lost | Budgets precede hashing and replay; field and path labels discarded (TR6) |
| Platform T3: hosted ingress, workers, PostgreSQL | Complete | Done, classification inconsistent | Canonical identity and native readback verified; `CorruptInput` mapped three ways (TR3) |
| Platform T4: review, inventory, publication | Complete | Done | Five review tests exist; composite qualification honestly labeled in `test-summary.json` |
| Platform constraint: "Keep helpers within the owning crate" | Followed | Followed, at a cost | Produces the duplication in TR4 |
| Economy T1: credit and fiscal | Checked | Done | `chio-credit/src/input.rs`, `chio-fiscal/src/input.rs`; canonical equality now precedes signature work |
| Economy T2: settlement and replay | Three of four checked | Three verified; consumer box honestly open | Dead-letter fallback removed safely (store already rejected legacy rows); consumers fail to compile (TR1) |
| Economy T3: markets, predicates, witnesses | Three of four checked | Three verified; consumer box honestly open | Rekor bounds and time binding verified; zero skew tolerance (TR8) |
| Economy T4: review, accounting, gates, publication | Unchecked | Partly done, review absent | Inventory (22 dispositions, 45 baseline) and clock gate done; no `review.md`; committed with a broken consumer build (repaired in `66e9ecc5bd`) |

## TR1. High: the committed tip does not compile `chio-control-plane`

`a2630c20a1` adds `PurchaseVerificationError::MemberInput`
(`crates/economy/chio-open-market/src/purchase_verification.rs:53-59`) and
`RecoveryVerificationError::MemberInput` and `CarrierInput`
(`crates/economy/chio-open-market/src/recovery.rs:36-44`). Both enums are matched
exhaustively, with no wildcard arm, in the control plane's denial classifiers:
`crates/platform/chio-control-plane/src/trust_control/finding_purchase_verifier.rs:24`
and `finding_recovery_verifier.rs:22`. Neither module is feature-gated
(`trust_control.rs:335-338`), and `chio-control-plane` depends on
`chio-open-market` unconditionally. The committed evidence shows exactly this:
`docs/reviews/artifacts/2026-10-01-economy-authority-readers/direct-consumers.log:174`
and `:195` record `error[E0004]` for both matches, with exit code 101 in
`direct-consumers.json`. Cargo stopped at the first failing crate, so
`chio-cli` and the other dependents of the control plane were never checked.

Failure scenario: anyone who builds, rebases onto, or merges this branch runs the
CLAUDE.md one-liner and `cargo build --workspace` fails in a TCB crate. The fix is
not purely mechanical: it is a security classification. A malformed purchase or
recovery member previously surfaced as `Member(_)` or `Carrier` and mapped to
`FindingDenialCode::CarrierInvalid`; the new variants need the same explicit
mapping, and the consumer check must be rerun through `chio-cli`.

Why the existing checks missed it: the batch qualified owning packages
(`owning-packages-accepted.json`, exit 0) and treated consumer compilation as a
later step. The plan is honest about the open box (economy plan lines 66 and 83),
but the execution record's "Implemented tasks" section does not say the branch is
unbuildable, and the commit was made in that state. It was not pushed: the remote
branch stayed at `593b642da9`. The earlier three batches
each passed their consumer check before committing (`direct-consumers-final.json`
and both `cli-consumers.json`, exit 0), so this is a regression in the batch
discipline, not the norm.

**Confidence:** Confirmed. The enum variants and the arm-complete matches are at
the cited lines at the tip; the compiler output is in the committed log.

**Status after the review tip:** repaired in `66e9ecc5bd` ("retain economy parser
causes through kernel denials"), committed about fifteen minutes after
`a2630c20a1`. It maps `MemberInput` and `CarrierInput` to
`FindingDenialCode::CarrierInvalid` and carries the native cause through
`FindingDenial::with_source`. `f6c8c39067` then ran the direct consumer check
through `chio-cli` with exit 0 (`direct-consumers-2.json`). Closed.

## TR2. Medium: VirusTotal "not found" now denies through the provider-failure path, so unseen URLs trip the circuit breaker

Before `377ee5b773`, a VirusTotal 404 ("never seen") returned `Ok(Verdict::Allow)`
with a code comment explaining the choice. The batch replaced the per-provider
status handling with `http_egress::response_json`
(`crates/guards/chio-external-guards/src/external/threat_intel/virustotal.rs:260`),
which turns every non-2xx status into an error
(`external/http_egress.rs:82-87`); `classify_status_error` makes a 404
`ExternalGuardError::Permanent` (`external/bedrock.rs:353-361`). In the adapter,
any error calls `self.circuit.record_failure()` and returns `Verdict::Deny`
(`crates/guards/chio-guards/src/external/mod.rs:399-408`), and errors are not
cached. The default breaker opens after five failures in sixty seconds and stays
open for thirty (`external/circuit_breaker.rs:56-63`).

Failure scenario: an agent checks five never-indexed URLs or file hashes in a
minute, or retries one unseen hash five times (no cache entry is written on
error). The breaker opens. With the default `CircuitOpenVerdict::Deny`, every
VirusTotal-guarded call, including known-clean ones, is denied for thirty seconds,
and normal browsing keeps re-tripping it. With `CircuitOpenVerdict::Allow`
(`external/mod.rs:148-151`, offered for advisory deployments), the same unseen
inputs open a window in which known-malicious hashes are allowed without a
lookup. Before the change, a 404 recorded a success and could not open the
breaker.

Why the existing checks missed it: the old test `virustotal_allows_on_404` failed
during qualification (`artifacts/2026-09-30-guard-security-readers/qualification-3.log:462`)
and was renamed and inverted to `virustotal_denies_unknown_404_result`
(`tests/threat_intel.rs:155`) instead of being treated as a behavior question.
The guard plan asked that missing verdict fields not become Allow; a 404 is a
definitive "unknown" answer, not a missing field. `ARCHITECTURE.md:80` and
`review.md:32` record the reversal as intended, but no plan item authorized a
product policy change, and nobody examined the breaker interaction.

Fix: treat 404 as a verdict, not a failure. Map it through an explicit
configuration (`unknown_verdict: Allow | Deny`, defaulting to the previous
behavior or to Deny by decision), record a breaker success, and cache it. More
generally, client-side and definitive provider answers (4xx other than 429,
invalid arguments) should not count as breaker failures.

**Confidence:** Confirmed by source trace from the 404 response to the breaker
state change; the breaker thresholds are the shipped defaults.

**Independent verification:** Confirmed, Medium (High for a deployment that opts into
`CircuitOpenVerdict::Allow`). Failures are not cached, only successes, so one unseen URL
repeated five times trips the breaker, and a half-open probe on another unseen URL reopens it.
The breaker check (`external/mod.rs:351`) runs before the cache, so in Allow mode every request
passes, including hashes already cached as Deny. No in-tree configuration selects Allow, but
`.circuit_open_verdict()` is a public builder option. The guard plan
(`2026-09-30-guard-security-readers.md`) never mentions VirusTotal or 404; the test rename
from `virustotal_allows_on_404` to `virustotal_denies_unknown_404_result` is the only record of
the policy change.

## TR3. Medium: retained native causes reach no sink at the HTTP boundaries, and the hosted edge classifies the same durable corruption three ways

The platform record says "Native causes remain local behind fixed HTTP bodies or
safe signed denial text" (platform execution record line 15). Locally true; the
causes are then dropped without being observed.

Hosted edge. Every handler ends in `error_response`
(`crates/platform/chio-finding-hosted-edge/src/server.rs:1151-1155`), which reads
the status and fixed body from the `HostedEdgeError` and drops it. The crate has
no `tracing` or `log` dependency and no code calls `source()`. The new
`InvalidInput`, `InvalidCredential`, `CorruptInput` and `Clock` variants carry
`SharedUntrustedJsonError`/`ClockError` sources that exist only until that
function returns. An operator who sees a 503 `integrity_failure` from durable
corruption has nothing to read.

The same port error is also classified inconsistently inside one crate:
`HostedMarketPortError::CorruptInput` becomes `InvalidCredential` (401,
non-retryable, Display "hosted credential JSON is invalid") in `auth.rs:627-628`,
`InvalidInput` (400, "hosted request JSON is invalid") in `lifecycle.rs:392-393`,
and `CorruptInput` (503 `integrity_failure`) in `server.rs:1141`. A corrupt
principal row read back during authentication tells the client its credential is
bad and tells the operator nothing; the same corruption on a projection read is a
503. The wire behavior for the auth and lifecycle paths matches the previous
catch-all arms, so this is not a regression, but the batch wrote the mappings
explicitly and gave them misleading local labels.

HTTP authority. `PreparedHttpEvaluation` and `HttpAuthorityEvaluation` gained a
public `capability_input_error` field (`crates/platform/chio-http-core/src/authority.rs:133`,
`:151`). The only production consumer, `chio-api-protect`, converts the evaluation
with `From<HttpAuthorityEvaluation> for EvaluationResult`
(`crates/products/chio-api-protect/src/evaluator.rs:497-505`) and drops the field;
`chio-tower` never reads it. Only `tests/authority_input.rs:123` does.

This is standard section 3.2 ("so the chain survives to the boundary that formats
it") satisfied in letter and not in purpose, and section 3.1 for the hosted
classification. Fix: log the error chain once at `error_response` (code, variant,
and `source()` chain, which is already redacted), map `CorruptInput` to
`IntegrityFailure` everywhere, and either consume `capability_input_error` in the
adapters' denial logging or remove it.

**Confidence:** Confirmed. The drop points and the three mappings are at the cited
lines; the absence of a logging dependency is in the crate manifest.

## TR4. Medium: input owners and limits were copied per crate, contrary to standard section 1.5

The platform plan's constraint "Keep helpers within the owning crate" (plan line
12) and the economy plan's "Each crate keeps its own input/error owner" turned
one boundary into many copies:

- The 40-line bounded no-follow `read_file` is byte-identical in
  `chio-guard-registry/src/input.rs:8-40`, `chio-guards/src/input.rs:8-40` and
  `chio-wasm-guards/src/input.rs:8-40`, although `chio-wasm-guards` already depends
  on `chio-guards`. `chio-settle/src/config.rs:417-432` and
  `chio-finding-worker/src/executor.rs:1625` (`read_cgroup_text`) add two more
  hand-rolled bounded reads in the same commits.
- "Strict canonical I-JSON bytes, then decode" is implemented six times:
  `chio-settle/src/input.rs:14-23`, `chio-finding-hosted-edge/src/input.rs:6-22`,
  `chio-finding-market-store-postgres/src/validation.rs:36-42`,
  `chio-finding-worker/src/protocol.rs:36` (`decode_original`),
  `chio-listing/src/outcome/mod.rs:134-151` and
  `chio-open-market/src/recovery.rs:172-190`. It is a missing method on
  `UntrustedJsonText`, not six owner contracts.
- `chio-pheromone-relay/src/input.rs` and `chio-pheromone-runtime/src/input.rs`
  repeat `decode`, `row_decode` and `encode` verbatim, and the relay depends on
  the runtime. `chio-credit`, `chio-fiscal` and `chio-settle` repeat the same
  `canonical` wrapper.
- `chio-commerce-order/src/input.rs:8-62` re-declares the transaction-passport
  budget algorithm and its three constants (16 MiB, 64 MiB, 4096).
  `chio-external-guards` declares the same 1 MiB twice
  (`external/http_egress.rs:14`, `external/input.rs:6`).

The cost is not only line count. The limits already disagree: the CLI loads a
commerce bundle under a 128 MiB budget
(`crates/products/chio-cli/src/cli/input/collection.rs:7`) while the library
rejects anything over 64 MiB (`chio-commerce-order/src/input.rs:9`), so a 64 to
128 MiB bundle is fully read and then refused. A future change to the file-custody
rule (for example ancestor-directory custody, which the guard record defers) must
be made in at least three places. Fix: one bounded regular-file reader in a
shared std crate, one `UntrustedJsonText` method for strict canonical external
bytes, one evidence-budget owner that commerce calls, and per-artifact limits
declared once.

**Confidence:** Confirmed by `diff` of the cited files and the dependency
manifests.

## TR5. Low: the "already validated" contract of `project` is a comment, not a type

`chio-commerce-order/src/input.rs:18-24` and
`chio-transaction-passport/src/input.rs:42-50` take any `serde_json::Value` and
deserialize it; the commerce copy's only protection is the comment "Only for
projections of an already validated original document", and the passport copy
has none. Any crate-internal caller can pass a `Value` from `serde_json::from_slice`.
Today none does: all six call sites (`commerce lib.rs:355`, `replay.rs:302`,
`settlement.rs:234`, `minimal.rs:1063`, `minimal.rs:1144`,
`runtime_security/evidence.rs:291`) receive a `Value` from `decode_signed` or
`decode_external`. Two sibling crates bypass the helper and inline their own copy
(`chio-agent-web-interop/src/evidence.rs:245`,
`chio-enterprise-export/src/evidence.rs:160-169`).

The re-projection is lossless for this workspace. `serde_json` is built with
`float_roundtrip` and without `arbitrary_precision` (checked with
`cargo tree -e features`); `validate_number_tokens`
(`chio-core-types/src/canonical/signed_json.rs:110-153`) rejects any token that
does not round-trip, so integers beyond the 64-bit range fail closed rather than
narrowing, and floats are exact. The defect is representational: mechanism A of
the unrepresentable-defects design exists to make "validated" a type. Fix: have
`decode` return a sealed `ValidatedJson` whose only exit is `project(self)`, or
decode a schema probe and the target type separately from the same
`UntrustedJsonText`.

**Confidence:** Confirmed for the unenforced contract and each call site's
provenance.

## TR6. Low: diagnostic context was discarded and two negative tests no longer prove which rule fired

Six helpers keep a now-unused label parameter: `_field` in
`chio-commerce-order/src/lib.rs:470` and
`chio-finding-market-store-postgres/src/validation.rs:46`, `_label` in
`chio-transaction-passport/src/evidence_graph.rs:923` and
`chio-finding-market-store-postgres/src/domain.rs:965`, `_artifact` in
`chio-credit/src/factor/mod.rs:100`, and `_node` in
`chio-enterprise-export/src/evidence.rs:161`. Each used to name the failing
artifact; the replacement `Input(_)` carries only a URN. Agent-web and enterprise
errors lost the artifact path; Chainlink errors lost the pair and feed address
(`chio-link/src/chainlink.rs:253-263`). None of these labels is attacker data, so
redaction did not require dropping them. Standard section 3.3 asks for exactly
this context.

Two commerce regressions were weakened in the same move:
`commerce_order_replay_rejects_event_without_actor` and
`..._without_digest` (`tests/commerce_order.rs:778`, `:805`) used to assert the
message named `actor` and `event_sha256`; they now assert only
`CommerceOrderError::Input(_)` and that a source exists, so either passes for any
decode failure of the fixture (standard section 3.1). Fix: an `Input { artifact:
&'static str, source }` shape, and assertions on the source's message in tests,
which are a trusted diagnostic consumer.

**Confidence:** Confirmed at the cited lines.

## TR7. Low: the Iroh delivery path does not pin the sender that the HTTP path pins

`decode_delivery_report` (`chio-pheromone-relay/src/delivery_report.rs:12-42`)
binds the canonical batch digest, `recipient_kernel_id`, schema, outcome
consistency and per-frame acceptance, and pins `authenticated_sender_kernel_id`
when given one. HTTP passes the local sender (`client.rs:91`). Iroh passes `None`
(`chio-federation-transport-iroh/src/lanes/pheromone.rs:943`) although
`drain_outbox_over_iroh` holds `sender_kernel_id` and already filters rows by it
(`pheromone.rs:1007`, `:1018`). If a recipient attributes the batch to another
kernel (for example a stale node-to-kernel mapping), HTTP refuses the
acknowledgement and Iroh retires the batch.

On the brief's binding question: the batch digest covers recipient, treaty,
frames and flush time, so a report cannot be replayed across recipients or
batches; it does not bind the HTTP nonce, the relay endpoint or the transport,
and replaying an acknowledgement for the identical batch is harmless. The report
is unsigned, so it proves only what the authenticated transport proves: TLS to
the directory-signed endpoint (production profile requires `https`) or the Iroh
endpoint key. Any TLS-terminating intermediary in front of a relay can mint a
correctly bound acceptance. The doc comment says so; it is a design boundary
worth recording, not a defect of this batch, which fixed the earlier state where
any well-formed report retired the batch.

**Confidence:** Confirmed for the asymmetry; the misattribution outcome is
Plausible because the receiver's frame-origin checks were not traced.

## TR8. Low: Rekor publication has no clock-skew allowance after the log has committed the entry

`RekorClient::validate_time` (`chio-anchor/src/witness/rekor.rs:137-153`) rejects
`integrated_time > now` with `NotYetValid`, and `publish` calls it after the POST
succeeded and the SET verified (`rekor.rs:718`). `integratedTime` is set by
Rekor's clock in whole seconds; `now` is the local fenced clock truncated to
seconds. When the local clock trails Rekor's by more than the response latency,
an integration close to a second boundary yields `published_at = now + 1` and
`publish` fails although the entry is in the log. Before this commit `publish`
had no time check and verification computed a saturating age. A retry posts the
identical entry; Rekor answers duplicate entries with 409 Conflict and the client
has no 409 handling, so the batch may never obtain a receipt (Plausible: Rekor's
behavior is external and the retry policy was not traced). The only future-time
test uses `i64::MAX` (`rekor/ingress_tests.rs:55`). No production code constructs
`RekorClient` today, so this is latent. Fix: a small configured skew allowance on
the future bound, and treat 409 by fetching the existing entry.

**Confidence:** Confirmed for the missing allowance; Plausible for the permanent
failure chain.

## TR9. Low: the mobile FFI rename left first-party consumers on the removed symbol

`90e8f0683b` renamed `verify_mobile_receipt` to `inspect_mobile_receipt_envelopes`
in Rust and UDL without an alias, which is the right call for a misleading name.
The record mentions only the XCFramework rebuild. Still calling the old symbol at
the tip: `sdks/swift/Sources/Chio/Chio.swift:101-106`,
`sdks/jvm/chio-kernel-mobile/src/main/kotlin/dev/chio/kernel/Chio.kt:22-23`,
`sdks/typescript/packages/mobile/src/index.ts:69-73` with its iOS and Android
stubs, `crates/kernel/chio-kernel-mobile/bindings/kotlin/ChioKernel.md:217-221`,
and `bindings/README.md:147` and `:189` (line 102 of the same README was updated).
Each breaks at the next binding regeneration; the Swift CI only runs on
`sdks/swift/**` changes against the committed framework, so nothing fails now.

**Confidence:** Confirmed by grep at the tip.

## TR10. Low: the normative boundary document still describes three decode modes

`signed-json-boundaries.md:53-56` lists `canonicalize`, `decode_signed` and
`decode_canonical`. These commits added `decode_external`
(`untrusted.rs:50-53`, `90e8f0683b`) and `decode_document` (`untrusted.rs:60-64`,
`377ee5b773`), the latter with a weaker numeric contract whose restriction to
unsigned documents is enforced only by its doc comment. It has three callers
(`chio-guards/src/embedding_anomaly.rs`, `chio-http-core/src/plan.rs`,
`chio-link/src/chainlink.rs`), each appropriate. The document wired into the
review lineage should say which owners may use the lax mode.

**Confidence:** Confirmed.

## TR11. Low: new code in an `include!` crate is invisible to the format gate

`chio-agent-web-interop/src/lib.rs` is `include!("interop.rs")`, so `cargo fmt`
never sees the crate. The new budget call (`interop.rs:713-717`) and the inline
projection (`evidence.rs:245`, one 152-character line) are not rustfmt-formatted
while `cargo fmt -p chio-agent-web-interop -- --check` passes. This is the
standard section 1.2 hazard in practice; the batch edited the crate without
converting it.

**Confidence:** Confirmed: direct `rustfmt --check` on the files reports diffs;
the package check reports none.

## TR12. Low: `parse`'s documentation now documents a constant

In `chio-tee-frame/src/frame.rs:236-241` the three-line doc comment for `parse`
("Parse canonical-JSON bytes back into a Frame...") sits above the inserted
`pub const MAX_FRAME_BYTES`, so rustdoc attaches it to the constant and `parse`
is undocumented.

**Confidence:** Confirmed.

## TR13. Note: roughly 35 of 121 dispositions read the operator's own data

By my classification of the 121 reviewed paths (`reviewed-readers.json` in each
artifact directory), readers facing an untrusted or external producer include
relay HTTP ingress and peer reports, Play Integrity tokens and JWKS, remote signer
replies, treaty and FROST imports, six provider responses, OCI manifests and
blobs, guest worker results and deny reasons, HTTP plan/compliance/emergency
bodies and presented capabilities, hosted ingress and credentials, third-party
evidence bundles, Rekor and remote publisher responses, and buyer carriers.
Roughly 35 paths read data this process or its operator wrote: pheromone SQLite
rows and supervisor profiles, the replay-corpus fixture writer, quarantine rules,
decoy and keyring state, guard caches, canaries and blocklists, the devnet
deployment file, settlement dead letters, PostgreSQL readback and the CCIP
fixture. For those, duplicate-key and numeric-lexeme rejection guards against a
writer that has more direct ways to corrupt the record; the byte bounds and the
retained causes are the useful part. Similarly, the commerce and passport bundle
budgets (`chio-commerce-order/src/input.rs:26-62`,
`chio-transaction-passport/src/input.rs:27-40`) run on bytes already in memory:
they bound hashing and parse work and, through the 16 MiB per-document cap, the
derived `serde_json::Value` tree (which can be an order of magnitude larger than
its text), not the input allocation. The bundle derives `Deserialize` but no
production code deserializes it from the wire; the CLI loader is the allocation
bound (TR4 notes its larger limit).

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| Trust 28: "HTTP also binds the expected sender" | True; Iroh does not | `client.rs:91` passes `Some`; `pheromone.rs:943` passes `None` (TR7) |
| Trust 29: unrelated or incomplete acknowledgements cannot retire the batch | True | `delivery_report.rs:20-40`; the unit test mutates seven bound fields plus a duplicate key, and both transports call the gate before `mark_delivered` |
| Trust 20: "TEE NDJSON reads are bounded before allocation" | True | `observation_input.rs:11-15` takes `MAX + 1` per line; `runner.rs` test asserts an empty capture after rejection |
| Trust 36: 1,964 tests pass | Consistent, not re-run | `test-summary.json` totals match |
| Trust 45: baseline 166 to 131 | Consistent | Chain 131, 98, 67, 45 across the four `inventory-summary.json`; 45 `raw-input-baseline` entries in the inventory at the tip |
| Guard 12: missing verdict fields cannot become Allow | True, with an unplanned extension | Azure, Bedrock, Vertex, VirusTotal defaults removed; 404 reversal (TR2) |
| Guard 16: OCI bounds in transport, aggregate preflight, per-descriptor size, exact hashes | True | `download.rs:109-131`, `:181-200`; `reqwest_helper.rs:303-321` checks Content-Length then every chunk; no decompression features are enabled |
| Guard `review.md:12`: Vertex `finishReason: SAFETY` allowed, now fixed | True, a real defect | `vertex_safety.rs` finish-reason and `blocked` checks; `reader_boundaries.rs:111` |
| Guard 25: `BoundedVec` rejects overflow without constructing another element | True | `ports/bounded.rs:179-188` |
| Platform 17: graph cardinality bounds and iterative cycle traversal | True, and a real fix | The removed recursive `visit_graph_node` had no node limit, so a long chain could exhaust the stack; the new walk at `evidence_graph.rs:1304` keeps `active` equal to the ancestors of the entry being expanded, so a revisit of an active node is a true back edge; 4096-node and 16384-edge caps |
| Platform 15: "Native causes remain local behind fixed HTTP bodies" | True, but unobserved | TR3 |
| Platform 28: "result identity is checked before output delivery" | Accurate, not new | The pre-commit executor already ran `validate_for` before `receive_outputs`; the new part is canonical job bytes |
| Platform 33: five review findings each with a regression control | True | All five named tests exist at the paths in `review.md` |
| Platform `test-summary.json`: 1,070 passes | Honestly composite | Labeled as not a single green command, original exit 101 retained |
| Economy 25: legacy dead-letter fallback removed | True, and safe | `dead_letters.rs:176-190` already required typed canonical bytes and null `pipeline_error`, so no stored row becomes newly unreadable |
| Economy 33-34: Rekor bounds, single entry, hash shape, time bound to entry | True | `rekor/input.rs:31-74`, `rekor.rs:356-379`, `:785-790`; zero skew (TR8) |
| Economy 23: publisher limits cover alternate transports | True as a projection bound | `publish.rs` applies `external_canonical` to the transport's returned `Vec` |
| Economy 40-41: 22 dispositions, 45 remaining, Rekor in the clock gate | True | `reviewed-readers.json` has 22 paths; `check-security-clocks.py` adds both Rekor roots |
| Economy 41-42: review and qualification "as they finish" | No review artifact; consumer build fails | TR1 |

## Verified clean

Registry downloads. The bound is enforced while streaming, not trusted from
Content-Length: the egress contract rejects an oversized Content-Length and then
checks the running total of every chunk before extending the buffer. Each blob's
bound is its descriptor size, all descriptors are size- and digest-validated
before any download, config and layers share 64 MiB, and the manifest is
digest-pinned at 16 MiB. Neither `reqwest` decompression features nor layer
decompression exist, so there is no decompression-bomb surface. Registry Basic
credentials are not sent to a foreign token realm.

Ordering of budget and replay admission. In
`verify_agent_web_interop_with_trust_mode` the budget is the first statement
(`interop.rs:713`) and the only replay commit is at `interop.rs:920`, after all
verification. Commerce `verify_commerce_order` budgets first (`lib.rs:54`). The
agent-web test would fail without the budget check because the padded bundle
otherwise verifies and inserts replay entries.

Economy witness custody. There is no private key in the witness path: the Rekor
client holds pinned public PEMs, posts a DSSE envelope already signed upstream,
and verifies the SET. Zeroization does not apply. "Custody" in this commit means
bounded retention: the response is capped at 4 MiB by Content-Length and while
streaming (`rekor/input.rs:41-65`), nested bodies are capped before and after
base64 decoding, stored proofs are capped on serialize and deserialize, and
`reqwest::Error` causes are stored `without_url`. New error formatting does not
echo response bodies.

Hosted edge redaction. Response bodies are fixed per variant, request IDs are
validated before echo, and `strict_canonical_body`/credential decoding keep their
previous wire codes for empty and oversized input.

Decode then re-project. Lossless for full-width `u64`/`i64` and floats in this
workspace (TR5 has the feature check); values beyond 64 bits fail closed.

Plan-argument parsing (platform R1). `decode_plan` accepts unsigned float
spellings in tool arguments, rejects duplicates anywhere, and re-decodes the
borrowed capability subtree under the native signed contract before replacing
the projected token, so the capability cannot ride the lax mode.

Dead-letter, credit and fiscal readers. Removing the legacy decoder strands no
persisted row. Credit and fiscal readers already enforced canonical equality;
the change moves equality before signature work, adds the credit 4 MiB bound and
keeps sources. Settlement observation and publisher responses keep exact request
digest binding.

House rules on added code: no em dashes, no `unwrap`/`expect` outside test code,
no process vocabulary in comments, no production file over the 2,000-line cap.

## Recommendations for the remaining plan

1. Before any further batch: map the new open-market variants in the control
   plane (TR1) and rerun the consumer check through `chio-cli`; make a passing
   consumer check a precondition of commit, as the first three batches did.
2. Restore a deliberate VirusTotal unknown-result policy outside the failure path
   and stop counting definitive provider answers as breaker failures (TR2).
3. Give the hosted edge one log line per error with its redacted source chain,
   and make `CorruptInput` an integrity failure everywhere (TR3).
4. Before the next 23 readers, consolidate: one bounded file reader, one strict
   canonical external method on `UntrustedJsonText`, one evidence budget owner,
   and a `ValidatedJson` token for decode-then-project (TR4, TR5). Retire the
   per-crate policy in the plans.
5. Keep artifact labels in `Input` errors and assert on sources in tests (TR6).
6. Update `signed-json-boundaries.md` for the two new modes (TR10) and convert
   `chio-agent-web-interop` from `include!` when it is next touched (TR11).
7. Rank the remaining 45 baseline files by producer trust and do the untrusted
   ones first; the operator-owned remainder can take bounds and causes without a
   full contract migration (TR13). Trim the per-batch evidence to the commands,
   exit codes and failures that a reader would actually re-check.
