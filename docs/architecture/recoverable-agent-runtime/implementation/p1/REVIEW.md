# P1 implementation and review

Phase: **P1, exact durable recovery**, architecture revision 3. All seven tasks
in [PLAN.md](PLAN.md) are implemented, locally verified and reviewed for the
declared sequential native support-disclosure profile. There are **zero open P0
or P1 severity findings in the reviewed phase changes**. Confidence is high
within that local profile. Codex reviewed the complete authored change; this
record does not claim independent human approval or production qualification.

[Source-bound verification](verification.json) retains commands, source and log
hashes, tool provenance, measured budgets and unavailable checks. The
[43-requirement crosswalk](requirements-coverage.json) maps the historical
obligations to actual tests and review anchors. The original specification and
requirements registry retain their historical meaning. The
[operating contract](OPERATIONS.md) specifies composition, limits, upgrade and
settlement behavior.

## Accomplished tasks

| Task | Implemented result | Verified behavior |
|---|---|---|
| P1-01 | Closed action, authorization, approval, coverage, grant v2, custody and admission-intent contracts; explicit version selection; generated SDK models | Shared 102-vector corpus, signed context substitutions, all grant binding fields and byte-stable ordinary v1 grants |
| P1-02 | Sealed observations of original native operation/effect truth, current scoped settlement and authoritative admission closure | Unknown and delivered-but-denied work cannot authorize another effect; cancellation fences late uncaptured admission; positive partial evidence spends the original step |
| P1-03 | Protected workflow/command/event records under the existing serving fence, global commit chain, integrity inventory and rollback anchors | Stable command identity, atomic selection, retained exact issuance, cross-process tenant quotas, tampering refusals and populated/interrupted migrations |
| P1-04 | Complete existing process binding extraction, preapproval reservation, protected exact-envelope finalization and original nonce attachment | Eight independent legacy binding references, one logical-call charge, frozen-denial preservation, v1 journal compatibility and original nonce bytes after process death |
| P1-05 | Conjunctive operator-scoped owner/compartment coverage, grant v2 verification and recovery participation in native admission/capture | Same-action coverage, alias/endorsement refusals, fresh source generations, atomic native joins and immutable signed issuance |
| P1-06 | One complete support-ticket-to-public-issue template, authenticated Rust host driver/router, pinned HTTPS connector and thin CLI/Python/TypeScript clients | Full exact preview, current audience checks, bounded no-retry transports, stable replay after token rotation and independent settlement control |
| P1-07 | Native benign/refusal, cancellation, corruption, resource and OS-death corpus with independent effect evidence | All 27 process-death cutpoints, original operation/signature/envelope/nonce/receipt recovery, no captured resubmission and retained source restrictions |

## Security and Rust review

Reviewed every changed handwritten Rust/SQL/include module, handwritten SDK
transport, manifest/lock delta, schema, native transaction, migration, fixture
boundary and generated artifact delta. The verification inventory identifies
those files and their final hashes. P0's source inventory, measurements and
verification record remain intact; the retained phase-start archive permits
comparison with its dirty source baseline.

The changes use real Rust modules for contracts, kernel ports, process binding,
protected storage, issuance, native joins, resources, host materialization,
transport and the connector. P1 integration tests have their own native
bootstrap module instead of extending the legacy adapter include family.
Global projection coverage was extracted into a real private module while
retaining existing verification behavior. No source-size allowance, lint policy,
toolchain or generator pin was relaxed. No unsafe production code was added.

Review conclusions:

- There is one native execution authority. Recovery data, approvals and provider
  observations cannot construct a dispatch owner. Custody, actor and provider
  lookup handles have private construction; compile failures verify relevant
  non-clone/non-deserialization boundaries. Original-only lookups confer no
  execution rights.
- Identity is scoped to the authority, tenant, process and exact action. Commands
  bind stable assigned principals and canonical semantic bodies, including the
  initial expected revision. Committed identity is resolved before rejecting
  a stale revision. Token rotation does not create a new command identity.
- Approval reserves the actual process identity before final admission. The
  exact unsigned requirements, source basis, recipient, purpose and deadlines
  are reviewed together. Every owner and removed compartment obligation is
  covered by current operator assignments for the same action. Aliased
  principals, duplicated issuers and unsupported endorsement powers refuse.
- Version selection is explicit. A present recovery selector requires a complete
  v2 object. Missing/null/unknown selectors, stripped bindings and mixed legacy
  fields refuse. The ordinary v1 representation and established process/native
  digest meanings are preserved.
- Issuance reserves one immutable challenge-bound body before signing. Concrete
  deterministic Ed25519 signing occurs outside transactions. Lost signing and
  attachment acknowledgements recover exact original bytes without renewing
  consent, age or deadlines. Review age is at most 15 minutes; grant age is at
  most 60 seconds and additionally bounded by initiating authority/evidence.
- Native capture owns the recovery join under the existing physical authority
  transaction and current fences. Capture compares the protected immutable
  request, current basis and complete authorization context. The existing
  conservative disclosure-consumption ordering remains in force; later failure
  cannot refund spent authority.
- Original nonce preflight/issuance remains operation-owned. Recovery attaches
  the existing issuance and uses separate fixed-envelope/native-history digests.
  It never rewrites the frozen process envelope or runs a new preflight to replace
  an ambiguous issuance.
- Effect truth comes from native custody or verified positive provider evidence.
  A denial receipt, timeout, negative lookup, cancellation, task abort or Drop
  cannot establish absence of an external effect. Positive partial or
  failed-after-effect settlement spends the step independently of output.
- Historical release reconstructs only a physically captured original operation,
  exact envelope and original verification context under the retained qualified
  profile. Current independent settlement control can recover it after caller
  revocation. Current recipient authority and source clearance still gate every
  result return. Profile changes that cannot verify original history refuse.
- Protected host/store DTOs stay inside the trusted host composition. Public
  protocol status, review, errors and retained results have separate audience
  gates. Debug and transport errors redact content, credentials and signatures.
  Telemetry never stands in for the protected journals or rollback anchors.
- SQLite transactions and store mutexes do not span signing or provider awaits.
  HTTP work has bounded reserved slots; disconnect cannot cancel a captured
  operation. Settlement has independent headroom. Closed identities and command
  tombstones are retained rather than evicted or recycled.
- The pinned connector admits one exact configured resource and native context,
  sends one physical POST, and disables redirects and transport retries. Its
  submit/read credentials are separate and zeroized. Provider evidence binds
  the original operation, attempt, account/resource, cardinality and current key.
  An idempotency header alone is never treated as proof of provider deduplication.
- Pure recovery/semantic libraries retain their dependency direction, alloc-only
  APIs, Rust 1.93 compatibility and WASM portability. Host effects stay in their
  owning Rust crates. Schema references resolve through a finite local catalog;
  unknown/network references, escapes, symlinks and duplicate IDs refuse.

Material corrections and focused verification during review included:

1. Refusing constrained, budgeted, sender-proof, delegated or attenuated control
   tokens whose required native enforcement cannot run on this control profile.
   Every matching grant is checked, including an extra matching DPoP grant.
2. Counting durable tenant workflow/command quotas across all process scopes.
   A second genuine process with the same tenant cannot obtain another intake
   allowance. Existing settlement and tombstones survive the flood.
3. Preserving exact original signature/envelope/nonce custody across lost
   acknowledgements, expiry and restart; preventing v2-to-v1 fallback.
4. Separating original-only historical settlement from new execution authority
   so caller revocation does not destroy captured outcome recovery.
5. Requiring a fresh native source generation even when its labels equal the
   previously reviewed labels. Only the proven same-call observation is accepted.
6. Building exact predecessor fixtures before migration tests, without deleting
   any recovery history or global references. Global predecessor negatives now
   remove the new kind before exercising their intended mutation; they cannot
   pass merely because an unrelated future kind invalidated the fixture.
7. Keeping complete referenced disclosure labels in the pinned Python generator
   output and using the same origin-rooted protocol routes in all clients.

Successful completed native receipts replay byte-for-byte. A compensated frozen
denial has no terminal tool outcome to replay; its immutable original receipt and
process request remain unchanged, while a fresh diagnostic denial may have other
receipt bytes. Its approved continuation has a distinct native/process identity.

## Verification and observed limits

All required local P1 gates pass. Exact commands, counts and fingerprints are in
verification.json; repeated/overlapping suites are not presented as independent
test counts.

| Local gate | Result |
|---|---|
| Native P1 benign/refusal tests | 15 pass; two explicit child/vector-export entrypoints are excluded from ordinary test execution |
| Fresh-process native corpus | All 27 declared SIGABRT cutpoints pass, with independent external-effect counts and exact retained identities |
| Pinned connector checks | Two pass, including unsafe/unscoped refusal and original native correlation/credential separation |
| Native migration/WAL checks | Populated v34 upgrade, interrupted production DDL and real pinned-reader WAL headroom pass |
| Migration regressions | 35 upgrade cases, five populated predecessor cases, the separately selected v28 native-anchor transition and four global-catalog cases pass |
| Pure contracts, flow and tooling | Owning suites pass; shared signatures/schema corpus and correctly re-signed binding mutations pass |
| Kernel ownership doctests | 13 pass |
| Python SDK | Full local suite: 383 pass |
| TypeScript recovery SDK | 150 pass; strict source/test checking with TypeScript 5.7.3 and public ESM/CommonJS build/export checks pass |
| Rust hygiene | Strict Clippy passes for all 11 selected native/pure/tooling crates and all targets; format, source-size, lint/toolchain parity and dependency/layer checks pass |
| Generator drift | Rust, Python and TypeScript checks pass with their unchanged generator pins |
| Portability | Isolated/unified Rust 1.93 and WASM alloc-only checks pass |
| Supported macOS workspace | All-target check passes, excluding the two existing Linux-only product crates |

The larger regressions were run and every failure was classified rather than
hidden behind a green aggregate:

- The control-plane library initially passed 1,092 cases. Its five native
  capture failures under concurrent load all pass sequentially with production
  deadlines unchanged. The other 55 failures require blocked listeners or DNS.
- The storage library initially passed 1,769 cases, with 62 failures and four
  ignored cases. Eighteen predecessor-fixture failures and one global fixture
  failure were corrected and pass. Fourteen failures pass with a canonical
  macOS temporary path. The remaining 29 require the unavailable Linux
  `/dev/shm` anchor fixture. No production path protection was weakened.
- The kernel library passes 1,447 cases; its 12 HTTP listener failures are
  sandbox `EPERM`. The process library passes all five cases.
- All 95 owning integration targets ran: 761 cases initially pass. Three
  receipt-writer cases pass with canonical `TMPDIR=/private/tmp`; their first
  run missed sync events under macOS's `/var` path alias. The remaining failures
  are 38 Linux anchor fixtures, 14 socket-dependent cases and one DNS case.
- The existing broader Node HTTP suite has 41 blocked socket cases; the 150
  recovery cases use current local sources and pass without listeners.
- Strict CLI Clippy stops at the existing macOS `Host.keyring` dead-code warning
  in an unchanged file. The CLI compiles and its recovery command group runs.
  This is not represented as a green strict CLI lint check.
- Kani 0.67.0 cannot launch because its pinned
  `nightly-2025-11-21-aarch64-apple-darwin` toolchain is absent. No new formal proof
  result is claimed. Existing proof/tool pins are intact.
- TypeScript runtime tests used cached Vitest 4.1.8 instead of lockfile 4.1.11;
  the package bundler used cached esbuild 0.27.7 instead of lockfile 0.28.1.
  TypeScript 5.7.3 and the code generators match their declared pins. A fresh
  hosted package-lock installation remains a separate release check.

These retained limits do not establish a fully green workspace, hosted CI,
Linux enforcement qualification, live-provider qualification, production
throughput or public release. No commit, push, deployment or publication was
performed. Task-created SDK dependency links/overlays were removed; external
caches and unrelated work were preserved.

## Matched budget and next phase

The isolated native debug comparison uses the same retained P0 fixture: eight
warmups, 64 measured calls and eight exact replays. It records zero benign errors,
72 actual external effects and 72 logical-call charges, with no extra effect or
charge on replay. P1 p95 is **184,721,458 ns**, below the predeclared
**220,683,049 ns** ceiling. P0 p95 was 183,069,208 ns; the observed increase is
approximately 0.90 percent. This is a local native-path regression measurement,
not end-to-end recovery or production throughput qualification.

Proceed to **[P2: explanations](../../10-delivery-decisions.md)**. Implement
recovery-specific pure snapshots, bounded counterfactual planning and
audience-safe signed advisory reports. Verify report recomputation, leak probes,
absence of effect dependencies and live refusal of stale bases. Keep P1's
durable native authority and exact-operation recovery as the execution boundary.
General semantic remedies remain P3; product/provider/installation and scale
qualification remain P6.
