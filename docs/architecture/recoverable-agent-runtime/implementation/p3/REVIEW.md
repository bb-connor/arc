# P3 source review and acceptance

Review scope: the complete P3 delta from the retained P2 working-tree baseline,
the native interfaces it changes, generated wire/SDK boundaries, fixtures,
dependency and schema manifests, and the declared local sequential profile.
Reviewer: Codex, source self-review. This is not independent human signoff.
Final closure is recorded only by the completed source-bound `verification.json`.

## Completed task crosswalk

| Task | Result |
|---|---|
| P3-01 | Independently signed package/deployment contracts, complete 13-channel inventory, finite selectors, reviewed overrides and immutable activation generations |
| P3-02 | Exact provider/account/resource transport binding, complete fresh ACL observations, bounded selected annotator powers and retained influence |
| P3-03 | Exact-action scoped integrity endorsement, separate confidentiality checks and one-shot protected native consumption |
| P3-04 | Native field-projection producer, exact provenance, selected alternate account transports and bound Withhold without raw fallback |
| P3-05 | Bounded acyclic plans, exact per-step materialization and distinct historical/current/held prerequisite checks |
| P3-06 | Semantic checks inside existing physical capture, final protected dispatch checks, affine submission ownership and native output/replay mediation |
| P3-07 | Shared closed wire vectors, native positive/refusal/restart/tamper cases, SDK checks, portability, operating contract and complete source review |

All 15 mandatory P3 obligations are mapped to implementation anchors, named
acceptance tests and retained executable evidence in `requirements-coverage.json`.
The architecture's historical requirements and P1/P2 evidence are unchanged.

## Reviewed boundaries

The inventory and verification record enumerate and hash every reviewed authored
Rust source. Review covered all P3 Rust changes, not just the new crate: closed
types and cryptographic domains; pure resolution, selectors, plans and evidence;
native history, original request and participant custody; serving-store protected
records; process/kernel request identity; physical budget/capture integration;
dispatch, transforms and output release; trusted host transports; tests and
fixtures; and Python generator changes. Generated Rust/Python/TypeScript output,
20 additive schemas, finite local schema aliases and registry/lock/manifest
updates were reviewed separately and checked for regeneration drift.

No new unsafe code, panic-based production error path, unwrap/expect allowance,
lint suppression or dependency package-pin change was introduced. The semantic
crate remains alloc-only and effect-free; native integration stays in owning
kernel, serving-store and host modules. Existing code follows the repository's
native capability, canonical JSON, fence, receipt and effect ownership standards.

## Material findings resolved before closure

| Finding | Resolution and acceptance evidence |
|---|---|
| Package metadata could otherwise substitute host topology or authority | Signed native/context/exposure digests, independently selected roots and exact actual inventory comparison; publisher/operator and coverage mutation tests |
| Payload-only endorsement could miss request identity, model or authorization changes | Exhaustive reviewed native request projection plus exact action digest; native identity/capability/model mutation matrix |
| Equal labels could hide an intervening knowledge generation | Endorsed native source basis and the existing original call's verified input/nonce history; foreign-generation native refusal |
| Annotation confidence or transport trust could become endorsement | Explicit selected fact powers, exact retained annotation influence, aggregate 32-fact limit and independent exact-action endorsement; role/owner/influence tests |
| An account alias, malformed version or incomplete ACL could widen recipients | Exact transport/credential tuple, closed response echo, exhausted pagination and one strong ETag; alternate-account, tuple, pagination and uncertainty tests |
| A plan or transform could substitute unknown bytes or another producer | Declared completed native dependencies, exact retained output and separate pinned projection operation; code/material/scope substitution and withheld-producer refusal |
| Old evidence could revive a predicate or lease | Strict newer observations, idempotent replay preserving revocation, current authoritative state and atomic one-shot lease consumption; historical/current/held and lease-reuse cases |
| Plan revision or duplicated dispatch description could reopen an effect | Stable logical step identity, protected evidence/submission spend and private consuming Send/non-Sync owner; direct-kernel/revision/restart cases and ownership compile-fail tests |
| A transformation, error or replay could release withheld provider bytes | Disposition applied before receipt content and final release on initial/replay paths; no future use of withheld producer; raw-error and output-canary tests |
| Waiting cancellation could free capacity while blocking work continued | Owned semaphore permit moves into the blocking worker and remains through submission; no store/network await lock is held |
| Required nullable proof fields could silently disappear in generated models | Required serde nullable fields and generator hardening; shared missing-field and generated exact-roundtrip vectors |
| Platform temporary aliases prevented rollback tests from reaching their assertions | Canonical existing backup parents in three fixtures and a canonical subprocess TMPDIR; production no-symlink checks and all rollback assertions remain intact |

Open P0 severity findings: **0**. Open P1 severity findings: **0** in the reviewed
P3 changes and declared supported local profile. Phase numbers and issue
severities are distinct. This conclusion does not claim an audit of every
unrelated workspace crate or production deployment.

## Verification and diagnostic limits

The final verification record lists every actual command, environment, exit code,
duration and log hash. Required gates cover native P3 behavior, retained P2 native
behavior, submission ownership doctests, owning Rust tests, conformance library,
strict Clippy across all 12 owning crates, formatting, vectors, three codegen
checks, SDK tests/builds, pure dependency mutations, schema/domain/lock/layering
checks and alloc/std/WASM/MSRV portability. Actual counts are derived from those
logs; only successful final required runs count toward acceptance.

A broad Rust conformance attempt is retained separately: six tests could not
bind tiny_http listeners because this sandbox returns EPERM. A subsequent broad
owning run reached 1,448 passing kernel library tests but failed 12 unchanged
payment HTTP listener tests with the same EPERM. Both failed broad attempts are
retained. The required kernel-library run filters only those 12 exact named tests;
its argv and filtered count are explicit. Eight other owning packages run in a
separate complete gate with canonical temporary paths and two test threads.
The store has focused rollback regression and doctest gates in addition to the
production native P3/P2 tests. The first broad store
attempt retained 1,786 passed, 45 failed and four ignored tests: 29 required the
unavailable separate Linux `/dev/shm` anchor device; 14 rejected macOS temporary
path aliases; two egress tests returned generic native InvalidData. Both egress
tests passed unchanged in isolated diagnostic runs. A later corrected store
component passed all 1,802 supported library tests, with zero failures, four
declared ignored cases and 29 exact unavailable separate-device filters. Its
aggregate command subsequently failed all 11 remote-delivery tests at socket
setup with EPERM. The complete attempt is retained in
`evidence/store-integration-attempt.{log,result.json}`; the passing component is
not reported as a passing aggregate command. The focused store gate rechecks the
changed rollback fixtures and preserves the qualified
anchor's distinct-device requirement rather than substituting a colocated root.
The passing store component included the corrected rollback fixtures and other
no-symlink path tests. No default-concurrency, remote-delivery or distinct-device
qualification is inferred from that supported component. Conformance/control-plane and kernel ownership checks are
recorded in their own gates. Prior broad P1 stress and Node HTTP socket failures remain in immutable
P2 evidence and are not reclassified. This phase does not claim full-workspace,
unfiltered-kernel, full-control-plane, all conformance integration or socket-suite qualification.

Exploratory native/P2 runs encountered clock-skew/late capture refusal. An
unchanged isolated withholding test passed; those failures were not promoted to
acceptance. A later competing broad build exhausted disk space, producing
explicit SQLite disk/full and compiler output failures. The failed commands and
logs are retained in `evidence/disk-exhaustion-*.{log,result.json}`. Only this
worktree's untracked incremental compiler cache was cleared, restoring 123 GiB
of headroom; the clean required runs use two build jobs and no incremental cache.
The clean run is the source-bound acceptance evidence, not an inferred correction
of the earlier failure results.

Local native tests use the production kernel/store/connector paths and an
independently counted, persistent provider fixture. Synthetic fixture keys and
schema/code identity tags are test data; they are not a live deployment
attestation. Trusted host setup must supply its reviewed actual exposure and
measurements and separately qualify its gateway's precondition guarantee.
Gateway wire construction/response checks are tested without opening listeners.
No live vendor gateway, hosted CI, Linux confinement, Kani execution, comparative
scale/performance or production release is qualified here. Offline cache
versions and lock differences are explicit in `evidence/tool-environment.json`.

## Evidence continuity and next phase

`source-baseline.json` and `evidence/p2-source-baseline.tar.gz` retain all 432 P2
source hashes and the historical phase document hashes. The source-bound P3
package adds a complete current inventory/archive and a read-only integrity
verifier. The P2 verification digest remains
`419bbe28b759f796f17e26d62b05dd94b8f53e8d6045412eb0a0c6a251ebdb55`;
historical evidence was not resealed against later code.

Next is **P4 durable knowledge**: mediated artifact publication/read, retained
labels and provenance through checkpoints/model contexts, restore/export,
retention, adoption and safe garbage collection. Reusable artifact authority
must not be inferred from P3's one-shot action endorsements or transform proofs.
