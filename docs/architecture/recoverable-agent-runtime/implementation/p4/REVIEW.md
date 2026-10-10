# P4 source review

Reviewer: Codex. Review kind: complete source self-review of the P4 changes
against the sealed P3 baseline. Independent human signoff: not obtained.
Confidence: high for the declared local Unix SQLite knowledge profile.
The final [verification record](verification.json) is the phase acceptance
record; [coverage](requirements-coverage.json) maps all 13 required obligations.

## Reviewed scope

The review covers all 59 handwritten Rust paths changed by P4, including pure
contracts and signatures, private broker ports, process migration/refusal,
publication, read/restore admission, transfer, retention/collection, actual
native row mutation and global-history reconstruction. It also covers the 13
new closed schemas, shared contract corpus, generated boundary representations,
Rust/Python/TypeScript consumers, codegen manifests and evidence tooling.
`source-inventory.json` records the complete joined source set and the P4 delta;
the verification record binds each reviewed Rust path to its final source hash.

Checks included state-machine cutpoints, actor and audience permissions,
fresh capability/ancestry liveness, native scope/identity, canonical signed bytes,
role/domain separation, producer/certificate identity, full dependency closure,
monotone confidentiality and influence, unknown acknowledgements, physically
shared dedup generations, GC/read/publication ordering, protected history and
rollback, durable activation and raw worker/reader routes. The review evaluated
failure paths as well as happy paths. No new unsafe code, lint suppression or
external dependency package/version pin is needed for P4.

## Findings resolved before closure

| Finding | Resolution and acceptance evidence |
|---|---|
| A certificate signature alone did not prove an actual native projection producer. | Projection now requires the actual completed captured transformation, exact selected implementation/configuration, full certified input identities and bytes, ReturnValue disposition and recomputed retained output. A self-described derivation and withheld producer refuse. `knowledge/native.rs` covers both cases. |
| Public artifact/model influence could leave an old scoped endorsement usable. | Native knowledge history retains influence for shared principal, lineage or session. Host framing and final native capture both recompute that influence under the existing shared work budget. An old endorsement refuses after a Public but externally influenced model observation. |
| A delayed collector could delete newly recreated equal bytes or clear a newer sweep. | Stored blobs have a random physical generation. Collection deletes only the exact original generation; the serving barrier and its finish acknowledgement bind the exact seal. Two delayed collectors and subsequent publication are exercised with deterministic interleavings. |
| Existing metadata-return paths, storage counts or physical process reuse could expose a private dedup/provenance channel, including a clearance reduction during publication. | Reservation, staging, metadata commit, finalization, checkpoint creation and collection metadata validate the fresh actor audience. A protected physical namespace/process owner binds the original tenant scope and refuses foreign profile reuse. Cross-scope errors are generic. Raw storage counts refuse after activation. The native clearance-reduction test proves refused commit rolls back to Staged and succeeds only after audience authority is restored. |
| An old/open raw reader, repeated registration, retained registry or restored legacy journal could reactivate raw checkpoint reads. | Every raw reader call rechecks the journal version; a protected native marker survives process-journal rollback. Every public snapshot route, including root/child registration and registry caller resolution, validates that marker and redacts checkpoint content. A read-only serving-port/fence probe avoids a kernel ownership cycle. Tests cover repeated registration, existing reader/registry revocation and a simulated old journal. |
| Native knowledge journal validation omitted explicit full release-scope and admitted-label bindings. | Journal validation now binds record, artifact and recipient scopes and requires the admitted label to flow to both the joined native source label and recipient clearance. Reopen recomputes complete row images in anchored global event order. |
| Native-operation, pending-review and checkpoint side-file retention needed explicit evidence. | Actual native custody and pending reviews have separately validated permanent pin APIs. All checkpoint revisions and selected model side files are scanned. Tests use a real unknown captured operation, native producer receipt and pending owner review. |

No open P0 or P1 severity finding remains in the reviewed P4 changes and declared
supported local profile. This statement does not qualify unrelated workspace
changes, future unsupported backends or deployment behavior.

## Acceptance review

The native P4 suite uses the production kernel, actual process journal,
fenced serving writer and native flow rows. It exercises five publication
cutpoints, orphan retirement, exact adoption, signature/producer substitutions,
missing/corrupt content, protected metadata mutation refusal, wrong tenant,
all-input closure and bounded overflow, archive tampering, old checkpoint CAS,
provider-context rotations, physical alias/replacement refusals, restart,
unknown release acknowledgement, live revocation and GC ownership. A sink
independently checks that the protected native knowledge record exists before
receiving any bytes.

The actual capture observer pauses before or after the real native capture
transaction to prove both commit orders with an intervening knowledge release.
The observer is test-feature-only and cannot skip or authorize capture. If
knowledge wins, stale capture refuses before an effect. If capture wins, the
operation and original quota ownership remain retained; a later dispatch refusal
is permitted and is not reported as proof of an uncaptured operation.

Portable acceptance recomputes shared vectors in Rust, validates closed ingress
in Rust/Python/TypeScript, distinguishes structural from cryptographic validity,
checks pure certificate/archive verification, and builds alloc, std, WASM and
MSRV 1.93 consumers. SDK conformance runs against this worktree's source, not the
older cache checkout. Strict Clippy and formatting are required gates. Failed
exploratory compilation/test-fixture/cache attempts remain diagnostic evidence;
only actual successful final gates qualify the phase.

The first P1 regression run correctly refused a process snapshot after protected
native history corruption. Its older assertion expected the raw snapshot to
remain readable. The test now requires that stronger refusal and independently
reads the private operator journal in read-only mode to prove the original one
call still owns its quota. A rejected multi-statement mutation can still drop a
trigger before its later SQL fails, so that partial DDL case also requires native
read refusal. The isolated four-mutation regression passed before rerunning the
complete P1 gate. No production validation was weakened or skipped.

The retained gate commands and logs, rather than this prose, determine exact
test counts. Store gates cover native participant state, global ordering, schema,
rollback regression and doctests. Kernel regression filters only the same 12
unchanged payment-listener cases unavailable in this sandbox. P1-P3 native
regressions are required. No unfiltered full-workspace green result is claimed.
The evidence audit rejected an initial schema filter that executed zero tests.
The corrected compiled module filter ran 15 passing schema tests with one
documented child-only test ignored. The sealer now rejects empty required
filtered Rust gates; the empty attempt remains diagnostic evidence.

## Qualification boundaries

The backend is host-private Unix SQLite with bounded buffered delivery. All
filesystem/object-store artifact backends, arbitrary paths, mutable aliases,
chunked streams, cross-authority/process transfers and evidence pruning refuse
or are absent from the declared profile. Permanent pins and finite history are
conservative: they fail closed on exhaustion and require explicit operational
capacity planning. The model envelope is local retained state, not a proven live
provider cache lifecycle. Outbound provider requests retain independent native
effect authority.

Offline Node qualification used cached Vitest 3.2.6, TypeScript 5.7.3, AJV 8.20.0,
esbuild 0.27.7 and json-schema-to-typescript 15.0.4. Vitest/esbuild differ from the
unchanged lock pins; clean-install qualification remains separate. Temporary
workspace overlays are removed before sealing the package. Existing P3 failed
broad socket/platform runs remain immutable historical evidence.

The review does not establish hosted CI, Linux confinement or distinct-device
anchors, Kani proof, live gateway/provider behavior, comparative performance,
scale acceptance or production deployment. The [operating contract](OPERATIONS.md)
states installation, delivery/replay and retention limits. P5 is confined returns:
host-issued lineage, enforced cage/broker launch, bounded parent returns and
mediation of every enabled output channel.
