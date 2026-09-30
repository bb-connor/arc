# Native multi-route consumer execution

Continued September 30 in `/tmp/arc-security-launch`, branch
`packet/3-retention-accounting`, from local parent `2a4c2fbe4f`.
The [plan](../superpowers/plans/2026-09-29-native-multiroute-consumers.md) covers
four tasks. Tasks 1 and 2 were committed in the preceding turn; this continuation
implements the remaining consumer and qualification work.

| Task | State | Delivered boundary |
| --- | --- | --- |
| 1. Multi-route broker authority | Complete | Bounded exact routes and common authority generation; original per-route custody, capture, recovery and offline evidence. |
| 2. Host-owned Docker/provider adapters | Complete | Pinned transport/resource identity, bounded parsing and no automatic effect retry. |
| 3. Consumer preparation and migration | Complete | Prepared session/operator/repository callers, host-owned repository adapter, exact Python/application resources, current-only retained state and original output proof. |
| 4. Native campaigns and CI | Complete for focused acceptance | Baseline/crash/unknown, sessions, repository scope/operator, installed packages, examples and AI SDK campaigns pass. Comparison passes all eight cases; large-output, restart replay and offline proof pass on CLI9. Native CI inputs are wired. |

## Retained-history and native lifecycle

Ordered history validation now checks each event's budget reference, digest and
lease fence in the same traversal. Admission/capture/output paths reuse the
initialization already verified in their current transaction. Current-row,
ordered replay, count, orphan, rollback and corruption checks remain enforced;
no verified result is cached across a transaction or mutation boundary.
Physical native-output readback also decodes retained output once, returning
the same canonically validated value whose digest, size and original operation
binding were checked. Field reconstruction and canonical validation are separate
private steps, so a wire decode does not serialize the full payload twice.
The projection and release-checkpoint validators share that decoded payload and
one checked signing-preimage read inside the current call. No decoded state is
cached across calls or transactions. No input or historical corruption check is
omitted. The native history suite passes all 96 cases, including independent reference-field
corruption and rollback controls.

The native mini-SWE baseline now finishes all eight calls. Known worker death
recovers without extra effects; the uncertain provider campaign records one
provider dispatch, zero command effects and no redispatch on restart. Historical
failed campaigns remain retained and are not relabeled as successful.

The MCP transport also had an independent exit race: its supervisor cancelled a
request after the child exited while the stdout reader was still decoding that
child's final response. Natural exit now leaves ordered response/EOF delivery to
the reader. Explicit shutdown and failed terminal-receipt persistence still
cancel requests; new calls after exit are refused. The original deadline bounds
stdout inherited by descendants. A deterministic held-reader regression fails
before the fix and passes after it. The full adapter suite passes 122 tests;
the two exit tests also pass after moving them into their own module.

## Repository and installed consumers

A Rust repository HTTPS adapter owns pinned loopback TLS and the bearer secret.
It validates its protected launcher, workspace configuration and per-command
configuration digest, then exchanges bounded framed messages with the installed
Python repository adapter. The launcher executes from a sealed memfd to close
the check/exec replacement window. Parent death kills the child; uncertain or
malformed responses retire and reap it without automatic restart or replay.
Workspace ownership is acquired per command, allowing idle offline export while
still rejecting concurrent execution. Recovery requires explicit operator action.

The process SDK captures a bounded, explicit Python module set into a protected
archive. The isolated interpreter, standard library, native extensions and
application archive are declared runtime resources. SQLite consumers precreate
the database and PERSIST journal, then receive exact read/write file access.
The compiler combines matching read/write grants only after separately checking
both operator ceilings. Directory writes and distinct hardlink aliases remain
refused. The selected native standard syscall profile adds positional writes,
data synchronization, effective-UID observation and nonblocking SQLite record
locks. It does not add socket creation, blocking locks or descriptor duplication.

Prepared streams retain their short authentication/control deadline and use the
signed request timeout for execution. The raw broker response ceiling remains
512 KiB; its nested byte-array and JSON transport envelopes have separate bounded
limits. Classification now has its own 4 MiB payload owner so complete delivered
envelopes can be classified, while control/authority bodies retain their 1 MiB
ceiling. Constructor, bounded-deserializer and full-envelope regressions cover
that distinction. The regex classifier and result validator use the same
classification ceiling. The CLI regression traverses the actual broker-body
classifier for large ASCII and escaped NUL data, retaining exact findings and
the original envelope digest.

Mini-SWE state is v2. Session request/authorization v2 pins the broker executable,
peer, route, signer, nonces and process identity. Repository receipt binding v2
binds each command/configuration to the original prepared request and matches
retained original output bytes to the signed kernel receipt. Offline verification
requires the command-output artifact. Obsolete mini-SWE and workspace v1 readers
are removed; workspace v2 shared snapshots and v3 scoped snapshots remain current
formats with different semantics.

Repository-review, adaptive review, shared-resource ownership, process packages,
the offline review kit, AI SDK qualification and the paired benchmark use these
explicit native resources. CI has a reusable prepared-broker action, the complete
bounded CPython closure, enforcing CLI/helper/adapter inputs and the current
installed process SDK. Discovery, recovery and negative gates remain enabled.
The comparison harness keeps private directory components short enough for Unix
socket paths, independent of human-readable scenario names.

## Verification and evidence

The [continuation evidence](artifacts/2026-09-29-native-multiroute-consumers/continuation-20260930/README.md)
contains terminal logs, reports, source differences and binary/package hashes.
The original artifact directory preserves the preceding partial qualification.
Exact commands/selectors and failures belong to those records; counts below
refer to their individual feature sets, not a deduplicated workspace total.

- Broker library: 173 pass. Repository adapter: four pass. Response budgets: two
  pass. Exact native read/write compiler: 17 pass. Selected SQLite syscall profile:
  one pass. Native history: 96 pass.
- Python SDK/session/process/helper campaign: 441 pass. Repository-review: 38
  pass. Shared-resource: 12 pass. AI SDK qualification helpers: two pass.
  After current-schema cleanup, 123 repository/storage/scope/recipient tests pass
  both locally and against the final installed wheel.
- MCP adapter: 122 pass; moved exit regressions: two pass. Classification payload
  bounds: two pass; complete broker envelope regression: one pass. Actual broker
  classifier and regex/result-bound regressions: one each. Flow classification and
  declassification: 11 pass. Kernel outcome contracts: 17 pass. SQLite outcome
  projection, owner rotation, tampering, compaction and rollback: 26 pass.
- Native mini-SWE baseline, known crash and unknown-effect recovery pass. Native
  retained state completes 120 turns and 361 revisions. Operator/provider failure,
  saved host/worker death, repository scope refusal, slow repository command,
  host replay, session export and final installed scoped session pass.
- Native repository-review, full review, adaptive review, shared-resource and
  explicit ownership campaigns pass. Installed Python/Node/source packages,
  recovery, offline review kit, AI SDK profiles and its paired benchmark pass.

The final public-repository campaign passes on CLI9: a 65-second command, exact
500,000-byte ASCII and 79,000-byte escaped-NUL outputs (plus their newlines),
restart replay without a new effect, two verified transitions, and a patch that
applies to the unchanged public source checkout. Earlier attempts remain failed;
the enclosing projection/release read was also consolidated after attempt 5
showed the initial raw-decoder optimization was insufficient.

The fresh isolated comparison passes all eight cases across two trials on CLI7,
including effect-oracle and original-receipt checks. Its earlier attempt failed
the sixth native handoff while the optimized CLI build was running; that retained
operation was not retried. Targeted Clippy, Rust/Python format, Rust hygiene,
trust-boundary, wire-schema, negative-assertion and CI-inventory checks pass.
The optional broad control-plane rerun was interrupted after 85 of 195 cases;
its recorded disposition makes no full-suite pass claim.

The native checkout is a common source base plus overlays, not the local final
Git commit. Source manifests identify remaining test/docs/formatting differences;
binary manifests distinguish every CLI generation, helper, adapter and image.
Passing one generation does not qualify a later exact candidate. Private keys,
authority databases and original uncertain operations remain on the retained
worker, including a private archive of the original failed and final campaign
states. OCI reports the worker STOPPED; boot and anchor volumes are retained.
The code graph was refreshed after the final projection repair. No push, merge,
publication, hosted CI, M5 or global roadmap completion follows from this batch.

## Next substantial batch

Continue the product authority and rejection queue through the 13 selected CLI
process/evidence reader files, all six `chio-api-protect` baseline decoder files and the nine
`chio-proof-room` baseline files. Classify their actual ingress/proof contracts,
repair original-byte and size checks, preserve typed local parser causes with
redacted public errors, and reconcile their clock/deadline/accounting owners.
Add owner-specific substitutions, expiry and corruption controls; ratchet the
inventories from observed contracts. This is a bounded implementation batch, not
a mass decoder replacement. The [remaining queue](2026-09-28-remaining-security-work.md)
keeps the other arithmetic, clock, schema, sanitizer, retention, formal,
supply-chain and exact-candidate delivery gates open.
