# Lease-fenced progress and framework ingress

Source base: `14ce46a3edbf75c27162d2c13c1dce07b919b070`. Implementation:
`323316a9921259eb25a9f315a1be556cca5280b0`, published and remote-verified on
`packet/3-retention-accounting` from `/tmp/arc-security-launch`.

**AC4 and the scoped CA3 batch are implemented and locally accepted.** The
[plan](../superpowers/plans/2026-10-02-lease-fencing-framework-ingress.md) and
[design](../superpowers/specs/2026-10-02-lease-fencing-framework-ingress-design.md)
define the scope. This is source delivery and local qualification. Hosted CI,
complete workspace health, release and deployed acceptance remain separate.

## Completed tasks

| Task | Implemented behavior | Evidence |
| --- | --- | --- |
| AC4 protected writes | Run, step and recovery-evidence writers require the current owner, lease ID and fencing token inside the committing IMMEDIATE transaction. Owned time is read after locking; malformed timestamp storage, expiry and clock regression refuse without mutation. | 13 write-fence cases plus 104 existing lease, operations and store cases |
| AC4 consumers | Insert-only pending registration grants no ownership. CLI plan/run acquire their own current lease and atomically commit run, step and artifact progress with fenced release. Destructive-operation lease evidence remains separate. | 15 CLI orchestration cases, including another-owner refusal and successive released fences |
| CA3 inventory | Request Json/Form, response JSON, alternate formats and shared-reader callers remain visible. Ordinary module/reader aliases, reexports, cycles and namespace distinctions have controls. | 739 files and 3,498 observations; 35 existing and 23 ingress Python cases |
| CA3 actual ingress | All 104 control-plane JSON bindings use bounded original bytes before typed extraction: 99 strict signed/authoritative and five unsigned document readers. Nested mounts, route ordering and deliberate body-limit exceptions retain the contract. | Complete 566-case trust-control suite, actual-router rejection/success controls and checked route composition |

The [HTTP contract](../security/http-ingress-contracts.md) records each parser
mode and body limit. Honest signed certification/policy requests succeed;
duplicate, lossy-number and tampered-signature requests leave registry bytes
unchanged. A valid unsigned simulation accepts `0.50`. Router tests cover nested
parameterized mounts, service authentication, media/method selection, transport
failure and early termination of oversized streams. The nested certification
publication fixture has no remote peers and does not qualify network fan-out.

Registration cannot reset an existing run. Progress advances the persisted time
floor without extending lease expiry. A late artifact SQL failure rolls back the
run, steps, evidence, heartbeat and release together. Explicit-time scheduler APIs
remain trusted orchestration entry points; protected writes independently observe
owned time. No whole-database rollback defense is claimed.

## Qualification and retained failures

The [qualification manifest](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-02-lease-fencing-framework-ingress/qualification.json)
records commands, exits, complete-log hashes, source hashes, binary hashes and
the remote source SHA. Full logs remain under
`/home/connor/chio-security-evidence/2026-10-02-lease-fencing-framework-ingress`.

| Final executed scope | Passed |
| --- | ---: |
| Runtime core: write fencing, lease boundaries, runtime operations and store | 117 |
| Control plane: trust-control suite plus distinct repaired/ingress/recovery cases | 600 |
| CLI orchestration | 15 |
| Python source-gate calibration | 58 |

There are **732 distinct Rust passes and 58 Python passes**, with zero ignored
or skipped cases in those final scopes. The control-plane count is the union of
566 trust-control cases and a 49-case selection, with 15 overlaps counted once.
Warnings-denied all-target Clippy passed for runtime-core, runtime, control-plane
and CLI. Workspace formatting, trust, clock, hygiene, negative-assertion and wire
gates passed. No allowance, timeout, ignore or debt baseline grew. Rust behavioral
runs precede three final formatting-only module/router edits; Clippy and source
checks passed on the formatted source. The manifest states Python check reuse.

Earlier attempts retain their actual outcomes:

- Four initial write controls failed behaviorally, followed by the separate
  stale-evidence control. One partial-name selector with `--exact` ran zero cases;
  it is recorded as not executed, not as a passing control.
- Three initial actual-router controls failed. Initial Python ingress calibration
  had six failures and one pass.
- A broad control-plane run was interrupted after 385 passes and ten observed
  economic-recovery fixture failures. The remaining cases were not executed.
  Those fixtures froze time after opening the authority store, backdating its
  persisted clock floor. Freezing before opening preserves the production fence.
- The first complete trust-control selection had 559 passes and seven failures:
  six old authority fixtures used non-private temporary parents, and the new
  unsigned simulation fixture lacked its required query anchor. Private fixture
  directories and a valid subject filter repair setup. The rerun passed all 566.
- The late scheduler rollback fixture expected the old string error instead of
  the typed SQLite cause. Its exact injected-failure and zero-write checks remain.
- Intermediate scanner fixes exposed recursion through glob imports and the
  module/value namespaces. Their failing controls, diagnostics, a stale reader
  hash and the initial formatting failure remain retained.

One [independent review](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-02-lease-fencing-framework-ingress/independent-review.md)
found four Important issues: SQLite storage classes, nested-router bypass,
middleware placement and alias visibility. All four have reproducing controls
and author-verified corrections. The original negative review verdict is retained;
there was no second independent review and no deferred Minor finding.

## Decisions and remaining boundaries

The existing isolated security checkout and publication authorization were reused;
preexisting `output/` and unrelated worktrees were preserved. One domain delegate
handled ingress, root owned Rust qualification/Git, and one fresh reviewer checked
the integrated source. Evidence writes were added to the lease boundary because
their presence affects recovery. Retaining an unfenced compatibility writer would
leave that path open, so downstream callers must migrate to explicit leases.

Source census counts are observations, not vulnerability or completion counts.
The direct census remains 253 files with 45 raw baseline files. Two API-protect
JSON extractors, three Form extractors and 35 response/alternate-format file
dispositions retain explicit remaining risks. Dynamic dispatch, arbitrary macros
and generated routes remain outside the bounded lexical resolver.

The next substantial batch is **AP4-AP6 inbound authority**: deny unmatched routes
and require explicit local anonymous-read policy; trust side-effect overrides only
from operator-pinned specs; reject unverified JWT confirmation and carry sender
proofs through production consumers; derive certificate/attestation identity from
trusted transport context. Close the two API-protect threshold JSON gaps while
working on those entry points. Current source still contains the reviewed default
allow and caller-header binding behavior. Remaining TCB reader semantics,
proof-result sealing, error provenance, other compliance findings, branch
decomposition and hosted/operator assurance remain queued.
