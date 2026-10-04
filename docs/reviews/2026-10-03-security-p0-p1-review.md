# Security P0/P1 review and repairs

The user requested publication of remaining security source and a deep review of
the existing security roadmap and review changes before any further feature work.
The reviewed base is `a99437b3ea8ef7ea03c7d2926049b27cb140b3c5` on
`packet/3-retention-accounting`, in `/tmp/arc-security-launch`.

The review follows the September 25 assurance closeout, September 26 engineering
standard and [October 1 execution review](2026-10-01-execution-review.md) and
[product-truth review](2026-10-01-compliance-product-truth-review.md). It focuses
on the integrated receipt, retention, authority, HTTP, MCP, clock, release and
evidence-package boundaries. This is a bounded source/regression review, not a
new whole-workspace independent audit or hosted qualification.

## Publication preflight

Origin was fetched and the security worktrees were inspected. All 28 selected
local security branch tips were already reachable through origin refs. There
were no pending security source edits before this review. Some historical local
branch pointers differ from their same-named remote, but their commits are
published through other refs; they were not force-pushed. Untracked historical
`output/` evidence and unrelated experimental worktrees were preserved.

The publication manifest and terminal commands are retained with this review's
[evidence](artifacts/2026-10-03-security-p0-p1-review/README.md).

## Findings and repairs

No P0 was found. Five P1 cases were accepted, including the existing EV1 case
whose High impact applies to deployments with receipt paging enabled.

| ID | Failure and precondition | Repair and regression |
| --- | --- | --- |
| RV1 | An archive editor changes unsigned source sequences while preserving authenticated claim payloads. Live/archive collisions or unconstrained duplicate rows silently omit authentic receipts or falsify query filters. | Validate committed cursor uniqueness by receipt kind, live allocation ceilings and absence of live collisions. Count every source and joined lineage row before checking signed projections. Controls cover one-row pagination, the native export page boundary, future tool/child sequences, changed archive DDL and extra source/lineage rows. |
| RV2 | A second store handle adds active reconciliation or a cross-prefix dependency after retention selects its boundary. A faithful archive copy passes equality checks, then destructive rotation removes required live work. Clamping an eligible later checkpoint to an earlier verified ceiling can also split a dependency. | Bound eligible candidates before selecting their maximum, then revalidate the exact selected checkpoint under `BEGIN IMMEDIATE` before deletion. Controls retain open/retry work and lineage, preserve all live receipts/watermark on refusal, and permit a later complete rotation. |
| RV3 | A request waits for an MCP stream after initial authorization, retains a session handle through terminalization, then enqueues work on the still-running shared transport. | Check lifecycle and the owned deadline under the same mutex used by drain/terminal transitions, holding it through enqueue. Approval validation stays outside that mutex to avoid nested locking. Controls include a deterministic HTTP stream interleaving, all terminal states, drain, wall/monotonic expiry, clock faults, initialization and a live positive case. |
| RV4 | Raw route matching authorizes an encoded template value that an upstream decodes into another handler, or an empty template capture that a slash-normalizing upstream interprets differently. | Require agreement between encoded and decoded route selection. Refuse decoded separators/delimiters, nested/malformed encoding, dot segments, repeated separators and empty template captures. A native loopback proxy control proves the interpretation difference and zero upstream calls on refusal; spaces, UTF-8 and ordinary escaped values remain usable. |
| RV5 / EV1 paging | A secret-leak deny automatically sends the blocked argument, raw denial reason, guard details and receipt metadata to PagerDuty/OpsGenie. | Automatic paging uses an allowlisted receipt-reference projection and omits raw denial text from summaries. Real HTTP controls retain critical severity, receipt ID and parameter hash while the sentinel is absent from both complete request bodies. |

The archive checks establish unique and complete cursor projections within the
pinned snapshot. They do not cryptographically authenticate the original source
sequence assignments: those fields were never included in checkpoint payload
roots. In-range permutations and stable pagination across adversarial mutations
between separate requests require a different contract. Legacy backfill orders
claims by timestamp, so imposing source-order monotonicity would reject valid
history.

Paging projections are unsigned notification references, not transformed signed
receipts. Existing signed receipts and storage semantics are preserved. General
SIEM exports, erasable argument storage, EV2 retention and EV15 alert signer
admission remain open. Direct caller-constructed `Alert` values remain the
caller's explicit payload; this repair covers automatic receipt-to-alert export.

## Review coverage and disposition

An independent read-only reviewer completed the storage review and then reviewed
all five repair diffs. That review found the unconstrained source/lineage and
empty-capture variants; both were reproduced and repaired. Its final source
verdict found no remaining P0/P1 in the repaired boundaries. It ran no Cargo
commands; runtime qualification belongs to the implementation owner.

Two broader review attempts ended before final verdicts. Their preliminary MCP
and path observations were independently traced and reproduced inline; they are
not counted as completed independent reviews. Inline checks also covered fresh
and recovered Live-mode authority, sender/issuer binding, transport custody,
signed replication, release identity and FROST sealing. No new P0/P1 was accepted
in those additional slices. Existing weak-key hardening in the remote DPoP path
requires a client/issuer-provisioned weak key and was retained as lower-priority
SF4 work, not represented as strong-key impersonation.

The eight historical High findings SR1, PB1, PR1, PR6, TR1, AP1, KG1 and RL1
already have source repairs in the branch and their linked execution records.
TR2's conditional High breaker case also has its October 2 operational repair:
documented unseen results are policy decisions and do not open the failure
circuit, including when an advisory circuit policy is selected.
This review preserves their historical qualification boundaries; it does not
relabel every prior suite as freshly rerun.

## Qualification

Final owner/gate results and source hashes are recorded in the evidence index.
The first focused repair run passed 11 regressions. Follow-up archive/filter and
empty-capture controls then failed against that intermediate patch and drove the
final repairs. Compilation failures in three newly written fixtures, the initial
missing-cosign setup failure, and every failed behavioral run remain in the
command history. Failed runs are not relabeled as passes.

The full SIEM campaign also exposed a stale Splunk timeout assertion expecting
private transport wording. Its correction requires an actual delayed HTTP
request, the bounded client timeout and the current public transport error code;
production timeout behavior was not changed.

The broader owner campaign found stale native fixtures as well. MCP approval
fixtures sent the initialized notification before committing `Ready`; they now
match the HTTP owner's order. SQLite approval fixtures now install their signer
and tenant and bind the exact tool-approval context before signing. Nested DPoP
fixtures explicitly remove the wire proof when testing missing explicit proofs;
a separate wire-only positive control verifies real dispatch and retained replay
custody through both sync and async entrypoints. These are fixture corrections,
not exceptions to production admission. The independent reviewer accepted the
changes and confirmed that the negative assertions retain their intended scope.
The same review accepted two later fixture corrections: bind the threshold
approval's capability and arguments before voting, and give the authority
provenance fixture its required private directory. No admission or file-custody
requirement was weakened to accommodate these fixtures.
The shared store-stamping fixture needed the same private-directory correction.

The complete MCP and SIEM rerun passed: 133 MCP tests and 155 SIEM tests, including
one documentation test. API-protect passed all 255 library tests. The initial
SQLite library campaign finished with 1,930 passed, 15 failed and 3 ignored; all
15 failed tests are present by exact name in passing reruns. Those reruns cover
32 approval/proof cases, all 146 budget cases and all 15 schema cases. The final
retention/export batch passed 20 tests, and the shared threshold lifecycle passed
10 integration tests. The original failed campaign is retained, not described as
a clean all-library rerun. The ignored cases are two scale campaigns and a child
process helper. Detailed source gates and failure mappings are in the evidence
index.

This qualification does not establish hosted CI, native isolation on another
platform, million-receipt performance, a whole-database rollback guarantee,
release publication, deployment or operational acceptance.

## Work boundary

No new roadmap feature or Mercury implementation was added. The withdrawn
Mercury proof-format follow-on is removed from the current queue. Further
execution should begin by prioritizing the remaining original review work,
including broader EV1/EV2 privacy and EV6/EV8/EV17 session certificates, with
their own explicit acceptance boundaries. This review does not declare the
security roadmap or all lower-priority review findings complete.
