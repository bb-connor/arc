# Native funding integration gate

Refreshed 2026-09-14 during the claim-escrow execution. The independent model,
contract, trace replay and financial reproduction are implemented. Native
funding admission remains gated on qualification of the combined source.

## Qualified local integration checkpoint

Security M4 now has a clean, committed local acceptance checkpoint at
`5d1a9ec0d900bd03ce55de903919d972be852d79`. Its local, remote and draft
PR #1117 heads matched when selected on 2026-09-14. The report closes the
required local M4 gates. The full hosted serial/MSRV lane remains unqualified;
this is not upstream merge or release approval.

The separate `integration/funded-work-m4` candidate starts at that checkpoint
and merges research `926e1aa8411e3b516fe737988dd1a0989c447d08`. Both input
worktrees remain separate. The exact rehearsal found nine code conflicts and
one generated coverage conflict. A fresh native provisioning baseline passed
before Rust edits. The [integration plan](../../../superpowers/plans/2026-09-14-funded-work-m4-integration.md)
records the selected test profile and required gates.

The candidate preserves authenticated return binding and caller release checks,
retains checked work before evaluation, and uses a separate native schema v35
extension for monetary successors. Security's v34 base SQL stays byte-identical.
The migration validates the exact old catalog and retained data, preserves
original operation and commit bytes, and rejects pre-v35 release namespaces.
Research's incompatible v10 database is not an automatic migration source.
The global commit catalog adds the payment-resolution kind without rewriting
prior row digests. The provider now constructs its A2A edge through a signed
manifest and the configured publisher pin, with an explicit public-only local
policy for this example profile.

The selected native, caller, consumer, flow and standalone regressions plus
combined-source checks passed on this candidate. Task 3 closes with the reviewed
local commit and retained evidence. Prior research evidence and M4 local
acceptance remain separate records. Task 4 has not begun.

The [combined-source report](14-native-integration-results.md) and
[evidence manifest](15-native-integration-evidence.json) record current local
results. Authenticated caller, native restart, standalone process, runtime,
workspace compilation/Clippy, formal, Rust consumer and full flow-security
gates have passed. This checkpoint qualifies the selected local integration;
full hosted and upstream qualification remain separate.

## Historical refresh after complete lifecycle recovery

At 2026-09-14 14:36 UTC, the security worktree still identifies
`f1b88451527b2dec7314114b3b1e91cf101312cf`. Its acceptance report now says
all required local execution gates, documentation review and source-graph
refresh passed. This is progress beyond the previous status below. Five
closeout documentation files remain modified, and the report says hosted MSRV
qualification is still running with its prior failure unresolved. These are
reported local results, not native suites rerun by this work.

Draft PR #1117 remains open, draft and blocked at
`6bb648b613b44ff5aaf1853768f2747bff166077`. No committed M4 closeout was
selected. A fresh read-only merge-tree of security `f1b8845152` and research
`331bd1bf8c` has 10 conflicts: nine code paths plus generated
`docs/formal/COVERAGE.md`. The merge base is `f5566d9a765c21cb36652a99c79de64968a656bf`
and the repository is not shallow. This rehearsal excludes dirty security
documentation and does not resolve, build or qualify a combined candidate.

The [lifecycle result](12-lifecycle-recovery-results.md) and
[manifest](13-lifecycle-results.json) retain the exact heads, conflict paths,
source hashes and gate observation. Admission versions are still research 10
and security 34, with distinct historical version-10 meanings. The existing
provider's unsigned manifest construction still differs from security's
`VerifiedManifestRegistry` constructor. These semantic requirements remain even
where Git reports no textual conflict.

All post-funding private-chain actions now use durable worker recovery:
submission, decision, payment and refund pass the full four-point crash matrix.
Funding/deployment/setup, native admission/hold correlation, Finding facets,
public finality and actual parent tool-process loss remain pending. Preserve
the qualified security lifecycle and the paper's separately authorized unknown
payment successor together when creating the isolated integration candidate.

## Previous refresh after rail-worker recovery

At 2026-09-14 13:13 UTC, the security worktree identifies
`f1b88451527b2dec7314114b3b1e91cf101312cf`, with its M4 acceptance report
modified. Draft [PR #1117](https://github.com/bb-connor/arc/pull/1117) still
identifies `6bb648b613b44ff5aaf1853768f2747bff166077`; it is open, draft
and blocked. The acceptance report explicitly states that M4 cannot close on
current evidence. The local source is therefore neither the PR head nor a
selected qualified checkpoint. This was a read-only refresh, not a hosted-check
or review-thread audit. Exact observations and report hash are in the
[recovery manifest](11-recovery-results.json).

The independent [funded W0 result](08-funded-w0-results.md) supplies actual
Rust-produced work, Python artifact verification, local SQLite custody and
canonical-digest EVM authorization. The subsequent
[recovery result](10-recovery-review-results.md) adds immutable signed-transaction
retention and actual rail-worker SIGKILL/restart. One payment survives four
interruption points, including an earned child after parent refund. These
results use one host, mock tokens and trusted private-chain observations.

Native admission, original native hold correlation, Finding facets, public
finality and parent tool-process loss remain pending. No integration base was
selected or merge attempted. The earlier funded W0 refresh observed matching
clean local/PR head `6bb648b613b44ff5aaf1853768f2747bff166077`; that is
historical evidence preserved in [its report](08-funded-w0-results.md).

## Earlier observed source

Draft [PR #1117](https://github.com/bb-connor/arc/pull/1117) is open and blocked,
head `8738bdfd7be8c43a0543ca0ce468541529c47add`, base
`f5566d9a765c21cb36652a99c79de64968a656bf`. The active worktree
`/tmp/arc-security-launch` has that same head, five modified documentation
files and one untracked M4 acceptance report. This work did not edit it.

Its acceptance report states that final qualification is in progress and M4
cannot close on current evidence. Earlier green checks preceded source repairs
and cannot qualify the repaired candidate. The observed PR JSON, report opening
and three report hashes are retained in the [execution manifest](07-claim-results.json).
This is a status refresh, not a new audit of hosted checks or review threads.

No qualified M4 checkpoint was selected, no integration worktree was created,
and no paper/security merge or populated-store migration was attempted.
The [prior sync review](../09-security-roadmap-sync-review.md) remains the
source-backed map; its historical conflict counts are not represented as a
fresh merge rehearsal here.

## Work ready to integrate once the gate passes

The research branch preserves paper inputs in `ec9189e79c5` and the two
dependency fixtures in `905583e951b`. The first execution closeout is
`56db3b0751`. The subsequent model and experimental contract commits add no
native Rust or existing-escrow semantic changes. Their selected source hashes,
tests, ABI vector and direct financial observations travel with the candidate.

The eventual integrated source must preserve these contracts together:

| Boundary | Required integration decision and evidence |
| --- | --- |
| Schema lineage | Map actual research version-10 layout to security's distinct historical version 10 and current version 34. Fingerprint predecessors, preserve original records and reject unsupported migrations |
| Caller delivery | Commit and read back the original start before effect; retain executor claims and signed reports; accept eligible late reports without re-admission |
| Financial successor | Reconcile rail effects to the original hold; preserve execution-unknown and its authorized financial successor; never fabricate old custody or charge twice |
| Manifest/session | Construct A2A through verified manifests and restore the negotiated profile; do not import unsigned manifests or upgrade sessions implicitly |
| Claim admission | Verify exact agreement, allocation, deployment/code, token, recipient and finality before native dispatch; payer-supplied summaries are insufficient |
| Acceptance/custody | Bind real W0 input, output, checker, required Finding facets and retained custody before signing a positive work decision |
| Retention | Fail closed before the 64-operation executor limit; do not evict claims, unknown effects or occupied nonces to fit a trial |
| Qualification | Run the affected authenticated-caller, native-restart, consumer, SDK-parity and flow inventories plus explicit standalone example suites; then required combined-source checks |

Optional process hosting remains a separate selection. Its open PR and ordinary
host evidence do not automatically qualify enforced flow. Legacy #1029 is not
the integration base. The experimental escrow's new-funding pause is distinct
from native output release and does not substitute for those security contracts.

## Next executable gate

Begin Task 4 with the strict experimental allocation encoding and a funding
observer whose deployment, agreement, chain and finality pins belong to the
receiver. Prove that unfinalized, mismatched and reused allocations deny before
reservation or dispatch, then correlate the accepted allocation with the
original native operation and hold. The interface review in the combined-source
report records why the legacy channel event decoder cannot stand in for this
claim allocation. A later process-runtime sync requires its own committed,
qualified candidate and a fresh merge rehearsal.

The independent demos now supply actual checked artifacts, local custody and
rail-worker recovery for an earned child claim. They do not supply independent
verifier custody, native funded admission, actual parent tool-process loss,
public-chain finality or independently operated companies. Those remain the
concrete boundaries of the native vertical slice.
