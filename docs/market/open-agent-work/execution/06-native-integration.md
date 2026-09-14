# Native funding integration gate

Refreshed 2026-09-14 during the claim-escrow execution. The independent model,
contract, trace replay and financial reproduction are implemented. Native
funding admission remains gated on a qualified Security M4 source.

## Observed source

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

Refresh the other agent's committed M4 closeout and exact source evidence.
Create a separate integration candidate from that checkpoint, then forward-port
the paper behavior in reviewable slices. Only after that candidate's selected
regressions pass should Task 4 connect finalized funding to one actual native
W0 admission and its crash/recovery paths.

The contract-only demo supplies the financial child-claim behavior for that
integration. It does not yet supply independent verifier custody, native work,
an actual parent process loss, public-chain finality or independently operated
companies. Those are the concrete remaining boundaries of this vertical slice.
