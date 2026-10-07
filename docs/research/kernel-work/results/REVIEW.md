# Tasks 2-4 final review and disposition

Fresh automated reviewer: `kernel_tasks234_review` (separate context).
Reviewed range: `6c12e3b62cc999d7338dfc85760dd1e8f46bfa54` through
`f8c67dfe678b205fca4d60e7840e536e2a23abac`.

The reviewer independently ran all 36 tests and the retained-artifact verifier.
It accepted the narrowed G1 decision and the bounded/no-theorem scope. It found
two Important defects despite those green checks and declined Task 4 completion
at the reviewed SHA. There were no Critical findings or separate Minor fixes.

| Finding and reproduction | Executor disposition and regression |
| --- | --- |
| `F01_exact`, revoke `read`, try `ReadResult`, then a fully owner-covered generic result release: native read denied but generic release allowed | Accepted Important. Both candidate and B1 now require current audience permission for the generic result channel. `F07_result_release_permission` checks both denials, then useful release after reauthorization. |
| `F05_true`, then independently approve op1 but finalize with op0's issuance 11/envelope 21: two operations consume/send under reused original identity | Accepted Important. Both decision implementations independently enforce unique ownership of each issuance and finalized envelope within the modeled local authority domain. `F04_unknown_{both,issuance,envelope,distinct}` and `F04_closed_gc_{both,issuance,envelope,distinct}` cover collisions and legitimate distinct identities after refund/uncertainty or completed GC, with restart in both paths. |

[review-red.log](model/review-red.log) and [exit record](model/review-red.json)
show the four failing family/arm tests before the fix. All nine added variants
run under both arms. The one correction pass also added independent identity
uniqueness assertions and two exploration alphabets for cross-operation identity
and result audience changes. [review-green.log](model/review-green.log) and its
[exit record](model/review-green.json) show the complete 36-test suite passing
afterward. The final [verification record](model/verification.json) covers all
changed sources, formatting, Clippy, explorer and provenance. No second fresh
review or human scientific endorsement is claimed.

## Explicitly scoped-out judgments

The executor accepts the reviewer's following boundaries, and keeps them visible
in [G2](G2.md):

- Native cryptography, exact byte custody, durable stores, real crashes and
  independently administered participants are supplied assumptions or Task 5 work.
- Arbitrary-trace composition/noninterference, dynamic DAGs and production
  decoding/allocation bounds are outside KW1's finite executable scope.
- Integration-time advantage, independent operation and generality require the
  preregistered later study; no symbolic test can substitute for it.
- False first authoritative E1 outcomes violate the stated qualified-provider
  truth premise; the filter count and terminal-conflict robustness are explicit.
- Generic release version 1 and publication `Change(bytes=2)` are distinct
  artifact/action abstractions. MODEL and the lab README now say so explicitly.
  This lab does not establish their shared-source binding. That exact binding is
  a concrete obligation for the later native/adapter correspondence task.

The executor's completion judgment is limited to Tasks 2-4's model, research
choice and corrected finite experiment. The publication and breakthrough claims
remain unestablished, with the manuscript frozen. Final source/artifact hashes
and task completion appear in G2 and the plan's acceptance record.
