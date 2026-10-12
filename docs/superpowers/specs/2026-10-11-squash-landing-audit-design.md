# Squash landing audit

The owner selected squash support through the Claude coordination session
(`2026-10-11T23:45:28Z`). This changes the accepted commit shape, while retaining
the auditor's existing qualification and failure requirements. It cannot make
the incomplete #1160 qualification pass.

## Accepted shapes

Let `P` be the merged commit, `E` the exact PR head, `B` the recorded qualified
base and `T` the qualified tree. Select the shape by `P`'s actual parent count.

- Two parents: retain the existing ordered `[B, E]` requirement.
- One parent: require `[B]`, `P != E`, the exact GitHub commit identity for `E`,
  and `tree(P) == tree(E) == T`. The GitHub comparison `B...E` must be strictly
  ahead, with zero commits behind and merge base exactly `B`.
- Reject every other parent count. A failed shape check cannot fall back to
  the other shape or to a locally computed merge tree.

The existing dedicated App identity must still bind the same repository, PR
number, `B`, `E`, `T`, authorized source and trusted definition. The existing
authenticated test merge still has ordered parents `[B, E]` and tree `T`.
Use these recorded values, not the mutable post-merge PR base.

Every existing CI history, original check, artifact, attempt, timestamp,
namespace and finalizer requirement remains. The final commit-to-PR lookup
must uniquely attribute `P` to the audited PR; final PR identity and main
reachability are rechecked. Commit messages and authors are not authority.
The auditor describes observed attribution; it does not establish historical
ruleset enforcement or infer bypass from an unsuccessful audit.

## Implementation boundary

Change `scripts/audit-security-merge-qualification.py`, its owning offline
tests and the existing auditor digest in `check-security-ci-contract.py`.
Return the actual parent vector and an explicit landing shape. Render that
shape accurately in Markdown. Keep the compatible REST API pin established
by the separate API repair.

No workflow permission, repository variable, source authorization, evidence
publication or proof campaign changes are included. Aligning any future
exception policy with the auditor's all-attempts-success rule is separate.

## Acceptance

A healthy squash fixture must fail against the original two-parent auditor
and pass after the repair. Retain a healthy two-parent control. Refuse wrong
tree, wrong E lookup, behind or unrelated base, mismatched recorded base,
`P == E`, zero or more than two parents, unmerged or changing PR identity,
same-tree sibling attribution, and incomplete, failed or late qualification.
Run the full existing audit suite and security contract controls. Obtain
independent source review before publication. No historical failed run is
relabelled by this work.
