# Process integration merge rehearsal

Status: read-only rehearsal completed after the funded-work/M4 integration
commit. No process source was checked out, imported, built or tested here.
The [rehearsal record](16-process-sync-rehearsal.json) retains exact inputs and
[Git output](integration-evidence/process-sync-merge-tree.txt).

## Result

The funded-work integration is committed as
`ae05b4939f94d347eb916bac31d01a5a3afcec42`, with the two reviewed input
histories retained. Its [selected local qualification](14-native-integration-results.md)
includes the final required-DPoP custody repair. Task 3 is complete locally.
Native funding Task 4 has not begun.

The process worktree was clean at
`3b926837372f2a878169671911e613968455f553`. Its committed source extends
Security M4 with durable process hosting and worker/container supervision
repairs. Its remaining integrity and full-foundation qualification gates are
still open in `docs/security/process-security-integration.md` on that branch.
A clean worktree does not close those gates.

The common ancestor is `5d1a9ec0d900bd03ce55de903919d972be852d79`, and the
repository is not shallow. The exact command was:

```bash
git merge-tree --write-tree --messages --name-only \
  ae05b4939f94d347eb916bac31d01a5a3afcec42 \
  3b926837372f2a878169671911e613968455f553
```

Git reported one textual conflict: generated `docs/formal/COVERAGE.md`.
The Rust files, manifests, lockfile, fuzz metadata and formal manifest merged
automatically. The worktree remained clean throughout the rehearsal.

## Semantic review still required

Inspection of the tentative tree found the process branch's joint claim/write
ports in budget authorization, capture, returned-work recording and evaluation
start. Its batched pure-result finalization is also present. The funded-work
outcome-authority module, checked-output verdict module and separate unknown
payment SQL extension remain byte-identical to the qualified funded-work input.
The required-DPoP caller guard is present. These are source observations, not
compilation or behavioral qualification of the tentative tree.

The critical future tests are checked-output denial and zero-charge recovery
through joint finalization, unchanged unknown-payment successor authority,
exact v34-to-v35 migration, and expiry refusals that preserve operation,
participant and commit-chain state. Keep the configured-but-unused credential
controls when reconciling the process review's caller-snapshot finding.

## Execution decision

Continue native funding from the qualified funded-work checkpoint. The optional
process stack is not required for that next slice: the current native/caller
process-loss harnesses are already available.

After the process branch closes its relevant integrity and foundation gates,
refresh both committed heads and repeat the rehearsal. Create a separate sync
candidate, review the automatically merged mutation boundaries, review changed
formal anchors, and regenerate coverage. Run the combined caller/native/flow,
consumer, process, funded-work, SDK and standalone checks, plus the full fuzz
selection required by changed member manifests. Preserve both input histories.
A successful textual merge or the two parents' separate test logs cannot
qualify that combination.

PR #1117 remains a separate draft security integration at the selected M4
commit in the recorded refresh. This rehearsal grants no upstream merge,
hosted deployment, public-chain finality or live-funding qualification.
