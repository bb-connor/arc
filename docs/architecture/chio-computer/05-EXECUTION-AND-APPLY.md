# C5: Execution observations, joins and exact apply

Status: proposed contract, revision 5. Parent: [Computer proposal](PROPOSAL.md).

## Purpose and owner

Expose a coherent ComputerExecution handle over existing work handles,
receiver-local process roots and resource revisions. Bind accepted results to
a stable ChangeSet and an independently authorized source apply operation.
The facade composes observations; it does not own a replacement effect machine,
acceptance ledger, settlement store or output release authority.

## Execution reference and view

The proposed serializable execution reference identifies the original launch,
candidate revision and authorized work/membership references. It carries no
bearer permit. Reconnection reauthenticates current query access.

Preserve WorkView's six independent observations:

| Dimension | Meaning |
| --- | --- |
| Execution | Original native execution observation, including UnknownEffect where applicable |
| Acceptance | Original contract/procedure/evaluator decision about exact produced work |
| Result references | Authorized references to exact retained artifacts; visibility is not permission to receive bytes |
| Recovery | Existing workflow/operation link and authorized available actions |
| Settlement | Financial owner's observation, or NotApplicable |
| Bilateral delivery | Counterparty delivery observation, separate from production or payment |

Reuse native states and the W1 observation wrapper: NotApplicable, Pending,
Available with owner revision/time, or Unavailable. Do not turn a missing row or
transport failure into a no-effect result. The view is not a global atomic
snapshot, and a child process exiting zero does not create Accepted.

## The hero's join contract

`run.join_tree()` is a proposed convenience operation on ComputerExecution.
Here, tree means the tracked execution family connected by retained work and
local process relationships; it does not make the source owner of foreign
process trees. A local Process handle retains its own narrower tree semantics.

For the initial all-success candidate profile, a successful convenience wait
requires all of the following:

1. Every required stage and admitted dynamic participant is accounted for under
   the exact program/work basis.
2. Existing graph/continuation and receiver-local process owners have committed
   the required closure fences. No member can admit a new relevant descendant
   after it has been counted as closed.
3. Every required local process and work dependency has its accepted terminal
   observation/evidence; unresolved effects that could change the required result
   prevent ready-for-apply success.
4. The resource owner has frozen and sealed an immutable candidate revision, and
   the originally configured evaluator accepted that exact result.
5. The caller can receive the governed ChangeSet reference and required status
   projection. Result bytes, including the diff, require their own current read.

Calling the wait starts observation, not immediate closure. Required stages and
their permitted collaborators must still be able to execute. Producers report
completion through the native owner's completion/admission fence; an unsigned
application claim of being done cannot close its creation scope.

The coordinator tracks immutable graph versions and owner-issued generations.
After required stages and finalizers reach their completion barrier, it obtains
the existing owners' extension/spawn closure fences and reconciles every work
and descendant binding committed through those fences. A child or extension
that wins the race is included and resolved under the admitted completion/drain
policy before success. It succeeds only with complete closure evidence for the
final membership. It cannot close a family by reading children once or by making
a best-effort broadcast. If a graph profile lacks the necessary completion or
close/continuation fence, this join profile is unavailable until that owner
contract is qualified.

Computer-0 therefore requires KERN-3a's capability/process closure and process
exit, plus KERN-3b's KSPEC-04 phase-3 graph tombstones and WORK-D1 DelegationRoot
fences in WORK-W1's canonical serving transactions. Retain their generations in
the normal migration/recovery inventory. A process-tree fence is not a
graph-issuance fence. Sealed permits
that predate closure remain dispatchable under their native contract and must
stay in membership until their required disposition is established. Issuance
closure neither cancels them nor frees their exposure. The caller's admitted
completion policy must authorize the owner closure operations; an observation
handle alone cannot invoke privileged teardown.

This wait does not require all payments to settle or all recipients to receive
bytes. A pending financial rail observation alone does not invalidate an exact
accepted revision. It also does not free retained exposure. A native unknown
effect affecting required result correctness cannot be ignored merely to let
the wait complete.

Structured non-success observations include rejected work, cancelled execution,
unavailable closure evidence, required reconciliation and withheld output.
Returning such an observation does not erase the underlying six-dimensional
view or claim a globally failed payment. Language exception/result spelling is
an SDK choice; the observations and successful-wait predicate are contractual.

## Continuity and control

Client disconnect does not cancel. Event hints cause authorized owner queries;
they cannot prove completion or authorize redispatch. Use original request IDs,
retained responses and stable subscription acknowledgements from KSPEC/REC.

Cancel, revoke and durable stop are distinct actions. Use the existing closure
and drain classifier for each native operation class. Future admission is
fenced; external effects, released information, payable claims and knowledge
history remain. Safety/control paths retain headroom when work exhausts limits.

Explain/approve/resume follow an authorized REC link. A changed continuation
must satisfy existing work allocation/graph binding rules and explicitly link
to the original workflow. No second remedy selection or retry reducer lives
inside ComputerExecution.

## Proposed ChangeSet

Required bindings are the source Computer/resource identities, exact expected
base version, candidate/output version and manifest digest, affected bindings,
producer operation/work references, provenance/labels, and exact acceptance
references. It includes no permission to mutate the source.

`candidate.diff()` and `candidate.changes` resolve this same sealed version;
neither follows a moving head after successful completion. Diff is a current
governed read, including names and errors. Printing it is not human approval.

## Apply protocol

1. Authenticate the source caller and resolve the exact ChangeSet under current
   metadata/content policy. Retain an original apply request identity.
2. Check source/candidate/tenant/resource relationships and expected base.
3. Verify exact producer operation, output and original acceptance contract,
   procedure/evaluator and evidence. Another task's identical bytes cannot
   substitute its acceptance.
4. Recheck current authority, revocation, stop/closure, resource scope,
   confidentiality and the action's required integrity profile. Computer-0
   uses REC's retained labels/influence, current release and exact protected
   acceptance plus the source's qualified action policy. It does not implement
   KSPEC-11 integrity admission. A source requiring that or another unavailable
   endorsement profile refuses apply; successful work acceptance cannot
   downgrade it. Later KSPEC-11 profiles bind the exact apply action and current
   influence/evaluator basis. See the [profile crosswalk](ROADMAP-CROSSWALK.md#qualification-profiles).
5. Publish through the resource owner's commit fence.
   - Under Computer-0 this is a compare-and-swap of the project ref against
     the expected base, on the git-native backend.
   - KSPEC-10 crossing records take over this step when they land after the
     success test.
   - In both cases, the current checks and generation validation must hold at
     the commit point itself, not only during preflight.
6. Recover publication and durable outcome by the original apply identity. A
   lost response cannot cause another apply with substituted material.

Protected `verify` is selected by the original work policy and cannot be edited
by the candidate. Its acceptance predicate is distinct from the source's apply
integrity requirement. Boot hashes alone do not establish trust; confined return
schemas alone do not authorize release or endorse an action.

If the source changed, return a conflict. Rebase/integration creates a new exact
candidate and requires its applicable acceptance/authority. Do not mutate the
old ChangeSet or reinterpret historical evidence using a new evaluator.

The first backend's commit is a managed ref publication on the git-native
backend. Live-directory
materialization is a separate admitted operation with dirty-file checks and a
recovery journal. Multi-owner resources use a qualified commit protocol or
explicit per-resource outcomes. No sequence of file/HTTP/rail writes implies
an atomic transaction across them.

## Evidence

A run evidence manifest references original receipts, producer and acceptance
records, graph/membership/closure evidence, exact resource revisions, applicable
confinement profile, key history and declared witness policy. It does not rewrite
native receipts or infer total completeness from a selected success sample.
Key-history witnesses and receipt-log witnesses have different roles. A signature
identifies accountable evidence; it does not prove arbitrary computation correct.

Acceptance: **C5-01 through C5-11** in [ACCEPTANCE.md](ACCEPTANCE.md).
