# C4: Binding a computer to admitted work

Status: proposed contract, revision 2. Parent: [Computer proposal](PROPOSAL.md).

## Purpose and owner

Bind an exact Computer image to the existing work commitment, receiver-local
process admission, governed input transfer, and accepted result. Use completed
WORK/COOP/HOST/SHARE contracts and their actual services. An ExecutionBinding is
a checked relationship among retained records, not a new signed capability or
independent effect journal.

## Two authority profiles

| Profile | Ownership |
| --- | --- |
| Same domain, another host | Existing authority can own the process family; the remote host supplies a qualified placement and local launch enforcement. |
| Independent organizations | Source owns its resources/revisions; receiver issues its own local authority and owns its process tree. Co-signed work binds their obligations and evidence. |

The second profile is part of the initial architecture and its complete
acceptance demonstration. Computer must not assume a common key, database,
operator, issuer, physical host, or globally controlled process tree.

`ProcessRuntime::create_root` rejects an incoming delegated chain. Do not strip
that chain, clone the issuer, or mint an unlimited substitute to run foreign
work. The receiver's offer/local capability and the retained work agreement
provide the already planned independent-authority relationship.

## Required bindings

The retained relationship identifies:

- original preparation/launch request and ComputerExecution references;
- source owner/domain, candidate revision, namespace/resource generations;
- exact boot expression, bundles, input manifest and selected profile basis;
- source resource authority references and intended receiver identity;
- receiver work handle, local offer/capability and process/attempt mappings;
- original work contract, allocation/selection/dispatch permit, graph basis,
  acceptance procedure/evaluator and agreement;
- consumption family/hold or delegated exposure binding and optional funding;
- transfer/release profile, host/confinement evidence and provider context;
- original owner operation references and final producer/result evidence.

Only audience-safe references cross general query surfaces. Actual credentials,
approval material and private invocation bytes use their existing protected
custody and authorized transfer. A remote reference never authorizes an arbitrary
fetch, secret export or capability import.

## Admission sequence

1. Resolve configured peer identity and exact supported work/host profiles.
   Authenticate transport and the work principal independently; verify current
   partner key history/status and federated proof of possession as required.
2. Retain a launch preparation under an original request identity and atomically
   claim the candidate's execution family. A disconnect before a handle is
   returned is recoverable by that identity.
3. Freeze the launch revision/program/input/resource basis. Admit any required
   branch storage and input export independently through their actual owners.
4. Use the existing WorkService preparation order: allocation and receiver
   offer/local capability, selection/seal, graph/treaty context, exact invocation
   custody, agreement, verified funding/reserve if required, then submit.
   Resolve profile-specific approvals before freezing their dependent request.
5. Before dispatch, recheck source rights, receiver consent, program restrictions,
   current authority predicates, supported enforcement and consumption backing.
   Initial grants bind the candidate's permitted boot/revision and one execution
   family; a changed direct expression cannot evade an exact boot restriction.
6. Transfer only authorized missing content, or use the admitted source branch
   service. Artifact publication and first release obey REC. Verify actual host
   enforcement before exposing inputs that require confinement.
7. Receiver-local admission establishes processes and fenced attempts. Retain
   their binding to the original work. A late/stale worker cannot publish results
   after reassignment or generation change.
8. Seal producer results, run the original acceptance procedure, and transfer or
   import results only through current release/resource admission. Source apply
   remains a separate operation under [C5](05-EXECUTION-AND-APPLY.md).

These steps describe dependencies, not a distributed transaction. Coordination
records keep preparation/owner references; native services retain truth about
issuance, holds, dispatch, recovery and release. Retrying a step reconciles those
references before attempting a permitted continuation. Partial progress does not
justify blanket rollback, refund, new operation identity or duplicate dispatch.

Use HTTPS with mTLS or signed bodies as CT-CROSS specifies; self-hosted iroh is
optional. Reuse W1/W2 work service routes and qualified host seams. A Unix worker
listener cannot become the remote protocol just by exposing it over TCP.

## Consumption and funding

The SHARE kernel hold ledger remains the sole consumption authority within its
qualified scope. D1 allocations, S1 commitments and other counters retain their
roles as commitments or views. Computer stores references, not another mutable
balance. Each charged operation must bind the actual consumption owner.

The hero's grant bounds admitted work using that grant, including descendants,
integration and verification. Fork/issuance and source apply use their own
authority and accounting. A cap does not promise a useful result within $5.

`expires_in` resolves against the issuing owner's qualified time contract.
Descendant expiry cannot exceed its ancestor, and reconnect/recovery cannot
restart the clock. Expiry denies future governed commitments; actual CPU/process
termination follows the admitted host deadline/control profile. Already sent
effects and retained reservations remain accountable. Reconciliation and later
source reads require their own currently valid authority, not revived work rights.
`delegable=True` permits only the admitted attenuation/depth path; it does not
give application code signing custody or let a foreign issuer extend source rights.

Model profiles reserve worst-case exposure before dispatch and reconcile down
after a known outcome. Unknown replies retain exposure. Token quotas, money,
CPU/process/storage/byte/concurrency limits and wall deadlines are distinct.
Do not silently bypass the broker, switch accounts/routes, or advertise a dollar
cap where the provider cannot bound the relevant cost.

The completed roadmap includes sender-funded cross-organization holds. The
selected profile must establish either admission through its designated
consumption owner or a durably reserved bounded suballocation whose outstanding
exposure remains counted at the parent. The exact inter-owner protocol remains
that program's contract; this proposal does not invent a universal wallet or
claim a transaction across two hold stores. Without a qualified binding the
corresponding remote monetary profile is unavailable.

Partition, lease expiry, lost replies or parent cancellation cannot alone free
outstanding foreign exposure. Independent receiver charges cannot be assumed
covered by the source cap unless the agreement/profile binds them to it. Work
may have an unpaid agreement and still use priced model resources. Actual
funding, committed exposure, spending permission and settlement remain separate.
Payable accepted child work survives parent failure or rejection of a patch.

## Laws

- **EXE-01:** both authority profiles preserve their issuer/process ownership.
- **EXE-02:** source permission and receiver consent are independently necessary.
- **EXE-03:** replay recovers the exact original bindings and cannot change code,
  input, recipient, resource/profile generations or sealed selection.
- **EXE-04:** native consumption includes all admitted relevant descendants;
  restart, fork, new handles and provider sessions cannot replenish it.
- **EXE-05:** private inputs and results cross only after current release checks;
  acceptance, signatures and settlement are not release authority.
- **EXE-06:** stop/revocation/closure fence future commitments; already dispatched
  effects and stranded exposure retain their native dispositions.
- **EXE-07:** a changed request uses a separately admitted linked continuation
  within existing limits. Uncertain work cannot be retried as new work to evade
  the unresolved-effect rule.

Acceptance: **C4-01 through C4-08** in [ACCEPTANCE.md](ACCEPTANCE.md).
