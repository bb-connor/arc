# Dynamic delegation: implementation result

The new capability is a reusable native path for forming a work tree and choosing
providers at runtime. It was implemented in the workflow allocator and opt-in
kernel guard, rather than added as another fixed collaboration scenario.
Provider choice can change before sealing. Afterwards, portable evidence binds
the original native operation and can be checked without the allocator online.

## Actual observed behavior

- A second holder subdivides its received slot using its own signature.
- Two SQLite connections racing for insufficient capacity cannot both allocate.
- Provider replacement succeeds before sealing; stale or post-seal changes fail.
- Signed offers bind the complete immutable slot, including acceptance terms.
- A receiver verifies the permit locally, with its own ordinary capability.
  Taking the allocator database offline does not prevent that execution.
- Mutating receiver, request, subject, capability, payload or cost cannot dispatch.
- The exact delivered JSON is checked after transforms. Predicate rejection in
  the qualified accepted-output pricing profile withholds output and gives a
  signed zero-charge denial; replay consumes no additional invocation.
- A real SIGKILL after `ToolReturnRecorded` leaves the original allocation
  unavailable for replacement. A sibling completes before the original recovers.
  Reopening the original receiver returns its result with zero new dispatches.

## Evidence and qualification

Task 1 initially passed 49 workflow tests with one pre-existing ignored doc
example. Portable verification and the full-contract offer regression increased
the workflow total to 51, including 13 delegation tests. The review repair
adds three allocator cases (54 workflow tests, including 16 delegation cases).
The native suite has nine labels: eight substantive tests and one subprocess
helper, including the configured receiver-clock regression. The runnable example exits zero and conserves its 1,000 fixture units.
Both workflow and native focused clippy checks passed.

The final current-source record is `evidence/qualification.json`. It requires
eleven terminal checks: workflow tests, native delegation tests, existing native
three-owner regressions, full swarm/runtime crate tests, three clippy commands,
two format commands, the executable example and artifact tests. The additional
swarm checks cover the [S1 evolution profile](../swarm-evolution/README.md).
Source hashes cover inherited native
inputs as well as the new code. The runner archives old outputs before producing
fresh recovery evidence. The manuscript check verifies this record separately
from the historical funded tree. Review and final qualification status are
recorded in `REVIEW.md`; development success is not hosted or release acceptance.

## Failed evidence retained

`offer-terms-red.log` is a substantive negative result: a receiver's offer could
be transplanted to a same-named slot with different terms. The full slot digest
now binds those terms, and the regression passes. `qualification-red.log` shows
that merely hashing a recovery file did not reject a trajectory with the wrong
cut or another dispatch; semantic validation now rejects it.

The other initial allocator/native logs include absent APIs, compile errors,
strict lock-directory permissions, a nonrecoverable simulated rail, fixture
serialization mistakes and guard-result expectations. Those are development or
fixture failures, not separate scientific discoveries. They remain retained;
later passing outputs do not make the initial campaigns successful.

The fresh review exposed cross-owner subdivision and selection replay even when
full local slot terms matched. Persistent allocator/root/slot digest binding
closes both cases. The native guard now also uses the configured fenced kernel
clock after a regression demonstrated an expired contract being admitted under
a different wall clock. Both failures and passing reruns are retained.

## Scientific judgment

This closes a concrete implementation gap: previous fixed KW1/three-owner
examples did not expose this reusable dynamic operation. It is a coherent kernel
interface worth evaluating. It does not establish a foundational breakthrough.
A competent conventional allocator can implement the same conservation,
portable certificates and native idempotency rules. The earlier SQL/ERC-8183
parity and 4,095-profile conditional-backing parity results remain valid.

The next result that would change the scientific judgment is independently
implemented, useful work with materially less repeated integration under the
same trust, resources and failure obligations. More counts from this local
fixture would not establish that result. The current research package preserves
the hypothesis and provides a concrete interface for that evaluation.

The implemented limits matter: previously qualified keys, finite work trees,
trusted allocator and receiver custody, declared rather than proved information
flow, simple acceptance predicates, no post-seal reclaim, one administrator and
fixture money. Neither a live marketplace nor a fused dynamic on-chain profile
was demonstrated.
