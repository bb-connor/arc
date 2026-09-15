# Code this paper's claims require, and who can write it

The paper states what the system should do. Where the code does not yet do it,
the gap is a work item, not a reason to weaken the paper. Five of these are
being built now. Three sit inside files another team owns on
`origin/security/launch-integration`, so they are specified here precisely
enough to be picked up without rediscovery.

## Owned elsewhere, specified here

### 1. The deciding component must resolve the intervals it enforces

**Claim the paper makes.** The window in which a statement can be presented is
the intersection of the lease, governance, and continuation intervals the
receiver itself resolved, each revocable and re-scoped per counterparty between
calls.

**What the code does.** The pre-dispatch hook resolves six artifact kinds and
none is a lease or a governance record. The only lease fact it holds is the
expiry the two co-signers wrote into the statement, denied only when it is at
or before the clock. That is a lower bound authored by the signers, not an
upper bound owned by the receiver. No governance interval exists on the path at
all. The conforming verifier does resolve both, which is why the two deciders
disagree about how long a statement is good for.

**What to build.** Give the hook the same two resolutions the verifier has:
look the lease up in the receiver's own registry by its identifier and take its
interval from the stored record rather than from the statement, and resolve the
governance record for a receipt-backed class and take its interval likewise.
Then compute the presentation window as the intersection of those two with the
continuation's, and deny outside it. The seam is typed and ready from the
comparison side; what is needed is the store access.

**Files.** `crates/kernel/chio-runtime-core/src/admission_hook/treaty_evidence.rs`
for the resolution, `crates/kernel/chio-runtime-core/src/admission_hook/store_artifacts.rs`
for the store trait, and `crates/kernel/chio-runtime-core/src/store/memory.rs` for
the in-memory implementation. All three are on the security branch.

**Why it is worth doing.** It closes the only substantive behavioural gap
between the conforming verifier and the component that decides live calls, and
it turns a signer-authored bound into a receiver-owned one, which is the whole
thesis of the paper applied to one more field.

### 2. A denial is a decision, so it should carry a co-signature too

**Claim the paper makes.** The reference kernel mints the outbound co-signature
on every federated request and fails the response when it cannot.

**What the code does.** A federated request whose receipt is a denial carrying
no verified treaty material returns without minting anything, and without
failing the response.

**What to build.** Mint the outbound statement for denials as well as allows.
The paper's own principle is that a denial is a receipt of the same shape,
built and signed and persisted on the same path as an allow, and the same
reasoning applies one level up: a peer that is told no should be able to prove
it was told no. Where there is no verified treaty material the statement cannot
carry a binding reference, so define what a denial's statement binds, most
likely the request digest, the agreement, and the failure code, and make that
shape explicit rather than absent.

**File.** `crates/kernel/chio-kernel/src/kernel/construction.rs`, on the
security branch, around the federation co-sign application.

### 3. A release is attempted for a hold the store has no record of

**What was observed.** In the cross-organization run, the retained revocation
records carry `budget state invariant violated: missing budget hold` on the
pre-dispatch release path. The paper had been reading those records as the
designed ambiguous-release path; they are not, they are an invariant violation.

**What to build.** Diagnose it. A release keyed by an admission that has no
hold is either a release running twice, a hold that was never taken on a path
that assumes it was, or an ordering problem between the hold and the record
that names it. Whichever it is, the fix should make the invariant hold rather
than make the message quieter, and the designed ambiguous-release path should
then be exercised by a test so the paper can cite it truthfully.

**File.** `crates/kernel/chio-kernel/src/kernel/evaluation/evaluation_helpers.rs`,
on the security branch, where the message is emitted.

## Being built now

| Claim | What is being built |
| --- | --- |
| Refused key names are refused wherever they appear | A scan at any depth, in objects and arrays, with a bound |
| Every denial leaves the dispatch counter at zero | The corpus driven through a path that has a counter |
| The path was held at saturation | A generator that holds many admissions in flight, with a concurrency sweep and a named bottleneck |
| Every interval is an interval for the median beside it | The intervals emitted and printed |
| A composition of existing parts has no carrier for what a receiver binds | The composed request rebuilt out of schemas this project did not author, each cited |

The last of those is the one that matters most. The claim was destroyed because
the composed alternative's request schema was ours, so its limits were our
choice. Grounded in formats designed elsewhere for other jobs, the same
sentence becomes a fact about those formats.
