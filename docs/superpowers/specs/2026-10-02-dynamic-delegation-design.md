# Dynamic delegation with durable allocations

`chio-workflow::delegation` lets one resource owner hand out bounded work and
lets holders subdivide it at runtime. Each allocation carries an effect set, a
reader set, a budget ceiling, an expiry, a remaining depth and an acceptance
predicate. A receiving kernel verifies a sealed permit locally. Ordinary native
capabilities still authorize the call; the allocation is evidence, never an
alternate certificate authority.

## Contract and authority

An owner creates a root slot for an authenticated holder through trusted
configuration (`DelegationStore::create_root`). A slot contains an identifier,
the holder public key, a set of exact server/tool effects, permitted reader
identifiers, an integer budget in one currency, an absolute expiry, a remaining
delegation depth and an acceptance predicate. A slot is either a container of
children or a dispatchable leaf.

Subdividing commits the child's entire budget from its parent; unused capacity
is never reclaimed. Child effects and readers are subsets of the parent's,
expiry cannot increase and depth must decrease. A child may carry its own
acceptance predicate, so its success is not proof of the parent's result. The
parent's predicate is immutable.

Holders sign subdivision and selection requests. A receiving kernel signs its
offer over the exact slot, input digest, effect, price, slot digest and validity
interval. An explicit, locally configured receiver allowlist qualifies
providers; discovery grants no authority. A selection binds a qualified offer to
a receiver-issued capability digest and request ID, and a holder cannot select a
provider for another holder's slot.

Signed bodies use domain-separated RFC 8785 canonical JSON under the
`chio.work-subdivision.v1`, `chio.work-offer.v1`, `chio.work-selection.v1` and
`chio.work-dispatch-permit.v1` domains. Every subdivision, offer, selection and
permit binds the allocation digest, which commits a persistent random allocator
namespace plus the complete immutable root and slot. Two allocators with equal
local slot names therefore never share signed consent.

## Durable state and transitions

`DelegationStore` is a SQLite allocator scoped to one resource owner and part of
that owner's trusted boundary. Its database carries one v1 schema: an empty file
is created and stamped, a file stamped at another version is refused with
`StaleSchema`, and a populated unstamped file is refused as foreign.

- `subdivide`: an authenticated holder adds an immutable child under an open
  slot. Atomic allocation rejects sibling overcommit and integer overflow. A
  selected slot cannot be subdivided.
- `select`: the holder binds a qualified signed offer and the exact native
  request and capability. Before sealing, the holder may select a replacement.
- `claim_dispatch`: the allocator marks the selected leaf dispatched for a
  receiver that consults it directly. A container cannot be dispatched.
- `seal_dispatch`: the allocator locks the selected binding and persists a
  signed permit in one commit. Sealing forbids replacement, and a retry returns
  the original permit bytes.

There is no reset, timeout refund or release of sealed allocations. Capacity
stays committed from sealing onward, even when no receiver executes. Native
durable admission owns operation replay and recovery. Immediate SQLite
transactions serialize sibling allocation and selection against sealing, across
connections and processes. Every mutation validates the supplied trusted time
against current expiry.

## Receiver verification

`verify_dispatch_permit` checks a permit against locally configured allocator
keys without the allocator database. It requires the request, capability, input
digest, effect and receiver bound by the selection, keeps the price within the
slot budget, and rejects an expired slot or offer. Revalidating the same
binding is idempotent.

## Acceptance language

`Acceptance` holds 1 to 16 clauses that must all hold. A clause is exact JSON
equality at a valid JSON pointer or an inclusive signed-integer range. Contracts
validate at load, and the checker runs no code and makes no network call. It
checks the agreed predicate, not general usefulness or hidden effects.

## Limits

The wire profile caps numbers at 2^53-1, depth at 32, effects at 64, readers at
256, children per slot at 64, slots per root at 4096 and each signed envelope at
65,536 bytes. Qualified providers must belong to the slot's reader set.

## Invariants

Local subset and depth checks keep every descendant's effects, readers and
lifetime within each ancestor. Atomic sibling allocation and the ban on
dispatching containers keep the sum of leaf ceilings at or below the root
budget. Immutable dispatch bindings preserve earlier obligations when new
children or providers appear. These invariants hold for this restricted
protocol only; they are not a general composition theorem.
