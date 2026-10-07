# Sovereign swarm evolution

Status: implementation design, 2026-10-02.

## Intent and authorization

The user approved the architectural direction: independently owned systems
compose into useful, evolving programs while owners retain enforceable control.
They explicitly requested a concrete plan, implementation, review, and manuscript
update, emphasizing reuse of existing swarm authority, treaties, and delegation.
This design makes the first missing runtime connection concrete. It does not
declare the broader scientific breakthrough established.

## Existing machinery and the missing connection

| Responsibility | Existing implementation | Decision |
| --- | --- | --- |
| Recursive graph, attenuation, signed witnesses, routes, joins, revocation | `chio-swarm-authority` verifier | Reuse unchanged authority checks |
| Receiver-selected treaty material and bilateral admission | `chio-runtime-core` admission hook and `chio-federation` | Keep as independent required dispatch gates |
| Native one-use continuation ownership and crash history | Kernel operation-owned runtime participant | Reuse; never reset or recreate consumed identities |
| Editable provider selection before dispatch | `chio-workflow::delegation` selection revision and sealing | Retain existing API |
| Swarm artifact storage | SQLite `runtime_swarm_authority_bundles` | Currently rejects any different bundle with the same graph ID |
| Historical artifact lookup | Current graph ID only | Add lookup by the existing signed graph digest |

The present immutable-store rule is sensible for replay safety, but prevents a
running swarm from extending its plan. Creating an unrelated graph would fail to
express which earlier tasks and allocations must survive. The change is a
checked, atomic extension of an existing graph, retaining old versions for exact
historical request verification.

## Alternatives and choice

1. **Extend existing swarm artifacts and their runtime store (selected).** Reuses
   graph and witness semantics and reaches the native admission path.
2. Build a general new collaboration language. This would duplicate current
   authority and contract representations before their integration is complete.
3. Replace the immutable bundle in place. This loses the evidence required to
   revalidate earlier operation-owned claims and enables competing rewrites.

## Extension contract

`verify_swarm_authority_extension(previous, candidate, trusted_keys, now)` uses
the existing live-admission verifier for both bundles at caller-owned time.
Neither supplied `nowUnixMs` is authoritative. It accepts only strict graph
growth within the originally installed envelope:

- Graph ID, issuer, planner, root transaction, creation/expiry times, maximum
  depth/fanout, witness mode, pool and revocation references remain identical.
- Every existing node, edge, join definition, route reference, route artifact,
  witness chain, join receipt, and allocation remains identical.
- Pool identity, currency, and total units remain identical. Existing checked
  accounting bounds all old and new allocation ceilings by that total.
- Every existing continuation retains its ID, nonce, scope/witness/route/budget
  references, parent evidence, issuer, mode, and lifetime. Only its graph digest
  and signature change to bind the extended graph.
- Every continuation is single-use, and at most one continuation names each
  task or allocation. An extension never creates another attempt for an issued
  task. New allocations belong to new tasks, one allocation per task.
- The revocation epoch remains identical. This extension API cannot undo a
  revocation or perform a constitutional amendment.
- A terminal parent cannot grow. The candidate adds at least one node and has
  no terminal receipt; completion evidence is a separate lifecycle operation.

The return value is the ordinary verified candidate report. There is no new
signature scheme, invocation capability, or replacement budget representation.

## Durable installation and artifact identity

Add `SqliteRuntimeOrchestrationStore::extend_swarm_authority_bundle` taking an
expected full parent bundle digest, a signed candidate, and locally configured
witness keys. In one immediate SQLite transaction it loads the protected parent,
checks its stored digest, compares the expected digest, verifies the extension
using the store clock, archives the exact old version, and updates the head.
Competing proposals from one parent cannot both commit. Errors leave both head
and history unchanged. The API requires an already provisioned graph; it cannot
register a root or change trust roots.

The archive keys versions by `(graph_id, signed_graph_sha256)` and stores the
complete bundle and digest. A strict node addition changes the graph digest.
Hash and index bindings are checked on every historical load. Existing
`insert_swarm_authority_bundle` retains its immutable/idempotent behavior.

Add `RuntimeAdmissionStore::swarm_authority_bundle_for_graph` with a compatible
default forwarding to existing lookup. SQLite and layered stores implement exact
historical resolution. The admission hook supplies the graph digest already in
the request's swarm reference. No new caller-controlled bypass or wire field is
introduced. Unknown hashes still fail the ordinary reference binding checks.

## Execution and concurrency semantics

Previously issued work stays valid under its original artifacts and normal
freshness/revocation checks. This is deliberately additive: it does not retire
old permissions or reclaim their budgets. Earlier native custody remains the
authority for replay, uncertainty, and recovery. A rebound continuation in a new
graph keeps its old identity, so native custody cannot treat it as fresh work.
New tasks dispatch through the normal capability and treaty gates.

Safety of concurrent dispatch and extension follows from retention: either
graph version reserves the same original allocations and continuation identities.
Only installation needs a per-graph linearization point; no global coordinator
is added. Existing trusted SQLite ownership and native source activation remain
requirements. Admission through an alternate independently provisioned store is
not prevented by a local database transaction.

## Acceptance and claim boundary

1. A one-worker live bundle grows into the existing two-worker bundle using the
   original signatures, witnesses, and route schema. Both ordinary verifiers run.
2. Rewriting old tasks, allocations, continuations, policy envelope, or epoch,
   exceeding budget, stale evidence, and untrusted signing all reject.
3. Two concurrent proposals yield one installed successor. Reopening preserves
   exact parent and successor evidence. Malformed history rejects.
4. Native dispatch executes an original task, installs an extension, executes
   the added task, and replays the original result without a second invocation.
   A previously issued but unfinished task can still use its original evidence.
   Rebinding a used continuation does not produce another effect.
5. Existing combined treaty/swarm operation-owned regressions pass. A targeted
   combined case verifies that historical swarm resolution leaves treaty
   admission and original physical custody intact.
6. Review, source-bound test evidence, and a rebuilt manuscript explain the
   additive result and the remaining broader research questions.

This is conservation of declared swarm allocations and authority identities,
not proof of funded money, arbitrary task correctness, end-to-end information
flow, autonomous trust enrollment, or arbitrary policy changes. The user-supplied
full recovery baseline remains assumed shipped for research. This implementation
does not substitute fixture observations for independent operators.

## Self-review

The additive profile avoids a dispatch-versus-revocation race introduced by
in-place mutation. Historical artifacts cannot mint fresh continuation IDs.
The implementation has two existing crate owners and no new dependency.
Non-additive reconfiguration must build on actual retirement/settlement authority
later, rather than silently widening this API.
