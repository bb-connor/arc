# Optional Chio operator projection

Status: optional proposed owner projection, amended 2026-10-08 UTC. See
[STATUS-GLOSSARY](STATUS-GLOSSARY.md). `chio.operator.v1` is a reserved name,
not an endpoint, frozen ABI, mandatory daemon or primary interface. Before the success test the unified
roadmap makes the trust-control dashboard the one operator web client (Lane
REL-4); a separate projection controller is `planning_status: deferred`. The
rules below bind any operator client that composes owner views, the dashboard
included. [HOST-CONTRACT](HOST-CONTRACT.md) and
[ADR-0038](../../../adr/ADR-0038-native-host-program.md) govern sequencing.

## Placement and authority

Applications and harnesses use the owner bindings directly; those freeze
without this projection. A projection is C-layer, outside the TCB and separate
from the gateway and process host. It holds no signing key, issues no
capability, signs no approval or receipt and keeps no competing task, recovery,
budget or authority ledger; losing its data cannot renew authority, erase an
effect, free capacity or create a result. Same-user IPC access alone is not an
application identity.

## Owner functions

Names describe composed functions, not RPC spellings. Wire schemas import the
landed owner types; no desktop work phase, replacement `WorkHandleV1`, recovery
or retry enum, approval format, event log or stop state machine exists.

| Function | Owning operation | Projection rule |
| --- | --- | --- |
| Observe receipts, lineage, budgets, revocations | Trust-control GETs on `/v1/receipts/*`, `/v1/lineage/*`, `/v1/budgets` and `/v1/revocations` | Method-specific: POST handlers on those paths are not observation. A receipt does not prove unobserved host effects. |
| Observe hook sessions | Host plugin session bond and hook records | Post-tool success stays `host-reported-success-unverified` and `detect_only`; needs a bounded authenticated host observation adapter. |
| Work functions | W1 `WorkClient` and `WorkQueryV1` (W planned) | Render `WorkViewV1`'s six observations; `Applied` means command processing, not success. Lost replies query the original preparation or command. |
| Recovery functions | R `SelectOffer`, `ResumeWorkflow`, `SubmitApproval`, non-persisting `read_recovery_workflow` (R unqualified) | Bind the current workflow revision; never clear cancellation or resubmit an unknown original; the controller never opens the store. |
| Close a task | K S4 authority-space closure | Exact coverage is the owner's obligation. |
| Emergency stop | K S8 routes or the process-host control socket | No task-to-global alias; preserve `stop_durable`, `stop_not_durable` and `stop_outcome_unknown`. |
| Events | K S5 Part B subscribe, ack and notifications | No independent desktop event protocol. |

A missing owner binding (work list, health, enrolled scope, review locator,
export adapter) disables that function; this document invents none.

## Rules for any operator client

- **Transport.** Linux reuses `chio-secure-ipc` listener custody, peer
  authentication and framing; Darwin adds its path in the same crate with
  macOS HOST-M2. No unauthenticated local fallback, separate XPC authority or
  in-guest endpoint (Q10).
- **Browser.** Authenticate the intended controller before releasing session
  material. Every protected read, subscription and mutation needs non-ambient
  request proof bound to the exact origin and session, checked on each HTTP
  request and WebSocket handshake; a cookie, permitted Origin, CORS policy or
  loopback address alone is insufficient (Q10).
- **Negotiation and decoding.** Negotiate the exact version and owner profiles
  first and again on reconnect, with no downgrade. Decode raw bytes strictly
  with duplicate-member rejection and byte, depth and count bounds; never
  coerce, truncate or float-round owner IDs or signed bytes (Q04).
- **Correlation.** Every response, errors included, matches the complete
  request binding; clients reject unsolicited, cross-owner or stale results.
  Pagination binds audience, query, owner namespace and snapshot, and a gap
  forces explicit refresh (Q04).
- **Full intent.** An owner-retained mutation binds the principal and every
  semantic parameter; the same ID with a changed body conflicts before any
  effect. Each owner arbitrates concurrent submissions atomically for every
  exposed mutation; controller-side deduplication never suffices (Q02).
- **Retries and errors.** Consume S9 M20 dispositions; replay never renews
  consent, quota, budget or clocks. A lost reply after possible dispatch is
  reported as unknown and resolved by owner lookup, never relabelled as a
  refusal or resubmitted (Q03).
- **Review.** Bind the owner, original operation, proposal, review and decision
  IDs, decision value, subject, recipient, revision and expiry. A deny never
  retains an approved credential. Without S28 attribution, records stay
  `SharedCredential` (Q05, Q06).
- **Health, scope and budgets.** Health names a nonempty set of supported
  profiles; stale, future or wrong-session evidence enables nothing. Reviewed
  scope resolves typed bindings and carries ADR-0011 labels per boundary.
  Budget views reject duplicate dimensions, and unavailable is never unbounded
  (Q15, Q16).
- **Stop.** Task closure needs K S4 phases 1 and 2 and live process cancel;
  kernel stop advertises only qualified S8 scopes (Q07, Q08).
- **Events.** S5 hints are unsigned and never authorize. Refresh through the
  authorized owner read, never by `InspectWorkflow` polling, which can drain
  quota and the settlement reserve. Ambiguous approval invalidation disables
  the affected actions until an exact re-read (Q09, Q21).
- **Presentation and helpers.** Agent text, filenames, output and URLs render
  inertly. Helpers use fixed executables, literal argv and bounded stdin, keep
  operands as data under the real parser (Git needs literal pathspecs), and
  missing operand safety disables the helper. Tokens never reach argv, logs,
  events or caches (Q17).
- **Execution profiles only.** Source capture refuses repository-controlled
  execution and fetch (Q14); an evaluator running candidate code has its own
  confinement and raw output never impersonates acceptance (Q12, Q19).

## Freeze and acceptance

Primary acceptance uses a real application and an independent harness with
every frontend and this projection absent (Q23). A projection freezes only for
capabilities its actual clients qualify, separately from owner ABI freeze and
native qualification; a UI suite qualifies no harness binding. The detailed
function and acceptance tables at `620c703d8` are the starting point if the
projection is scheduled.
