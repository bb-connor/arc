# P1 recovery operating contract

This contract covers one native, sequential support-ticket disclosure: review
the complete title and body, verify every required data authority, create one
public issue, and recover the original operation. It covers ordinary execution
and the kernel's operation-owned nonce profile. General semantic remedies,
artifacts, confined children and product installation are later roadmap phases.

## Trusted host composition

1. Provision/open the serving authority and receipt store through their existing
   APIs. Install the durable admission, outcome, budget and revocation stores
   under the current serving fence. Reconcile retained admission state before
   accepting work. Recovery records participate in the same protected inventory,
   global commit chain, integrity checks and rollback anchors.
2. Open the existing process journal with its operator-selected security profile.
   Derive the process's actual security context. Import/hydrate native security
   state through the existing source-adoption protocol. Enable captured native
   flow with a verified manifest and the explicitly scoped disclosure issuer.
3. Register `PinnedSupportIssueConnector` with one canonical HTTPS issue endpoint,
   explicit provider/account identity, provider observation key and response
   ceiling. Submission and read-only lookup credentials are host-owned. The
   connector sends one physical POST with original operation/attempt correlation,
   uses no redirects or transport retries, and exposes no caller-selected URL.
   An idempotency header alone does not establish provider deduplication.
4. Install `RecoveryDeploymentV1` with
   `configure_recovery_deployment`. Bind the actual store UUID, tenant, process,
   native authority, security context, policy, effect contract, recipient,
   disclosure purpose, target label, aggregate issuer, current actor assignments
   and complete coverage authority. Compute its authority scope with
   `recovery_authority_scope_digest`. P1 requires effect cardinality one.
5. Construct `RecoveryRuntime` from that kernel, process, captured flow resolver,
   scope and `Ed25519Backend`. Construction checks the native binding, process
   context, issuer key and nonce profile. Mount `recovery_router` on the trusted
   host's private authenticated control listener. The native
   [fixture](../../../../../crates/platform/chio-control-plane/src/recovery/tests.rs)
   demonstrates this complete composition using an independently durable effect
   sink; it does not configure a public provider deployment.

Control tokens are direct, verified issuer tokens assigned to stable operator
principals. Their exact server is `chio.recovery`, exact tool is the requested
permission (`create`, `inspect`, `select`, `approve`, `resume`, `cancel`, `report`
or `settle`), and operation is `Invoke`. P1 refuses matching wildcard grants,
constraints, invocation/monetary budgets, sender-proof requirements, delegation,
caveats and attenuation. Its command and lookup quotas are durable recovery
quotas. A token requiring a native invocation enforcement path cannot silently
use the control path. The initiating tool capability still goes through native
capability, budget, nonce and participant enforcement.

The aggregate issuer uses deterministic Ed25519 signatures over one immutable
reserved body. Every owner and removed compartment obligation must be covered
by operator-scoped current approval evidence. Integrity endorsement is not
implemented by this profile. Governed/supplemental/federated/monetary native
participant combinations outside the declared P1 profile refuse explicitly.
There is no claim of nondeterministic remote signing support.

## Command, review and return behavior

`POST /v1/recovery/commands` carries canonical `RecoveryTransportRequestV1`:
the capability and canonical command are bounded JSON strings. Review and
settlement use `POST /v1/recovery/review` and `POST /v1/recovery/settle`, with the
capability string and workflow ID. Python and public TypeScript clients use these
same operations. The CLI provides `chio recovery command`, `review` and `settle`;
capabilities and commands come from bounded files. Client transports have finite
timeouts and never automatically repeat ambiguous submissions.

Retain the original command ID and exact semantic body after an uncertain
acknowledgement. Its durable identity is scope, stable assigned principal,
command kind and command ID; its digest includes the original expected revision.
Rotating access tokens are not identity. Replay resolves committed identity
before stale-revision rejection, performs fresh authentication and audience
checks, and never reapplies a committed mutation or renews consent. Changed
content conflicts. A lost acknowledgement is resolved by the original identity.

Create retains the seed and materializes a distinct continuation, step and
process request. It never rewrites a frozen denied request. Selection requires
the exact offer and revision. The full approval preview binds canonical action,
request semantics, all unsigned authorization requirements, recipient, purpose,
source restrictions and deadlines. Submit signed scoped coverage for that
exact challenge. Resume reserves issuance, signs outside transactions, attaches
the exact signature and envelope, finalizes the original process reservation,
then enters ordinary native admission/capture. Each reservation charges one
logical-call slot. Request, process-binding, flow-payload and credential-free
native-history digests retain their distinct meanings.

Recovery v2 is explicit. Missing/null/unknown version selectors, stripped
bindings and cross-context or v2-to-v1 substitutions refuse. Ordinary legacy
v1 grants keep their original representation and cannot satisfy recovery v2.

Current capability, assignment, revocation, time and clearance gate every view
and result return. Status has opaque references and bounded categories; protected
preview/envelope/result bytes are separate authorized channels. Errors and Debug
representations redact payloads, signatures and credentials. HTTP replies are
bounded at 256 KiB. Approval inspection needs current source clearance.

## Uncertainty, cancellation and settlement

Reconciliation reads the original native operation before another invocation.
Capture retains the recovery participant, budget and disclosure consumption
under the serving authority. The existing conservative consumption ordering
remains in force: a later failure does not restore spent authority.

Unknown, captured-but-unacknowledged and delivered-but-denied work cannot start
a replacement effect. Cancel records intent, fences late uncaptured admission,
and preserves captured/uncertain ownership. Provider failure, client disconnect,
task cancellation, expiry and Drop do not establish absence of an effect.

`settle` uses current independent scoped recovery control. It reconciles retained
evidence without creating execution rights or requiring a renewed initiating
capability. `settle_from_provider` additionally consumes an affine original-only
lookup reservation, uses the host's independent read credential, then verifies
fresh authenticated provider evidence against the original operation, attempt,
provider/account/resource, cardinality and current observation key. A negative
lookup never establishes final no-effect closure. Lookups are capped at 32 per
workflow. Positive partial/failed-after-effect evidence spends the step even when
no output is available; it does not manufacture a native receipt or result.

Guarded release after a captured return restores the exact original envelope,
participants and receipt under current serving authority. Revoking/expiring the
initiating capability prevents new capture without erasing historical effect
evidence. Current recipient authority and source clearance still govern replay.

## Time, resources and upgrades

Review validity is at most 15 minutes. A grant is at most 60 seconds and is also
capped by initiating capability and approval-evidence deadlines. Restart never
renews age. Clock rollback, unavailable time, changed policy/context generations,
keys, permissions or deployment bindings refuse pending capture. Same labels
with an unrelated newer generation do not satisfy the original reviewed basis.
The original operation-owned nonce and frozen process envelope are restored
without a new nonce or refreshed caller authority.

| Resource | New intake | Existing settlement |
|---|---:|---:|
| Workflows per tenant, across process scopes | 64 | Existing identities retained |
| Workflows per authority | 128 | Existing identities retained |
| Commands per tenant | 3584 | 4096 |
| Commands per authority | 7168 | 8192 |
| Current protected record bytes | 48 MiB | 64 MiB |
| Immutable recovery events | 57344 | 65536 |
| Individual record | 256 KiB | 256 KiB |
| Authority database | Less than 1 GiB | Less than 2 GiB |
| WAL | Less than 64 MiB | Less than 128 MiB |
| Available disk reserve | At least 128 MiB | At least 16 MiB |

Intake has four bounded host slots; settlement has two independently reserved
slots. The connector has four slots, a five-second connect timeout, twenty-second
request timeout and at most 64 KiB response. Decode ceilings remain 64 KiB wire,
depth 16, 4096 nodes, 32 KiB strings, 256 container entries and 4096 verifier work
units per bounded verification. Title/body limits are 256/16384 bytes. No store
transaction spans network/signing/provider awaits. PASSIVE WAL checkpointing
starts at 32 MiB outside writers; pinned readers cannot force unbounded recovery
intake. Disk, WAL or commit failures retain original ownership. Settlement
headroom is finite; exhaustion requires restoring capacity while preserving
the authority and its identities. Closed identities and command tombstones are
not evicted or recycled.

Authority schema 35 upgrades populated schema 34 atomically. Existing native
operation and global-chain bytes stay unchanged. An interrupted migration rolls
back to 34; a capable binary then upgrades on reopen. The schema-34 compatibility
guard refuses schema 35. The process journal accepts ordinary legacy v1 records;
the first recovery reservation installs v2 metadata and immutable reservation
protection. v2 downgrade or missing protection refuses reopen. The process ABI
is `chio.process.abi.v3`; legacy request-binding vectors remain unchanged.

Drain pending workflows under the retained capable profile before changing
issuer/policy/participant selections. P1 does not silently reinterpret captured
work under another profile. If the required historical verifier/profile is
unavailable, quarantine the operation and restore a qualified original
settlement path. Binary rollback can disable new intake while the capable binary
drains; it cannot delete recovery rows or restore an older authority snapshot.

## Qualification boundary

The retained corpus exercises production native capture against a deterministic
external fixture that appends every attempt without provider deduplication.
It verifies actual effects independently of receipts and workflow projections.
It is local implementation evidence. Real-provider behavior, public deployment,
Linux enforcement, hosted CI, production throughput and installation are
separate qualification work, with product qualification assigned to P6.
