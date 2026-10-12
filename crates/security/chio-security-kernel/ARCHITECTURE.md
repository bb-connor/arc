# chio-security-kernel architecture

## Responsibility and boundary

This crate adapts active-defense contracts to `chio-kernel` extension points.
Its guards inspect trusted `SecurityInvocationContextV1` values and invoke
authorities supplied through `Arc` trait objects. The public surface also
includes flow resolver traits, tripwire publication, and issuance admission.
It owns the conversion from authority results to kernel decisions and evidence.
Stores, identity establishment, connector execution, and policy selection are
owned by the host and the crates implementing those authorities.

`chio-control-plane::security::ActiveDefenseRuntime` is a concrete consumer.
Its pre-invocation installation adds tripwire, containment, capability-set
suspension, egress, flow, and throttle guards. It also installs raw-output and
flow output hooks, issuance admission, an enforced pre-dispatch hook, and the
security-context authority. Constructing an adapter alone does not install it.

## Structure

| Module | Kernel interface and responsibility |
| --- | --- |
| `pre_invocation` | `Guard`; resolved flow admission and input-taint persistence. |
| `pre_dispatch` | `SecurityPreDispatchHook`; final flow fence and dispatch outcome recording. |
| `post_invocation` | `PostInvocationHook`; flow output transition and raw-output tripwire wrapper. |
| `tripwire` | Decoy/watermark detection, signed event publication, and receipt linkage. |
| `tripwire/arguments` | Bounded, byte-preserving candidates from JSON keys and string values. |
| `containment` | Session, principal, lineage, and capability overlay guard. |
| `capability_set_suspension` | Exact tenant/capability suspension lookup and validation. |
| `egress_restriction` | Tenant/session/server-destination restriction guard. |
| `session_throttle` | Invocation-attempt commitment and consumed-window validation. |
| `issuance_freeze` | `CapabilityIssuanceAdmissionAuthority` adapter for issue/delegate admission. |

`MissingContextPolicy` is the shared allow/deny choice for adapters that support
it. There are no declared Cargo features; the crate requires `std` and enables
it on the security types and flow engine dependencies.

## Data and control flow

`EngineFlowPreInvocationPort` resolves the request, persists observed input
taint before evaluating policy, then persists the resulting admission.
Its evaluation path rejects declassification that lacks a consumption authority.
The host's paired pre-dispatch authority owns one-shot consumption and evidence
before connector entry. `FlowPreDispatchHook` forwards the canonical request
and dispatch commitment and wraps the returned recorder in a request-bound
kernel outcome handle.

`EngineFlowPostInvocationPort` resolves output flow, evaluates its transition,
and persists the label join. `FlowPostInvocationHook` requires request and
identity context after accepting the security context. It returns an atomic
inspection containing the verdict and its evidence.

`TripwireGuard` collects argument candidates before any lookup, then checks
capability identity, tool identity, and each candidate's supported decoy kinds.
`RawOutputTripwireHook` inspects canonical JSON output for signed watermarks.
On a match the publisher attempts to append the observation receipt, builds a
security event linked to that receipt, signs it, and submits it to
`SecurityEventIngress::verify_and_append`. A match still blocks when persistence
fails, and the evidence distinguishes event and receipt persistence outcomes.

## Trust and invariants

Missing-context behavior is configurable. The control-plane installation uses
`Deny`; `Allow` is a real library option. Store errors and invalid restrictive
decisions deny once authoritative context is present. These decisions return
guard evidence for the kernel to include in its receipt path.

Containment checks session, principal, lineage, and capability targets and
rejects inconsistent posture/contribution presence. Capability-set suspension
uses `validate_capability_suspension_decision`. Egress checks the exact key,
destination ID, and consistency between denial and active effect IDs. The
destination is the request server identifier; this guard does not inspect URLs.

Throttle commitments include tenant, session, request ID, capability, server,
tool, arguments, and a kernel-owned invocation attempt ID. Public construction
of `GuardContext` grants no attempt identity. Clock zero/failure, consumption
failure, or inconsistent snapshot/window results deny. Validation checks the
snapshot generation/version and whether counts represent a new consumption,
an allowed replay, or exhaustion without an increment.

Argument collection bounds depth at 32, visited nodes at 4,096, input string/key
bytes at 1 MiB, emissions at 4,096, and emitted bytes at 4 MiB. Emissions are
charged before deduplication. Delimiter splitting preserves candidate bytes;
the collector does not decode encoded strings or search arbitrary substrings.

`TripwireEventPublisher::with_receipt_evidence` checks a nonzero policy hash and
receipt readiness. A publisher without that sink cannot append a linked event
on a match. The ingress implementation must authenticate signed source evidence
against its own trusted producer configuration.

`IssuanceFreezeAdmission` checks authoritative query shape and decision binding.
The caller must place authorization immediately before the issuance mutation;
the lineage store owns serialization with causal-fence acquisition.
Flow dispatch outcome persistence errors require recovery and cannot release
output as a successful durable transition.

## Dependencies

`chio-kernel` supplies extension interfaces and evidence delivery.
`chio-flow` evaluates resolved information-flow decisions. `chio-decoy` handles
authenticated decoy and watermark detection. `chio-security-types` supplies
ports, overlay validators, clock types, and response-independent security records.
`chio-core` provides canonical bytes, hashes, signing, and security receipt/event
formats; Serde encodes the local commitments.

## Verification

`tests/adapters.rs` exercises pre/post flow, tripwire detection and persistence,
containment denial, and concurrent atomic output evidence through the kernel.
Its `adapters/tripwire_arguments.rs` cases cover headers, cookies, URLs, command
delimiters, object keys, candidate budgets, and detector failure.
`adapters/security_callbacks.rs` checks panic containment and recovery behavior
at the kernel callback boundary.

Separate tests cover exact suspension, egress, and issuance queries, corrupted
decisions, missing authoritative context, and state outages.
`tests/session_throttle_kernel.rs` exercises kernel-owned attempts, alternate
matching grants, session claims, retries, and fresh-kernel identities with a
SQLite state store. `tests/decoy_argument_port.rs` covers registered surfaces,
lifecycle expiry, tenant separation, and exact marker matching.

Run `cargo test -p chio-security-kernel` for these adapter and integration tests.
They exercise constructed kernels and stores; operational deployment requires
the host's configuration, service custody, and authority readiness checks.
