# External consumer and application acceptance

Status: specified. This contract defines consumer outcomes and evidence, not new
endpoints or wire operations. [HOST-CONTRACT](HOST-CONTRACT.md) owns the systems
boundary and [PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md) owns source and
owner reconciliation. Cases are defined in [CASES](CASES.md); this document
explains the surrounding design.

## Consumer boundary

[FIRST-CLASS-INTEGRATIONS](FIRST-CLASS-INTEGRATIONS.md) names the required
harnesses and Herdr. Each needs its own installed platform evidence; one
harness in C01 is an incremental proof, not completion of that commitment.

- **Frontend absent.** An external harness and an application coordinator use
  the selected Chio capabilities with every Chio graphical frontend absent.
  Closing, replacing or upgrading a client cannot erase authority, retained
  work, reservations, resource fences or evidence.
- **Approval still applies.** Selected approval policy applies to headless
  callers. A missing approval mechanism makes that operation unavailable, not
  approved.
- **Independent consumers.** The harness and the application are independently
  implemented. A CLI and a UI wrapping the same adapter do not prove reusable
  host infrastructure.
- **Real bindings only.** Use the supported SDK, protocol and owner bindings
  that source reconciliation selects. Native L0, process L1, work L2 and
  recovery L3 are different surfaces. W1 handles do not exist because a sample
  has a mission ID. Do not invent a common endpoint to hide a missing owner.
- **Ownership stays put.** The harness keeps planning, model state and its own
  workflow; the application keeps assignment and business completion.
  Application components that hold signing keys, state or dispatch custody are
  inside the relevant owner TCB. Herdr and other presentation clients receive
  projections and supported actions, never a second runtime against an
  owner's store.

## Owner handoffs

Aliases are the pins in PROGRAM-MAP. Consume a named owner revision after its
gates pass; never fabricate an absent file or port locally.

| Responsibility | Owner source | Handoff |
| --- | --- | --- |
| Agent identity, workers and lifecycle | F:`crates/kernel/chio-process` (`registry.rs`, `WORKER_PROTOCOL.md`); F:`crates/products/chio-cli/PROCESS_HOST.md` | Process owner supplies bootstrap, invoke, observe, control and stop semantics and keeps original logical operations. |
| Authenticated native clients | F:`crates/security/chio-secure-ipc` | IPC owner ports and qualifies OS peer identity; a token-only loopback sample is not native control. |
| Harness integration and model custody | FIRST-CLASS-INTEGRATIONS owners; F:`docs/strategy/chio-direction/19-priority-agent-integrations.md`; F:`crates/security/chio-secret-broker` | Each harness owner routes its effects and model calls; secret and native owners keep credentials and confinement. Each protected host passes I01-I08. |
| Resource mutation and capacity | `crates/kernel/chio-kernel/src/budget_store.rs`; `crates/platform/chio-store-sqlite/src/budget_store.rs` | Resource and budget owners bind caller, assignment, request, reservation and result in one transaction; adapters add OS ports, not a second ledger. |
| Work commitments and acceptance | W:`docs/superpowers/specs/2026-10-03-work-runtime-design.md` | Work owner lands W1; an application exit or queue completion cannot synthesize accepted work. |
| Recovery and result release | R:`crates/security/chio-security-types/src/recovery/commands.rs`; R:`crates/kernel/chio-kernel/src/knowledge.rs` | Recovery and knowledge owners reconcile revision, recipient, retry disposition and disclosure, using non-persisting observation. |
| Independent operators | `crates/trust/chio-federation`; `crates/kernel/chio-kernel/src/federation_artifact_store.rs` | Federation owners test peer trust, treaty evidence, local refusal, revocation freshness and durable bilateral artifacts. |
| Identity and passports | F:`crates/trust/chio-credentials`; F:`crates/kernel/chio-kernel-core/src/passport_verify.rs` | Credential and admission owners bind subject, issuer policy, challenge, audience and validity; a passport never becomes a grant. |
| Recursive delegation | F:`crates/core/chio-core-types/src/capability/attenuation.rs`; K:S1 and S4 | Authority owners qualify supported depth and reduce-only scope and revoke descendants through current admission. |
| Swarm authority | W:`crates/kernel/chio-swarm-authority`; W:`crates/kernel/chio-runtime-core/src/store/sqlite/swarm_authority_bundles.rs` | Swarm and W1 owners keep the protected graph head; extension needs an atomic owner commit. |
| Existing application and Herdr consumer | Megastart `src/{authority,mission,operator}.rs`, `herdr/{CONTRACT.md,src/client.rs}` | The application keeps its packaged v1 API and adds an adapter to new owner bindings if needed. |

Public process and resource examples are acceptance patterns, not owner
implementations to copy. Freeze their source identities if reused as test
workloads.

## Organizational claims

C06 and C07 cannot claim organizational independence from three IDs or
processes under one administrator; a local fixture qualifies only its protocol
branch. The organizational record names separate operators, keys, stores,
resource owners, trust enrollment and disclosure policy, and each owner can
refuse. Never share signing keys or databases, and never infer a global atomic
allowance from local C04.

## Megastart and Herdr compatibility

The packaged `herdr/CONTRACT.md` v1 is Megastart's application API. Nothing here
renames its routes or actions or turns them into a host contract. An adapter
that maps a new owner binding into that projection preserves operation identity,
approval binding, authority and capacity provenance, disconnection semantics and
no automatic mutation retry, and passes the existing client conformance plus
C02, C04, C05 and C08 against the installed tuple.

Retain the documented limits: one-hop aggregate-family delegation, single-owner
durable family accounting, explicit uncertainty outside the captured crash point
and no qualified interactive native PTY. A coordinator's assignment is not a
delegated authority hop.

## Evidence manifest

Each implementation packet supplies an owner-format manifest with:

1. Fetchable public Chio revision, target owner pins, application revision and
   lockfile hashes, and every built and installed component hash.
2. Host and plugin versions, launcher identity, OS build and architecture,
   backend, configuration and policy digests, credential context and trust
   enrollment.
3. Current versus target behavior per capability, with unavailable cases named.
4. The command, input, positive control, adversarial stimulus, raw output,
   independent observations and reviewer decision for each case.
5. Source availability, local tests, hosted checks, installed qualification and
   independently operated federation as separate statuses. A rebuilt artifact
   or changed tuple re-runs its cases.

No consumer scenario, Megastart recording or owner unit test inherits doc 19
I01-I08 for any host.

## Promotion order

Reconcile sources and owners, then build one external harness and one
application consumer against the installed headless profile. C01 to C05
establish local systems behavior; C08 joins for exposed acceptance and
publication; C06 and C07 gate an advertised cross-organization capability, which
a local release may ship as explicitly unavailable. C09 to C11 follow the
capabilities selected in CAPABILITIES. User-session and service-host profiles
qualify independently; detached processes and GUI-free startup do not qualify
unattended authority. Herdr, the workbench, the menu bar and QML are consumers,
never prerequisites for direct owner clients.
