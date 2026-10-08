# Product and public-source grounding

Research date: 2026-10-08 UTC. Confidence is high in the inspected documentation
and downloaded source identity, moderate in the proposed adoption sequence, and
unknown for unexecuted target-platform behavior. This is design evidence, not
runtime qualification.

[HOST-CONTRACT](../HOST-CONTRACT.md) owns the accepted systems boundary.
[PROGRAM-MAP](../../../../architecture/PROGRAM-MAP.md) owns implementation pins,
source reconciliation and predecessor gates. [CONSUMERS](../CONSUMERS.md) owns
consumer acceptance; [QUALIFICATION](../QUALIFICATION.md) owns native and release
failure cases. Public source references use the
[public Chio repository](https://github.com/backbay-labs/chio).

## Product ambition

**Chio is a Rust kernel for building agentic operating systems.**

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.**

The live [Agentic Operating Systems essay](https://www.chio.computer/docs/concepts/agentic-operating-systems)
describes a lasting environment for responsibility, shared resources and work
across individual runs. The [Cooperation Across Companies essay](https://www.chio.computer/docs/concepts/cooperation-across-companies)
describes independently operated systems contributing to one result while each
company controls its resources. The [Platform overview](https://www.chio.computer/docs/platform)
connects kernel, node, durable process, cluster, swarm and federation contracts.

A workbench can expose this environment, but cannot define its persistence,
authority or usefulness. Removing a graphical client must leave the selected
systems capabilities usable through supported owner bindings. Equally, merely
running a tool-admission proxy without a GUI is too small a product definition.
The operating-system ambition includes retained responsibility, coordinated
handoffs, resource ownership, capacity, recovery and independently governed peers.

## Navigation, catalog and publication inventory

The inspected `chio-world` checkout contains 457 documentation `page.tsx` files
and 411 unique documentation hrefs in `src/lib/docs-nav.ts`. These are source
inventory counts, not deployed route or qualification counts. The checkout has
pre-existing edits and is not the current publication snapshot.

The six always-on navigation areas are Learn, Platform, Security, Economy, Build
and Reference; Agents, Forums and Products are flag-gated. Platform separates
Kernel, Node, Agent Processes, Cluster, Swarm and Federation. Build contains
application guides, examples and integration routes. `src/lib/docs-journeys.ts`
defines learning sequences separately from that taxonomy.

The article fetch reviewed 51 relevant live pages returning HTTP 200. The
navigation group `/docs/integrations` itself returned 404; use its individual
integration routes. Published Federation has seven groups: Peer Trust; Treaties
and Admission; Authority; Evidence and Reputation; Transport; Enterprise Identity;
and Operations and Assurance. Several expanded pages are absent from the older
local navigation and source tree. Published vision essays also contain expanded
systems/recovery material. Source availability, live publication and runtime
qualification therefore require separate records.

The source catalog extends beyond the sidebar:

- `src/lib/docs-swarm-artifacts.ts` orders signed graph, continuation, witness,
  join, route, budget, epoch and terminal artifacts with their owning pages.
- `src/lib/docs-formal-theorems.ts` and `src/lib/docs-finding-artifacts.ts` own
  specific claim inventories.
- `scripts/federation-docs/catalog.ts` names complete local workflows and their
  limits, including replay storage, trust inputs, loopback transport and fixtures.
- `scripts/swarm-examples/catalog.ts`,
  `src/components/docs/transcripts.generated.ts` and
  `src/components/docs/snippets.generated.ts` supply example material.
- `scripts/search/source-catalogs.ts` explicitly registers the catalogs consumed
  by extraction. Search presence is not implementation acceptance.

The following source paths are relative to the `chio-world` repository. A live-only
entry means the page was fetched but no corresponding file exists in the inspected
local docs tree; it is not a guessed implementation path.

| Contract | Docs source | Published reference and implication |
| --- | --- | --- |
| Agentic operating environment | `src/app/docs/concepts/agentic-operating-systems/page.tsx` | [Agentic Operating Systems](https://www.chio.computer/docs/concepts/agentic-operating-systems): responsibility survives individual workers; app completion remains explicit. |
| Independent resource owners | `src/app/docs/concepts/cooperation-across-companies/page.tsx` | [Cooperation](https://www.chio.computer/docs/concepts/cooperation-across-companies): selected diagnostics, proposals and evidence cross separately owned boundaries. |
| Kernel/host decomposition | `src/app/docs/concepts/architecture/page.tsx`, `portable-kernel/page.tsx` | [Architecture](https://www.chio.computer/docs/concepts/architecture), [Portable Kernel](https://www.chio.computer/docs/concepts/portable-kernel): portable decision logic and native state/I/O are different contracts. |
| Durable actor and worker protocol | `src/app/docs/processes/page.tsx`, `host-workers/page.tsx` | [Processes](https://www.chio.computer/docs/processes), [Host and Workers](https://www.chio.computer/docs/processes/host-workers): host-owned identity and authority; worker gets a process-bound private connection. |
| Coordination and recovery | `src/app/docs/processes/supervision/page.tsx`, `calls-recovery/page.tsx`, `checkpoints/page.tsx`, `mailboxes/page.tsx` | [Supervision](https://www.chio.computer/docs/processes/supervision), [Recovery](https://www.chio.computer/docs/processes/calls-recovery), [State](https://www.chio.computer/docs/processes/checkpoints), [Mailboxes](https://www.chio.computer/docs/processes/mailboxes): attempts, logical operations, checkpoints and claims retain distinct meanings. |
| Shared mutation | `src/app/docs/processes/shared-resources/page.tsx`, `src/app/docs/guides/rust-resource-service/page.tsx` | [Resource Ownership](https://www.chio.computer/docs/processes/shared-resources), [Rust Resource Service](https://www.chio.computer/docs/guides/rust-resource-service): trusted caller, assignment/fence, version and retained result meet in the resource transaction. |
| Native application host | `src/app/docs/processes/embedded-host/page.tsx`, `operations/page.tsx` | [Embedded Host](https://www.chio.computer/docs/processes/embedded-host), [Host Operations](https://www.chio.computer/docs/processes/operations): embedding is a supported architecture; keep authority/state/evidence together through restart. |
| Same-operator shared state | `src/app/docs/cluster/overview/page.tsx`, `coordination/page.tsx`, `budgets/page.tsx` | [Cluster](https://www.chio.computer/docs/cluster/overview), [Coordination](https://www.chio.computer/docs/cluster/coordination), [Budgets](https://www.chio.computer/docs/cluster/budgets): legacy peer repair is not global consensus or a realized-spend ceiling. |
| Delegated work | `src/app/docs/swarms/overview/page.tsx`, `task-graphs/page.tsx` | [Swarms](https://www.chio.computer/docs/swarms/overview), [Task Graphs](https://www.chio.computer/docs/swarms/task-graphs): signed authority graph; application still schedules and validates useful completion. |
| Cross-organization standing relationship | `src/app/docs/federation/overview/page.tsx`, `protocol/page.tsx`, `treaties/page.tsx` | [Federation](https://www.chio.computer/docs/federation/overview), [Model](https://www.chio.computer/docs/federation/protocol), [Treaties](https://www.chio.computer/docs/federation/treaties): local peer trust and compatible action requirements are separate. |
| Peer/issuer/evidence distinctions | Expanded live-only pages | [Peer Handshake](https://www.chio.computer/docs/federation/peer-handshake), [Authority](https://www.chio.computer/docs/federation/authority), [Delegation](https://www.chio.computer/docs/federation/delegation), [Evidence Sharing](https://www.chio.computer/docs/federation/evidence-sharing): pinning a peer does not trust a capability issuer; sharing records does not activate trust or payment. |
| Bilateral verification and qualification | `src/app/docs/swarms/bilateral-cosign/page.tsx`; expanded assurance page is live-only | [Bilateral Co-Sign](https://www.chio.computer/docs/swarms/bilateral-cosign), [Federation Assurance](https://www.chio.computer/docs/federation/assurance): exact signed bytes plus required context; production peer independence/partition tolerance/durable gossip remain unsupported in that catalog. |
| External harness adoption | `src/app/docs/guides/choose-agent-integration/page.tsx`, `connect-an-application/page.tsx` | [Choose Integration](https://www.chio.computer/docs/guides/choose-agent-integration), [Connect Application](https://www.chio.computer/docs/guides/connect-an-application): existing MCP assistant, native durable worker and framework-owned graph are distinct choices. |
| Useful systems | `src/app/docs/examples/agentic-os/{software-factory,shared-worker-fleet,incident-response}/page.tsx` | [Factory](https://www.chio.computer/docs/examples/agentic-os/software-factory), [Fleet](https://www.chio.computer/docs/examples/agentic-os/shared-worker-fleet), [Incident](https://www.chio.computer/docs/examples/agentic-os/incident-response): artifact, authority, resource and independently checked result provide acceptance workloads. |
| Source/release identity | `src/app/docs/reference/compatibility/page.tsx` | [Compatibility](https://www.chio.computer/docs/reference/compatibility): source and published packages can share 0.1.0 while exposing different APIs. |
| Portable reputation and runtime identity | `src/app/docs/concepts/reputation-passports/page.tsx`, `workload-identity/page.tsx` | [Passports](https://www.chio.computer/docs/concepts/reputation-passports), [Workload Identity](https://www.chio.computer/docs/concepts/workload-identity): signed assessments and authenticated workload context are distinct inputs to current admission. |
| Recursive authority and continuation | `src/app/docs/guides/delegate-between-agents/page.tsx`; `src/app/docs/swarms/{authority,witness-chains,continuations}/page.tsx` | [Delegation](https://www.chio.computer/docs/guides/delegate-between-agents), [Authority](https://www.chio.computer/docs/swarms/authority), [Witnesses](https://www.chio.computer/docs/swarms/witness-chains), [Continuations](https://www.chio.computer/docs/swarms/continuations): scope narrows recursively; runtime replay and evidence lookup require separate configured owners. |

## What the examples establish

Vision interactions are authored browser models, not running workers or deployed
federation. The executable examples and captures describe named paths and failure
points. This research did not execute their complete runtime suites. Neither a
published page nor a source listing qualifies a new OS/backend or host adapter.

The process contract distinguishes a durable actor from its OS worker; an external
service manager may own worker launch through the documented serve path. Framework
state can remain with LangGraph or an AI SDK application. Kernel-selected caller
context must reach a cooperating resource over a trusted path. Mailbox leases,
resource ownership and operation deduplication do different jobs.

The incident example separates three local processes and separately governed
tools, an actual provider repair, and a subsequent customer health observation.
It is a useful source for a cooperation test. Production independence still needs
separate administrators, key custody, transport, retained state and failure tests.
The federation assurance catalog explicitly separates tested, modeled, measured
and unsupported claims.

## Capability-to-product traceability

These capabilities explain why the systems layer is worth adopting. They must not
disappear into a generic isolation service or an operator dashboard. The broader
[capability crosswalk](../CAPABILITIES.md) reconciles the complete kernel/work
program and NVIDIA strategy; this table records the direct consumer consequences.
Source aliases refer to PROGRAM-MAP, not public checkout instructions.

| Capability and benefit | Owner and inspected contract | Consumer consequence and qualification boundary |
| --- | --- | --- |
| Identity and passports let an agent present attributable history to a new counterparty. | F:`crates/trust/chio-credentials/src/{passport,presentation,challenge}.rs`; F:`crates/kernel/chio-kernel-core/src/passport_verify.rs`; public passport/workload pages above. | Preserve subject, trusted issuer, validity, challenge and selected disclosure. A signed assessment is neither workload authentication nor a resource grant. Portable verification does not by itself check revocation or issuer chains; native presentation/admission owners qualify those selected requirements. C09 tests this separation. |
| Recursive delegation lets a coordinator recruit sub-specialists without handing each one root authority. | F:`crates/core/chio-core-types/src/capability/attenuation.rs`; signed lineage and S4 closure in PROGRAM-MAP; public delegation/witness pages. | Preserve bound delegator, reduce-only scope/constraints, expiry and applicable budget rules through each supported hop. C10 tests useful descendant work, widening refusal and ancestor revocation. General delegation support does not remove Megastart's one-hop aggregate-family restriction. |
| Swarm authority makes distributed contributions a checked connected graph. | W:`crates/kernel/chio-swarm-authority/src/{types,verifier,evolution}.rs`; W:`crates/kernel/chio-runtime-core/src/store/sqlite/swarm_authority_bundles.rs`. | Plans remain external; owner-issued graph heads, continuations, witnesses, routes, allocations and revocation must agree. Pure verification has no durable replay store. Additive extension needs an atomically protected head and production issuance custody. C11 tests the actual configured runtime, not just offline signatures. |
| Verifiable work separates execution from accepted useful output. | W:`docs/superpowers/specs/2026-10-03-agentic-work-kernel-design.md`, `2026-10-03-work-runtime-design.md`; W1.0-W1.6 gates. | Bind producer, artifact, evaluator and original contract; retained acceptance and dependency claims remain with their owner. C08 includes execution-success/acceptance-failure and changed candidate controls. The proposed facade is not inferred from existing sample missions. |
| Shared resources and capacity turn collaboration into bounded operating behavior. | Native resource owner; kernel budget and SQLite owner paths in CONSUMERS; public resource contract and Megastart family implementation. | A claim cannot override current resource assignment; a new client cannot renew allowance. C03-C04 inspect owner transactions, reservations and independent effects through handoff/restart. No distributed budget guarantee follows from one local database. |
| Federation and scoped disclosure let autonomous organizations cooperate. | Federation peer/treaty/runtime owners and W:`docs/superpowers/specs/2026-10-03-work-owner-services-design.md`; public federation inventory. | Each organization retains trust, keys, resource decisions and refusal. C06-C07 qualify scoped work, changed relationships and original outcome recovery. Unpaid cooperation is useful without mandatory marketplace or settlement; funded obligations add the selected payment owner. |

The public continuation reference states that current product binaries do not
automatically configure the swarm admission path. Its pure verifier checks a
bundle; stored evidence, route comparison and single-use replay belong to a
configured runtime. A headless integration must deliver that configuration and
owner evidence before advertising it. Similarly, a passport UI or successful
cryptographic parse cannot silently create admission authority.

NVIDIA research informs the platform isolation choice through PROGRAM-MAP's N
register. Isolation constrains reachable effects; it does not replace passports,
recursive delegation, graph authority, work acceptance or resource/recovery
custody. The capability crosswalk owns that competitive comparison and its source
qualification; no competing runtime is accepted merely by naming it here.

## Megastart and Herdr: inspect the existing consumer before designing another

The [Megastart archive](https://www.chio.computer/examples/megastart.zip) was fetched
on 2026-10-08 UTC. The archive identity and eight selected files were checked
against the local `public/examples/megastart/` source. Both Cargo lockfiles were
also fetched from the archive and compared byte-for-byte. This is publication
provenance, not a new runtime test.

| Item | Recorded identity |
| --- | --- |
| Archive | 335,069 bytes; 59 members; SHA-256 `9dcbecec5bf9681c301ffd0bf7a2eeea685ec8b8b5911ac180692f66cf292050` |
| Public kernel dependency | `6753edbc365f5ea820224b96a59940feedbfca94`; [public commit](https://github.com/backbay-labs/chio/commit/6753edbc365f5ea820224b96a59940feedbfca94) was available through the public GitHub API |
| Root `Cargo.lock` | SHA-256 `64b1a6079697fe10a586b3f18c497a7fdc5b07c60678a703907bbf7570db67b0` |
| `herdr/Cargo.lock` | SHA-256 `5033b1d3fa697618f2017a0d3b1a5819b4869cc240ffc6167658e29321e7a039` |
| `herdr/CONTRACT.md` | SHA-256 `1282916aefb717e28f11b7ccb62f7ef2d1f30f393eb381b5c0b0bb192f9591e4` |

Exact source responsibilities in that archive:

| Source | Existing ownership and target implication |
| --- | --- |
| `Cargo.toml`, `Cargo.lock`, `support/shared/`, `support/runtime/` | Pinned public kernel dependencies and packaged application runtime; do not substitute a branch tip without requalifying the composed tuple. |
| `src/authority.rs` | Retained signed grants and one aggregate invocation family. It directly issues worker grants because this public dependency rejects multi-hop aggregate-family delegation. Coordinators assign work without adding a delegation hop. |
| `src/mission.rs`, `src/operator.rs` | Application mission, retained outcomes, candidate/approval flow and application console. These are application responsibilities, not a new universal kernel task API. |
| `src/agents/service.rs` | Native worker endpoint/session composition under retained family authority. Its launcher/provider assumptions remain specific source behavior to reconcile with the selected target profile. |
| `herdr/CONTRACT.md`, `herdr/src/client.rs` | Packaged operator contract v1, loopback descriptor/authentication, bounded state/events and explicit actions. This is the Megastart application API. |

The [packaged Herdr contract](https://www.chio.computer/examples/megastart/herdr/CONTRACT.md)
names `GET /api/state`, `GET /api/events?after=N`, and `POST /api/action`. It records
contiguous cursor validation, no automatic mutation retry after network failure,
and capacity observation from the mission authority. Closing a pane or unlinking
the plugin preserves the detached mission host and retained state. The contract
reports exercised Herdr 0.9.0 and Apple Silicon macOS; it does not qualify new
Linux/native launchers, interactive PTY control, arbitrary crash points or the
current target host integrations.

The [Megastart README](https://www.chio.computer/examples/megastart/README.md)
separates the atomic single-SQLite family allowance from the sibling-share
registry. Reopening preserves consumption. Its injected crash occurs after four
effects and their receipts are retained; a different uncertain window refuses
redispatch. A local application budget is not a global multi-organization budget.

Preserve this packaged v1 compatibility. A migration to newly landed owner
bindings belongs in an application adapter, with source/API/evidence reconciliation
and compatible client tests. Do not force a breaking API change merely to make a
sample match proposed `chio.operator.v1`; that optional projection is neither the
kernel ABI nor a mandatory service. Do not generalize the three sample endpoints
into universal APIs.

## Alternatives and decision

| Alternative | Assessment |
| --- | --- |
| Workbench-first platform | Makes client navigation and presentation a dependency of systems adoption. It also risks duplicating task, authority and recovery state already owned elsewhere. Reject as the common critical path; retain as an optional consumer. |
| Headless admission gateway only | Fits an existing tool connection but does not deliver durable responsibility, shared-work ownership or resource continuity. Keep as one integration shape, not the complete product definition. |
| New universal daemon and universal demo API | Adds authority/state custody without evidence that a missing owner requires it; conflates application mission routes with kernel contracts. Reject unless a specific owner later establishes the need and accepts the interface. |
| Systems-first existing owners and bindings | Allows trusted embedding or separately hosted native services, external harnesses, application coordinators and optional clients. Reuses process/resource/evidence/recovery responsibilities and makes adoption measurable. Selected direction. |

The implementation handoff is concrete: foundation/process owners reconcile the
worker ABI; secure IPC and native service owners implement missing OS ports;
resource/budget owners preserve atomic custody; W1 and recovery owners supply
only their landed command/query/retry contracts; federation owners retain peer,
issuer, treaty and disclosure decisions. Applications and Herdr adapt their
workflows and views above those contracts. PROGRAM-MAP must resolve each exact
source revision and owner test before a platform packet advertises it.

An acceptance result should show what infrastructure an adopter no longer owns:
credential distribution, durable actor bookkeeping, operation recovery, scoped
handoff, shared allowance or stale-owner exclusion. A coding patch is one useful
workload. Cross-organization operation additionally needs independently controlled
owners and its own qualification; local hosting need not wait for that entire
program to ship.
