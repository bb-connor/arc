# North-star flows

Status: approved by the program owner on 2026-10-08. It governs the native
host program. The [ADR-0038 amendment](../../../adr/ADR-0038-native-host-program.md#amendment-2026-10-08-north-star-and-flows)
records the decision, and the unified roadmap (#1196) schedules the flows. The
document restructure in [section 7](#7-program-restructure) follows as
separate, reviewable changes. This document qualifies no implementation,
installed profile or release.

`planning_status: ready_after_adr`. `boundary_class` is stated per operation
below and follows [ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md).

M1, M2 and M3 in this program are HOST-M1, HOST-M2 and HOST-M3 in other
documents (unified roadmap section 12). HOST-M1 is re-cut server-first in the
roadmap's Lane COOP (COOP-1). macOS HOST-M2 comes after the success test
(roadmap section 11); until then the executing organization of a HOST-M3 run
uses Linux.

> **Agents working on this branch:** this document sets the spine of the
> program. Restructure the other documents to reference it. Do not restate its
> flows. Add new findings as rows in the case table it calls for, not as new
> prose paragraphs.

Source aliases (T, F, W, K, N, R, G) are the pins in
[PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md). T is current `main`. F is
`main` after the #1160 merge commit; its runtime is experimental and its
broker is Linux-only.

## 1. North star and vocabulary

**Chio is a Rust kernel for agentic operating systems that coordinate work,
share resources, and cooperate across organizational boundaries.**

Supporting line: **Authority that only narrows. Work that survives. Evidence
that travels.**

### What "kernel" means

Chio is a userspace **authority and work-state kernel**. It carries, narrows,
checks and records authority. It owns:

- durable operation identity;
- holds and receipts;
- federation.

It does not provide isolation. Isolation comes from the host: bubblewrap and
Landlock, Seatbelt, containers or OpenShell. Every isolation claim names its
backend and its #1174 S7 evidence kind. This keeps the evidence in #1170 intact
(N:`docs/research/nvidia/06-strategy-and-roadmap.md`, section 2). That research
objected to "kernel" read as isolation or as a separate authority. It did not
object to "kernel" as the owner of authority and work state.

### What "agentic operating system" means

An agentic operating system is whatever system an owner runs where agents do
work. Those agents include harnesses such as Claude Code, Codex, Pi and Hermes,
and applications such as Megastart running in Herdr. Chio supplies that
system's kernel services:

| Chio service | OS counterpart | Status |
| --- | --- | --- |
| Agent passports, `did:chio` | Users and credentials | Shipped (T: `crates/trust/chio-credentials`, `crates/trust/chio-did`) |
| Capabilities and attenuation | Permissions and handles | Shipped (T: `crates/core/chio-core-types/src/capability/attenuation.rs`) |
| Durable process trees | Processes | main (experimental; F: `crates/kernel/chio-process`) |
| Holds, budgets, credential broker | Quotas and keychain | Holds shipped (T: `crates/kernel/chio-kernel/src/budget_store.rs`); broker on main (experimental; Linux-only) |
| Mailboxes, protocol edges | IPC and syscalls | Edges shipped; mailboxes on main (experimental; `crates/kernel/chio-process/src/mailboxes`) |
| Signed receipts | Audit log | Shipped |
| Treaties and federation | Networking between systems | Shipped as libraries and CLI (T: `crates/trust/chio-federation`) |

### The three verbs in Chio terms

- **Coordinate work.** This is the durable rights and records of work across
  agents: delegation chains, process trees, work commitments and recovery.
  Planning and scheduling stay in applications and harnesses. Chio does not
  compete with A2A, Temporal-class engines or Herdr.
- **Share resources.** Grants that only narrow, over pools the owner meters.
  Today the pools are money and invocation counts. Credentials, process slots
  and model tokens come later. Every use takes a hold and produces a signed
  receipt. A restart never replenishes a pool.
- **Cooperate across organizational boundaries.** Each owner admits foreign
  agents at its own door, under its own policy. The steps are a passport
  challenge, then federated issue, then a local capability. Evidence travels
  back for offline verification, and neither side holds the other's keys. No
  shipped product combines all four of: separately operated owners
  who each admit at their own door, attenuation-only grants, evidence the
  counterparty verifies offline, and durable work identity.
  - NVIDIA's Secure Agent Workspace, OpenShell, Microsoft AGT, AWS AgentCore and
    Entra each stop at their own trust domain (N: `05-competitive-analysis.md`).

### Audiences and retired phrases

- **Builders and OS contexts** (Omarchy, macOS, the verifiable-work paper) use
  the north-star sentence.
- **Contexts where Chio sits inside another runtime** (NVIDIA, enterprise) use
  #1170's category sentence: Chio carries, narrows, checks and records
  authority.

Retire these phrases:

- "The kernel your agents answer to";
- "Agents that pay each other";
- every "only protocol" claim;
- every unscoped "every call".

State limits once, in a single Boundaries section of each public document. Do
not attach a hedge to every sentence.

## 2. Identity and domain model

Each side of a cooperation is described only with identity types that already
exist.

| Unit | Definition | Status and owner |
| --- | --- | --- |
| **Organization principal** | A `did:chio` Ed25519 key. It signs passports, verifier policies and federated delegation policies. | Shipped (T: `chio-did`, `chio-credentials`, `chio passport`, `chio trust federated-delegation-policy-create`) |
| **Domain** | One install of Chio's services. Today that is `chio trust serve`: capability authority, challenge store and passport lifecycle status. Later it also covers the F process host and broker. | Shipped as `chio trust serve` (T: `crates/products/chio-cli/src/cli/types/trust.rs`) |
| **Agent subject** | Each harness session or worker has its own key. The organization issues it a passport. A domain issues it capabilities. | Shipped |
| **Operator** | The human who approves issuance and co-signs agreements. | K S8 S28 roster and a production passkey verifier; both are owner gaps |

A personal install is a solo organization with one domain, which is all M1
requires. Multi-domain organizations are deferred. An example is a laptop
enrolled under a company authority. That case uses the existing
enterprise-provider lane (provider-admin records and SCIM, T:
`docs/reference/IDENTITY_FEDERATION_GUIDE.md`). This design invents no new
authority type.

### Key custody

Today keys are plaintext seed files (`--seed-file`, `--signing-seed-file`,
`--holder-seed-file`). This is the largest gap for cooperation.

**Owner change:** add a custody provider behind the existing `SigningBackend`
surface, so every signing command accepts a key reference instead of a seed
path.

| Platform | Custody |
| --- | --- |
| macOS | A device-only, non-synchronizing data-protection Keychain item. Ed25519 cannot live in the Secure Enclave, so this is an OS-protected software key, and the product says so plainly. |
| Omarchy, user session | Secret Service through the desktop keyring. Verify on the target host. |
| Omarchy, service principal | TPM2-sealed `systemd-creds`. Verify on the target host. |
| Operator approvals | Passkeys through `chio-custody-hw`: Touch ID on the Mac, a platform or FIDO2 authenticator on Linux. Hardware-backed where the hardware exists. |
| Development profile only | Plaintext seed files, labelled as such |

### What the user sees

An Identity view shows:

- the organization DID and the domain;
- where each key lives, with a warning for plaintext files;
- issued passports and their lifecycle status (`chio passport status publish/revoke`);
- key rotation.

First run creates the organization key in OS custody, or imports it there.

### Owner changes

1. A custody provider behind `SigningBackend`.
2. A durable revocation oracle. The current implementation is in memory only
   (T: `crates/trust/chio-revocation-oracle`).
3. A lifecycle-status check in the portable passport verifier, before any
   embedded host relies on it. Today that verifier checks only issuer key,
   validity window and signature (T:
   `crates/kernel/chio-kernel-core/src/passport_verify.rs:152-178`).
   Federated issue uses the trust-control path that checks published status.

## 3. Flow M1: Cooperate-0

**Scenario.** Org A, a developer on **Omarchy**, has an agent that needs a
capability Org B provides. Org B runs a **Mac** and exposes a governed tool
behind `chio api protect`. There are two machines, two human operators and
no shared keys. Every command below ships today (T:
`docs/reference/AGENT_PASSPORT_GUIDE.md`, sections Federated Issuance, Holder
Transport and Remote Verifier Surface).

| Step | Who | Action | `boundary_class` |
| --- | --- | --- | --- |
| 0 | Both | Native host services: `chio trust serve --advertise-url`, plus, on B, the governed tool behind `chio api protect` with `CHIO_TRUSTED_ISSUER_KEY` set to B's trust-control authority key. Both run as user-session units (section 6), with keys in OS custody (section 2). | n/a |
| 1 | A | `chio passport create` for the agent subject, then `chio passport status publish`. Optionally `chio trust federated-delegation-policy-create` to cap scope and TTL. | Sets A's ceiling |
| 2 | B | `chio passport policy create`, which allowlists A's DID and sets receipt thresholds. Then `chio passport challenge create`, which returns public challenge and submit URLs. | n/a |
| 3 | A's agent | `chio passport challenge respond --challenge-url`, then `chio passport challenge submit`. | n/a |
| 4 | **B's operator** | Reviews and approves on the desktop. Then `chio trust federated-issue` mints a **B-local** capability bound to A's ceiling. | n/a |
| 5 | A's agent | Calls B's tool. **B's kernel admits or denies at B's door** and signs receipts, deny receipts included. | `prevent`, at B only |
| 6 | B | `chio evidence export`, and the package goes to A. | n/a |
| 7 | A | `chio evidence verify` offline, then `chio evidence import`, then `chio reputation compare`. Imported trust is shown separately and weighted down. | `detect_only` for A; reputation `advisory_only` |

Step 5 uses `chio api protect` rather than `chio mcp serve-http`. The API
protect evaluator accepts a capability presented in the `X-Chio-Capability`
header from issuers named in `CHIO_TRUSTED_ISSUER_KEY(S)` (T:
`crates/products/chio-api-protect/src/evaluator.rs` `extract_presented_capability`,
lines 463-469; `crates/products/chio-cli/src/cli/runtime.rs`
`parse_trusted_capability_issuers_from_env`, line 576). `serve-http` issues
session capabilities from its own policy and does not accept externally issued
ones.

### Desktop moments

- **Issuance review (step 4).** B's operator sees A's DID against the
  allowlist, the passport's lifecycle status and receipt history, the requested
  scope as a difference from policy, the TTL and A's ceiling. Approval uses a
  passkey. Until S28 lands, the approval record is labelled `SharedCredential`.
- **Evidence check (step 7).** A's operator sees B's verified receipts,
  including denials, and imported reputation labelled advisory.

Both surfaces start thin: a native notification opens a review view.

### Owner changes for M1

- Native service packaging for `chio trust serve` and `chio api protect`.
  This is the user-session profile in [HOST-CONTRACT](HOST-CONTRACT.md).
- TLS reachability. HTTPS lanes exist; iroh is not needed for M1.
- An end-to-end test of steps 5 and 6 across two hosts. Today steps 1 to 4 are
  tested on one host (T: `crates/products/chio-cli/tests/federated_issue.rs`),
  and steps 5 and 6 are only inferred.
- Verification uses `chio evidence verify` only.
  `chio receipt explain --inspect-bilateral` checks structure, not signatures.

### Evidence M1 produces

- The first independently operated cross-organization run. The verifiable-work
  paper lists `independent-operation` as an open gate
  (W: `docs/papers/verifiable-work/PUBLICATION.json`).
- An answer to the north star's statement that "Today every multi-owner result
  comes from one host" (K: `docs/research/2026-10-04-chio-kernel-north-star.md:226`).

The run counts only when two different people control the two machines. "Two
configured keys do not prove two independent organizations" (T:
`docs/papers/programmable-sovereignty/CLAIM_LEDGER.md:36`).

### Not claimed by M1

- Treaty enforcement at the receiver. The admission hook is installed only by
  the test harness today.
- Offline lineage deeper than one hop.
- Remote co-signing; that is M3.
- Budgets that span both organizations.

## 4. Flow M2: One root grant, many agents

**Scenario.** On one machine, a coordinator delegates parts of one task to
several harnesses. The coordinator is Megastart in Herdr, a harness acting as
planner, or the CLI. All the workers draw on **one owner-metered pool** and
leave **one authority tree**. Both survive restarts.

| Step | What happens | Owner | Status |
| --- | --- | --- | --- |
| 1 | The owner creates a **root grant** with caps (`max_total_cost`, `max_invocations`). It is the shared pool. | Capability scope and hold ledger (T: `/v1/budgets/holds/*`) | Shipped |
| 2 | The coordinator spawns Claude Code, Codex, Pi and Hermes workers in restricted modes. Each spawn is one signed, narrower hop with a basis-point share. | `chio-process spawn`, attenuation, sibling-sum split | Split shipped, in memory only (T: `crates/kernel/chio-kernel-core/src/budget_split.rs`); durable trees on main (experimental) |
| 3 | Swarm admission checks the whole graph before any child runs. | `chio-swarm-authority` with F: `crates/products/chio-cli/src/cli/process_host/swarm.rs` | Verifier shipped; serving install on main (experimental) |
| 4 | Workers call **kernel-owned** tools: gateway file tools, and the model through the relay with broker-held credentials. Each call takes a hold and produces a signed receipt. | Gateway, relay, broker | main (experimental; broker Linux-only) |
| 5 | Handoffs use durable mailboxes. Results are joined, and acceptance comes from the W1 evaluator. | `crates/kernel/chio-process/src/mailboxes`; W1 | main (experimental); W1 planned |
| 6 | Stop: revoke a child, cancel a subtree, and later S4 closure. | Process host; K S4 | Cancel works only while the host is stopped (F: `crates/products/chio-cli/PROCESS_HOST.md`) |
| 7 | Restarting, removing a client, or closing a Herdr pane never replenishes or loses the pool. | Durable journal and hold ledger | main (experimental) |

### What the user sees

A live authority tree. For every node it shows:

- the harness;
- how its scope differs from its parent;
- its basis-point share;
- calls used against the cap;
- open holds;
- revocation generation.

The pool shows exposed against realized spend and the store's guarantee level
(`SingleNodeAtomic`). Receipts appear per node, with uncertain outcomes flagged.

Stop controls state what they do not do: they do not kill the OS process and do
not undo effects. That text stays until live control and S4 closure land.

### Claims

| Activity | `boundary_class` |
| --- | --- |
| Kernel-owned tool calls in restricted modes | `prevent` |
| Hook-mode sessions, shown alongside | `detect_only` |
| Isolation | Credited to the Seatbelt or bubblewrap backend through its S7 kind |

### Decision: Megastart's allowance moves to kernel holds

Megastart's aggregate allowance is application-owned state (G in PROGRAM-MAP).
An application counter is a competing ledger, and only a kernel-held pool
survives a restart. The Megastart owner rebinds the allowance to a root grant
and its holds.

### Owner changes for M2

- Live cancel and revoke on the process host.
- A durable sibling-share registry outside process paths. The hosted kernel
  keeps it in memory today.
- A token or spend dimension at the model relay. The relay counts requests
  only today.
- After the success test (roadmap section 11): a Darwin process runner and a
  broker backed by Keychain and XPC.
- Megastart's allowance on kernel holds, and a Megastart Linux port.
- Linux restricted launchers for Claude Code, Codex and Hermes, following Pi's
  bubblewrap profile.

### Evidence M2 produces

- The first serving-path swarm admission. This closes the README overclaim
  that swarm authority verifies the whole task graph before a child runs.
- Durable sibling budgets across restart ([CONSUMERS](CONSUMERS.md) C02 and C04).
- Delegation across vendors' harnesses, which no single vendor's sandbox
  provides.

## 5. Flow M3: Work that crosses an organization boundary and comes back verified

M3 joins M1 and M2 through #1173's work commitments. It gives CONSUMERS C06,
the three-organization flow, a concrete shape.

| Step | What happens | Owner | Status |
| --- | --- | --- | --- |
| 1 | A offers B a **bounded, unpaid** subtask as a work commitment. B signs an offer. **Both operators co-sign the agreement** with passkeys. Each sees the exact predicate: treaty reference, action class and digest. | W: `docs/superpowers/specs/2026-10-03-work-owner-services-design.md` (`/v1/work/{prepare,commands,query,cosign}`), remote co-signer | Planned |
| 2 | B runs the work **inside B's own M2 tree and pool**. A sees only the commitment's `WorkViewV1` observations. | M2 and W1 | W1 planned |
| 3 | B submits. **Acceptance comes from the evaluator named in the contract**, never from a click by either side. Delivery is durable and bilateral. | W1 evaluator; W2 delivery | Planned |
| 4 | A lost reply is resolved through the original operation, with no second dispatch. | W1.6 queries; R recovery | Planned; R is not qualified |
| 5 | A verifies B's receipt chain, the co-signed agreement and the acceptance offline. | `chio evidence verify`, `chio-credentials` | Verification shipped |
| 6 | Optional: A proves a subset of that evidence to a third party C, a customer or auditor, with selective disclosure. | T: `crates/trust/chio-selective-disclosure` (BBS) | One slice shipped |
| 7 | Optional and experimental: funding through an F1 agreement and escrow. | #1161 and W, private chain | Experimental |

### What the user sees

- A **work inbox** of incoming offers, each with the counterparty's passport
  and treaty summary.
- **Agreement review and co-signing**, showing the exact predicate.
- **Work status** as six independent observations, with acceptance attributed
  to its evaluator.
- A **disclosure dialog** that shows exactly what C will see.

### Claims

- `prevent` applies only at each owner's own door.
- The counterpart's evidence is `detect_only`.
- "Verifiable without trusting the operator" applies only to the offline
  verifier.
- Per #1170 decision F-15, Backbay never holds both co-signer keys in any demo
  (N: `docs/research/nvidia/06-strategy-and-roadmap.md:797`).

### Owner changes for M3

- The W1 facade.
- W2 owner services and the remote co-signer.
- Receiver-owned admission in a serving path. Today it is installed only by
  T: `crates/kernel/chio-runtime-harness/src/kernel.rs`.
- Durable bilateral delivery.

### Evidence M3 produces

- The verifiable-work thesis demonstrated by separately operated owners.
- A partial answer to north-star bet 6, "evidence anyone can verify".

### Platform note

M3 needs M2 on the executing owner's platform. Until macOS reaches M2, B can run
on Omarchy with A on the Mac.

## 6. Platform delivery

| Need | Omarchy (Linux) | macOS |
| --- | --- | --- |
| M1 services | systemd user units (user-session profile). TPM2 `systemd-creds` for an always-on service principal. | LaunchAgent through `SMAppService`. LaunchDaemon only for an enrolled service principal. |
| Key custody | Secret Service; `systemd-creds` | Data-protection Keychain; passkey through Touch ID |
| Local operator IPC | `chio-secure-ipc` `SO_PEERCRED` (main, experimental) | `LOCAL_PEERTOKEN` plus a code-signing check in the same crate (owner change) |
| M1 desktop moments | A notification opens a review page. The QML bar shows identity and the count of pending reviews. A Walker entry opens reviews. | A notification opens a native review window. The menu bar shows identity and the pending count. |
| M2 resource owner | F: `integrations/required-agents` container resource and four-tool gateway | Not yet available. Needs the VM or container backend under evaluation in the macOS annex. |
| M2 process host and broker | F: `chio process`, which needs pidfd, and `chio-secret-broker` | Darwin process runner and a Keychain/XPC broker (owner changes) |
| M2 harness launchers | Pi bubblewrap exists. Claude Code, Codex and Hermes need Linux launchers that follow Pi's profile (plugin-repo changes). | Seatbelt candidates exist for Pi, Claude Code and Cursor. Codex has a restricted mode. |
| Coordinator application | Megastart Linux port, for Herdr on Omarchy (owner change) | Megastart native exists (Apple Silicon) |
| Confinement evidence | S7 `AgentHostBwrap`, `ProcessContainer` | S7 `Seatbelt`, a macOS VM kind |

### Delivery order

1. **M1 on both platforms together.** It needs only portable Rust services plus
   custody and packaging.
2. **M2 on Omarchy with Pi first,** then Linux launchers added one host at a
   time. Each host is promoted only on its own doc 19 I01 to I08 evidence.
3. **M2 on macOS** after the success test (roadmap section 11), once the Darwin
   runner, broker and resource backend land. `planning_status: deferred` until
   then.
4. **M3** pairs whichever platforms have reached M2.

Native surfaces stay thin: notifications, bar or menu-bar status, and review
windows. Rich views share one web client: authority tree, pool and evidence.
Every service remains usable from the CLI and SDKs with no Chio interface
installed.

## 7. Program restructure

The restructure that followed approval is recorded in the DOCS-1177.0 to
DOCS-1177.7 commits on #1177:

- ADR-0038 is renamed to match its title and amended with the north star, the
  kernel definition, the retired phrases, the domain model, the flow order and
  the Megastart allowance decision.
- The program [README](README.md) leads with the three flows;
  [CAPABILITIES](CAPABILITIES.md) is a verb, owner, status and platform matrix.
- [CASES](CASES.md) holds every C, Q and H case; [STATUS-GLOSSARY](STATUS-GLOSSARY.md)
  replaces repeated disclaimers; HOST-CONTRACT, RELEASE and OPERATOR are
  trimmed to what the flows consume.
- The Omarchy and macOS annexes and plans are organized by flow. The Omarchy
  annex records Herdr: "Herdr support" currently means Megastart's plugin, and
  Linux Herdr cases stay blocked until the Megastart Linux port lands.
- Public positioning copy (README, AGENTS, the SVGs, the competitive landscape
  and the ADR index) belongs to the unified roadmap's U3 items, not to this
  program's documents.

`scripts/check-native-host-docs.py` gates links, retired phrases, em dashes,
case IDs and these word budgets:

| Document set | Budget |
| --- | --- |
| Shared specification | 15,000 words or fewer |
| Each annex | 6,000 words or fewer |
| Each implementation plan | 8,000 words or fewer |

## 8. Exit criteria, testing and failure rules

### M1 Cooperate-0 is complete when

- **Setup.** One x86_64 Omarchy host and one Apple Silicon Mac are run by two
  different people. Services run as native user-session units. No plaintext
  seed file is used.
- **Positive path.** The passport, challenge and B's operator approval lead to
  federated issue. An in-scope call is allowed and receives a receipt.
- **Negative paths.** Each of the following is refused before dispatch, with a
  signed deny receipt wherever a call reached a kernel:
  - an out-of-scope call;
  - a replayed or stale challenge;
  - a wrong verifier;
  - a request beyond A's delegation ceiling;
  - a revoked passport status;
  - a key missing from custody.
- **Evidence.** A verifies B's evidence offline with signatures checked, then
  imports it. Imported reputation appears separately as advisory.
- **Records.** An independent-operation record (operators, hosts, key
  fingerprints) is published for the paper's gate. Every public claim is
  reviewed against ADR-0011.

### M2 is complete (Omarchy first, then macOS) when

- One root pool is in place. Pi plus at least one other host have each passed
  their own I01 to I08 on Linux.
- The process tree is durable. Restarting the controller or a harness changes
  neither the pool nor the tree.
- An over-pool call is denied.
- Swarm admission rejects a graph that exceeds `maxDepth` or `maxFanout`.
- Live cancel stops new admissions within a stated bound.
- Uncertain outcomes are flagged per node.

macOS meets the same criteria once its runner, broker and backend exist, after
the success test (roadmap section 11).

### M3 is complete when

- Two separately operated owners co-sign an agreement through passkey
  operators. No single party holds both co-signer keys.
- B runs the work in its own tree.
- Acceptance comes only from the evaluator.
- A lost reply is resolved without a second dispatch.
- A verifies everything offline. Selective disclosure to C works.

### Testing

- Owner behaviour is tested in the owner crates and linked from `CASES.md`.
- A two-host regression harness, with a Linux VM and a macOS runner in CI,
  makes the federated-issue end-to-end test continuous.
- Milestone evidence always comes from real hosts with real operators. CI runs
  and mocks never qualify a milestone.

### Failure rules for every flow

- Fail closed.
- A lost reply triggers a lookup of the original operation, never a new
  identity.
- When custody is unavailable or a counterparty is unreachable, the result is
  pending or refused. It is never a retry under new authority.

## 9. Owner change register

Each row becomes a tracked issue after this document is approved, linked from
`CASES.md` in the same way as #1180, #1181, #1182 and chio-bridge#3.

| Change | Owner | Needed by |
| --- | --- | --- |
| Custody provider behind `SigningBackend` (Keychain, Secret Service, `systemd-creds`) | Kernel signing and CLI | M1 |
| Native service packaging for `chio trust serve` and `chio api protect` | CLI and release | M1 |
| Two-host federated-issue and evidence end-to-end test | Trust plane | M1 |
| Lifecycle-status check in the portable passport verifier | `chio-kernel-core` | M1, embedded hosts |
| Durable revocation oracle | `chio-revocation-oracle` | M1 hardening |
| Production passkey approval path and S28 roster | Kernel approval, K S8 | M1 attribution, M3 |
| Live process cancel and revoke | `chio-process` (F) | M2 |
| Durable sibling-share registry outside process paths | `chio-kernel` | M2 |
| Token and spend dimension at the model relay | Relay and broker (F) | M2 |
| Linux launchers for Claude Code, Codex and Hermes | Plugin repositories | M2 Omarchy |
| Megastart allowance on kernel holds; Megastart Linux port | Megastart (G) | M2 |
| Darwin process runner, broker and peer identity | `chio-process`, broker, `chio-secure-ipc` | M2 macOS, after the success test |
| macOS resource backend selection | macOS annex owner | M2 macOS, after the success test |
| W1 facade | W | M3 |
| W2 owner services and remote co-signer | W | M3 |
| Receiver-owned admission in a serving path | `chio-runtime-core` | M3 |

## 10. Sources

| Topic | Source |
| --- | --- |
| Passport, challenge, federated issue and remote verifier commands | T: `docs/reference/AGENT_PASSPORT_GUIDE.md` |
| Enterprise identity lane | T: `docs/reference/IDENTITY_FEDERATION_GUIDE.md` |
| Federation routes | T: `crates/platform/chio-control-plane/src/trust_control/service_types/paths.rs:12-19` |
| Hold ledger and budget routes | T: `crates/kernel/chio-kernel/src/budget_store.rs`; `paths.rs:127-143` |
| Delegation attenuation and sibling split | T: `crates/core/chio-core-types/src/capability/attenuation.rs`; `crates/kernel/chio-kernel-core/src/budget_split.rs`; `spec/PROTOCOL.md` |
| Swarm authority verifier | T: `crates/kernel/chio-swarm-authority` |
| Process host, mailboxes, broker, required-agent resource | F: `crates/kernel/chio-process`; `crates/products/chio-cli/PROCESS_HOST.md`; `crates/security/chio-secret-broker`; `integrations/required-agents/README.md` |
| Work commitments and owner services | W: `docs/superpowers/specs/2026-10-03-work-runtime-design.md`; `2026-10-03-work-owner-services-design.md` |
| Paper publication gates | W: `docs/papers/verifiable-work/PUBLICATION.json` |
| North-star bets 6 and 8 | K: `docs/research/2026-10-04-chio-kernel-north-star.md` |
| Positioning and competition | N: `docs/research/nvidia/05-competitive-analysis.md`; `06-strategy-and-roadmap.md` |
| Two-keys caution | T: `docs/papers/programmable-sovereignty/CLAIM_LEDGER.md:36` |
| Megastart and Herdr | G and P in PROGRAM-MAP |
