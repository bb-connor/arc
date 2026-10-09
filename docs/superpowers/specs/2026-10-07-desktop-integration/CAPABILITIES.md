# Capability matrix

Status: accepted planning direction, amended 2026-10-08. Source existence,
roadmap intent and installed qualification are distinct; this matrix is a
crosswalk, not a new API or claim registry. Sources use the aliases in
[PROGRAM-MAP](../../../architecture/PROGRAM-MAP.md) and the paths in
[NORTH-STAR-FLOWS section 10](NORTH-STAR-FLOWS.md#10-sources). Cases are in
[CASES](CASES.md).

A new capability enters only with its consumer problem, existing primitive and
source, authoritative owner, OS port, what stays application-owned, its status
and a useful positive with an independent failure oracle. A feature name is
never a reason to add a daemon, protocol, resource ledger or task language.

Status values:

- `shipped`: on `main` (T) with tests; not qualified as a native host profile.
- `main (experimental)`: arrives with #1160 (F); the broker is Linux-only.
- `W planned`: designed in #1173; no code. `WorkHandleV1`, `WorkViewV1`,
  `WorkClient` and `WorkTransport` are design-only.
- `R unqualified`: implemented in #1179, not qualified.
- `library-only`: a crate exists, with no native host serving path in this
  program.

| Verb | Capability | Owner and source | Status | `boundary_class` | `planning_status` | Omarchy | macOS | Flow |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Cooperate | Agent passports and holder challenge | T: `crates/trust/chio-credentials`; `docs/reference/AGENT_PASSPORT_GUIDE.md` | shipped | `prevent` at the receiving door through current admission; a passport alone grants nothing | `ready_after_adr` | HOST-M1 | HOST-M1 | HOST-M1 |
| Cooperate | `did:chio` organization and subject identity | T: `crates/trust/chio-did` | shipped | `advisory_only` (identifies, never grants) | `ready_after_adr` | HOST-M1 | HOST-M1 | HOST-M1 |
| Cooperate | Federated issue of a receiver-local capability | T: `chio trust federated-issue`; `crates/platform/chio-control-plane` | shipped | `prevent` at the issuing owner's door | `ready_after_adr` | HOST-M1 | HOST-M1 | HOST-M1 |
| Cooperate | Evidence export, verify and import | T: `chio evidence` (`crates/products/chio-cli/src/cli/dispatch/receipt_evidence.rs`) | shipped | `detect_only` for the verifier; imported reputation `advisory_only` | `ready_after_adr` | HOST-M1 | HOST-M1 | HOST-M1 |
| Cooperate | Treaties and federation | T: `crates/trust/chio-federation`, `crates/trust/chio-federation-authority`; `crates/trust/chio-federation-transport-iroh` (ADR-0014) | shipped as libraries and CLI; iroh transport `library-only` | `prevent` at each owner's own door; counterpart evidence `detect_only` | `ready_after_adr`; iroh `deferred` (HTTPS is the default transport) | HOST-M1, HOST-M3 | HOST-M1, HOST-M3 | HOST-M1, HOST-M3 |
| Cooperate | Selective disclosure to a third party | T: `crates/trust/chio-selective-disclosure` (BBS) | shipped (one slice) | `prevent` for undisclosed claims | `ready_after_adr` | HOST-M3 | HOST-M3 | HOST-M3 |
| Share | Attenuation and the sibling split | T: `crates/core/chio-core-types/src/capability/attenuation.rs`; `crates/kernel/chio-kernel-core/src/budget_split.rs` | shipped; split held in memory only | `prevent` for kernel-mediated calls | `ready_after_adr` | HOST-M2 | after the success test | HOST-M2 |
| Share | Hold ledger and budgets | T: `crates/kernel/chio-kernel/src/budget_store.rs` (`/v1/budgets/holds/*`) | shipped | `prevent` for kernel-mediated calls | `ready_after_adr` | HOST-M1, HOST-M2 | HOST-M1 | HOST-M2 |
| Share | Metering and settlement | T: `crates/economy/chio-metering`, `crates/economy/chio-settle` | `library-only` | holds and caps `prevent`; rail settlement outcomes `detect_only` | `deferred` (funded work follows the success test) | none before the test | none before the test | HOST-M3 (optional) |
| Share | Credential broker | F: `crates/security/chio-secret-broker` | main (experimental) | `prevent`: raw credentials never reach the worker | `ready_after_adr`; macOS `deferred` | HOST-M2 | after the success test (Keychain and XPC broker) | HOST-M2 |
| Share | Model relay | F: relay and broker provider adapter | main (experimental); request counts only | `prevent` on request count; token and spend `cannot_see` until the relay dimension lands | `ready_after_adr` | HOST-M2 | after the success test | HOST-M2 |
| Coordinate | Swarm authority | T: `crates/kernel/chio-swarm-authority`; F: `crates/products/chio-cli/src/cli/process_host/swarm.rs` | verifier shipped; serving install main (experimental) | `prevent` in the serving path; offline bundle verification `detect_only` | `ready_after_adr` | HOST-M2 | after the success test | HOST-M2 |
| Coordinate | Process trees | F: `crates/kernel/chio-process`; `crates/products/chio-cli/PROCESS_HOST.md` | main (experimental) | `prevent` for kernel-owned spawns; isolation credited to the host backend | `ready_after_adr`; macOS `deferred` | HOST-M2 (pidfd) | after the success test (Darwin runner) | HOST-M2 |
| Coordinate | Mailboxes | F: `crates/kernel/chio-process/src/mailboxes` | main (experimental) | `prevent` on lease and authority checks | `ready_after_adr` | HOST-M2 | after the success test | HOST-M2 |
| Coordinate | Work commitments | W: `docs/superpowers/specs/2026-10-03-work-runtime-design.md`, `2026-10-03-work-owner-services-design.md` | W planned | `prevent` at each owner's door; counterpart work view `detect_only` | `ready_after_adr` | HOST-M3 (executing) | HOST-M3 (requesting) | HOST-M3 |
| Coordinate | Recovery by original operation | R: `crates/security/chio-security-types/src/recovery/commands.rs` | R unqualified | `prevent` against a second dispatch | `ready_after_adr` | HOST-M3 | HOST-M3 (requesting) | HOST-M3 |

## What the matrix does not claim

A row's `shipped` status is source and test evidence on `main`, not a native
host profile; profiles qualify only through their CASES rows on real hosts.
Hook-mode activity beside these capabilities is `detect_only`. No row implies a
distributed atomic budget, a global scheduler or authority issued by an
application or by Herdr.
