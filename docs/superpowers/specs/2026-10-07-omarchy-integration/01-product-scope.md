# Product scope and success contract

Status: Proposed design, 2026-10-07. Confidence: moderate on adoption, high on
the availability of Omarchy's plugin interface. This is a specification package,
not an installed product or a qualified release. Dependencies: the source and
qualification inventory in [Chio readiness](research/chio-readiness.md).

## Product decision

Chio for Omarchy makes a delegated computer task visible, bounded and recoverable.
The first useful job is a coding task on an operator-selected project copy that
produces a tested review artifact. Omarchy owns desktop presentation; Chio owns
the agent execution contract. A user can tell what the task may touch, what has
actually happened, and which intervention is needed after interruption.

The selected architecture is a native QML plugin, a thin Rust desktop controller,
and protected host/resource adapters backed by the existing Chio kernel. Linux
remains the machine kernel; Chio is the Rust kernel for agentic systems.

| Approach | Benefit | Cost and reason for selection |
| --- | --- | --- |
| Native plugin plus existing authority | Native desktop affordances and reusable execution semantics | Selected. Requires a Linux qualification effort and explicit adapter boundaries. |
| MCP desktop tools with a local permission panel | Fast route to visible desktop automation | Existing OMCP already provides much of this; by itself it covers only its tool route. Useful resource integration, insufficient project execution boundary. |
| Omarchy fork with privileged agent daemon | Deep launcher and system-repair integration | Deferred. Large maintenance and privilege surface before the first workflow demonstrates value. |

The runtime is local first. No hosted account, cloud control service, telemetry
backend or new model provider subscription is a dependency. A selected model
provider can still receive explicitly released model context. Local first does
not imply local inference or zero provider disclosure.

## Audiences and jobs

1. **Developer:** give a bounded coding task to an agent while continuing other
   desktop work. Review an artifact with the actual tests that produced it.
2. **Operator:** choose resources, limits and authority; reconcile an interrupted
   action without clearing state or repeating an unknown effect.
3. **Omarchy user:** later diagnose and repair a particular desktop setting with
   an inspectable diff and a verified restoration path.
4. **Integration maintainer:** qualify a precise Omarchy/host/runtime combination
   and understand which update invalidated it.

One person can occupy all four roles. Their authority channels remain distinct
from the confined agent. The product does not assume a multi-user organization.

## Release profiles and phase boundaries

| Profile | First phase | User-visible capability | Entry gate |
| --- | --- | --- | --- |
| `observe-v1` | P1 | View explicitly enrolled task status and retained evidence | P0 API compatibility; working native status source |
| `project-v1` | P2 | One Pi task, dedicated project copy, fixed test recipe, local review artifact | Actual x86_64 Omarchy confinement and exact native kernel/host/resource tuple |
| `reviewed-publish-v1` | P3 | Native approval for one exact artifact/destination | Native decision binding and recovery contract qualified |
| `desktop-v1` | P4 | Bounded allowlisted desktop operations | Project boundary plus qualified desktop resource |
| `repair-v1` | P5 | One supported user-configuration repair transaction | Desktop boundary plus backup, validation and restoration qualification |
| `delegated-v1` | P6 | Bounded children and original-operation transfer | Separate native delegation/custody prerequisites |

P7 qualifies named profiles independently. Shipping `observe-v1` never implies
that `project-v1` is safe to enable. The plugin installation only installs its UI;
an absent backend is a supported unavailable state, not an invitation to run the
ordinary agent as a fallback.

## First useful workflow

The user selects a project using a trusted file chooser and previews the import
inventory. Dirty tracked changes are included only as disclosed by the import
contract; ignored secrets, special files and outside aliases are excluded or
refused. Chio prepares a private task identity, an immutable resource generation,
a fixed tool inventory and a selected model profile. The task prompt remains
untrusted content, even when the user wrote it.

Pi searches and reads that resource, proposes a patch, runs an operator-defined
test recipe and emits a review artifact. It receives neither the source working
tree nor authority to publish externally. The task panel joins artifact digest,
recipe digest, native operation identifiers, verified receipts and independent
resource observations. An explanation from the model is supplementary content.

The operator can later authorize the exact publication. If a reply is lost after
an effect, recovery looks up the original operation. Creating a new task, host
profile or authority cannot be used as the recovery button.

## Explicit scope limits

The first profile has one task worker, one resource workspace, sequential tool
calls, a selected provider/model route and a local review destination. Ordinary
interactive Pi, arbitrary shell commands, automatic project extensions, native
browser control, package installation, privileged repair, remote desktop control
and cross-user service are excluded from this profile. Later profiles have their
own gates. These exclusions are contractual, not hidden settings.

No strong isolation from malicious same-user desktop plugins is promised. The
default profile trusts the desktop session and confines the guest agent. No
generic exactly-once guarantee is promised for arbitrary external services.

## Adoption experiment and stopping rules

Run three recorded sessions with an independent operator: a successful project
task, a scope violation followed by valid work where policy permits, and an
interrupted task requiring recovery. Record setup time, intervention count,
completion, diagnosis accuracy, UI latency and reproducibility. Initial targets
are hypotheses: cold setup within 15 minutes after supported dependencies,
identification of scope and current state within 30 seconds, and an independent
operator correctly explaining the unknown-outcome recovery in every exercise.
No success rate or performance result is asserted by this document.

Stop expansion into desktop repair if the project profile requires an unrestricted
guest path, if a host-specific recovery cache becomes a second authority, or if
the independent operator cannot distinguish completion from uncertainty. Address
the failed contract before adding integrations. A negative adoption result can
justify shipping the controller API for other desktops rather than an Omarchy
product; it does not justify relaxing confinement.

The first qualification project is a small pinned Node fixture with a single-process
fixed recipe (2 seconds plus 100 ms termination grace, 16 KiB output). General
repository test runners, dependency installation and interactive coding sessions
require separate recipe/host qualification. This narrow pilot must demonstrate
a useful edit-review workflow before expanding the resource inventory.

## Normative requirements

| ID | Requirement | Proposed acceptance |
| --- | --- | --- |
| OM-PRD-001 | Every advertised profile MUST name its exact feature set and qualification tuple. | AT-PRD-001 |
| OM-PRD-002 | Missing native prerequisites MUST leave dependent actions unavailable without ordinary-agent fallback. | AT-PRD-002 |
| OM-PRD-003 | P2 MUST produce a useful local project artifact through mediated operations. | AT-PRD-003 |
| OM-PRD-004 | Installation and enrollment MUST preserve existing agent profiles and unrelated desktop configuration. | AT-PRD-004 |
| OM-PRD-005 | Completion claims MUST distinguish verified effects, observed tests, model explanations and uncertainty. | AT-PRD-005 |
| OM-PRD-006 | Recovery MUST retain original task, authority and native operation bindings. | AT-PRD-006 |
| OM-PRD-007 | Expansion decisions MUST record measured adoption results and explicit stopping-rule outcomes. | AT-PRD-007 |
| OM-PRD-008 | The product MUST disclose the default desktop-trust boundary and unsupported profiles during enrollment. | AT-PRD-008 |

## Proposed acceptance

### AT-PRD-001: Profile claims match evidence
Trigger: install a package qualifying only `observe-v1`. Expected: task launch,
approval and repair are unavailable. Oracle: independent comparison of signed
release profile inventory, runtime feature response and every menu action.
Artifact: `profile-claims.json` plus screenshots of unavailable actions.

### AT-PRD-002: Missing dependency never launches ordinary Pi
Trigger: remove or substitute the selected native runtime before task launch.
Expected: explicit prerequisite refusal, zero provider requests and zero guest
launches. Oracle: external process and network observer. Artifact:
`missing-prerequisite.json` with observed executable identities.

### AT-PRD-003: Useful task produces independently inspectable work
Trigger: a real model fixes a seeded failing test in an enrolled project copy.
Expected: initial failure, permitted patch, passing identical recipe and one
review artifact. Oracle: read-only artifact inspector and recipe observer, not
the model's transcript. Artifact: `project-useful-work.json` and joined receipts.

### AT-PRD-004: Installation preserves originals
Trigger: enroll on a machine with customized shell and ordinary Pi profiles.
Expected: only disclosed task-owned paths/entries change. Oracle: before/after
hash inventory with private values omitted. Artifact: `installation-diff.json`.

### AT-PRD-005: Uncertainty remains visible
Trigger: lose completion after a resource effect. Expected: no success badge;
the view distinguishes resource observation from retained native outcome.
Oracle: resource ledger and authority journal independently inspected. Artifact:
`completion-classification.json` plus UI capture.

### AT-PRD-006: Recovery preserves identity
Trigger: restart the controller and host after dispatch. Expected: one original
operation, no fresh grant or effect merely to restore a task. Oracle: authority
and resource dispatch counts. Artifact: `original-recovery.json`.

### AT-PRD-007: Adoption evidence drives the next phase
Trigger: independent operator completes the three experiment sessions.
Expected: measured values and pass/fail for each stopping condition; failed
conditions prevent phase promotion. Oracle: signed observer record and operator
task answers. Artifact: `adoption-experiment.json`; empty results fail the gate.

### AT-PRD-008: Trust assumptions are accurately represented
Trigger: inspect onboarding, help and release notes. Expected: same-user desktop
trust and profile limitations are consistent; no whole-machine protection claim.
Oracle: claim inventory reviewed against [authority](06-authority-approvals.md).
Artifact: `claim-review.json` with reviewed text locations.
