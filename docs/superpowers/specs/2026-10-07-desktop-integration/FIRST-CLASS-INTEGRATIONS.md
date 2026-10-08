# Required harness and workspace integrations

Status: user-required product scope, amended 2026-10-08 UTC. Installed native
qualification remains open. This document supersedes any Pi-first or mini-swe
first-product ordering in retained platform research. It defines no new runtime.

Chio is a Rust kernel for agentic operating systems that coordinate work, share
resources, and cooperate across organizational boundaries. The primary adoption
path is the agent harness and workspace people already use. The kernel supplies
common authority, resource custody, evidence and recovery through native OS
bindings; it does not replace those consumers' planning, model sessions or UX.

[Source handoff](research/required-harnesses.md) records exact public revisions,
existing plugin/launcher files, Megastart pins and present qualification gaps.
Those observations do not supply installed acceptance for the target matrix.

## Required scope and existing owners

| Integration | Required product role | Implementation owner |
| --- | --- | --- |
| Claude Code | First-class native harness; its own runtime and user workflow | Existing [Claude Code plugin repository](https://github.com/backbay-labs/chio-claude-code-plugin), its plugin/hooks and restricted launcher/transport owners |
| Codex | First-class native harness; its own runtime and user workflow | Existing [Codex plugin repository](https://github.com/backbay-labs/chio-codex-plugin), its plugin/hooks and restricted launcher/transport owners |
| Pi | First-class native harness; its own runtime and user workflow | Existing [Pi plugin repository](https://github.com/backbay-labs/chio-pi-plugin), extension and restricted launcher/transport owners |
| Hermes | First-class native harness; the Hermes runtime, not another agent using its model account | Existing `sdks/python/chio-hermes` integration and launcher/transport owners at the reconciled PROGRAM-MAP revision |
| Herdr | First-class workspace/plugin integration over applications using Chio | Existing Megastart `herdr/` plugin and application-owned compatibility contract, including `CONTRACT.md`, manifest and `src/client.rs` |

The required native coverage is each of the four harnesses on Linux/Omarchy and
macOS, with at least one explicitly scoped protected profile per harness on each
platform. Track those eight host/platform cells individually, expanding by every
additional advertised architecture/backend/deployment tuple. Track Herdr on each
platform separately. Present Linux-only launchers, unavailable Darwin ports or
historical example captures leave the corresponding target cell open; they are
neither promises of current availability nor reasons to drop the requirement.

Existing integration owners deliver the changes. The platform program supplies
their missing OS ports and composed qualification, rather than implementing a
new generic agent runner. Preserve plugin-native configuration, diagnostic hooks
and supported workflows; distinguish those paths from a qualified protected
launch. Hook installation alone cannot close a protected support cell.

Herdr support is required; installing or running Herdr is optional. A headless
Claude Code, Codex, Pi or Hermes integration remains independently usable. Herdr
continues to render and operate an application contract, not to issue kernel
authority, own resource accounting or become a mandatory kernel daemon. Its
Megastart plugin is the existing integration to preserve and extend, not evidence
of a generic plugin already compatible with every future Chio application.

Cursor and OpenClaw remain obligations of the broader doc 19 six-host program.
This amendment establishes the named four as this native program's required
first-class harness scope; it does not declare the broader program complete or
delete its remaining hosts. Other SDK/protocol consumers remain extensible.

## Mini-swe's bounded role

`chio-mini-swe` is an existing experimental adapter/reference workload. Its
sealed repository execution, recovery or export tests can exercise their actual
owner contracts when selected. It is not the common host API, mandatory coding
resource, default harness, required backend or first product release.

Its Docker/rootless compatibility, upstream version and test results do not
gate Claude Code, Codex, Pi, Hermes or Herdr unless a specific selected integration
actually depends on that owner. A shared low-level primitive may be reused after
source reconciliation, but an incidental workload dependency must be removed
from general native gates. Preserve every confinement, evaluator, export and
uncertainty obligation for workloads that do execute code. Replacing the harness
never waives those obligations.

## First-class means installed behavior

Use each integration's actual host/plugin/runtime and existing qualification
suite. The following H labels organize product acceptance, not a second
protocol or replacement for doc 19 I01-I08, CONSUMERS C01-C11 or Q01-Q31.

| Case | Required useful behavior and negative control | Scope and existing owner gates |
| --- | --- | --- |
| H01 Install and select | Install the pinned plugin/launcher and actual upstream host; discover/select its resolved identity. Reject stale, removed, substituted or unsupported components without falling back to an unprotected launch. Preserve the user's separate personal installation and settings. | Each of the eight required host/platform cells; I01/I08 and native release/activation gates. Record source, host, plugin, runtime, backend, architecture and installed hashes. |
| H02 Useful native harness work | Start the named harness in its own runtime, perform a useful governed task and produce an independently checked result with every Chio GUI and mini-swe absent. The harness retains planning, model/context state and normal supported workflow. | Each required cell; I02, C01, Q23. No stub host, hook-only invocation, static fixture or different agent can substitute. |
| H03 Authority and denied alternatives | Bind native workload identity and current scoped authority to actual effects. Reject a real out-of-scope call, missing kernel, expired/revoked authority and the selected profile's alternate file/network/process paths. Observe protected bytes and effect counters outside the guest. | Each required protected cell; I03-I05, Q10-Q14/Q22/Q31 and selected platform isolation gates. Passport verification never supplies a missing grant. |
| H04 Correct evidence and recovery | Verify exact request/result/receipt identity. Lose a reply after an effect, restart/reconnect the real harness, look up the original operation and demonstrate no repeated mutation or replenished allowance. | Each required cell; I06/I07, C02/C04/C05 and applicable Q02-Q04/Q14/Q19/Q21. Unknown outcomes stay unknown until the owner reconciles them. |
| H05 Lifecycle and credentials | Exercise actual supported login/credential flow, start/stop, update/removal, lock/logout/reboot and unavailable credential/backend behavior. No silent billing/account fallback, copied personal login or broad key exposure. | Each required cell; I08, Q10/Q13/Q29/Q31 and platform lifecycle. User-session support cannot imply independently enrolled service-host support. |
| H06 Harness composition | Run a same-harness positive for each named harness, then one mixed-harness coordination scenario involving all four as separately identified workers. Share an owner-enforced resource/capacity and retained handoffs; restart one worker and attempt an over-scope handoff. | Each platform; C02-C04 and selected Q25-Q27. App chooses assignments; kernel owners retain authority, accepted-result rules and conserved capacity. Megastart's supported delegation depth remains explicit. No requirement to test all combinatorial role permutations. |
| H07 Herdr plugin compatibility | Install/link the existing plugin; select and start each required harness through the supported application; inspect authentic state and evidence; close/reopen/unlink the pane/plugin while the declared host continues. Exercise gaps, substituted endpoints, lost mutation replies and explicit stop/approval only where qualified. | Each platform and each of the four harness selections; packaged Herdr contract, C02/C04/C05/C08 and relevant Q04/Q09/Q10/Q16/Q17. Reconnect must not replay actions or create authority; plugin removal must not delete mission state. No native PTY claim without separate qualification. |
| H08 Independent use and honest capabilities | Run each harness with Herdr/workbench/menu/QML absent. Run Herdr with only the selected harness installed, reporting absent integrations as unavailable. Verify a valid supported choice works and an unsupported choice cannot silently switch harness, model account or assurance mode. | Each platform; C01/C05/Q23 and release catalog. A missing optional consumer cannot block a qualified native profile, while incomplete required coverage remains visible in the program record. |

For H06, evidence of four separate host passes is not evidence of their
composition. Conversely, a mixed demonstration does not qualify every host's
I01-I08. Bind both to the actual candidate and native tuple. Current Megastart
proves an application design and provides test scenarios; its captures cannot
stand in for the new installed campaigns.

First-class does not imply every kernel capability is already implemented in
every host. Maintain an explicit per-host capability map for passport admission,
delegation, swarm authority, shared resources, verifiable work and recovery.
Supported operations descend through their existing owners; unavailable features
stay open. C09-C11 and Q24-Q28 gate additional advertised semantics. The program's
full coordination/resource/organizational ambition remains a separate completion
requirement, including independently administered counterparties.

## Delivery, promotion and completion

Shared packet 1 reconciles source and per-host capabilities; packets 3/4 deliver
the existing plugin/launcher bindings and H01-H08; packet 5 proves system-level
composition; packet 6 and platform O5/O7 or M7/M9/M10 own installed delivery.
Native prerequisite gaps belong to their existing identity/IPC/process/credential/
isolation owners. Herdr compatibility work stays in its plugin/application owner.

Each individually qualified profile may promote without waiting for another
harness, platform, Herdr or mini-swe. Full first-class integration completion
requires all eight host/platform cells and both platform Herdr matrices, with
the approved exact tuples and required positive/negative evidence. A partial
release names its actual supported set. Removing a required host from a
candidate's result manifest cannot close the program or redefine its catalog.

Record source discovery, implemented integration, installed qualification,
public artifact availability and public support claims separately. A plugin
README, repository default branch, prior Pi pass or Megastart recording supplies
only its own scoped evidence. Select release pins against actual native owner
compatibility; do not combine unrelated candidate branches by name alone.
