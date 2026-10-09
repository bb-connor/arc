# Required harness and workspace integrations

Status: required product scope, amended 2026-10-08. Installed native
qualification remains open. This document supersedes any Pi-first or
mini-swe-first ordering in retained platform research and defines no new
runtime. Cases are defined in [CASES](CASES.md); this document explains the
surrounding design.

The primary adoption path is the agent harness and workspace people already
use. Chio supplies common authority, resource custody, evidence and recovery
through native OS bindings; it does not replace those consumers' planning,
model sessions or interface. The [source handoff](research/required-harnesses.md)
records public revisions, plugin and launcher files, Megastart pins and current
gaps; those observations are not installed acceptance.

## Required scope and existing owners

| Integration | Role | Implementation owner |
| --- | --- | --- |
| Claude Code | First-class harness in its own runtime | [Claude Code plugin repository](https://github.com/backbay-labs/chio-claude-code-plugin), its hooks and restricted launcher |
| Codex | First-class harness in its own runtime | [Codex plugin repository](https://github.com/backbay-labs/chio-codex-plugin), its hooks and restricted launcher |
| Pi | First-class harness in its own runtime | [Pi plugin repository](https://github.com/backbay-labs/chio-pi-plugin), its extension and restricted launcher |
| Hermes | First-class harness: the Hermes runtime, not another agent using its model account | `sdks/python/chio-hermes` and its launcher owners |
| Herdr | Workspace and plugin integration over applications using Chio | Megastart's `herdr/` plugin and its application contract (`CONTRACT.md`, manifest, `src/client.rs`) |

## Coverage

- **Linux first.** Each of the four harnesses needs at least one explicitly
  scoped protected profile on Linux (HOST-M2 on Omarchy), tracked as its own
  cell and expanded per advertised architecture, backend and deployment tuple.
  Pi's bubblewrap launcher exists; Claude Code, Codex and Hermes need Linux
  launchers that follow it (NORTH-STAR-FLOWS section 9).
- **macOS after the test.** Protected harness cells on macOS depend on macOS
  HOST-M2 and come after the success test (unified roadmap section 11). Until
  then macOS harness use is HOST-M1 scope and stays labelled by its real
  boundary class.
- **Hooks are coverage, not enforcement.** Hook failure does not block the
  host, so hook mode stays `detect_only` (Q11). Hook installation alone never
  closes a protected cell.
- **Existing owners deliver.** Integration owners make the changes; the
  platform program supplies missing OS ports and composed qualification, not a
  new generic agent runner. Preserve plugin-native configuration and workflows.
- **Open cells stay open.** Linux-only launchers, unavailable Darwin ports and
  historical captures leave a target cell open; they neither promise
  availability nor drop the requirement.

Herdr support is required; installing Herdr is optional. Herdr renders an
application contract and never issues kernel authority, owns accounting or
becomes a required daemon. Its Megastart plugin is the integration to extend,
not evidence that other Chio applications already work with it.

Cursor and OpenClaw remain obligations of the broader doc 19 six-host program;
this document does not declare that program complete.

## Mini-swe's bounded role

`chio-mini-swe` is an experimental reference workload, not the host API, a
required backend, the default harness or a first release, and it gates no named
harness. Workloads that execute code keep every confinement, evaluator, export
and uncertainty obligation whichever harness runs them.

## Promotion rules

H01 to H08 organize product acceptance on top of doc 19 I01-I08 and the C and Q
cases; they add no wire operations.

- **One harness on one platform** promotes on its own H01 to H05, H06a and H08a,
  I01-I08 and applicable owner cases. Neither H06b nor Herdr evidence is a
  predecessor. A profile advertising mixed-harness capability also qualifies
  the composition it exposes.
- **A Herdr tuple** needs its H07 and H08b, the application and native owner
  gates, and the selected harness's qualified profile. Missing selections stay
  unavailable and never switch harness silently.
- **Complete platform coverage** needs all four harness cells, H06b, and H07 and
  H08b for all four Herdr selections. Cross-platform completion needs both
  platforms. Partial promotion closes neither aggregate claim.

The release verifier selects the catalog independently of submitted results:
dropping unrelated records still promotes a complete single host, dropping its
own required subcase refuses it, and missing H06b or a Herdr selection refuses
only the aggregate claim.

First-class does not mean every kernel capability works in every host. Keep a
per-host capability map for passport admission, delegation, swarm authority,
shared resources, verifiable work and recovery; unavailable features stay open.

## Delivery

Shared packet 1 reconciles sources and per-host capabilities; packets 3 and 4
deliver the plugin and launcher bindings and H01 to H08; packet 5 proves
composition; packet 6 and the platform plans own installed delivery. Native
gaps go to the identity, IPC, process, credential and isolation owners; Herdr
compatibility stays with its plugin and application owner.

A partial release names its actual supported set; a plugin README, prior Pi
pass or Megastart recording supplies only its own scoped evidence.
