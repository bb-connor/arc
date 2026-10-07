# Chio for Omarchy implementation plan set

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a native Omarchy interface to independently qualified Chio tasks,
starting with status and one confined project workflow.

**Architecture:** QML plugin, literal-argv Rust client/opener, thin Rust controller,
existing native Chio authority, protected Pi host and closed resource adapters.

**Tech Stack:** Rust, Qt/Quickshell QML, typed NDJSON, SQLite projection store,
existing Chio/Pi contracts, Linux enforcement, systemd user services and Arch packages.

Status: Proposed plans. No runtime implementation or phase acceptance is part of
this documentation PR. Read the [design](../../specs/2026-10-07-omarchy-integration/README.md),
[prerequisite register](../../specs/2026-10-07-omarchy-integration/16-roadmap-decisions.md)
and [source readiness](../../specs/2026-10-07-omarchy-integration/research/chio-readiness.md)
before starting. All paths not present in the current tree are explicit future
delivery targets; a proposed function name is not an existing native API.

## Ordered execution

| Plan | Deliverable | Depends on |
| --- | --- | --- |
| [00 Native prerequisites](00-native-prerequisites.md) | Exact source/package tuple, native contracts and fail-closed capability inventory | Source research; named native owners |
| [01 Controller and plugin](01-controller-and-plugin.md) | Shared ABI/store/shim and read-only actual Omarchy surface | P0 read-only tuple |
| [02 Confined project task](02-confined-project-task.md) | Trusted import, one protected Pi task, fixed tests and review artifact | P1 and all P2 native/Linux/provider gates |
| [03 Approvals and publication](03-approvals-publication.md) | Native exact decision and enrolled reviewed destination | P2 and native decision fix |
| [04 Desktop resources](04-desktop-resources.md) | Closed metadata tools and exact workspace effect | P3 and pinned compositor |
| [05 Configuration repair](05-configuration-repair.md) | Single-file scalar repair with bounded reload | P4, writer exclusion and reload closure |
| [06 Delegation](06-delegation.md) | Attenuated children, aggregate reservations and recovery | P3 and separate native child contract |
| [07 Distribution and qualification](07-distribution-qualification.md) | Real Linux evidence and independent install/update/rollback/removal | Only the exact profiles selected for release |

P7 is a repeated qualification lane, not a promise to complete all optional phases
before shipping any value. Some Linux harness and packaging work from plan 07
must happen before P2 can close; P2 names those prerequisite artifacts explicitly.
Assign one integration owner to the shared harness, ABI and profile matrix before
parallel implementation. Do not let phases independently invent incompatible
capability callbacks, state names, harness flags or package layouts.

## Shared implementation ownership

| Future path | Owner and contract |
| --- | --- |
| `crates/products/chio-desktop/` | Desktop maintainer; controller/client/opener in one product crate with shared contracts |
| `integrations/omarchy/fixtures/plugin/` | Desktop maintainer; sole editable plugin source until deliberate split to separately pinned distribution repo |
| `integrations/omarchy/resources/{desktop,configuration}/` | Resource owners; protected operations, no controller authority substitute |
| `integrations/omarchy/{qualify.py,tests,fixtures}/` | Integration/qualification owner; real effect oracles and structural unit tests distinctly labeled |
| `packaging/omarchy/` | Release maintainer; package/service/support-tuple source and provenance |
| Existing native/Pi packages | Their respective owners; prerequisite fixes delivered and independently qualified upstream of controller |

Before writing files, inspect the current tree and refresh the source crosswalk.
If an equivalent native contract exists by then, adapt and test it instead of
creating a duplicate. Preserve dirty work using an isolated worktree. Respect
repository checks and document any pre-existing failures separately.

## Proposed qualification harness ABI

The harness is future work. Its shared CLI is:

```bash
python3 integrations/omarchy/qualify.py --phase P2 --profile project-v1 --bundle /absolute/qualified-bundle.json --output /absolute/new-evidence-dir
```

- `--phase`: exactly P0 through P7; evaluates that phase and its declared gates.
- `--profile`: exact enrolled release-profile ID, never an arbitrary policy file.
- `--bundle`: immutable selected tuple plus prerequisite/evidence commitments,
  validated against trusted release/native identities before any effect.
- `--output`: fresh directory for a run, refusing overwrite or symlink escape.
- `--fixture-only`: structural/component harness mode, always synthetic and incapable of runtime qualification.
- `--case AT-...`: optional repeatable selector for debugging. Selected runs are
  partial evidence and can never mark a profile qualified.
- `--verify-only`: reads an existing output directory, checks artifacts/coverage/
  tuple freshness and has no runtime effects. It refuses missing or stale evidence.

Exit 0 means all requested checks passed at their declared evidence class. Any
failed, missing or inapplicable unreviewed prerequisite returns nonzero. Runtime
qualification requires full current-profile case coverage and independent review;
exit 0 from a component or selected-case invocation cannot promote a release.

P0 must deliver a reviewed profile applicability matrix over every normative
requirement, distinguishing full acceptance, required disabled-feature refusal,
and structurally inapplicable requirements with reasons. No runner may infer
coverage from the traceability file's `planning_phase`. Refusal variants must
specify their own inputs/oracle/artifact and cannot claim the full enabled test
passed. A missing applicability decision blocks profile qualification.

## Work discipline and handoff

- [ ] Select one phase/profile and verify each prerequisite artifact before coding.
- [ ] Add the named failing test; record its expected failure cause, not merely a nonzero exit.
- [ ] Implement the smallest contract path that makes the positive and negative cases pass.
- [ ] Run the phase's focused checks and real environment acceptance where required.
- [ ] Request independent review of authority, identity, race and recovery boundaries.
- [ ] Commit the bounded change with evidence; report source, local checks, runtime qualification and publication separately.
- [ ] Leave later profiles unavailable until their own gates close.

The detailed plans contain concrete file maps, test sketches, red/green commands,
commit checkpoints and exit evidence. Their test names are proposed delivery
targets; they are not existing passing tests.
