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

## Boundary metadata and inheritance

[ADR-0011](../../../adr/ADR-0011-boundary-taxonomy-product-wording.md) requires separate `boundary_class` and `planning_status` fields. Each plan identifies its individual control, observation and guidance boundaries below its title; the index preserves those scope-to-field mappings. Boundary classes describe the proposed control point, not implementation or runtime qualification. `ready_after_adr` rows rely on accepted ADR-0011 for the stated evidence/research planning only; named missing artifacts still block execution and qualification.

The current numbered specifications remain the normative proposed contract for consistency review. The [architecture review](../../specs/2026-10-07-omarchy-integration/reviews/2026-10-07-architecture-review.md#decisions-needed-from-the-owner) is non-normative and does not supersede them. Its owner decisions on the first product (F1), shared desktop ABI/program (F2), native contract sequencing (F3) and Omarchy scope/ownership (F5) remain unresolved. Product implementation is `blocked_by_adr` pending those decisions; the review's proposed replacement, cuts and delegation transfer are not approved. F4 concerns the macOS isolation direction and is not an additional Omarchy runtime gate. The metadata does not authorize runtime implementation.

Every derived task and implementation ticket touching a trust boundary must inherit the matching scope's `boundary_class`, `planning_status`, owner-decision blocker and execution prerequisites as separate structured fields. A task crossing multiple scopes must retain one pair per boundary. Do not summarize observation or guidance as preventive mediation, or promote a child ticket past an unresolved parent decision. An accepted owner decision must update the relevant metadata and contracts together before implementation status changes. UI/SIEM tasks must preserve `receipt_kind` alongside `boundary_class`, as ADR-0011 requires.

## Ordered execution

| Plan | Deliverable | Depends on | `boundary_class` by scope | `planning_status` by scope |
| --- | --- | --- | --- | --- |
| [00 Native prerequisites](00-native-prerequisites.md) | Exact source/package tuple, native contracts and fail-closed capability inventory | Source research; named native owners | `capability_admission=prevent`; `native_observation=detect_only`; `source_inventory=advisory_only` | `capability_admission=blocked_by_adr`; `native_observation=ready_after_adr`; `source_inventory=ready_after_adr` |
| [01 Controller and plugin](01-controller-and-plugin.md) | Shared ABI/store/shim and read-only actual Omarchy surface | P0 read-only tuple | `operator_admission=prevent`; `status_projection=detect_only`; `navigation_guidance=advisory_only` | `operator_admission=blocked_by_adr`; `status_projection=blocked_by_adr`; `navigation_guidance=blocked_by_adr` |
| [02 Confined project task](02-confined-project-task.md) | Trusted import, one protected Pi task, fixed tests and review artifact | P1 and all P2 native/Linux/provider gates | `guest_admission=prevent`; `provider_observation=detect_only`; `provider_internal_execution=cannot_see`; `review_projection=advisory_only` | `guest_admission=blocked_by_adr`; `provider_observation=ready_after_adr`; `provider_internal_execution=hard_skip`; `review_projection=blocked_by_adr` |
| [03 Approvals and publication](03-approvals-publication.md) | Native exact decision and enrolled reviewed destination | P2 and native decision fix | `approval_and_publication=prevent`; `review_guidance=advisory_only`; `outcome_observation=detect_only` | `approval_and_publication=blocked_by_adr`; `review_guidance=blocked_by_adr`; `outcome_observation=ready_after_adr` |
| [04 Desktop resources](04-desktop-resources.md) | Closed metadata tools and exact workspace effect | P3 and pinned compositor | `desktop_admission=prevent`; `compositor_observation=detect_only`; `reserved_window_actions=prevent` | `desktop_admission=blocked_by_adr`; `compositor_observation=ready_after_adr`; `reserved_window_actions=deferred` |
| [05 Configuration repair](05-configuration-repair.md) | Single-file scalar repair with bounded reload | P4, writer exclusion and reload closure | `file_apply_and_reload=prevent`; `diagnosis_and_preview=advisory_only`; `repair_observation=detect_only` | `file_apply_and_reload=blocked_by_adr`; `diagnosis_and_preview=blocked_by_adr`; `repair_observation=ready_after_adr` |
| [06 Delegation](06-delegation.md) | Attenuated children, aggregate reservations and recovery | P3 and separate native child contract | `child_admission_and_custody=prevent`; `child_status_projection=detect_only`; `remote_custody=prevent` | `child_admission_and_custody=blocked_by_adr`; `child_status_projection=blocked_by_adr`; `remote_custody=deferred` |
| [07 Distribution and qualification](07-distribution-qualification.md) | Real Linux evidence and independent install/update/rollback/removal | Only the exact profiles selected for release | `activation_and_profile_gates=prevent`; `independent_observation=detect_only`; `release_claims=advisory_only` | `activation_and_profile_gates=blocked_by_adr`; `independent_observation=ready_after_adr`; `release_claims=blocked_by_adr` |

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
