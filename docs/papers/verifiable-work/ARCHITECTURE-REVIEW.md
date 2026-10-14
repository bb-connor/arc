# Kernel architecture revision: manuscript review

Date: 2026-10-03. Base: `f4a4c4db9fd13fb25dd6a89318e4725bf024b710` on
`paper/verifiable-work-20261002`. Reviewed material: the subsequent working-tree
revision of the manuscript and companions. The
[revision plan](ARCHITECTURE-PLAN.md)
preserves the user-approved design brief.

## Argument and scope

The abstract and introduction present Chio as a kernel architecture that
separates agent planning from the authority and durable execution state
governing its effects. Section 2 defines the host and kernel boundary, local
admission, programmable sovereignty, treaties, distributed program state and
trust assumptions, with a diagram of two independently governed domains.
Sections 3-5 develop the work commitment, its lifecycle and the conditional
preservation result. Section 6 evaluates these mechanisms through the retained
composed execution. The running example now follows the architectural model.

The revision introduces no replacement API, wire profile or authority store.
Its architectural account uses the existing capability, guard, receipt, treaty,
delegation, swarm, recovery and settlement mechanisms. The preservation
proposition, proof and subsequent qualifications are byte-identical to the
base revision. Their premises and scope continue to govern the claim.

## Fresh review and repairs

One fresh-context automated reviewer read the complete manuscript, both
appendices, README, revision plan and diff. Focused checks covered the profile
protocols, composed results and review, claim register, artifact mapping,
Lean specification and composition source. The review was read-only and ran
no native suites.

The reviewer found no Critical or Important manuscript defect. It judged that
the revision explains the architecture before the experiment, and that the
organization and explanation changed substantively. It found two Minor issues:

| Finding | Repair | Verification |
| --- | --- | --- |
| The abstract no longer identifies implementation or empirical evidence, leaving readers unsure whether the paper describes a realized system | Added one sentence identifying Chio's runtime and evaluation of plan growth, process loss and settlement under one administrator, before the final architectural consequence. Rust is identified in Section 6, where the implementation is described | Coordinator read the final abstract against Section 6 and the retained composed result |
| The artifact guide still placed the failed-intermediary example in Sections 1-2 | Updated the guide to locate the architecture in Sections 1-2, the example in Section 3 and admission, recovery and payment in Section 4 | Coordinator checked the guide against the final section headings and contents |

Both findings are addressed. No review finding is deferred. The coordinator
also corrected README agreement, applied widow/orphan penalties, and kept the
slot definition and proposition together with their explanatory text. The final repairs were checked by the coordinator;
no second reviewer pass is claimed.

The reviewer found the prose professional and precise, with the architectural
terms explained through state ownership, reference checks and lifetime rules.
It explicitly retained the following boundaries: host confinement, local trust
selection, protected non-forking custodians, additive growth, enrolled principals,
distinct admission and settlement decisions, unknown external outcomes, and
local execution evidence versus final bilateral delivery. Its verdict supports
completion of this editorial revision after artifact and rendering checks.

## Evidence and verification

The native implementation, formal program, experimental outputs, comparison
results, claim register and artifact tools remain unchanged. The current native
qualification still consists of its retained 21 terminal commands, 36,556 inputs
and 48 outputs, with six separately recorded opt-in chain regressions. These
are prior implementation results, not tests rerun for this revision.

The existing artifact-tool suite was run for this revision: 13 tests passed.
The first freeze and build reported native inventory drift: the newly added
editorial plan outside the paper directory was counted as a native input. A full
inventory comparison found that one addition, with no changed or removed native
inputs. Moving the plan into this separately qualified paper package restored
the exact 36,556-input inventory. Verification logic and qualification records
were not changed.
The coordinator handles final rendering, citation and link checks, source
scope, artifact freezing and reproducible rebuilding. Terminal results and
the final PDF digest are recorded in [PROGRESS.md](PROGRESS.md).

The reviewer declined exhaustive novelty determination, independent human peer
review, fresh experimental reproduction, rendered-page inspection, complete
implementation security audit, production readiness, independent-operation
qualification, economic advantage and publication-gate closure. Rendering is
verified separately by the coordinator. Fresh artifact-tool checks do not
reproduce the native experiments. All other declined scopes remain outside
this revision's completion claim; their research and release gates retain their
existing states. This is automated manuscript review, not external peer review
or evidence of a foundational breakthrough.

The [previous prose review](PROSE-REVIEW.md),
[earlier editorial review](EDITORIAL-REVIEW.md) and
[implementation review](../../research/evolving-funded-work/REVIEW.md) remain
available at their original scopes.
