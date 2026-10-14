# Publication execution record

2026-10-03 architecture revision (base `f4a4c4db9f`): the approved revision is
complete. The abstract and introduction state the kernel architecture;
Section 2 develops admission, programmable sovereignty, treaties, state ownership
and trust boundaries before the delegated-work construction. A new diagram
shows two locally governed kernels. Implementation, evaluation, related work,
scope and conclusion follow that argument. The title and all experimental
results remain unchanged. Plan: `ARCHITECTURE-PLAN.md`; review:
`ARCHITECTURE-REVIEW.md`.

One fresh automated reviewer found no Critical or Important defect and two
Minor issues. Both were repaired: the abstract now briefly identifies the
implemented runtime and local evaluation before its architectural conclusion,
and the artifact reading guide matches the revised sections. Coordinator
verification covered the repairs and rendered abstract, architecture, slot
definition, proposition and conclusion. No finding is deferred; no second
review or independent human peer review is claimed.

Verification for this revision:
- Baseline artifact check: passed.
- Existing artifact-tool suite: 13 passed, zero failed.
- First freeze and build: failed with native inventory drift. Exact comparison
  found one added editorial plan, zero changed inputs and zero removed inputs.
  Moving the plan into the separately qualified paper directory restored all
  36,556 inputs. Neither verifier nor native evidence was changed.
- Final render, freeze and build: passed; 658 artifact files agree.
- PDF: 19 pages (14 main, two references, three appendices), 361,747 bytes;
  rebuild is byte-identical. No LaTeX warnings or overfull/underfull boxes.
- All 28 unchanged claim records and evidence paths resolve; all 30 local links
  in the revised companion documents resolve.
- Proposition, proof and qualification tail are byte-identical to the base.
  Native code, formal programs, experiments and artifact tools are unchanged.
- Publication check: expected exit one for independent operation, useful-work
  economics, integration advantage, foundational claim and the two false
  readiness flags. No artifact failure remains.
- PDF SHA256: `0b923c230e45fbcd8293f20dd4cef4bb3ddb5bd535460a4d9f8402bafc8daa7b`.

Execution decisions: use the existing isolated paper worktree and the user's
explicit execution authorization; validate this prose revision with rendering,
semantic review and existing artifact checks; repair both editorial findings
within the requested quality bar; keep the editorial plan in the paper package
to preserve exact native qualification. No new implementation test campaign,
external publication, shared-branch merge or research-gate promotion is implied.
The review's declined scopes remain explicit in ARCHITECTURE-REVIEW.md.

2026-10-03 explanatory revision: the user approved the prose critique and asked
for its execution. The bounded design is to replace component inventory and
repeated significance statements with a causal argument: define the work
commitment, expose substitution and replay across changing plans, derive the
binding and durable-state rules, then establish the preservation guarantee.
The title, implemented behavior, trust premises and recorded results remain
fixed. The work is confined to the paper and its companion records.

Execution checklist:
- [x] Rewrite the abstract and main argument for readers unfamiliar with Chio.
- [x] Retain every technical premise, comparison and evidence boundary while
      replacing implementation shorthand with definitions and causal explanations.
- [x] Obtain a fresh prose and technical review; repair concrete findings.
- [x] Render, inspect layout, validate claims and source continuity, freeze,
      reproduce the PDF and commit the revision.

2026-10-03 explanatory revision acceptance: the approved revision is complete.
Fresh automated prose and technical review identified two Important and three
Minor findings. All five were repaired and rechecked with no remaining findings
in the reviewed scope. The record is PROSE-REVIEW.md. The coordinator then cut
repeated setup and inspected the final abstract, worked receiver mismatch,
protocol figure, graph-version table, proposition and conclusion. The scientific
premises, implementation, proof program and measured results are unchanged.

The final PDF has 17 pages (12 main text, two references, three appendices),
354318 bytes, SHA-256
6d63cd4e8e7268ee08c12fbb358361d5a13fc76c2a6bda4026fb556e71f8de80.
The render has no LaTeX warnings or overfull/underfull boxes. All 28 claim records
retain complete fields, unique IDs and existing evidence paths; all 30 local
Markdown links checked in edited documents resolve. Labels and references agree.

The final render, artifact freeze and make build pass. The build reproduces the
frozen PDF bytes and verifies all 656 artifact files, current native inventory,
historical source pins, bibliography and derived results. The inventory changes
15 existing paper files and adds one review record. No native input, formal
program, experiment or artifact tool changes. Native inventory digest remains
865a331ba3a022f8ee11554a878c0f07727a754190dda36624bdc4e7cf3d24bd.
No native tests were rerun for this prose revision. Git diff --check passes.

The publication check exits one for the four unchanged open gates (independent
operation, useful-work economics, integration advantage and foundational
critique) and the two false readiness flags, with no artifact error. Prose review
does not supply new independent-operation or breakthrough evidence. The work
remains on its isolated paper branch; no merge, push or publication is performed.

2026-10-03 manuscript revision: the user redirected the next chunk from an
outside trial to making the paper itself complete and compelling, then specified
writing from the completed contribution. This is a bounded revision of the
existing manuscript, authorized by that direction. Preserve the locked title,
existing protocol and evidence; strengthen the claim, explanation and structure.

Revision plan: (1) state the kernel contract and programmable sovereignty first;
(2) organize delegation, admission, graph evolution, recovery and payment around
one commitment and one running example; (3) present the composed preservation
argument with explicit premises; (4) consolidate measured results and prior-art
comparisons, with exact profile details in an appendix and development history
in the companion; (5) obtain a fresh technical/editorial review, repair findings,
render, visually inspect and freeze the final artifact. No new experiment,
independent-operator result, formal refinement or economic advantage is inferred
from this change in voice. Native source and its qualified evidence remain the
implementation boundary; manuscript validation is the relevant changed boundary.

2026-10-03 editorial acceptance: all five revision steps are complete. The main
text now presents the completed protocol through programmable sovereignty, one
work commitment, one running example and one preservation proposition. The
abstract and conclusion state the contribution directly. Profile definitions and
qualification detail are retained in two technical appendices. Fresh automated
review closed one Important and three Minor findings; its follow-up accepted
the reviewed scope with no remaining findings. `EDITORIAL-REVIEW.md` records
the repairs and review boundaries.

The final PDF is 17 pages (12 main text, two references, three appendices),
332736 bytes, SHA-256
`ebbd609b563014ee15866a93f485792c7474ce275e8a67888250f311f085b5dd`.
Visual checks cover the abstract, protocol figure, conclusion and evidence
appendix. The LaTeX log has no warnings or overfull/underfull boxes. All 28 claim
records have their required fields, unique IDs and existing evidence paths;
all 28 local Markdown links checked in the edited documents resolve.

`make render`, `python3 -B tools/check.py --freeze` and `make build` pass. The
last build reproduces the frozen PDF bytes and validates all 655 artifact files,
current native inventory, historical source pins, bibliography and derived
results. The inventory comparison contains only 15 changed paper files and
three new paper files; no native input, proof program, tool or retained evidence
output changed. `git diff --check` passes. No native tests were rerun for this
editorial revision.

The publication check exits one for exactly the four retained open gates
(independent operation, useful-work economics, integration advantage and
foundational critique) and the two false readiness flags. This verifies their
unchanged status; the completed manuscript revision supplies no new experiment
or outside review. The paper remains on its isolated branch, with no merge,
push or external publication performed.

2026-10-03 composed execution revision: the user reiterated execution using
existing delegation, swarm authority and treaties. The active plan is
`docs/superpowers/plans/2026-10-02-evolving-funded-work.md`. The composed
trajectory passes through real parent SIGKILL, original child withdrawal and
unchanged physical claims. The new receiver controls and eleven native export
tests pass. Fresh automated review closed two Important findings. Implementation
and qualification tools are committed as `d46524ee8c`. All 21 source-bound
commands pass against 36,556 unchanged inputs and 48 hashed outputs; six
additional opt-in chain regressions pass against the identical inventory.
The paper now
states one local composed result and distinguishes local execution from final
bilateral receipt delivery. No outside operator or economic-advantage result
has been added. Historical entries below retain their original scope.

2026-10-03 final composed acceptance: all three implementation-plan tasks are
complete. Rust totals by boundary are 54 workflow (one pre-existing ignored
doctest), 10 native delegation labels (including the worker), 5 existing native
composition, 453 swarm/runtime, 11 execution export, 25 durable SQLite and
91 default standalone tests. The six default opt-in skips pass in their own
explicit chain run, making 97 standalone cases exercised. Three Node wire tests,
13 artifact tests, the composed SIGKILL trajectory and four existing child
crash subcases pass. Four strict Clippy commands and all three format commands
pass. The new run does not overwrite historical source qualifications.

Final manuscript/artifact checks pass and the 19-page PDF rebuilds byte-for-byte.
Edited links and all 28 claim records resolve. The publication command exits
one for exactly independent operation, useful-work economics, integration
advantage, foundational critique, and the two false readiness flags. This is
the expected open research boundary, not a local validation failure. The paper
and source remain on the isolated branch. The next decisive tasks and public
receiver package are in `docs/research/evolving-funded-work/NEXT.md`.

2026-10-02 swarm evolution revision: the user reiterated execution through review
and manuscript update, with explicit reuse of swarm authority, treaties and
delegation. The new plan is
`docs/superpowers/plans/2026-10-02-sovereign-swarm-evolution.md`. The pure extension
verifier and atomic SQLite history installer are committed. Seven focused
store/native cases pass. The manuscript now states the additive conservation
argument alongside D1 and retained F1. Full changed-crate qualification and one
fresh combined review are in progress. Initial build and fixture failures are
retained; no new independent operator or scientific-breakthrough result is
claimed.

2026-10-02 dynamic delegation revision: the user explicitly authorized further
design, implementation, review and manuscript edits. The active plan is now
`docs/superpowers/plans/2026-10-02-dynamic-delegation.md`; its result and review
live in `docs/research/dynamic-delegation/`. The records below preserve the
earlier funded manuscript's completed work. They are not current qualification
for the changed native source or the new paper argument. External publication
and foundational-claim gates remain open.

Plan: `docs/superpowers/plans/2026-10-02-verifiable-work-publication.md`.

2026-10-02: isolated branch `paper/verifiable-work-20261002` starts at funded checkpoint `7755d3762b`. User authorized executing the approved direction continuously. Current security worktree is dirty; only committed `491f585e90` is eligible for this integration. The dry merge has 21 conflict paths. Dedicated integration runs at `/tmp/chio-paper-security-integration`.

Task 1: in progress. Tasks 2-4: pending.

Ruling: retain the complete approved research gates and distinguish a finished manuscript from an established breakthrough. Local actors cannot supply evidence of independent administration. This avoids presenting an author-controlled test as independent adoption.

2026-10-02 local evidence: finite model 18 tests; 5,508 states and 132,192 transitions; 118 representative traces; actual contract suite 143 passed; deliberate expiry mutants fail for the intended earned-refund reason. Ordinary SQLite matches 312 non-time steps, with a separate manually specified counterexample schedule. Lean 4.28.0 checks seven named abstract results without unchecked proof placeholders. Artifact-tool tests progressed from three comparator red cases, through five passing checks, to two added publication-gate red cases and seven passing checks.

Task 2: locally complete. The argument states capital and verifier assumptions, distinguishes recorded acceptance from off-chain signatures, and explicitly disclaims implementation refinement. The closest real baseline is unmodified ERC-8183 at 142e669c1f: 76 upstream and 20 comparison tests pass, including relocation reproduction. It reproduces independent-child payment and has partial settlement. This materially narrows the novelty claim.

Task 3: complete manuscript drafted; final integrated evidence and fresh review remain. Main text is compact, the PDF builds, bibliography resolves, and the figure and evaluation pages have been visually checked. No economic or independent-operation result is invented.

Ruling: add the pinned upstream ERC-8183 comparison, beyond the original ordinary-ledger comparator, because it is closer prior art. Cost if wrong: additional review scope, with no withheld capabilities or artificial economic advantage assigned to Chio.

Ruling: strengthen the publication checker to reject deleted required gates and false readiness flags. Cost if wrong: maintainers must version an explicit gate change instead of accidentally publishing through an empty list.

2026-10-02 user clarification: no partner available; prepare the external trial package. Added the original three core operators, newcomer, two independent provider implementations, four arms, original thresholds, profile hashes, operator runbook and prospective data templates. External execution remains unperformed.

Task 1 native progress: combined-source snapshot v2 passes 95 standalone tests including six opt-in chain tests, authenticated peer payout/refund, isolated bilateral payout/refund, and four earned-child process cases. Python 38-test suite passes against the immutable v2 binary. Integration found and repaired a delayed-attestation enrollment clock bug with a red/green regression. Strict Clippy found one redundant dereference; the integration record will retain the exact v2-to-final source delta. Root paper checks do not turn inherited formal-mirror or file-hygiene failures into a qualified security release.

Task 1: complete for the declared local research boundary. Combined source committed as 71e5cbc3bf, with immutable v1/v2/v3 inventories. Full v2 native run: 95 tests, no ignored or failed cases; 20 selected process scenarios. Final v3 differs only by the retained redundant-dereference patch; strict Clippy, four peer unit tests and authenticated payout/refund pass on final source. The 38-test Python checker run is pinned to v2. All old failures remain labelled. Broader release gates remain open, not waived.

Task 4: artifact assembled and hash/PDF/bibliography check passes. External handoff includes frozen profile hashes, prospective manifests, attempt records and original analysis thresholds. Fresh whole-artifact review is pending; final readiness is not asserted.

Final review: fresh automated reviewer found no Critical/Important issue and independently reproduced the PDF bytes, selected contract cases, full paired Foundry cases, model tests, artifact tests and Lean. Its complete bounded judgment and declined-to-judge dispositions are recorded in REVIEW.md. This is not external human critique or an independent operator trial.

Final Ruling: close both reviewer Minor documentation findings now, honoring the user's explicit publication-quality bar. Q1-Q10 is restored in the trial labels and the versioned claim register has every specified traceability field plus the original H1-H5 crosswalk. Cost if wrong: a small additional documentation pass; no implementation behavior or experimental threshold changes. Documentation verification checks all 19 records and referenced paths; no implementation tests were added for these reversible prose/data changes.

Final Ruling: the inherited security audit, full/hosted release qualification, off-host/finality/hostile-administration evidence, external economics and exhaustive novelty remain outside the achieved local boundary. Each remains explicitly unqualified in REVIEW.md and the research gates; the cost of retaining this boundary is that the requested breakthrough/publication judgment remains no.

Task 4: local manuscript/artifact/trial-package work complete after the final check. Both review findings fixed; no deferred minor findings. All four implementation-plan tasks have concrete deliverables. Original external research gates are still open and are not marked completed by those task checkboxes. Branch remains local and reviewable, without public release, shared-branch integration or partner contact.

2026-10-02 final D1/S1 qualification: all 11 commands exited zero against
36,549 recorded source inputs and 23 hashed outputs. Rust labels: 54 workflow
(1 pre-existing ignored doctest), 9 native delegation, 5 existing native
regression, 453 swarm/runtime; 12 artifact tests pass. Three strict Clippy
commands, two format commands and the runnable example pass. Fresh automated
review found one Important namespace flaw; both cross-owner regressions failed
before the fix and pass afterward. An additional configured-clock regression
failed before the guard adopted the existing kernel clock, and now passes.
The exact review, declined scopes and repair evidence are retained.

Final ruling: follow the approved plan by retaining the isolated paper branch,
without reopening an integration-choice prompt. No main-branch merge, external
publication, operator trial or production release is inferred. Rebuilt PDF and
artifact checks pass; the breakthrough and independent research gates remain
false/open. The next concrete integration is recorded in
docs/research/swarm-evolution/NEXT.md.
