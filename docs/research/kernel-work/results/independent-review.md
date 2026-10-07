# Tasks 5-7 review provenance

This file records fresh automated adversarial review. It is not independent
human expert review or an independently operated experiment. No outside partner
is available, and none was contacted.

The review input includes the approved design and plan, G0-G3 decisions, strong
counterdesign and failed hypotheses, source pins, native and family experiments,
the contribution decision, and the execution ledger's rulings. The five required
review focuses are unknown effects, owner-bound composition, settlement versus
revocation, useful progress, and a fair provisioned baseline.

Reviewer: fresh `kernel_tasks567_review` automated agent. Reviewed source range
`188031256600903676eb69bda3144b9e8a1660da` through
`bc3ed4a1839b1a99316f50f9947a0596dcc6d00d`. Verdict: **with fixes**. No Critical
finding or new production/family safety defect. The reviewer agreed that the
contribution decision and open full-native/independent gates were justified.

## Findings and one fix pass

1. **Important: aggregate provenance omitted prerequisite dependencies.**
   The new checker validated saved successful-check logs without checking that
   the earlier model evidence was still valid. A read-only overlay changed
   `results/model/explorer.stdout`; the aggregate checker accepted it with zero
   reads while the original checker rejected its hash. The
   [reviewer probe](followthrough/reviewer-probe.py) and
   [output](followthrough/reviewer-probe.stdout) are retained.

   Four [regression tests](../test_followthrough.py) reproduced changed prior output, prior manifest, G0
   claim register and verifier script being accepted:
   [red output](followthrough/review-red.stderr),
   [exit](followthrough/review-red.exit.json). The fix binds the complete declared
   prior-model source/output closure and manifest, G0 input files and verifier
   scripts. Aggregate verification also reruns the two inexpensive structural
   checks, including frozen-manuscript validation. All four regressions then
   pass: [green output](followthrough/review-green.stderr),
   [exit](followthrough/review-green.exit.json).

2. **Resume instructions described completed local work as future work.**
   The reviewer graded this Minor. The executor treats inaccurate handoff state
   as Important here because the user explicitly requested preserved continuity
   and it can cause repeated experiments. The README now separates completed
   local Tasks 5-6 work, open native/independent gates and the Task 7 decision;
   its stale recommendation of separately novel R2 was also corrected. Direct
   inspection and the documentation/provenance checks verify the change.

There is one fix pass and no second reviewer endorsement. The final
[qualification record](followthrough/verification.json) binds the corrected
checker and all tested inputs. The complete earlier record is retained in
`followthrough/pre-review/`. No deferred minor findings remain.

## Independently rerun by the automated reviewer

- Three family test functions; 28 comparison cases, 17 shared-adapter refusals.
- The native cross-owner binary: both substantive tests and both subprocess
  helper entrypoints passed, including all 10 death schedules and the retry control.
- Three contractual-resolution tests, including isolated expiration rejection.
- Aggregate record, original model record and G0 provenance checked separately.
- Frozen manuscript tree confirmed as `b8c5b771ca04903e219f9b42a50a050d326ba0ac`.

These are independent checks by another automated context on the same local
machine. They do not satisfy the independent operator or human expert gates.

## Explicitly unjudged boundaries

The reviewer set aside full mediated cross-owner approval/artifact/money
composition; universal confinement, arbitrary traces and dynamic graphs;
cryptographic or multi-artifact refinement; actual production connector retry
qualification; independent integration advantage, human scientific endorsement
and useful economics; full-workspace/hosted/deployment readiness; and a fresh
literature-wide novelty determination. The executor accepts these as open
boundaries already stated in G3 and the contribution decision. None is promoted
by this review or by passing local tests. G4 remains unsupported.
