# Explanatory revision: prose and technical review

Date: 2026-10-03. Base: `edcc13af39` on
`paper/verifiable-work-20261002`. Reviewed material: the subsequent working-tree
revision of the abstract and main manuscript, with the unchanged technical
appendices and retained source evidence.

## Editorial requirement

The revision was required to define the work commitment, demonstrate the failure
it prevents, explain the construction and derive the guarantee. The previous
draft relied too heavily on component lists, implementation vocabulary and
repeated statements of significance. Successful building and technically
defensible claims were insufficient evidence that its prose was finished.

The revised introduction develops a lost-intermediary example and a replay
problem caused by graph versions. Section 3 constructs the commitment and
demonstrates a validly signed receiver mismatch. Section 4 follows one execution
right across versions, then explains admission, recovery and payment. Section 5
derives the conditional preservation result. Programmable sovereignty follows
from the receiving owner's control over admission throughout these operations.

## Fresh review and repairs

A fresh-context automated reviewer read every main section and both appendices,
compared the base manuscript, and inspected focused implementation and evidence
records. It judged the explanatory argument and prose as well as the retained
technical premises. The review was read-only and ran no builds or native tests.

The first pass found two Important and three Minor issues, with no Critical
finding. All five were repaired and rechecked by the same reviewer.

| Finding | Repair | Final disposition |
| --- | --- | --- |
| Important: cross-record checks used graph concepts before explaining them and lacked a worked failure | Section 3.4 defines the graph's allocation, routing and authorization roles, then shows a valid permit for receiver R1 combined with a signed route to R2 and identifies the comparison that rejects it | Closed |
| Important: the running example assigned survey commissioning and payment inconsistently | The introduction and evaluation identify the buyer as funder of the survey and follow-on review, the intermediary as the survey's named beneficiary, and the intermediary's own funds as the specialist's backing | Closed |
| Minor: the preservation proof left recovery implicit | The induction explicitly covers stored permits and output, retained unknown outcomes, consumed execution rights and reuse of the original settlement transaction | Closed |
| Minor: operation referred both to a tool action and its durable record | The proposition says tool operation; admission and recovery refer to the execution record | Closed |
| Minor: the abstract's chronology was ambiguous and its closing declaration repeated significance | The specialist is added after the initial survey returns; the abstract ends with the concrete result | Closed |

The reviewer accepted the revised manuscript within this scope, with no
remaining Critical, Important or Minor findings from its review. Its judgment
was that the central object, failures, checks, durable transitions and
conditional guarantee now form a coherent argument; another substantial
rewrite was unnecessary.

After that recheck, the coordinator shortened repeated introductory setup and
section navigation, without changing the reviewed mechanisms or premises.
The final coordinator pass also kept the proposition together on its page,
started the references on a separate page, and checked the rendered abstract,
worked mismatch, graph-version table, proof and conclusion.

## Evidence and validation

The title, experimental outputs, comparison results, native implementation,
formal program and artifact tools are unchanged. Native qualification remains
the existing record of 21 terminal commands, 36,556 inputs and 48 outputs,
plus the separately recorded six opt-in chain regressions. No test totals are
attributed to this prose revision.

The rendered PDF has 17 pages: 12 main text, two references and three appendices.
The final LaTeX log contains no warnings or overfull/underfull boxes. Artifact
validation uses the existing sequence: render, freeze reviewed sources, and
rebuild against the frozen hashes. The terminal results and final PDF digest
are recorded in [PROGRESS.md](PROGRESS.md).

The reviewer did not judge native correctness beyond focused reads, PDF layout,
artifact reproducibility, exhaustive novelty, foundational significance,
institutional endorsement, independent operation, production security,
public-chain behavior, economic advantage, or publication and merge readiness.
The coordinator handles layout and artifact validation separately. The other
boundaries retain their existing status in [PUBLICATION.json](PUBLICATION.json).
This automated review is not independent human peer review.

The [earlier editorial record](EDITORIAL-REVIEW.md) and
[implementation review](../../research/evolving-funded-work/REVIEW.md) retain
their original scopes.
