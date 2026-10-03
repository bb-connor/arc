# Manuscript review: programmable sovereignty and preserved commitments

Date: 2026-10-03. Manuscript base: `03dcfafae1` on
`paper/verifiable-work-20261002`. Scope: the working-tree manuscript revision
following that commit and the repairs listed below.

The user requested a completed-contribution paper centered on the agentic kernel
vision. The revision organizes the existing protocol around one rule: plans may
evolve while issued commitments retain their bounds and identity. It connects
programmable sovereignty, delegation, treaty admission, graph growth, recovery
and settlement through one running example and one preservation proposition.
Concrete profiles and detailed qualification records move to two appendices.

## Review and disposition

A fresh-context automated reviewer examined the manuscript against the native
implementation, protocol specifications, qualified composed trajectory and
retained comparison evidence. The reviewer left the checkout unchanged and did
not rerun native tests. This was technical and editorial review within the
project, not independent human peer review.

The first pass found one Important and three Minor issues. The author repaired
all four, and the reviewer rechecked them against the revised source. The final
judgment was: accepted for the reviewed manuscript scope, with no remaining
Critical, Important or Minor findings.

| Finding | Repair | Disposition |
| --- | --- | --- |
| Important: the composition argument left exclusive pool custody and initialization implicit | Section 2 states one protected graph lineage per declared pool and one protected execution/budget domain per receiving key; Section 5 gives valid initialization and the induction base | Closed |
| Minor: the encoding summary appeared to apply canonical JSON to every signed body | Section 3 distinguishes native canonical JSON from EIP-712 settlement decisions | Closed |
| Minor: a new accounting interval could appear to reset accounts with outstanding locks | Section 5 fixes one deposited cohort, keeps refunds as outflows, and accounts later deposits separately without releasing earlier locks | Closed |
| Minor: the intermediary appeared before its role was explained | Section 1 introduces it as the buyer's agent commissioned to review an API | Closed |

The reviewer also checked that the four-party diagram places the agreed verifier
between execution evidence and the escrow decision, with a separate backing
observation before dispatch. Appendix consolidation preserves source epochs,
representative versus exhaustive coverage, default skips versus separately
exercised cases, and the distinction between the conditional argument and a
mechanized implementation refinement.

The final coordinator pass tightened the conclusion and bibliography layout,
updated the companion documents, and visually checked the abstract, protocol
figure, conclusion and evidence appendix. The rendered paper has 17 pages:
12 of main text, two of references and three of appendices. The build reports no
LaTeX warnings or overfull/underfull boxes.

## Evidence boundary

This revision changes no native implementation, formal proof program, experiment
or comparison tool. The current qualification still binds 36,556 source inputs
and 48 outputs to 21 terminal commands. Its canonical source inventory digest is
`865a331ba3a022f8ee11554a878c0f07727a754190dda36624bdc4e7cf3d24bd`.
The six opt-in chain regressions retain their separate result on that inventory.
See the [composed implementation review](../../research/evolving-funded-work/REVIEW.md)
and [artifact companion](ARTIFACT.md) for their exact scopes and earlier evidence.

The final artifact procedure is `make render`, `python3 -B tools/check.py --freeze`,
then `make build`. It verifies native inventory continuity, historical source
pins, derived results, citations, PDF contents and frozen file hashes. The final
execution record is in [PROGRESS.md](PROGRESS.md). No native test totals are
credited to this editorial work.

The reviewer declined to judge exhaustive novelty, independent operation or
interoperability, economic or integration advantage, production or whole-workspace
security, public-chain finality, mechanized implementation refinement, and
publication or merge readiness. These boundaries retain their existing status
in [PUBLICATION.json](PUBLICATION.json). The completed contribution and its
scientific premises are presented directly in the manuscript; its measurements
retain their actual provenance.
