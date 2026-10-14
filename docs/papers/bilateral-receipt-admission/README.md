# Bilateral Receipt Admission (retired)

Retired as of September 2026. This paper must not be circulated, submitted, or
cited. Its sources are kept only as a design note.

The verifier order, rejection-code taxonomy, wire format, and subject-digest
definition the paper describes do not match the shipped construction, and two
of the attacks it claims to defeat (single-lane witness compromise and
operator-attributed signer reuse) have no mechanism in the code. What it says
about the predicate is therefore not a description of Chio, and a reader who
checks one gate, one code, or one field name against the repository will find
it wrong.

The normative description of the predicate, its envelope, and its verifier is
[spec/CHIO_BILATERAL_COSIGN_INVOCATION.md](../../../spec/CHIO_BILATERAL_COSIGN_INVOCATION.md).
The surviving paper is [programmable-sovereignty](../programmable-sovereignty/README.md),
"Receiver-Owned Bilateral Admission for Cross-Organization Agent Tool Calls".
The family index is [docs/papers/README.md](../README.md).

## What the note still offers

Material worth carrying into the surviving paper once it has been rewritten
against the code: the contrast between build provenance and admission
provenance (section 1); the SCITT and COSE-receipt comparison (section 8);
rejection codes as protocol surface with signed denials (sections 3 and 6);
the attack-by-construction table format (section 7); and the
Ed25519-authoritative, BBS-presentation-only stance (sections 2 and 5). None
of it may be quoted as a description of the implementation.

## Sources

`paper.tex`, `sections/01` to `09`, `bib.bib`, and the last built `paper.pdf`
(2026-05-19). The sources build with
`pdflatex paper.tex && bibtex paper && pdflatex paper.tex && pdflatex paper.tex`
from this directory. Do not rebuild for distribution.
