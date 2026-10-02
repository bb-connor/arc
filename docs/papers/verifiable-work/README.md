# Chio: A Peer-to-Peer Economy of Verifiable Work

[Read the paper](paper.pdf) · [Source](paper.tex) · [Artifact and reproduction](ARTIFACT.md) · [Claim register](CLAIMS.json) · [Publication gates](PUBLICATION.json)

Title approved and locked on 2026-09-14. Full research manuscript and reproducible
artifact prepared on 2026-10-02. **The requested breakthrough/publication bar
remains open:** independently operated useful work and a measured advantage over
the strongest practical alternative have not been established.

The paper connects receiver-local authority, checkable acceptance and exclusively
funded work obligations. It explains both a successful exchange and a child
payment surviving parent failure, with explicit verifier, settlement and
availability assumptions. It credits existing escrow and agent-commerce work,
including ERC-8183, and retains the matching ordinary-escrow result.

## Contents

- `paper.pdf`, `paper.tex`, `sections/`, `bib.bib`: complete main manuscript.
- `ARTIFACT.md`: concrete profile mapping, source boundaries and exact reproduction commands.
- `CLAIMS.json`: supported claims, assumptions, limitations and unestablished hypotheses.
- `sources.json`: versioned primary references and content hashes.
- `formal/WorkClaims.lean`: checked abstract conservation and earned-state lemmas.
- `tools/compare.py`: ordinary transactional escrow replayed against the same finite trace corpus.
- `evidence/`: fresh logs, model traces, negative controls and integration/comparison records.
- `PUBLICATION.json`: fail-closed high-bar readiness gates.
- `EXTERNAL-TRIAL.md`, `trial/`: independent operator handoff, frozen analysis rules and data templates; no completed trial is implied.
- `PROGRESS.md`: execution decisions and remaining work.
- `REVIEW.md`: fresh review, reproduced checks, documentation fixes and its limits.

```sh
make build
make test
make check
python3 tools/check.py --publication
```

The final command must fail while a publication gate remains open. A passing
artifact check means the paper agrees with its retained evidence; it does not
mean that an open research hypothesis became true.

The [open agent work program](../../market/open-agent-work/README.md) is the
approved research plan. [Evidence Crosses, Authority Does Not](../evidence-crosses/README.md)
and the [September review](../review-2026-09/README.md) remain historical
antecedents. Their original sources and evidence snapshots are preserved.
