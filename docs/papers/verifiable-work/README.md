# Chio: A Peer-to-Peer Economy of Verifiable Work

[Read the paper](paper.pdf) · [Source](paper.tex) · [Artifact and reproduction](ARTIFACT.md) · [Claim register](CLAIMS.json) · [Publication gates](PUBLICATION.json)

Chio is a kernel architecture for peer-to-peer verifiable work. It separates
agent planning from the authority and durable execution state governing its
effects. Programs can develop across independently controlled resources while
each owner enforces its own conditions for admission.

The paper develops this architecture through programmable sovereignty,
capabilities, treaties and work commitments. A commitment connects a selected
call with its allowance, receiving authority and, for paid work, settlement
terms. Plan growth preserves earlier execution rights; recovery retains their
history; separately funded agreements preserve earned payments.

The manuscript defines the kernel boundary and distributed program state,
specifies the composition rules, and gives a preservation argument under
explicit trust assumptions. The implementation and evaluation follow an API
review through task discovery, graph growth, intermediary process loss and
collection of the specialist's original claim.

Appendix A fixes the concrete profiles and encodings. Appendix B retains the
qualification and comparison details. The [architecture review](ARCHITECTURE-REVIEW.md)
records the review and validation of this revision. The
[previous prose review](PROSE-REVIEW.md) and
[earlier editorial review](EDITORIAL-REVIEW.md) remain available at their original
scopes.

The title was approved on 2026-09-14. The manuscript and artifact were revised on
2026-10-03. The composed result uses one administrator and a private chain. The
[claim register](CLAIMS.json) and [publication record](PUBLICATION.json) preserve
the separate evidence requirements for independent operation, useful-work
economics, integration advantage and external foundational critique.

## Contents

- `paper.pdf`, `paper.tex`, `sections/`, `bib.bib`: manuscript and technical appendices.
- `ARTIFACT.md`: concrete profile mapping, source boundaries and exact reproduction commands.
- `CLAIMS.json`: supported claims, assumptions, limitations and unestablished hypotheses.
- `sources.json`: versioned primary references and content hashes.
- `formal/WorkClaims.lean`: checked abstract conservation and earned-state lemmas.
- `tools/compare.py`: ordinary transactional escrow replayed against the same finite trace corpus.
- `evidence/`: source-bound logs, model traces, negative controls and integration/comparison records.
- `PUBLICATION.json`: fail-closed high-bar readiness gates.
- `EXTERNAL-TRIAL.md`, `trial/`: independent operator handoff, frozen analysis rules and data templates; no completed trial is implied.
- `PROGRESS.md`: execution decisions and remaining work.
- `ARCHITECTURE-REVIEW.md`, `PROSE-REVIEW.md`, `EDITORIAL-REVIEW.md`, `REVIEW.md`: current manuscript review and retained earlier review records.
- [Dynamic delegation](../../research/dynamic-delegation/README.md): protocol,
  results, current native source qualification and implementation review.
- [Swarm evolution](../../research/swarm-evolution/README.md): reuse map,
  additive composition argument, native trajectories and combined review.
- [Evolving funded work](../../research/evolving-funded-work/RESULTS.md): the
  composed execution, fresh qualification, review and outside receiver contract.

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
