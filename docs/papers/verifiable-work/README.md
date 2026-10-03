# Chio: A Peer-to-Peer Economy of Verifiable Work

[Read the paper](paper.pdf) · [Source](paper.tex) · [Artifact and reproduction](ARTIFACT.md) · [Claim register](CLAIMS.json) · [Publication gates](PUBLICATION.json)

Chio is a kernel for composing agentic work under the authority of its resource
owners. Its central rule is simple: **plans may evolve while issued commitments
retain their bounds and identity.**

An agent can delegate bounded capacity, select a collaborator and grow a running
work graph. Each receiver admits the resulting invocation under its own
capabilities and treaty conditions. Durable custody preserves the original
execution, and funded claims preserve earned obligations after parent failure.
This is programmable sovereignty at the execution boundary: owners control what
may enter their domains, while agents compose work within those bounds.

The paper gives the protocol, its conditional preservation argument and a Rust
implementation. One running example connects the design to an executable result:
an API survey triggers a specialist task, the intermediary is killed after the
specialist earns payment, and the original claim is collected while earlier
execution evidence remains unchanged.

The manuscript presents the kernel contract, trust model, commitment lifecycle,
preservation property and evidence as one argument. Appendix A fixes the concrete
profiles and encodings; Appendix B retains the exact qualification and comparison
boundaries. The [editorial review](EDITORIAL-REVIEW.md) records the technical
review and repairs behind this revision.

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
- `EDITORIAL-REVIEW.md`, `REVIEW.md`: current manuscript review and retained earlier review records.
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
