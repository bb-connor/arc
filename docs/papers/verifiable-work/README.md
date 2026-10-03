# Chio: A Peer-to-Peer Economy of Verifiable Work

[Read the paper](paper.pdf) · [Source](paper.tex) · [Artifact and reproduction](ARTIFACT.md) · [Claim register](CLAIMS.json) · [Publication gates](PUBLICATION.json)

Title approved and locked on 2026-09-14. Full research manuscript and reproducible
artifact prepared on 2026-10-02. **The requested breakthrough/publication bar
remains open:** independently operated useful work and a measured advantage over
the strongest practical alternative have not been established.

The paper now centers on evolving programs with preserved commitments. A running
swarm can add work through its existing signed authority while retaining prior
allocations, exact historical artifacts and native continuation custody.
Native tests preserve new and unfinished work, original receipts and bilateral
treaty conditions across growth and restart.

Dynamic delegation supplies the complementary operation: a holder subdivides bounded work,
selects a receiver and seals the exact contract and invocation into portable
evidence. The receiver checks it locally using its own capability and durable
custody. The new experimental Rust profile demonstrates recursive allocation,
provider replacement before sealing, offline-allocator execution, checked output
and real process-kill recovery while a sibling completes.

The separately qualified funded profile explains collectible child payments
after parent failure. Allocation ceilings and actual backing remain distinct.
The paper preserves the ordinary-escrow, ERC-8183 and conditional-capital parity
results; it makes no claim that conventional implementations lack these rules.

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
- [Dynamic delegation](../../research/dynamic-delegation/README.md): protocol,
  results, current source qualification and review of this revision. The older
  paper-local review concerns the earlier funded manuscript.
- [Swarm evolution](../../research/swarm-evolution/README.md): reuse map,
  additive composition argument, native trajectories and combined review.

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
