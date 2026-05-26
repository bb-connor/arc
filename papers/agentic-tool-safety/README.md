# Tool Calls as Reversible-Action Admission

Workshop paper drafted for an AI-safety audience. Argues that the safety of an LLM agent's tool call is partly a property of the substrate that admits the call, not solely a property of the model that produced it; that a tool call has the structural shape of a delegated executive act; and that a typed rollback witness with a mandatory TTL composes orthogonally with alignment-training-time interventions such as Constitutional AI, RLHF, debate, and scalable oversight.

## Working title

*Tool Calls as Reversible-Action Admission: A Formal Grammar for Agentic AI Safety*

## Target venues

Primary candidates (workshop / short-paper, 3000-4500 words):

- NeurIPS Safe-AI Workshop
- ICML AI Safety workshop
- AI Safety Camp / ALTA proceedings

Secondary candidates:

- USENIX Security AI track
- AISafety @ AAAI 2027

The paper is sized for a workshop submission. A longer systems version that puts the substrate first would target USENIX Security or NDSS; this version puts the safety framing first.

## Relationship to the parent paper

This paper sits next to `papers/programmable-sovereignty/`, which formalises the broader substrate (polity triple, treaty intersection, amendment refinement, capability attenuation). The parent paper carries the Lean machinery and is the natural citation target for the substrate's structural theorems. This paper is sharper: it restricts attention to one application (agentic tool calling), one threat model (a possibly-misaligned model), and one structural claim (admission-time rollback witness composes orthogonally with training-time alignment).

The cross-reference is one-directional. This paper cites the parent paper for the structural theorems. The parent paper does not need to cite this paper.

## Status

This is a **position paper that uses the parent paper's substrate as its structural backbone**. The novel contribution is not a new theorem; it is a reframing of agentic-AI safety as a structural problem at the admission layer rather than (only) a training-layer problem, accompanied by a typed grammar for what a substrate-level safety property looks like.

The headline-claim survival case is bounded: two safety layers compose when every tool call is mediated through a correctly classified single-envelope path, with independent cosigners, an intact action-class registry, no bypass channel, and working rollback executors. A scheming model that successfully evades the training-time layer still faces a substrate-side admission predicate, but the paper no longer claims protection under registry compromise, host-side willing signatures, TOCTOU races, multi-agent collusion, admission-hook DoS, or faulty rollback code.

### Anthropic primary contact

**Ethan Perez** is the best primary contact for this paper. The argument is closest to red-teaming and adversarial-evaluation work: a substrate that survives a misaligned model is the structural dual of a model that survives an adversarial evaluator. The paper's threat model assumes the alignment training has failed; that is the regime Perez's red-teaming work explicitly targets. Sam Bowman is the second choice (model-behaviour evaluation), Hubinger / Greenblatt third (alignment-faking is the cited prior work), Grosse fourth (interpretability adjacency is weaker for an admission-layer construction). Kaplan should be approached only after a technical co-author is on board.

The parent paper's outreach memo (`papers/programmable-sovereignty/swarm-notes/anthropic-coauthor-outreach.md`) ordered Bowman first; this paper's framing changes that ordering. The bounded-action plus typed rollback story is in Perez's wheelhouse more directly than in Bowman's.

### Publishability without an Anthropic co-author

Honest assessment: this paper is publishable at a top AI-safety workshop without an Anthropic co-author, *if* it is positioned as a position paper and grounded in the parent paper's formal substrate. The argument carries on its own merits: substrate-level safety is orthogonal to training-level safety, and orthogonal contributions are accepted at safety workshops without endorsement. The paper is not publishable at a top AI-safety **conference** track (NeurIPS main, ICML main, AAAI main) without either an empirical evaluation against a real misaligned model or an institutional co-author whose name carries the alignment-research voice. An Anthropic co-author would not gate workshop acceptance; it would change reviewer perception at the top-conference tier.

### Submission readiness

- LaTeX shell, all nine sections drafted, bib placeholders inherited from the parent paper.
- Word count is on target (roughly 3700-4200 words across sections).
- Three open items before submission:
  1. Replace qualitative red-team sketch with a small empirical evaluation if time permits.
  2. The substrate citation. The parent paper is the structural backbone; whether it is cited as a pre-print or as an accepted publication determines the strength of the substrate-citation move. If the parent paper has not landed, this paper carries more of the structural weight and may benefit from the formal grammar being expanded by half a page.
  3. Re-audit the action-class registry story against a concrete tool server so the threat-model boundary does not read as hand-waved operational work.

Estimate: **2-3 weeks of polish from a competent author** to convert this draft into a submission-ready workshop paper, assuming the parent paper exists as a citable artifact. Less time if a co-author from Anthropic engages.

## License

CC-BY-4.0, matching the parent paper.
