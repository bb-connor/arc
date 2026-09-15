# Handoff: is this a breakthrough, or good engineering dressed as one?

You are reviewing a whitepaper and the system behind it. The question you are
being asked is not whether the paper is publishable. Six simulated program
committees already answered that: 2.42 of 5 on the first draft, 3.17 with one
accept on the second. The question is harder and it is the only one that
matters here.

**Is this a breakthrough in agentic systems, of the kind the Bitcoin whitepaper
was for money, or is it careful engineering that has been made to sound like
one?**

Answer that. Be willing to say no. A false yes is worth nothing to anyone.

## Where everything is

Repository `/home/connor/backbay/arc`, branch `paper/roadmap-phase-0-1`.

| What | Where |
| --- | --- |
| The paper | `docs/papers/evidence-crosses/`, 12 pages, 4,992 body words |
| The formal companion | `docs/papers/evidence-crosses/proof-model.md` |
| The mechanization | `formal/lean4/Chio/Chio/Treaty/AdmissionBinding.lean` |
| The head-to-head artifact | `examples/composed-baseline/` |
| The normative spec | `spec/CHIO_BILATERAL_COSIGN_INVOCATION.md` |
| The original review | `docs/papers/review-2026-09/00` through `11` |
| What execution produced | `docs/papers/review-2026-09/12-execution-record.md` |
| Work still owed | `docs/papers/review-2026-09/13-code-the-paper-owes.md` |

Thirteen commits from `884fd7894d` to `1f031be355`.

## The claim, as it now stands

The rule: authority is minted and verified only inside the kernel that
dispatches, against roots that kernel activated itself, and nothing carried in a
request can add a root. Only signed, content-addressed evidence crosses an
organization boundary.

The thesis the paper now argues from that rule:

> Which names must cross is settled by what the receiver decides, so the carrier
> is co-designed with the decision rather than bolted onto a request shaped
> before it.

And the load-bearing sentence, which is the one to attack:

> Every value that reaches this receiver was minted by the caller or by the
> caller's own authorization server, so a check against receiver-held state is a
> comparison with an assertion the adversary chooses.

## What the evidence actually is

- A 55-leaf classification of the co-signed predicate, total by exhaustiveness
  over the leaf type in Lean, cross-checked against an executed corpus that
  reads the Lean module and fails if the enumerations disagree. 23 leaves
  compared for equality against a named receiver-held value, 2 for membership in
  a receiver-held set, 13 against the statement alone, 11 against nothing.
- 536 kernel evaluations over 268 substitution cases, each asserting a dispatch
  counter reads zero on denial and exactly one on admission.
- A composed alternative built from nine published documents (Model Context
  Protocol, A2A, RFC 8693, RFC 7519, RFC 7515, RFC 6749, three SPIFFE
  standards), with a test that walks every byte an admissible call serializes
  and fails on any path none of those documents defines. Of the 15 facts a
  receiver binds: 4 have a carrier it can resolve, 3 ride where no signature
  reaches, 8 have no field anywhere in that set.
- A two-host run between a Linux server and a macOS workstation over a real
  wide-area link: 100 admitted calls with 100 dispatches, 7 denial classes over
  140 calls with zero dispatches, a measured clock offset between the two
  administrative domains.

## What I got wrong, so you can calibrate

I want you to know my failure modes before you trust anything above.

1. **I withdrew claims instead of building them.** Reviewers proved seven
   sentences described behaviour the code lacked. I weakened the sentences. The
   repository owner's response was that this was backwards: the paper states the
   system we intend, and the code catches up. He was right. Five of the seven
   were then built, each with a test that fails when reverted. Check whether the
   restored sentences are now actually true, and whether I over-corrected
   anywhere.

2. **The first version of the central claim was circular.** The paper argued no
   composition of existing parts could reach admission binding, resting on a
   request schema I had written myself. A reviewer added one field and destroyed
   it. The rebuild on published specifications is the repair. Decide whether the
   repair is sound or whether I have simply moved the circularity somewhere
   harder to see.

3. **The paper made four claims that flattered the system**, found by four or
   five readers independently each. Assume more remain. The highest-value thing
   you can produce is one more.

## Three specific things to attack

**The thesis may be a tautology.** "The carrier is co-designed with the
decision" could be read as: a receiver can only check facts it was sent. That is
trivially true and would not be a breakthrough. The paper needs it to mean
something stronger. Decide which it is.

**The novelty may be placement, not mechanism.** Every primitive here is old:
signed receipts, pinned keys, content addressing, single-use tokens, monotone
epochs. The paper claims the contribution is where authority is minted, not what
it is made of. Saltzer's end-to-end argument is the cited ancestor. Is this the
same kind of contribution, or is it an implementation of that argument rather
than an addition to it?

**The comparison may be unfair in a way I cannot see.** It concludes that
Model Context Protocol, A2A, token exchange, and SPIFFE carry no field for 8 of
15 bound facts. That is true of those documents. But those protocols were built
for other jobs, and "a protocol designed for X does not do Y" is not by itself a
result. Ask whether the comparison establishes anything an informed reader did
not already know.

## What would make this a breakthrough, in my view, and why I am unsure

Bitcoin's whitepaper named a problem everyone had accepted as unsolvable
(double-spend without a trusted third party) and gave a mechanism that dissolved
it. The test is: before the paper, competent people believed X was impossible or
inevitable; after it, they did not.

The candidate here is: **an agent's tool call across an organization boundary
has to be decided by the receiver from facts only the receiver holds, and the
record of that decision has to be one object that is simultaneously the
authorization, the audit entry, the accounting entry, and the evidence a third
party can check.** If that reframes what people build, it is a breakthrough. If
it is a well-argued preference among existing options, it is a good systems
paper.

I genuinely do not know which. Tell me.

## How to work

Verify before you agree. Three severe defects in this system were found by
readers who checked the paper against the code rather than reading the paper:
a signing oracle that let any admitted peer forge receipts attributed to another
kernel, a co-signing mode that forced no evidence despite its name, and a
concurrency defect that denied correct calls. All three are fixed. All three
were invisible to anyone reading only the prose.

Do not produce a score. Produce a judgement with the reasoning attached, name
the single strongest objection to your own conclusion, and say what would change
your mind.
