# Foundational-Paper Benchmark

Source: Wave 2 canon analysis (one agent, foundational documents analyzed from their primary texts, quotes and page counts verified by fetch where possible), scored against both papers as submitted at HEAD `fe5657020c`. The lead reviewer's reading is in `01-executive-summary.md`; this document is the evidence.

## What foundational documents have in common

- The first sentence states a problem or a claim the reader already cares about, in the world's terms, with no citation and no reference to the authors' own system (Bitcoin, Raft, seL4, Paxos, Lamport, Saltzer, Diffie-Hellman, Kerberos, Dynamo, MapReduce, Torvalds).
- Exactly one named primitive, short enough to become vocabulary: proof-of-work chain, contract, refinement proof, replicated log, happened-before, end-to-end argument, public key, file, ticket, macaroon, map/reduce, capability, append-only log. The name is used consistently and the paper is organized around it.
- Short. Median 11-14 pages; Bitcoin 9, Lamport 8, Torvalds 150 words. Length goes to the mechanism, not to positioning, and no section exists to satisfy a venue.
- At least one worked example the reader can trace by hand with real values: word count, careful file transfer, the shopping cart, the seven-leaf Merkle tree, the coin as a chain of signatures, the 10-ether transaction, the Kerberos message sequence.
- The correctness or security argument is inside the paper and derived from the mechanism (attacker probability table, P1/P2 invariants, Log Matching plus Leader Completeness, clock condition theorem, MTH recursion, HMAC chain), never delegated to a supplement or another manuscript.
- Numbers are derived from the mechanism (q tables, clock-drift bound, election-timeout inequality, proof size and effort, complexity estimates) rather than only measured on one machine.
- Complete enough to implement from the text alone: Raft's Figure 2, Paxos's derivation, RFC 6962, Macaroons' equations, MapReduce's interface, Kerberos' messages, Bitcoin's header layout. A reference implementation exists or ships soon after.
- Assumptions are stated once, in one place, without apology (seL4's assumption list, Dynamo's non-hostile environment, Kerberos' known weaknesses, Diffie-Hellman's missing cryptosystem), and the central claim is then asserted plainly everywhere else.
- Related work is absent or a short section at the end; no contribution bullet lists; no research-question framing; citations are few and used to derive, not to position.
- The paper defines vocabulary that survives it (block, term, caveat, ticket, happened-before, capability, log) because each term names one mechanism.
- Diagrams show the mechanism (chain of signatures, space-time diagram, Merkle tree, log states), never the software pipeline or the evaluation harness.
- Direct authorial voice, first person, no committee prose, and a willingness to say what the authors believe (Raft: 'We believe that Raft is superior'; Diffie-Hellman: 'brink of a revolution').

## Anti-patterns (things foundational documents never do)

- Opening with the system's own name and internal vocabulary (treaty, ladder, continuation, lineage, polity, constitution, sovereignty) before the reader has a problem stated in ordinary terms.
- Enumerating contributions as a bullet list of artifacts ('four contributions', 'five falsifiable artifacts') instead of stating one idea.
- Framing the evaluation as RQ1..RQn and letting single-host p50/p99 tables occupy the space where the mechanism's argument should be.
- Citing file paths, function names, line numbers, crate names, or theorem identifiers in the body as evidence; the paper becomes unreadable without the repository and stale the moment the code moves.
- Delegating the hard part to a supplementary artifact or to 'a related manuscript (anonymized for review)'.
- Hedging the central claim in every section instead of stating assumptions once; the reader loses track of what is being claimed at all.
- Formalizing the trivial (a definitional biconditional proved by unfold and simp) and presenting it as a theorem with corollaries.
- Describing a construction (field names, digest domain, gate order, code taxonomy) that does not match what shipped, then claiming properties 'by construction'.
- Taxonomy inflation: counting gates, codes, atoms, cases, corollaries, and surfaces as if the counts were results.
- Confusing the artifact for the idea: writing about 'the Rust implementation', 'the Lean model', and 'the benchmark' rather than about the mechanism they realize.
- Introducing more new terms per paragraph than a reader can absorb, each defined parenthetically inside the sentence that uses it.
- Citing 20-30 references to position the work in a venue's literature while deriving nothing from any of them.
- Reporting measurements whose retained data disagree with the prose, or that were not retained at all.

## The rubric

| # | Criterion | Description |
| --- | --- | --- |
| 1 | Problem-first opening | The first paragraph states a problem a reader outside the project already has, in the world's terms, before naming any system, crate, or project-specific noun. Score 5 if a non-specialist can restate the problem after one paragraph; 1 if the first paragraph requires the project's glossary. |
| 2 | One named primitive | A single mechanism with a short name that the reader can restate in one sentence and that could become vocabulary. Score 5 if the whole paper is organized around it; 3 if a primitive is named but the paper immediately fragments it into components; 1 if the paper is organized around evidence surfaces or contributions rather than one idea. |
| 3 | Self-contained correctness or security argument | The reason the mechanism works is derived in the body (invariant, proof sketch, attacker calculation, case analysis over the bound fields), not delegated to a test corpus, an artifact, or another manuscript. Score 5 for a derivation a reviewer can check by hand; 1 for 'all N named cases passed'. |
| 4 | Executable worked example | At least one concrete example with real values that the reader can trace end to end (a real envelope, a real denial, a real sequence of messages). Score 5 if the example matches the shipped format and is carried through the paper; 1 if there is no example or only a one-sentence scenario. |
| 5 | Derived numbers | Quantitative content follows from the mechanism (bounds, probabilities, sizes, complexity, replay windows) rather than only from a benchmark harness. Score 5 if the numbers would survive a change of machine; 1 if every number is a p50 on one laptop. |
| 6 | Implementability from the text | An engineer could rebuild the mechanism from the paper alone: wire format, field names, canonicalization, verification order, state machine for any consumable state. Score 5 if no external spec is needed; 1 if the reader must open the repository or a spec file to learn the shape of any message. |
| 7 | Assumptions once, claims unhedged | Trust assumptions appear in one table or paragraph; the central claim is asserted plainly elsewhere. Score 5 if the disclaimers appear exactly once; 1 if the same limitation is restated in most sections or the interesting cases are deferred to another paper. |
| 8 | Economy | Length and structure are proportional to the mechanism. No RQ framing, no contribution bullets, no section that exists to satisfy a template, no counting of artifacts as results. Score 5 if every section carries the idea forward; 1 if the evaluation and positioning exceed the mechanism. |
| 9 | Independence from the authors' codebase | No file paths, symbol names, line numbers, internal crate names, harness names, or pending sibling papers are load-bearing. Score 5 if the paper reads the same when the repository is deleted; 1 if line numbers or unpublished theorem names are cited as evidence. |
| 10 | Fidelity to what shipped | Every described format, ordering, taxonomy, and measurement matches the reference implementation and the retained data at the pinned commit, and the pin is reproducible. Score 5 if a reviewer diffing paper against code finds nothing; 1 if the wire format, gate order, or code set in the paper does not exist in the code. |

## P1 scorecard: Receiver-Owned Bilateral Admission (programmable-sovereignty)

| Criterion | Score (1-5) | Evidence |
| --- | --- | --- |
| Problem-first opening | 3 | 01-introduction.tex L3-7 opens well: 'Consider a buyer agent that asks a vendor agent to stage a refund. The vendor returns a correctly signed receipt. The buyer still has to reject it if the receipt belongs to another treaty, binds different arguments, follows an expired continuation, omits required lineage, or records a policy result the buyer does not accept.' The abstract's first sentence is also plain: 'A receiver cannot authorize a cross-organization agent call from a vendor signature alone.' But the third sentence already stacks four undefined project nouns (treaty, continuation, lineage, policy result), paragraph two is 'Receiver-owned admission moves that decision into the receiving kernel', and the refund example is never returned to. |
| One named primitive | 2 | The paper names a protocol, not a primitive, and then decomposes it: 'The protocol combines three familiar objects in a stricter order. A receipt is ... A treaty fixes ... A bilateral predicate is ...' (01 L18-23). The contribution list binds 'the request, outcome, treaty, continuation, lineage, leases, governance references, and both receipt digests' (01 L47-48). The one real idea, that the request may carry identifiers but never trust ('It may not supply the receiver's expected keys, treaty record, trust bundle, or continuation state', 03-substrate L4), is only given a name in the Discussion: 'Receiver-owned resolution turns those references into lookups against local state' (07 L8-9). |
| Self-contained correctness or security argument | 2 | The security objective is one implication, 'A_R(q)=allow => coreAllows(q) and receiverEvidenceAccepts(q)' (02-background L33-36), glossed as 'receiver-resolved treaty evidence is fresh, mutually bound, strictly verified, and accepted by receiver policy' (L38-39); no argument connects the seven-step sequence in 03 L38-48 to it. The Lean theorem is about a different object: 'refinesOn(K',K,D)=true <=> forall r in D. admits(K',r)=true => admits(K,r)=true' (04-model L55-65), and the paper concedes 'An empty list passes vacuously' (04 L71) and 'The differential suite, however, compares Rust with Rust' (06 L81-82). The argument that substitution fails is therefore 'All 20 cases returned the expected denial code' (06 L60). |
| Executable worked example | 1 | There is no envelope, treaty, receipt, or denial shown anywhere. The two figures are pipeline diagrams: 'Figure 2 shows the receiver's control flow' (03 L36) and 'Trust material flows from receiver-owned stores, not from the request' (03 L53). Table 1 lists case numbers ('01, 03, 05--07') and evidence classes, not contents. The refund scenario in the introduction is one sentence and is never instantiated. |
| Derived numbers | 1 | Every number is a measurement: 'pre-dispatch denial: \PSPredispatchDenyPFiftyMs~ms p50' (06 L129), compiled from bench/results/bilateral-admission-inline.tex as 4.115 ms, while CLAIM_LEDGER.md L25 says 'pre-dispatch treaty denial: 11.124 ms p50 and 20.530 ms p99' and L26 '2.488 s p50' against the macro 2.370 s. 06 L12 says 'Linux/aarch64 with eight Arm Neoverse-N1 cores' while bench/results/bilateral-admission-environment.txt records aarch64-apple-darwin. The only bounds are configuration constants ('a 64 KiB document limit, a 1 KiB atom string limit, and depth and node limits of 32 and 1,024', 05 L70-71). The paper says of its own headline: 'This number is not receiver-hook latency' (06 L138) and 'their sum is not the complete workflow' (06 L151). |
| Implementability from the text | 2 | The predicate is a prose field list: 'Its treaty reference binds the treaty scope and ladder-intersection digests; admission report; continuation; lineage bundle; action class and consistency model; request and outcome digests; local and remote receipt digests; lease and governance references; and participant kernel identifiers' (03 L18). No field names, no subject rule, no hash domain, no canonicalization beyond citing RFC 8785; the verification order is seven prose steps (03 L39-47). An implementer must read spec/CHIO_BILATERAL_COSIGN_INVOCATION.md, which the paper does not cite. |
| Assumptions once, claims unhedged | 2 | Assumptions are correctly collected once in Table 4 ('Assumptions outside the evaluated receiver', 09 L4-26), but the key-custody hedge is restated at least six times: 01 L30-32, 03 L22-24, 05 L46-48, 07 L12-17, 09 L35-39, CLAIM_LEDGER 'Not established', and the Lean-does-not-verify-Rust hedge at 04 L85-93, 06 L80-84, 09 L28-33 and supplementary/README.md. The one plain claim, 'The receiver can prevent a foreign agent action from crossing its tool boundary when the supplied evidence does not match receiver-controlled state' (01 L65-66), is immediately followed by 'The protocol makes no claim that either signer is honest'. |
| Economy | 2 | 5,050 words, ten sections, four contribution bullets (01 L45-63), four RQs ('We ask four questions. RQ1 ... RQ4', 06 L4-8), a ten-row latency table (06 L88-126), a seven-row 'Implementation surfaces exercised by the evaluation' table (05 L97-128), and a 135-word conclusion that repeats the abstract. The evaluation (954 words) is the longest section; the mechanism section (03) is 751 words. |
| Independence from the authors' codebase | 2 | Body text cites ChioRuntimeAdmissionHook::evaluate (05 L7), treaty_ref_from_request and RuntimeAdmissionStores (05 L17-20), verify_chio_bilateral_invocation (05 L32), BilateralCoSigningError::code (05 L45), VerifiedFederationTreatyMaterial (05 L53), bounded_treaty_receipt_view_from_verified_artifacts (05 L72), run_runtime_loopback_scenario and verify_package (05 L83-88), run-bilateral-admission.sh and run-replay-corpus.sh (06 L18-22), PS-TH-01..20 and PS-A-01. Symbols rather than line numbers is the better form of this, but the paper does not read without the repository. |
| Fidelity to what shipped | 3 | Mostly faithful (symbols, corpus, verifier all exist at HEAD), with three defects. (a) 03 L12: 'The finite order is observation, guarded, receipt-backed, partition-contingency, and quorum-required', but crates/trust/chio-federation/src/treaty.rs ladder_mode_rank (L859-869) accepts 'maintenance' => 4 and rejects anything else with chio_federation_ladder_invalid_mode; only crates/kernel/chio-runtime-core/src/treaty.rs (L752-758) accepts '"maintenance" \| "quorum_required" => Ok(4)'; spec/CHIO_LADDER.md lists maintenance. (b) Measurements: ledger vs inline macros disagree; prose environment vs retained environment file disagree; bench JSON pins 3dfd241e67 while the manifest pins dfcd511651. (c) supplementary/README.md promises 'bash scripts/check-programmable-sovereignty-artifact.sh' as fast verification, but at HEAD the generator reports 'working artifact differs from pinned commit at Cargo.lock', 922 commits after the pin. |

Total: 20 / 50

## P2 scorecard: Bilateral Receipt Admission (bilateral-receipt-admission)

| Criterion | Score (1-5) | Evidence |
| --- | --- | --- |
| Problem-first opening | 3 | 01-introduction.tex L3 contains the best sentence in either paper: 'existing supply-chain provenance (SLSA, in-toto, Sigstore, Rekor) attests how an artifact was built; agent invocations need provenance for how an action was admitted at the receiving kernel.' But the abstract's first sentence is 90 words with three parenthetical definitions ('(the runtime admission engine inside each organization, not an OS kernel)', '(the cross-organizational agreement that names participant identities, predicate scope, and lifetime)', '(the directed graph of admitted receipts and their causal links)'), and by 01 L5 the reader is expected to hold treaty-scope hash, ladder-intersection hash, continuation hash, and receipt-graph state. |
| One named primitive | 4 | P2 does name one thing and organizes around it: 'We close that gap with a single cryptographic construction' (01 L5); section 2 is titled 'Receipt Admission as a Primitive' and states 'The bilateral-receipt-admission primitive is the smallest construction that answers that question' (02 L5); README: 'a single cryptographic construction - a bilateral DSSE envelope with a treaty-bound subject digest'. Deducted because the primitive is then split into 'four concerns' (02 L7-13) including BBS selective disclosure, which is orthogonal, and because the section-3 six-gate accept set and the section-4 three-gate Lean accept set are two different primitives with the same name. |
| Self-contained correctness or security argument | 2 | The form is right (six gates at 03 L79-90; one attack class per rejection code at 03 L136-144; section 7 with adversary, state, rejection, residual risk per class; an oracle bound 'the error surface leaks at most log2 5 ~ 2.32 bits per attempt', 03 L146). The substance fails: the Lean theorem is admitted to be definitional ('the proof is one Lean tactic line that unfolds the definition', 04 L25; at HEAD freestanding_accept_set_theorem is 'unfold accept; simp'); signatures are abstracted away ('Signature byte validity is abstracted into trust-store membership', 04 L11); and the ordering premise is false at HEAD: 03 L91 says 'the verifier never reaches (G1)-(G6) until both bytes-level signatures verify' and 05 L10 says 'every byte-level check fires before the verifier consults state the sender cannot see', but verify_chio_bilateral_dsse_envelope_inner in crates/trust/chio-federation/src/bilateral_dsse/verify.rs (L175 onward) checks payload_type, signatures.len()==2, canonical bytes, statement_type, predicate_type, validate_chio_predicate, subject count and name, keyid distinctness and fingerprints, and only then calls org_a_public_key.verify and org_b_public_key.verify. The 2.32-bit bound is decoration given 16 VerifierError codes plus 8 BilateralCoSigningError codes. |
| Executable worked example | 2 | P2 has the right instinct: a 'Worked envelope' (03 L45-69) with treatyId 'treaty:opus-alpha:2026', 'lease': {'epoch': 412, 'expiry': 1788000000}, signerKids ['kid:opus#1','kid:alpha#1'], and three narrated denial fixtures (06 L8). But the example is of a design that never shipped: the shipped BilateralPredicate (bilateral_dsse/types.rs L123) is snake_case (invocation_id, tool_server_a, tool_server_b, tool_name, co_sign, consistency_model, cross_org_visibility, timestamp_unix_ms, treaty_binding_ref with 15 fields), the subject name is 'chio-receipt:<invocation_id>' and its digest is SHA-256 of the canonical receipt body (spec section 4), not 'subjectDigest = H(canonical(bindingTuple))' over a 'ten-field tuple' with leaseHash and signerKidsHash (03 L72). An engineer who implements the example will be rejected by Chio. |
| Derived numbers | 1 | The only derived figure is the 'log2 5 ~ 2.32 bits' bound, computed from a taxonomy that does not exist in the code. Everything else is measured and unretained: 'p50 72.051 us (Criterion 95% CI 71.745 us to 72.367 us)' on 'Apple M1 Max, 10 cores, 32 GB RAM, Darwin 25.4.0' for a path the paper itself says 'is not a cryptographic-primitive measurement' (06 L10-12); treaty intersection 'N=1 ... p50 131.67 us ... N=100 p50 4980.46 us' (06 L18); '50 fixtures, manifest-stable across machines (test wall-time 1.07 s)' (06 L14). docs/papers/bilateral-receipt-admission/ contains only sections/, bib.bib, paper.pdf, paper.tex, README.md; no result files, no commit pin, no environment record. |
| Implementability from the text | 3 | P2 gives what P1 does not: field names, a canonicalization rule ('The subject digest is then SHA-256(JCS(bindingObject))', 'sixty-four lowercase ASCII characters with no sha256: prefix', 03 L72), an ordered gate list, and named codes. From the text alone one could implement P2's construction. Deducted because two load-bearing checks are unspecified: the 'operator-resolution test, parameterized by verifier-owned attribution metadata' for signer reuse (03 L140) and 'the treaty's declared multi-lane witness policy' (07 L10); and because what is implementable is not Chio (see criterion 10). |
| Assumptions once, claims unhedged | 2 | The central claims are stated plainly ('The bilateral-DSSE primitive is self-standing', 01 L7; 'rejected structurally rather than detected', 07 L4) and the limitations are collected in one section (09), which is foundational form. But the hard cases are deferred out of the paper: the phrase 'related polity-layer construction (anonymized for review)' or '(anonymized for review)' appears in the abstract, 01 L7, 03 L142, 06 L16, 06 L20, 06 L22, 07 L14, 07 L16, 08 L13, 09 L6, 09 L16 (twice), 09 L18: at least fourteen deferrals, including intra-lease replay, schema versioning, PQC migration, cross-process federation, and the trajectory-invariant theorem. A 'Stub disclosure' paragraph (05 L33) about a macOS Endpoint Security integration describes a component that does not exist at HEAD (no crate or es_new_client reference under crates/). |
| Economy | 2 | 7,983 words in 10 pages with a 330-word abstract and five contribution bullets (01 L11-17). Section 3 is 2,285 words and spends a paragraph on rejected alternatives ('Raw concatenation, length-prefixed concatenation with field tags, and HKDF-Expand with field-tag info parameters are not used', 03 L72). Section 4 is 963 words for a theorem 'proved by unfolding accept and rewriting' plus 'Three corollaries [that] follow definitionally and serve as scope-clarification artifacts rather than as independent theorems' (04 L27). Related work is 810 words covering SCITT, IMA, IRONDICT, distributed vector commitments, and applied-pi composition, none of which the construction uses. |
| Independence from the authors' codebase | 1 | Table 1 and text cite 'crates/trust/chio-federation/src/bilateral_dsse.rs:996' four times (05 L10, L22-24) and 'bilateral_verifier.rs' twice; a line number is the most fragile possible citation and the file no longer exists as a single file at HEAD (it is bilateral_dsse/{verify,types,...}.rs, following the 2026-06-09 crate move). Also cited: 'formal/lean4/Chio/Chio/Treaty/BilateralAccept.lean' (01 L16, 04 L25), require_unique_signature_keyids, PREDICATE_TYPE_BILATERAL (the constant at HEAD is PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION), and three theorem names from an unpublished sibling paper (amendment_admissible_iff_backward_refinement, treaty_admission_iff_predicate_intersection, essential_preserved_chain, 04 L31, 08 L13). |
| Fidelity to what shipped | 1 | Seven divergences. (a) 'five rejection codes (noncanonical-payload, predicate-type-mismatch, signer-reuse, stale-lease, subject-digest-mismatch)' vs the real VerifierError with 16 codes (dsse.malformed, statement.malformed, predicate.schema_invalid, signature.server_a_invalid, ladder.manifest_stale, ...) plus 8 BilateralCoSigningError codes; 'noncanonical-payload' is really CanonicalJson('statement.malformed: payload is not canonical JSON') string-matched in map_bilateral_error. (b) camelCase ten-field tuple vs snake_case BilateralPredicate plus TreatyBindingRef. (c) Signatures-first ordering claim is false (signatures verified last). (d) The Lean trust store is asymmetric (issuerKeys/kernelKeys, BilateralAccept.lean) and P2's G4 is 'sig_1.kid in IssuerKeys and sig_2.kid in KernelKeys' (03 L85-86), but the Rust verifier is symmetric (org_a/org_b pinned peers, both distinct); no issuer/kernel split exists in Rust. (e) 'The verifier evaluates the receipt's anchor set against the treaty's declared multi-lane witness policy' (07 L10): WitnessPolicy and evaluate_witness_policy exist in crates/economy/chio-anchor/src/witness.rs (L244, L341) and LaneQuorumPolicy in Lean PredicateLang.lean L524, but nothing in chio-federation/src/treaty.rs or bilateral_verifier/cosign.rs references a lane or witness policy (cosign.rs has only 'Step 16: consistency anchor reconciliation' requiring consistency_anchor 'frost-quorum' for n_of_m); no treaty-attached lane quorum exists in Rust. (f) The three denial fixtures are said to return 'subject-digest-mismatch', 'the party-independence gate', and 'the lease-freshness gate' (06 L8); the corpus codes are chio_treaty_scope_hash_mismatch, signer.independence_required, capability.lease_expired_or_unknown. (g) No benchmark files, environment record, or commit pin retained. |

Total: 21 / 50

## Verdict

Scores: P1 20/50 (3,2,2,1,1,2,2,2,2,3), P2 21/50 (3,4,2,2,1,3,2,2,1,1). Neither is close to foundational; both average about 2 out of 5. They fail in opposite ways. P2 has the shape of a foundational document (one named primitive, a worked envelope, a canonicalization rule, an attack-by-construction section, plain claims) and is untrue: its wire format, gate order, code taxonomy, issuer/kernel trust-store split, and treaty-attached witness policy do not exist at HEAD, its benchmarks are unretained, and it cites a line number in a file that no longer exists. P1 is true (the claim ledger, the assumptions table, and the symbol-level artifact discipline are exactly what the field needs) and has no idea in it that a reader can hold: it is organized around evidence surfaces (hook, verifier, Lean model, differential suite, benchmark, corpus), it contains no example, no wire format, no derived number, and it hedges the same two points six and four times respectively. By form P2 is closer; by truth P1 is closer; the founder should not polish either.

Single biggest structural gap. P1: no named primitive. The real idea is written in the Discussion ('Receiver-owned resolution turns those references into lookups against local state') and in the intro as 'A receipt is a kernel-signed record of a mediated tool decision over canonical bytes', but the paper is built around the evaluation of an implementation rather than around that sentence. P2: the construction it describes is not the construction that ships, so every 'by construction' claim is about a paper design; fixing the prose to the shipped format would also collapse its five-code oracle argument and its six-gate ordering argument, which are the only arguments it has.

What a foundational Chio paper would have to look like. Length: 8 to 10 pages, under 5,000 words including one real envelope and one real denial receipt; no research questions, no contribution bullets, no sibling-paper references, no crate or file names, no anonymized deferrals. Named primitive: the receipt, defined in one sentence that P1 already has ('a kernel-signed record of a mediated tool decision over canonical bytes'), extended to the cross-organization case in one more: a receipt becomes bilateral when two kernels sign the same canonical bytes, and a receiver admits a foreign call only by checking that receipt against state it alone holds, consuming the continuation once, and writing a receipt whether it allows or denies. Everything else (treaty, ladder, lineage, lease, governance) is policy over receipts and gets one paragraph, not a section. First paragraph, in the world's terms and carried through the whole paper as the worked example: an agent at one company asks an agent at another to refund an order; the second company's software must decide, before it touches its ledger, whether to obey; today that decision rests on a signature and an API key, which say who is asking and nothing about whether this call, with these arguments, under this agreement, has already been authorized, already been performed, or already been revoked; we describe a receipt that answers those questions before the tool runs, and a rule that the request may carry names but never keys. Must contain: the shipped snake_case envelope with the real subject rule (chio-receipt:<invocation_id>, digest over the canonical receipt body); the receiver's check sequence as the shipped numbered algorithm with signatures last and one sentence on why structural gates precede signature verification; a substitution case analysis over the TreatyBindingRef fields that names, for each substituted field, the code that fires (this is the argument P2 attempted and P1 delegated to PS-TH-01..20); the reserve/consume/release state machine for continuations, since that is the entire replay defense; one derived bound (the replay window equals the continuation validity interval, and the evidence graph a receiver must resolve is bounded by the fields of one binding reference); the assumptions table from P1 section 9, once; and at most one measured number, with the environment file that produced it. Must omit: the finite-domain Lean theorem and the definitional accept-set theorem (one sentence pointing at the theorem inventory is enough; neither carries the paper), the Rust-vs-Rust differential suite, the ten-row Criterion table, the buyer-workflow seconds, BBS selective disclosure, anchor lanes, the macOS stub, the polity and sovereignty vocabulary, and the word treaty wherever agreement will do. Preconditions before any of this can be written honestly: re-pin the artifact at a commit whose wire format matches the text (the check is broken at HEAD, 922 commits after the pin); make CLAIM_LEDGER.md numbers equal the compiled inline macros; retain P2-style measurements or delete them; and settle one ladder vocabulary (federation accepts maintenance, runtime-core accepts maintenance or quorum_required, P1 prints quorum-required). The discipline in the claim registry is correct and should stay; foundational papers put that discipline in one assumptions paragraph and then speak plainly everywhere else.

## Appendix: the documents analyzed

### Bitcoin: A Peer-to-Peer Electronic Cash System (2008)

- Why foundational: Solved double-spending without a trusted third party with one mechanism (a chain of hash-based proof-of-work) that an engineer could implement from the text, and shipped the implementation three months later. Every later ledger inherits its vocabulary (block, chain, longest chain, confirmation).
- Named primitive: proof-of-work chain (longest-chain rule)
- Opening move: Abstract, sentence one: 'A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution.' Introduction: 'Commerce on the Internet has come to rely almost exclusively on financial institutions serving as trusted third parties to process electronic payments.' The problem (trust-based mediation) is stated in the world's terms before any mechanism.
- Structural features:
  - Length: 9 pages (verified by pdfinfo on bitcoin.org/bitcoin.pdf), 12 numbered sections, 8 references.
  - One named primitive: the proof-of-work chain ('an ongoing chain of hash-based proof-of-work, forming a record that cannot be changed without redoing the proof-of-work').
  - Problem-first opening: section 1 begins with commerce and trusted third parties, not with the system.
  - Security argument: section 11 'Calculations' is an explicit attacker race with a Poisson/gambler's-ruin derivation, C code, and tables for q=0.1 and q=0.3 (verified in the text).
  - Worked example: the coin as a chain of digital signatures, the Merkle-pruned block, the 80-byte header size arithmetic (4.2 MB/year).
  - Refuses to hedge: 'As long as a majority of CPU power is controlled by nodes that are not cooperating to attack the network, they'll generate the longest chain and outpace attackers.'
  - Leaves out: implementation details, benchmarks, related work section, governance, any evaluation section, any contribution bullet list.
  - Diagrams draw the mechanism (chain of signatures, Merkle tree), never the software pipeline.

### Ethereum White Paper (A Next-Generation Smart Contract and Decentralized Application Platform) (2013-2014)

- Why foundational: Reframed a ledger as a state transition system and introduced a Turing-complete contract layer metered by gas; every smart-contract platform since either copies or reacts to it.
- Named primitive: the contract executed by a gas-metered EVM (state transition function)
- Opening move: 'The concept of decentralized digital currency, as well as alternative applications like property registries, has been around for decades.' A history-first opening that defines Bitcoin as a state machine so that Ethereum can be presented as a generalization of that machine.
- Structural features:
  - Length: roughly 13,500 words as a web document (verified by fetch of ethereum.org/en/whitepaper), no page limit, no venue.
  - One named primitive: the contract (an account with code executed by the EVM, metered by gas).
  - Problem-first opening: begins with the history of decentralized digital currency and Bitcoin as a state transition function before naming Ethereum.
  - Security argument: the halting-problem and denial-of-service discussion is resolved by gas; block validation and fee economics are argued, not proved.
  - Calculations and worked example: a full state-transition example (10 ether value, 2000 gas, 0.001 ether gasprice, 64 bytes data) and example contracts in Serpent (token system, name registry).
  - Refuses to hedge: asserts that a Turing-complete scripting layer with gas is the correct base layer.
  - Leaves out: benchmarks, formal proofs, evaluation, related work as a section; it is a design document that expects to be implemented.

### seL4: Formal Verification of an OS Kernel (SOSP) (2009)

- Why foundational: First machine-checked functional-correctness proof of a general-purpose OS kernel's C implementation against its specification; set the template for what 'verified' means in systems (assumptions listed, proof size and effort reported).
- Named primitive: functional-correctness refinement proof from specification to C
- Opening move: Abstract: 'Complete formal verification is the only known way to guarantee that a system is free of programming errors.' Introduction: 'The security and reliability of a computer system can only be as good as that of the underlying operating system (OS) kernel.' (both verified from the PDF text)
- Structural features:
  - Length: 14 pages in the SOSP proceedings (fetched copy paginates to 18 with appendix).
  - One named primitive: the refinement proof chain (abstract specification to executable specification to C implementation).
  - Problem-first opening: the abstract's first sentence is a claim about the only known way to guarantee absence of programming errors; the introduction starts from the kernel as the trust root of every system.
  - Security argument: the proof itself, plus an explicit list of what the proof assumes (compiler, assembly, hardware, boot code, cache and TLB management).
  - Calculations: 8,700 lines of C, about 200,000 lines of proof script, roughly 20 person-years, IPC performance numbers.
  - Worked example: the invariant classes and a concrete bug list found during verification.
  - Refuses to hedge: 'Complete formal verification is the only known way to guarantee that a system is free of programming errors.'
  - Leaves out: security-property proofs (integrity and confidentiality came in later papers), any claim about the trusted computing base below the kernel.

### In Search of an Understandable Consensus Algorithm (Raft) (2014)

- Why foundational: Made replicated-log consensus implementable by ordinary engineers by choosing a strong leader and decomposing the problem; it became the default consensus algorithm in industry (etcd, Consul, TiKV) within three years.
- Named primitive: replicated log with a strong leader and terms
- Opening move: Abstract: 'Raft is a consensus algorithm for managing a replicated log.' (verified) The first sentence names the primitive; the second sentence states the design goal (understandability) as the problem.
- Structural features:
  - Length: 16 pages (USENIX ATC), 18 pages in the extended version (verified by pdfinfo on raft.github.io/raft.pdf).
  - One named primitive: the replicated log under a strong leader with terms.
  - Problem-first opening: 'Consensus algorithms allow a collection of machines to work as a coherent group that can survive the failures of some of its members.' (verified)
  - Safety argument: section 5.4 with the Log Matching Property and the Leader Completeness proof sketch; a TLA+ specification is cited.
  - Worked example: Figure 7 log-state scenarios; Figure 2 is a one-page condensed summary complete enough to implement from.
  - Calculations: election-timeout reasoning (broadcastTime << electionTimeout << MTBF) and a 43-student user study.
  - Refuses to hedge: 'We believe that Raft is superior to Paxos and other consensus algorithms, both for educational purposes and as a foundation for implementation.'
  - Leaves out: Byzantine faults, extensive performance tuning, a deep implementation report.

### Paxos Made Simple (2001)

- Why foundational: Re-derived Paxos from its safety requirements so that the algorithm is reconstructed rather than presented; it is the version of Paxos most engineers actually read.
- Named primitive: the Paxos proposer/acceptor protocol derived from invariants P1 and P2
- Opening move: Abstract: 'The Paxos algorithm, when presented in plain English, is very simple.' Introduction: 'The Paxos algorithm for implementing a fault-tolerant distributed system has been regarded as difficult to understand, perhaps because the original presentation was Greek to many readers [5].' (both verified)
- Structural features:
  - Length: 14 pages including cover (verified), no figures, one reference joke.
  - One named primitive: the proposer/acceptor two-phase protocol derived from invariants P1, P2, P2a, P2b, P2c.
  - Problem-first opening: the algorithm 'has been regarded as difficult to understand'.
  - Correctness argument: safety by construction (each invariant strengthens the previous until an implementable rule appears); liveness discussed separately.
  - Worked example: the derivation itself is the example; the reader sees each rule fail and be repaired.
  - Calculations: none beyond the invariants.
  - Refuses to hedge: the entire abstract is one sentence asserting simplicity.
  - Leaves out: evaluation, implementation, related work, benchmarks, contribution list, figures.

### Time, Clocks, and the Ordering of Events in a Distributed System (1978)

- Why foundational: Defined happened-before and logical clocks, the conceptual basis of every later distributed-systems consistency result; the most cited paper in the field.
- Named primitive: happened-before and logical clocks
- Opening move: Abstract: 'The concept of one event happening before another in a distributed system is examined, and is shown to define a partial ordering of the events.' Body: 'The concept of time is fundamental to our way of thinking.' The opening move is to question a notion the reader took for granted.
- Structural features:
  - Length: 8 pages in CACM (verified by pdfinfo).
  - One named primitive: the happened-before relation and the logical clock condition.
  - Problem-first opening: 'The concept of time is fundamental to our way of thinking.' (verified)
  - Correctness argument: the clock condition is stated and satisfied by two implementation rules; a theorem bounds physical clock synchronization with explicit epsilon and drift terms.
  - Worked example: space-time diagrams and a distributed mutual-exclusion algorithm built on the total order.
  - Calculations: the physical-clock synchronization theorem with a numeric bound.
  - Refuses to hedge: 'is shown to define a partial ordering of the events'.
  - Leaves out: implementation, evaluation, extensive related work.

### End-to-End Arguments in System Design (1984)

- Why foundational: Gave a name to a function-placement principle that had been used implicitly; the name became a design vocabulary for the Internet and for every layered system since.
- Named primitive: the end-to-end argument
- Opening move: 'This paper presents a design principle that helps guide placement of functions among the modules of a distributed computer system.' (verified) It names the principle in the first sentence and then spends the paper on examples.
- Structural features:
  - Length: about 10-12 pages (fetched copy 10 pages; ACM TOCS 2(4) pp. 277-288).
  - One named primitive: the end-to-end argument.
  - Problem-first opening: 'Choosing the proper boundaries between functions is perhaps the primary activity of the computer system designer.' (verified)
  - Argument: a qualitative reliability argument (functions at low levels are redundant when the endpoints must check anyway).
  - Worked example: careful file transfer, followed by bit error recovery, encryption, duplicate suppression, crash recovery, delivery acknowledgement.
  - Calculations: informal probability reasoning on file-transfer failure rates only.
  - Refuses to hedge: 'Low level mechanisms to support these functions are justified only as performance enhancements.'
  - Leaves out: implementation, evaluation, formalism, a related-work section.

### New Directions in Cryptography (1976)

- Why foundational: Introduced public-key cryptography and digital signatures as concepts and gave the exponential key exchange; it created the field before a full public-key cryptosystem existed.
- Named primitive: public-key cryptosystem and public key distribution
- Opening move: Abstract: 'Two kinds of contemporary developments in cryptography are examined.' Introduction: 'We stand today on the brink of a revolution in cryptography.' The opening asserts the magnitude of the change before explaining it.
- Structural features:
  - Length: 11 pages (IEEE Trans. IT-22(6) pp. 644-654, verified).
  - One named primitive: the public key cryptosystem (with one-way and trap-door functions) and public key distribution.
  - Problem-first opening: key distribution and the need for a written-signature equivalent in teleprocessing.
  - Security argument: definitions grounded in computational complexity; the discrete-logarithm key exchange is described with its assumed hardness.
  - Worked example: the exponential key exchange over GF(q).
  - Calculations: complexity estimates for the exchange and for exhaustive search.
  - Refuses to hedge: 'We stand today on the brink of a revolution in cryptography.' (verified fragment)
  - Leaves out: a concrete public-key cryptosystem (explicitly stated as an open problem); evaluation.

### The UNIX Time-Sharing System (1974)

- Why foundational: Described a small, general-purpose system with a uniform file abstraction and a programmable shell; nearly every operating system interface since descends from it.
- Named primitive: the file abstraction (files, devices, pipes) and the shell
- Opening move: Abstract: 'UNIX is a general-purpose, multi-user, interactive operating system for the Digital Equipment Corporation PDP-11/40 and 11/45 computers.' (verified) It defines the artifact in one sentence and lists five features.
- Structural features:
  - Length: 11 pages (CACM 17(7) pp. 365-375, verified).
  - One named primitive: the file (hierarchical file system in which devices and pipes share the file interface) together with the shell.
  - Problem-first opening: 'There have been three versions of UNIX.' (verified) The paper opens with history and the system, then explains the file system and shell.
  - Security argument: file protection bits and set-user-ID are described plainly with their limits.
  - Worked example: shell command lines, redirection, and pipelines shown as the user would type them.
  - Calculations: sizes of the system, cost of the hardware, installation counts.
  - Refuses to hedge: 'It offers a number of features seldom found even in larger operating systems.'
  - Leaves out: formalism, benchmarks, a related-work section; a candid 'Perspective' section replaces evaluation.

### Linus Torvalds' comp.os.minix announcement (25 Aug 1991) and first design notes (5 Oct 1991; Jan 1992 reply to Tanenbaum) (1991-1992)

- Why foundational: Not a paper: a working kernel plus source plus an invitation to change it. It is foundational because the artifact existed before the prose, and the prose invited participation rather than asserting authority.
- Named primitive: a free 386 kernel with the source (Linux)
- Opening move: 'Hello everybody out there using minix - I'm doing a (free) operating system (just a hobby, won't be big and professional like gnu) for 386(486) AT clones.' (verified) The opening names the audience, the artifact, and its limits in one sentence.
- Structural features:
  - Length: about 150 words for the announcement; the October post is about 300 words (both verified on cs.cmu.edu/~awb/linux.history.html).
  - One named primitive: a free, source-available, monolithic, POSIX-like kernel for the 386.
  - Problem-first opening: addressed to 'everybody out there using minix', i.e. to people with a known frustration.
  - Security argument: none.
  - Calculations: none.
  - Worked example: 'I've currently ported bash(1.08) and gcc(1.40)'; the 0.02 post ships the source.
  - Refuses to hedge on the artifact while hedging on ambition: 'just a hobby, won't be big and professional like gnu'; 'It is NOT portable'.
  - Leaves out: everything except what works today and what the author wants feedback on. The January 1992 reply to Tanenbaum (from memory; not fetched) defends the monolithic design on practical grounds and concedes the theoretical point.

### Certificate Transparency: RFC 6962 (June 2013) and Ben Laurie, 'Certificate Transparency: Public, verifiable, append-only logs' (ACM Queue) (2013-2014)

- Why foundational: Turned certificate misissuance from an undetectable event into a publicly auditable one with a single data structure; now mandatory for public TLS and copied by Sigstore/Rekor and binary transparency.
- Named primitive: the public, verifiable, append-only Merkle log
- Opening move: RFC abstract: 'This document describes an experimental protocol for publicly logging the existence of Transport Layer Security (TLS) certificates as they are issued or observed, in a manner that allows anyone to audit certificate authority (CA) activity...' (verified). The opening names the artifact and who benefits.
- Structural features:
  - Length: RFC 6962 is 27 pages (verified); the Queue article is a short practitioner piece.
  - One named primitive: the public, verifiable, append-only log built on a Merkle Tree Hash.
  - Problem-first opening: 'Certificate transparency aims to mitigate the problem of misissued certificates by providing publicly auditable, append-only, untrusted logs of all issued certificates.' (verified)
  - Security argument: security considerations on misbehaving logs, detection by auditors and monitors, and the consequences of a log's signed tree head being contradicted.
  - Worked example: section 2.1 gives the exact recursive MTH definition and a seven-leaf example tree with audit paths (verified).
  - Calculations: the MTH recursion and consistency-proof construction are exact enough to implement.
  - Refuses to hedge: 'The core idea behind Certificate Transparency is the public, verifiable, append-only log.' (Laurie, verified via search snippet)
  - Leaves out: gossip between clients (deferred), performance, benchmarks.

### Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud (NDSS) (2014)

- Why foundational: Gave a bearer credential that can be attenuated offline by anyone who holds it using chained HMACs, with third-party caveats; it is the modern reference construction for delegatable, attenuable tokens.
- Named primitive: the macaroon (chained-HMAC caveated bearer credential)
- Opening move: 'Controlled sharing is fundamental to distributed systems; yet, on the Web, and in the Cloud, sharing is still based on rudimentary mechanisms.' The gap between what is fundamental and what is deployed is the problem statement.
- Structural features:
  - Length: 16 pages (verified by pdfinfo on the Google research copy).
  - One named primitive: the macaroon (nested chained HMAC with caveats and discharge macaroons).
  - Problem-first opening: 'Controlled sharing is fundamental to distributed systems; yet, on the Web, and in the Cloud, sharing is still based on rudimentary mechanisms.' (verified)
  - Security argument: a section on security properties (unforgeability, attenuation-only, contextual confinement) argued from the HMAC chain.
  - Worked example: a photo-sharing scenario with concrete caveats and the HMAC equations written out.
  - Calculations: microsecond-level verification cost per caveat; credential sizes.
  - Refuses to hedge: 'highly efficient, easy to deploy, and widely applicable'.
  - Leaves out: a full formal proof of security, a large deployment study.

### MapReduce: Simplified Data Processing on Large Clusters (OSDI) (2004)

- Why foundational: Two functions and a runtime that hides partitioning, scheduling, and failure; it created Hadoop and a decade of data infrastructure.
- Named primitive: map and reduce
- Opening move: Abstract: 'MapReduce is a programming model and an associated implementation for processing and generating large data sets.' (verified) The first sentence defines the primitive; the introduction then gives the pain that motivated it.
- Structural features:
  - Length: 13 pages (verified by pdfinfo).
  - One named primitive: map and reduce.
  - Problem-first opening: 'Over the past five years, the authors and many others at Google have implemented hundreds of special-purpose computations that process large amounts of raw data...' (verified)
  - Security argument: none; fault tolerance argument instead (re-execution, idempotent outputs, atomic renames).
  - Worked example: word count in section 2.1 with code ('emits each word plus an associated count of occurrences (just 1 in this simple example)', verified) and five more one-paragraph examples.
  - Calculations: grep and sort over 1 TB on 1,800 machines with timing figures; 'upwards of one thousand MapReduce jobs are executed on Google's clusters every day'.
  - Refuses to hedge: 'Programs written in this functional style are automatically parallelized and executed on a large cluster of commodity machines.'
  - Leaves out: formalism, comparison against other systems, anything beyond the two functions.

### Dynamo: Amazon's Highly Available Key-value Store (SOSP) (2007)

- Why foundational: Showed that a production system could trade consistency for availability with a documented set of techniques (consistent hashing, vector clocks, sloppy quorum, hinted handoff, anti-entropy, gossip); it seeded Cassandra, Riak, and the NoSQL generation.
- Named primitive: the always-writeable eventually consistent key-value store
- Opening move: Abstract: 'Reliability at massive scale is one of the biggest challenges we face at Amazon.com, one of the largest e-commerce operations in the world...' (verified). The opening states the business constraint that forces the design.
- Structural features:
  - Length: 16 pages (verified; SOSP pp. 205-220).
  - One named primitive: the always-writeable eventually consistent key-value store (Table 1 maps each problem to its technique).
  - Problem-first opening: 'Amazon runs a world-wide e-commerce platform that serves tens of millions customers at peak times using tens of thousands of servers located in many data centers around the world.' (verified)
  - Security argument: explicitly out of scope (internal, non-hostile environment stated in the assumptions).
  - Worked example: the shopping cart; a vector-clock evolution figure.
  - Calculations: the 99.9th-percentile SLA at 300 ms, production latency percentiles, 99.94% of reads seeing a single version.
  - Refuses to hedge: the 'always writeable' requirement is asserted as non-negotiable.
  - Leaves out: security, formal proofs, range queries, anything the authors did not run in production.

### Kerberos: An Authentication Service for Open Network Systems (USENIX Winter) (1988)

- Why foundational: Made third-party authentication with tickets and authenticators a deployable protocol; it is still the authentication substrate of Windows domains and most enterprise networks.
- Named primitive: the ticket and authenticator
- Opening move: 'In an open network computing environment, a workstation cannot be trusted to identify its users correctly to network services.' The first sentence states the trust failure that the protocol repairs.
- Structural features:
  - Length: 11 pages (USENIX Winter 1988 pp. 191-201).
  - One named primitive: the ticket (plus authenticator) issued by a trusted authentication server and ticket-granting server.
  - Problem-first opening: 'In an open network computing environment, a workstation cannot be trusted to identify its users correctly to network services.' (verified via search snippet)
  - Security argument: threats (eavesdropping, replay, impersonation) and how lifetimes, session keys, and timestamps address them; known weaknesses stated (clock dependence, password guessing, replay within lifetime).
  - Worked example: the message-by-message protocol walkthrough with a notation table.
  - Calculations: none of substance.
  - Refuses to hedge: the model is presented as what Project Athena runs.
  - Leaves out: formal analysis, performance, anything beyond the protocol and its deployment.

### The Protection of Information in Computer Systems (Saltzer and Schroeder, Proc. IEEE) (1975)

- Why foundational: Stated the eight design principles (economy of mechanism, fail-safe defaults, complete mediation, open design, separation of privilege, least privilege, least common mechanism, psychological acceptability) that every security design still cites, and framed capabilities versus access control lists.
- Named primitive: the eight design principles of protection
- Opening move: 'This tutorial paper explores the mechanics of protecting computer-stored information from unauthorized use or modification.' (verified) It announces itself as a tutorial and then defines the vocabulary the field still uses.
- Structural features:
  - Length: 31 pages (Proc. IEEE 63(9) pp. 1278-1308), a tutorial.
  - One named primitive: the eight design principles (and the descriptor/capability versus ACL dichotomy).
  - Problem-first opening: 'As computers become better understood and more economical, every day brings new applications.' (verified) followed by the new exposure that follows.
  - Security argument: the paper is the argument; each principle is stated in one sentence, e.g. fail-safe defaults: 'Base access decisions on permission rather than exclusion.' (verified)
  - Worked example: a progression of descriptor-based protection systems from simple to complex.
  - Calculations: none.
  - Refuses to hedge: principles are stated as principles, not as findings.
  - Leaves out: implementation, evaluation; unsolved problems (confinement, certification) are named in one section rather than hedged throughout.

### Capability Myths Demolished (JHU SRL technical report SRL2003-02) (2003)

- Why foundational: Separated the object-capability model from the access-matrix reading of capabilities and refuted the three myths (equivalence, confinement, irrevocability) that had kept capabilities out of mainstream systems; it is the reference for every ocap design since (Caja, WASI, CHERI's arguments).
- Named primitive: the object-capability model (seven properties)
- Opening move: Opens by naming the myths to be demolished (Equivalence, Confinement, Irrevocability) and attributing them to differing interpretations of one model; the paper then defines the models precisely enough to decide each myth. (Quoted from a search summary; the PDF host was unreachable.)
- Structural features:
  - Length: about 15 pages (mirror unreachable during this review; length from memory).
  - One named primitive: the object-capability model, distinguished by seven security properties across three models.
  - Problem-first opening: names the three myths in the first paragraph (per search snippet: 'The prevalence of these myths is due to differing interpretations of the capability security model').
  - Security argument: the confinement argument and the confused-deputy re-analysis.
  - Worked example: the Lampson access matrix reinterpreted under each model; the *-property example.
  - Calculations: none.
  - Refuses to hedge: the title.
  - Leaves out: implementation, benchmarks, deployment.

### KeyKOS Architecture (Hardy, ACM Operating Systems Review 19(4)) (1985)

- Why foundational: Described a commercially deployed pure capability operating system with a persistent, checkpointed single-level store; its design fed EROS, Coyotos, and the modern ocap kernels Chio's own background section cites.
- Named primitive: the key (capability) with a persistent checkpointed store
- Opening move: Opens by naming the commercial requirements (security, sharing, pricing, reliability, extensibility) the system was built to meet and then promises a complete description of the kernel. (Quoted from a search summary; the cap-lore mirror was unreachable.)
- Structural features:
  - Length: 18 pages (OSR 19(4) pp. 8-25, per search result).
  - One named primitive: the key (capability) and the domain, with whole-system checkpoint/restart.
  - Problem-first opening (per search snippet): 'KeyKOS was originally designed to solve the security, sharing, pricing, reliability, and extensibility requirements of a commercial computer service in a network environment.'
  - Security argument: authority only via keys; no ambient authority; the kernel is described completely so the reader can reason about it.
  - Worked example: the enumeration of kernel object types and what each key permits.
  - Calculations: performance and checkpoint figures reported (from memory; the host presented a certificate error during this review).
  - Refuses to hedge: 'attempts to be essentially complete concerning the function of the kernel'.
  - Leaves out: formal proofs, comparative evaluation.

### Bringing the Web up to Speed with WebAssembly (PLDI) (2017)

- Why foundational: A bytecode designed with a formal semantics from the start by four competing browser vendors, with a type system, soundness, and a memory-safe sandbox; it became a universal compilation target within two years.
- Named primitive: the validated stack-machine bytecode with linear memory
- Opening move: Abstract: 'The maturation of the Web platform has given rise to sophisticated and demanding Web applications such as interactive 3D visualization, audio and video software, and games.' (verified) The opening states the demand before the design.
- Structural features:
  - Length: 16 pages (verified by pdfinfo; PLDI pp. 185-200).
  - One named primitive: the structured stack-machine bytecode with validation (typing) and linear memory.
  - Problem-first opening: 'The Web began as a simple document exchange network but has now become the most ubiquitous application platform ever...' (verified)
  - Security argument: memory safety via bounds-checked linear memory and control-flow integrity by structured control flow; the type-soundness theorem.
  - Worked example: small code listings in both text and binary form.
  - Calculations: PolyBenchC benchmarks relative to native across engines.
  - Refuses to hedge: presents itself as the first industrial-strength VM designed with a formal semantics from the start (from memory of the abstract).
  - Leaves out: garbage collection, threads, exceptions (named as future work); anything not implemented in all four browsers.

