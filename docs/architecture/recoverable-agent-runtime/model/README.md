# Bounded protocol exploration and review models

This dependency-free Rust program explores the abstract recovery ownership protocol for one effectful workflow step. It is an architecture artifact, not production code or a native store test.

The finite model has two possible continuations, two coordinators and at most two owner epochs per continuation. It explores every reachable state under selection, verified approval, ownership takeover, capture, external effect with lost response, process death, authoritative completion and verified final no-effect closure. Durable state survives the modeled process death; local coordinator handles do not.

The baseline checks exclusive unresolved ownership, current owner epoch, consumed authority before capture-derived execution, closure truth and at most one effect for the single modeled step. A no-effect closure preserves the old continuation's consumed authority. A new continuation may then request distinct authority. Successful completion forbids a new continuation for that step.

Four deliberate mutations must produce counterexamples: overlapping selection, ignored owner epoch, replaying an unknown effect and treating unknown as no effect. Their shortest discovered traces are retained in [results](results.txt), and the runner verifies the intended failure reason. A million-state guard aborts with an error rather than reporting partial exploration as success.

The model assumes atomic authoritative transitions, authentic verified approval/no-effect evidence and correct external outcome evidence. It does not model cryptographic forgery, actual SQL transactions, process-authority reservation bridging, artifact publication, prerequisite DAGs, clock changes, liveness/fairness or all kernel participant states. Those require the specified implementation and additional models/tests. Identical state reduction is not proof that real code correctly implements it.

The [review runner](review.rs) adds four independent, smaller finite models:

| Model | Bounds and assumptions | Required mutation failures |
|---|---|---|
| Admission | One immutable intent, one delayed submission, one native operation and one possibly missing projection; atomic native closure/capture | Closing from a missing projection; admitting after terminal closure; capturing after cancellation wins |
| Knowledge | One fixed public preparation, one restricted observation/release and one capture; native flow generation is abstracted to old/new | Releasing before a native join; ignoring the changed flow fence |
| Replay | One committed command, revisions 0 through 2, one revocation and one replay | Checking the stale revision before resolving replay; returning cached protected data after revocation |
| PartialEffect | One effectful step with successful or partially applied settlement and independent result release | Treating partial failure as no effect and dispatching again |

[Review results](review-results.txt) retain each baseline and eight expected counterexamples. Each model enumerates every reachable state under its finite transitions, with a 100,000-state failure bound. These are separate abstractions, not a composed proof: in particular, they do not model the full process/store bridge, provider deduplication, cryptography, actual byte custody, timing or fairness. Release approval, native evidence and immutable payload correctness are assumptions, not verified implementations.

The [third-pass runner](third.rs) adds an envelope/nonce protocol with one native operation, one possible crash, expiry/cancellation and durable attachment from the original issuance. Its baseline explores 133 states and 252 transitions and requires successful settlement after losing the issuance acknowledgement and reopening. Five mutations test missing request custody, preflight before retained intent, renewal after a process-cache miss, rewriting the frozen process envelope, and requiring a live initiating grant for already-owned internal settlement. The last check is local enabledness under available recovery authority, not eventual liveness or scheduler fairness.

Its [symbolic coverage corpus](third_contracts.rs) checks 3,844 cases: four distinct authority obligations, four exact context bindings, and two-signature principal-alias combinations. Three mutations test accepting partial coverage, mixing approval contexts, and counting two aliases of one principal toward a two-principal requirement. These are small semantic models with assumed authentic scoped attestations. They do not test real signatures, full label algebra, grant consumption storage or production schema decoding. [Third-pass results](third-results.txt) retain the baselines and eight intended counterexamples. No model in this package alone proves the complete composed architecture.

From the development checkout root:

```sh
python3 docs/architecture/recoverable-agent-runtime/model/run.py
python3 docs/architecture/recoverable-agent-runtime/check.py --write-report
```

The runner checks formatting, compiles all three programs with Rust 1.94.1 and warnings denied, runs them, and records [evidence](evidence.json) binding every Rust source, the runner, compiler identity and output hashes. The architecture validator checks those bindings before accepting retained output. Editing a model requires rerunning it. This is reproducibility metadata, not an independently attested build.

Compiled binaries use a temporary directory outside the repository. The models introduce no workspace dependency, manifest change or production runtime behavior.
