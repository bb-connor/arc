# Provider reader qualification

Source base: `82eec927b20ec4dae1fff2a4eb149fef4592c817`. The owning commit contains
this record and the source hashes; no candidate-SHA self-reference is required.

All 28 pinned reader paths are disposed in [reviewed-readers.json](reviewed-readers.json).
Additional implementation contracts are in [supporting-owners.json](supporting-owners.json).
The raw decoder baseline falls from 194 to 166 workspace files, including zero
remaining protocol and CLI baseline files. These are semantic review counts,
not a vulnerability count or full protocol-security closure.

## Terminal evidence

- [Final package campaign](qualified.log): **596 passed, 0 failed, 0 ignored**,
  across 63 test targets in 12 packages; all eight provider fixture features,
  Anthropic computer-use, OpenAI provider-adapter and contract reqwest egress
  are enabled. Commands, environment and 35.46-second elapsed time are in
  [qualified.json](qualified.json).
- [Trust inventory](inventory-final.log): 404 original-input constructors,
  85 tenant tables and 170 explicit SQL principal contracts.
- [File hygiene](file-hygiene.log), [negative assertions](negative-assertions.log)
  and [wire schemas](wire.log): pass without raising limits or exemptions.
- [Changed-file formatting](format.log): pass on the recorded source set.
- [Qualification summary](qualification.json), [source hashes](source-hashes.json)
  and [test-binary hashes](binary-hashes.json) bind the local evidence.
- [Independent review resolutions](review-resolutions.md): three important
  findings and one native-source gap resolved, with explicit rulings for every
  behavior the reviewer declined to judge. One review, no delegated implementation.

The final campaign covers original/duplicate argument decoding, fragmented call
assembly, complete message/choice termination, no evaluator calls on invalid
tails, actual chunked HTTP bounds, redirect rejection, native error retention,
redacted diagnostics, real AWS SDK decoding through an injected HTTP replay
client, bounded file custody, subprocess output/deadline/descendant cleanup,
and final Anthropic recorder argument reconstruction.

## Prior attempts retained

| Attempt | Result and remediation |
|---|---|
| [Initial build](build-initial.log) | New provider error variants required exhaustive taxonomy-test arms. |
| [Initial campaign](test-initial.log) | Two timeout mocks needed a native source field. |
| [Second campaign](test-second.log) | 541 passed, 48 failed. Old public-string expectations and incomplete synthetic lifecycle fixtures were repaired; an unused import was removed. The new stricter production checks were retained. |
| [Third campaign](test-third.log) | 593 passed; review fixes qualified before the additional recorder reconstruction repair. |
| [Recorder build](test-final.log) | Its child module required an explicit path under the existing path-attributed recorder module. |
| [Recorder retry](test-final-retry.log) | 594 passed. |
| [Final campaign](qualified.log) | 596 passed, including adjacent Gemini/Groq refusal-text redaction checks. |
| [Inventory update](inventory-initial.log) | The updater incorrectly treated the checker's `(errors, snapshot)` tuple as an error list after persisting the correct census. Its first element was empty; the standalone final checker passed. |

The user requested action-first batching. This record does not claim a red/green
campaign for every edit or a second independent review of the final fixes.
Only dependency edges changed in Cargo.lock; no dependency versions changed.
Raw command logs retain their terminal blank lines. Full diff whitespace checking
reports those three log-only EOF warnings; source and documentation diff checks
pass with only the raw `.log` artifacts excluded.

## Acceptance boundary and next work

This is local hermetic/package qualification, including local HTTP and native AWS
SDK codec tests. No live provider credentials, OCI VM, hosted CI, merge, release
or activation were used. Full workspace and M5 acceptance remain separate.
Unix fixture opens and Linux process groups have targeted controls; hostile
ancestor replacement and deliberately escaped descendants need OS isolation.
The existing Cohere assembled-event and Gemini whole-call protocol contracts
are retained; this batch does not qualify a new live event-model implementation.

Next: the [35 pinned trust readers](next-readers.json), covering attestation and
credential imports, custody/TEE/remote-signing boundaries, and federation and
pheromone persisted or exchanged evidence. Preserve original signed bytes and
native signed numeric domains while bounding input and retaining typed causes.
