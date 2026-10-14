# Combined delegation and swarm evolution review

A fresh automated reviewer examined the combined change against base
`96c25e99a188bb8d1d084c7324a30050a2fd496d`, committed head `ddfd54b3c7` plus the
working native tests, manuscript and artifact tools. Scope included the D1
allocator/guard, S1 lifecycle, treaty and replay boundaries, conditional
arguments and evidence handling. The reviewer made no checkout changes and
spawned no additional reviewer.

It found one Important D1 defect, no Critical defect and no additional blocking
S1 or manuscript issue. Its verdict was changes required. The author reproduced
and repaired the finding, and found a clock defect during that repair. Final
qualification passed all 11 commands: 521 Rust test labels, 12 artifact tests,
three strict Clippy commands, two format commands and the runnable example.
One pre-existing workflow doctest is ignored. No second independent review of
the repair is claimed.

## Findings and repairs

**Cross-owner mutation replay (Important).** Signed subdivisions named a local
parent ID and child. Two honest stores with different roots but equal parent
names and holders accepted the same signature. Full-slot offer hashes also
omitted the allocator/root namespace. The reviewer reproduced subdivision replay
against built Rust libraries; the author reproduced subdivision and selection
replay in failing regression tests. No database fork or dishonest issuer was
needed.

The repair binds a persistent random allocator namespace, full immutable root
and target slot into an allocation digest. Subdivision signs the parent's digest;
offers sign the selected allocation; selection signs the complete offer; the
allocator permit repeats the digest. The mutation transaction verifies the
binding. The namespace survives reopen; an issued store missing it rejects
instead of silently creating a replacement. Prepublication signed domains
advance to v2, requiring fresh signatures; no live v1 migration is asserted.

`namespace-review-red.log` records two failing regression expectations.
`namespace-review-green.log` records all 15 tests then passing. The final suite
also covers namespace persistence/loss and signed-permit mismatch.

**Configured clock bypass (Important, author-found).** The guard read wall time
even when the receiver used a different authority clock. A native invocation
expired under receiver time was admitted. The guard now reuses the kernel's
fenced authority clock. `clock-review-red.log` records the unexpected Allow;
`clock-review-green.log` records rejection with zero tool dispatches. All four
repair logs live in `../dynamic-delegation/evidence/`.

## S1 judgment

The reviewer confirmed atomic extension/archive, historical full-bundle/index
checks, stable native continuation IDs and the explicit original-claim
revalidation through the treaty gate. Cross-edge capability digests are not
globally joined by bundle verification, although scopes are checked through
attenuation and native admission compares all incident endpoints with the
task's capability. A conflicting new endpoint can block successor-version
execution of that task; historical dispatch still uses its original artifacts.
No scope widening or continuation refresh was found. The claims therefore cover
retained commitments and demonstrated conditional progress, without universal
capability provenance or arbitrary swarm progress.

## Verification and explicit scope decisions

The reviewer independently passed 12 artifact Python tests and reproduced the
namespace flaw. It did not run Cargo. The author owns repair regressions and
the final source qualification. This is automated engineering/research review,
not outside scientific critique.

| Behavior set aside by the reviewer | Author's disposition and cost |
| --- | --- |
| Independent operators, interoperability, economics, integration advantage, foundational novelty | Remain open research gates; local tests cannot close the requested publication bar. |
| Unified D1/S1/F1 execution | Separate evaluated profiles; the next integration must bind existing resource custodians explicitly. |
| Global information flow and arbitrary tool correctness | Host confinement and selected predicates remain assumptions, with no general usefulness or disclosure guarantee. |
| Reclaim, migration, epoch replacement, consensus, malicious protected-store administration | Excluded additive/protected-state boundary; capacity can remain stranded and copied authorities can equivocate. |
| All crash cuts and recovery after expiry | One actual kill cut; completion rechecks expiry and may remain stranded. No universal recovery or exactly-once effect guarantee. |
| Fresh F1 qualification | Historical source pin remains distinct; current checks cannot promote modified funded paths or a release. |
| Complete Rust qualification and artifact freeze | Author must finish before closing the implementation plan; pending evidence is not passing evidence. |
| Namespace repair and later fixture edits | Author verifies regression failures, passing reruns and final suites; no second independent review implied. |

No cosmetic Minor item was deferred. Initial compiler, fixture and suite failures
remain retained. Final command status and source hashes live in
`../dynamic-delegation/evidence/qualification.json`.

Final author disposition: the material findings are closed by the retained
regressions and full declared qualification. The local implementation and
manuscript boundary is complete; the external scientific/publication gates
remain open. Final code commit: `8cca48fb2a`. Qualification SHA-256: `5e4b5dfcd54ee6cca4d82513905cc186ae2a3ee53b1be82683d8ae03a59001ce`.

PDF/artifact validation: `make build` exited zero and reproduced the frozen
PDF. `tools/check.py --publication` exited one for exactly the four open
research gates and two false readiness flags. The retained logs are
`evidence/paper-build.log` and `evidence/publication-gates.log`. This expected
publication refusal does not change the passing local artifact result.
