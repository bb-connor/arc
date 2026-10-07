# P2 execution plan

Phase: explanations, architecture revision 3. Preserve the verified P1 dirty
source baseline in `source-baseline.json` and its retained archive. Implement all
eight SIM obligations in `04-counterfactuals.md` without adding execution rights
to advice, reports, signatures or projected references.

| Task | Deliverable | Obligations |
|---|---|---|
| P2-01 | Closed, bounded snapshots and resolved remedy facts; explicit per-source versions, gaps, integrity and information-flow context | SIM-01, SIM-02 |
| P2-02 | Deterministic finite evaluation, complete dependency coverage, explicit search exhaustion and partial-order alternatives | SIM-01, SIM-05 |
| P2-03 | Canonical classified report envelopes and expected-trust verification with independent pure recomputation | SIM-06 |
| P2-04 | Audience-bound signed views, opaque random references and conservative projection without protected transitive commitments | SIM-04, SIM-08 |
| P2-05 | Authenticated bounded read-only host explanation adapter, protected inspection and common transport; current native validation remains mandatory | SIM-03, SIM-07 |
| P2-06 | Differential, mutation, leak, ownership, native-staleness and portability acceptance; complete source review and operating contract | All eight |

The planner accepts explicit data and supplied time only. It has no clock reads,
filesystem, network, signing, store, runtime or dispatch ports. Report signing
uses an independent advisory signer and grants no native permission. Dry-run
report construction does not require a live kernel, process runtime, disclosure
issuer or budget mutator.

Declared ceilings before execution: 32 observed facts, 16 registered remedy
templates, eight dependencies/steps per template, 16 returned alternatives and
4096 work units. Existing 64 KiB ingress, depth 16, 4096 JSON nodes, aggregate
32 KiB string content and bounded visitors remain in force. Report/view validity
is at most 30 seconds; relevant fact, capability and deployment deadlines further
restrict classified reports. Projected restricted views have a fixed public
window and cannot expose secret deadlines, candidate counts or basis digests.
The explanation listener has separate bounded capacity and finite per-actor
intake. It performs no implicit provider consult or retry.

New P2 schema identifiers use `https://chio.computer/schemas/`. Existing P0/P1
and legacy schema identities remain stable. Unknown schema references refuse
through the finite local catalog.

Acceptance must recompute signed reports from authorized original inputs;
refuse correctly re-signed semantic substitutions; preserve uncertainty across
mixed observation versions; produce deterministic results under permutations;
retain non-comparable alternatives; make hidden worlds indistinguishable in the
restricted response; reject reports at live APIs; and prove stale policy/source/
recipient observations cannot bypass P1 admission and capture. Review every
authored source and signed-wire/projection boundary. Resolve all discovered P0/P1
severity findings before completion. Local phase acceptance and hosted/provider/
production qualification remain separate claims.
