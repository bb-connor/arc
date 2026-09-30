# Remaining CLI reader execution

Base: `da4086017f`. Scope: the 29 paths in the preceding reader handoff.

1. Finding, attestation and workflow: bounded original bytes, canonical custody, private keys, current-only status floors, fenced time, preserve verified authority before effects.
2. Buyer, treaty and pheromone: bounded documents and aggregate collections, archive namespace validation, private signing material, authenticated peer identities.
3. MCP, runtime, lineage and market: strict original decoding, bounded transport/files, enforcing-host and signed-policy checks, bind retained records to requested identities.
4. Focused owner qualification, one whole-batch review, inventory reconciliation, source/evidence hashes and local commit.

## Review focus

Inspect effect ordering, typed error propagation, aggregate limits, canonical versus native-number contracts, private-key lifetime, obsolete-schema acceptance, response identity, stored record binding, and host-enforcement gates. Parsing does not grant authority.

## Execution decisions

The user authorizes action-first implementation and batched focused checks. Existing isolated worktree is retained; no per-task agents or repeated broad builds. Existing `output/` is unrelated and untouched. One final independent review covers the whole batch.

## Ledger

- Scope and base verified; all tracked files clean before work.

- Main 29-reader implementation landed in the working diff; focused iroh-enabled compile exposed four integration errors (missing import, three fallible-clock call sites) and one stale optional-key test expectation. All were repaired; initial terminal build failure retained.
- One independent final review reported aggregate failed-read accounting, private profile lifetime, publish response binding and a binary/document limit distinction. Repairs passed the first complete focused run. The final implementer review then tightened initialization replay custody; its final qualification is recorded with the artifact index.
- Decision: opaque supply-chain artifacts have a separate 512 MiB bound; JSON retains its 16 MiB bound. Larger artifacts reject explicitly.
- Decision: private profile Deserialize uses wiping temporary fields and transfers ownership to wiping profile types, preserving the current document format. Public profile selection parses only a schema header before the owning canonical decoder.
- Scope boundary: native host enforcement and cryptographic implementation correctness remain existing owner responsibilities; this local batch retains their checks and does not requalify hosted/native platforms. Hostile concurrent ancestor replacement still requires OS isolation.

- Initial focused run: 231 passes and 14 fixture/expectation failures; repaired without weakening production checks. Subsequent run: 245 passes, plus 18 integration tests and one profile-custody test. Final evidence includes the added private/public initialization replay controls.
- Final implementer review: private initialization replay now validates the opened file under wiping custody and rejects unsafe permissions rather than repairing them; public replay uses its own exact-content contract.

- All four scoped tasks are complete: the 29 reader owners and supporting custody/clock/archive repairs; final 266-test focused qualification; ratchets and semantic inventories; bounded execution record, source/binary hashes and next 28-reader protocol handoff. Local commit is the delivery boundary.
