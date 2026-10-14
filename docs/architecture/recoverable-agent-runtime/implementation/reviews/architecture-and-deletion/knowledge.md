# Knowledge ownership and format decisions

This is a source review of the pinned subject, not collection acceptance.

## Required owners

The admission Store owns publication metadata, restrictions, reference custody,
checkpoints, restore intents and retirement barriers. The Process broker owns
physical objects. Collection crosses these owners: `knowledge/lifecycle.rs:411`
first retires metadata and establishes a sweep; the host collects the exact
sealed object; `:455` acknowledges that sweep before releasing publication
capacity. Removing the barrier/acknowledgment distinction would admit new
references while bytes are being collected.

The active reference index is separate from immutable owner history
(`knowledge/references.rs`). Its purpose is bounded current custody lookup,
not a second artifact database. `lifecycle.rs:239` queries active owners;
`:244` trusts an empty result only with complete writer coverage. Keep that
condition. Missing or older coverage cannot mean zero references.

Checkpoint writes preserve a previous revision, retain reference ownership,
write the new envelope, and publish an authenticated head in one native
transaction (`knowledge/checkpoints.rs:61`). Keep identity framing and exact
id/revision checks even if old-format readers are removed. Those are current
correctness, not compatibility overhead.

## Concrete old-format candidates

| Surface | Evidence | Decision |
|---|---|---|
| Colliding checkpoint-key reader | `checkpoints/head.rs:35`, `:109`, `:143` | Conditional removal. Old raw keys, ambiguous-slot resolution and scanning for the highest surviving revision exist to read the earlier PR format. With no supported old data, retain only framed latest/revision keys and reject old catalogs. Keep adversarial current-key collision tests. |
| Publication keys without actor binding | `knowledge.rs:188-207` and optional `publication_principal` | Conditional removal. Old publication identities must not silently acquire a new actor. A supported migration needs an explicit attribution/quarantine rule. |
| Reference readiness V1/V2 | `references/ready.rs:48-67`, `lifecycle.rs:247-301` | Conditional removal as one unit. Older markers lack complete writer coverage and require conservative history scans. Do not merely relabel them V3. Current V3 producers, custody checks and cold activation remain necessary. |
| Shared content-generation sweep keys | `lifecycle.rs:39-54`, `:111-192`, `:509-524` | Conditional removal only after confirming all supported Process objects use independent `object:<uuid>` seals. Old shared bytes require all owners' barriers; modern object collection must retain exact seal matching and orphan cleanup. |
| Old interned-label journal codec | `security_participant_state/knowledge/encoding.rs:64`, `knowledge/encoding/legacy_labels.rs` | Conditional removal after checking old journal support. Keep current atom/chunk codec and exact native custody. |

These formats were introduced within this PR. That fact makes them candidates;
it does not prove that the user's development databases contain no such data.
Preserve an immutable archive or explicit offline migration path for any data
that must survive. Do not maintain arbitrary intermediate formats indefinitely
without a named consumer.

## A misleading name that must not drive deletion

`checkpoints/restore/encoding.rs` has `Legacy`, `Compact` and `Chunked` variants.
It would be wrong to delete `Legacy` just from its name. The **current writer**
at `logical_body:243` intentionally emits that ordinary representation whenever
it fits the 262,144-byte row ceiling. Larger logical values use the atom table;
larger atom bodies use authenticated immutable chunks. These are also size
tiers in the current format, not just three release generations.

Rename the internal `Legacy` variant to `Inline` or `Plain` after confirming
its untagged serialization remains byte-identical. Keep all three size tiers
unless a measured replacement handles the full supported label envelope under
the existing row/resource bounds. The old `interned_labels_v1` native journal
decoder is a different compatibility obligation and can be assessed separately.

## Remaining gaps in this bounded review

The checkpoint save/read implementation, key resolution, restore encoding,
reference readiness and collection lifecycle were read. All reference producer
and physical-liability implementations have not been reviewed line by line.
The currently parked capture work remains excluded. Consequently this document
does not approve replacing the reference index with a counter, nor does it
establish that every producer is integrated or that normal traffic never
exhausts capacity.
