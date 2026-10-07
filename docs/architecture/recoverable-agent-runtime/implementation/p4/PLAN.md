# P4 execution plan

Phase: durable knowledge, architecture revision 3. The P3 source baseline and
all 108 sealed P3 artifacts are retained without modification. All 13 P4
obligations (CON-09 and ART-01 through ART-12) remain mandatory.

| Task | Deliverable | Obligations |
|---|---|---|
| P4-01 | Closed artifact version, provenance, release, certificate and checkpoint contracts | ART-01, CON-09 |
| P4-02 | Durable reserved/staged/metadata/available publication with quarantine and exact reconciliation | ART-02, ART-03, ART-11 |
| P4-03 | Audience-scoped opaque references and fresh mediated native reads | ART-04, ART-10, ART-12 |
| P4-04 | Provenance-preserving copy, derivation, signed export/import and exact adoption | ART-05, ART-06, ART-08, CON-09 |
| P4-05 | Labeled checkpoint CAS, provider context binding and monotone restore | ART-07, ART-08, ART-12 |
| P4-06 | Retention, protected live pins, generation-barrier collection and permanent ownership tombstones | ART-09 |
| P4-07 | Native fault/race/restart/refusal acceptance, portable contracts and complete source review | All 13 |

The supported backend is the existing private bounded SQLite process blob
journal, with FULL synchronous commits and exact digest/size verification.
There is no caller-selected filesystem path, writable alias or chunked release.
Filesystem brokers and streams beyond one MiB refuse in this profile. No watcher
or pathname lookup provides authority. Raw worker/checkpoint/operator companion
routes are durably disabled when the enforced profile activates. Legacy bytes
remain private and quarantined until exact-content signed adoption.

Bounds declared before implementation: one MiB per immutable blob, existing
per-process tree quotas, 16 direct dependencies per version, at most 64 versions
per bounded traversal, 16 versions per archive, 16 host-selected recipients, eight model
context artifacts, 256 KiB protected records, 64 KiB canonical contract ingress,
4096 portable verification work units. Overflow refuses rather than dropping
inputs. Existing recovery and native row/journal quotas remain in force.

Metadata, releases, pins and lifecycle state use existing protected recovery
records/events and authority-wide rollback anchors. Native knowledge joins use
an affine monotone mutation owner and lossless row images in that same authority,
folded into the existing global native history order. No second knowledge store
or transaction across SQLite databases is claimed. Blob staging and metadata
publication have explicit independent commit cutpoints.

Release commits current recipient identity, the complete monotone source join
and stable intent before the first byte. Unknown acknowledgement requires exact
anchored readback. Recipient or authority changes refuse. A captured return and
a separately admitted artifact release remain distinct. Provider/model contexts
are retained as labeled state; outbound provider requests still require native
effect admission and an independently selected provider contract.

One-shot semantic endorsements cannot classify persistent artifacts. Only an
independently selected exact-content classification/projection certificate may
create a new authoritative provenance root, with input identity and influence
retained. Copies and imports preserve restrictions; restore never resets newer
knowledge. Collection retires availability under the serving writer before blob
removal and preserves all replay and ownership records.

Acceptance must exercise the real process journal, fenced serving authority,
native flow rows, restart and corruption boundaries. Local verification does
not imply Linux confinement, hosted CI, live provider or production deployment
qualification. Resolve all scoped P0/P1 severity findings before sealing P4.
