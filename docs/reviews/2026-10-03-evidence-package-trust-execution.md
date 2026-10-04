# Authenticated evidence package execution, October 3, 2026

Qualified source `67b20708a7691a69a26340baee4f189b75993801` is committed and pushed on
`packet/3-retention-accounting`, based on
`0a455ac2c0fb9641b96d36bb2289bcd8047c325b`. The remote ref matched that exact
source commit after publication. The [publication record](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-evidence-package-trust/source-publication.json)
retains the observation and qualified source-manifest hash. This documentation-only
follow-up records publication without changing the qualified source. This record owns EV6 package authenticity and trusted signer
inputs, EV7 external anchor acceptance for Chio evidence packages, EV12 strict
receipt/checkpoint signatures and EV13 receipt/checkpoint signer binding.
The certificate portion of EV6 and the distinct Mercury proof-package trust
format remain open.

## Implemented behavior

The existing `SignedExportEnvelope` signs the new
`chio.evidence_export_commitment.v1` domain, canonical manifest digest and complete
decoded payload digest. The envelope authenticates query, tool and child records,
checkpoints, proofs, lineage, retention, uncheckpointed records, transparency and
the federation policy. Disk verification and decoded remote import share the same
verifier. Required files must appear exactly once in the signed inventory.
Missing envelopes, schema substitution, omitted records, rewritten manifests and
divergent structured payloads fail closed. Duplicate signed JSON fields reject
before typed consumption.

Export requires existing private `--kernel-seed-file` custody before effects.
Verify/import require independent `--trusted-kernel-pubkey` pins; repeat the flag
to configure rotation. Every envelope, tool receipt, child receipt and checkpoint
signer must belong to that set, and each tool proof requires exact equality of its
receipt and checkpoint keys. Receipt, child/lineage, envelope and checkpoint
verification use the existing strict cryptographic verifier, rejecting identity
key forgeries and small-order Ed25519 points.

An optional `--trusted-anchor-file` supplies the complete independently obtained
publication binding. All publication descriptors must match it exactly, including
certificate reference and profile version. The signed payload covers the binding.
Without that input, package-supplied anchor metadata remains a transparency preview.
These are configured trust inputs, not online certificate or transparency discovery.

Authenticated remote import validates before leader forwarding or store opening.
An administrative service token authorizes the independent policy supplied with
that import. Rejected requests cannot leave a stored share. Remote export gathers
raw evidence and signs locally; no private seed crosses the transport. Wall and
Mercury producers retain their existing in-memory kernel identity, and Mercury
proof export now requires explicit pins when reading a Chio evidence package.

Uncheckpointed records have their own required file and must exactly match the
unproved receipt set. Authentic advisory records roundtrip with zero authorization
claims. Children have pinned signatures and envelope coverage; this batch adds no
independent child Merkle proof. Unix readers use descriptor-relative no-follow,
nonblocking opens, accept regular files only, and bound each read to 64 MiB. The
manifest limits declared file data to 256 MiB.

Operator flags, trust distribution and unsigned-package migration are documented
in the [export guide](../release/COMPLIANCE_EVIDENCE_EXPORT_PLAN.md). The
[design](../superpowers/specs/2026-10-03-evidence-package-trust-design.md) and
[plan](../superpowers/plans/2026-10-03-evidence-package-trust.md) retain the selected
scope and task acceptance.

## Qualification

The immutable [command index](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-evidence-package-trust/README.md)
retains every terminal command, exit and log hash, including failed campaigns.

| Owner | Passing tests | Terminal command |
| --- | ---: | --- |
| Core types, complete default library | 435 | `core-signature-owners` |
| Kernel checkpoint/export modules | 76 | `kernel-evidence-owners` |
| Control-plane evidence package module | 40 | `qualified-control-package-owners` |
| CLI native evidence workflows | 14 | `qualified-native-package-owners` |
| Mercury native consumers | 41 | `mercury-native-consumers` |
| Wall complete unit/native suites | 25 / 3 | `wall-owner`, `wall-native-consumers` |

These are 634 scoped runtime passes, zero failures and no ignored tests in the
accepted runs. An additional 80 receipt tests pass with `pq,fips` enabled,
including hybrid floors, P-256 receipts and strict weak-key rejection. These
overlap default cases and are reported separately, not added as distinct tests.
This backend check does not establish FIPS certification. This is not a full
workspace runtime campaign. All 14 CLI cases
include real local export/verify/import and the authenticated remote route; its
rejection controls leave no imported share before the accepted native import.

The owner build uses one locked feature graph across core-types, kernel,
control-plane, CLI, Mercury and Wall. Executable hashes bind direct runtime
commands to the builds. Full workspace all-target Clippy passes with `-D warnings`.
Formatting, trust-boundary, clock, negative-assertion, wire-schema, domain and
arithmetic gates pass. No decoder/SQL debt or negative-assertion allowance was
added. Wall's module allowance was removed and Mercury's test cap reduced after
normal module extraction. The new schema has a pinned wire-shape/domain test;
the unpinned schema count stays at 168.

The RED record demonstrates weak tool/child/envelope/checkpoint signatures,
self-claimed anchor promotion, unsigned package acceptance and receipt/checkpoint
signer substitution. Native RED also demonstrates missing custody/trust flags;
its initial roundtrip and anchor cases stopped at the then-unsupported flag.
Later owner failures are retained separately: one unsigned-package fixture needed
the admin-all child scope; the duplicate-input assertion first expected public
message text and then the wrong error variant; the remote fixture used the wrong
existing transparency wire field. Corrected fixtures require exact rejection
codes/variants and typed request decoding. The first strict lint run failed on
two needless fixture borrows; both are fixed without allowances. Initial reader,
file-size and schema gates remain failed records before reconciliation.

## Review and rulings

One independent read-only review returned **With fixes**: no new consequential
production defect, two Important fixture corrections, no Critical or Minor. The
author adopted those grades because both tests must reach the intended trust
boundary. Both fixture fixes now have terminal owner passes (40/40 and 14/14);
no production source changed during review and no Minor remains deferred. The [review](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-evidence-package-trust/independent-review.md)
preserves the original verdict; the
[ledger](https://github.com/bb-connor/arc/blob/ecb44791501c2aba671de2a967d2506f039ab42e/docs/reviews/artifacts/2026-10-03-evidence-package-trust/progress.md) records each failed
run, correction and declined-boundary ruling. No second review is requested.

The design deliberately requires trusted-source re-export of unsigned packages;
per-import administrative pins rather than a receiver-owned roster; local custody
for remote collection; and externally distributed descriptor trust. Those choices
place key/descriptor distribution with operators and make the service administrator
a trust-policy authority. Full-bundle certificates, independent child Merkle
proofs, equivalent Windows filesystem race protection, downstream Mercury proof
trust and hosted/release/operational acceptance remain outside this qualification.

## Deferred certificate work after foundation landing

The [October 4 landing ledger](../security/landing-ledger.md) owns the current
execution order. The following scope is preserved for a later security slice.

Implement non-vacuous session certificates (EV8, EV17 and the remaining EV6
certificate case): collect real retained receipts by signed session metadata,
derive or require evaluation policy, check actual guard verdicts and capability
scope/delegation, validate session continuity/timestamps, and reject empty or
incomplete full bundles under independent signer pins. Drive this through native
positive, omission, substitution, bad-guard and wrong-anchor tests. The separate
Mercury proof-format follow-on is withdrawn from this security execution queue.

The user's subsequent instruction prioritizes the
[P0/P1 review and repairs](2026-10-03-security-p0-p1-review.md) before any further
roadmap execution. That review also retains broader EV1/EV2 privacy as unfinished
work; no certificate implementation is authorized by this status paragraph alone.

Remaining EV5 launchers, EV1/EV2 secret minimization, EV3/EV4 denial evidence,
SIEM defects, other key/guard/release findings and hosted qualification remain
queued separately. No full-roadmap, merge, deployment or release completion is
claimed by source publication.
