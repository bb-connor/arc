# Authenticated evidence packages

The approved continuation closes package findings EV6/EV7/EV13 and strict receipt
and checkpoint verification EV12. The certificate empty-bundle portion of EV6
belongs to the subsequent EV8 certificate batch. Retained source reads are already
implemented by the preceding receipt lifecycle batch.

## Contract

An evidence package must authenticate its complete manifest and decoded payload
against verifier-supplied kernel public keys. No embedded key grants trust. A
versioned SignedExportEnvelope binds canonical manifest and payload SHA256 hashes,
the export signer and a domain-separated schema. The payload includes the query,
tool and child records, checkpoints, proofs, lineage, retention, uncheckpointed
records, transparency and federation policy. Disk and structured remote imports
use the same envelope and signer checks before accepting any evidence.

All consumed package files must be declared exactly once in the signed manifest.
Required files cannot be omitted, and malformed paths, unsupported schemas,
duplicate fields, weak keys, changed hashes, altered counts, substituted payloads
and modified query/anchor metadata reject. Readers use bounded file acquisition.
Unsigned historical packages require re-export from a trusted source; verification
and import have no implicit compatibility fallback.

CLI export requires an existing private kernel seed file. Library producers pass
their existing kernel key directly. Remote collection remains a transport of
evidence; package signing happens under explicitly configured local custody, and
the seed never crosses that transport. Verify/import require one or more
--trusted-kernel-pubkey values. Every envelope, receipt and checkpoint signer must
belong to that explicit set, supporting configured key rotation. Inclusion proofs
also bind the receipt kernel key to the checkpoint kernel key.

Remote import is an authenticated administrative operation. Its explicit trusted
keys and optional anchor descriptor are separate request parameters, never taken
from the package. The same validation runs before destination stores are opened.
This does not create a persistent remote trust roster or grant tenant callers the
ability to select trust policy.

## Anchor and signature semantics

Without verifier-supplied anchor material, publication state remains local preview
even when a package declares an anchor. An optional --trusted-anchor-file contains
the complete CheckpointPublicationTrustAnchorBinding obtained independently by the
verifier. Each publication must match that descriptor exactly, and the signed
envelope authenticates those bindings. Mismatch fails. This is explicit configured
anchor trust, not online X509, DID or transparency-service discovery.

Receipt, child/lineage receipt and checkpoint Ed25519 verification uses the existing
strict verifier; weak identity keys and small-order signatures reject. Existing
valid Ed25519, ECDSA and hybrid verification remain supported. Tool inclusion proofs
retain their existing format; child records receive envelope and signer coverage,
not a new independent child-proof claim.

## Delivery

Migrate CLI, control-plane import and direct Wall/Mercury consumers together.
Generated product fixtures preserve their in-memory signing identity; external
Mercury evidence input requires explicit trusted keys. Tests exercise real native
CLI export/verify/import, wrong signer, omission plus manifest rewrite, remote
payload substitution, missing/incorrect/exact anchor, and strict weak-key rejection.
Retain failures separately from corrected qualification. One integrated review,
affected-owner tests and workspace lint precede the already-authorized commit/push.
