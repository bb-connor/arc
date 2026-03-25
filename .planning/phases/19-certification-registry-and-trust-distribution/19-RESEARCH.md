# Phase 19: Certification Registry and Trust Distribution - Research

**Researched:** 2026-03-25
**Domain:** Signed certification artifacts, local registry persistence, and
trust-control distribution
**Confidence:** HIGH

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| CERT-01 | Signed certification artifacts can be stored, versioned, and retrieved through a registry surface with stable IDs and immutable artifact verification | The signed artifact already provides canonical payload and signature material; the missing piece is a file-backed registry entry model keyed by a deterministic digest |
| CERT-02 | Relying parties and operators can resolve the current certification status of a tool server, including superseded or revoked artifacts | Resolution can be implemented safely as a pure status layer over the immutable artifact registry, exposed both locally and over trust-control |

</phase_requirements>

## Summary

The certification flow already had the hard cryptographic part: a signed check
artifact. Phase 19 should treat that signed blob as immutable and layer a
registry around it rather than inventing a second certification document.

The central design constraint is that status changes must never mutate the
artifact itself. Stable artifact identity should come from a canonical hash of
the signed JSON, while supersession and revocation live in adjacent registry
metadata.

## Recommended Architecture

### Registry Model
- `artifact_id`: SHA-256 of canonical signed artifact JSON
- store full signed artifact, digest, status, timestamps, optional superseded
  or revocation metadata
- keep file format versioned for future compatibility

### CLI and Trust-Control
- local CLI:
  - `pact certify verify`
  - `pact certify registry publish|list|get|resolve|revoke`
- remote trust-control:
  - `GET/POST /v1/certifications`
  - `GET /v1/certifications/{artifact_id}`
  - `GET /v1/certifications/resolve/{tool_server_id}`
  - `POST /v1/certifications/{artifact_id}/revoke`

### Resolution Semantics
- identical republish is idempotent
- newer active artifact supersedes the previous one for the same tool server
- resolution prefers active, then revoked, then latest remaining entry

## Validation Strategy

- `cargo test -p pact-cli --test certify -- --nocapture`

## Conclusion

Phase 19 is a storage-and-distribution layer around the existing signed
artifact, not a new trust model. The safest implementation keeps the artifact
immutable and makes registry state explicit.
