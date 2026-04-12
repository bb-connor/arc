# MERCURY Threat Model

**Date:** 2026-04-02  
**Audience:** Security, engineering, and risk reviewers

---

## 1. Security Objectives

MERCURY's security objective is not to prove every external fact. It is to
protect the integrity, traceability, and portability of workflow evidence
inside the MERCURY trust boundary.

Security goals:

- prevent forged or altered workflow records
- preserve linkage between receipts and retained source artifacts
- detect omission or tampering in publication
- scope retrieval access appropriately
- make compromise or degradation visible

---

## 2. Assets

Primary assets:

- signing keys and publication credentials
- receipt bodies and checkpoint chain
- evidence bundles and source artifact references
- reconciliation metadata
- verifier trust anchors
- API access controls and entitlement mappings

---

## 3. Adversaries

- malicious workflow actor trying to forge or reshape evidence
- insider with storage or operational access
- external attacker targeting keys, storage, or APIs
- operator error that weakens retention, publication, or entitlement controls
- skeptical reviewer or regulator testing integrity claims

---

## 4. Trust Boundary

Trusted:

- receipt construction logic
- signing backend
- checkpoint generation
- evidence retention controls
- publication process

Partially trusted:

- mirrored or source-system inputs
- market-data artifacts
- external review systems

Untrusted:

- any system outside the documented capture path
- actors attempting to inject or overwrite evidence

---

## 5. Threat Categories

### Key compromise

If the signing key is compromised, false records can be produced.

Mitigations:

- hardened key storage
- rotation procedures
- published trust anchors
- incident response and revocation plan

### Receipt tampering

An attacker may try to modify a stored record after signing.

Mitigations:

- canonical signed receipt body
- checkpoint commitment
- verifier-side integrity checks

### Artifact substitution

An attacker may keep the receipt but swap the retained source artifact.

Mitigations:

- stable bundle references or hashes
- verifier-side bundle integrity checks
- retention and chain-of-custody controls

### Omission in publication

An operator may omit records or selectively publish proof material.

Mitigations:

- contiguous checkpoint publication
- external witness or immutable publication step
- monitoring for sequence gaps

### Overbroad retrieval access

A reviewer or client may gain access to records outside their entitlement.

Mitigations:

- account, desk, and client scoped entitlements
- separation between business access and raw agent identity
- audit logging on retrieval

### False confidence from untrusted inputs

Users may mistake hashed external artifacts for independent truth.

Mitigations:

- explicit proof boundary in product and API docs
- separate provenance fields for third-party-attested artifacts
- reviewer guidance on trust assumptions

### Operational degradation

Backups, publication, or retention may fail silently.

Mitigations:

- monitoring and alerting
- degraded-mode documentation
- periodic recovery tests

---

## 6. Residual Risks

MERCURY does not eliminate:

- incorrect or malicious external source data
- off-system workflow activity
- poor policy design
- inadequate human oversight
- broader environment compromise outside the evidence path

These must be addressed by surrounding systems and governance processes.

---

## 7. Expansion-Specific Risks

If MERCURY moves into mediated live control, additional risks become material:

- higher availability requirements
- fail-open versus fail-closed tradeoffs
- credential custody for downstream systems
- tighter change-management expectations

If ARC-Wall is added, model-memory and prompt-injection risks remain relevant
even when tool-boundary enforcement is strong.

---

## Summary

MERCURY's threat model is centered on evidence integrity, publication
credibility, and retrieval control. It should be evaluated as an evidence
system with explicit trust boundaries, not as a system that removes all trading
or compliance risk.
