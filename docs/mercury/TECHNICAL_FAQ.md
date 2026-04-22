# MERCURY Technical FAQ

**Date:** 2026-04-02  
**Audience:** Engineering and security teams evaluating MERCURY

---

## Architecture

### How does MERCURY integrate with an existing trading stack?

The initial product integrates through replay, shadow, paper-trading, or
supervised workflow inputs. It captures workflow events, approvals, and source
artifacts, then turns them into signed evidence records and `Proof Package v1`
exports. The first workflow is usually a controlled model, prompt, policy, or
parameter release or rollback path. Production OMS/EMS or FIX integrations are
supported as a later funded path, one integration at a time.

### Does MERCURY sit in the live execution path?

Not by default. The initial product is designed to provide evidence without
requiring in-line control. Mediated live control is a supported expansion path
for selected workflows after pilot validation. Any live-path deployment needs
an explicit operating regime covering:

- supervisory ownership of the control
- fail-open versus fail-closed behavior
- control testing and annual review
- change-control procedures
- books-and-records and communications analysis for generated outputs

### Can it run on-premises?

Yes. MERCURY is designed for customer-controlled deployment and does not depend
on a vendor cloud service at runtime.

### Can it run in air-gapped or tightly controlled environments?

Yes, as long as the deployment includes local signing, storage, and artifact
retention. Publication and verification can also be handled through offline
export packages when needed.

---

## Evidence and Verification

### What exactly gets signed?

The canonical receipt body, including business identifiers, decision metadata,
policy references, and evidence-bundle references.

### What is `Proof Package v1`?

`Proof Package v1` is the canonical export contract for independent review. It
contains the receipt, bundle manifest, checkpoint material, inclusion proof,
publication metadata, trust-anchor references, and disclosure metadata needed
to verify or review a workflow event without depending on operator-only
systems.

### What is `Inquiry Package v1`?

`Inquiry Package v1` is the reviewed export layer built on top of a specific
proof package. It adds audience scope, redaction state, and disclosure
approval metadata for internal, client, auditor, or regulator-facing use.

### What does the verifier check?

Receipt signature validity, checkpoint inclusion, publication-chain integrity,
and evidence-bundle integrity.

### Is there more than one verifier surface?

The initial supported surface is a Rust library plus the dedicated
`chio-mercury` CLI app. Additional distribution surfaces such as browser or
WASM packaging follow later.

### Can verification happen offline?

Yes. The supported verifier is designed to work offline with exported proof
material.

### What does the verifier report?

The verifier reports whether `Proof Package v1` is structurally valid, whether
trust-anchor assumptions were satisfied, whether publication continuity gaps
exist, and whether the package is full or redacted for a specific audience.
For inquiry packages, it should also report whether the export remains
verifier-equivalent or disclosure-only.

---

## Proof Boundary

### Does MERCURY prove best execution?

No. It proves decision provenance and evidence integrity, not economic
execution quality.

### Does hashing a market snapshot make it authoritative?

No. A hash proves consistency with the retained artifact. It does not prove the
artifact was exchange-authoritative or economically complete.

### Does MERCURY replace CAT, reporting, or surveillance?

No. It complements those systems by improving the internal and external
evidence chain around workflow decisions.

### Can MERCURY outputs become records or communications?

Yes. Depending on the workflow and audience, receipts, review exports, prompts,
or proof packages may need to be treated as retained records or reviewed
communications. That classification is a firm obligation, not an automatic
property of the cryptographic object.

### How do redacted or client-facing exports work?

MERCURY supports audience-specific export packaging. A package can omit or mask
selected artifacts while preserving the verifiable relationship between the
receipt, publication chain, and disclosed evidence. Those exports still require
firm review and approval before external use.

### What has to be preserved for inquiry or disclosure use?

In addition to the underlying proof material, customers may need to preserve
the exact rendered export, the audience or recipient scope, and the approval or
production log tied to that export.

---

## Security and Operations

### How are keys managed?

The signing key is a root-of-trust component and should be managed with a
documented onboarding, rotation, and publication process. HSM-backed signing is
preferred for production use.

### What happens if the evidence service is unavailable?

In replay or shadow deployments, evidence capture pauses and the primary
workflow can continue through its existing systems. In a mediated live
deployment, fail-open versus fail-closed behavior must be decided explicitly as
part of that production design.

### What should be monitored?

- signing failures
- checkpoint publication gaps
- evidence-bundle retention failures
- API retrieval errors
- trust-distribution and key-rotation events
- legal-hold and export-policy exceptions
- redaction or disclosure-policy failures

### Does SQLite scale?

SQLite is acceptable for the initial product program and early deployments.
Higher-scale or replicated backends can be added later if production usage
demands them.

---

## Integrations

### Which OMS/EMS platforms are supported?

The roadmap supports one production integration path at a time based on buyer
pull. The initial product does not require broad pre-built OMS/EMS coverage.

### How does FIX fit?

FIX is a production integration path, not a prerequisite for the initial
product. See [FIX_INTEGRATION_RESEARCH.md](./FIX_INTEGRATION_RESEARCH.md) for
recommended architecture and phasing.

### Can we integrate a proprietary workflow or OMS?

Yes. The product is designed around canonical evidence capture and
reconciliation metadata, so proprietary systems can be mapped into the MERCURY
model without changing the proof model.

---

## Product State

### What is shipping first?

- core evidence model
- `Proof Package v1`
- `Inquiry Package v1`
- evidence-bundle retention
- verifier library and CLI
- proof-package API
- pilot-ready deployment package

### What comes later?

- supervised-live productionization for the same workflow
- governance, downstream-consumer, and assurance distribution surfaces
- embedded OEM and trust-network services
- companion products such as Chio-Wall

### Do you have SOC 2 or third-party pen test reports?

Not yet. MERCURY is at design-partner stage. Early deployments should assume
customer review of architecture, threat model, and deployment controls rather
than mature vendor-certification packaging.
