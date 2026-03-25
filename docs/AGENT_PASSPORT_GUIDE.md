# Agent Passport Guide

**Status:** alpha plus verifier infrastructure, multi-issuer composition, and shared-evidence analytics shipped  
**Date:** 2026-03-24

---

## Overview

PACT now ships Agent Passport verification and presentation on top of:

- local reputation scoring
- reputation-gated issuance
- `did:pact`
- signed receipt and checkpoint evidence
- signed reusable verifier policy artifacts
- replay-safe verifier challenge state
- truthful multi-issuer bundle verification and evaluation
- shared-evidence provenance in operator and comparison reporting

The current CLI surface is:

```text
pact passport create
pact passport policy create
pact passport policy verify
pact passport policy list
pact passport policy get
pact passport policy upsert
pact passport policy delete
pact passport challenge create
pact passport challenge respond
pact passport challenge verify
pact passport evaluate
pact passport verify
pact passport present
```

The passport is a bundle of independently verifiable reputation credentials.
Each embedded credential is signed by the issuing operator key and identifies
both issuer and subject as `did:pact` DIDs.

`pact passport create` still produces a single-issuer passport from one local
operator signing key and one local receipt corpus. Verification, evaluation,
and presentation now also support same-subject passport bundles composed from
multiple independently signed issuer credentials.

## Create

```text
pact \
  --receipt-db receipts.sqlite3 \
  --budget-db budgets.sqlite3 \
  passport create \
  --subject-public-key <agent-ed25519-hex> \
  --output passport.json \
  --signing-seed-file authority-seed.txt \
  --validity-days 30 \
  --receipt-log-url https://trust.example.com/v1/receipts \
  --require-checkpoints
```

What this does:

- assembles the local reputation corpus for the selected subject
- computes a deterministic local scorecard
- builds one signed `PactReputationAttestation`
- wraps it in an `AgentPassport`

`--require-checkpoints` fails closed if any selected receipt lacks checkpoint
coverage.

## Verify

```text
pact passport verify --input passport.json
```

Verification checks:

- every embedded credential signature
- `did:pact` issuer and subject consistency
- credential validity windows
- single-subject passport consistency
- bundle `validUntil` does not exceed the minimum credential expiry
- reports `issuerCount` and `issuers`, and only reports a single top-level
  `issuer` when the bundle actually has one issuer

## Multi-Issuer Composition

PACT now accepts passport bundles that contain credentials from multiple
issuers when all credentials:

- independently verify
- name the same passport subject
- stay within their own issuance and expiration windows

The verifier contract remains conservative:

- no cross-issuer aggregate score is invented
- no synthetic bundle-level issuer is invented
- policy evaluation still runs per credential
- the passport is accepted when at least one credential satisfies the verifier
  policy
- evaluation output reports `matchedIssuers` plus `credentialResults[].issuer`

This means multi-issuer support is a verification/evaluation/presentation
feature, not a claim that PACT now synthesizes a new trust signal across
issuers.

## Evaluate

```text
pact passport evaluate \
  --input passport.json \
  --policy examples/policies/passport-verifier.yaml
```

This is the first relying-party verifier lane on top of the shipped passport
format. The verifier:

- performs the same structural passport verification as `pact passport verify`
- evaluates each embedded credential independently against a relying-party policy
- accepts the passport if at least one credential satisfies the policy
- does not invent cross-issuer aggregation semantics beyond those independent
  credential results

The policy file can require:

- issuer allowlisting
- minimum composite / reliability / least-privilege / delegation-hygiene scores
- maximum boundary pressure
- minimum receipt count, lineage records, and history span
- checkpoint coverage and receipt-log URLs
- maximum attestation age

See [examples/policies/passport-verifier.yaml](/Users/connor/Medica/backbay/standalone/pact/examples/policies/passport-verifier.yaml).

## Reusable Verifier Policy Artifacts

```text
pact passport policy create \
  --output verifier-policy.json \
  --policy-id rp-default \
  --verifier https://rp.example.com \
  --signing-seed-file verifier-seed.txt \
  --policy examples/policies/passport-verifier.yaml \
  --expires-at 1900000000 \
  --verifier-policies-file verifier-policies.json

pact passport policy verify --input verifier-policy.json

pact passport policy list \
  --verifier-policies-file verifier-policies.json
```

Verifier policy artifacts are now signed documents that bind:

- `policyId`
- verifier identity
- signer public key
- creation and expiry timestamps
- the underlying `PassportVerifierPolicy`

The same artifact format works for local file-backed verifier registries and
remote trust-control admin APIs.

## Compare Against Live Local State

```text
pact reputation compare \
  --subject-public-key <agent-ed25519-hex> \
  --passport passport.json
```

This compares the portable passport artifact against the live local reputation
corpus and reports explicit per-credential drift as `local_minus_portable`.
The same comparison contract is also available over trust-control through
`POST /v1/reputation/compare/{subject_key}` and is now surfaced in the
dashboard portable comparison panel.

The comparison payload now also includes `sharedEvidence`, which reports:

- referenced remote share count
- referenced remote capability rows
- upstream share issuer/partner metadata
- local anchor capability ids and local receipt counts for downstream activity

## Federated Issuance

```text
pact \
  --control-url https://trust.example.com \
  --control-token <service-token> \
  evidence import \
  --input upstream-evidence-package

pact trust federated-delegation-policy-create \
  --output delegation-policy.json \
  --signing-seed-file authority-seed.txt \
  --issuer local-org \
  --partner remote-org \
  --verifier https://trust.example.com \
  --capability-policy examples/policies/federated-parent.yaml \
  --parent-capability-id cap-upstream \
  --expires-at 1900000000

pact \
  --control-url https://trust.example.com \
  --control-token <service-token> \
  trust federated-issue \
  --presentation-response response.json \
  --challenge challenge.json \
  --capability-policy examples/policies/federated-child.yaml \
  --enterprise-identity enterprise-identity.json \
  --delegation-policy delegation-policy.json \
  --upstream-capability-id cap-upstream
```

This lane now supports verified bilateral evidence consumption plus a real
multi-hop continuation step. `pact evidence import` verifies the upstream
package before it is indexed locally, the delegation policy binds to an exact
upstream capability ID, and `pact trust federated-issue --upstream-capability-id ...`
persists a local delegation anchor that bridges to the imported parent without
pretending the foreign capability was natively issued by the local authority.

When `--enterprise-identity` is supplied, federated issue can also enter the
enterprise-provider lane. The lane is only active when
`enterpriseIdentity.providerRecordId` resolves to a validated
provider-admin record on the trust-control service. In that case:

- the capability policy is resolved as HushSpec and its origin profiles are
  matched against provider, tenant, organization, groups, and roles
- missing provider validation or missing enterprise origin matches deny instead
  of falling back to a weaker path
- successful responses include `enterpriseAudit` with provider provenance,
  canonical principal, subject key, tenant, organization, groups, roles,
  `attributeSources`, `trustMaterialRef`, and the matched origin profile

If enterprise identity is present only for observability and no validated
provider-admin record is selected, federated issue stays on the legacy
bearer-only path and the response explains that the enterprise-provider lane
was not activated.

## Present

```text
pact passport present \
  --input passport.json \
  --output presented.json \
  --issuer did:pact:... \
  --max-credentials 1
```

This produces a filtered passport presentation for selective disclosure. The
presentation reuses the original signed credentials; it does not re-sign them.
For multi-issuer bundles, issuer filtering and `--max-credentials` apply across
the composed credential set.

## Challenge-Bound Presentation

```text
pact passport challenge create \
  --output challenge.json \
  --verifier https://rp.example.com \
  --ttl-secs 300 \
  --policy-id rp-default \
  --verifier-policies-file verifier-policies.json \
  --verifier-challenge-db verifier-challenges.sqlite3

pact passport challenge respond \
  --input passport.json \
  --challenge challenge.json \
  --holder-seed-file subject-seed.txt \
  --output response.json

pact passport challenge verify \
  --input response.json \
  --challenge challenge.json \
  --verifier-policies-file verifier-policies.json \
  --verifier-challenge-db verifier-challenges.sqlite3
```

This verifier loop is now reusable and replay-safe. The challenge document
carries:

- verifier identity
- `challengeId`
- nonce
- issuance and expiration timestamps
- optional selective-disclosure hints (`issuerAllowlist`, `maxCredentials`)
- either an embedded verifier policy or a `policyRef`

The holder response:

- reuses the original signed credentials
- filters the passport according to the challenge disclosure hints
- signs the embedded challenge plus presented passport with the passport
  subject key
- lets the verifier check freshness, proof-of-possession, and policy
  acceptance without custom glue code

When a challenge references `policyRef.policyId`, verification resolves the
stored signed policy, checks that its bound verifier matches the challenge
verifier, and consumes the replay-safe challenge record. Verification output
now exposes:

- `challengeId`
- `policyEvaluated`
- `policyId`
- `policySource`
- `replayState`

## Remote Verifier Surface

```text
pact trust serve \
  --listen 127.0.0.1:8090 \
  --advertise-url https://trust.example.com \
  --service-token verifier-token \
  --verifier-policies-file verifier-policies.json \
  --verifier-challenge-db verifier-challenges.sqlite3

pact \
  --control-url https://trust.example.com \
  --control-token verifier-token \
  passport policy create \
  --output verifier-policy.json \
  --policy-id rp-default \
  --verifier https://trust.example.com \
  --signing-seed-file verifier-seed.txt \
  --policy examples/policies/passport-verifier.yaml \
  --expires-at 1900000000

pact \
  --control-url https://trust.example.com \
  --control-token verifier-token \
  passport challenge create \
  --output challenge.json \
  --verifier https://trust.example.com \
  --policy-id rp-default

pact \
  --control-url https://trust.example.com \
  --control-token verifier-token \
  passport challenge verify \
  --input response.json \
  --challenge challenge.json
```

Remote verifier flows use the same policy-reference and replay-safe challenge
contract as local CLI flows. Trust-control exposes verifier policy CRUD plus
challenge create/verify endpoints behind the same service token boundary.

## Alpha Boundary

Shipped now:

- single-issuer reputation credentials
- single-issuer passport bundle creation
- multi-issuer passport bundle verification, evaluation, and filtered presentation
- offline verification without custom glue code
- relying-party policy evaluation over passports without custom glue code
- filtered passport presentation
- challenge-bound presentation with holder proof-of-possession
- signed reusable verifier policy artifacts with local and remote admin surfaces
- replay-safe verifier challenge persistence for local verification,
  trust-control challenge verification, and federated issue

Not shipped yet:

- `did:pact:update` rotation flows
- zero-knowledge selective disclosure
- wallet transport semantics beyond file-based challenge/response
- cluster-wide verifier-state replication beyond a configured verifier store
- automatic local multi-issuer bundle authoring beyond external composition
