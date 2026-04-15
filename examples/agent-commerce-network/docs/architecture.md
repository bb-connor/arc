# Architecture

## Objective

Show ARC governing a realistic cross-org service purchase:

- the buyer owns budget and approval policy
- the provider owns delivery and quote semantics
- the reviewer verifies exported evidence without privileged local state

## Components

### 1. Trust control plane

One shared ARC control surface is responsible for:

- capability issuance
- budget state
- approval evidence
- receipt storage and querying
- operator reports
- settlement reconciliation outputs

This is the example's authoritative evidence plane.

### 2. Buyer procurement API

The buyer-side service exposes a procurement workflow:

- request quote
- submit job
- approve job
- inspect job state
- raise dispute

It is the easiest place to demonstrate `arc api protect` because the routes are
business-shaped and the OpenAPI spec can carry explicit ARC metadata.

### 3. Provider review family

The provider offers one family, `security-review`, with bounded scope options:

- code review
- cloud configuration review
- combined release review

The provider side should eventually emit:

- quote artifact
- fulfillment package
- settlement-facing output
- optional dispute response material

### 4. Reviewer

The reviewer is intentionally separate from both operators. It should consume
exported evidence bundles and verify:

- receipt lineage
- checkpoint / proof material
- reconciliation context
- imported trust semantics

## Recommended first live path

For the first live implementation:

1. `arc trust serve`
2. buyer API behind `arc api protect`
3. provider behind `arc mcp serve-http` or a native ARC service
4. reviewer as a shell or Python verifier over exported artifacts

That gives a believable first version without building a full marketplace UI.

## Topology

```text
Buyer Agent / API
   |
   |  governed HTTP routes
   v
arc api protect ----------------------------\
   |                                        \
   | receipt / budget / approval             \
   v                                          v
ARC Trust Control --------------------> Provider Edge / Service Family
   ^                                          |
   |                                          | priced capability execution
   |                                          v
Reviewer <----------- exported evidence ---- Fulfillment + settlement artifacts
```

## Design constraints

- one buyer only
- one provider only
- one reviewer only
- one priced service family only
- scenarios should be operationally rich, not visually complex

## Non-goals

- not a general marketplace product
- not a full billing or payments frontend
- not a synthetic multi-tenant platform
- not a fake universal market-position proof
