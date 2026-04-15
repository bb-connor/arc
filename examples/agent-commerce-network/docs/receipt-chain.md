# Receipt Chain

This example is designed so each scenario can be explained as one evidence
chain rather than unrelated logs.

## Expected lineage

### 1. Quote request

- buyer route invocation receipt
- provider quote-generation receipt
- optional pricing / quote metadata artifact

### 2. Approval

- buyer-side approval-required denial or pending state
- approval issuance / review receipt
- approved submission receipt

### 3. Fulfillment

- provider execution receipts
- delivery / fulfillment package artifact
- optional child receipts for sub-steps

### 4. Settlement / reconciliation

- settlement report or reconciliation artifact
- operator-facing report output
- any reversal or dispute artifact

### 5. Federated review

- exported evidence package
- imported evidence lineage
- reviewer-side verification output

## Example canonical IDs

These are conceptual IDs for the docs and scripts:

- `quote_req_acme_001`
- `quote_contoso_001`
- `approval_acme_001`
- `job_acme_001`
- `fulfillment_contoso_001`
- `settlement_acme_contoso_001`
- `federated_review_northwind_001`

## What the first live implementation should preserve

When this scaffold is wired to real services, the scenario artifacts should be
able to answer:

- who authorized the action?
- what budget or approval constraint applied?
- what exactly was delivered?
- what settlement decision followed?
- what can a third-party reviewer verify later?

That is the difference between an ARC example and a normal integration demo.
