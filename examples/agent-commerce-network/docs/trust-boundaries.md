# Trust Boundaries

## Boundary 1: Buyer authority

The buyer controls:

- budget ceilings
- approval thresholds
- accepted provider scope
- dispute initiation

ARC must be authoritative here for:

- quote acceptance constraints
- job submission authorization
- approval evidence
- budget-deny behavior

## Boundary 2: Provider fulfillment

The provider controls:

- offer catalog
- indicative pricing
- review execution details
- fulfillment package contents

ARC must be authoritative here for:

- capability-bounded execution
- receipt-bearing provider actions
- explicit difference between governed execution and any compatibility path

## Boundary 3: Shared evidence plane

Neither buyer nor provider should have to trust the other's raw logs.

The authoritative shared layer is:

- ARC receipts
- checkpoints / inclusion proof
- settlement reconciliation artifacts
- exported evidence packages

## Boundary 4: Reviewer import

The reviewer should be able to say:

- this evidence was imported, not locally issued
- upstream lineage is preserved
- trust was not silently upgraded
- the package is enough for bounded review

## Authoritative versus degraded paths

This example should explicitly show both:

### Authoritative

- governed, receipt-bearing execution
- approval and budget state linked to the receipt chain
- partner-visible contract artifacts

### Degraded / compatibility-only

- `allow_without_receipt`
- compatibility passthrough
- non-authoritative for settlement, dispute, or audit

The example should never blur those two.
