# Platform Hardening Validation Package

**Date:** 2026-04-03  
**Milestone:** `v2.52`

---

## Purpose

The validation package proves the current MERCURY plus ARC-Wall portfolio
boundary is explicit, machine-readable, paired with one executed hardening
package, and still bounded to the current product set only.

---

## Canonical Command

```bash
cargo run -p arc-cli -- product-surface validate --output target/arc-product-surface-hardening-validation
```

---

## Output Layout

- `product-surface/shared-service-catalog.json`
- `product-surface/mercury-product-surface.json`
- `product-surface/arc-wall-product-surface.json`
- `product-surface/shared-dependency-map.json`
- `product-surface/cross-product-governance.json`
- `product-surface/cross-product-release-matrix.json`
- `product-surface/trust-material-recovery-drill.json`
- `product-surface/operator-alert-routing.json`
- `product-surface/platform-hardening-backlog.json`
- `product-surface/boundary-regression-suite.json`
- `validation-report.json`
- `expansion-decision.json`

---

## Supported Claim

The package supports one bounded claim only:

> ARC now has one executed shared-service, release-control, recovery-routing,
> and qualification package for the current MERCURY and ARC-Wall product set.

It does not claim:

- a merged product shell
- generic multi-product console readiness
- authorization for new buyer motions or companion products
