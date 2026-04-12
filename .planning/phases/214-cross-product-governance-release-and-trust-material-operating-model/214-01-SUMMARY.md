# Summary 214-01

Phase `214-01` encoded the governance and trust-material model in the generic
ARC contract layer:

- [product_surface.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-control-plane/src/product_surface.rs) now defines cross-product governance, trust-material boundaries, and fail-closed rules
- the product-surface export now emits `cross-product-governance.json` beside the product manifests
- governance validation now fails if the active products diverge from the exported MERCURY and ARC-Wall surfaces
