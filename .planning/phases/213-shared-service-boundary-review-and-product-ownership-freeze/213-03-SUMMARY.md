# Summary 213-03

Phase `213-03` added the generic ARC export surface and regression coverage:

- [main.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/main.rs) now exposes `arc product-surface export` and `arc product-surface validate`
- [product_surface.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/product_surface.rs) now verifies the exported boundary package contains separate MERCURY and ARC-Wall manifests plus the shared ARC service catalog
- the cross-product hardening lane stays in the generic ARC CLI rather than being folded into either product app
