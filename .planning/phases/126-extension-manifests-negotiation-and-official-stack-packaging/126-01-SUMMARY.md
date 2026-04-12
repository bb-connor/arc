# Summary 126-01

Defined machine-readable extension manifest and negotiation contracts.

## Delivered

- added `ArcExtensionManifest`, compatibility, runtime-envelope, and
  negotiation-report types in `crates/arc-core/src/extension.rs`
- added validation and fail-closed negotiation helpers for extension admission
- published `docs/standards/ARC_EXTENSION_MANIFEST_EXAMPLE.json`

## Result

Custom implementations now have one machine-readable contract for declaring
what they replace and how they expect ARC to negotiate compatibility.
