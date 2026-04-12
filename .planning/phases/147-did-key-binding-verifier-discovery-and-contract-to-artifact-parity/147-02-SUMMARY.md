# Summary 147-02

Mapped the contract package back into ARC's published artifact and standards
surface.

## Delivered

- updated `docs/standards/ARC_WEB3_CONTRACT_PACKAGE.json` to point at the real
  Solidity implementations, ABI artifacts, and Rust binding target
- updated `docs/standards/ARC_WEB3_CHAIN_CONFIGURATION.json` with measured
  package-aligned gas assumptions
- updated `docs/standards/ARC_WEB3_PROFILE.md`, `spec/PROTOCOL.md`, and
  `docs/release/RELEASE_CANDIDATE.md` so the public claim references the
  actual runtime contract package and qualification outputs

## Result

ARC's standards and release boundary now describe the shipped runtime package
instead of a research-only contract family.
