# Summary 206-02

Phase `206-02` exposed the trust-network contract family through the Mercury core crate:

- [lib.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-mercury-core/src/lib.rs) now exports the trust-network types and schemas
- the new surface sits alongside the existing downstream, governance, assurance, and embedded-OEM lanes
- no ARC-generic CLI or substrate surface was widened for this Mercury-specific contract family
