# Chio for Omarchy integration design

Status: Proposed, 2026-10-07. Research and specification work only.

The complete design is the [Omarchy integration specification set](2026-10-07-omarchy-integration/README.md).
Its 17 focused specifications own product scope, desktop UX, plugin lifecycle,
controller/protocol, native authority, hosts/providers, Linux confinement,
project/desktop/configuration resources, distribution, delegation, state/evidence,
qualification, decisions and privacy/performance.

Selected architecture: native QML plugin + thin Rust desktop controller + existing
Chio native authority/kernel and protected adapters. Begin with read-only desktop
status, then one confined Pi project task. Gate reviewed publication, desktop
effects, repair and delegation independently.

The [implementation plan set](../plans/2026-10-07-omarchy-integration/README.md)
decomposes delivery into dependency-ordered P0-P7 work. Proposed commands and
future file paths in those plans are not current implementation claims.
The [validation record](2026-10-07-omarchy-integration/reviews/validation.md)
states what this documentation change actually verified.
