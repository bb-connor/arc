# chio-credentials Architecture

`chio-credentials` owns Chio's native reputation credential and Agent Passport artifacts. It issues canonically signed Ed25519 credentials, bundles them into unsigned passports, and projects them into OID4VCI, OID4VP, SD-JWT, JWT VC, lifecycle, and trust-tier surfaces.

The native passport structs are the source of truth. External projection modules may derive standards-native forms, but they must not widen the native schema or reinterpret unverified JSON as trusted passport state.

The main pain point is the broad include-based module layout: artifact types, passport construction, presentation challenge logic, policy evaluation, and projection code share crate-private helpers through one compilation unit. This pass keeps that boundary stable and hardens the native wire schema instead of reshuffling modules.

Planned improvement: reject unknown fields on native passport, presentation, and verifier-policy documents so malformed JSON fails at parse time before verification or canonical-signature logic sees it.
