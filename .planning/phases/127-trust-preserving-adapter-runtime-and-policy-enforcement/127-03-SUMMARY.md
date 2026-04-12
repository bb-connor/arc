# Summary 127-03

Documented the trust-preserving evidence and execution rules for extensions.

## Delivered

- published the normative extension-boundary language in
  `docs/standards/ARC_EXTENSION_SDK_PROFILE.md`
- aligned the profile with the runtime-envelope and negotiation types
- made the official stack and custom-extension boundary reviewable without
  reverse-engineering Rust traits

## Result

ARC now has one written boundary for how external evidence and execution may
enter the system without becoming ambient trust.
