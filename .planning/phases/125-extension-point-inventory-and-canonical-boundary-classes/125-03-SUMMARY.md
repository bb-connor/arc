# Summary 125-03

Documented stability tiers and trust-boundary guardrails for extension seams.

## Delivered

- added extension stability, isolation, evidence-mode, and privilege-envelope
  types in `crates/arc-core/src/extension.rs`
- made guardrail validation fail closed when extensions claim truth mutation or
  trust widening
- published the normative boundary language in
  `docs/standards/ARC_EXTENSION_SDK_PROFILE.md`

## Result

The extension inventory now carries the stability and guardrail data needed to
keep later manifest and runtime work bounded.
