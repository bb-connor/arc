# Summary 126-03

Encoded compatibility, versioning, and mismatch handling as fail-closed rules.

## Delivered

- negotiation now rejects mismatched ARC contract versions, wrong official
  stack packages, unknown profiles, unsupported components, unsupported
  isolation modes, unsupported evidence modes, and unsupported privileges
- compatibility expectations are documented in
  `docs/standards/ARC_EXTENSION_SDK_PROFILE.md`
- the example manifest now targets the same official component ids the
  inventory and official stack package advertise

## Result

Unsupported extensions no longer rely on operator interpretation; the
contract records why activation must fail closed.
