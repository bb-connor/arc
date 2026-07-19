# ADR-0016: Singular Approval Compatibility Removal

- Status: Accepted
- Decision date: 2026-07-14
- Decision owner: protocol and kernel security lane
- Related plan: `docs/superpowers/plans/2026-07-09-protocol-primitives.md`

## Context

Threshold approval adds `approval_tokens` and a signed threshold proposal to
the governed tool-call protocol. Existing integrations still emit the singular
`approval_token` field for one-of-one governed approval. Removing that field in
the same change would break those integrations, but carrying two equivalent
public approval encodings into the frozen v1 protocol would leave permanent
ambiguity and expand every adapter's validation surface.

The compatibility reader is already narrow. A request supplying both token
forms is rejected. A singular token normalizes to one token only when no
threshold proposal is present. Threshold policy never accepts a singular token,
and governed active response accepts only the complete token vector bound to
its threshold proposal and admission operation.

## Decision

Retain `approval_token` only for the current pre-v1 compatibility window. New
emitters must use `approval_tokens`, including a one-element vector for a
one-of-one policy. No new protocol, SDK, adapter, or product surface may emit
the singular field.

Public v1 freeze is blocked until a removal change does all of the following in
one reviewed migration:

1. Removes `approval_token` from core request and session resource types.
2. Removes it from every protocol adapter, parser, SDK, schema, generated
   binding, fixture, and conformance vector.
3. Removes singular normalization from the kernel while retaining rejection of
   malformed or ambiguous historical input at any explicitly versioned legacy
   boundary.
4. Converts remaining in-tree one-of-one tests and producers to a one-element
   `approval_tokens` vector.
5. Proves cross-language conformance and the complete workspace gates on the
   removal head.

If external migration is incomplete at the proposed public v1 freeze, the
release is delayed. The singular field is not carried into public v1 and there
is no post-freeze extension of this compatibility window.

## Consequences

- Current pre-v1 integrations retain a bounded migration interval.
- Threshold and active-response authorization have one unambiguous production
  representation now.
- Release engineering has a binary gate: either the singular surface is gone,
  or public v1 does not freeze.
- Removing the field is an intentional breaking protocol change and must not be
  hidden inside generated-code drift or adapter-local coercion.

## Verification

Before public v1 freeze, the removal review must show that `approval_token`
appears only in versioned historical documentation, then pass code generation,
cross-language conformance, workspace build, workspace tests, clippy, and
formatting on the same commit.
