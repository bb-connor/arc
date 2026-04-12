# MERCURY Downstream Review Operations

**Date:** 2026-04-02  
**Audience:** workflow owners, review operations, and integration support

---

## Operating Model

The downstream review lane is a bounded file-drop handoff into one
case-management review intake. It is owned operationally by
`mercury-review-ops` and destination ownership remains explicit on the partner
side.

The export path is:

1. generate the supervised-live qualification artifacts
2. derive internal and external assurance packages from the same proof package
3. stage the external review artifacts into the consumer drop
4. write a consumer manifest and delivery acknowledgement

If any required artifact is missing or delivery staging fails, the export must
fail closed and no acknowledgement file should be treated as valid handoff.

---

## Required Checks

- the output directory is empty before export starts
- the consumer manifest matches the selected `case_management_review` profile
- the external inquiry package verifies successfully before staging
- the delivery acknowledgement exists and references the staged files

---

## Failure Recovery

- **Missing proof or inquiry artifact:** stop export, regenerate from the same
  proof path, do not handcraft replacements
- **Consumer-drop write failure:** stop export, clear the partial output, and
  rerun
- **Disclosure mismatch:** regenerate the external assurance package with the
  intended disclosure profile; do not repurpose an internal package
- **Partner-side intake issue:** keep scope limited to the file-drop contract;
  do not widen into bespoke runtime coupling inside this milestone

---

## Support Boundary

Supported in `v2.45`:

- one file-drop delivery contract
- one case-management review intake profile
- one internal assurance package
- one external assurance package

Not supported in `v2.45`:

- multiple downstream consumer profiles
- partner-specific API orchestration
- surveillance-specific routing
- generic archive retention services
