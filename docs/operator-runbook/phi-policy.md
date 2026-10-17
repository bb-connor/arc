# Healthcare Pilot PHI Policy

This page pins the healthcare design-partner PHI and PII redaction policy.
It applies to request arguments, tool responses, signed receipts, PagerDuty
alerts, and audit-log exports.

## Guard Configuration

The pilot relies on the post-invocation `SanitizerHook` (see
`spec/GUARDS.md` section 4.2), which the default runtime profile installs.
Its built-in PII detectors cover SSN, card numbers (Luhn validated), email
and medical record numbers (`MRN` followed by 6 to 12 digits). A medical
record number is removed whole; the other PII detectors keep a two-character
prefix and suffix under the default `partial` strategy.

Required deployment settings:

- Keep the `pii` and `secrets` categories enabled.
- `denylist.patterns` for design-partner identifiers, if supplied by the
  partner SOC team. Denylist matches are always redacted.
- Outbound messages to external APIs go through `ContentReviewGuard` with
  `detect_pii` enabled.

`SanitizerHook` redacts and does not block. A tool whose responses cannot be
safely redacted must stay out of the pilot capability scope. Dates of birth,
phone numbers in responses, and ICD-10 codes have no built-in detector; add
denylist patterns for them after P3 schema negotiation if the pilot needs
them.

## Receipt Fields

Treat these receipt fields as PHI-sensitive:

- `action.parameters`
- `action.parameter_hash`
- `decision.reason`
- guard evidence details
- `metadata`
- raw OCSF `raw_data`
- CEF `msg`
- CEF custom string values

`action.parameter_hash` is not PHI by itself, but it links to
`action.parameters` and must be handled as audit-sensitive evidence.

## PagerDuty Rule

PagerDuty summaries must contain only:

- receipt id
- checkpoint id
- policy hash
- guard id
- tool id
- redaction status

Never include patient name, MRN, SSN, ICD-10 code, address, phone number,
email, date of birth, or free-text clinical content in PagerDuty.

## Log Redaction Enforcement

Operator-facing tracing that can carry payloads, response bodies, prompts,
tool arguments, tool output, user messages, or downstream response text must
use `chio-log-redact`.

- Wrap sensitive fields with `redacted!(value)` before logging.
- Install `RedactionLayer` as the sink-facing tracing layer for deployment
  logs that leave the process boundary.
- CI runs `scripts/check-log-redaction.sh` to block raw `%reason`, `%body`, and
  sensitive-arm log fields in the SRE-owned kernel and SIEM surfaces.

If redaction fails, `redacted!()` emits `[REDACTION-FAILED]` rather than the
original value. Treat that as a fail-closed operator signal and investigate the
redactor configuration before continuing cutover.

## Audit Export Rule

OCSF JSON remains the canonical export. CEF is the SOC text format for this
pilot. Both exports carry `redaction_status`.

Allowed `redaction_status` values:

- `clean`
- `redacted`
- `blocked`
- `unknown`

If redaction status is unknown for a PHI-bearing field, fail closed and open a
P1. If a PHI-bearing field reaches PagerDuty or an external SOC sink, open P0
and evaluate the canonical halt triggers.

## HIPAA Retention

The design-partner deployment retains Chio receipts for 6 years on its own
audit store. Chio does not ship a long-retention storage tier in this release. The export
schema records checkpoint ids so the design partner can bind retained receipts
to its HIPAA evidence chain.

## Cutover Checks

Production cutover requires:

1. Business Associate Agreement chain sign-off.
2. `SanitizerHook` installed with the `pii` category enabled and the partner
   denylist loaded.
3. Synthetic PHI input blocked or redacted as configured.
4. Synthetic deny receipt persisted with `redaction_status`.
5. OCSF export row accepted by the SOC sink.
6. CEF export row accepted by the SOC sink.
7. PagerDuty heartbeat confirmed PHI-free.

Until all checks pass, the pilot remains in zero-PHI shadow mode.
