# Proposed machine contracts

These schemas define the proposed desktop boundary and evidence index. They are
not implemented endpoints, native signed-receipt schemas or release artifacts.
Use JSON Schema Draft 2020-12 with format checking enabled. All references resolve
locally; validation must not fetch arbitrary network schemas.

| File | Purpose |
| --- | --- |
| [common.schema.json](common.schema.json) | IDs, task projection, evidence reference and cursor shapes |
| [operator-request.schema.json](operator-request.schema.json) | Closed method-specific operator requests |
| [operator-response.schema.json](operator-response.schema.json) | Exact method/result association plus typed failures |
| [operator-event.schema.json](operator-event.schema.json) | Separate bounded event union |
| [method-catalog.json](method-catalog.json) | Exhaustive method, result-kind and mutation catalog |
| [compatibility.schema.json](compatibility.schema.json) | Proposed exact tuple and prerequisite status index |
| [release-evidence.schema.json](release-evidence.schema.json) | Evidence index structure; full gate needs native verification and coverage checks |
| [fixture-catalog.json](fixture-catalog.json) | Positive and deliberately invalid synthetic examples |

The [protocol prose](../05-operator-protocol.md) and [data semantics](../14-state-evidence-data.md)
are mandatory. JSON Schema does not enforce UTF-8 bytes, duplicate keys, nesting
depth, JCS commitments, freshness, peer identity, revision races, idempotency,
native evidence authenticity or complete release coverage. Validate those before
dispatch in the actual implementation. There is no free-form extension object.

Errors prior to a trustworthy decoded method/request ID close the connection
without reflecting attacker-controlled identifiers; the shim reports a bounded
local protocol diagnostic. Once a typed envelope is established, use its method
and request ID in the typed error response. An unsupported hello version can be
classified from its bounded header without accepting further calls. Event streams
begin after a successful `events.subscribe` response and carry no command inputs.
Heartbeats reuse the current watermark, never increment the durable journal
sequence; only committed change events advance it. On a heartbeat, compare the
watermark without applying it as a task mutation.

`review.open` returns an opaque native review ID for the trusted review surface,
not a caller-supplied path or URL. It cannot approve or publish. Opening an
existing exact review is idempotent and carries no reusable execution authority;
any native review preparation with effects requires its own retained owner key.
The `chio-desktop-open` helper navigates only fixed views. Enrollment and provider
credential management remain trusted setup outside this operator ABI.

All fixture IDs, zero digests, timestamps and decision handles are synthetic.
Passing schema checks on a `qualified` shape alone does not qualify anything.
The real gate must verify every required component/digest/prerequisite, complete
profile-specific case coverage, evidence artifacts and unresolved native findings.

Run from repository root with Python 3.11+ and `jsonschema==4.21.1`:

```bash
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/verify.py
python3 docs/superpowers/specs/2026-10-07-omarchy-integration/verify.py --self-test
```

Dependency installation, if needed, belongs in a temporary virtual environment:

```bash
python3 -m venv /tmp/chio-omarchy-doc-validation
/tmp/chio-omarchy-doc-validation/bin/pip install jsonschema==4.21.1
/tmp/chio-omarchy-doc-validation/bin/python docs/superpowers/specs/2026-10-07-omarchy-integration/verify.py --self-test
```
