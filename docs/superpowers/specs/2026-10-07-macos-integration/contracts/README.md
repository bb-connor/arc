# Proposed Mac and shared desktop machine contracts

These schemas describe proposed message and evidence shapes. They do not implement a service, verify native signatures, issue authority, or qualify a runtime. Every checked-in example is synthetic; all native IDs, hashes and signatures referenced by those examples are invented test data.

| File | Role |
| --- | --- |
| `common.schema.json` | Bounded IDs, native-reference shape, checked unsigned decimals, task projections with rereadable stop state and native stop durability |
| `operator-request.schema.json` | Closed per-method request parameter shapes |
| `operator-response.schema.json` | Closed per-method success/error replies |
| `operator-event.schema.json` | Bounded hint-only events, including replayable native subscription terminals, with stable subscription identity |
| `compatibility.schema.json` | Installed tuple and per-profile prerequisite/qualification reference shape |
| `release-evidence.schema.json` | Candidate-only evidence envelope consumed by a separate semantic qualification verifier |
| `method-catalog.json` | All proposed methods and their positive paired examples |
| `fixture-catalog.json` | Expected schema and response-correlation results for every synthetic example |

The protocol name `chio.desktop.operator.v1` requires explicit negotiation and a versioned Omarchy compatibility map. Native references are opaque locators verified by their registered owner. A digest-shaped field, matching issuer string or successful schema check proves neither possession nor authority. Destination/resource types, generations, current policy, grants, influence, signatures and stop state are checked by native owners.

The custom JSON Schema format `uint64-decimal` is mandatory for every unsigned decimal field. Validators must check canonical spelling and the inclusive range 0 through 18446744073709551615. Merely applying the regex without format validation is insufficient. JSON numbers are safe integers only; money and native generations use these decimal strings. Unknown fields are rejected.

Example files use pretty-printed JSON for review. They represent payload values, not signed or canonical wire bytes. Runtime commitments and hashes use RFC 8785 through the registered codec. The document checker does not certify an RFC 8785 implementation; it checks strict parsing, shapes and response correlation. Native signed objects keep their own registered encoding and verifier.

## Run document validation

Use Python 3.11 or later in an isolated environment, with the pinned validator dependency:

```bash
python3 -m venv /tmp/chio-macos-doc-validation
/tmp/chio-macos-doc-validation/bin/python -m pip install -r docs/superpowers/specs/2026-10-07-macos-integration/contracts/requirements-validation.txt
/tmp/chio-macos-doc-validation/bin/python docs/superpowers/specs/2026-10-07-macos-integration/verify.py --self-test
```

Do not overwrite an existing unrelated environment; choose a fresh temporary path if that one exists. An already installed matching dependency is also sufficient. The program exits nonzero for missing local references, missing or duplicate acceptance definitions, requirement traceability drift, schema/example mismatch, response substitution, catalog drift, or strict decoder regressions. It always reports `runtime_qualification: false`.

After intentionally editing normative tables, update their derived manifest and review its diff:

```bash
python3 docs/superpowers/specs/2026-10-07-macos-integration/verify.py --write-traceability --self-test
git diff -- docs/superpowers/specs/2026-10-07-macos-integration/requirements.json
```

Requirement traceability assigns each requirement to a primary implementation plan. It does not select release applicability. The immutable, pre-run profile manifest in [qualification](../17-qualification.md) must expand the actual applicable cases, controls, evidence classes, prerequisites and thresholds before a runtime qualification run. Candidate data cannot choose its own easier case set afterward.

## Candidate versus verified qualification

`release-evidence.schema.json` permits only `status: candidate`. Its fields bind source and installed components, signing evidence, host/guest/SDK tuple, permissions, policy/native generation, applied profile manifest, observer/harness artifacts, controls, expected and observed results, performance baseline, verifier identity and restoration freshness reference.

The future semantic verifier must read and verify those referenced artifacts using separately configured trust roots. It rejects missing bytes, duplicate or omitted cases, false expected/observed predicates, unqualified observers, stale runs, altered installed tuples, synthetic evidence, and failed or unavailable required cases. A separate verified-qualification artifact may then enter the native evidence path. Only a currently verified artifact matching the installed tuple can support compatibility's `qualified_for_tuple` state.

An inspection-only profile may use `restore_freshness_ref: null` only when its immutable applicability manifest excludes authority restoration and requires a test proving restored authority stays disabled. Any claimed authority restoration requires the independently verified native freshness reference. Likewise an empty permission-observation array is valid only when the selected profile requires no such grants; it cannot omit a permission required by the applied manifest. Missing native policy generation is represented as null in unavailable health, never an invented current generation.

Even a structurally valid compatibility record with a fabricated `qualification_ref` is insufficient. Its signatures, applicability, current installation, permission observations and native freshness are runtime checks outside this validator. Source, component and historical evidence never enable execution through a shape-only branch.
