# chio-data-guards architecture

## Responsibility and boundary

The crate owns local data-access policy checks and result shaping.
`SqlQueryGuard`, `VectorDbGuard`, and `WarehouseCostGuard` implement the
kernel's pre-invocation `Guard` interface. `QueryResultGuard` supplies borrowed
and owned post-invocation hooks. `StructuredClassifier` exposes byte-oriented
classification with validated identities and findings.

Capability issuance, database execution, receipt signing, and persistence
belong to callers and the kernel. Warehouse cost checks consume supplied
metadata; they do not issue provider dry runs. Returning a cost dimension
requires the caller to record it in its metering workflow.

## Structure

- `config` defines SQL dialects, operation classes, and policy fields.
- `sql_parser` reduces one parsed statement to `SqlAnalysis`.
- `sql_guard` enforces operation, table, projection, and predicate checks.
- `error` supplies structured SQL denial reasons.
- `vector_guard` reads configurable vector request fields and scope constraints.
- `warehouse_cost_guard` extracts estimates and compares byte and decimal costs.
- `result_guard` locates result rows and provides output hooks.
- `structured_classification` validates findings and compiles regex classifiers.

## Data and control flow

Pre-invocation wrappers use `extract_action_checked`. Malformed action fields
deny; unrelated actions pass through. Vector and warehouse guards additionally
recognize configured substrings in database identifiers or tool names.
Callers must choose markers and argument paths appropriate to their tools.

SQL parsing rejects empty and multiple statements before policy evaluation.
`analyze` then checks operations, tables, SELECT projections, normalized WHERE
text, and required WHERE clauses for mutations. `allow_all` skips policy checks
after parsing. Computed projections are rejected when a column policy exists;
unlisted column-policy tables have no per-table column restriction.

Vector collection enforcement applies when its allowlist is nonempty. An empty
collection list alone does not deny a policy configured through other fields.
Namespace enforcement is optional:
`None` disables it and an empty list permits no named namespace. Kernel context
selects the matched grant; standalone checks use the full scope constraints.
Warehouse extraction requires both bytes and estimated USD fields even with
`allow_all`, and limit checks compare supplied values.

Result hooks select matched-grant constraints when available, otherwise scope
constraints. They truncate recognized row arrays, redact denied columns, then
apply configured PII regexes to string values. Constrained unknown result shapes
have their leaf values replaced. Installing only the pre-invocation guard
interface does not apply these output transformations.

## Trust and invariants

Empty SQL policies deny unless explicitly opened. SQL predicate and output
PII pattern constructors enforce count, length, complexity, and compiled-size
bounds. `SqlQueryGuard::try_new` and `QueryResultGuard::new` expose load errors;
the infallible SQL constructor substitutes a deny-all SQL configuration.
Predicate matching uses normalized SQL text, not signed canonical JSON.

Classification results bind SHA-256 and length of the original payload.
Constructors validate classifier identity, categories, confidence, finding
count, byte ranges, and JSON pointer locations. Field findings decode bounded,
duplicate-aware signed JSON and require their locations to exist. Regex
classification is pattern detection; confidence is supplied rule metadata.
These objects do not independently authenticate the classifier or sign results.

## Dependencies

`chio-kernel` supplies guard and hook interfaces; `chio-guards` supplies action
extraction. `chio-core` and `chio-security-types` supply scopes, hashing, bounded
JSON readers, and classification limits. `chio-metering` supplies cost types.
`sqlparser` supplies dialect ASTs, while `regex` and `regex-syntax` support
bounded pattern evaluation. Serde handles configuration and JSON values.

## Verification

Integration tests exercise SQL allowlists, dialects, projection restrictions,
mutation checks, and pattern limits. Vector tests cover matched-grant selection,
namespace checks, malformed arguments, and custom field paths. Warehouse tests
cover missing estimates, cost ceilings, and cost dimensions. Result tests run
post-invocation hooks and unknown-shape redaction. Classification tests cover
shared payload limits; module tests cover validated findings and regex rules.

Run `cargo test -p chio-data-guards` for the package suite. These tests use local
requests and fixtures; they do not establish database-driver compatibility or
the truth of external warehouse estimates.
