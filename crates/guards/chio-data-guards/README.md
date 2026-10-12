# chio-data-guards

Data-store guards for Chio's kernel pipeline. This crate checks SQL query
structure, vector request fields, warehouse estimates, and database result
shapes through the guard interfaces supplied by `chio-kernel` and `chio-guards`.

## Usage

Analyze a single query without a database connection:

```rust
use chio_data_guards::{SqlGuardConfig, SqlOperation, SqlQueryGuard};

let guard = SqlQueryGuard::try_new(SqlGuardConfig {
    operation_allowlist: vec![SqlOperation::Select],
    table_allowlist: vec!["orders".into()],
    ..SqlGuardConfig::default()
})?;
assert!(guard.analyze("SELECT id FROM orders").is_ok());
assert!(guard.analyze("DROP TABLE orders").is_err());
# Ok::<(), String>(())
```

The example uses the package's ordinary dependencies and performs no I/O.
Register pre-invocation guards in a `GuardPipeline`; register a
`QueryResultGuard` hook separately for output shaping.

## Guarantees

- `SqlQueryGuard::analyze` rejects malformed, empty, and multiple statements.
  It enforces operation/table allowlists and optional projected-column rules.
- `SqlQueryGuard::try_new` rejects invalid or oversized predicate patterns.
  `new` converts those failures into a guard denying SQL queries.
- `VectorDbGuard` checks configured collections, optional namespaces, denied
  verbs, and applicable capability operation and result-count constraints.
- `WarehouseCostGuard` requires parseable supplied estimates for recognized
  warehouse calls. `record_cost` returns a metering dimension for callers.
- `QueryResultGuard::new` rejects invalid PII patterns. Its hooks truncate
  rows and redact denied columns using the applicable grant constraints.

## Status

The crate implements local policy evaluation and output transformations.
SQL analysis depends on the parser's supported syntax and extracted fields.
Vector and warehouse routing uses configurable name markers and field paths.
Warehouse estimates are caller-provided metadata; this crate does not contact
warehouses to obtain or attest their accuracy. Regex classification detects
configured byte patterns. Result redaction requires callers to install the hook.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol verification rules](../../../spec/PROTOCOL.md#53-verification-rules)
- [Native guard pipeline](../chio-guards/README.md)
- [Default byte redactor](redactors/default/README.md)

## License

See [LICENSE](../../../LICENSE).
