# chio-conformance

Loads Chio scenario and result corpora, renders compatibility reports, and
coordinates native and cross-language test runs. The library supplies report
and runner APIs; its integration tests exercise other Chio crates against
protocol fixtures and adversarial inputs.

## Usage

Load a temporary scenario with the public loader. This example needs no peer
SDK, cage helper, network listener, or repository discovery.

```rust
use chio_conformance::load_scenarios_from_dir;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("initialize.json"), r#"{
        "id": "initialize", "title": "Initialize", "area": "lifecycle",
        "category": "mcp-core", "specVersions": ["2025-11-25"],
        "expected": "pass"
    }"#)?;
    let scenarios = load_scenarios_from_dir(directory.path())?;
    assert_eq!(scenarios[0].id, "initialize");
    Ok(())
}
```

`load_results_from_dir` accepts individual records or arrays of records.
`generate_markdown_report` renders a `CompatibilityReport` without running
scenarios. For external Cargo targets, set `CHIO_CHECKOUT_ROOT` to the absolute
checkout path when using repository defaults.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Enables `in-repo-fixtures`. |
| `in-repo-fixtures` | Yes | Declared fixture feature; current runtime discovery also runs with this feature disabled. |
| `fuzz` | No | Exposes `fuzz::peers_lock_decode` for lockfile fuzz targets. |
| `chio-bbs` | No | Enables optional disclosure/workflow dependencies and the BBS selective-disclosure test. |

## Guarantees

`load_scenarios_from_dir` rejects missing or empty scenario directories;
its tree walk rejects symlinks. Both loaders return JSON errors with the file
path and sort their outputs. These loaders deserialize typed fixtures;
they do not authenticate result provenance.

`PeersLock::validate` checks the schema, nonempty peer list, supported languages,
HTTPS URL prefix, lowercase SHA-256 spelling, target, and relative binary path.
`PeersLock::load` and `parse_str` require an explicit subsequent validation call.
`ResultStatus` retains pass, fail, unsupported, skipped, and expected failure.

## Status

Repository test tooling with publication disabled. Live runners can build
binaries, start processes, and write results; the cross-language runner replaces
its configured results directory. Its default upstream is a mock MCP server.
Native artifact fixtures and deployment-shape smoke checks have their own
bounded coverage. Runtime, security, and release acceptance require the relevant
execution evidence and qualification gates.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol evidence boundary](../../../spec/PROTOCOL.md#54-safety-properties-and-evidence-boundary)
- [MCP compatibility](../../../spec/PROTOCOL.md#82-mcp-compatibility)
- [Trace validation](../chio-trace-validate/README.md)
- [Lambda matrix driver](verdict_matrix/drivers/lambda/README.md)

Licensed under [Apache-2.0](../../../LICENSE).
