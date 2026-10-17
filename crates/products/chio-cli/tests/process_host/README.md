# CLI native integration fixtures

`process_host` exercises ordinary mailbox and worker behavior. Native MCP
administration and recovery run in `process_host_native`, including
`process_administration_preserves_files_and_releases_diagnostic_locks`.
The `process-workers.yml` native recovery step runs that entire target after
the `enforced-native-fixture` action qualifies the host. It builds the real
static `process-report-fixture` and sets `CHIO_PROCESS_REPORT_TOOL`.

`process_host_survives_os_death_at_each_dispatch_cutpoint` runs `os_death.py`.
It SIGKILLs `chio process serve` while the fixture holds an append before its
effect (C1, control `hold-before`) or after it (C2, `hold-after`), always with
an uncheckpointed authority WAL (C5), and for C4 also kills the restarted host
before output, after `ready` and after one inspect. The fixture writes the
granted `publications.held` marker and waits for control `ready` within a fixed
number of control-file reads; the native syscall profile grants no sleep. These cases discharge REST-1 TEST-03 only for the
non-recovery native lifecycle; they are not recovery-runtime qualification.

`process_host_keeps_a_durable_stop_across_os_death` runs `stop_os_death.py`.
C7 SIGKILLs the host right after a durable stop: the restart is
`ready_stopped`, refuses its first call with the stop denial and keeps the
epoch until an offline resume. C8 refuses a call while stopped, kills the host
and resumes: the same request identity then dispatches exactly once. Same
scope as above.

Native tests require Linux x86_64 with the qualified cage enforcement features,
a non-root operator, a static position-independent `chio-cage-init`, and a
private receipt anchor on a different filesystem from the receipt database.
Linux aarch64 can check signed provisioning artifacts and refusal paths, but
cannot provide native execution evidence.

To run the native process target after that fixture setup:

```sh
cargo test --locked -p chio-cli --features real-linux-enforcement --test process_host_native
```

The `mcp_auth_server`, `mcp_serve`, and `mcp_serve_http` integration targets use
the same enforcing host. Their shared helper calls
`chio security provision-reference-runtime --discover-tools`.
It requires the following inputs from the fixture action:

- `CHIO_CAGE_INIT` and `CHIO_RECEIPT_ANCHOR_ROOT`.
- `CHIO_DEMO_PYTHON`, the packaged Python executable.
- `CHIO_CAGE_READ_PATHS_FILE` and `CHIO_CAGE_RUNTIME_FILES_FILE`, the reviewed
  Python import and ELF runtime closure.
- `CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS`, when supplementary groups are needed.

The helper includes the exact per-test script path in the signed runtime files
and read grants. Shared-owner tests also bind their startup marker via signed
argv and an explicit file write grant. It does not grant the directory
containing signing custody. These targets retain explicit prerequisite failures
when run on an unqualified host;
they do not skip or authorize an unconfined launch.

```sh
cargo test --locked -p chio-cli --features real-linux-enforcement \
  --no-fail-fast --test mcp_auth_server --test mcp_serve --test mcp_serve_http \
  --test conformance_cli
```

The live `conformance_cli` case also needs `CHIO_CAGE_EXECUTION_UID`,
`CHIO_CAGE_EXECUTION_GID`, and an explicit
`CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS` value (possibly empty), all exported by
the fixture action. Its wrapped server uses `CHIO_DEMO_PYTHON`; the peer keeps
the SDK-capable interpreter configured by the conformance run options.

Run the Python MCP targets before replacing the Python runtime inventories with
the static report fixture's empty read-path inventory. The native process
workflow intentionally clears Python runtime settings for its static tool.
