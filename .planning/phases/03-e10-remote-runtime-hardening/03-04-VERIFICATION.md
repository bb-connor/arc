# 03-04 Verification

## Gate

Plan `03-04`: lifecycle diagnostics, cleanup behavior, and hosted-runtime operational docs (`REM-03`, final E10 closeout).

## Commands

```bash
cargo fmt --all -- --check
cargo test -p arc-cli --test mcp_serve_http
cargo test --workspace
```

## Result

All three commands passed.

## Evidence

- `mcp_serve_http_idle_expiry_reaps_sessions_and_blocks_reuse`
- `mcp_serve_http_admin_drain_shutdown_and_delete_have_distinct_terminal_states`
- `/admin/sessions` diagnostics landed alongside per-session trust inspection for terminal sessions
- Full workspace verification stayed green after the hosted lifecycle changes

## Residual risk

- Terminal session tombstones are retained in memory for a bounded window and are not durable across process restart.
