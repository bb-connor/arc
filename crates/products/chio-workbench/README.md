# Chio Workbench

Run a local coding task through an investigator, an editor, and a reviewer.
Each role receives a signed capability derived from the same parent. Workspace
tools execute through Chio's kernel and produce signed receipts. A local browser
page shows the task tree, tool allowances, model usage, results, and authority.

## Run

The initial platform is Linux with Rust and a trusted project check command.
Set `ANTHROPIC_API_KEY` in your environment and select the model you want to use:

```bash
export ANTHROPIC_MODEL='your-claude-model-id'
cargo run -p chio-workbench -- \
  --workspace /absolute/path/to/your/project \
  --state-dir /absolute/path/to/private/workbench-state \
  -- python3 -m unittest discover -s tests
```

Arguments after `--` are the check command and its arguments. They are executed
directly, without a shell. For a Rust project, use `-- cargo test --lib`.
The command receives `PATH` and `PYTHONDONTWRITEBYTECODE`; other parent environment
variables, including model credentials, are not inherited. Checks must finish
within 60 seconds and emit at most 128 KiB on each output stream.

Open the access URL printed in the terminal. The server listens only on
`127.0.0.1:7392`. Use `--port 0` to choose a free port. The access key authorizes
the local operator to read and modify the selected workspace; keep it private.
The browser removes it from the URL and keeps it in session storage. Restarting
the server changes the key.

Give the team a concrete task, such as fixing a failing test. The investigator
and reviewer can list files, read files, and run the configured checks. The
editor can additionally replace exact text in existing files. Every role has a
share of the total tool-call allowance and a maximum of ten model turns.
The reviewer must run passing checks before the run can finish successfully.
That result establishes successful execution and passing checks, not proof that
an arbitrary natural-language task is correct.

## Local operating boundary

- File tools accept relative paths within the workspace, reject symlinks and
  multiply linked files, exclude hidden/build/credential paths, and limit files
  to 128 KiB. Edits require one unambiguous match. Creating files is deferred.
- The check command runs project code with the operator's OS permissions.
  The workbench does not sandbox that command. Use a trusted checkout and command.
- Tool arguments, outputs, model summaries, and signed receipts are stored
  locally. Workspace content supplied to the model is sent to the configured
  Claude API. Provider credentials are never sent to workspace tools.
- The allowance counts tool attempts. It is enforced by the application across
  tools and narrowed per-tool kernel quotas. It is not a monetary budget.
  Reported input/output token usage is separate and can omit a request whose
  response was lost or cancelled.
- Stop revokes the parent capability and cancels pending model requests and
  checks. A call already admitted can finish; edits are not rolled back.
- Runs and receipts persist in SQLite. After restart, unfinished runs and pending
  effects are marked interrupted/unknown and are never automatically replayed.
  Start a new task after inspecting the workspace. Resume is deferred.
- One run and one process per state directory are supported. Each directory
  retains at most 100 runs. Archive it and use a new directory when it fills.

The Rust `Provider` trait isolates model transport from execution. Tests supply
a scripted model while using the real kernel, SQLite stores, file tools, and
project checks. No scripted fallback exists in the application binary.

## Verify

```bash
cargo test -p chio-workbench
cargo clippy -p chio-workbench --all-targets -- -D warnings
cargo fmt -p chio-workbench -- --check
node --check crates/products/chio-workbench/web/app.js
```

For browser verification, run `cargo run -p chio-workbench --example browser_fixture`.
That test harness creates a temporary broken Python project and uses scripted
model proposals through the actual workbench, kernel, stores, and tools.
With Playwright installed, pass its printed URL to `tests/browser-smoke.mjs`:

```bash
PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs \
node crates/products/chio-workbench/tests/browser-smoke.mjs 'PRINTED_URL'
```

The script submits the repair through the browser, checks the seven receipted
calls and final passing checks, reloads persisted history, checks the mobile
layout, and writes screenshots under `/tmp/chio-workbench-*.png`.
