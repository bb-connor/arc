# Chio agent preview

This archive contains a Linux CLI, four Python wheels, locked runtime dependencies,
and runnable examples. It contains no generated kernel identity, runtime database,
receipt history, or virtual environment. Rust, Cargo, CMake, and protoc are not
needed to run the bundled CLI.

Newer previews also include `bin/chio-workbench` and a guided repair example.
Their `PREVIEW.json` records the workbench installation acceptance separately.

`PREVIEW.json` identifies the source revision, architecture, build profile, and
recorded installation acceptance. This is an unsigned developer preview. Checksums
detect changed files; they do not authenticate a publisher or qualify a release.
Use a source and archive checksum you trust. Native library compatibility must be
checked on the destination machine; this preview was exercised on its build host.

## Use the CLI

From the extracted directory on the matching Linux architecture:

```bash
sha256sum -c SHA256SUMS
./bin/chio --version
./bin/chio mcp adopt --help
```

Keep this directory at a stable location, then add its `bin` directory to PATH:

```bash
export PATH="$PWD/bin:$PATH"
```

Prepare your existing local MCP configuration with your reviewed policy, then
close the client and activate the selected entries:

```bash
chio mcp adopt --config /path/to/client.json --policy /path/to/policy.yaml --output /path/to/new-chio-state
chio mcp activate --adoption /path/to/new-chio-state --config /path/to/client.json
```

Restart the client. Use `chio mcp status --adoption /path/to/new-chio-state
--config /path/to/client.json --admin-all` to inspect recent signed decisions.
To undo the configuration change, close the client, run `chio mcp restore` with
the same adoption and config arguments, then restart it. Activation and restore
preserve unrelated settings and refuse detected conflicts. `--dry-run` previews
either change. Runtime state and signing keys belong to the new state directory.

## Run the examples

Python 3.11 or newer and `uv` are required for the Python examples:

```bash
uv venv --python python3 .venv
uv pip install --python .venv/bin/python --require-hashes -r python/requirements.txt
uv pip install --python .venv/bin/python --no-deps python/wheels/*.whl
uv pip check --python .venv/bin/python
.venv/bin/python -I examples/mcp-adoption/check.py --chio "$PWD/bin/chio"
.venv/bin/python -I examples/langchain-kernel/run.py --chio "$PWD/bin/chio"
```

These checks need no model API key. They exercise actual tools, signed receipts,
restart persistence, activation, and restore. Keep generated state private; share
the original archive rather than an extracted directory after running examples.

## Try the workbench

If this archive contains `bin/chio-workbench`, use Python 3.11+ and an installed,
authenticated Claude Code client to start a live repair:

```bash
python3 -I examples/workbench/start.py \
  --workbench "$PWD/bin/chio-workbench" \
  --output /tmp/chio-first-repair --model haiku
```

Choose a new output directory. Open the printed local URL and submit the suggested
task. The investigator establishes the failure, the editor fixes the file, and
the reviewer checks the result. Expand actions to inspect their signed receipts.
The configured check command lives outside the editable fixture. Model use is
billed through your client; the workbench passes a $0.25 per-request budget and a
team can make up to 30 model requests. This is not a whole-team spending cap.

For your own trusted project, select its workspace and check command:

```bash
./bin/chio-workbench --provider claude-code --model haiku \
  --workspace /absolute/path/to/project \
  --state-dir /absolute/path/to/private/workbench-state \
  -- python3 -m unittest discover -s tests
```

The check command executes project code with your OS permissions. The workbench
does not provide an OS sandbox. Workspace content goes through the selected
model client. Keep generated state and signing keys private.

The bundled installation check needs no model account, uses explicitly scripted
proposals, and verifies a real repair and restart through the installed binary:

```bash
.venv/bin/python -I examples/workbench/check.py \
  --workbench "$PWD/bin/chio-workbench" --state-dir /tmp/chio-workbench-check
```
