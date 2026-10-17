# Writing a Chio adapter on chio-adapter-base

This guide is for authors of Chio Python adapters such as
`chio-langchain`, `chio-llamaindex`, `chio-crewai`, `chio-prefect`,
`chio-airflow`, `chio-ray`, `chio-temporal`, `chio-langgraph`,
`chio-dagster`, `chio-autogen`, `chio-streaming`, and `chio-iac`.
`chio-adapter-base` supplies the shared security, receipt, filter, and
redaction primitives. The sections below describe each primitive, the
redaction entry points, and the tests an adapter carries.

`CHANGELOG.md` lists the contents of each release. The integration
overview and per-adapter pin matrix are in
`docs/integrations/CHIO-ADAPTER-BASE.md`.

## 1. Depend on the package

Pin the floor in the adapter's `pyproject.toml`:

```toml
dependencies = [
    "chio-adapter-base>=0.2.0,<0.3",
]
```

Inside the monorepo, resolve the package from the workspace path:

```toml
[tool.uv.sources]
chio-adapter-base = { path = "../chio-adapter-base" }
```

Import primitives from their submodule (`chio_adapter_base.security`,
`chio_adapter_base.receipts`, `chio_adapter_base.redact`,
`chio_adapter_base.filters`). The top-level package re-exports the
same names for convenience.

## 2. Primitives

| Module | Names | Use |
| --- | --- | --- |
| `security` | `sanitised_env`, `harden_git_argv`, `reject_shell_argv_escape`, `resolve_within`, `BoundedSubprocess`, `BoundedSubprocessResult`, `ChioPathEscapeError` | Run subprocesses and resolve paths inside a workspace root. |
| `receipts` | `ReceiptBuffer`, `append_jsonl`, `canonical_dumps` | Hold recent receipts, queue them per task, and append them to a JSONL log. |
| `redact` | `redact_args`, `RedactArgs`, `RedactionPolicy`, `bind_and_redact`, `build_alias_map`, `DEFAULT_TOOL_POSITIONAL_NAMES` | Replace body fields with an omission marker before a tool call is evaluated. |
| `filters` | `forbidden_path_filter`, `filter_directory_entries`, `filter_diff_output`, `filter_status_output` | Drop forbidden paths from listings, diffs, and status output. |

`sanitised_env` returns a copy of the environment with secret-bearing
keys removed. `BoundedSubprocess` applies that environment, a timeout
(`DEFAULT_SHELL_TIMEOUT`), and an output cap
(`DEFAULT_SUBPROCESS_MAX_BYTES`). `resolve_within(path, root)` raises
`PermissionError` when the resolved path leaves `root`.

`ReceiptBuffer(buffer_max=..., log_path_factory=...)` is thread-safe.
`push(task_id, record)` and `pop_next(task_id)` queue receipts FIFO per
task. `record(receipt)` stores a receipt, writes it to the JSONL log
when a path factory is set, and counts denials. `recent(n)`,
`denial_count()`, and `pending_total()` read the state back.

## 3. Redaction

Redaction replaces a protected field with a stub that records its size:

```python
{"omitted": True, "byte_count": 6}
```

`byte_count` is the length of the value encoded as UTF-8 (the length
itself for `bytes` and `bytearray`).

`RedactionPolicy` maps a tool name to the tuple of fields to redact.
`RedactionPolicy.chio_default()` protects `content` on
`chio_file_write` and `patch` on `chio_file_edit`. An adapter with
other tools builds its own policy:

```python
from chio_adapter_base.redact import RedactionPolicy

POLICY = RedactionPolicy(body_fields={"my_custom_tool": ("body",)})
```

### Choosing an entry point

`redact_args(tool_name, args, *, policy=None)` takes a dict of named
arguments and returns a redacted copy. It fits wrappers that already
see named arguments, such as LangChain `_run(**kwargs)`, LlamaIndex
`BaseTool.acall(**kwargs)`, and CrewAI `BaseTool._run(**kwargs)`.
`RedactArgs` binds a policy to a callable form of the same function.

`bind_and_redact(fn, args, kwargs, *, tool_name, policy=None,
drop_self=False, positional_table=None)` takes the raw `(*args,
**kwargs)` of a call to `fn`. It maps positional values to parameter
names, redacts the protected ones, and returns
`(redacted_args, redacted_kwargs)` with positional values still
positional and keyword values still keyword. Use it when the wrapper
sees the call as `(*args, **kwargs)`. Pass `drop_self=True` when
`args[0]` is a method receiver.

The choice between redacting before evaluation and after the tool call is
covered in `docs/integrations/CHOOSING_REDACTION_BOUNDARY.md`.

### Signature shapes

`bind_and_redact` handles these shapes:

- Fixed parameters. Names come from the signature.
- Keyword-only parameters. A name that matches a protected field
  redacts in place.
- `*args` extras. Each extra takes the next free slot of the tool's
  positional table and redacts under that slot's name. Extras beyond
  the table stay raw because no field name exists for them.
- `**kwargs` spillover. Protected fields that arrive through the
  spillover are redacted.
- Pure forwarders (`def f(*args, **kwargs)`), `fn=None`, and callables
  that cannot be introspected. These use the positional table keyed by
  `tool_name`. A tool absent from the table has its kwargs redacted and
  its positional values forwarded raw.
- Wrappers that rename parameters, such as `def write(body, path)` for
  a tool table `("path", "content")`. A wrapper name that equals a
  canonical field routes to itself. When the order differs from the
  table, unmatched names route to the unclaimed canonical fields in
  declaration order, so `body` redacts under `content` and `path` is
  preserved. `build_alias_map` exposes this routing and is meant for
  diagnostics and adapter-local tests. Custom routing belongs in
  `positional_table`.
- A variadic parameter named after a protected field, such as
  `def upload(*payload)`. Each value redacts under that name.
- Duplicate positional and keyword values, such as `def fn(path,
  *rest, **kw)` called with a keyword for a protected slot. Both
  positions redact independently. When `inspect.Signature.bind`
  raises `TypeError`, the alias map is kept so renamed keyword
  arguments still redact under their canonical names. Arity errors
  are left for the caller to surface.

### Positional tables

`DEFAULT_TOOL_POSITIONAL_NAMES` holds `("path", "content")` for
`chio_file_write` and `("path", "patch")` for `chio_file_edit`. A
`positional_table` argument replaces this default. Tools absent from
the passed table are not looked up in the default. An adapter that
adds tools and keeps the default entries spreads the default into its
table and passes a policy that protects the new field:

```python
from chio_adapter_base.redact import (
    DEFAULT_TOOL_POSITIONAL_NAMES,
    RedactionPolicy,
    bind_and_redact,
)

MY_TABLE = {
    **DEFAULT_TOOL_POSITIONAL_NAMES,
    "my_custom_tool": ("path", "body"),
}
POLICY = RedactionPolicy(body_fields={"my_custom_tool": ("body",)})

redacted_args, redacted_kwargs = bind_and_redact(
    fn,
    args,
    kwargs,
    tool_name="my_custom_tool",
    policy=POLICY,
    positional_table=MY_TABLE,
)
```

To list every table an adapter passes, run
`grep -rn 'positional_table=' src/` in the adapter.

## 4. Wire-shape envelopes

Some adapters send tool-call parameters in an envelope of their own.
Build the envelope in one function that wraps the output of
`bind_and_redact`. `chio-prefect` does this in `_task_parameters`
(`sdks/python/chio-prefect/src/chio_prefect/decorators.py`). That
function keeps the `{"args": [...], "kwargs": {...}}` envelope and
the `<name>__var_kw_spillover__` key for `**kwargs` collisions, and
delegates binding and redaction to `bind_and_redact`. An adapter
needs no local signature-walking helper beside it.

Assert the envelope against a golden snapshot for one representative
call of each signature shape the adapter wraps.

## 5. Tests

`chio_adapter_base.conformance` is a pytest plugin that carries the
contract every adapter honours:

```python
pytest_plugins = ["chio_adapter_base.conformance"]
```

It provides the `adapter_base_fixture` fixture (a `ConformanceFixture`)
and the helpers `assert_redacts_secrets`, `assert_receipts_fifo`,
`assert_denial_count_increments`, and
`assert_forbidden_path_filter_partitions`. An adapter with a custom
policy builds a `ConformanceFixture` directly.

Add one test per signature shape the adapter wraps. The shared
coverage is in `tests/test_bind_and_redact.py` and
`tests/test_bind_and_redact_properties.py`.

1. Path and body. For `chio_file_write`, the path passes through and
   the body becomes the stub:

   ```python
   redacted_args, redacted_kwargs = bind_and_redact(
       my_write,
       ("/tmp/x", "SECRET"),
       {},
       tool_name="chio_file_write",
   )
   assert redacted_args[0] == "/tmp/x"
   assert redacted_args[1] == {"omitted": True, "byte_count": 6}
   ```

2. `def fn(*, body)` with a policy that protects `body` redacts the
   keyword in place.
3. `def write(body, path)` against the table `("path", "content")`
   redacts `body` under `content` and keeps `path`.
4. A duplicate positional and keyword call that raises `TypeError`
   in `inspect.Signature.bind` still redacts renamed keywords.
5. `def upload(*payload)` with a policy that protects `payload`
   redacts every variadic value.
6. `def fn(path, *rest, **kw)` with `body=` supplied redacts the
   colliding extra positional value.
7. A custom `positional_table` without `chio_file_write` leaves
   `chio_file_write` calls unredacted.
8. For every redacted field, `byte_count` equals the UTF-8 byte
   length of the value.
