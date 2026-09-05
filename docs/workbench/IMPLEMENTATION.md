# Local agent workbench

The first implementation runs one coding task through three delegated roles:
investigator, editor, and reviewer. All workspace tools execute through
`ChioKernel::evaluate_tool_call`; the model never receives local credentials
or a direct workspace handle. The application owns orchestration and UI.

## First usable slice

- Standalone `chio-workbench` binary bound to loopback with a per-start access key.
- Real Claude Messages tool-use harness behind a provider-independent Rust trait.
- Optional Claude Code transport using the installed client's authentication,
  with its own tools and customizations disabled. The client emits structured
  proposals and Chio retains workspace execution.
- Investigator and reviewer can inspect files and invoke an operator-configured
  check command. Only the editor can replace exact text in existing files.
- Signed child capabilities narrow a persisted parent capability. Kernel receipts,
  revocations, budgets, and application run history use local SQLite stores.
- A run page shows each role, tool-call allowance, model usage, results, errors,
  and signed receipts. Stop revokes the root and prevents further dispatch.
- Interrupted runs are retained as interrupted. They are never silently replayed.

## Boundaries

The initial budget is a tool-call allowance plus a bounded number of model turns,
not a monetary spending cap. Provider token usage is reported separately.
The configured check command executes project code with the operator's OS
permissions. This local workbench does not provide an OS sandbox for that code.
Use a trusted checkout and check command. The file tools reject symlinks, hidden
paths, traversal, oversized files, and ambiguous text replacements.

Live provider access requires explicit model configuration and either an API key
or an authenticated Claude Code client. The CLI transport inherits the client's
normal authentication and networking behavior; its process is trusted local
software. API transport retains its fixed HTTP egress contract. Tests use a
scripted provider with the same real kernel and filesystem tools; that provider
is not exposed as a successful live-model fallback.

## Validation

The initial Linux implementation passes 11 Rust tests. They exercise real edits
and checks, verify receipt signatures and delegation, deny unauthorized writes,
exhaust allowances, reject malformed model batches before dispatch, stop during
model work and check subprocess execution, recover an interrupted run, and reject
unauthenticated and cross-origin HTTP mutations. Provider tests cover response
parsing and the fixed HTTPS egress contract.

The Playwright browser smoke test submits a real repair through the test provider,
asserts all seven tool outcomes and visible receipts, reloads persisted history,
and checks the mobile layout. Strict Clippy, workspace formatting, JavaScript syntax,
workspace layering, public-surface, file-hygiene, HTTP egress, and Docker context
checks pass. The proof-coverage inventory is regenerated for the new workspace
member; this does not add a formal proof claim for the workbench.

An authenticated Claude Code 2.1.261 live run with the Haiku selection repaired
the arithmetic fixture through all three roles. Ten tool receipts and the role
delegations verified; the investigator established failure, the editor changed
the file, and both the reviewer and a separate operator check established the
passing result. The provider transport also has tests for disabled client tools,
private working directories, failed or oversized responses, timeouts, and
cancellation of descendants. The model response parsers have a dedicated fuzz
target. Direct API task completion remains unverified in this environment.
This is a local developer preview, not a production qualification.
