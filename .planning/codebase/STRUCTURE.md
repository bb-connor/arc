# Codebase Structure

**Analysis Date:** 2026-03-19

## Directory Layout

```text
arc/
├── .github/              # CI workflow definitions
├── assets/               # Project images and branding assets
├── crates/               # Main Rust workspace crates
│   ├── arc-cli/         # Operator CLI, HTTP serving, trust-control surfaces
│   ├── arc-conformance/ # Live conformance harness support
│   ├── arc-core/        # Core wire types, crypto, receipts, sessions
│   ├── arc-guards/      # Guard implementations and pipeline logic
│   ├── arc-kernel/      # Runtime mediation, session state, trust stores
│   ├── arc-manifest/    # Manifest signing and verification
│   ├── arc-mcp-adapter/ # MCP wrapping, transport, and edge logic
│   └── arc-policy/      # Policy compilation, merge, validation, evaluation
├── docs/                 # Research, roadmap, ADRs, and epic specs
├── examples/             # Example tool server and example policies
├── formal/               # Formal and differential test work
├── spec/                 # Draft protocol/specification docs
├── tests/                # Workspace-level e2e crate
└── .planning/            # GSD execution scaffold for the current milestone
```

## Directory Purposes

**crates/**
- Purpose: Main product code split by responsibility
- Contains: Individual Cargo crates with `src/`, tests, and crate manifests
- Key files: `crates/arc-cli/src/main.rs`, `crates/arc-kernel/src/lib.rs`, `crates/arc-core/src/lib.rs`
- Subdirectories: One crate per subsystem

**docs/**
- Purpose: Long-form design and planning source of truth
- Contains: `ROADMAP_V1.md`, `EXECUTION_PLAN.md`, `POST_REVIEW_EXECUTION_PLAN.md`, ADRs, epic docs, research notes
- Key files: `docs/EXECUTION_PLAN.md`, `docs/POST_REVIEW_EXECUTION_PLAN.md`, `docs/epics/README.md`
- Subdirectories: `adr/`, `epics/`, `research/`

**examples/**
- Purpose: Runnable examples and example policy files
- Contains: `hello-tool`, `policies/`
- Key files: `examples/hello-tool/Cargo.toml`, `examples/policies/default.yaml`
- Subdirectories: Example crate and policy directory

**formal/**
- Purpose: Formal and differential testing support
- Contains: Rust diff-test crate and Lean work
- Key files: `formal/diff-tests/tests/scope_diff.rs`
- Subdirectories: `diff-tests/`, `lean4/`

**tests/**
- Purpose: Workspace-level end-to-end verification
- Contains: `tests/e2e` Cargo crate
- Key files: `tests/e2e/tests/full_flow.rs`
- Subdirectories: `e2e/`

**.planning/**
- Purpose: GSD roadmap, requirements, state, and codebase map for autonomous execution
- Contains: `PROJECT.md`, `REQUIREMENTS.md`, `ROADMAP.md`, `STATE.md`, `codebase/`
- Key files: `.planning/ROADMAP.md`, `.planning/STATE.md`
- Subdirectories: `codebase/`

## Key File Locations

**Entry Points:**
- `crates/arc-cli/src/main.rs`: Main `arc` CLI entrypoint
- `crates/arc-mcp-adapter/src/edge.rs`: MCP edge/session bridge
- `tests/e2e/tests/full_flow.rs`: Full-flow system verification

**Configuration:**
- `Cargo.toml`: Workspace membership and shared dependency versions
- `.github/workflows/ci.yml`: CI gate for fmt, clippy, build, and tests
- `.planning/config.json`: GSD execution configuration

**Core Logic:**
- `crates/arc-core/src/`: Core types, crypto, sessions, receipts
- `crates/arc-kernel/src/`: Kernel mediation, session state, trust stores
- `crates/arc-cli/src/trust_control.rs`: Trust-control service and clustering logic
- `crates/arc-cli/src/remote_mcp.rs`: Remote HTTP/MCP serving path
- `crates/arc-policy/src/`: Policy compiler and evaluation logic

**Testing:**
- `crates/arc-cli/tests/`: CLI, remote MCP, trust cluster, and trust revocation integration tests
- `crates/arc-conformance/tests/`: Live conformance wave tests
- `tests/e2e/`: End-to-end Cargo test crate
- `formal/diff-tests/`: Differential security/property tests

**Documentation:**
- `README.md`: Project overview and supported surface
- `spec/PROTOCOL.md`: Draft protocol details
- `docs/epics/`: Issue-ready epic specs

## Naming Conventions

**Files:**
- Rust modules use `snake_case.rs`
- Cargo crates use `arc-*` names for workspace components
- Epic docs use `E<number>-<slug>.md`

**Directories:**
- Top-level workspace directories are lowercase
- Crates are grouped under `crates/`
- Test collections use explicit directories (`tests/`, `formal/`, crate-local `tests/`)

**Special Patterns:**
- Integration tests live in `tests/*.rs` inside crates or dedicated workspace crates
- Important planning docs use uppercase filenames (`ROADMAP.md`, `STATE.md`, `PROJECT.md`)

## Where to Add New Code

**New runtime feature:**
- Primary code: `crates/arc-kernel/src/` or the most relevant existing crate
- Tests: Matching crate `tests/` plus any needed conformance/e2e coverage
- Docs: `docs/epics/`, `docs/EXECUTION_PLAN.md`, and `.planning/` if it changes phase execution

**New edge or transport behavior:**
- Implementation: `crates/arc-mcp-adapter/src/` and/or `crates/arc-cli/src/remote_mcp.rs`
- Tests: `crates/arc-cli/tests/mcp_serve*.rs`, `crates/arc-conformance/tests/`
- Docs: `README.md`, `docs/epics/`, `docs/research/` as needed

**New policy or guard behavior:**
- Implementation: `crates/arc-policy/src/`, `crates/arc-guards/src/`, `crates/arc-cli/src/policy.rs`
- Tests: Crate tests plus example-policy coverage
- Docs: `examples/policies/`, `README.md`, `docs/epics/`

## Special Directories

**target/**
- Purpose: Cargo build artifacts
- Source: Auto-generated by Cargo
- Committed: No

**.planning/**
- Purpose: GSD working memory and execution docs
- Source: Maintained by the planning workflow
- Committed: Yes for this repo configuration

---
*Structure analysis: 2026-03-19*
*Update when directory structure changes*
