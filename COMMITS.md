# COMMITS.md — arc (upstream PR)

`arc/` is the upstream project. The current working-tree changes
**must not be committed directly** to the local arc checkout — they
become a pull request to the arc maintainers.

The change set re-lands Wave 1.6 (`rules.velocity` / `rules.human_in_loop`
first-class) and Wave 5.0.1 (`extensions.chio` reserved namespace) against
the renamed `chio-policy` crate. Design doc: `arc/docs/ARC_UPSTREAM_PROPOSAL.md`
(**must be written before opening the PR** — see `ORG_NAMING.md` blocker).

---

## 1. policy: first-class rules.velocity and rules.human_in_loop

**Body.** Promote `velocity` and `human_in_loop` from the
`extensions.chio.*` passthrough namespace to first-class `Rules` enum
variants, matching the rest of HushSpec's closed-schema rule keys.
`Rules::velocity` compiles to `VelocityGuard + AgentVelocityGuard`;
`Rules::human_in_loop` compiles to `Constraint::RequireApprovalAbove`
on every matching tool grant. Backports the Wave 1.6 work that was lost
in the `arc`→`chio` crate rename and re-adds against `chio-policy`.
Additive on the schema — policies still using `extensions.chio.velocity`
continue to parse; a follow-up deprecation pass can warn on them.

**Files.**

- `arc/crates/chio-policy/src/models.rs` — `VelocityRule`,
  `HumanInLoopRule`, `HumanInLoopTimeoutAction` structs; `Rules` enum gains
  `velocity` and `human_in_loop` variants.
- `arc/crates/chio-policy/src/compiler.rs` — new arms producing
  `VelocityGuard` / `AgentVelocityGuard` / `RequireApprovalAbove`.
- `arc/crates/chio-policy/src/merge.rs` — merge semantics for the two
  new variants (latest-wins per field; `enabled=false` drops).
- `arc/crates/chio-policy/src/validate.rs` — shape validation
  (window_secs > 0, approve_above currency ISO-4217).
- `arc/crates/chio-policy/tests/velocity.rs` — full-shape parse +
  compile regressions.
- `arc/crates/chio-policy/tests/human_in_loop.rs` — same for HIL,
  including `on_timeout` variants.
- `arc/docs/ARC_UPSTREAM_PROPOSAL.md` — design rationale, migration
  table, schema-version policy (must exist — see `ORG_NAMING.md`).

---

## 2. policy: first-class extensions.chio namespace

**Body.** Reserve `extensions.chio.*` as an additive, unknown-fields-
allowed passthrough namespace within a schema that otherwise runs
`deny_unknown_fields`. Lets downstream runtimes (the `@chio/*` plugin
stack) ship knobs that are chio-specific without forking HushSpec or
waiting on arc to promote each one. Re-lands the Wave 5.0.1 extension
block introduced when the `chio-policy` crate was renamed from
`arc-policy`. Complements commit 1: anything that is chio-only
(e.g. `market_hours`, future `signing`) goes under `extensions.chio`;
anything that is genuinely protocol-wide (velocity, HIL) is promoted
to `rules.*` per commit 1.

**Files.**

- `arc/crates/chio-policy/src/models.rs` — `Extensions { chio: Value }`
  field on `HushSpec`, serde-flattened with `#[serde(default)]`.
- `arc/crates/chio-policy/src/validate.rs` — do **not** validate
  unknown fields under `extensions.chio`; linter emits an info-level
  hint when unknown keys appear elsewhere ("did you mean
  `extensions.chio.<key>`?").
- `arc/crates/chio-policy/tests/chio_extension.rs` — round-trip,
  merge, and linter-hint tests.
- `arc/docs/ARC_UPSTREAM_PROPOSAL.md` — the namespace contract and
  the explicit non-guarantees (`extensions.chio` does **not** compile
  to guards inside arc; plugins are responsible for consuming it).

---

## Submission

Once both commits sit on a branch in the arc upstream:

```bash
# From the arc checkout against the upstream remote.
gh pr create \
  --title "policy: first-class rules.velocity, rules.human_in_loop, and extensions.chio" \
  --body "$(cat arc/docs/ARC_UPSTREAM_PROPOSAL.md)"
```

Until the PR merges, downstream plugins keep their README notes stating
`velocity` / `human_in_loop` live under `extensions.chio.*`. Once the
PR merges and a new arc release cuts, bump `@<NPM_SCOPE>/bridge` minor
and remove those README caveats.

---

## What must **not** go in the PR

- Any file under `arc/.planning/` — those are Backbay-side planning
  docs.
- `arc/AGENTS.md`, `arc/CLAUDE.md` — harness-specific.
- The Homebrew tap changes (`arc/Homebrew/`) — ship separately.
- Target / build artifacts (`arc/target/`, release binaries under
  `arc/output/`) — not part of the schema change.
