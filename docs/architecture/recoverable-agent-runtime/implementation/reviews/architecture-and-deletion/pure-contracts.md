# Pure planning and semantic contracts

Subject: the snapshot named in README.md. All production `src/` files in
`chio-recovery` and `chio-semantic-contracts` were read in full. Their tests,
schemas and callers have not thereby received full coverage.

## Keep the two responsibilities

`chio-recovery` evaluates supplied facts, projects them for an audience and
recomputes signed advisory reports. `chio-semantic-contracts` verifies explicit
contract data and signed evidence. The latter does not own native capture or
execution. These are distinct layers, not duplicate runtime implementations.

The maintained explanation caller is
`chio-control-plane/src/recovery/explanation/service.rs:183`. It calls
`prepare_explanation_report`, signs the report and view separately, and holds no
Kernel, Process or provider handle. Keep this dependency boundary.

`projection.rs:27` filters hidden facts and templates before search. A full
evaluation followed by filtering is not an equivalent simplification: it can
reveal hidden candidates through counts, ranking or budget exhaustion.
`report.rs:208` checks caller-selected trust and recomputes the full payload;
`report.rs:241` only verifies view provenance. Preserve both contracts. A
signature-only verifier cannot replace report recomputation.

`verification.rs:119` and `:131` share the semantic verifier but intentionally
return different types. Input classification defers live disclosure acceptance;
full verification does not. Neither result grants capture authority. Keep this
distinction and its compile-fail test.

## Concrete simplification candidates

1. Remove `WorkflowDirective::RequestApproval` and the resulting unused
   `ApprovalIntentRef` import from `decision.rs:33`. `advise_workflow` never
   constructs this variant, and the pinned repository consumer search found no
   constructor or match for it. This enum is new in this PR and is not a wire
   format. If there is an external consumer, document it before removal. Keep
   the existing awaiting-approval reconciliation behavior.
2. Classify `advise_workflow` as an advisory utility, not the production driver.
   Its observed consumers are its tests, `examples/pure_baseline.rs` and the
   independent `fixtures/recovery-portable-consumer` feature-resolution fixture.
   The ControlPlane executes its own native state machine. Either retain this
   small pure API with that limited claim, or remove the API and its benchmark
   if it is not a supported product surface, replacing the portability fixture's
   exercised API so it still checks the promised dependency boundary. Do not route native execution
   through it merely to manufacture a consumer.
3. Consolidate duplicated DAG mechanics only after fixing the ordering contract.
   `graph.rs:48` uses the smallest currently ready step on every iteration;
   `plans.rs:6` appends a sorted ready layer at a time. Both reject cycles and
   missing/duplicate dependencies, but their valid orders can differ. Semantic
   plans additionally validate future-output inputs. A common private bounded
   graph validator can own identity/edge/cycle checks; wrappers must preserve
   format-specific input checks, limits, work accounting and declared ordering.
   Package dependency validation in `registry.rs:139` only needs acyclicity, so
   a generic graph framework is not justified just to remove its small loop.
4. Move modeled predecessor verifiers out of the maintained verifier after the
   predecessor support decision. `verification.rs:141-196` exports three
   `admission-test-support` entry points that switch off annotation or status
   checks. They are fixture producers, not production compatibility. Today they
   feed Store test support, so deleting them alone breaks the tests. Prefer
   immutable predecessor fixtures with exact provenance, or a separately built
   fixture generator. Keep current incomplete-annotation and missing-status
   refusal tests. Never expose those switches as a runtime option.

## Boundaries requiring further integration evidence

The pure planner validates symbolic registered plans and returns no grant,
signature, native witness or effect handle. This is useful modularity, but its
unit tests do not establish production plan materialization. In particular,
the reviewed support-disclosure runtime materializes its own fixed action.

The semantic contract profile permits input/success/error/no-value channels and
requires the other nine channels disabled (`registry.rs:79-110`). This differs
from the confined-process channel profile. Do not claim that semantic connector
verification alone qualifies logs, streams or arbitrary connector transport.

The retained semantic plan decoder allows sixteen predecessor steps while
fresh validation accepts eight (`plans.rs:11`). Like other PR-local codecs,
that wider retained shape needs an explicit persisted-data obligation before
it becomes permanent compatibility policy.
