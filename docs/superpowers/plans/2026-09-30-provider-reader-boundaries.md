# Provider reader boundaries

Base: `82eec927b20ec4dae1fff2a4eb149fef4592c817`, branch
`packet/3-retention-accounting`, existing isolated checkout `/tmp/arc-security-launch`.
Scope: all 28 paths in the preceding CLI batch's `next-readers.json`, plus the
shared helpers and direct consumers required to make those boundaries coherent.

Spec: mechanisms B and C of `2026-09-26-unrepresentable-defects-design.md`;
remaining-security-work item 2. The user approved this batch after its explanation.

## Tasks

1. Shared provider HTTP and egress: bound actual reads before retention, preserve
   typed local transport/parser causes, redact public failures, retain deadlines
   and redirect/credential protections.
2. Provider adapters and tool-call fabric: validate original external JSON and
   nested argument strings before projection; constrain streaming accumulation,
   call identity and terminal state; preserve valid provider behavior and native
   signed numeric domains where required.
3. Recorder/replay: bounded fixture and subprocess/network capture, strict
   original decoding, safe capture errors, and production-linked negative controls.
4. One final independent batch review, focused crate/feature qualification,
   semantic reader dispositions, evidence hashes, roadmap update and local commit.

## Review focus

Check allocation before limits, cumulative versus per-frame bounds, duplicate
argument keys, projection before validation, streaming gate/effect ordering,
call identity and terminal state, raw response/credential exposure, native error
sources, original versus canonical bytes, and fixture/subprocess resource custody.

## Ledger and decisions

- Base and clean tracked state verified; unrelated `output/` remains untouched.
- Ruling: use action-first implementation followed by batched focused tests under
  the user's standing instruction; no repeated per-edit builds or claim of a
  per-fix red/green campaign. One final reviewer, no delegated implementation.
- Ruling: preserve existing effective limits and authentication/egress checks;
  a lexical baseline entry is review debt, not a demonstrated vulnerability.
- Delivery is a local conventional commit. Hosted/native enforcement, M5,
  publication and external activation remain separate acceptance boundaries.

## Completion ledger

- Tasks 1-3: implemented and locally qualified. Bedrock original-response
  interception, terminal-aware two-phase gates and complete Anthropic capture
  reconstruction are included in the final batch.
- Task 4: one independent review resolved; 596 tests pass across the 12 affected
  packages with all eight fixture features. Four scoped repository ratchets and
  changed-file formatting pass. All 28 pinned readers have semantic dispositions;
  the baseline is 166, with zero protocol/CLI baseline files.
- Ruling: the review's native URL/header source gap is required by mechanism C,
  so it was fixed with the three important findings. Anthropic recorder semantic
  reconstruction was promoted into scope because captured arguments were wrong.
- Ruling: existing Cohere/Gemini event models, non-Unix qualification, hostile
  ancestor mutation and deliberate process-group escape remain explicit limits;
  fixture qualification is not live protocol or OS-isolation qualification.
- Ruling: the authorized delivery remains a local conventional commit on the
  existing branch. Preserve the worktree and unrelated output; no integration
  menu, workspace-wide rebuild or external action is needed for this batch.
- Evidence: `docs/reviews/artifacts/2026-09-30-provider-reader-boundaries/README.md`.
- Next queue: 35 trust readers pinned in that artifact directory.
