# SDD ledger - plan: docs/superpowers/plans/2026-10-02-inbound-authority.md

Base: e84e53ae436ed8d8e2e5b85e62dea185cf7c33d6. Existing isolated checkout verified.
Pre-flight: Tasks 1/2 share HTTP authority. Unmatched denial must precede capability
projection, including the synthetic tools path; Task 2 must preserve DenyAll.
Pre-flight: Tasks 2/3 share MCP ingress. Invocation proofs bind tools; transport
proofs bind HTTP and token identity. Never interchange their action domains.
Pre-flight: Tasks 1/4 share API router; retain auth before protected mutation.
Ruling: use explicit authenticated proxy transport rather than add TLS termination
in AP6; AP7 owns listeners. Cost if wrong: deployment still needs a trusted,
header-sanitizing proxy and protected proxy-to-service link.
Ruling: execute approved scope continuously and reuse publication authorization;
write design/plan as implementation records. No new user decision is needed.
Task 1: started; adding behavioral regressions before source changes.

Task 1: initial 2 behavioral controls failed (unknown requests reached upstream).
First owner run: 220 passed, 19 failed. One additional real defect: broad read
pattern shadows an exact deny route. Corrected with specificity plus restrictive
tie-breaking. Other failures identify legacy fixtures relying on implicit routes
or anonymous permission; migrate their explicit local policy, preserving their
original upstream/revocation/nonce/security assertions. Pin success fixture moved
to the required multithread Tokio host. Initial compile missed one policy evidence
match arm; preserved as a failed build.

Task 1: owner suite passes 239/239 (ap4-owner-final); route shadowing control
went RED to GREEN. Final CLI and source gates are integrated qualification work.
Task 2: started. RED tests exercise policy scope, session dispatch, MCP metadata,
production replay configuration and HTTP required-proof projection.
Ruling: unbound grants retain their explicit bearer semantics. This batch repairs
required-proof consumers and rejects unsupported HTTP proof projection rather
than claiming a caller-supplied agent_id is authentication. Mandatory proof on
all legacy durable reservations requires separately activated replay authority;
forcing volatile custody there would weaken the existing durable-profile gate.
Cost: unbound bearer grants still do not prove individual sender possession.

Tasks 2/3: five AP5 regressions and both AP6 controls reproduced. AP6 unknown,
empty/null cnf accepted in 5 of 6 controls; caller-set TLS identity also accepted.
Task 4: original threshold reader cause regression reproduced (RED).
Ruling: origin-specific DPoP policy is refused by compilation because the current
compiled pipeline cannot enforce origin-specific proof rules. Root policy works;
reference evaluation denies without kernel proof verification. Cost: explicit
origin-specific profiles need a later origin-aware guard.
Implementation uses the existing serde_json raw_value feature and existing tower
as a dev-only test harness. No new runtime crate or lockfile package is introduced.

Independent integrated review: two Important findings accepted, no Critical or
Minor findings. Remote subject bootstrap failed its retained control; encoded
route dot segments reached upstream in the retained router control. Fix pass
binds native/stdio issuance to configured caller keys, retains verified remote
sender keys through issuance and resume, and denies URL normalization changes.
No second independent review is claimed. Reviewer-declined boundaries are in
`docs/reviews/artifacts/2026-10-02-inbound-authority/independent-review.md`.
Ruling: proof-required native/stdio startup without a caller public key rejects;
remote proof-required sessions need a verified Chio sender key. TLS-only/static
bearer policies cannot silently mint unusable proof subjects. Existing bearer
policies retain their established subject generation.

Integrated owner campaign found an additional compatibility regression: legacy
nested callers project the signed request to ToolCallOperation and also pass the
same explicit proof. Rejecting every dual source rejected an honest invocation.
The retained exact-binary diagnostic failed with ambiguous invocation proof
sources. Coalesce only fully equal typed proofs; conflicting or malformed inputs
still fail before session start. New sync/async controls cover conflict, honest
success and replay. Retain the original owner campaign as failed, not green.

Final: Ruling: bound native signed integers retain the existing full u64 domain;
replace the incorrect numeric-rejection assertion with original duplicate-proof
rejection. Cost if wrong: canonical integer interoperability would need revision.
Final: Ruling: malformed notification parameters stay in protocol validation;
the original proof reader only projects object metadata and never emits a new
notification response. Cost if wrong: legacy MCP notification semantics differ.
Factory fixture correction: explicit default block plus wildcard allow emits
proof-required grants; default allow plus a nonempty allowlist intentionally
emits no default grants. Match the mock discovery list to its signed manifest.
Final controls: MCP edge 133/133, remote 125/125, kernel 1506/1506; all 5
affected control-plane nested controls pass after exact proof coalescing.
Keep interrupted control-plane campaign and all earlier failures as failures.
Kernel regression tests moved to a dedicated module to satisfy existing file
hygiene limit; no allowance or cap was raised.

CLI qualification exposed fixture-only failures: the parsing test bypassed the
existing 8 MiB parser-thread helper; the native proof test used a durable-store
helper with explicit durability off; the check test supplied missing read args
and expected lowercase verdicts. Retain the abort/failures and correct fixture
contracts. Production check now signs with the kernel fenced authority clock.
A retained actual binary check with a required-proof HushSpec and valid file-read
arguments returns ALLOW. Full wire schema suite passes 11/11.

Workspace lint found a stale hello-a2a example caller left behind by original-byte
protocol decoding. Migrate production example and its existing controls to bytes
and propagate the native Result. Also remove an erroneous field insertion from a
separate example DTO; that file now has no semantic change. These compiler
failures remain recorded in inbound-workspace-clippy-first.

Workspace continuation also found the matching ACP stale caller. Review of the
three example readers found original duplicate MCP fields collapsed to Value and
unbounded read-line allocation before validation. Four behavioral controls went
RED: oversized whitespace frames on A2A/ACP/MCP and duplicate MCP fields. Bound
allocation first (including whitespace) and use original-byte protocol readers.
The public example loops now propagate typed adapter errors rather than silently
normalizing authority input. Native CLI session 43/43 and preset integration
11/11 pass after fixture repairs; the native parser control also passes.

All 19 example owner controls now pass. Full all-target Clippy additionally found
preexisting generated-binding harness and fixture drift: UUID dependency missing
from generated-type test crates, three old ProtectConfig literals lacking approval
configuration, an unused ACP test import and two ACP proxy test-layout lints.
Use the existing UUID crate as a dev dependency, explicitly opt the SSRF read
fixtures into anonymous reads (retain all redirect/oversize/no-target assertions),
and repair module layout without lint allowances or production semantic changes.

Tasks 1-4 source and local qualification complete. Final strict all-target workspace
Clippy exits 0 (inbound-workspace-clippy-verified); formatting and source gates pass.
Generated primitive/vector tests 1+5 and SSRF integration tests 6 pass. The four
example reader RED controls now pass inside 19 example owner tests. No additional
independent review or full control-plane runtime pass is implied.
Final: Ruling: use exact retained same-session owner runs and targeted corrections
rather than repeat unrelated expensive suites. Cost: bounded runtime coverage,
explicitly not full workspace/hosted qualification. The entire workspace and all
targets do compile under strict Clippy.
Publication: commit/push authorized; preserve preexisting output and other worktrees.
