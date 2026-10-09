# Trim ledger

Audit record for DOCS-1177.3 to DOCS-1177.5 (Review Focus item 4 of the
north-star restructure plan). It lists every sentence containing "must" or
"MUST" that the shared spec files carried at the pre-restructure head
`620c703d8` and that no longer appears verbatim, with where its obligation now
lives. "Restated" means the destination keeps the obligation in shorter
words; "restored" means the trim had dropped it and it was put back,
because a removed sentence with no home is restored, never left unmapped.

Check any row against the source text:

```bash
git show 620c703d8:docs/superpowers/specs/2026-10-07-desktop-integration/<File> | tr '\n' ' ' | tr -s ' ' | grep -F '<first 12 words>'
```

The Omarchy and macOS annexes and plans were reorganized in DOCS-1177.6 and
DOCS-1177.7; their commit bodies record where each retained obligation lives.

| # | Removed sentence (first 12 words) | File | Now covered by |
| --- | --- | --- | --- |
| 1 | Harnesses must route the selected calls and supply required provenance through qualified | HOST-CONTRACT.md | HOST-CONTRACT, Layers and trust (restated) |
| 2 | Native confinement must deny alternate paths before a protection claim is made. | HOST-CONTRACT.md | HOST-CONTRACT, Layers and trust (restated); Q22 |
| 3 | A user-session host can qualify while the service-host profile remains unavailable, but | HOST-CONTRACT.md | HOST-CONTRACT, Deployment profiles (restated); Q29 |
| 4 | The complete platform roadmap must disposition both profiles with exact supported scope | HOST-CONTRACT.md | Q29; FIRST-CLASS-INTEGRATIONS, Delivery (partial release names its set); platform annexes, Packaging and lifecycle |
| 5 | A reusable host must carry stable process/work/resource references, authorized handoffs and retained | HOST-CONTRACT.md | C02, C03; HOST-CONTRACT, Coordination, shared resources and organizations |
| 6 | A peer can refuse a locally valid request, and revocation or unavailable | HOST-CONTRACT.md | HOST-CONTRACT, Coordination, shared resources and organizations (restated); Q28 |
| 7 | A release claiming cross-organization operation must nevertheless implement and qualify the applicable | HOST-CONTRACT.md | HOST-CONTRACT, Coordination, shared resources and organizations (restated); Q28 |
| 8 | It must shrink duplication rather than adding a second runtime. | HOST-CONTRACT.md | HOST-CONTRACT, Coordination, shared resources and organizations (restated) |
| 9 | Every selected effect still must pass its present admission/crossing/receipt/recovery invariants. | HOST-CONTRACT.md | QUALIFICATION, Effects without blanket keystone dependencies |
| 10 | Any dimension required by the selected grant, owner policy or advertised profile | HOST-CONTRACT.md | HOST-CONTRACT, Model-provider resource boundaries (restated); Q15 |
| 11 | Those packets must record concrete owner entrypoints before coding. | RELEASE.md | HOST-CONTRACT, Native port inventory (resolve owners before implementation) |
| 12 | Removing all profiles/cases, downgrading policy/catalog version, omitting a consumer, changing a capability's | RELEASE.md | RELEASE, Inputs and decision (restated); Q18 |
| 13 | The installed/advertised capability inventory must match the selected independently approved policy. | RELEASE.md | RELEASE, Inputs and decision (restored) |
| 14 | Q18's correctly signed malformed fixtures must reach the decoding/semantic gates instead of | RELEASE.md | Q18; RELEASE, Required acceptance (authorized signers) |
| 15 | Installed tests must be able to generate evidence before production promotion. | RELEASE.md | RELEASE, Qualification candidates and activation |
| 16 | Normative MUST/REJECT statements below are acceptance obligations for the named owners, not | OPERATOR.md | OPERATOR, status paragraph; STATUS-GLOSSARY, Case status (specified) |
| 17 | Wire schemas MUST import the landed closed owner types and generated bindings. | OPERATOR.md | OPERATOR, Owner functions (restated) |
| 18 | The latter must be exposed by the owner through an authenticated bounded | OPERATOR.md | OPERATOR, Owner functions (recovery row); Q09, Q21 |
| 19 | A work-list owner/index with authorized enumeration, consistent pagination and original-reference recovery MUST | OPERATOR.md | OPERATOR, Owner functions (missing binding disables the function) |
| 20 | Native `UnknownEffect`, successful execution with refused acceptance, withheld result, unpaid obligation and | OPERATOR.md | Q01; OPERATOR, Owner functions (work row) |
| 21 | The existing resource owner must disable or reject repository-controlled execution, implicit fetching | OPERATOR.md | Q14; OPERATOR, Rules for any operator client (execution profiles) |
| 22 | An evaluator that imports, builds or runs candidate-controlled code MUST use a | OPERATOR.md | Q12, Q19; QUALIFICATION, Effects without blanket keystone dependencies (sealed evaluator) |
| 23 | For a separately hosted projection, Linux MUST reuse `chio-secure-ipc` listener custody, peer | OPERATOR.md | OPERATOR, Rules for any operator client (transport) |
| 24 | Darwin MUST add and qualify its peer-credential/custody path in that same crate; | OPERATOR.md | OPERATOR, Rules for any operator client (transport, with macOS HOST-M2) |
| 25 | The native transport/session and browser delivery owners must supply the supported binding; | OPERATOR.md | Q10; OPERATOR, Owner functions (missing binding disables the function) |
| 26 | Existing and reconnecting sessions must withstand endpoint takeover, and captured material must | OPERATOR.md | Q10 (spoofed server); OPERATOR, Rules for any operator client (browser) |
| 27 | Before any protected read, subscription or mutation, the existing native transport/session owner | OPERATOR.md | Q10; OPERATOR, Rules for any operator client (browser) |
| 28 | Every response, including errors, MUST correlate to the exact request ID, function, | OPERATOR.md | Q04; OPERATOR, Rules for any operator client (correlation) |
| 29 | Pagination MUST bind the authenticated audience, full query/filter/order/limit parameters, owner namespace, snapshot/generation | OPERATOR.md | Q04; OPERATOR, Rules for any operator client (correlation) |
| 30 | Each owner MUST atomically arbitrate concurrent submissions of the same identity: exact | OPERATOR.md | Q02; OPERATOR, Rules for any operator client (full intent) |
| 31 | A known existing context must not imply this rejected request was submitted. | OPERATOR.md | Q04 |
| 32 | Admission exhaustion must preserve bounded lookup/reconciliation capacity. | OPERATOR.md | C04 (restored in the oracle); Q02 |
| 33 | Review MUST bind the exact owner, original operation, proposal/review/decision IDs, decision value, | OPERATOR.md | Q05; OPERATOR, Rules for any operator client (review) |
| 34 | A deny must never retain an approved credential. | OPERATOR.md | Q05; OPERATOR, Rules for any operator client (review) |
| 35 | The installed approval utility must pass deny and mismatch regressions. | OPERATOR.md | Q05; QUALIFICATION, Tracked owner defects |
| 36 | Successful operator health responses MUST contain a nonempty set of explicitly named | OPERATOR.md | Q16; OPERATOR, Rules for any operator client (health) |
| 37 | Reviewed scope MUST resolve typed principal, authority/trust root, project and selection, policy, | OPERATOR.md | OPERATOR, Rules for any operator client (health, scope and budgets) |
| 38 | Approval invalidation must resolve the native owner, original operation and proposal/review identity, | OPERATOR.md | OPERATOR, Rules for any operator client (events) |
| 39 | Exact and changed-intent concurrent submissions must exercise native arbitration, not a controller | OPERATOR.md | Q02; OPERATOR, Rules for any operator client (full intent) |
| 40 | Every helper MUST preserve untrusted operands as data under the actual tool | OPERATOR.md | Q17; OPERATOR, Rules for any operator client (presentation and helpers) |
| 41 | An external agent harness and an application coordinator must be able to | CONSUMERS.md | C01, Q23; CONSUMERS, Consumer boundary (frontend absent) |
| 42 | The application and harness must be independently implemented consumers. | CONSUMERS.md | CONSUMERS, Consumer boundary (independent consumers) |
| 43 | PROGRAM-MAP must supply the target owner pins independently. | CONSUMERS.md | CONSUMERS, Owner handoffs (aliases are the PROGRAM-MAP pins) |
| 44 | Negatives must inspect the actual resource, dispatch counter, private-byte canary, ledger or | CONSUMERS.md | CASES, Rules for every row |
| 45 | Service-host continuity must pass independently of user-session hosting. | CONSUMERS.md | Q29; CONSUMERS, Promotion order |
| 46 | Authority/process/budget/closure owners qualify supported depth and conservation; the Megastart one-hop aggregate profile | CONSUMERS.md | C10 (restated) |
| 47 | An application adapter can map a new owner binding into the existing | CONSUMERS.md | CONSUMERS, Megastart and Herdr compatibility (restated) |
| 48 | A changed adapter must pass existing client conformance and C02/C04/C05/C08 against the | CONSUMERS.md | CONSUMERS, Megastart and Herdr compatibility (restated) |
| 49 | Plugin removal must not delete mission storage. | CONSUMERS.md | H07 |
| 50 | A test record must include a positive control, the actual adversarial stimulus, | QUALIFICATION.md | CASES, Rules for every row; CONSUMERS, Evidence manifest |
| 51 | The existing release owner must reject raw ambiguous, noncanonical or over-limit manifests | QUALIFICATION.md | Q18; RELEASE, Inputs and decision |
| 52 | Signature checking and semantic consumption share the exact accepted bytes and one | QUALIFICATION.md | Q18; RELEASE, Inputs and decision |
| 53 | Each selected effect owner must prove current-authority admission before dispatch, exact request/scope | QUALIFICATION.md | QUALIFICATION, Effects without blanket keystone dependencies (restated) |
| 54 | A known-good artifact must produce a bound valid result; hostile candidate hooks | QUALIFICATION.md | QUALIFICATION, Effects without blanket keystone dependencies (sealed evaluator) |
| 55 | The selected elapsed timebase must include host suspend; a guest timer or | QUALIFICATION.md | Q12; QUALIFICATION, Effects without blanket keystone dependencies (execution lifetime) |
| 56 | The owner must fence expired new authority and prevent untrusted continuation beyond | QUALIFICATION.md | Q31; QUALIFICATION, Effects without blanket keystone dependencies (execution lifetime) |
| 57 | Any profile that ships or exposes this utility must repair exact decision | QUALIFICATION.md | Q05; QUALIFICATION, Tracked owner defects |
| 58 | Q09/Q21 must use non-persisting observation without consuming settlement reserve. | QUALIFICATION.md | Q09, Q21 |
| 59 | Every row expands to an explicit executable case manifest at implementation time. | QUALIFICATION.md | CASES, Rules for every row; QUALIFICATION, Profile coverage |
| 60 | Each platform's source reconciliation must map every applicable HOST-CONTRACT, CAPABILITIES and CONSUMERS | QUALIFICATION.md | QUALIFICATION, Profile coverage (restated) |
| 61 | Independent owner dispatch/effect counters and read/stream canaries must show no protected bytes | QUALIFICATION.md | Q10 |
| 62 | Test leading-dash input, option aliases and Git pathspec magic/ globs with outside-file, | QUALIFICATION.md | Q17 |
| 63 | Descriptor/stdin/typed APIs must prove the same data boundary. | QUALIFICATION.md | Q17 |
| 64 | An observation profile that exposes support export or lifecycle actions must qualify | QUALIFICATION.md | QUALIFICATION, Profile coverage (Observe row) |
| 65 | The platform plans must set numeric resource limits from those experiments before | QUALIFICATION.md | QUALIFICATION, Performance, privacy and operations (restated) |
| 66 | Exceeding a bound must degrade observation or refuse a new task explicitly, | QUALIFICATION.md | QUALIFICATION, Performance, privacy and operations (restated) |
| 67 | A selected GUI applies every graphical/browser case; a headless exclusion must name | QUALIFICATION.md | CASES, Rules for every row; QUALIFICATION, Profile coverage |
| 68 | For a release claiming the full product ambition, Q23 plus the selected | QUALIFICATION.md | QUALIFICATION, Full product claims (restated) |
| 69 | The owner must define and qualify how it establishes current validity after | QUALIFICATION.md | Q31; QUALIFICATION, Effects without blanket keystone dependencies (execution lifetime) |
| 70 | Native protected-byte canaries, approval/credential retention and dispatch/effect counters must show no new | QUALIFICATION.md | Q31 |
| 71 | The exact route must enforce that bound before admission; show-only unknown limits | QUALIFICATION.md | Q15; HOST-CONTRACT, Model-provider resource boundaries |
| 72 | A shared low-level primitive may be reused after source reconciliation, but an | FIRST-CLASS-INTEGRATIONS.md | FIRST-CLASS-INTEGRATIONS, Mini-swe's bounded role |
| 73 | Reconnect must not replay actions or create authority; plugin removal must not | FIRST-CLASS-INTEGRATIONS.md | H07 |
| 74 | Missing H06b or a required Herdr selection must refuse the aggregate completion | FIRST-CLASS-INTEGRATIONS.md | FIRST-CLASS-INTEGRATIONS, Promotion rules (restated) |
| 75 | A proposal must identify: the consumer problem; existing primitive and source; authoritative | CAPABILITIES.md | CAPABILITIES, introduction (restated) |
| 76 | Any grant projection must document semantic loss and reject unrepresentable required restrictions. | CAPABILITIES.md | HOST-CONTRACT, Layers and trust (restored) |
| 77 | Future adapter selection must repin and rerun its exact conformance. | CAPABILITIES.md | HOST-CONTRACT, Native port inventory; STATUS-GLOSSARY, Standing limits (historical evidence) |
| 78 | The integration must preserve all three. | README.md | Q24, C09; CONSUMERS, Owner handoffs (identity and passports) |
