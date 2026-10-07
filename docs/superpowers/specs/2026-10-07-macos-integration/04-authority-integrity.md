# Native authority, exact review and integrity

Status: proposed normative design. Confidence: high in the authority boundary and attack cases; unknown in integrated runtime enforcement. [Readiness](research/chio-readiness.md) records current native approval checks and absent integrity contracts. This specification depends on CHIO-NORTHSTAR NK-04/NK-05/NK-06/NK-07, not on an app-created signer or local approval database.

An agent can use untrusted information while Chio controls the consequences. The Mac operator makes each consequential action intelligible and sends a decision to the native authority. The kernel verifies whether the deciding principal may endorse that exact action under the current context, policy, resource and authority generations. A trusted-looking window or an authenticated source does not expand an agent's scope.

## Principals, resources and custody

| Principal or asset | Native owner / boundary | Mac responsibility |
| --- | --- | --- |
| Human operator | Native roster identity and control authorization | Authenticate transport peer and invoke the native review path; display the owner-resolved actor |
| Agent, parent and child | Native capability subject, lineage, session and isolation epoch | Carry opaque bindings; OS PID or login UID alone cannot select these values |
| Project and destination | Typed native resource identity, generation, policy and exact effect binding | Resolve chosen object safely; display destination and change; no ambient path authority |
| Approval / integrity endorsement | Existing native approval, recovery or semantic owner plus delivered NK-05 adapter | Transport native endorsement reference and explicit decision under [06](06-operator-protocol.md); no Swift signing key or alternate consume ledger |
| Capability, receipt and child keys | Native key-custody owner | Keychain or hardware backend may hold a native key handle only after a qualified binding; UI/helper/guest never receives secret bytes |
| Budget | Native ancestor-bound reservation/commitment owner | Show remaining/reserved/unknown values with units; local limits can only tighten |
| ES/NE provider | Authenticated platform component with bounded restrictive view | Further deny and report; cannot convert sensor identity into a new agent grant |

Fast user switching, helper restart, forged XPC dictionaries and app code-signing identity are transport/lifecycle concerns. They cannot select another tenant's authority. Operator peer authentication, code identity and native authorization are all required for protected commands. Their concrete transport design is [host architecture](05-host-architecture.md) and [operator protocol](06-operator-protocol.md).

## Integrity model and Mac input disposition

The canonical owner is the proposed native knowledge journal. Each distinct delivery into a context has a stable observation identity. Retries/replay of the same delivery deduplicate; two actual deliveries of identical bytes are distinct. A context is an observation set; joins are set union. Provenance uncertainty is monotone. Commitment, origin classes and bounded capacity derive from that set; a summary or restored UI cannot erase it.

NK-05 owns `InfluenceObservationV1`, `InfluenceStateV1`, `IntegrityRequirementV1`, `Constraint::RequiredIntegrity` and the commitment domain. Its context keys use tenant and isolation epoch with the specified union of principal, lineage and session matches. The desktop must not redefine the lattice or compare semantic-action influence digests to context commitments from a different domain.

| Input / transition | Default native classification | Requirement before use |
| --- | --- | --- |
| Repository files, README, issue text, dependency output, shell output | External, including text in apparently local files | Join before delivery; exact resource provenance; code signature or path hash is not a trust assertion |
| Browser page/search result, app message, mail content, clipboard, drag/drop | External; unknown when complete provenance cannot be established | Typed import and explicit origin; no clipboard metadata promotion |
| Provider/model response | Operator-bound provider class only when qualified; otherwise external/unknown | Native provider identity and deployment binding; generated summary inherits all input influence |
| Initial prompt, agent configuration, templates, memories and restored context | Classified bootstrap plus inherited influence | Join before context ready; trust requires the specified operator-signed bootstrap assertion, not only a pinned digest |
| Ordinary child | Exact conservative parent influence plus classified child bootstrap | Same-transaction parent snapshot and native child generation; spawning does not reset taint |
| Quarantined reader | Fresh isolation epoch and verified no-parent-channel confinement | No inherited channel except declared typed return; host recomputes value and capacity |
| File or checkpoint produced before tracking | Unknown unless complete mediated producing history is proven | Conservative migration seed and readiness rebuild; absence of recorded taint is not trust |
| Finder preview or UI summary | Derived presentation, never authority | Preserve native reference and meaningful exact diff; links/markup cannot trigger approvals |

`Trusted`, `BoundedExternal` and `ProviderOnly` are native integrity requirements, independent of an optional action-selection contract. Bounded return is an explicit allowance for influence, not a zero-injection claim. A Boolean contributes one bit per distinct delivery; accepted variable-length values require exact cardinality across every allowed length. Free text is not a typed confined return. An action-selection contract fixes the allowed action set and ordered input slots. Its host-recomputed selection, membership, cardinality and single consumption remain enforced even with an endorsement.

Task creation carries the shared protocol's `input_ref` for the sealed native task-input artifact, separately from the workspace `resource_ref`. Native capture binds that bootstrap input and joins its influence before agent readiness. The authenticated operator's act of choosing the input does not classify the content as trusted; any trust assertion uses the explicit native bootstrap assertion contract.

## Exact endorsement procedure

1. Native materialization freezes the exact operation, request namespace and canonical action; current policy/deployment, resource/destination and influence commitments; validity interval; deciding authority; and applicable selector/obligations. The Mac receives a bounded review projection plus opaque native references.
2. The native UI renders a meaningful diff, exact destination/recipient/account, released data, units/cost bound, and changed inputs. Long or hidden content receives an explicit expand/review affordance; unsafe markup stays inert. Review presentation cannot silently omit a security-relevant field.
3. A user decision returns the original review, operation and native endorsement references plus explicit approve/deny. These fields and stable retry intent use [06](06-operator-protocol.md). Authentication or Touch ID success alone does not create an endorsement.
4. The native owner checks the decision before retaining it. It verifies principal/roster membership, native binding, expiry, policy/deployment generation and signature. A valid artifact that encodes approval cannot be retained as approved when the submitted decision is deny.
5. At crossing, the native adapter constructs `VerifiedEndorsementFactV1` inside the writer. It rechecks current context commitment and exact native action, current integrity roster, selector constraints and one-use continuation. Only this verified fact can satisfy the endorsement branch.
6. Consumption and crossing commit are atomic in the native owner. Same-operation replay returns its retained result; another operation cannot reuse the endorsement. A new join, policy change, resource generation change, destination change, expiry, revocation or stop can invalidate the prepared action. The UI refreshes the explanation and requests a new review where allowed; it cannot patch the signed artifact.

Recovery integrity approval and P3 semantic endorsement remain separate source formats. The P3 adapter must run original P3 verification and additionally check integrity roster, exact native action, current semantic influence recomputed from the same journal, and one-use semantic capture. Until that adapter is delivered, a P3 signature is not automatically an integrity endorsement. No arbitrary equality between digest domains is accepted.

## Failure and race procedures

| Cut or fault | Native result | Required presentation / recovery |
| --- | --- | --- |
| Untrusted join commits after early guard but before intent | Crossing denies unless fresh exact endorsement covers new state | Explain insufficient integrity; original intent remains unchanged; no effect |
| Intent commits before join | Existing effect may proceed; join applies to later calls | Evidence shows real writer order; no retroactive claim |
| New join after review | Endorsement stale at capture | Review invalidated; no automatic reuse or conversion to trust |
| Destination alias resolves to changed object | Exact effect binding mismatch | Refuse and rematerialize; display resolved object, not the old friendly alias |
| Deny races approve | Native decision/consumption owner serializes current version | One retained native decision; stale request conflicts; UI reads back the actual winner |
| Approval commit succeeds but reply is lost | Result unknown to transport, known or recoverable natively | Stable intent readback; no second click generates new approval authority |
| Parent stops while child is being admitted | Shared native cut decides child before/after ordering | Refused child or included committed child; never an untracked orphan |
| Key unavailable, user locked or signature invalid | Typed unavailable/refused; new authority closed | Read-only operation and stop routes remain per their authority; no temporary software key fallback |
| Budget amount/currency unknown after dispatch | Original commitment retained | Show unknown consumption separately; do not refund based on timeout or worker death |

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-AUT-001 | Native bindings MUST derive tenant, principal, session, lineage, run and isolation generation from authority-owned state, never from unauthenticated UI or sensor claims. | AT-MAC-AUT-001 |
| MAC-AUT-002 | Every input delivery, including bootstrap, restored state and native app content, MUST join classified influence before becoming usable. | AT-MAC-AUT-002 |
| MAC-AUT-003 | Influence MUST be monotone and replay-idempotent; missing history or unsupported migration MUST yield unknown or refuse readiness. | AT-MAC-AUT-003 |
| MAC-AUT-004 | Gated grants MUST enforce integrity and independent action-selection constraints in the crossing writer; unsupported enforcement MUST reject load and issuance. | AT-MAC-AUT-004 |
| MAC-AUT-005 | Exact review MUST bind operation, action, destination, resource generation, policy/deployment, influence, validity and deciding authority to native materialization. | AT-MAC-AUT-005 |
| MAC-AUT-006 | Approval submission MUST verify explicit decision before retention and MUST use the native signer/store/consume owner with no app-owned positive authority. | AT-MAC-AUT-006 |
| MAC-AUT-007 | Endorsement acceptance MUST use a same-writer verified fact with current roster, native action, current influence commitment and atomic single-use consumption. | AT-MAC-AUT-007 |
| MAC-AUT-008 | Every freshness change MUST invalidate a stale review or refuse crossing; native replay MUST return the original outcome without minting replacement authority. | AT-MAC-AUT-008 |
| MAC-AUT-009 | Semantic endorsement adaptation MUST preserve digest domains and add every missing integrity binding; unavailable adaptation MUST refuse the automatic endorsement branch. | AT-MAC-AUT-009 |
| MAC-AUT-010 | Ordinary children MUST inherit influence and attenuated constraints atomically; reset requires the qualified quarantined-child contract. | AT-MAC-AUT-010 |
| MAC-AUT-011 | Quarantine returns MUST use host-recomputed closed types and exact capacity accounting; unknown channels or free text MUST withhold. | AT-MAC-AUT-011 |
| MAC-AUT-012 | Action-selection inputs MUST be context-bound, ordered, distinct and consumed once; endorsement MUST NOT bypass the selector or authorized action set. | AT-MAC-AUT-012 |
| MAC-AUT-013 | Capability, receipt, endorsement and child key material MUST remain in qualified native custody; unavailable custody MUST close new authority rather than export or substitute keys. | AT-MAC-AUT-013 |
| MAC-AUT-014 | Parent/child budgets MUST consume native ancestor accounting with explicit units, ceilings and commitment release authority; unknown outcomes MUST NOT manufacture refunds. | AT-MAC-AUT-014 |
| MAC-AUT-015 | Review presentation MUST render security-relevant native fields faithfully and keep agent-controlled markup, filenames and destinations inert. | AT-MAC-AUT-015 |
| MAC-AUT-016 | Integrity qualification MUST attack repository, browser, clipboard, app, summary, bootstrap, child and restore routes with independent forbidden-effect observers and useful positive controls. | AT-MAC-AUT-016 |

## Acceptance procedures

| Acceptance | Setup/action | Expected independent evidence |
| --- | --- | --- |
| AT-MAC-AUT-001 | Forge tenant/run fields through another user's app/helper; reuse a PID after exec; replay a prior launch binding. | Native binding refusal before authority lookup/dispatch; zero records or paths from victim scope in response and export. |
| AT-MAC-AUT-002 | Inject a sentinel instruction via each input row, including initial prompt and resumed model context. Pause immediately before delivery. | Native journal observation committed before delivery; crossing denies forbidden consequential action; source classification retained. |
| AT-MAC-AUT-003 | Replay one delivery ten times, then deliver identical bytes as a second real input; rebuild heads; import pre-tracking context. | First counts once, second counts twice, rebuild is byte-equivalent; legacy context is unknown; interrupted migration never serves gated grants. |
| AT-MAC-AUT-004 | Load/delegate a grant with required integrity into baseline without enforcement; race join against intent in qualified build. | Baseline refuses feature/issuance; qualified writer enforces after join; cannot drop or weaken action contract during attenuation. |
| AT-MAC-AUT-005 | Change each bound field one at a time after review materialization, including canonical destination behind an alias. | Each substitution refuses before host effect; independent reviewer can recover exact reviewed field set from protected native record. |
| AT-MAC-AUT-006 | Submit deny with a valid approve artifact, approve with deny artifact, forged signer and duplicate request. | Requested/encoded mismatch refuses before storage; one native decision retained; scanning app storage finds no signing secret or approval authority ledger. |
| AT-MAC-AUT-007 | Run two concurrent operations using one endorsement; move roster generation between early validation and capture. | At most one exact continuation consumed; second refuses; generation race denies; capture transaction and native evidence prove winner. |
| AT-MAC-AUT-008 | Drop approval reply; change influence/policy/resource and retry same intent after reconnect. | Readback reports original decision or invalidation; no new endorsement or effect; stale materialization cannot become approved by UI refresh. |
| AT-MAC-AUT-009 | Supply valid route-key P3 endorsement off integrity roster; supply correct semantic digest in context domain; disable adapter. | Each case refuses with classified native reason; valid adapter fixture recomputes both domains from one writer snapshot before consumption. |
| AT-MAC-AUT-010 | Race parent join/stop with child creation; try tainted-parent fresh child with no quarantine evidence. | Child inherits at creation cut or creation refuses; no laundering through child, fresh session or selected provider. |
| AT-MAC-AUT-011 | Return invalid enum, out-of-range integer, free text and covert extra stream; replay a Boolean delivery; test variable-length capacity boundaries. | Host projection rejects invalid data and all undeclared channels; exact integer cardinality matches accepted domain; distinct deliveries add capacity. |
| AT-MAC-AUT-012 | Bind one observation to two slots; select a convenient older value; leave required return unbound; endorse action outside selector output. | All refuse; valid slot sequence consumes exactly once at native order; independent sink sees only the selector-selected approved action. |
| AT-MAC-AUT-013 | Lock/restart custody service; deny key access; request raw signer bytes from app, guest and helper; restore old custody handle. | No key export or fallback; native handle generation rejection; signed historical verification remains possible with retained public keys. |
| AT-MAC-AUT-014 | Exhaust common ancestor concurrently; request currency conversion without bound rate; kill worker after charged request and lose provider response. | Native aggregate ceiling holds; unsupported monetary claim refuses; retained commitment survives reboot; UI distinguishes measured usage from hard enforceable ceilings. |
| AT-MAC-AUT-015 | Render hostile filename, bidirectional destination, hidden long recipient list and HTML containing clickable approve wording; compare displayed diff to native canonical action. | No executable markup or side-effecting link; exact destination and material fields visible; render/action mismatch blocks decision. |
| AT-MAC-AUT-016 | Adaptive red-team tries private-file exfiltration and unapproved publication from each input route; legitimate read/edit/test workflow runs beside it. | Independent filesystem/network/publication observers show zero forbidden effects; useful allowed workflow completes; report names untested paths instead of a universal claim. |

## Design dispositions

Current `ApprovalRequest::parameter_hash` checks are reused where applicable but are insufficient for NK-05. Mac peer authentication supplements native authorization. Keychain is a backend choice, not a new trust issuer. Bounded quarantine is an explicit influence allowance, not a trust reset. Local policy caches may restrict; only the native owner can relax. Scope/resource behavior is [10](10-project-resources.md), host/provider behavior [15](15-host-adapters.md), subtree execution [16](16-delegation.md), and all receipt/recovery claims [11](11-state-recovery.md).
