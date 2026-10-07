# Host, framework, and model adapters

Status: proposed normative design. Confidence: high in the inspected source distinctions, moderate in the integration design, unknown for Mac runtime qualification. No row below is a qualified installed Mac host.

The Mac operator makes bounded agent work useful across different reasoning hosts. The first candidate is Pi's restricted SDK/print entry mode inside a qualified project worker, with native Chio tool execution, a host-owned model gateway, private task input and verified output delivery. A framework adapter translates calls; the selected execution profile supplies isolation, and the kernel supplies authority. All three must be present for a protection claim.

Dependencies: [kernel contracts](03-kernel-contracts.md), [authority and integrity](04-authority-integrity.md), [host architecture](05-host-architecture.md), [operator protocol](06-operator-protocol.md), [VM execution](07-vm-execution.md), [resources](10-project-resources.md), [recovery](11-state-recovery.md), [privacy](13-privacy-performance.md), and [qualification](17-qualification.md). Delegated work additionally requires [delegation](16-delegation.md). Publication remains the separate `publication-v1` feature.

## Inspected implementation matrix

`MAC-BASE` and `PI-PUBLIC` are pinned in [source research](research/clawdstrike.md). Source presence, component behavior, installed behavior and qualified behavior are separate evidence classes. Dependency ranges below describe source manifests, not supported Mac version ranges. A row marked unavailable can still supply useful observation or protocol conversion under its actual scope.

| Surface | Existing source and exact inspected selection | Implemented boundary | Missing Mac contract and availability |
| --- | --- | --- | --- |
| Pi restricted host | PI-PUBLIC `package.json`, `src/governance.ts`, `src/protected-cli.ts`: adapter `0.2.0`, Pi `1.0.2`, optional Durable `1.0.2`; Node declares `>=22.19.0` | Restricted host composition; native tool execution references; fixed relay and native governance ports; required CLI governance refuses before credentials | Exact Node build, macOS build, guest image/architecture, installed native owner and private-input path are unqualified. Candidate only; no Mac protected task enabled. |
| Pi delegation and knowledge | PI-PUBLIC `src/delegation.ts`, `src/governance.ts`, `docs/NATIVE-PREREQUISITES.md` | Typed native composition ports and local owner association | Native child admission, release custody and durable cross-host service must be delivered and qualified. A complete callback-shaped facade is insufficient. |
| MCP adapter | MAC-BASE `crates/protocol/chio-mcp-adapter/src/server.rs`, `src/transport.rs`; workspace package version `0.1.0` | Presents selected MCP server calls to kernel routing and provides bounded stdio conversion | All other host tools, filesystem access, direct MCP clients, sampling/elicitation, credentials and egress need the selected profile and explicit resource contracts. Full host mediation unavailable. |
| OpenAI protocol adapter | MAC-BASE `crates/protocol/chio-openai-adapter/src/lib.rs`, `src/adapter.rs`, `src/transport.rs`; workspace `0.1.0`, provider feature uses its own pinned API contract | Tool-call translation/kernel routing and optional provider transport/verdict gating | No implication that a caller's entire prompt/context or alternate HTTP clients are governed. Model gateway must bind actual installed route, account, API contract and final bytes. |
| LangChain | MAC-BASE `sdks/python/chio-langchain/src/chio_langchain/tool.py`, manifest adapter `0.1.1`, `langchain-core>=0.2,<1` | Explicit advisory sidecar evaluation; returns a non-authorizing outcome | No effect dispatch or confinement supplied by this wrapper. Observation scope only until a new native dispatch adapter and full host tuple qualify. |
| CrewAI | MAC-BASE `sdks/python/chio-crewai/src/chio_crewai/tool.py`, adapter `0.1.1`, `crewai>=0.80,<1` | Wrapped local callable path with receipt checks; non-authorizing receipts rejected | Callback gating cannot control raw Python, shell or SDK access. No exact host lock or Mac mediation qualification in this package. |
| AutoGen | MAC-BASE `sdks/python/chio-autogen/src/chio_autogen/functions.py`, adapter `0.1.1`, `pyautogen>=0.2,<0.3` | Classic function-map wrapping and local execution path with receipt checks | The source explicitly targets the classic API. It does not establish compatibility with newer agent-chat APIs or full host confinement. |
| LlamaIndex | MAC-BASE `sdks/python/chio-llamaindex/src/chio_llamaindex/function_tool.py`, adapter `0.1.1`, `llama-index-core>=0.11,<1` | Wrapped function/query surfaces and receipt checks | Retrieval, ingestion, model SDK calls, arbitrary Python and local files require separately governed resources. Exact runtime tuple unavailable. |
| A2A and other protocol edges | MAC-BASE `crates/protocol/chio-a2a-adapter/` and `chio-a2a-edge/` | Selected protocol conversion and edge handling | A protocol endpoint is neither a worker lease nor cross-host custody. Requires the delegation contract and exact target-host qualification. |
| General CLI, IDE agent, Claude Code, Codex CLI, browser agent, or ordinary Pi TUI | No qualified Mac host entry in this package | External host may be observed, or call an explicitly brokered resource | A shell wrapper, CLI exit code, MCP callback, UI permission or installed plugin supplies no complete mediation claim. Protected execution unavailable until a complete surface inventory and own tuple pass. |

This matrix does not deny the capabilities of those products. It states the inspected Chio integration boundary. Adding a host requires evidence for that host's actual callable and disclosure surfaces, including features added by an update.

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-HST-001 | Each selected host MUST match an exact installed qualification tuple before protected launch; package presence or a dependency range MUST NOT enable a profile. | AT-MAC-HST-001 |
| MAC-HST-002 | Every adapter MUST inventory effects, model traffic, tool transports, discovery, plugins, subprocesses, attachments and persistence; uncontrolled surfaces MUST be disabled or place the host outside the claimed profile. | AT-MAC-HST-002 |
| MAC-HST-003 | Preparation MUST validate current native authority, profile, policy, owner and installation bindings before credential access or provider egress; required feature mismatch MUST refuse without fallback. | AT-MAC-HST-003 |
| MAC-HST-004 | Tool admission and effects MUST remain with their native owners; adapters MUST NOT interpret advisory receipts, callbacks, OS permission or local allow bits as execution authority. | AT-MAC-HST-004 |
| MAC-HST-005 | Tool declarations and canonical argument binding MUST be immutable for the run, and lifecycle replacement or reload MUST preserve the exact registry before further dispatch. | AT-MAC-HST-005 |
| MAC-HST-006 | Provider, capability-signing and native owner secrets MUST stay in authenticated trusted custody; workers MUST receive only scoped routes or opaque handles with no reusable credential export. | AT-MAC-HST-006 |
| MAC-HST-007 | Private prompts and task context MUST use bounded authenticated private transfer, with no sensitive bytes in argv, inherited environment, diagnostics or ordinary events. | AT-MAC-HST-007 |
| MAC-HST-008 | Model disclosure mode MUST be frozen and visible; `required` MUST use a qualified native release owner that commits and submits exact bytes, and MUST refuse if that owner is absent. | AT-MAC-HST-008 |
| MAC-HST-009 | Model requests MUST bind route, provider, account, model/API contract, credential generation, tool inventory, history, content commitments and resource limits; redirects and undeclared secondary channels MUST refuse. | AT-MAC-HST-009 |
| MAC-HST-010 | Resource and provider limits MUST distinguish hard enforcement, observation and unavailable dimensions; reservations and absolute deadlines MUST survive resume and aggregate with delegated children. | AT-MAC-HST-010 |
| MAC-HST-011 | Every returned artifact, tool result and model output MUST follow its admitted release disposition; receipt verification, safe rendering and native delivery custody MUST precede release or ACK. | AT-MAC-HST-011 |
| MAC-HST-012 | An unresolved original or pending delivery ACK MUST fence dependent effects; retry and resume MUST reconcile the original native identity rather than dispatch a new effect. | AT-MAC-HST-012 |
| MAC-HST-013 | Compaction, checkpoint restore, branch/switch, import and host replacement MUST preserve influence, disclosure and owner bindings; unsupported transformations MUST refuse. | AT-MAC-HST-013 |
| MAC-HST-014 | Stop MUST request native fencing and worker termination separately, preserve precommitted effects and withhold later releases as required; host exit MUST NOT prove effect closure. | AT-MAC-HST-014 |
| MAC-HST-015 | Adapter errors and task summaries MUST preserve authoritative dispatch classification and uncertainty without raw secrets; model prose, zero exit and unsigned host reports MUST NOT establish success. | AT-MAC-HST-015 |
| MAC-HST-016 | Host or provider changes MUST require a new matching qualification and admission where bindings change; silent account, route, model, registry or version substitution MUST refuse. | AT-MAC-HST-016 |
| MAC-HST-017 | Protocol adapters MUST mediate reverse calls, sampling, elicitation, resource reads and nested delegation according to typed contracts, and MUST reject unregistered effect/disclosure channels. | AT-MAC-HST-017 |
| MAC-HST-018 | The implementation MUST maintain the source/component/installed/qualified matrix with explicit unavailable features and independent negative evidence for each advertised tuple. | AT-MAC-HST-018 |

## Frozen preparation and credential custody

The controller uses [the shared operator contract](06-operator-protocol.md); no host-specific route silently substitutes for it. A proposed host installation descriptor records exact adapter archive and installed-file hashes, host/runtime versions, lock digest, execution profile, OS/guest architecture and image, tool-registry digest, native ABI/build and authority/store identity, provider contract and account-selection rule, disclosure mode and applicable qualification references. The kernel supplies native authority and binding generation. The adapter reports installation observations and preserves opaque native handles; code-signing identity authenticates a local peer but does not grant task authority.

Preflight first validates the required capabilities and frozen account requirements without obtaining a secret. The selected trusted credential owner then resolves the credential privately and checks its actual account identity before provider submission. Unknown account identity refuses when the task requires account-specific policy. A missing key, failed refresh or account mismatch cannot select the user's ambient login or another provider. Rotation within an admitted account requires the native generation transition; account changes require new admission. macOS Keychain access, if selected, is a storage mechanism, not the grant to send a model request.

Private input uses the authenticated resource transfer defined by the controller/resource owners, or a scoped inherited FD consumed only by the trusted worker supervisor. For a future FD implementation, declare a length bound before reading, reject overflow rather than truncate, and close all unrelated inherited descriptors. A FIFO path in a world-readable directory or a temporary file merely hidden from the UI is not equivalent. The proposed initial input cap is 256 KiB; this is a testable product limit, not a measured platform maximum. The public Pi CLI's `--prompt` path is a known mismatch to this requirement and must be replaced or bypassed through qualified trusted SDK embedding.

## Model gateway and safe output

`execution-only` is an explicitly limited mode: protected effects use Chio, while a fixed trusted relay exports the selected input/history to the chosen provider under the declared task disclosure boundary. It does not claim native label-aware knowledge governance. `required` additionally needs native integrity joining and exact model-release authority. The Mac UI must show the selected mode before admission and reject a task demanding required governance when only execution-only exists.

The native model owner commits the final serialized request and performs the provider submission after current crossing checks. The adapter cannot receive a Boolean permit and later call arbitrary HTTP. Final bindings include inline context/history, tool schemas, output disposition, account/model/route, request identity, authority and policy generation, credential generation and limits. Redirects, request-header overrides, external item references, provider-hosted web/computer tools, attachments fetched by a second channel and model caches with unadmitted history are excluded until a typed contract covers them. TLS and an allowlisted hostname alone do not authorize the content.

Native context custody must include content introduced through Finder, clipboard, browser, repositories, app messages, restored sessions and child outputs. Code signing or a receipt proves origin under its contract, not that the contents are instructionally trustworthy. A summarizer cannot erase relevant influence. Different providers or accounts are different disclosure destinations.

Model and tool output begins in native release custody or the profile's declared bounded buffer. Streaming is unavailable unless the selected contract authorizes the stream's framing, chunk release, bounds and stop behavior. Otherwise buffer within the admitted limit and release after required verification. Independently verify the retained receipt, signer/trust roots, result commitment, recipient, policy and original operation. The native owner rechecks output release after stop/revocation even if the effect intent committed earlier.

Display data is inert: escape markup, strip terminal control effects, disable remote image/resource loading, refuse automatic URL/attachment opening and use typed review actions for publication. Rendering a diff cannot execute a command or cause an external fetch. A safe preview is not a delivery ACK. ACK occurs only when the authorized consumer has received the exact verified result through the native delivery contract. Receipt export and listing are separate operations.

## Lifecycle and limits

The first Pi candidate executes effect-bearing calls sequentially. Provider advice such as `parallel_tool_calls=false` is supplementary; the controller/native session fences dependent calls while original result delivery is unresolved. A lost response, failed ACK, disconnected UI or closed guest preserves original custody. Shutdown waits for active callbacks and pending native delivery observers before relinquishing ownership, while retaining uncertain effects for reconciliation.

The public Pi source supports separate request, response-byte and wall-clock bounds; subscription hard output-token bounds are unavailable. Those source facts do not determine the eventual Mac limits. Each selected tuple declares exact hard limits, observed usage and unsupported accounting. Token usage or money cannot be inferred exactly from stream length. Retry counts, model reservations and absolute task deadlines cannot reset on guest restart or split into a fresh full allowance for every child. If a task demands a hard bound the selected provider cannot enforce, admission refuses.

Updates and session transformations compare the entire frozen binding. A registry or account change cannot silently migrate an active task. A compatible restart may recover the original; an incompatible installation leaves it inspectable but unavailable for continuation. Unknown external effects remain unknown regardless of host completion prose.

## Acceptance procedures

Every case records the exact tuple and evidence class, with a provider listener, native store/effect observer or independent verifier outside the untrusted worker. Synthetic outcomes do not close installed qualification. Artifacts use the acceptance ID as filename under the selected qualification run.

### AT-MAC-HST-001: Exact installation selection

Prepare the candidate with no qualification, then with a fixture-qualified descriptor, and mutate one host version, Node digest, guest architecture, macOS build or native ABI at a time. The independent launch and credential-read counters remain zero for every unavailable/mismatched case. Only the exact complete tuple reaches preparation; record the matched signed qualification reference.

### AT-MAC-HST-002: Bypass inventory

Place hostile global/project plugins, skills, shell hooks, MCP config, provider SDK calls, extension tools and writable startup files around the worker. Attempt each declared and undeclared surface before and after reload. Outside-worker filesystem canaries, network listeners and process observations show that only the admitted inventory is reachable. Any uncontrolled surface keeps protected launch unavailable.

### AT-MAC-HST-003: Preflight before secrets

Substitute a stale generation, foreign owner, unsupported native release contract and incompatible profile. Instrument the trusted credential store and provider endpoint. Each preparation refuses before a secret read or outbound request, with a typed unavailable reason. Then present an actual wrong-account credential only after valid preflight; it refuses before egress without pretending the unread account was previously verified.

### AT-MAC-HST-004: Advisory is not authorization

Feed a valid signed advisory receipt, unsigned allow object and callback success to each effect path. The independent protected-resource counter remains zero. A real native admitted call produces exactly one original operation and independently verified effect evidence. Calling a framework executor outside its hook must be blocked by the selected profile or invalidate the host claim.

### AT-MAC-HST-005: Registry equality and reload

Change a tool alias, schema, undeclared property, canonical argument type or registry digest; repeat after Pi session reload and host replacement. Native dispatch receives no altered call. A valid call preserves its canonical argument commitment, and the measured installed callable inventory still matches the retained registry.

### AT-MAC-HST-006: Credential canaries

Use synthetic distinguishable provider and native-signing secrets. Probe guest env, files, process arguments, inherited FDs, crash reports, logs and endpoints. No reusable secret reaches those surfaces; the provider observes requests through the correct trusted account owner only. A malicious guest cannot select a credential or refresh another account.

### AT-MAC-HST-007: Private input transfer

Send a unique private prompt through the proposed bounded transfer, then send 256 KiB plus one byte, a truncated frame and a foreign caller. Only the bounded authenticated transfer is consumed once. An independent process/diagnostic observer finds no prompt in argv/env/events, and rejected input creates no model request or spill file.

### AT-MAC-HST-008: Required governance refusal and release

Supply absent, callback-only and foreign native ports; request required mode. All refuse before credential access. With a real qualified native owner, cut execution before intent commit, after commit before ACK and before provider submission. Native journal and destination capture prove bytes are released only under the owner's retained original and current crossing, never by adapter fetch after a permit.

### AT-MAC-HST-009: Model destination and byte equality

Attempt account/model substitution, redirect, proxy headers, remote context references, hosted tools and changed final JSON after preparation. Capture provider-side traffic and the native release commitment. Invalid requests produce no disclosed bytes; the valid request's exact bytes and destination match the retained native record.

### AT-MAC-HST-010: Durable aggregate bounds

Exhaust request, byte and admitted hard-token limits across restart, two children and a held provider request; inject clock change and a subscription profile requiring a hard-token bound. Independent reservation and provider counters stay within enforceable limits; unsupported hard bounds refuse, and absent usage remains unavailable rather than zero.

### AT-MAC-HST-011: Verified inert output

Return a forged/foreign receipt, changed artifact, terminal escapes, hostile HTML, remote image, oversized stream and a valid result. Verify no invalid bytes reach parent context, no preview causes external network/process effects and no mere preview/export sends ACK. Stop between return retention and release; the native owner records the return and withholds the later release as required.

### AT-MAC-HST-012: Original recovery and ACK

Lose dispatch response and delivery ACK at separate cutpoints, restart both adapter and guest, and request a second dependent effect. Original native IDs and effect count remain unchanged; the second effect stays fenced until verified delivery/reconciliation. Corrupt retained state cannot trigger a fresh identity or rerun.

### AT-MAC-HST-013: Context transformations

Compact attacker-influenced history, restore a stale checkpoint, switch session and import a foreign transcript. Compare native knowledge/influence commitments before and after. Qualified transformations retain or strengthen relevant influence and destination constraints; unsupported transforms refuse before raw context enters the model.

### AT-MAC-HST-014: Stop does not erase effects

Race stop before intent, after intent before effect, and after effect before output release; kill the wrapper while a child remains. Native transaction order, external effect log and process observer distinguish all states. Post-stop releases follow the kernel fence; process exit never fabricates external rollback or completed closure.

### AT-MAC-HST-015: Truthful outcomes and safe errors

Combine a provider 401/429/5xx, timeout, malformed response or failed required test with a host zero exit and success paragraph. Task projection follows verified native state and test evidence. Unknown effects remain unresolved. Scan error/event exports for the synthetic secret and private payload canaries; neither appears.

### AT-MAC-HST-016: No qualification inheritance

Change one provider contract, account, adapter archive, host version or optional Durable selection after a successful run. The old qualification cannot enable the new tuple, and a retained task cannot silently adopt the changed binding. Independently compare installation hashes and admission records.

### AT-MAC-HST-017: Reverse protocol channels

Exercise MCP sampling/elicitation/resource reads, nested A2A calls and tool-generated URL/attachment requests. Unknown or unregistered channels refuse without a model call, browser open, new child or disclosed bytes. An explicitly admitted channel produces its own crossing and destination evidence; a notification remains a hint.

### AT-MAC-HST-018: Matrix publication gate

Give the release checker component-test evidence alone, an unrelated architecture run, a stale installation and a complete current tuple. Only the last can be reported qualified. Independently verify that every public capability statement has an applicable positive and negative artifact and all open/skipped cases remain visible.
