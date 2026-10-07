# Shared desktop operator protocol and Mac transport

Status: proposed contract, 2026-10-07. `chio.desktop.operator.v1` is a new shared operator proposal. It is not the installed kernel ABI, a replacement native approval format, or an alias for `chio.omarchy.operator.v1`.

## Transport and identity

The Mac app uses an authenticated XPC service carrying bounded JSON bytes in fixed request/reply methods and a fixed event delivery callback. A CLI reaches the same authenticated service through a signed bridge. The public protocol does not expose a localhost HTTP listener. Before decoding sensitive data, validate service/caller designated signing requirements, UID, audit session and the registered endpoint identity. Associate the connection with the current native principal using the delivered kernel binding contract.

Decode UTF-8 strictly; reject duplicate keys, invalid Unicode, nonfinite numbers, unsafe integer values, unknown fields and unknown methods. Limit each envelope to 65,536 bytes and nesting to 16; limits apply before buffering an entire attacker-controlled stream. The byte codec uses RFC 8785 canonical JSON when it commits or hashes an envelope. Native signed objects are opaque references, verified using their own registered native encoding and verifier. Do not reserialize signed native payloads through Swift's generic dictionaries.

Allow at most 16 in-flight requests per connection, 64 queued events per subscription and 100 items per page. A request times out at the operator transport after 30 seconds; timeout does not cancel or undo an admitted effect. Native work duration uses a separately admitted limit. Queue overflow emits a gap and requires snapshot reread. Event payloads contain no document bodies or reusable credentials.

## Envelopes and native references

The [schemas](contracts/README.md) are authoritative for proposed JSON field shapes. Requests have `version`, `request_id`, `method`, and `params`. Responses repeat version, request ID and method, with exactly one success result or classified error. `request_id` is a transport correlation value. A mutating `intent_id` is stable over retries by the same authenticated principal/method and parameter commitment; neither is a native operation identity.

Native references contain `kind`, `issuer`, `native_id`, `generation`, and `digest`. They are locators into a registered authority owner, never arbitrary URLs to fetch. Only the native verifier establishes ownership, subject binding, freshness and content. Decimal generation and budget fields use canonical nonnegative decimal strings. Monetary units are explicit; the initial operator example uses USD minor units, not floating-point dollars or arbitrary token pricing.

The controller's hello/session identity authenticates a connection and binds its selected wire version. It does not mint agent authority. A connection must complete hello once before other methods. Repeated hello with a different nonce/version on the same connection closes it; reconnect creates a new transport session without creating a new native operation or grant.

## Closed method set

| Method | Meaning and native boundary |
| --- | --- |
| `hello` | Negotiate exactly one supported operator version and establish the transport session |
| `health.get` | Read redacted feature prerequisites; no credentials or arbitrary filesystem probing |
| `tasks.list`, `task.get` | Read principal-scoped native projections, including full current stop state, with bounded pagination |
| `task.create` | Request fixed `project-change-v1` template using native workspace, sealed task-input and grant references, selected qualified execution profile and attenuated limits |
| `operation.get` | Reconcile the original native operation reference, including unresolved outcome |
| `task.stop` | Request task or task-and-descendants stop through the native owner; return separate stop dimensions |
| `review.open` | Open the installed trusted native review for an existing operation; no caller-provided web URL |
| `approval.submit` | Forward native review and endorsement references plus the exact decision to the native approval owner |
| `events.subscribe` | Allocate a stable subscription ID and bounded hint cursor; mark rebase explicitly |
| `events.ack` | Acknowledge an observed native-ended subscription for this authenticated session using its stable ID; a live subscription refuses acknowledgement |
| `evidence.export` | Request a redacted evidence bundle into an enrolled destination resource under native export authority |

The trusted review component obtains a native decision record through the delivered approval-owner interface. `approval.submit` checks decision equality and consumes/records it under that native contract. It does not transform a UI boolean, biometric success, browser event, or message arrival into endorsement. If the native review or decision-binding interface is missing, review and submission are unavailable.

Selecting a new source or destination is a trusted enrollment interaction, governed by [resource contracts](10-project-resources.md), before those references are used here. This version intentionally has no generic path-open, shell, settings-write, provider-secret, arbitrary app automation, or task-resume method. Recovery uses original native operation reconciliation and an explicit later typed contract if continuation needs new authority.

The trusted native publication-preparation bridge similarly returns a retained native operation before `review.open`. It accepts only a sealed artifact and enrolled destination under the closed owner contract; it binds exact content, parent identity/generation, filename, absent-target condition and current policy/influence. It cannot publish before native approval/admission. This is an M0 resource/approval prerequisite, registered in the same census, not an unlisted public operator mutation or a reuse of evidence export.

`input_ref` identifies a sealed task-input resource containing the user's task objective. It is distinct from the project `resource_ref`; neither can substitute for the other even though both use the native resource reference shape. The native owner verifies each resource's registered type and generation. Bootstrap influence joins before agent readiness; authentic operator input requires the native assertion contract if it is to carry an endorsed integrity level. Raw prompts and their potential secrets stay outside operator event/diagnostic payloads.

## Mutation, ordering and recovery

For each mutating request, the native owner binds authenticated principal, method, intent ID and canonical parameter commitment atomically before dispatch. Equal retries resolve the original operation; unequal reuse is conflict. The controller may cache the mapping only as a projection. A crash between dispatch and response must be resolved through native original lookup before any repeated dispatch. If that contract is absent, the method is unavailable rather than locally journaled as a new authority engine.

The serving writer serializes crossing authorization with stop, revocation, integrity state and reservations. Two controller connections cannot bypass that serialization. A stop response may say requested while worker, network and external outcome remain unknown. A prior committed intent may still take effect; post-return release is independently checked. `internal_unavailable` and `outcome_unknown` must never be translated into a fresh create intent.

Stop responses and authoritative task rereads include `durability` as `unknown`, `process_only`, `latch_only`, or `durable`, using the native meanings in spec 11. `admission: restricted` reports a partial/local restriction; `fenced` requires durable native stop evidence, and `durable` requires a native stop reference. Schema checks only those structural implications; the native verifier establishes the actual evidence. Every task projection includes `stop_state`: null means the native owner confirms no stop request for that task generation at the observed revision, not an unknown stop outcome. If that fact cannot be established, return an unavailable/error or explicit unknown stop state. `task.get` and `tasks.list` therefore recover progress after reconnect without issuing a second stop mutation.

Errors use a closed code and a safe `message_key`, not a raw exception or secret path. `retry` is `never`, `same_intent`, or `reread`; a retry hint cannot enlarge native permission. Authentication failure, stale references, conflicting intent reuse and unmet prerequisites are distinguishable. Native operation references in errors are included only if authorized for the caller.

## Events and shared-platform migration

Events are `task.changed`, `coverage.changed`, `review.invalidated`, `stream.gap`, or `subscription.ended`; every event has `hint_only: true`. Consumers reread the relevant native state. The cursor is controller transport state, not a kernel crossing order, ES sequence number, provider generation or evidence completeness proof.

Stable `subscription_id` values are never reused within the authenticated native session and are retained with their acknowledgement disposition according to the delivered native event contract. Rebase and acknowledgement serialize through that owner. A prior subscription cannot be resurrected by a stale publisher; an acknowledgement for another session is rejected. Controller restart either restores the native subscription binding or reports a new transport subscription with an explicit gap. It never acknowledges a native subscription based only on a local transport sequence.

`subscription.ended` projects the native retained terminal for that exact stable subscription. The native owner retains and replays it across dropped delivery/reconnect until an authorized acknowledgement succeeds. A client attempts `events.ack` only after observing this terminal; the owner independently checks ended state and refuses acknowledgement of a live entry. A terminal hint does not itself grant authority or prove that every preceding event was received. Gaps still require reread, and a local transport gap/closure must not fabricate a native terminal. An already acknowledged tombstone returns `already_acknowledged` only to the owning authenticated session and is never reused as a new subscription.

The reason mapping is total over the pinned NK-08 owner: `Revoked -> revoked`, `Expired -> expired`, `AuthorityTimeUnavailable -> authority_time_unavailable`, `AuthRotated -> auth_rotated`, and `SubjectGone -> subject_gone`. A newly introduced owner reason requires an explicit compatible contract update; unknown variants close the adapter's compatibility gate rather than being mislabeled. Transport overflow is `stream.gap`, not a fabricated native terminal. All five native reasons have synthetic contract fixtures, including quiet expiry.

The Omarchy adapter continues to support its existing version. M2 introduces a compatibility map for shared method semantics, identity, bounds, errors and stable subscription behavior. Migration requires explicit negotiation and fixture evidence in both adapters. Mac wire-contract acceptance cannot qualify Linux or change the old ABI in place.

## Requirements

| ID | Requirement | Acceptance |
| --- | --- | --- |
| MAC-IPC-001 | The service MUST authenticate the peer and bind principal/session before all non-bootstrap operations; hello MUST precede other methods and MUST NOT grant native authority. | AT-MAC-IPC-001 |
| MAC-IPC-002 | Decoding MUST enforce the closed method/field set, strict UTF-8/Unicode, duplicate-key rejection, integer rules, 65,536-byte limit and nesting depth 16. | AT-MAC-IPC-002 |
| MAC-IPC-003 | Each response MUST match the initiating version, request ID, method and any echoed native operation, task, subscription or decision binding. | AT-MAC-IPC-003 |
| MAC-IPC-004 | Native references MUST resolve only through registered native owners and MUST pass native kind, issuer, subject, generation, digest and freshness verification before use. | AT-MAC-IPC-004 |
| MAC-IPC-005 | Mutation retries MUST use native retained principal/method/intent/parameter bindings; equal retries return original disposition and unequal reuse MUST conflict before effect. | AT-MAC-IPC-005 |
| MAC-IPC-006 | Task creation MUST select a qualified profile, fixed template, verified workspace and sealed task-input resources and native grant, and MUST attenuate requested limits against current native authority. | AT-MAC-IPC-006 |
| MAC-IPC-007 | Approval submission MUST require a native endorsement bound to operation, decision, review and relevant current authority/influence. Local UI events MUST NOT synthesize it. | AT-MAC-IPC-007 |
| MAC-IPC-008 | Stop MUST route through the native owner and MUST return native durability plus admission, worker, network, cleanup and external-outcome dimensions; task reads MUST expose those facts after reconnect without another mutation. | AT-MAC-IPC-008 |
| MAC-IPC-009 | Events MUST remain hints, use principal-scoped stable subscription identities, and require reread after gaps; acknowledgement MUST NOT use transport event sequence as native identity. | AT-MAC-IPC-009 |
| MAC-IPC-010 | Pagination and event subscriptions MUST enforce configured resource bounds and owner-scoped cursors; cursor guessing MUST NOT disclose another principal's state. | AT-MAC-IPC-010 |
| MAC-IPC-011 | Timeout, cancellation of the transport and lost reply MUST preserve native recovery obligations and MUST NOT authorize fresh redispatch of an uncertain effect. | AT-MAC-IPC-011 |
| MAC-IPC-012 | Errors MUST use closed safe codes and message keys, redact internal paths/secrets, and distinguish unknown outcome from definite denial. | AT-MAC-IPC-012 |
| MAC-IPC-013 | Evidence export MUST be an admitted release into a native destination resource under export authority; a caller-provided path MUST be rejected. | AT-MAC-IPC-013 |
| MAC-IPC-014 | Version negotiation MUST reject unknown versions and silent Omarchy aliases; migration MUST preserve existing semantics through explicit cross-platform mapping tests. | AT-MAC-IPC-014 |
| MAC-IPC-015 | The codec MUST preserve native signed bytes or opaque references and MUST NOT claim schema validation verifies signatures, authority or confinement. | AT-MAC-IPC-015 |
| MAC-IPC-016 | Revocation, stop, endorsement consumption, integrity and budget checks MUST occur at their native serialized crossing; request ordering in XPC MUST NOT substitute for it. | AT-MAC-IPC-016 |
| MAC-IPC-017 | Successful hello and health observations MUST NOT enable unavailable features; current qualification plus native per-operation authority MUST be required for mutation. | AT-MAC-IPC-017 |
| MAC-IPC-018 | Compatibility and release evidence MUST bind the selected profile and installed tuple; synthetic fixtures and source/component evidence MUST NOT qualify runtime. | AT-MAC-IPC-018 |
| MAC-IPC-019 | Native subscription terminals MUST be observable and replayed until acknowledged; live acknowledgements MUST refuse. Rebase, end acknowledgement and publication MUST serialize through the stable-subscription owner; stale publication MUST NOT resurrect acknowledged state. | AT-MAC-IPC-019 |
| MAC-IPC-020 | Each method MUST have a positive and relevant negative contract fixture, with response-substitution checks outside JSON shape validation. | AT-MAC-IPC-020 |

## Acceptance procedures

| Acceptance | Setup/action | Required oracle |
| --- | --- | --- |
| AT-MAC-IPC-001 | Connect unauthorized and signed expected peers; send mutation before hello and renegotiate after hello. | Unauthorized/bootstrap violations rejected without native dispatch; expected peer can read its authorized status. |
| AT-MAC-IPC-002 | Send duplicate keys, malformed UTF-8, lone surrogates, huge integers, oversized/deep envelopes, unknown fields and shell methods. | Codec rejects before invoking native adapters, with bounded memory and stable safe errors. |
| AT-MAC-IPC-003 | Substitute another request's result, method, operation reference, task ID, decision and subscription ID. | Correlation validator rejects each swap even when both individual envelopes have valid shapes. |
| AT-MAC-IPC-004 | Change each native reference field and replay revoked, foreign-user and prior-generation references. | Native verifier refusal, no resource effect, authentic positive reference accepted within scope. |
| AT-MAC-IPC-005 | Race equal and unequal same-intent requests across connections, then crash after dispatch before reply. | Exactly one retained native operation/effect for equal intent; unequal reuse conflicts; recovery returns original. |
| AT-MAC-IPC-006 | Request unqualified profile, expanded budget, wrong resource generation and unknown template. | Refusal before launch/provider access; bounded qualified positive control runs. |
| AT-MAC-IPC-007 | Submit without endorsement, with wrong decision, changed influence, expired review and foreign operator. | Native refusal without consumption of unrelated approval; exact positive control records once. |
| AT-MAC-IPC-008 | Stop before intent, after intent and during external effect; inject journal and anchor failure, disconnect and read task state again. | Process-only/journal-only/durable evidence and distinct dimensions agree with native order and outside observers; read-only reconnect recovers progress without another stop. |
| AT-MAC-IPC-009 | Drop events, rebase stream and acknowledge with transport ID or another session's ID. | Gap requires reread; only stable authorized subscription acknowledged. |
| AT-MAC-IPC-010 | Exhaust page/queue/concurrency limits and replay another user's cursor. | Bounded refusal/backpressure with no cross-user disclosure or loss of native obligations. |
| AT-MAC-IPC-011 | Delay reply past 30 seconds while the external operation completes; reconnect and retry. | Original operation is reconciled; no duplicated external effect. |
| AT-MAC-IPC-012 | Trigger each error using secret-bearing test paths and credentials. | Expected closed code/key and no secret substring; unknown remains distinct from denied. |
| AT-MAC-IPC-013 | Export to a forged path, revoked destination reference and valid enrolled destination. | First two rejected; valid export is independently observed and recorded as a release. |
| AT-MAC-IPC-014 | Send legacy/unknown version and run both adapters' versioned vectors. | No implicit downgrade; explicit supported mapping only. |
| AT-MAC-IPC-015 | Change one signed native payload byte and feed a shape-valid fabricated reference. | Native verifier rejects; document validator reports only its limited shape result. |
| AT-MAC-IPC-016 | Interleave two connections with stop, integrity change and budget exhaustion at writer barriers. | Native order controls outcome; stale precheck never grants a later crossing. |
| AT-MAC-IPC-017 | Replay a healthy/qualified observation after installed tuple change or revocation. | Mutation blocked by current gates and native check, regardless of UI health. |
| AT-MAC-IPC-018 | Substitute architecture, build digest, permission state or applicability manifest; use synthetic evidence. | Runtime verifier refuses qualification; document shape checker makes no runtime claim. |
| AT-MAC-IPC-019 | Attempt live acknowledgement, drop first native terminal delivery, reconnect, observe replayed terminal, then pause a publisher while another connection acknowledges/rebases. | Live ack refuses; terminal is replayed until valid ack; stale publisher cannot resurrect it; a new subscription remains separately live. |
| AT-MAC-IPC-020 | Run all catalog fixtures and mutate method/result correlation beyond schema validation. | Deterministic shape/correlation results match catalog; missing fixture coverage is a document failure. |

See [machine contracts](contracts/README.md) and the [implementation plan](../../plans/2026-10-07-macos-integration/02-protocol-controller.md). These acceptance procedures require implementation and native evidence beyond the synthetic document validator.
