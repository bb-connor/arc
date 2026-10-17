# Chio Audit Receipts for CPython: PEP 578 Hooks as a Receipt Source with Soft-Deny

- Status: Draft for review (2026-07-16). Proposal only. Part of the substrate-receipts program; this is the Python twin of the Bun runtime design's Path A, with the difference that CPython's choke points already ship.
- Scope: a new Python package (working name `chio-audit`) depending on `chio_adapter_base`, integration into `sdks/python/chio-hermes`, and optionally a later pyo3 native hook crate in `arc`.
- Related: `docs/superpowers/specs/2026-07-15-bun-runtime-enforcement-design.md` (trust model, session signer, aggregation rules, claim discipline all inherited), `docs/integrations/HERMES.md`.

## 1. Context and problem statement

Most of the agent-framework world runs on CPython, and CPython has had runtime audit hooks since 3.8: PEP 578 defines `sys.addaudithook()` and an event stream covering file opens, socket connections, subprocess creation, imports, `exec`/`compile`, and `ctypes.dlopen`, raised from inside the interpreter's own implementations. Two properties make this the right substrate for the receipt pattern: hooks cannot be removed or replaced once added, and an exception raised from a hook aborts the audited operation, which yields a soft-deny mode for free.

PEP 578 is equally explicit about what this is not: it is an auditing mechanism, not a sandbox. Native extensions bypass it entirely, an operation reached through an API that fails to raise its event is a coverage bug rather than an impossibility, and PEP 551 positions the whole facility as defense-in-depth. That is exactly the honesty posture the Bun design's Path A already takes (receipt source, never called enforcement), so the labels transfer unchanged.

Chio's Python surface today is chio-hermes, whose hooks are tool-call-level plugin callbacks and whose receipts module already implements the canonical-JSON buffer plus sidecar-store split. There is no interpreter-level receipt source. This design adds one, usable by hermes and by any Python agent framework.

## 2. Goals

- A signed receipt stream for interpreter-level operations (fs, net, spawn, import, dlopen, exec) attributed to agent sessions, using the same session signer, sequence numbers, and aggregation rules as the Bun design.
- Soft-deny mode: policy-denied operations abort via a hook-raised exception, honestly labeled soft because of the PEP 578 caveats.
- Framework-agnostic packaging with first-class hermes integration, so reach extends beyond Chio's own host.
- A hardening ladder toward a native (pyo3) hook for performance and tamper resistance.

## 3. Non-goals

- Calling anything here enforcement. PEP 578's own text forecloses that claim; the strongest honest label is receipt source with soft-deny.
- Governing native-extension behavior after import, or subprocess behavior after spawn (both are the same gated-not-covered boundaries as the Bun design's section 6, and `ctypes.dlopen` plus `subprocess.Popen` events are the gates).
- Patching or forking CPython.
- A general Python sandbox (that problem is srt/cage territory, per the companion srt design).

## 4. Architecture

**4.1 Hook installation.** `chio_audit.install(policy_path=None, mode="observe"|"soft-deny")` adds one audit hook and connects to the session signer (same Unix-socket protocol as the Bun design; local JSONL buffer fallback per the hermes receipts pattern). Installation routes: explicit call (frameworks), the hermes plugin (automatic when a governed session starts), or a `.pth`/`sitecustomize` shim for zero-code adoption. The hook is installed once per interpreter; installation itself emits a session-binding receipt (interpreter version, policy hash, install route, mode).

**4.2 Event mapping.** A fixed table maps audit events to the shared operation vocabulary from the Bun design: `open` -> fs, `socket.connect`/`socket.getaddrinfo` -> net/dns, `subprocess.Popen`/`os.exec*` -> spawn, `import` -> module load, `ctypes.dlopen` -> ffi, `exec`/`compile` -> code eval. Events outside the table pass through uncounted but are sampled into a coverage receipt (which event names fired this session), because the event set varies across CPython versions and coverage must be attested, not assumed.

**4.3 Decision path.** Observe mode records only. Soft-deny mode evaluates the compiled Hush document per operation with the same (op-type, target) decision cache as the Bun design and raises `ChioPolicyDenied` on deny, aborting the operation with a structured message the agent can act on. Policy blocks map as in the Bun design: egress for net, filesystem for fs, shell for spawn; ffi/import gating rides `extensions.vendor.chio.runtime`.

**4.4 Aggregation and volume.** Python's `open` and `import` events are extremely hot (every module import compiles and opens files). The Bun design's aggregation rules apply unchanged: full receipts for net/spawn/ffi, first-touch-plus-digest for fs and imports, aggregation attested in the policy.

**4.5 Attribution.** Audit hooks receive no task context. Session-level attribution is inherent (one interpreter, one session receipt chain); sub-session attribution (which asyncio task or thread initiated an operation) uses a contextvar the hermes integration sets around tool invocations, read best-effort by the hook, and marked absent rather than guessed when unset.

## 5. Hardening ladder

1. **Pure-Python hook (this design's deliverable).** Correct, portable, adequate for observe mode; per-event overhead is Python-function-call scale, so soft-deny on hot events needs the cache and may still be measurable. Measured, not assumed, before default-on.
2. **Native hook via pyo3.** A small extension module registering the hook in Rust: nanosecond-scale checks, immune to Python-level tampering with the hook's own code, sharing `chio-policy` compiled-policy machinery. This is the production shape if adoption warrants it.
3. **Embedded launcher (named, not designed).** `PySys_AddAuditHook` from C before the interpreter starts (a `chio-python` launcher) closes the installation-ordering hole (a hook added first sees hooks added later; code running before `install()` is unobserved). Only worth building if the `.pth` route proves too fragile.

## 6. Trust model deltas from the Bun design

The Bun design's table holds with two Python-specific weakenings, both stated in every artifact:

- The hook runs in-process and in-language. It cannot be removed, but code running before installation is unobserved (ordering hole; the launcher rung closes it), and CPython event coverage is a per-version empirical fact (the coverage receipt makes it checkable).
- Soft-deny aborts cooperating code paths. A native extension makes syscalls the interpreter never sees; `ctypes.dlopen` deny-by-default in soft-deny mode is therefore the load-bearing rule, exactly as FFI gating is in Bun.

Out-of-process signing, sequence-gap suppression detection, and the session-binding receipt are inherited unchanged.

## 7. Operator experience

Same shape as the Bun design at every persona. Developer: one line in hermes config (or `pip install chio-audit` plus an env var for other frameworks); denials are structured exceptions agents can read; `chio profile` consumes the same receipt stream to synthesize policy. Platform team: same fleet signals (deny spikes, dlopen grants, sequence gaps), now covering Python agents, which for most orgs is the larger population. Auditor: same export bundle, same verify, claim scoped per section 6.

## 8. Rollout and claim discipline

1. Observe mode ships first, labeled receipt source, and feeds policy synthesis.
2. Soft-deny ships behind an explicit mode flag with the PEP 578 caveats in the enablement docs, never described as enforcement.
3. The pyo3 rung is gated on measured overhead from rung 1 under a real agent workload (hermes session corpus).

## 9. Risks and open questions

- **Hot-event overhead** may make soft-deny impractical in pure Python for import-heavy workloads; the ladder exists for this, but rung 1 numbers decide.
- **Installation fragility.** `.pth`/`sitecustomize` behavior varies across venv tools, uv, and site configurations; the hermes route is reliable but only covers hermes-hosted sessions.
- **Event-set drift** across CPython 3.8-3.14; the coverage receipt turns this from a silent gap into an attested fact, but the mapping table needs per-version CI.
- **`chio-hermes` PyPI publication is still pending** (wheels built, upload blocked on a pypi.org token); `chio-audit` shares that distribution dependency.
- **Threaded attribution** is best-effort; anything stronger (per-frame walking) costs too much on the hot path and is explicitly not attempted.

## 10. Deliverables

`chio-audit` package (hook, event map, decision cache, coverage receipt, signer client reusing `chio_adapter_base.receipts`); hermes plugin integration + contextvar attribution; policy-block mapping validation in `chio-policy`; overhead report on a recorded hermes corpus; claim-scoped README; pyo3 rung as a follow-on decision, not a commitment.

## 11. References

- PEP 578: https://peps.python.org/pep-0578/
- PEP 551 (security transparency guidance): https://peps.python.org/pep-0551/
- CPython audit events table: https://docs.python.org/3/library/audit_events.html
