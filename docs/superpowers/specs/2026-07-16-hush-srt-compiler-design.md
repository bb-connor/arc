# Hush-to-srt Compiler: Cross-Platform Child Sandboxing from the Same Policy Document

- Status: Draft for review (2026-07-16). Proposal only. Part of the substrate-receipts program; this discharges the spawn hole the Bun runtime design names as gated-not-covered, using the sandbox Claude Code already ships.
- Scope: `arc` (a profile compiler in or beside `crates/guards/chio-policy`, receipt schema additions, spawn-wrap integration for governed runtimes) plus a thin TypeScript shim over `@anthropic-ai/sandbox-runtime`.
- Related: `docs/superpowers/specs/2026-07-15-bun-runtime-enforcement-design.md` (section 6.2 names this program), `docs/superpowers/specs/2026-07-09-enterprise-hardening-design.md` (`chio-cage`, the deep Linux endgame this complements), `docs/superpowers/specs/2026-07-16-python-audit-receipts-design.md`.

## 1. Context and problem statement

The runtime designs (Bun, Python) share one dominant hole: child processes. A spawned `curl` touches none of the runtime's choke points, and spawning shell commands is most of what a coding agent does. The Bun design's enforcement option for spawn is "wrap the child in an OS sandbox profile generated from the same Hush document" and defers that program; `chio-cage` (enterprise-hardening design) is that program's deep form, Linux-only, manifest-driven, FD-retained grants, default-deny seccomp, and it is designed but not implemented.

Meanwhile Anthropic open-sourced sandbox-runtime (srt, `@anthropic-ai/sandbox-runtime`, Apache-2.0, beta research preview): the sandbox Claude Code's own sandboxed bash uses. It wraps arbitrary commands with filesystem rules (bubblewrap bind mounts on Linux, Seatbelt profiles via sandbox-exec on macOS, NTFS ACLs on Windows alpha), and network rules enforced by routing all egress through host-side HTTP/SOCKS5 proxies that check a domain allowlist (network namespace removal plus socat on Linux, loopback-only Seatbelt rules on macOS, WFP filters on Windows). It also ships a violation store.

The gap this design fills: compile the same Hush document that governs the runtime into srt settings, wrap policy-permitted spawns with srt automatically, and turn srt's proxy decisions and violations into receipts on the session chain. Enforced-mode spawn then stops being grant-with-evidence and becomes bounded-with-evidence, cross-platform, today, without waiting for cage.

## 2. Goals

- A deterministic compiler from a Hush document (filesystem, egress, shell blocks plus `extensions.vendor.chio.runtime`) to an srt settings object, with a content-addressed profile hash.
- Spawn integration: governed runtimes wrap permitted spawns with the compiled profile; the spawn receipt records profile hash and lossiness report (below).
- Receipts from the child's boundary: srt proxy domain decisions and violation-store events map into the session chain as child-attributed net/fs events, partially closing the child observation hole, not just the enforcement hole.
- An explicit, attested lossiness contract wherever Hush semantics do not fit srt semantics.

## 3. Non-goals

- Replacing `chio-cage`. Cage is the deep Linux endgame (FD-retained grants, default-deny seccomp allowlist, no reliance on proxy cooperation); when it lands, it supersedes srt on Linux. This design is the breadth-now, cross-platform bridge, and both compile from the same document, so the swap is a backend change.
- Fixing srt's own limitations (domain fronting, broad-domain exfiltration, no traffic inspection beyond domain checks). They are inherited and named in the claim, exactly like the runtime designs' holes.
- Windows support claims. srt's Windows backend is alpha with material caveats (DNS not fenced, proxy token visible in process args); compile for it, mark it experimental, claim nothing.
- Sandboxing the governed runtime itself (the runtime designs cover the parent; this covers children).

## 4. Semantics mapping and the lossiness contract

The compiler's central discipline is that every Hush constraint either maps, or is reported. The mapping has real impedance mismatches that must be handled honestly:

- **Filesystem reads are default-allow in srt** (`denyRead` carves out of allow-everything, and `allowRead` overrides `denyRead`). Hush filesystem read allowlists therefore cannot compile to a true read allowlist on srt. The compiler emits `denyRead` entries for known-sensitive roots plus the workspace complement where expressible, and records `fs-read: partial` in the lossiness report. Writes are default-deny in srt and map cleanly.
- **Linux paths are literal; only macOS gets globs.** Glob-bearing Hush rules compile per-platform; on Linux, unexpandable globs are lossy and reported.
- **Network is domain-level via proxy.** Hush egress host rules map to `allowedDomains`/`deniedDomains` (deny takes precedence in srt, matching deny-wins). Port- or IP-level Hush rules beyond srt's model are lossy and reported. srt's hardcoded always-blocked writes (shell rc files, `.git/hooks`, `.claude/`) are a floor the compiler never relaxes.
- **Weakener flags** (`enableWeakerNestedSandbox`, `enableWeakerNetworkIsolation`, `allowAppleEvents`, `allowAllUnixSockets`) are never emitted unless the policy explicitly opts in via the vendor block, and any emitted weakener appears in both the profile hash inputs and the spawn receipt.

The lossiness report is a canonical, hashed artifact listing every constraint that could not be fully expressed on the target platform. Fail-closed rule: in enforced mode, a lossy profile denies the spawn unless the policy carries an explicit `allow_lossy_sandbox` acknowledgment scoped to the loss classes it accepts; advisory mode proceeds and receipts the report. This is the mechanism that keeps "sandboxed" from quietly meaning different things on different machines.

## 5. Architecture

1. **Compiler** (Rust, beside `chio-policy`): Hush document + target platform in; srt settings JSON, profile hash, lossiness report out. Deterministic, no ambient state, property-tested (same document + platform always yields byte-identical settings).
2. **Spawn wrap**: when a governed runtime's spawn check allows with sandbox obligation, the runtime launches the child under srt with the compiled settings (`SandboxManager.wrapWithSandbox` from the TS shim for Bun-side; CLI wrapping for hermes-side). The spawn receipt gains `{sandbox: "srt", srt_version, profile_hash, lossiness_hash}`.
3. **Receipt bridge**: a collector subscribes to the srt proxy's decision log and violation store, translating events into child-attributed net/fs receipts on the session chain (child pid/argv-hash correlation from the spawn receipt). Suppression semantics inherit the runtime design's sequence-number treatment.
4. **Verification**: `chio verify` gains profile-hash checking, so an auditor confirms not only that a spawn was sandboxed but under exactly which compiled profile, and with which acknowledged losses.

## 6. Trust model

What an srt-wrapped spawn receipt proves: the child was launched under a profile compiled from policy hash P, with lossiness report L, and the recorded proxy decisions are the child's domain-level egress history. Inherited weaknesses, always stated: srt inspects domains, not traffic; a broad allowed domain is an exfiltration channel; on Linux, a tool that ignores proxy environment variables loses connectivity rather than bypassing (fail-closed by architecture), but unix-socket grants (e.g. Docker) are host-access grants; violation monitoring on Linux is not automatic. srt is a beta research preview and this design's assurance ceiling is srt's assurance ceiling; cage exists because that ceiling is not the endgame.

## 7. Operator experience

Nothing new to author: the same Hush document that governs the parent runtime bounds the children, which is the entire point. The visible additions are the lossiness report in `chio policy analyze` output (what would this document lose on macOS vs Linux), the `allow_lossy_sandbox` acknowledgment when policy authors accept partial read confinement, and child egress showing up in the same fleet views and profiles as parent egress. `chio profile` gets materially better: child network behavior, which was invisible, now feeds policy synthesis.

## 8. Rollout and claim discipline

1. Compiler + `chio policy analyze` lossiness output first (pure tooling, no runtime change).
2. Spawn wrap in advisory sessions: children sandboxed in permissive profiles, receipts flowing, overhead measured (srt adds proxy hops to child egress; measure before promising).
3. Enforced-mode spawn obligation last, gated on the bounded-operational-profile discipline from the runtime design, with section 6's scoping in every claim. The Bun design's section 6.2 is then updated: spawn moves from grant-with-evidence to bounded-with-evidence on platforms where srt is qualified.

## 9. Risks and open questions

- **srt API churn.** Beta research preview; settings schema and library API can move. Pin versions, vendor the settings schema, and treat srt upgrades like spec bumps (compiler conformance vectors re-run).
- **Upstream dependence.** srt is Anthropic-maintained; deprecated tomorrow means this bridge ages out. Acceptable because the compiler's front half (Hush -> abstract confinement profile) is exactly what cage consumes; only the backend is srt-shaped.
- **macOS sandbox-exec deprecation** remains the platform risk it was in the Bun design; srt inherits it, and so do we.
- **Correlation fragility** in the receipt bridge (proxy events to child identity) needs a real design during implementation; pid reuse and short-lived children are the annoying cases.
- **Double-sandboxing** with Claude Code's own srt usage (its sandboxed bash) needs detection: wrapping an already-wrapped child either composes or conflicts, and `enableWeakerNestedSandbox` is the flag srt itself reaches for, which is a weakener we refuse by default.

## 10. Deliverables

Profile compiler with property tests and per-platform conformance vectors; lossiness report format + `allow_lossy_sandbox` policy acknowledgment in `chio-policy`; TS shim + Bun/hermes spawn-wrap integration; proxy/violation receipt bridge; `chio verify` profile-hash support; overhead report on a recorded session corpus; Bun design section 6.2 update once qualified.

## 11. References

- sandbox-runtime: https://github.com/anthropic-experimental/sandbox-runtime
- Anthropic on Claude Code sandboxing: https://www.anthropic.com/engineering/claude-code-sandboxing
- npm package: https://www.npmjs.com/package/@anthropic-ai/sandbox-runtime
