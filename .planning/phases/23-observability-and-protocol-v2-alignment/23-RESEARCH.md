# Phase 23 Research

## Findings

1. `pact trust serve` already exposed `/health`, `/v1/authority`, and
   `/v1/internal/cluster/status`, but the top-level health payload did not yet
   summarize authority availability, store configuration, federation registry
   state, or cluster peer counts.
2. `pact mcp serve-http` already exposed `/admin/authority`,
   `/admin/sessions`, and per-session trust views, but it lacked a single
   additive `/admin/health` snapshot covering auth mode, store setup, session
   counts, federation configuration, and OAuth metadata.
3. Provider-admin, verifier-policy, and certification state was already
   persisted in shared file-backed registries; the operational gap was surfacing
   configured vs available vs active state explicitly.
4. The provider-admin regression added for health reporting exposed an initial
   mismatch between runtime-loaded verifier-policy state and the on-disk
   registry. The final cut reports both live file state and the currently loaded
   snapshot.
5. `spec/PROTOCOL.md` was still a long-form pre-RFC design document with
   schema claims and topology assumptions that no longer described the shipped
   repository profile.
6. The A2A adapter already had the operator-facing ingredients needed for
   observability: fail-closed partner/admission errors, explicit unsupported
   auth failures, lifecycle validation errors, and a durable task registry.
7. Release-facing docs still needed one production observability contract and a
   runbook update so operators would actually use the new health/admin surfaces.

## Chosen Cut

- `23-01`: define the supported observability contract and the exact runtime
  surfaces that belong in it
- `23-02`: implement trust-control and hosted-edge health reporting, document
  it, and prove it with targeted regressions
- `23-03`: replace the stale protocol draft with a shipped `v2` protocol and
  artifact contract
