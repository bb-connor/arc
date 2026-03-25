# Summary 23-02

Trust-control `/health` now reports authority, store, federation, and cluster
state in one additive payload, including live enterprise-provider,
verifier-policy, and certification summaries. Hosted remote MCP edges now
expose `/admin/health`, which surfaces runtime identity, auth mode, control
plane, store configuration, session counts, federation setup, and OAuth
metadata. The new health contract is covered by provider-admin, hosted-edge,
and certification regressions.
