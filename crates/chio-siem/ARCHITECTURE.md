# chio-siem Architecture

`chio-siem` is the SIEM export pipeline for Chio receipt audit logs. It reads kernel receipts through an explicit read boundary, wraps them as `SiemEvent` values, and fans them out to Splunk, Elasticsearch, Datadog, Sumo Logic, OCSF, CEF, webhook, alerting, and other exporter surfaces.

The manager owns polling configuration, cursor advancement, retry backoff, rate limiting, and dead-letter behavior. Invalid polling configuration must fail before the database is opened so a bad operator setting cannot start a hot loop or partial exporter.

`SiemEvent` keeps authorization semantics separate from raw receipt decisions. A receipt is exported as authorized only when its id, signature, parameter hash, and trusted kernel signer all verify.

## Trust Invariants

- SIEM polling requires explicit admin receipt read authority before opening the
  receipt database.
- Tenant-scoped read contexts are invalid for the manager because SIEM export
  is an operator-wide audit surface.
- Receipt authorization labels require verified id, signature, action parameter
  hash, and trusted kernel signer.
