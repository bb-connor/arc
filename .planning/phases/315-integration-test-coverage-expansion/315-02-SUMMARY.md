# Summary 315-02

`arc-credentials`, `arc-policy`, and `arc-store-sqlite` now each have
integration tests that cover a primary success path, a primary failure path,
and an exported-API edge case. The new coverage stays on public contracts:
passport issuance and presentation, HushSpec parse/validate/evaluate flows, and
SQLite authority, budget, and revocation behavior.
