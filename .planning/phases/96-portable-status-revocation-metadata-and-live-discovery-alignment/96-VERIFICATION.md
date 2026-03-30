# Phase 96 Verification

Phase 96 is complete locally.

## What Changed

- added explicit `stale` portable lifecycle state plus `updated_at` tracking
  for persisted and resolved passport lifecycle records
- required TTL-backed lifecycle distribution whenever ARC advertises a public
  lifecycle resolve URL
- removed remote lifecycle-response backfilling so incomplete or contradictory
  public lifecycle metadata fails closed
- updated portable lifecycle docs, protocol text, qualification commands, and
  partner or release boundary materials to describe stale-state behavior
  honestly

## Validation

Passed:

- `cargo fmt --all`
- `cargo test -p arc-credentials passport_lifecycle_validation_rejects_contradictory_fields -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_metadata_rejects_public_status_distribution_without_cache_ttl -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_lifecycle_stale_state_fails_closed_on_offer_and_public_resolution -- --nocapture`
- `cargo test -p arc-cli --test passport passport_portable_sd_jwt_status_reference_projects_active_superseded_and_revoked_states -- --nocapture`
- `cargo test -p arc-cli --test passport passport_issuance_remote_requires_published_status_and_exposes_public_resolution -- --nocapture`
- `git diff --check`

## Outcome

ARC's portable credential lane and hosted metadata lane now tell one consistent
story: public lifecycle discovery must advertise freshness bounds, stale
lifecycle truth is surfaced explicitly, and portable consumers do not silently
trust incomplete remote lifecycle metadata.
