# Phase 283 Context

## Goal

Wire coverage generation into CI with `cargo-tarpaulin`, emit reports under the
repo's `coverage/` directory, and set a floor from an actual measured run.

## Existing Surface

- the repo already has an empty top-level `coverage/` directory
- neither `.github/workflows/ci.yml` nor `scripts/ci-workspace.sh` invokes
  tarpaulin today
- `cargo-tarpaulin` is not installed locally, but Docker is available and the
  official tarpaulin images document Docker-based execution for CI and
  non-Linux development
- release qualification already stages artifact bundles under
  `target/release-qualification/`, which makes it a natural place to copy
  coverage outputs for later milestones

## Important Constraint

Tarpaulin tooling has to work both in hosted CI and from this local macOS
environment. The simplest cross-environment path is a repo-owned script that:

- uses a local `cargo tarpaulin` binary when present
- otherwise runs the official tarpaulin Docker image with `seccomp=unconfined`

## Execution Direction

- add a repo-owned coverage runner script that writes HTML, LCOV, and JSON
  outputs under `coverage/`
- wire a dedicated coverage job into `ci.yml`
- stage coverage into `target/release-qualification/coverage/` from
  `qualify-release.sh`
- run tarpaulin once after wiring to measure current coverage and set a floor
  from that observed value
