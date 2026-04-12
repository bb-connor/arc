# Phase 173: Hosted Web3 Qualification Workflow and Artifact Publication - Context

**Gathered:** 2026-04-02
**Status:** Complete locally

<domain>
## Phase Boundary

Move ARC's bounded web3 qualification lane from local-only evidence into the
hosted `Release Qualification` workflow and publish a stable hosted artifact
bundle alongside the existing release corpus.

</domain>

<decisions>
## Implementation Decisions

### Hosted Workflow Wiring
- keep the repo-wide release qualification lane intact and add the web3 lane
  as a dedicated hosted step in `.github/workflows/release-qualification.yml`
- provision `pnpm` and install the contracts workspace dependencies explicitly
  in the hosted workflow instead of assuming they exist on the runner

### Stable Artifact Paths
- stage hosted web3 outputs into `target/release-qualification/web3-runtime/`
  so reviewers get one stable release artifact root
- include both generated outputs and copied web3 release-doc snapshots in the
  staged bundle
- generate an `artifact-manifest.json` file so hosted reviewers can tell which
  web3 evidence files were actually present for the run

### Release Gate Truth
- keep external publication blocked on observed hosted workflow results rather
  than implying they have already been seen locally
- update web3-facing release docs and the external qualification matrix so
  they point at the hosted artifact bundle path consistently

</decisions>

<code_context>
## Existing Code Insights

- the bounded web3 lane already existed as `./scripts/qualify-web3-runtime.sh`
  but the hosted release workflow never invoked it
- the hosted workflow also lacked explicit `pnpm` setup and contract
  dependency installation, so the web3 lane was not runnable there as written
- the existing artifact upload step only published `target/release-qualification/`,
  which meant hosted web3 outputs needed staging under that same root to give
  reviewers stable paths

</code_context>

<deferred>
## Deferred Ideas

- bounded live deployment runner and approval/rollback semantics in phase
  `174`
- generated runtime reports and exercisable emergency controls in phase `175`
- integrated hosted recovery and partner-ready end-to-end settlement proof in
  phase `176`

</deferred>
