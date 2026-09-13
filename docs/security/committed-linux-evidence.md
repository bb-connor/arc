# Committed Linux evidence verification

Committed Linux capture evidence is accepted only through the strict
repository-bound verifier. Signature verification alone is not a committed
evidence gate.

The default-branch control plane and repository variables supply every
expectation independently of the candidate tree:

- the SHA-256 of the trusted `chio-enterprise-evidence` verifier binary
- the pinned Ed25519 runner public key
- the source commit and evidence-only descendant commit
- the canary generation window
- the exact runner name, operating system, architecture, and labels digest
- the configuration, schema inventory, and complete canary binding digests
- the exact seven gate-result digests

The evidence commit may descend from the source commit only through a linear
sequence that changes these three `100644` blobs:

```text
audits/evidence/enterprise-linux/enterprise-migration-canary.json
audits/evidence/enterprise-linux/enterprise-migration-canary.json.sha256
audits/evidence/enterprise-linux/enterprise-migration-binding-digest.txt
```

No private signing seed belongs in the repository, an uploaded evidence
bundle, verifier arguments, or any candidate execution context. The seed is
present only in the protected finalizer's single signing step environment and
is removed by its cleanup trap before upload. The
finalizer signs the canonical canary with a separately published verifier whose
HTTPS release URL and SHA-256 are repository variables. It fails before the
secret-bearing step if the verifier is missing or does not match the pin, then
publishes only the three secret-free files above.

The controller, capture, finalizer, revocation, and reusable enterprise
workflow must first land together on `main` at reviewed definition commit `B`.
Before dispatching any of them, set
`CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA=B`. The controller, capture,
finalizer, publisher, and revoker treat `B` as the authorized workflow-content
baseline. Each authenticates its actual execution head from the Actions run API
and requires the workflow blob at that head to equal the blob at `B`. An
unrelated `main` advance can therefore run the unchanged authority definitions,
but changed workflow bytes fail closed. The `ci.yml` caller must separately pin
the reusable workflow to the same immutable full `B` SHA. Update the reusable
pin and definition variable as one authority rotation only after a new complete
workflow set has been reviewed. Configure
`CHIO_AUTHORIZED_SECURITY_SOURCE_SHA`,
`CHIO_ENTERPRISE_CANARY_SIGNER_PUBLIC_KEY`,
`CHIO_ENTERPRISE_EVIDENCE_VERIFIER_URL`, and
`CHIO_ENTERPRISE_EVIDENCE_VERIFIER_SHA256` as repository variables. Also set
`CHIO_SECURITY_APP_ID` as a repository variable. The App ID is public,
repository-scoped configuration required by the unprotected secret-free
revocation listener as well as the protected publisher. The protected
finalizer publishes the exact canonical value to set as
`CHIO_ENTERPRISE_EVIDENCE_POLICY_JSON`. After committing the exact three files,
set `CHIO_COMMITTED_LINUX_EVIDENCE_SHA` to that detached evidence commit.
Configure `CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX` only as a secret in the
protected `enterprise-evidence-signing` environment. The introducing pull
request cannot establish these default-branch and environment trust roots by
itself.

## Protected signing environment

Create `enterprise-evidence-signing` with a zero-minute wait, no reviewers,
and a custom deployment branch policy containing only `main`:

```bash
jq -n '{
  wait_timer: 0,
  prevent_self_review: false,
  reviewers: [],
  deployment_branch_policy: {
    protected_branches: false,
    custom_branch_policies: true
  }
}' | gh api \
  --method PUT \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/bb-connor/arc/environments/enterprise-evidence-signing \
  --input -

gh api \
  --method POST \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/bb-connor/arc/environments/enterprise-evidence-signing/deployment-branch-policies \
  -f name=main \
  -f type=branch
```

Disable administrator bypass for `enterprise-evidence-signing` in the
repository UI. Set only the environment secret
`CHIO_ENTERPRISE_CANARY_SIGNING_SEED_HEX`. Do not create a repository or
organization copy of the signing seed. A pull-request workflow must never be
eligible to enter this environment.

## Dedicated security check publisher

Create a private GitHub App named `chio-security-authority`. Install it only on
`bb-connor/arc` and grant exactly Metadata read, Checks read and write, and
Commit statuses read and write. GitHub requires `statuses:write` for an App to
be selected as the expected source of an integration-bound ruleset check. The
publisher narrows its short-lived installation token to Checks write only, so
the runtime credential cannot create a legacy commit status. The App needs no
Contents, Actions, Pull requests,
Administration, or Secrets permission. The ordinary `GITHUB_TOKEN` belongs to
the GitHub Actions App with integration ID `15368`; it is not this authority.

Create the `security-check-publisher` environment with a zero-minute wait, no
reviewers, and a custom deployment branch policy containing only `main`:

```bash
jq -n '{
  wait_timer: 0,
  prevent_self_review: false,
  reviewers: [],
  deployment_branch_policy: {
    protected_branches: false,
    custom_branch_policies: true
  }
}' | gh api \
  --method PUT \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/bb-connor/arc/environments/security-check-publisher \
  --input -

gh api \
  --method POST \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/bb-connor/arc/environments/security-check-publisher/deployment-branch-policies \
  -f name=main \
  -f type=branch
```

Disable administrator bypass for `security-check-publisher` in the repository
UI. Set only the environment variable `CHIO_SECURITY_APP_INSTALLATION_ID` and
the environment secret `CHIO_SECURITY_APP_PRIVATE_KEY_PEM`. Keep
`CHIO_SECURITY_APP_ID` at repository scope and do not shadow it with an
environment variable. Do not create a repository or organization copy of the
installation ID or private-key secret.

The finalizer's secret-free publication-authorizer requires
`CHIO_COMMITTED_LINUX_EVIDENCE_SHA` to equal the live pull-request head `E`.
It runs the strict checker from authorized source `S` against `E`, requires the
`ci.yml` run title to be exactly `CI N=<PR> E=<E> B=<base> M=<M>`, and requires
that run, its exact attempt, and these five GitHub Actions App `15368` jobs on
`E` to finish successfully:

```text
Build, lint, test
MSRV build and test
cargo-vet (locked supply-chain audit)
cargo-deny (supply-chain bans/advisories/licenses)
Security contract
```

The fifth entry above is the intermediate Actions aggregate. It is a publication
prerequisite, not a ruleset authority. The authorizer separately downloads the
singleton `ci-merge-binding-<run>-<attempt>` artifact, verifies its API digest
and bounded exact archive, and verifies the included GitHub attestation with a
SHA-256-pinned GitHub CLI 2.96.0 binary. The certificate must bind the reusable
signer at `B`, source commit `M`, `refs/pull/<PR>/merge`, the exact caller run
and attempt, repository identities, and a GitHub-hosted runner. The canonical
predicate independently proves `M` has ordered parents `<base>, E` and the
expected tree. After those checks and all committed evidence, controller,
capture, runner, artifact, and policy bindings verify, the publisher also
requires the protected migration-canary signing job to succeed before it
revalidates the exact current test merge `M`. It creates four
GitHub Actions App `15368` mirrors on `M`, one for each ordinary check, then
mints the dedicated App token and posts the fifth authority context on `M`:

```text
name: Security contract
head_sha: M
status: completed
conclusion: success
external_id: arc:<PR>:<E>:<M>:<S>
app.slug: chio-security-authority
```

The publisher rejects App ID `15368`, the wrong App slug, owner, installation,
repository inventory, permissions, source or evidence variable, workflow ref,
publication binding, payload head, and response attribution.

Each mirror uses the same identity plus an exact context suffix. Publication is
idempotent for `(<PR>, <E>, <M>, <S>)`. Any prior failure in any of the five
exact App-and-name namespaces is sticky; the publisher never creates a later
success in that namespace. Labels authorize and describe capture only. Label
changes after capture cannot grant, renew, or revoke a published authority.

A trusted default-branch `workflow_run` listener handles bad CI completions and
eligible failed finalizer publishers. Every completed CI conclusion other than
success, including an absent conclusion, is failure-authoritative. Both paths
bind the immutable `workflow_run.run_attempt` carried by the event, retrieve the
exact historical attempt endpoint, and require the returned run and attempt
identity to match. They never substitute the mutable current-run projection.
The listener never trusts nested workflow-run pull request metadata. For CI, it
parses the exact `N/E/base/M` run title, authenticates the run head as `E`,
proves the authorized `ci.yml` blob at `S`, `E`, and `M`,
proves the ordered parents and tree of `M` directly, and verifies the signed
binding artifact and certificate whenever the builder succeeded. If the live
pull request still has the same base, head, and explicit merge ref, it requires
`CHIO_COMMITTED_LINUX_EVIDENCE_SHA=E` and may create missing tombstones. If the
pull request advanced from `(base1, M1)` to `(base2, M2)`, it targets only `M1`,
may normalize preexisting authority there, cannot create a missing namespace,
and never writes to `M2`. Under the shared non-cancelling
`security-check-authority-<M>` lock, it proves every affected namespace is a
singleton completed failure while preserving existing external IDs and source
metadata. For a failed finalizer, it authenticates the exact `N/E/M/S/nonce`
title, historical default-branch workflow blob, bot actors, ordered merge
parents, exact four-job attempt, and capture-owned dispatch intent. Validation,
signing, and publication authorization must have completed successfully, while
the publication job must have started and completed unsuccessfully. The exact
dedicated App success check must carry a `details_url` bound to that failed run
and attempt. Earlier finalizer failures are ineligible because they cannot have
published dedicated authority. Later source or definition rotation does not
erase the authenticated historical failure. The listener can normalize only
preexisting exact authority created by that failed attempt and cannot create a
namespace.

Withdrawal is a three-step fail-closed operation. First, freeze every future
publication by setting `CHIO_COMMITTED_LINUX_EVIDENCE_SHA` to the reserved
all-zero SHA. Keep the App, installation, publisher environment, and private
key available until revocation verifies:

```bash
gh variable set CHIO_COMMITTED_LINUX_EVIDENCE_SHA \
  --body '0000000000000000000000000000000000000000'
```

Second, dispatch only the default-branch `Security contract revocation`
workflow as the repository owner:

```bash
gh workflow run security-contract-revocation.yml \
  --ref main \
  -f authorized_source_sha='<S>' \
  -f evidence_sha='<E>' \
  -f merge_commit_sha='<M>' \
  -f pr_number='<PR>' \
  -f reason='policy-authority-withdrawn'
```

The protected manual revoker requires the all-zero freeze, revalidates the
requested live `(<PR>, <E>, <M>, <S>)` tuple, and mints the same
Checks-write-only App token. It paginates the four App `15368` mirror
namespaces and the dedicated-App `Security contract` namespace on `M`. An
absent namespace receives an exact completed-failure tombstone. Existing
members are updated to `conclusion: failure` while preserving each external ID
and source metadata. If duplicates exist, the oldest member carrying the
required external ID remains under the protected name and every other member
is renamed to a unique failure-only superseded name. The revoker then re-queries
and requires one exact failed member per namespace. A missing required external
ID fails closed. This
normalization is mandatory because a ruleset binds check name and App, not
external ID. Third,
withdraw or replace the affected source, policy, App, installation, key,
environment, or ruleset authority. A repeated revocation is idempotent. Never
restore authority for the same test merge. Produce a new reviewed source,
evidence commit, or merge commit, then publish a new tuple.

Publication and revocation use the same non-cancelling maximum-queue
`security-check-authority-<M>` concurrency group. Both jobs set `queue: max`,
so a later authority mutation cannot replace an earlier pending member.
Publication rejects any
existing failed or duplicate namespace member. Its success-publication branch
is POST-only and never updates an existing check. The protected job is an
authority reconciler: before every success POST, immediately after every
success POST, and after the complete set, it paginates authenticated CI run
identities for the current PR/E/M. For every matching run it reads the current
maximum attempt, retrieves every exact historical attempt from one through that
maximum, and fails closed before GitHub's 1,000-result filtered-search ceiling.
A completed non-success attempt dominates any newer incomplete attempt and
immediately selects the failure-only branch. An incomplete history blocks
publication when no bad completion exists. It requires the maximum
attempt fingerprint to agree between the current projection before the scan,
the exact historical endpoint, and the current projection after the scan. It
then re-lists the matching run IDs and revalidates every recorded maximum. The
whole scan retries at most three times and fails closed if a run appears or any
maximum advances. If any completed non-success attempt exists, including an
earlier failure followed by a successful rerun,
its separate late-CI branch creates missing failure tombstones or
updates existing members only toward completed failure while preserving
external IDs and source metadata. After PR or merge-ref drift, the
publisher branch may normalize existing authority on historical `M` but cannot
create a missing namespace. Every serialized ordering converges to a failed
authority tombstone that publication cannot
restore. This is deliberately conservative: any completed non-success CI
completion for the current `E` and `M` can permanently tombstone
that tuple even when a later rerun succeeds. Recovery requires a new reviewed
source, evidence, or test merge tuple.

Apply a branch ruleset with no bypass actors. Replace only the numeric
`CHIO_SECURITY_APP_ID` shell value below with the live App ID; do not use
`15368` for it. The payload pins the four trusted merge-check mirrors to GitHub
Actions and pins only the authority check to the dedicated App. These are the
exact five contexts on `M`; the source CI workflow run is bound to `E`, while
its original job Check Runs are authenticated on `E` but remain evidence
inputs rather than merge-authority contexts:

```bash
test "${CHIO_SECURITY_APP_ID:?set the dedicated App ID}" -gt 0
test "${CHIO_SECURITY_APP_ID}" != 15368

jq -n --argjson security_app_id "${CHIO_SECURITY_APP_ID}" '{
  name: "main-security-contract",
  target: "branch",
  enforcement: "active",
  bypass_actors: [],
  conditions: {
    ref_name: {
      exclude: [],
      include: ["refs/heads/main"]
    }
  },
  rules: [
    {type: "deletion"},
    {type: "non_fast_forward"},
    {type: "required_linear_history"},
    {
      type: "pull_request",
      parameters: {
        allowed_merge_methods: ["squash", "rebase"],
        dismiss_stale_reviews_on_push: false,
        require_code_owner_review: false,
        require_last_push_approval: false,
        required_approving_review_count: 0,
        required_review_thread_resolution: true
      }
    },
    {
      type: "required_status_checks",
      parameters: {
        do_not_enforce_on_create: false,
        strict_required_status_checks_policy: true,
        required_status_checks: [
          {context: "Security mirror / Build, lint, test", integration_id: 15368},
          {context: "Security mirror / MSRV build and test", integration_id: 15368},
          {context: "Security mirror / cargo-vet (locked supply-chain audit)", integration_id: 15368},
          {context: "Security mirror / cargo-deny (supply-chain bans/advisories/licenses)", integration_id: 15368},
          {context: "Security contract", integration_id: $security_app_id}
        ]
      }
    }
  ]
}' | gh api \
  --method POST \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/bb-connor/arc/rulesets \
  --input -
```

Workflow files do not create or enforce the App, installation, environment,
secret placement, admin-bypass setting, or ruleset. Publication is not a merge
authority until every external item above is configured and the ruleset's
`Security contract` entry reports the dedicated App integration ID.

The committed-evidence SHA must remain fetchable without rewriting its
identity. Squash or rebase of the evidence commit changes its SHA and invalidates
the configured gate; deleting its only ref can eventually make the object
unavailable. Preserve the exact evidence commit with a merge strategy and
retained branch or tag that keep the configured SHA reachable.

The committed gate invokes only:

```bash
/usr/bin/python3 authorized-checker/scripts/check-committed-linux-evidence.py \
  --root committed-evidence \
  --verifier "$TRUSTED_ENTERPRISE_EVIDENCE_VERIFIER" \
  --verifier-sha256 "$PINNED_VERIFIER_SHA256" \
  --source-commit "$EVIDENCE_SOURCE_COMMIT" \
  --evidence-commit "$EVIDENCE_COMMIT" \
  --runner-public-key "$PINNED_RUNNER_PUBLIC_KEY" \
  --expected-runner-name "$EXPECTED_RUNNER_NAME" \
  --expected-runner-os Linux \
  --expected-runner-arch X64 \
  --expected-runner-labels-digest "$EXPECTED_RUNNER_LABELS_DIGEST" \
  --expected-configuration-digest "$EXPECTED_CONFIGURATION_DIGEST" \
  --expected-inventory-digest "$EXPECTED_INVENTORY_DIGEST" \
  --expected-runner-contract-digest "$EXPECTED_RUNNER_CONTRACT_DIGEST" \
  --expected-key-log-transparency-digest "$EXPECTED_KEY_LOG_DIGEST" \
  --expected-broker-boundary-digest "$EXPECTED_BROKER_DIGEST" \
  --expected-cage-enforcement-digest "$EXPECTED_CAGE_DIGEST" \
  --expected-committed-adversarial-evidence-digest "$EXPECTED_COMMITTED_ADVERSARIAL_DIGEST" \
  --expected-linux-adversarial-controls-digest "$EXPECTED_LINUX_CONTROLS_DIGEST" \
  --expected-migration-state-store-digest "$EXPECTED_MIGRATION_STORE_DIGEST" \
  --expected-binding-digest "$EXPECTED_BINDING_DIGEST" \
  --generated-at-not-before-unix-ms "$CANARY_NOT_BEFORE_UNIX_MS" \
  --generated-at-not-after-unix-ms "$CANARY_NOT_AFTER_UNIX_MS"
```

The required reusable lane obtains this checker from the exact
`CHIO_AUTHORIZED_SECURITY_SOURCE_SHA` checkout and runs it in a fresh job; it
does not invoke checker bytes from the current candidate tree. The checker
rejects a non-linear descendant, any path outside the three-file
surface, a missing or extra entry, a non-data tree mode, a dirty checkout,
verifier substitution, a noncanonical or corrupt canary, a stale generation or
source commit, runner or digest rebinding, and public-key substitution.
