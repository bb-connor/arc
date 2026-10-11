# Committed Linux evidence verification

Committed Linux capture evidence is accepted only through the strict
repository-bound verifier. Signature verification alone is not a committed
evidence gate.

CI requires a configured, valid `CHIO_COMMITTED_LINUX_EVIDENCE_SHA`, distinct
from the authorized source commit, followed by successful strict verification.
An empty evidence variable fails even for the authorized source. There is no
bootstrap-success path. Updating local workflow source does not rotate the
separately trusted reusable-workflow pin or authorize a new execution image.
The required Actions aggregate also joins the reusable nonce and FIPS inventory;
main pull requests and main pushes reach it through CI, while manual runs,
project-branch pushes and non-main pull requests retain their direct coverage.

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

Candidate compilation uses the trusted runner's source projection. Before
materializing any source, the runner validates this closed namespace and omits
these three regular output blobs. They are absent from both the read-only source
mount and the candidate's isolated Git baseline. All other source blobs retain
their bytes and modes. A build script or procedural macro cannot consume the
publication outputs through a computed path in this execution context.

Direct mutation controls refuse a checkout containing this namespace before
executing candidate code. Use the isolated runner for an evidence-bearing
checkout. The strict committed-evidence verifier still authenticates the three
original committed files and their source policy outside candidate execution;
projection does not grant signature authority or delete those files. Mutation
evidence describes this projected execution, not arbitrary builds that expose
additional inputs to build scripts.

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

## Execution seccomp source policy

The trusted execution profile is derived from the byte-pinned
[Moby default profile](https://github.com/moby/profiles/blob/6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef/seccomp/default.json).
Its original JSON and Apache-2.0 license are committed beside the derived profile;
`security-evidence-seccomp-provenance.json` records their Git blobs, SHA-256
commitments and exact derivation. The runner independently reconstructs the
profile from the pinned upstream bytes, and the source checker commits the exact
derived bytes and provenance.

The policy defaults to ERRNO and grants only the Linux/X64 ABI. It removes every
prior explicit denial and every io_uring syscall from allow rules, preserves
upstream personality and socket argument restrictions, and permits clone only
when namespace mask `2114060416` equals zero. clone3 returns ENOSYS 38 so standard
thread creation can use its ordinary clone fallback. The container still drops
ALL capabilities and adds only CHOWN, SETGID and SETUID for supervisor setup.
Those capabilities activate no upstream conditional syscall allowance, and every
capability-dependent allowance is removed. Candidate identity drops and all
existing container mount, network, cgroup and output boundaries remain required.

The 367 named baseline-compatible allowances are a source policy, not a claim of
an operationally minimal or working syscall set. Acceptance requires genuine
native qualification on the designated Linux/X64 runner for supervisor startup,
helper handshake, Cargo/compiler/linker execution, exact tests, kernel probes,
mutation campaigns, artifact collection and cleanup. Preserve denied calls and
failed runs. Any extra permission requires explicit review of demonstrated
native need. ARM Docker, schema checks and simulated Docker tests do not satisfy
that gate.

## Authority queue syntax qualification

GitHub's [concurrency documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
and [2026-05-07 release note](https://github.blog/changelog/2026-05-07-github-actions-concurrency-groups-now-allow-larger-queues/)
define queue max with up to 100 pending jobs and cancel-in-progress false. Runs
beyond the limit can still be cancelled. Preserve the shared exact-M authority
lock and every authentic critical bad completion.

Some actionlint releases predate this field. `check-actions-workflow-syntax.py`
first verifies the exact publisher and revoker queue/group/non-cancellation
contracts, then omits only those two recognized queue lines from a temporary
lint input. Every remaining byte and generic lint failure is retained. Unknown
locations, duplicate members, weakened groups and different queue values fail.
The original unsupported-linter failure is separate evidence. Passing this
source syntax check does not establish acceptance of the candidate workflow by
the hosted GitHub runtime.

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
`ci.yml` run title to be exactly `CI N=<PR> E=<E> B=<base> M=<M_ci>`, where the
authenticated CI merge `M_ci` has ordered parents `<base>, E` and the sealed
tree `T`. It requires
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
signer at `B`, source commit `M_ci`, `refs/pull/<PR>/merge`, the exact caller run
and attempt, repository identities, and a GitHub-hosted runner. The canonical
predicate independently proves `M_ci` has ordered parents `<base>, E` and the
expected tree. After those checks and all committed evidence, controller,
capture, runner, artifact, and policy bindings verify, the publisher also
requires the protected migration-canary signing job to succeed before it
revalidates that `refs/heads/main` is still `<base>`, that the live test merge has
ordered parents `<base>, E` and tree `T`, and that no other pull request has head
`E`. A regenerated test merge with the same parents and tree changes nothing.
Duplicate-head refusal is detection, not per-pull-request enforcement.
It mints the dedicated App token
and posts only the dedicated authority context on evidence head `E`:

```text
name: Security contract
head_sha: E
status: completed
conclusion: success
external_id: chio:v3:<PR>:<E>:<K>
app.slug: chio-security-authority
```

Both CI authentication and each positive publication boundary read the open-PR
census and the PRs associated with `E`. Each census allows at most ten pages of
100 entries and validates every returned PR number and head SHA. Another PR
with head `E`, including a closed PR returned by the associated-PR endpoint,
refuses positive publication. Unreadable, malformed or truncated censuses also
refuse. Negative CI or authorizing-finalizer evidence retains its authenticated
E-scope denial path, independent of main currency and duplicate-head detection.

The candidate identity `I` is `chio.security-candidate-identity.v1` with exactly
nine ASCII string fields: `schema`, `repository`, `repository_id`, `pr_number`,
`base_sha`, `evidence_sha`, `merge_tree_sha`, `authorized_source_sha` and
`security_definition_sha`. `K` is SHA-256 of its canonical sorted compact JSON.
The publisher and auditor independently recompute `K` and bind every identity
field to the authorized candidate and retained landing. The captured and CI
merge SHAs are separate `merge_observations`, rather than identity fields.

The publication binding is `chio.security-check-publication.v2`. Its strict
`chio.security-check-authority.v3` text carries `I`, `K`, both merge observations,
the exact source CI attempt, four required original check IDs, the Actions
aggregate ID, and the CI binding artifact ID and archive/body digests. IDs alone
grant no authority: before every positive boundary the publisher re-reads the
exact source attempt, its complete unique job inventory and the repository-bound
check URLs, and authenticates each original check's name, E, success, Actions App
and exact check suite. Legacy `arc:` authority is `unverified`, and legacy binding
or check metadata schemas cannot qualify this v3 candidate.

The publisher rejects App ID `15368`, the wrong App slug, owner, installation,
repository inventory, permissions, source or evidence variable, workflow ref,
publication binding, payload head, and response attribution.

Publication is
idempotent for the candidate identity `I`. Any prior failure in the dedicated
App-and-name namespace is sticky; the publisher never creates a later
success in that namespace. Labels authorize and describe capture only. Label
changes after capture cannot grant, renew, or revoke a published authority.

Actions mirrors are not published. Any check run or commit status named
`Security mirror / ...` is outside authority: the publisher, revoker and auditor
never read or write it. The four ordinary CI contexts stay governed by
`main-required-checks` (22033486), and every original CI job and exact check-suite
verification remains mandatory. The workflow tokens used by the publisher and
revoker have read permissions only; only the dedicated App token writes authority.

A trusted default-branch `workflow_run` listener handles bad CI completions and
eligible failed finalizer publishers. Every completed CI conclusion other than
success, including an absent conclusion, is failure-authoritative. Both paths
bind the immutable `workflow_run.run_attempt` carried by the event, retrieve the
exact historical attempt endpoint, and require the returned run and attempt
identity to match. They never substitute the mutable current-run projection.
The listener never trusts nested workflow-run pull request metadata. It binds
the immutable event attempt, repository and head repository IDs, trusted workflow
path and API head `E`, and proves the authorized `ci.yml` blob at `S` and `E`.
The run title is classification, never authentication. When the title is valid
and an exact artifact is available, its binding and certificate are verified;
startup failures without jobs and malformed titles cannot erase an authenticated
negative. When `CHIO_COMMITTED_LINUX_EVIDENCE_SHA=E`, it creates a denial-only
tombstone even for a closed pull request, unless that PR merged with head `E`.
A non-committed `E` is existing-only. No main, live test-merge or pull-request
state predicate gates a denial. N and M remain recorded observations.
Under the shared non-cancelling
`security-check-authority-<E>` lock, it proves every affected namespace is a
singleton completed failure while preserving existing external IDs and source
metadata. For a failed finalizer, it authenticates the exact `N/E/M/S/nonce`
title, historical default-branch workflow blob, bot actors, exact four-job
attempt, capture-owned dispatch intent and recorded v3 candidate identity. Validation,
signing, and publication authorization must have completed successfully, while
the publication job must have started and completed unsuccessfully. The exact
dedicated App success check must carry a `details_url` bound to that failed run
and attempt. Earlier finalizer failures are ineligible because they cannot have
published dedicated authority. Later source or definition rotation does not
erase the authenticated historical failure. The listener can normalize only
preexisting exact authority created by that failed attempt and cannot create a
namespace.

A failed retry of an already authorizing finalizer run retains the binding from
that run's immutable successful first attempt. The listener proves the original
four successful jobs and capture-owned intent, then authenticates the existing
dedicated App check's exact external ID, first-attempt details URL, v3 metadata,
source CI attempt, and identical `ci.yml` blobs at `S` and `E`. A later
attempt cannot create authority or restore a failure. The publisher scans every
attempt of this recorded authorizing run before each success boundary and uses
only failure PATCH operations on the existing dedicated namespace when it finds an
authenticated bad completion. A failed sibling without that App binding is
ineligible; its title alone grants no withdrawal authority. The current initial
publisher may finish while its own first attempt is in progress, after proving
all three protected predecessor jobs succeeded and no rerun has started.

The protected-merge auditor reads every attempt of the recorded authorizing run,
reports the successful history, and rechecks its stable current projection. At
the final audit boundary it rechecks that the protected merge remains reachable
from `main`. Legitimate descendants preserve the result; withdrawal of that
merge rejects qualification.

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

The protected manual revoker requires the all-zero freeze and authenticates the
commit `E`; N and M are recorded evidence. It mints the same
Checks-write-only App token.
It paginates the dedicated-App `Security contract` namespace on `E`. An
absent eligible namespace receives an exact completed-failure tombstone with
external ID `chio:v3:deny:<E>` and `chio.security-check-revocation.v2` metadata. Existing
members are updated to `conclusion: failure` while preserving each external ID
and source metadata. If duplicates exist, the oldest member remains under the
protected name regardless of its candidate identity, and every other member
is renamed to a unique failure-only superseded name. The revoker then re-queries
and requires one exact failed member per namespace. The create identity is
required only for a newly created tombstone. This
normalization is mandatory because a ruleset binds check name and App, not
external ID. Third,
withdraw or replace the affected source, policy, App, installation, key,
environment, or ruleset authority. A repeated revocation is idempotent. Never
restore authority for the same evidence head `E`. Produce a new reviewed
evidence head before publishing a new candidate identity.

Publication and revocation use the same non-cancelling maximum-queue
`security-check-authority-<E>` concurrency group. Both jobs set `queue: max`,
so a later authority mutation cannot replace an earlier pending member.
Publication rejects any
existing failed or duplicate namespace member. Its success-publication branch
is POST-only and never updates an existing check. The protected job is an
authority reconciler: before every success POST, immediately after every
success POST, and after the complete set, it paginates the complete CI history
of the evidence head: every `ci.yml` `pull_request` run whose API head is `E`,
for any pull request, base, test merge, or run title. A run title is never
authentication and never removes a run from this history. A run is outside it
only when it is a trusted-workflow `pull_request` run of this repository for `E`
whose head repository has a numeric ID and a well-formed name that both differ
from this repository: such a run is never positive
evidence and never tombstones `E`.
A head repository name alone never removes a run from this history.
A listed run without a proven
same-repository head and repository identity, the trusted workflow ID and path,
the `pull_request` event, and API head `E` leaves the history incomplete.
For every matching run it reads the current
maximum attempt, retrieves exact historical attempts within the first100, and
fails closed before GitHub's 1,000-result filtered-search ceiling.
It never falls back to an unfiltered listing.
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
external IDs and source metadata. It normalizes only the dedicated-App
`Security contract` namespace. A current unmerged E permits a missing denial
tombstone; a merged same-head PR or non-current E is existing-only.
Every serialized ordering converges to a failed
authority tombstone that publication cannot
restore. This is deliberately conservative: any completed non-success CI
completion for the current `E`, under any pull request, base, test merge, or run
title, can permanently tombstone that tuple even when a later rerun succeeds.
Recovery requires a new reviewed evidence head `E`.

Required CI does not subscribe to label-removal events. Its caller and reusable
enterprise and nonce/FIPS lanes isolate concurrency by run ID and attempt and do
not cancel another critical run. The process-isolated nextest lane is reported by
`Security nextest advisory`, outside the CI workflow. Its failures remain visible
with their original conclusion and JUnit artifact; they do not publish or revoke
security authority. Every critical CI dependency and exact-success assertion
remains mandatory. A cancelled critical run remains failure-authoritative for
its evidence head, so the publisher refuses every later tuple on the same `E`.
The listener's writes for an obsolete tuple still reach only its evidence head `E`,
subject to the existing no-create rule.

P5 denies authenticated E without main or live-merge predicates at any write
boundary. H reads both workflow and repository CI inventories, requires every
workflow-listed ID to appear in the repository path-`ci.yml` census, and scans
the repository census across registration changes. A retired workflow's success
cannot supply positive authority; its authenticated non-success remains sticky.
API errors or incomplete identities beside an authenticated bad attempt preserve
the denial; without a bad attempt, incomplete history refuses publication.
The maximum is100 exact attempts per run. An over-limit history cannot grant,
while an authenticated negative within that window still denies E. Close and
reopen cannot erase same-E history. The auditor re-lists both inventories and
rechecks the retained maximum attempts. These source changes do not establish
hosted qualification or dedicated-App H2 acceptance.

The post-merge audit first requires every attempt of every `ci.yml`
`pull_request` run whose API head is `E`, for any pull request, base, test merge,
or run title, to have completed successfully, and each run's listed and current
projections to agree with its latest successful attempt.
A run whose head is another
repository is outside this history only when that identity is complete and
distinct; any other run without a proven same-repository identity leaves the
landing unverified. Only then does a run title select the positive source. The
audit reads the singleton dedicated App-and-name qualification on `E`, authenticates
its strict v3 `I` and recomputed `K`, and binds the exact CI and finalizer attempts.
The retained protected merge's ordered parents and tree must equal `I.base_sha`,
`E` and `I.merge_tree_sha`; historical `M_ci` must retain those parents and tree.
It verifies the four original CI checks plus the Actions aggregate through the
exact source attempt's jobs: job name, run/head, successful
completion, repository-bound check URL, original check ID/name/head, Actions App
ID and slug, and the exact source check-suite ID/head must agree. Those inventory
IDs must equal the sealed v3 IDs. The recorded binding artifact must be unexpired,
owned by the exact CI run and E, and match its API and downloaded SHA-256 digests.
API and ZIP reads stop at 16 MiB with a 30-second deadline; the unique regular,
unencrypted `ci-merge-binding.json` member is bounded to 64 KiB and its body digest
and duplicate-aware JSON tuple must match `M_ci`, N, base, E, tree and exact CI
attempt. The auditor relies on the App-authenticated historical finalizer's
signature verification and does not repeat Sigstore verification. Its authority
stability re-list includes only the dedicated check; unrelated checks and commit
statuses cannot supply or revoke authority. It then proves the actual main
merge has ordered parents `<base>, E` and the sealed tree `T`. It requires identical
`ci.yml` blobs at S, E and the retained landing L. It does not expect
mirror checks on the new main merge commit, and an ordinary Actions aggregate
named `Security contract` cannot substitute for dedicated-App authority. The
auditor runs from the authorized trusted definition. A failed audit is an
unverified landing diagnosis; administrator bypass attribution requires separate
external evidence. Manual audit dispatch requires an explicit merged PR number.

The associated-PR signal `commits/L/pulls` must contain the audited PR and no
other PR recorded as merged by L. The output labels this attribution as observed,
not enforcement. An unavailable or expired retained artifact yields `unverified`.

The 2026-10-08 scratch Actions transport observations refused X on M and accepted
X on E. They do not qualify the dedicated App Y or the proposed ruleset. Y on E
still requires H2 acceptance through an actual protected `PUT pulls/N/merge`, a
main transition and retained rule suites. UI state cannot establish that result.
Per-PR enforcement remains a separate acceptance obligation.
See [GitHub required-check troubleshooting](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks).

The last observed production ruleset (`main-required-checks`, ID `22033486`,
2026-10-06) required the four ordinary CI contexts, used non-strict status checks,
and had no linear-history requirement or bypass actors. The repository permitted
merge, squash and rebase. Refresh this external state before acting. The payload
below is the proposed strict authority ruleset, not a claim of current activation.
It allows only a merge commit and omits linear history so exact `E` and both
histories remain reachable. Independent exact-source review is still a separate
landing requirement; the payload does not assert that CODEOWNERS approval is
currently enforced.

Before adoption, land and review the complete trusted-definition prerequisite on
main, rotate its immutable definition and caller pins together, and run the real
dedicated-App-context required-check acceptance experiment. Candidate-only changes do
not replace a default-branch `workflow_run` listener. Require the exact dedicated
App-bound context on current `E`, verify the ruleset reports their integration
IDs and strict policy with no bypass actors, and retain the protected merge's
parents and tree as acceptance evidence. Keep missing, pending, failed and
unavailable observations explicit. Do not disable a required context to land.

Apply a branch ruleset with no bypass actors. Replace only the numeric
`CHIO_SECURITY_APP_ID` shell value below with the live App ID; do not use
`15368` for it. The payload pins the authority check to the dedicated App. The dedicated
context is on `E`; the source CI
workflow run and its four original job Check Runs are authenticated on `E`.
The original CI requirements remain in `main-required-checks` (22033486).
The v3 identity and head placement are source changes. Per-PR enforcement and
dedicated-App H2 acceptance remain separate F077 obligations; this payload is not
a live settings change:

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
    {
      type: "pull_request",
      parameters: {
        allowed_merge_methods: ["merge"],
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
