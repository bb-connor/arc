# Funded W0 work from retained custody

Date: 2026-09-14. Implementation commit:
`028347541e4d480b0deed01f4017fa2a12f6b02f`, on
`research/funded-work-baseline` in `/home/connor/backbay/arc-funded-work`.
The [execution manifest](09-w0-results.json) records source hashes, commands,
public artifacts, expected failures and the refreshed native integration gate.

This experiment now pays for an actual checked work artifact. The provider
runs the existing Rust OpenAPI declaration checker; the verifier retrieves its
exact input/output from local SQLite custody and independently recomputes the
predicate in Python. Joint signed terms, the provider's signed submission,
custody receipt and verifier decision bind that result to one funded allocation.
The canonical decision digest is authorized through the existing EIP-712
contract domain. A contract-only synthetic certification no longer supplies
acceptance in these four scenarios.

This is the independent artifact/custody subset of the
[vertical-slice plan](../../../superpowers/plans/2026-09-14-funded-work-claim-escrow.md).
It is not the native funded-work vertical slice: native admission, Finding
assurance, financial crash reconciliation and a qualified Security M4 integration
remain required. All agents, verifier keys, custody and the private chain share
one host. No public-chain finality or independent company operation is claimed.

## What changed

- [Artifact boundary](../../../../examples/funded-work/artifacts.py): exact signed
  agreement/submission/decision grammars, RFC 8785, local key pins, canonical
  monetary strings, bounded parsing and malformed vectors. Unsupported native
  assurance is denied. These are example-local profiles pending registry/SDK
  integration, not additions to existing Finding guarantees.
- [Custody](../../../../examples/funded-work/custody.py): FULL-synchronous SQLite
  transactions, content-addressed bytes, owner/mode/path checks, immutable claim
  and decision bindings, and reopen/readback. Limits of 64 claims and 16 MiB
  deny new evidence without erasing old authority. There is no deletion API,
  remote service or rollback-protection claim.
- [Verifier](../../../../examples/funded-work/verifier.py): checks joint authority,
  exact retained evidence, pinned checker source, actual Python predicate and
  trusted private-chain observations before releasing a financial authorization.
  Incorrect output rejects; missing/invalid authority, custody or checker inputs
  produce no decision.
- [Private-chain reproduction](../../../../contracts/scripts/work-claim-w0.mjs):
  actual Rust output, reopened Python verification, canonical-digest EIP-712
  authorization, direct token balance/event accounting and retained public
  evidence. Existing escrow code and semantics are unchanged.

The [profile](../../../../examples/funded-work/PROFILE.md) spells out every field,
which objects each SHA-256 covers, the separate EVM domain, and trust limits.
The [operator README](../../../../examples/funded-work/README.md) gives standalone
commands. The added Rust command invokes the existing checker with a bounded
file read; it does not fabricate a kernel receipt or native admission.

## Observed financial outcomes

Every case starts with A=1000, B=1000, C=0 mock-token units. The child allocation
is separately funded by B. Values below come from actual contract state and
ERC20 events, checked against direct balances.

| Case and retained evidence | Deposited | Paid | Refunded | Remaining locked | Final A / B / C |
| --- | ---: | ---: | ---: | ---: | --- |
| [Correct W0 result](w0-evidence/accepted.json) | 100 | 100 | 0 | 0 | 900 / 1100 / 0 |
| [Incorrect authentication observation](w0-evidence/rejected.json) | 100 | 0 | 100 | 0 | 1000 / 1000 / 0 |
| [Custody unavailable at verification](w0-evidence/missing-custody.json) | 100 | 0 | 100 | 0 | 1000 / 1000 / 0 |
| [Earned child, then parent refund](w0-evidence/child.json) | 160 | 60 | 100 | 0 | 1000 / 940 / 60 |

The child is `Payable` and C still has zero when the parent refunds. C withdraws
60 after all deadlines, without further parent action. B bears that 60-unit
loss. The parent never submits; no native parent process was killed. This tests
the earned-claim financial property with real child work, not native crash
recovery or an aggregate company solvency claim.

The unavailable case temporarily makes the custody store inaccessible, receives
no certificate, restores the original store and waits for the contract timeout.
Timeout is distinct from checker rejection. Neither case rewrites an uncertain
execution as known. No native unknown-execution record is created in this fixture.

## Checks and negative controls

| Check | Fresh result |
| --- | --- |
| New Python artifact/custody/CLI suite | 23 passed, zero skips |
| Existing Python buyer suite | 30 passed |
| Standalone federated Rust suite | 11 passed |
| Standalone Rust build, all-target Clippy, formatting | Passed |
| Claim contract, all 118 model trace representatives, four W0 integrations | 141 Node checks passed |
| Existing escrow characterization | 6 Node checks passed |
| Combined selected Node coverage | 147 passed, zero failures/skips |
| Standalone child command, separate from tests | Exit 0; 160 deposited, 60 paid, 100 refunded |
| Standalone custody reopened after process exit | Exact input, output, submission and decision retrieved; signatures verified |
| Deliberately bypassed checker predicate | Expected exit 1: false output was incorrectly accepted |
| Original research checkout preservation | All 3,688 snapshotted files and modes, HEAD, branch and status unchanged |

Review reproduced an identity defect in the first child fixture: its EVM payer
was B, but the artifact buyer still reused A's key. A failing regression now
requires the parent provider's Ed25519 key to be the child buyer key and a
separate C key to sign the child output. Final integration passes that check.
Authority substitution, conflicting submissions, missing/tampered custody,
unsafe file modes, retention exhaustion and monetary/domain mutations have
focused denial checks. The model replay and old contract negative controls
retain their prior scope; they do not model artifact correctness or custody.

The standalone child's private custody remains at
`/tmp/chio-w0-execution/retained-child`; only its
[public result](w0-evidence/standalone-child.json) is committed. Test runs delete
throwaway state. Neither an immediate reopen nor a signed retention promise
proves 30 days of availability. Public input/output and signed evidence are
also retained with this report. Generated private keys were checked against
public evidence and are absent.

## Costs and limits

The observed provider process times are about 15-27 ms; successful verifier
measurements are about 16-17 ms. Provider timing includes Rust process startup;
verifier timing excludes Python startup and initial fixture-key loading. These
are single-run diagnostics under shared host load, not comparable benchmark
samples or a claimed verification advantage.

Recorded work-path gas is 525653 for acceptance, 505955 for rejection, 430987 for
custody timeout and 891525 for parent plus child. Receipts retain gas prices and
usage. These totals exclude deployment, minting, allowlisting and approval setup.
The selected token is a mock; verifier/dispute fees and bond remain zero.
No margin, real payment finality or live-funds deployment is established.

The new artifact-only profile makes no promise about native receipt facets,
revocation, confinement, market admission, payer mandate authorization, challenge
standing, remote custody access control or sustained trial capacity. The contract
still trusts its pinned verifier. A dishonest verifier can certify a false
result, and a host administrator can erase local custody. Existing transport,
Finding and kernel guarantees must be explicitly qualified when integrated.

## Integration decision and next work

The read-only refresh sees Security M4 at
`6bb648b613b44ff5aaf1853768f2747bff166077`, with a clean worktree. Draft
[PR #1117](https://github.com/bb-connor/arc/pull/1117) remains open and blocked;
its acceptance report explicitly says M4 cannot close on current evidence.
No security code, merge, schema migration or integration worktree was changed.
See the [gate record](06-native-integration.md).

Next select the qualified M4 checkpoint, map the divergent store/schema lineage,
then connect one finalized allocation to one native admission and its original
financial hold. Qualify success, rejection, unknown-payment recovery and actual
parent process loss without re-admission or a second payment. Keep the current
artifact-only profile distinct until the required native Finding/custody facets
are verified. W1, independent implementation/operators and the matched economic
trial remain later gates.
