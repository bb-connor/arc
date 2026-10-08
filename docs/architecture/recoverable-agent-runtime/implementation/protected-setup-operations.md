# Current protected setup operating contract

This page describes the current source procedure. Current qualification is tracked in [STATUS.md](STATUS.md). The archived [P6 operating contract](p6/OPERATIONS.md), measurement scripts and source packages remain evidence for their own recorded implementation.

## Prepare the original call

Configure the selected recovery profile, semantic operator, native knowledge broker and trusted setup operator key. The current setup selection belongs to one complete authority, tenant and process scope. Each additional process needs its own current selection and mediation.

Before pinning the self-test, drive that agent process through one real first-attempt call to the selected deployment tool. The initiating capability must name that tool and caller. The model-free request reaches the native input owner without a declassification grant and is refused before dispatch. Retain the exact request, its original Process call identity and native denial. Setup requires this journaled original with authenticated `CompensatedBeforeDispatch` custody and no dispatch commit; a synthetic request or a refusal that lacks the original custody cannot become a new self-test.

The operator supplies this exact original to the native setup creation host, pins the chosen self-test, then completes the existing action selection and approval. The native owner freezes one Resume identity for the first probe. Repeating the same request preserves that identity and its original charge.

## Keep the selected source quiet

From materialization through the first probe, keep the selected session's mutable native flow source unchanged. Another ordinary denied or allowed call can advance that source. A stale source then produces `recovery.conflict` before the self-test effect. A writer change before the uncommitted probe produces `recovery.restart_required`; expiry produces `recovery.probe_expired`. These precondition refusals require investigation of the selected original, rather than a generic retry under a new command ID.

A pending self-test with a charged, acknowledged Process reservation requires permanent authenticated native and Process closure before its active workflow capacity can be returned. The materialized closure route is still under implementation. Current materialized stale selections therefore refuse prompt replacement; deleting retained rows or treating an absent native bank as zero debt is not a supported replacement procedure. The separately authenticated unmaterialized path applies only before an Action or Process acknowledgement exists.

## Probe, restart and qualify

Use the independently selected setup operator public key for both CLI calls. Obtain that key from the deployment configuration; the key carried by an incoming signed envelope cannot select its own trust root.

```sh
chio recovery setup probe \
  --endpoint "$RECOVERY_ENDPOINT" \
  --capability "$RECOVERY_CAPABILITY_FILE" \
  --workflow-id "$SELF_TEST_WORKFLOW" \
  --operator-key "$SETUP_OPERATOR_PUBLIC_KEY" > setup-probe.json
```

A successful probe retains one actual benign effect and signed receipt plus the denied native policy leg for the same permitted initiating tool authority. Preserve the exact canonical stdout bytes. The CLI checks the operator signature and reports the required writer restart on stderr.

Restart the serving native writer through the host's ordinary operator procedure while retaining the same authority store, Process journal, profile and self-test identity. Then qualify with the retained proof:

```sh
chio recovery setup qualify \
  --endpoint "$RECOVERY_ENDPOINT" \
  --capability "$RECOVERY_CAPABILITY_FILE" \
  --probe setup-probe.json \
  --operator-key "$SETUP_OPERATOR_PUBLIC_KEY" > setup-report.json
```

The first qualification must finish within the initial fifteen-minute probe window. Qualification from the original writer is refused. After an accepted qualification, an identical current profile can re-attest the retained completed self-test under a later writer beyond that original window, with no new self-test effect or workflow. A changed profile requires new qualification. Current capabilities, current actor assignments and live mediation remain necessary for every protected action.

The CLI's setup transport deadline is 120 seconds. It issues no automatic retries. An unpinned `--operator-key` path remains explicitly untrusted even if the envelope signature is internally valid.

## Preserve legacy custody

Canonical historical selections without `command_bound` use an explicit legacy representation. Authenticated decoding preserves their exposed Resume bytes and does not rewrite the stored preimage. This codec compatibility does not renew old capability, native origin, profile or readiness authority.

The current original-claim writer refuses when retained workflow history lacks linked original custody, anywhere in the authority. Those stores need a separate authenticated migration before fresh creation; ordinary pinning or an explicit new workflow ID cannot perform that migration. Historical inspection, cancellation and settlement retain their separate current authorization requirements. Genuine older protected setup retirement and renewed current setup remain separately reviewed migration obligations.

## Account for calls and retained history

A fresh source-bound setup starts with these logical Process charges:

| Transition | Additional Process tree calls | External self-test effects |
| --- | ---: | ---: |
| First original native refusal before dispatch | 1 | 0 |
| Materialize and acknowledge the self-test reservation | 1 | 0 |
| Probe under that exact reservation | 0 | 1 |
| Replay the retained completed probe and qualify | 0 | 0 |

The fresh setup total is two tree calls and one successful benign effect. Returning an eligible active workflow slot preserves those original call debits and all historical records. Logical calls, physical write debt, native funding and external effects are separate measurements.

The archived P6 measurement assertion `effects == tree_calls == 1` remains part of its original evidence. A successor qualification package must record the original denial and reservation separately, together with its actual observed effects, charges and source binding. Editing the archived assertion or associating an old run with current bytes would not qualify this procedure.
