//! Callback fault containment only. Real policy and physical participant
//! provenance are covered by the control-plane and SQLite integration tests.
use super::*;
use crate::admission_operation::{
    AdmissionDigest, NativeSecurityDispatchLedgerContext, NativeSecurityDispatchLedgerRecordV1,
};
use std::sync::Mutex;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Default)]
enum Fault {
    #[default]
    None,
    Deny,
    NoWrite,
    LostAck,
    PanicWrite,
    WrongAck,
    MissingRead,
    PanicRead,
    ChangedReadback,
    WrongDigest,
    WrongPolicy,
    WrongOperation,
    WrongContext,
    WrongGrant,
    WrongRequest,
    Oversized,
}

#[derive(Default)]
struct State {
    fault: Fault,
    reads: usize,
    writes: usize,
    record: Option<NativeSecurityDispatchLedgerRecordV1>,
}

#[derive(Default)]
pub(super) struct TestLedger(Mutex<State>);

impl TestLedger {
    pub(super) fn retain(
        &self,
        input: NativeSecurityDispatchLedgerContext<'_>,
    ) -> Result<NativeSecurityDispatchLedgerRecordV1, AdmissionOperationStoreError> {
        let mut state = self.0.lock().map_err(invalid)?;
        state.writes += 1;
        let fault = state.fault;
        if matches!(fault, Fault::Deny) {
            return Err(invalid("injected ledger denial"));
        }
        let mut value = serde_json::json!({
            "schema": "chio.native-dispatch-preparation-ledger.v1",
            "operation": input.custody.operation.to_persisted(),
            "context": input.custody.security_context,
            "policy": serde_json::from_slice::<serde_json::Value>(input.policy_json).map_err(invalid)?,
            "grant_index": input.grant_index,
            "live_request_digest": sha256_hex(&canonical_json_bytes(input.custody.request).map_err(invalid)?),
        });
        match fault {
            Fault::WrongPolicy => value["policy"] = serde_json::json!({"other": true}),
            Fault::WrongOperation => value["operation"]["version"] = serde_json::json!(0),
            Fault::WrongContext => value["context"] = serde_json::Value::Null,
            Fault::WrongGrant => value["grant_index"] = serde_json::json!(999),
            Fault::WrongRequest => value["live_request_digest"] = serde_json::json!("other"),
            _ => {}
        }
        let bytes = if matches!(fault, Fault::Oversized) {
            vec![b' '; 1024 * 1024 + 1]
        } else {
            canonical_json_bytes(&value).map_err(invalid)?
        };
        let mut record = NativeSecurityDispatchLedgerRecordV1 {
            operation_id: input.custody.operation.binding().operation_id().clone(),
            record_digest: AdmissionDigest::try_new("ledger", sha256_hex(&bytes))?,
            canonical_record: bytes,
        };
        if matches!(fault, Fault::WrongDigest) {
            record.record_digest = AdmissionDigest::try_new("ledger", sha256_hex(b"wrong"))?;
        }
        if !matches!(fault, Fault::NoWrite) {
            state.record = Some(record.clone());
        }
        drop(state);
        match fault {
            Fault::LostAck => Err(AdmissionOperationStoreError::OutcomeUnknown(
                "injected ledger lost acknowledgement".into(),
            )),
            Fault::PanicWrite => panic!("injected ledger panic after retention"),
            Fault::WrongAck => {
                record.record_digest = AdmissionDigest::try_new("ack", sha256_hex(b"wrong-ack"))?;
                Ok(record)
            }
            _ => Ok(record),
        }
    }

    pub(super) fn load(
        &self,
        id: &AdmissionOperationId,
    ) -> Result<Option<NativeSecurityDispatchLedgerRecordV1>, AdmissionOperationStoreError> {
        let mut state = self.0.lock().map_err(invalid)?;
        state.reads += 1;
        let reads = state.reads;
        let fault = state.fault;
        let mut record = state
            .record
            .clone()
            .filter(|record| &record.operation_id == id);
        drop(state);
        match fault {
            Fault::MissingRead => return Ok(None),
            Fault::PanicRead => panic!("injected ledger read panic"),
            Fault::ChangedReadback if reads == 2 => {
                if let Some(record) = &mut record {
                    record.record_digest =
                        AdmissionDigest::try_new("read", sha256_hex(b"changed"))?;
                }
            }
            _ => {}
        }
        Ok(record)
    }
}

fn invalid(error: impl std::fmt::Display) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(error.to_string())
}

#[test]
fn native_dispatch_ledger_confirms_both_reads_without_activating_dispatch() -> TestResult {
    for egress in [false, true] {
        let (kernel, request, context, store) = native_egress::fixture("ledger-callback-positive")?;
        let operation = store.operation();
        let prepared = kernel.prepare_native_security_egress(
            operation.binding().operation_id(),
            &request,
            &context,
        )?;
        let policy = canonical_json_bytes(&serde_json::json!({"exact-policy": true}))?;
        let record = if egress {
            prepared
                .acquire(current_unix_timestamp_ms() + 60_000)?
                .commit_with_dispatch_ledger(0, &policy)?
                .1
        } else {
            prepared.retain_dispatch_ledger(0, &policy)?
        };
        let state = store.native_dispatch_ledger.0.lock().map_err(invalid)?;
        assert_eq!(state.reads, 2);
        assert_eq!(state.writes, 1);
        assert_eq!(state.record.as_ref(), Some(&record));
        drop(state);
        assert_eq!(store.operation(), operation);
        assert_eq!(
            kernel
                .run_security_pre_dispatch_hook(&request, Some(&context), None)
                .err()
                .ok_or("dispatch denied")?
                .reason,
            "native security dispatch lifecycle is unsupported"
        );
    }
    Ok(())
}

#[test]
fn native_dispatch_ledger_faults_deny_even_when_history_survives() -> TestResult {
    for egress in [false, true] {
        for fault in [
            Fault::Deny,
            Fault::NoWrite,
            Fault::LostAck,
            Fault::PanicWrite,
            Fault::WrongAck,
            Fault::MissingRead,
            Fault::PanicRead,
            Fault::ChangedReadback,
            Fault::WrongDigest,
            Fault::WrongPolicy,
            Fault::WrongOperation,
            Fault::WrongContext,
            Fault::WrongGrant,
            Fault::WrongRequest,
            Fault::Oversized,
        ] {
            let (kernel, request, context, store) =
                native_egress::fixture(&format!("ledger-{fault:?}"))?;
            let operation = store.operation();
            let prepared = kernel.prepare_native_security_egress(
                operation.binding().operation_id(),
                &request,
                &context,
            )?;
            store
                .native_dispatch_ledger
                .0
                .lock()
                .map_err(invalid)?
                .fault = fault;
            let expected_egress = if egress {
                let acquired = prepared.acquire(current_unix_timestamp_ms() + 60_000)?;
                let acquisition = acquired.history().acquisition.clone();
                let result = acquired.commit_with_dispatch_ledger(0, b"{}");
                assert!(result.is_err(), "accepted egress {fault:?}");
                Some(acquisition)
            } else {
                let result = prepared.retain_dispatch_ledger(0, b"{}");
                assert!(result.is_err(), "accepted local {fault:?}");
                None
            };
            let mut state = store.native_dispatch_ledger.0.lock().map_err(invalid)?;
            assert_eq!(state.writes, 1, "{fault:?}");
            assert_eq!(
                state.reads,
                if matches!(fault, Fault::ChangedReadback) {
                    2
                } else {
                    1
                },
                "{fault:?}"
            );
            assert_eq!(
                state.record.is_some(),
                !matches!(fault, Fault::Deny | Fault::NoWrite),
                "{fault:?}"
            );
            state.fault = Fault::None;
            drop(state);
            assert_eq!(store.operation(), operation);
            let history = store
                .native_egress
                .read(Some(operation.clone()))?
                .ok_or("original egress operation")?
                .1;
            match (history, expected_egress) {
                (Some(history), Some(expected)) => {
                    assert_eq!(history.acquisition, expected);
                    assert!(history.commitment.is_some(), "{fault:?}");
                }
                (None, None) => {}
                _ => return Err(format!("{fault:?}: partial custody differs").into()),
            }
            // A callback panic cannot poison the kernel mutation sequencer.
            let _prepared = kernel.prepare_native_security_egress(
                operation.binding().operation_id(),
                &request,
                &context,
            )?;
        }
    }
    Ok(())
}

#[test]
fn native_dispatch_ledger_rejects_invalid_inputs_before_egress_mutation() -> TestResult {
    for (grant, policy, reason) in [
        (1, b"{}".to_vec(), "unmatched grant"),
        (usize::MAX, b"{}".to_vec(), "unmatched grant"),
        (0, Vec::new(), "exceeds its bound"),
        (0, vec![b' '; 256 * 1024 + 1], "exceeds its bound"),
        (0, b"{".to_vec(), "is not JSON"),
        (0, b"{ }".to_vec(), "is not canonical"),
    ] {
        // Both entry points validate before their next irreversible phase.
        // A caller which already acquired a fence retains only acquisition.
        for acquired_first in [false, true] {
            let (kernel, request, context, store) = native_egress::fixture("invalid-ledger-input")?;
            let operation = store.operation();
            let prepared = kernel.prepare_native_security_egress(
                operation.binding().operation_id(),
                &request,
                &context,
            )?;
            let (result, expected) = if acquired_first {
                let acquired = prepared.acquire(current_unix_timestamp_ms() + 60_000)?;
                let expected = acquired.history().clone();
                (
                    acquired.commit_with_dispatch_ledger(grant, &policy),
                    Some(expected),
                )
            } else {
                (
                    prepared.acquire_and_commit_with_dispatch_ledger(
                        current_unix_timestamp_ms() + 60_000,
                        grant,
                        &policy,
                    ),
                    None,
                )
            };
            let error = result.err().ok_or("invalid ledger command succeeded")?;
            assert!(
                error.to_string().contains(reason),
                "{acquired_first}: {error}"
            );
            assert_eq!(
                store
                    .native_egress
                    .read(Some(operation.clone()))?
                    .ok_or("original egress operation")?
                    .1,
                expected
            );
            let ledger = store.native_dispatch_ledger.0.lock().map_err(invalid)?;
            assert_eq!((ledger.writes, ledger.reads), (0, 0));
            assert!(ledger.record.is_none());
            assert_eq!(store.operation(), operation);
        }
    }
    Ok(())
}
