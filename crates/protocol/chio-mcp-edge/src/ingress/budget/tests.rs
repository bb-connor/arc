#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use std::sync::mpsc;

fn budget() -> IngressBudget {
    IngressBudget::new(Arc::new(AtomicBool::new(false)))
}

fn retained(budget: &IngressBudget) -> Footprint {
    budget.state.lock().expect("budget state").retained
}

fn message(budget: &IngressBudget) -> AccountedMessage {
    budget
        .read_message(&mut b"{\"id\":1,\"result\":{\"ok\":true}}\n".as_slice())
        .expect("admit a real JSON frame")
}

#[test]
fn reservations_survive_full_send_and_release_on_disconnect_and_drop() {
    let budget = budget();
    let first = message(&budget);
    let one = retained(&budget);
    let second = message(&budget);
    let (sender, receiver) = mpsc::sync_channel(1);
    assert!(sender.try_send(first).is_ok());
    let returned = match sender.try_send(second) {
        Err(mpsc::TrySendError::Full(message)) => message,
        _ => panic!("full channel must return the owned reservation"),
    };
    assert_eq!(retained(&budget), one.checked_add(one).expect("two frames"));
    drop(returned);
    assert_eq!(retained(&budget), one);
    drop(receiver);
    assert_eq!(retained(&budget), Footprint::default());
    let disconnected = sender.try_send(message(&budget));
    assert!(matches!(
        disconnected,
        Err(mpsc::TrySendError::Disconnected(_))
    ));
    drop(disconnected);
    assert_eq!(retained(&budget), Footprint::default());
}

#[test]
fn batch_and_result_handoff_release_once_without_cloning_trees() {
    let budget = budget();
    let messages = vec![message(&budget), message(&budget), message(&budget)];
    assert!(retained(&budget).nodes > 0);
    let values = AccountedMessage::into_values(messages);
    assert_eq!(values.len(), 3);
    assert_eq!(values[0]["result"]["ok"], true);
    assert_eq!(retained(&budget), Footprint::default());
    let result = message(&budget)
        .into_result()
        .expect("move the response result");
    assert_eq!(result["ok"], true);
    assert_eq!(retained(&budget), Footprint::default());
}

#[test]
fn every_limit_is_atomic_and_failure_survives_capacity_release() {
    for excess in [
        Footprint {
            wire_bytes: 1,
            ..Footprint::default()
        },
        Footprint {
            nodes: 1,
            ..Footprint::default()
        },
        Footprint {
            text_bytes: 1,
            ..Footprint::default()
        },
    ] {
        let budget = budget();
        let exact = Footprint {
            wire_bytes: MAX_RETAINED_WIRE_BYTES,
            nodes: MAX_RETAINED_NODES,
            text_bytes: MAX_RETAINED_TEXT_BYTES,
        };
        let reservation = budget.reserve(exact).expect("inclusive aggregate limits");
        assert!(budget.reserve(excess).is_err());
        assert_eq!(retained(&budget), exact);
        assert!(budget.shutdown_requested.load(Ordering::Acquire));
        drop(reservation);
        assert_eq!(retained(&budget), Footprint::default());
        assert!(budget.ensure_open().is_err());
    }
}

#[test]
fn admission_counts_decoded_keys_strings_containers_and_values() {
    let text = "{\"a\":[null,true,12.50],\"\\u0062\":\"\\u20ac\"}\n";
    let measured = admission::measure(text).expect("stream structural accounting");
    assert_eq!(
        measured,
        Footprint {
            wire_bytes: text.len(),
            nodes: 6,
            text_bytes: 5
        }
    );
    let budget = budget();
    let frame = budget
        .read_message(&mut text.as_bytes())
        .expect("canonical decode");
    assert_eq!(frame.value()["b"], "\u{20ac}");
    assert_eq!(frame.value()["a"][2].as_f64(), Some(12.5));
    assert_eq!(retained(&budget), measured);
    drop(frame);
    assert_eq!(retained(&budget), Footprint::default());
}

#[test]
fn canonical_rejection_releases_pre_decode_reservation() {
    let budget = budget();
    let error = budget
        .read_message(&mut b"{\"x\":1,\"x\":2}\n".as_slice())
        .expect_err("canonical decoder must still reject duplicate keys");
    assert_eq!(
        error.to_string(),
        "urn:chio:error:attest:signed-json-invalid-input"
    );
    assert_eq!(retained(&budget), Footprint::default());
}

#[test]
fn admission_preserves_unsigned_numbers_and_original_depth_limit() {
    let budget = budget();
    let text = b"{\"ordinary\":0.50,\"small\":1e-05,\"wide\":18446744073709551615}\n";
    let frame = budget
        .read_message(&mut text.as_slice())
        .expect("unsigned number compatibility");
    assert_eq!(frame.value()["ordinary"].as_f64(), Some(0.5));
    assert_eq!(frame.value()["small"].as_f64(), Some(0.00001));
    assert_eq!(frame.value()["wide"].as_u64(), Some(u64::MAX));
    drop(frame);
    let deep = format!("{}0{}\n", "[".repeat(130), "]".repeat(130));
    assert!(budget.read_message(&mut deep.as_bytes()).is_err());
    assert!(budget.read_message(&mut b"{} {}\n".as_slice()).is_err());
    assert_eq!(retained(&budget), Footprint::default());
}

#[test]
fn terminal_diagnostics_bound_primary_and_cleanup_independently() {
    let budget = budget();
    let original = format!("primary {}", "\u{1f980}".repeat(4096));
    budget.fail(&original);
    budget.note_cleanup(&Err(AdapterError::ConnectionFailed(format!(
        "cleanup {}",
        "x".repeat(8192)
    ))));
    budget.fail("must not replace the first failure");
    let error = budget
        .terminal_error()
        .expect("read terminal state")
        .expect("terminal failure");
    let diagnostic = error.to_string();
    assert!(diagnostic.len() < 2 * MAX_DIAGNOSTIC_COMPONENT_BYTES + 128);
    assert!(diagnostic.contains("primary"));
    assert!(diagnostic.contains("terminal receipt cleanup failed"));
    assert!(diagnostic.contains("cleanup"));
    assert!(!diagnostic.contains("must not replace"));
}

#[test]
fn terminal_diagnostic_formatting_never_holds_the_budget_lock() {
    struct LockCheckingDiagnostic<'a>(&'a IngressBudget);

    impl fmt::Display for LockCheckingDiagnostic<'_> {
        fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
            assert!(
                self.0.state.try_lock().is_ok(),
                "formatting callbacks must run outside the ingress budget lock"
            );
            output.write_str("upstream MCP ingress overload")
        }
    }

    let budget = budget();
    budget.fail(LockCheckingDiagnostic(&budget));
    assert!(budget.ensure_open().is_err());
}
