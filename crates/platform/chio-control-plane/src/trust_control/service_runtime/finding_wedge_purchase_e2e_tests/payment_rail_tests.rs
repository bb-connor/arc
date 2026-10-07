//! Rail observations retain exact reference identity and actual financial state.
use super::*;
use chio_kernel::RailSettlementState;

fn request(reference: &str) -> PaymentAuthorizeRequest {
    PaymentAuthorizeRequest {
        amount_units: 7,
        currency: "USD".into(),
        payer: "buyer".into(),
        payee: "seller".into(),
        reference: reference.into(),
        governed: None,
        commerce: None,
    }
}

fn held(calls: &Arc<PaymentCalls>) -> ReversibleHoldAdapter {
    ReversibleHoldAdapter {
        calls: calls.clone(),
        authorize_hook: None,
    }
}

#[test]
fn unissued_references_are_absent_without_authorizing() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let hold = held(&calls);
    let prepaid = PrepaidFinalAdapter {
        calls: calls.clone(),
    };
    for rail in [
        &hold as &dyn PaymentAdapter,
        &prepaid as &dyn PaymentAdapter,
    ] {
        assert_eq!(
            rail.settlement_state("unissued", None)?,
            RailSettlementState::NoAuthorization
        );
    }
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    assert_eq!(calls.releases.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn held_authorization_is_observable_without_its_reply_id() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let rail = held(&calls);
    let authorization = rail.authorize(&request("held-reference"))?;
    assert_eq!(
        rail.settlement_state("held-reference", None)?,
        RailSettlementState::Held {
            authorization_id: authorization.authorization_id.clone()
        },
    );
    assert_eq!(
        rail.settlement_state("held-reference", Some(&authorization.authorization_id))?,
        rail.settlement_state("held-reference", None)?,
    );
    assert_eq!(
        rail.settlement_state("unrelated", None)?,
        RailSettlementState::NoAuthorization
    );
    Ok(())
}

#[test]
fn prepayment_is_observed_as_final_settlement() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let rail = PrepaidFinalAdapter {
        calls: calls.clone(),
    };
    let authorization = rail.authorize(&request("prepaid-reference"))?;
    let RailSettlementState::Settled {
        authorization_id,
        result,
    } = rail.settlement_state("prepaid-reference", None)?
    else {
        panic!("prepayment must remain a final financial effect");
    };
    assert_eq!(authorization_id, authorization.authorization_id);
    assert_eq!(result.transaction_id, authorization_id);
    assert_eq!(result.settlement_status, RailSettlementStatus::Settled);
    assert_eq!(calls.captures.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn observation_refuses_wrong_and_unissued_authorization_ids() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let rail = held(&calls);
    let authorization = rail.authorize(&request("held-reference"))?;
    assert!(rail
        .settlement_state("held-reference", Some("wrong"))
        .is_err());
    assert!(rail
        .settlement_state("unissued", Some(&authorization.authorization_id))
        .is_err());
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn authorizing_reference_retains_uncertainty_without_locking_the_hook() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let hook_calls = calls.clone();
    let rail = ReversibleHoldAdapter {
        calls: calls.clone(),
        authorize_hook: Some(Arc::new(move || {
            let observer = held(&hook_calls);
            assert!(matches!(
                observer.settlement_state("pending-reference", None),
                Err(PaymentError::Unavailable(_)),
            ));
            assert_eq!(
                observer
                    .settlement_state("unissued", None)
                    .map_err(|error| error.to_string())?,
                RailSettlementState::NoAuthorization,
            );
            Ok(())
        })),
    };
    let (sent, received) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let _ = sent.send(rail.authorize(&request("pending-reference")));
    });
    let authorization = received.recv_timeout(Duration::from_secs(5))??;
    assert!(worker.join().is_ok());
    assert_eq!(
        held(&calls).settlement_state("pending-reference", None)?,
        RailSettlementState::Held {
            authorization_id: authorization.authorization_id
        },
    );
    Ok(())
}

#[test]
fn repeated_authorization_is_idempotent_and_conflicting_reuse_is_refused() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let rail = held(&calls);
    let original = request("stable-reference");
    let first = rail.authorize(&original)?;
    assert_eq!(rail.authorize(&original)?, first);
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    let mut conflict = original;
    conflict.amount_units += 1;
    assert!(rail.authorize(&conflict).is_err());
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn release_observation_retains_the_exact_terminal_result() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let rail = held(&calls);
    let authorization = rail.authorize(&request("release-reference"))?;
    let result = rail.release(&authorization.authorization_id, "release-reference")?;
    assert_eq!(
        rail.settlement_state("release-reference", None)?,
        RailSettlementState::Settled {
            authorization_id: authorization.authorization_id.clone(),
            result: result.clone()
        },
    );
    assert_eq!(
        rail.release(&authorization.authorization_id, "release-reference")?,
        result
    );
    assert_eq!(calls.releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn capture_observation_retains_the_exact_terminal_result() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let rail = held(&calls);
    let authorization = rail.authorize(&request("capture-reference"))?;
    let result = rail.capture(
        &authorization.authorization_id,
        7,
        "USD",
        "capture-reference",
    )?;
    assert_eq!(
        rail.settlement_state("capture-reference", None)?,
        RailSettlementState::Settled {
            authorization_id: authorization.authorization_id.clone(),
            result: result.clone()
        },
    );
    assert_eq!(
        rail.capture(
            &authorization.authorization_id,
            7,
            "USD",
            "capture-reference"
        )?,
        result
    );
    assert_eq!(calls.captures.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn conflicting_terminal_actions_cannot_replace_an_observed_result() -> TestResult {
    for capture_first in [false, true] {
        let calls = Arc::new(PaymentCalls::default());
        let rail = held(&calls);
        let authorization = rail.authorize(&request("terminal-reference"))?;
        let id = &authorization.authorization_id;
        let first = if capture_first {
            rail.capture(id, 7, "USD", "terminal-reference")?
        } else {
            rail.release(id, "terminal-reference")?
        };
        let conflicting = if capture_first {
            rail.release(id, "terminal-reference")
        } else {
            rail.capture(id, 7, "USD", "terminal-reference")
        };
        assert!(conflicting.is_err());
        assert_eq!(
            rail.settlement_state("terminal-reference", None)?,
            RailSettlementState::Settled {
                authorization_id: authorization.authorization_id,
                result: first,
            },
        );
    }
    Ok(())
}

#[test]
fn an_existing_reference_cannot_change_its_rail_mode() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let rail = held(&calls);
    let original = request("mode-reference");
    let authorization = rail.authorize(&original)?;
    let prepaid = PrepaidFinalAdapter {
        calls: calls.clone(),
    };
    assert!(prepaid.authorize(&original).is_err());
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(
        rail.settlement_state("mode-reference", None)?,
        RailSettlementState::Held {
            authorization_id: authorization.authorization_id
        },
    );
    Ok(())
}

#[test]
fn an_ambiguous_hook_failure_cannot_become_payment_absence() -> TestResult {
    let calls = Arc::new(PaymentCalls::default());
    let rail = ReversibleHoldAdapter {
        calls: calls.clone(),
        authorize_hook: Some(Arc::new(|| Err("ambiguous authorization response".into()))),
    };
    let original = request("ambiguous-reference");
    assert!(rail.authorize(&original).is_err());
    assert!(matches!(
        rail.settlement_state("ambiguous-reference", None),
        Err(PaymentError::Unavailable(_)),
    ));
    assert!(rail.authorize(&original).is_err());
    assert_eq!(calls.authorizations.load(Ordering::SeqCst), 1);
    Ok(())
}
