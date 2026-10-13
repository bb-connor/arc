use super::*;
use chio_test_support::prelude::*;

#[test]
fn scheduler_fence_rejects_token_without_owner() {
    for token in [1, 9, u64::MAX] {
        let mut current = None;
        let error = validate_response_scheduler_fence(
            None,
            Some(token),
            false,
            &mut current,
            &mut 0,
        )
        .test_expect_err("a fencing token requires its owner");
        assert!(matches!(
            error,
            Error::CanonicalJson(message)
                if message == "scheduler owner and fencing token binding is invalid"
        ));
        assert_eq!(current, None);
    }
}

#[test]
fn receipt_backed_effect_rejects_token_without_owner() {
    let mut scheduler_fence = None;
    let mut effect_generations = [0];
    let mut receipt_backed_effects = [false];
    let error = validate_response_effect_receipt_order(
        ResponseEffectReceiptOrderInput {
            effect_index: 0,
            effect_generation: 1,
            scheduler_lease_owner_id: None,
            scheduler_fencing_token: 9,
            effect_transition_id: None,
            non_request: false,
            dispatch_bound: true,
        },
        ResponseEffectReceiptOrderState {
            scheduler_fence: &mut scheduler_fence,
            highest_legacy_scheduler_fencing_token: &mut 0,
            effect_generations: &mut effect_generations,
            receipt_backed_effects: &mut receipt_backed_effects,
        },
    )
    .test_expect_err("receipt-backed effects require a scheduler owner");
    assert!(matches!(
        error,
        Error::CanonicalJson(message)
            if message == "scheduler owner and fencing token binding is invalid"
    ));
    assert_eq!(scheduler_fence, None);
    assert_eq!(effect_generations, [0]);
    assert_eq!(receipt_backed_effects, [false]);
}

#[test]
fn scheduler_fence_accepts_bound_lease_and_strict_takeover() {
    let owner = LeaseOwnerId::new("worker-1").test_expect("valid lease owner");
    let successor = LeaseOwnerId::new("worker-2").test_expect("valid successor");
    let mut current = None;
    for (lease_owner, token) in [(&owner, 9), (&owner, 9), (&successor, 10)] {
        validate_response_scheduler_fence(
            Some(lease_owner),
            Some(token),
            true,
            &mut current,
            &mut 0,
        )
        .test_expect("owner-bound fence is valid");
        assert_eq!(current, Some((lease_owner.clone(), token)));
    }
}

#[test]
fn scheduler_fence_rejects_equal_token_takeover_and_regression() {
    let owner = LeaseOwnerId::new("worker-1").test_expect("valid lease owner");
    let successor = LeaseOwnerId::new("worker-2").test_expect("valid successor");
    for (lease_owner, token) in [(&owner, 8), (&successor, 9), (&successor, 8)] {
        let mut current = Some((owner.clone(), 9));
        let error = validate_response_scheduler_fence(
            Some(lease_owner),
            Some(token),
            true,
            &mut current,
            &mut 0,
        )
        .test_expect_err("takeover and renewal cannot regress the fence");
        assert!(matches!(
            error,
            Error::CanonicalJson(message)
                if message == "scheduler owner or fencing token regressed"
        ));
        assert_eq!(current, Some((owner.clone(), 9)));
    }
}
