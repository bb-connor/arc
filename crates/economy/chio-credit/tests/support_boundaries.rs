use chio_credit::{CreditScorecardSupportBoundary, ExposureLedgerSupportBoundary};

#[test]
fn exposure_ledger_boundary_refuses_cross_currency_netting() {
    let boundary = ExposureLedgerSupportBoundary::default();
    assert!(
        !boundary.cross_currency_netting_supported,
        "the exposure ledger must not advertise cross-currency netting: {boundary:?}"
    );
}

#[test]
fn scorecard_boundary_refuses_capital_allocation_and_cross_currency_netting() {
    let boundary = CreditScorecardSupportBoundary::default();
    assert!(
        !boundary.capital_allocation_supported,
        "the scorecard must not advertise capital allocation: {boundary:?}"
    );
    assert!(
        !boundary.cross_currency_netting_supported,
        "the scorecard must not advertise cross-currency netting: {boundary:?}"
    );
}
