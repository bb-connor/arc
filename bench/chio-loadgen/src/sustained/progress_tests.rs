use super::*;
use crate::StoreBacking;
use chio_test_support::prelude::*;

#[test]
fn backlog_saturation_reports_real_progress() {
    let config = LoadgenConfig {
        arrival_rate_hz: 200,
        duration: Duration::from_secs(5),
        tool_latency: Duration::ZERO,
        store: StoreBacking::Memory,
        p99_budget: Duration::from_millis(500),
        rss_growth_budget_bytes: 256 * 1024 * 1024,
    };

    let harness = StackHarness::boot_smoke(&config).test_unwrap();
    let error = run_sustained_with_completion(&harness, &config, &|| {
        harness.set_tool_latency_ms(2_000);
    })
    .test_unwrap_err();

    match error {
        LoadgenError::DispatchBacklogSaturated {
            scheduled,
            attempted,
            completed,
            in_flight,
            capacity,
            ..
        } => {
            assert_eq!(scheduled, 1_000);
            assert_eq!(capacity, 96);
            assert!(completed > 0, "dispatches before the stall completed");
            assert!(completed < attempted);
            assert_eq!(in_flight, attempted - completed);
            assert!(in_flight <= capacity);
        }
        other => {
            panic!("a stalled dispatch path must deny with DispatchBacklogSaturated, got {other:?}")
        }
    }
}
