// Ordinary production execution across the nonempty credential and nonce profiles.
use super::*;

#[test]
fn native_declassification_composes_nonce_runtime_approval_and_dpop_sync_and_async() -> TestResult {
    for combined in [false, true] {
        for nonce in [false, true] {
            for asynchronous in [false, true] {
                let (mut fixture, _) = profile(combined, 300)?;
                let legacy = if nonce {
                    // Expiry boundaries have separate real-clock tests. This
                    // fixture allows debug-build verification of every participant.
                    let legacy = super::super::nonce::execution::install_nonce(&mut fixture, 120);
                    super::super::nonce::execution::issue(&mut fixture)?;
                    Some(legacy)
                } else {
                    None
                };
                let response = if asynchronous {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?
                        .block_on(fixture.kernel.evaluate_tool_call_with_security_context(
                            &fixture.request,
                            &fixture.context,
                        ))?
                } else {
                    fixture
                        .kernel
                        .evaluate_tool_call_blocking_with_security_context(
                            &fixture.request,
                            &fixture.context,
                        )?
                };
                assert_eq!(
                    response.verdict,
                    Verdict::Allow,
                    "combined={combined} nonce={nonce} async={asynchronous}: {:?}",
                    response.reason
                );
                assert!(
                    matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
                );
                assert!(response.receipt.verify_signature()?);
                assert_completed(&fixture, combined, nonce)?;
                if let Some(legacy) = legacy {
                    assert_eq!(legacy.load(Ordering::SeqCst), 0);
                }
            }
        }
    }
    Ok(())
}
