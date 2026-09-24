use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{client_builder, OperatorReadinessProbe};

#[tokio::test]
async fn dns_uses_the_async_resolver_inside_the_deadline() -> Result<(), Box<dyn std::error::Error>>
{
    struct PendingResolver(Arc<AtomicUsize>);
    impl reqwest::dns::Resolve for PendingResolver {
        fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        }
    }

    let calls = Arc::new(AtomicUsize::new(0));
    let mut probe = OperatorReadinessProbe::prepare("http://readiness.invalid/health", None)?;
    // Override only DNS inside this private test. The production builder still
    // supplies the timeout and all HTTP policy; no public override is exposed.
    probe.client = client_builder()
        .dns_resolver(Arc::new(PendingResolver(Arc::clone(&calls))))
        .build()?;
    let ready = tokio::time::timeout(Duration::from_secs(4), probe.probe()).await?;
    assert!(!ready);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "DNS must use the asynchronous request resolver"
    );
    Ok(())
}
