//! Public worker API against a dedicated, migrated TLS PostgreSQL fixture.
//! No schema resets or privilege changes. Run explicitly with --ignored.

use std::error::Error;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::sha256_hex;
use chio_finding_market_store_postgres::{
    HostedJobLease, HostedJobState, HostedJobWriteOutcome, HostedMarketStoreError,
    HostedPostgresConfig, HostedTenantId, HostedTenantLimits, PostgresFindingMarketStore,
};

fn configuration(variable: &str) -> Result<HostedPostgresConfig, Box<dyn Error>> {
    let ca = PathBuf::from(std::env::var("CHIO_JOB_DATABASE_CA")?);
    Ok(HostedPostgresConfig::new(std::env::var(variable)?)?.with_ca_certificate(ca)?)
}

#[tokio::test]
#[ignore = "requires dedicated TLS PostgreSQL runtime and worker credentials"]
async fn public_worker_lease_methods_preserve_role_and_fence_boundaries(
) -> Result<(), Box<dyn Error>> {
    let runtime =
        PostgresFindingMarketStore::connect(&configuration("CHIO_JOB_TEST_RUNTIME_URL")?).await?;
    // These are the production connection and privilege checks, not a test pool constructor.
    let worker =
        PostgresFindingMarketStore::connect_worker(&configuration("CHIO_JOB_TEST_WORKER_URL")?)
            .await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let tenant = HostedTenantId::new(format!("worker-api-{}", now.as_nanos()))?;
    runtime
        .register_tenant(
            &tenant,
            &HostedTenantLimits::new(4, 10, 1_000_000, "worker-api-v1")?,
            now.as_secs(),
        )
        .await?;
    worker.probe_tenant(&tenant).await?;
    for job in ["handoff", "failed", "exhausted", "disabled"] {
        runtime
            .put_job(
                &tenant,
                job,
                "test",
                &sha256_hex(b"{}"),
                b"{}",
                now.as_secs(),
                now.as_secs(),
            )
            .await?;
    }
    let claimed = worker.claim_due_jobs(&tenant, "original", 600, 4).await?;
    assert_eq!(claimed.len(), 4);
    let job = |id: &str| {
        claimed
            .iter()
            .find(|job| job.job_id == id)
            .ok_or("claimed job missing")
    };
    let first = HostedJobLease::new("original", job("handoff")?.lease_fence)?;
    worker
        .renew_job_lease(&tenant, "handoff", &first, 600)
        .await?;
    worker
        .relinquish_job_lease(&tenant, "handoff", &first)
        .await?;
    assert_eq!(
        worker
            .get_job(&tenant, "handoff")
            .await?
            .ok_or("job missing")?
            .state,
        HostedJobState::Pending
    );
    let replacement = worker
        .claim_due_jobs(&tenant, "replacement", 600, 1)
        .await?;
    assert_eq!(replacement.len(), 1);
    let replacement = replacement.first().ok_or("replacement missing")?;
    assert_eq!(replacement.job_id, "handoff");
    assert!(replacement.lease_fence > first.fence());
    let wrong_owner = HostedJobLease::new("original", replacement.lease_fence)?;
    assert!(matches!(
        worker
            .complete_job(&tenant, "handoff", &wrong_owner, b"{\"ok\":true}")
            .await,
        Err(HostedMarketStoreError::LeaseLost)
    ));
    let lease = HostedJobLease::new("replacement", replacement.lease_fence)?;
    assert_eq!(
        worker
            .complete_job(&tenant, "handoff", &lease, b"{\"ok\":true}")
            .await?,
        HostedJobWriteOutcome::Inserted
    );
    assert_eq!(
        worker
            .complete_job(&tenant, "handoff", &lease, b"{\"ok\":true}")
            .await?,
        HostedJobWriteOutcome::ExactReplay
    );
    assert!(matches!(
        worker
            .complete_job(&tenant, "handoff", &lease, b"{\"ok\":false}")
            .await,
        Err(HostedMarketStoreError::Conflict)
    ));
    worker
        .fail_job(
            &tenant,
            "failed",
            &HostedJobLease::new("original", job("failed")?.lease_fence)?,
            "retry",
            60,
        )
        .await?;
    assert_eq!(
        worker
            .get_job(&tenant, "failed")
            .await?
            .ok_or("job missing")?
            .state,
        HostedJobState::Failed
    );
    worker
        .exhaust_job(
            &tenant,
            "exhausted",
            &HostedJobLease::new("original", job("exhausted")?.lease_fence)?,
            "exhausted",
        )
        .await?;
    assert_eq!(
        worker
            .get_job(&tenant, "exhausted")
            .await?
            .ok_or("job missing")?
            .state,
        HostedJobState::Exhausted
    );

    // A worker cannot create jobs or disable the tenant through the runtime API.
    assert!(worker
        .put_job(
            &tenant,
            "forbidden",
            "test",
            &sha256_hex(b"{}"),
            b"{}",
            now.as_secs(),
            now.as_secs()
        )
        .await
        .is_err());
    assert!(worker.set_tenant_enabled(&tenant, false).await.is_err());
    runtime.set_tenant_enabled(&tenant, false).await?;
    let disabled_lease = HostedJobLease::new("original", job("disabled")?.lease_fence)?;
    assert!(matches!(
        worker.probe_tenant(&tenant).await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    assert!(matches!(
        worker.get_job(&tenant, "disabled").await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    assert!(matches!(
        worker.claim_due_jobs(&tenant, "replacement", 600, 1).await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    assert!(matches!(
        worker
            .renew_job_lease(&tenant, "disabled", &disabled_lease, 600)
            .await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    assert!(matches!(
        worker
            .complete_job(&tenant, "disabled", &disabled_lease, b"{}")
            .await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    assert!(matches!(
        worker
            .fail_job(&tenant, "disabled", &disabled_lease, "retry", 60)
            .await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    assert!(matches!(
        worker
            .relinquish_job_lease(&tenant, "disabled", &disabled_lease)
            .await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    assert!(matches!(
        worker
            .exhaust_job(&tenant, "disabled", &disabled_lease, "exhausted")
            .await,
        Err(HostedMarketStoreError::TenantDisabled)
    ));
    runtime.set_tenant_enabled(&tenant, true).await?;
    assert_eq!(
        worker
            .get_job(&tenant, "disabled")
            .await?
            .ok_or("job missing")?
            .state,
        HostedJobState::Leased
    );
    assert!(worker.get_job(&tenant, "forbidden").await?.is_none());
    Ok(())
}
