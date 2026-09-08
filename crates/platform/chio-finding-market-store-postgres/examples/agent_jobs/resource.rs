use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core_types::{canonical_json_bytes, sha256_hex};
use chio_finding_market_store_postgres::{
    HostedJobLease, HostedJobWriteOutcome, HostedMarketJob, HostedMarketStoreError, HostedTenantId,
    HostedTenantLimits, PostgresFindingMarketStore,
};
use serde::Deserialize;
use serde_json::{json, Value};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    job_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    job_id: String,
    expected_fence: u64,
    result: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Renewal {
    job_id: String,
    expected_fence: u64,
    lease_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    owner_capability_sha256: String,
    lease_seconds: u64,
    limit: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    job_id: String,
    owner_capability_sha256: String,
    expected_fence: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    job_id: String,
    task: Value,
}

fn digest(value: &str) -> Result<&str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("kernel capability binding must be a lowercase SHA-256 digest".into());
    }
    Ok(value)
}

pub async fn seed(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
    input: Value,
) -> Result<Value> {
    let input: Seed = serde_json::from_value(input)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    store
        .register_tenant(
            tenant,
            &HostedTenantLimits::new(16, 100, 1_000_000, "agent-jobs-v1")?,
            now,
        )
        .await?;
    let task = canonical_json_bytes(&input.task)?;
    let outcome = store
        .put_job(
            tenant,
            &input.job_id,
            "agent-assessment",
            &sha256_hex(&task),
            &task,
            now,
            now,
        )
        .await?;
    Ok(json!({"job_id":input.job_id,"created":matches!(outcome, HostedJobWriteOutcome::Inserted)}))
}

pub async fn invoke(
    store: &PostgresFindingMarketStore,
    tenant: &HostedTenantId,
    mode: &str,
    params: &Value,
) -> Result<Value> {
    // Only a trusted kernel-owned pipe may supply this metadata. It is not a
    // credential. Worker tool arguments cannot select another lease owner.
    let caller = digest(
        params["_meta"]["chioCallerCapabilitySha256"]
            .as_str()
            .ok_or("caller binding required")?,
    )?;
    let name = params["name"].as_str().ok_or("tool name required")?;
    let arguments = params["arguments"].clone();
    let result = match (mode, name) {
        ("worker", "task") | ("operator", "inspect") => {
            let input: Job = serde_json::from_value(arguments)?;
            return match store.get_job(tenant, &input.job_id).await? {
                Some(job) => describe(job, mode == "operator"),
                None => Ok(json!({"status":"not_found"})),
            };
        }
        ("worker", "complete") => {
            let input: Completion = serde_json::from_value(arguments)?;
            if !input.result.is_object() {
                return Err("job result must be an object".into());
            }
            let lease = HostedJobLease::new(caller, input.expected_fence)?;
            store
                .complete_job(
                    tenant,
                    &input.job_id,
                    &lease,
                    &canonical_json_bytes(&input.result)?,
                )
                .await
                .map(|outcome| {
                    json!({"status": match outcome {
                        HostedJobWriteOutcome::Inserted => "completed",
                        HostedJobWriteOutcome::ExactReplay => "already_completed",
                    }})
                })
        }
        ("worker", "renew") => {
            let input: Renewal = serde_json::from_value(arguments)?;
            store
                .renew_job_lease(
                    tenant,
                    &input.job_id,
                    &HostedJobLease::new(caller, input.expected_fence)?,
                    input.lease_seconds,
                )
                .await
                .map(|renewed| json!({"status":"renewed","expires_at":renewed.expires_at}))
        }
        ("operator", "assign") => {
            let input: Assignment = serde_json::from_value(arguments)?;
            digest(&input.owner_capability_sha256)?;
            if input.limit == 0 || input.limit > 16 {
                return Err("assignment limit exceeds bounds".into());
            }
            let jobs = store
                .claim_due_jobs(
                    tenant,
                    &input.owner_capability_sha256,
                    input.lease_seconds,
                    input.limit,
                )
                .await?;
            return Ok(
                json!({"status":"assigned","jobs": jobs.into_iter().map(|job| describe(job, true)).collect::<Result<Vec<_>>>()?}),
            );
        }
        ("operator", "release") => {
            let input: Release = serde_json::from_value(arguments)?;
            digest(&input.owner_capability_sha256)?;
            store
                .relinquish_job_lease(
                    tenant,
                    &input.job_id,
                    &HostedJobLease::new(input.owner_capability_sha256, input.expected_fence)?,
                )
                .await
                .map(|()| json!({"status":"released"}))
        }
        _ => return Err("tool is not enabled on this connection".into()),
    };
    match result {
        Ok(value) => Ok(value),
        Err(HostedMarketStoreError::LeaseLost) => Ok(json!({"status":"superseded"})),
        Err(HostedMarketStoreError::Conflict) => Ok(json!({"status":"result_conflict"})),
        Err(HostedMarketStoreError::NotFound) => Ok(json!({"status":"not_found"})),
        Err(error) => Err(error.into()),
    }
}

fn describe(job: HostedMarketJob, operator: bool) -> Result<Value> {
    let task: Value = serde_json::from_slice(&job.payload_json)?;
    let result = job
        .result_json
        .as_deref()
        .map(serde_json::from_slice::<Value>)
        .transpose()?;
    let mut value = json!({"job_id":job.job_id,"state":job.state,"task":task,
        "lease_fence":job.lease_fence,"lease_expires_at":job.lease_expires_at,
        "result":result,"payload_sha256":job.payload_sha256,"result_sha256":job.result_sha256});
    if operator {
        value["owner_capability_sha256"] = json!(job.lease_owner);
    }
    Ok(value)
}
