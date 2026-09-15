//! A stdio MCP adapter over the existing PostgreSQL job lease API.
//! The database connection uses the production role and TLS checks.

use std::error::Error;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;

use chio_finding_market_store_postgres::{
    HostedPostgresConfig, HostedTenantId, PostgresFindingMarketMigrator, PostgresFindingMarketStore,
};
use serde_json::{json, Value};

mod resource;
mod tools;

const MAX_FRAME: u64 = 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let mode = arguments
        .next()
        .ok_or("expected migrate, seed, worker or operator")?;
    let tenant = arguments.next();
    if arguments.next().is_some() {
        return Err("unexpected arguments".into());
    }
    let url =
        std::env::var("CHIO_JOB_DATABASE_URL").map_err(|_| "CHIO_JOB_DATABASE_URL is required")?;
    let ca = PathBuf::from(
        std::env::var("CHIO_JOB_DATABASE_CA").map_err(|_| "CHIO_JOB_DATABASE_CA is required")?,
    );
    let config = HostedPostgresConfig::new(url)?.with_ca_certificate(ca)?;
    if mode == "migrate" {
        PostgresFindingMarketMigrator::connect(&config)
            .await?
            .migrate()
            .await?;
        println!("{}", json!({"migrated": true}));
        return Ok(());
    }
    let tenant = HostedTenantId::new(tenant.ok_or("tenant is required")?)?;
    if mode == "seed" {
        let store = PostgresFindingMarketStore::connect(&config).await?;
        let frame = read_frame(&mut std::io::stdin().lock())?.ok_or("seed is required")?;
        let value = resource::seed(&store, &tenant, serde_json::from_slice(&frame)?).await?;
        println!("{value}");
        return Ok(());
    }
    if mode != "worker" && mode != "operator" {
        return Err("unknown adapter mode".into());
    }
    let store = PostgresFindingMarketStore::connect_worker(&config).await?;
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    while let Some(frame) = read_frame(&mut input)? {
        let request: Value = serde_json::from_slice(&frame)?;
        let Some(id) = request.get("id") else {
            continue;
        };
        let result = match request.get("method").and_then(Value::as_str) {
            Some("initialize") => json!({"protocolVersion":"2025-11-25",
                "capabilities":{"tools":{}},
                "serverInfo":{"name":"chio-postgres-jobs","version":"1"}}),
            Some("ping") => json!({}),
            Some("tools/list") => json!({"tools":tools::definitions(&mode)}),
            Some("tools/call") => {
                match resource::invoke(&store, &tenant, &mode, &request["params"]).await {
                    Ok(value) => json!({"content":[{"type":"text","text":value.to_string()}],
                        "structuredContent":value,"isError":false}),
                    Err(_) => json!({"content":[{"type":"text",
                        "text":"Resource operation failed. Do not retry an uncertain effect under a new identity."}],
                        "isError":true}),
                }
            }
            _ => {
                writeln!(
                    output,
                    "{}",
                    json!({"jsonrpc":"2.0","id":id,
                    "error":{"code":-32601,"message":"Unknown method"}})
                )?;
                output.flush()?;
                continue;
            }
        };
        writeln!(
            output,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"result":result})
        )?;
        output.flush()?;
    }
    Ok(())
}

fn read_frame(reader: &mut impl BufRead) -> std::io::Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    reader.take(MAX_FRAME + 1).read_until(b'\n', &mut frame)?;
    if frame.is_empty() {
        return Ok(None);
    }
    if frame.len() as u64 > MAX_FRAME || frame.last() != Some(&b'\n') {
        return Err(std::io::Error::other("incomplete or oversized MCP frame"));
    }
    Ok(Some(frame))
}
