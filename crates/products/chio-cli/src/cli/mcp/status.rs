//! Inspect adopted client configuration and local kernel evidence without
//! launching a tool server or changing configuration, policy, or receipt rows.

use super::*;
use serde_json::{json, Value};

use super::adoption_bundle as config;
#[path = "status/receipts.rs"]
mod receipts;

#[derive(clap::Args, Debug)]
pub(crate) struct McpStatusArgs {
    /// Adoption directory produced by chio mcp adopt.
    #[arg(long, value_name = "DIR")]
    pub(crate) adoption: PathBuf,
    /// Actual client configuration to compare with the generated launch entries.
    #[arg(long, value_name = "FILE")]
    pub(crate) config: PathBuf,
    /// Explicitly permit reading all local receipts in each adopted server's database.
    #[arg(long)]
    pub(crate) admin_all: bool,
    /// Maximum number of recent receipts to verify per server.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub(crate) limit: u32,
}

fn invalid(message: impl Into<String>) -> CliError {
    CliError::cli_other_error(message.into())
}

pub(crate) fn cmd_mcp_status(args: &McpStatusArgs, json_output: bool) -> Result<(), CliError> {
    let (adoption, template) = config::load_adoption(&args.adoption)?;
    let (client, _) = super::adopt::load_config(&args.config)?;
    let entries = client
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("client config must contain an mcpServers object"))?;
    if entries.len() > 128 {
        return Err(invalid("client config exceeds 128 servers"));
    }
    let policy = load_policy(&adoption.policy_path).ok();
    let mut issues = Vec::new();
    let policy_report = match policy.as_ref() {
        Some(policy) => {
            let durable = policy.kernel.durable_admission_mode
                != chio_kernel::admission_operation::DurableAdmissionMode::Off;
            if !durable {
                issues.push("policy_durable_admission_disabled".to_owned());
            }
            json!({
                "status": if durable { "valid" } else { "durable_admission_disabled" },
                "source_hash": policy.identity.source_hash,
                "runtime_hash": policy.identity.runtime_hash,
                "changed_since_adoption": policy.identity.source_hash != adoption.policy_source_hash
                    || policy.identity.runtime_hash != adoption.policy_runtime_hash,
            })
        }
        None => {
            issues.push("policy_unreadable_or_invalid".to_owned());
            json!({"status": "unreadable_or_invalid"})
        }
    };
    let mut servers = Vec::new();
    for server in &adoption.wrapped_servers {
        let expected = &template["mcpServers"][&server.server];
        let actual = entries.get(&server.server);
        let configuration = match actual {
            None => "missing",
            Some(entry) if entry.get("disabled") == Some(&Value::Bool(true)) => "disabled",
            Some(entry) if entry != expected => "changed",
            Some(_) => "matches_adoption",
        };
        if configuration != "matches_adoption" {
            issues.push(format!("{}: config_{configuration}", server.server));
        }
        let binary_available = config::executable_available(expected);
        if !binary_available {
            issues.push(format!("{}: kernel_executable_unavailable", server.server));
        }
        let evidence = if args.admin_all {
            match receipts::inspect(
                server,
                args.limit,
                policy.as_ref().map(|p| p.identity.runtime_hash.as_str()),
            ) {
                Ok(evidence) => evidence,
                Err(code) => {
                    issues.push(format!("{}: {code}", server.server));
                    json!({"status": "verification_failed", "error": code})
                }
            }
        } else {
            json!({"status": "not_inspected", "reason": "requires_admin_all"})
        };
        servers.push(json!({
            "server": server.server, "configuration": configuration,
            "kernel_executable_available": binary_available, "receipts": evidence,
        }));
    }
    let outside: Vec<_> = entries
        .keys()
        .filter(|name| !adoption.wrapped_servers.iter().any(|s| &s.server == *name))
        .collect();
    let report = json!({
        "schema": "chio.mcp.status.v1", "policy": policy_report,
        "servers": servers, "servers_outside_this_adoption": outside,
        "receipt_limit_per_server": args.limit, "issues": issues,
        "live_client_connection_checked": false,
        "complete_history_verified": false,
    });
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human(&report, args.admin_all);
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(invalid("MCP adoption status found issues; see the report"))
    }
}

fn print_human(report: &Value, inspected_receipts: bool) {
    println!("MCP adoption status");
    println!(
        "Policy: {}",
        report["policy"]["status"].as_str().unwrap_or("unknown")
    );
    if report["policy"]["changed_since_adoption"] == true {
        println!("  Policy changed since adoption; recent receipts show whether it was used.");
    }
    if let Some(servers) = report["servers"].as_array() {
        for server in servers {
            let receipt = &server["receipts"];
            println!(
                "{}: {}; receipts: {} ({} verified)",
                server["server"].as_str().unwrap_or("unknown"),
                server["configuration"].as_str().unwrap_or("unknown"),
                receipt["status"].as_str().unwrap_or("unknown"),
                receipt["verified"].as_u64().unwrap_or(0)
            );
            if let Some(recent) = receipt["recent"].as_array() {
                for item in recent {
                    let timestamp = item["timestamp"]
                        .as_u64()
                        .and_then(|value| i64::try_from(value).ok())
                        .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
                        .map(|value| value.to_rfc3339())
                        .unwrap_or_else(|| item["timestamp"].to_string());
                    println!(
                        "  {} {} {} {}",
                        timestamp, item["tool"], item["outcome"], item["id"]
                    );
                }
            }
        }
    }
    if let Some(outside) = report["servers_outside_this_adoption"]
        .as_array()
        .filter(|a| !a.is_empty())
    {
        println!("Servers outside this adoption: {}", json!(outside));
    }
    if let Some(issues) = report["issues"].as_array() {
        for issue in issues {
            println!("Issue: {}", issue.as_str().unwrap_or("unknown"));
        }
    }
    if !inspected_receipts {
        println!("Use --admin-all to inspect local receipts.");
    }
    println!("Live client connection and complete history: not checked.");
}
