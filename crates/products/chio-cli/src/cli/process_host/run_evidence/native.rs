//! Join the call's signed host observation to the original cage launch and exit.

use std::collections::BTreeSet;

use super::*;

pub(super) fn pins(values: &[String]) -> Result<BTreeMap<String, PublicKey>, CliError> {
    let mut pins = BTreeMap::new();
    for value in values {
        let (server, key) = value
            .split_once('=')
            .ok_or_else(|| error("native policy pin must be SERVER=PUBLIC_KEY"))?;
        super::super::state::identifier(server)?;
        require(
            pins.insert(server.to_string(), PublicKey::from_hex(key).map_err(error)?)
                .is_none(),
            "duplicate native policy signer pin",
        )?;
    }
    Ok(pins)
}

pub(super) fn verify(
    evidence: &Evidence,
    pins: &BTreeMap<String, PublicKey>,
) -> Result<(), CliError> {
    let mut used = BTreeSet::new();
    for call in evidence.results.values() {
        let receipt: ChioReceipt = serde_json::from_str(
            call.response["receipt_json"]
                .as_str()
                .ok_or_else(|| error("missing completed tool receipt"))?,
        )
        .map_err(error)?;
        let metadata = receipt
            .metadata
            .as_ref()
            .ok_or_else(|| error("missing call metadata"))?;
        let reference = &metadata["native_launch"];
        if reference.is_null() {
            require(
                metadata["route"]["bridge"] != "mcp",
                "MCP call is missing its actual launch receipt",
            )?;
            continue;
        }
        let id = reference["receipt_id"]
            .as_str()
            .ok_or_else(|| error("missing native receipt ID"))?;
        let launch = evidence
            .confinement
            .get(id)
            .ok_or_else(|| error("referenced native launch evidence is absent"))?;
        require(
            launch.enforcement.id == id
                && reference["receipt_sha256"] == hash(&launch.enforcement)?,
            "native launch receipt digest differs from tool receipt",
        )?;
        let key = pins
            .get(&receipt.tool_server)
            .ok_or_else(|| error("missing external native policy signer pin"))?;
        let mut window =
            crate::mcp_cli::verify_native_launch_evidence(launch, &receipt.tool_server, key)?;
        let server = evidence
            .host_record
            .config
            .servers
            .iter()
            .find(|server| server.id == receipt.tool_server)
            .ok_or_else(|| error("native server is absent from original host record"))?;
        let manifest = evidence
            .host_record
            .manifests
            .iter()
            .find(|manifest| manifest.server_id == receipt.tool_server)
            .ok_or_else(|| error("native manifest is absent from original host record"))?;
        window.manifest.tools.sort_by(|a, b| a.name.cmp(&b.name));
        require(
            hash(&window.manifest)? == hash(manifest)?
                && server.command == window.target_argv
                && server.launch_policy_signer.as_deref() == Some(key.to_hex().as_str()),
            "native policy differs from original host configuration",
        )?;
        let route = hash(&(
            server,
            hash(manifest)?,
            sha256_hex(launch.signed_policy.as_bytes()),
        ))?;
        require(
            metadata["route"]["protocolTarget"] == format!("mcp://sha256/{route}")
                && metadata["route"]["selectedRoute"] == format!("mcp:{}", receipt.tool_server)
                && metadata["route"]["bridge"] == "mcp",
            "native policy bytes differ from the admitted route",
        )?;
        require(
            window.tools.contains(&receipt.tool_name)
                && receipt.timestamp >= window.started_at_unix_ms / 1000
                && receipt.timestamp <= window.exited_at_unix_ms / 1000
                && launch.terminal.timestamp <= evidence.authority.now_unix_ms / 1000,
            "tool call is outside the signed launch surface or lifetime",
        )?;
        used.insert(id.to_string());
    }
    require(
        used == evidence.confinement.keys().cloned().collect(),
        "unreferenced confinement evidence",
    )
}

#[cfg(target_os = "linux")]
pub(super) struct ExportedLaunches {
    pub(super) confinement: BTreeMap<String, crate::mcp_cli::NativeLaunchEvidence>,
    pub(super) pins: BTreeMap<String, PublicKey>,
}

#[cfg(target_os = "linux")]
pub(super) fn export(
    config: &super::super::state::Config,
    results: &BTreeMap<String, CompletedCall>,
) -> Result<ExportedLaunches, CliError> {
    let mut references = BTreeMap::<String, BTreeSet<String>>::new();
    for call in results.values() {
        let receipt: ChioReceipt = serde_json::from_str(
            call.response["receipt_json"]
                .as_str()
                .ok_or_else(|| error("missing completed tool receipt"))?,
        )
        .map_err(error)?;
        if let Some(id) = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata["native_launch"]["receipt_id"].as_str())
        {
            references
                .entry(receipt.tool_server)
                .or_default()
                .insert(id.to_string());
        }
    }
    let mut launches = BTreeMap::new();
    let mut pins = BTreeMap::new();
    for (server_id, ids) in references {
        let server = config
            .servers
            .iter()
            .find(|server| server.id == server_id)
            .ok_or_else(|| error("native receipt server is absent from operator configuration"))?;
        let key = PublicKey::from_hex(
            server
                .launch_policy_signer
                .as_deref()
                .ok_or_else(|| error("missing configured native signer"))?,
        )
        .map_err(error)?;
        let policy = server
            .launch_policy
            .as_deref()
            .ok_or_else(|| error("missing configured native policy"))?;
        for (id, launch) in
            crate::mcp_cli::export_native_launch_evidence(policy, &server_id, &key, &ids)?
        {
            require(
                launches.insert(id, launch).is_none(),
                "duplicate native launch across servers",
            )?;
        }
        pins.insert(server_id, key);
    }
    Ok(ExportedLaunches {
        confinement: launches,
        pins,
    })
}
