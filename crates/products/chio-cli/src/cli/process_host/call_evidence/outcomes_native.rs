//! Bind each observed MCP response to its original signed launch reference.
//! A recovery refusal can reference a recovery connection, not the earlier effect.

use super::*;

pub(super) fn pins(values: &[String]) -> Result<BTreeMap<String, PublicKey>, CliError> {
    let mut pins = BTreeMap::new();
    for value in values {
        let (server, key) = value
            .split_once('=')
            .ok_or_else(|| error("native policy pin must be SERVER=PUBLIC_KEY"))?;
        super::super::super::state::identifier(server)?;
        require(
            pins.insert(server.to_owned(), PublicKey::from_hex(key).map_err(error)?)
                .is_none(),
            "duplicate native policy signer pin",
        )?;
    }
    Ok(pins)
}

fn response(call: &ChioReceipt) -> Result<ChioReceipt, CliError> {
    crate::input::text(
        call.action.parameters["response"]["receipt_json"]
            .as_str()
            .ok_or_else(|| error("missing observed response receipt"))?,
    )
}

pub(super) fn verify(
    run: &Outcomes,
    pins: &BTreeMap<String, PublicKey>,
) -> Result<BTreeMap<String, Value>, CliError> {
    let mut used = BTreeSet::new();
    let mut servers = BTreeSet::new();
    let mut reports = BTreeMap::new();
    for (worker, signed_call) in &run.calls {
        let call = response(signed_call)?;
        let metadata = call
            .metadata
            .as_ref()
            .ok_or_else(|| error("missing call metadata"))?;
        let reference = &metadata["native_launch"];
        if reference.is_null() {
            require(
                metadata["route"]["bridge"] != "mcp",
                "MCP response lacks its actual native launch reference",
            )?;
            continue;
        }
        let id = reference["receipt_id"]
            .as_str()
            .ok_or_else(|| error("missing native receipt ID"))?;
        let launch = run
            .confinement
            .get(id)
            .ok_or_else(|| error("referenced native launch is absent"))?;
        require(
            launch.enforcement.id == id
                && reference["receipt_sha256"] == hash(&launch.enforcement)?,
            "native launch differs from original signed response reference",
        )?;
        let key = pins
            .get(&call.tool_server)
            .ok_or_else(|| error("missing external native policy signer pin"))?;
        let mut window =
            crate::mcp_cli::verify_native_launch_observation(launch, &call.tool_server, key)?;
        let server = run
            .host_record
            .config
            .servers
            .iter()
            .find(|server| server.id == call.tool_server)
            .ok_or_else(|| error("native server absent from original host record"))?;
        let manifest = run
            .host_record
            .manifests
            .iter()
            .find(|manifest| manifest.server_id == call.tool_server)
            .ok_or_else(|| error("native manifest absent from original host record"))?;
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
                && metadata["route"]["selectedRoute"] == format!("mcp:{}", call.tool_server)
                && metadata["route"]["bridge"] == "mcp",
            "native policy bytes differ from signed response route",
        )?;
        require(
            window.tools.contains(&call.tool_name)
                && call.timestamp >= window.started_at_unix_ms / 1000
                && call.timestamp <= run.observed_at_unix_ms / 1000
                && window
                    .exited_at_unix_ms
                    // An interrupted response is signed after observing the process exit.
                    .is_none_or(|exit| {
                        matches!(call.decision, Some(Decision::Incomplete { .. }))
                            || call.timestamp <= exit / 1000
                    })
                && launch
                    .terminal
                    .as_ref()
                    .is_none_or(|terminal| terminal.timestamp <= run.observed_at_unix_ms / 1000),
            "response is outside native tool surface or observed lifetime",
        )?;
        used.insert(id.to_owned());
        servers.insert(call.tool_server.clone());
        reports.insert(
            worker.clone(),
            json!({
                "receipt_id": id, "server_id": call.tool_server,
                "started_at_unix_ms": window.started_at_unix_ms,
                "exited_at_unix_ms": window.exited_at_unix_ms,
                "terminal_verified": launch.terminal.is_some(),
                "scope": "original_signed_response_connection",
            }),
        );
    }
    require(
        used == run.confinement.keys().cloned().collect(),
        "unreferenced confinement evidence",
    )?;
    require(
        servers == pins.keys().cloned().collect(),
        "native signer pin inventory differs from referenced servers",
    )?;
    Ok(reports)
}

#[cfg(target_os = "linux")]
pub(super) struct Exported {
    pub confinement: BTreeMap<String, crate::mcp_cli::NativeLaunchObservation>,
    pub pins: BTreeMap<String, PublicKey>,
}

#[cfg(target_os = "linux")]
pub(super) fn export(
    config: &super::super::super::state::Config,
    calls: &BTreeMap<String, ChioReceipt>,
) -> Result<Exported, CliError> {
    let mut references = BTreeMap::<String, BTreeSet<String>>::new();
    for observed in calls.values() {
        let call = response(observed)?;
        if let Some(id) = call
            .metadata
            .as_ref()
            .and_then(|metadata| metadata["native_launch"]["receipt_id"].as_str())
        {
            references
                .entry(call.tool_server)
                .or_default()
                .insert(id.to_owned());
        }
    }
    let mut confinement = BTreeMap::new();
    let mut pins = BTreeMap::new();
    for (server_id, ids) in references {
        let server = config
            .servers
            .iter()
            .find(|server| server.id == server_id)
            .ok_or_else(|| error("native server absent from operator configuration"))?;
        let key = PublicKey::from_hex(
            server
                .launch_policy_signer
                .as_deref()
                .ok_or_else(|| error("missing configured native signer"))?,
        )?;
        let policy = server
            .launch_policy
            .as_deref()
            .ok_or_else(|| error("missing configured native policy"))?;
        for (id, launch) in
            crate::mcp_cli::export_native_launch_observations(policy, &server_id, &key, &ids)?
        {
            require(
                confinement.insert(id, launch).is_none(),
                "duplicate native launch across servers",
            )?;
        }
        pins.insert(server_id, key);
    }
    Ok(Exported { confinement, pins })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historical_signed_outcomes_do_not_qualify_current_enforcement(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = PublicKey::from_hex(
            include_str!("../../../../tests/fixtures/process-worker-outcomes/v2-budget-kernel.pub")
                .trim(),
        )?;
        // The original signed evidence carries a retired launch policy schema id;
        // its valid signature cannot qualify the current enforcement contract.
        let signed = crate::receipt_verify::verify_original_receipt(
            include_str!("../../../../tests/fixtures/process-worker-outcomes/v2-budget.json"),
            &key,
        )?;
        let selected: Value = crate::input::text(include_str!(
            "../../../../tests/fixtures/process-worker-outcomes/v2-budget-pins.json"
        ))?;
        let pins: BTreeMap<String, PublicKey> = selected["launch_policy_signers"]
            .as_object()
            .ok_or("pins")?
            .iter()
            .map(|(server, value)| {
                Ok((
                    server.clone(),
                    PublicKey::from_hex(value.as_str().ok_or("key")?)?,
                ))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;
        let runtime = selected["runtime_id"].as_str().ok_or("runtime")?;
        let run: Outcomes = serde_json::from_value(signed.action.parameters.clone())?;
        assert!(super::super::verify_outcomes(&signed, &run, &key, runtime, &pins).is_err());
        let error = verify(&run, &pins)
            .err()
            .ok_or("accepted historical evidence from obsolete enforcement")?;
        assert_eq!(
            error.to_string(),
            CliError::cli_other_error(
                "failed to parse cage launch policy exported-launch-policy: \
                 urn:chio:error:attest:signed-json-invalid-shape"
            )
            .to_string()
        );
        Ok(())
    }

    #[test]
    fn retained_crash_outcomes_bind_actual_launches_without_inventing_exits(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = PublicKey::from_hex(
            include_str!("../../../../tests/fixtures/process-worker-outcomes/current-native-budget-kernel.pub")
                .trim(),
        )?;
        let signed = crate::receipt_verify::verify_original_receipt(
            include_str!(
                "../../../../tests/fixtures/process-worker-outcomes/current-native-budget.json"
            ),
            &key,
        )?;
        let selected: Value = crate::input::text(include_str!(
            "../../../../tests/fixtures/process-worker-outcomes/current-native-budget-pins.json"
        ))?;
        let pins: BTreeMap<String, PublicKey> = selected["launch_policy_signers"]
            .as_object()
            .ok_or("pins")?
            .iter()
            .map(|(server, value)| {
                Ok((
                    server.clone(),
                    PublicKey::from_hex(value.as_str().ok_or("key")?)?,
                ))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;
        let runtime = selected["runtime_id"].as_str().ok_or("runtime")?;
        let run: Outcomes = serde_json::from_value(signed.action.parameters.clone())?;
        super::super::verify_outcomes(&signed, &run, &key, runtime, &pins)?;
        let report = verify(&run, &pins)?;
        assert_eq!(report.len(), 4);
        // Every attested response replays a receipt naming the original launch,
        // which host death killed before any exit was recorded.
        for worker in ["alice", "bob", "carol", "dave"] {
            assert_eq!(report[worker]["terminal_verified"], false, "{worker}");
        }
        assert!(verify(&run, &BTreeMap::new()).is_err());
        let mut extra_pin = pins.clone();
        extra_pin.insert("unused-server".into(), key.clone());
        assert!(verify(&run, &extra_pin).is_err());
        let mut wrong_pin = pins.clone();
        wrong_pin.insert("alice-probe".into(), key);
        assert!(verify(&run, &wrong_pin).is_err());

        // Test the native composition boundary after the original signatures
        // above passed. Substituted receipts retain their valid native signatures.
        let alice = report["alice"]["receipt_id"].as_str().ok_or("alice")?;
        let carol = report["carol"]["receipt_id"].as_str().ok_or("carol")?;
        let params = &signed.action.parameters;
        // A genuine signed exit of another campaign's launch.
        let foreign: Value = crate::input::text(include_str!(
            "../../../../tests/fixtures/process-worker-outcomes/v2-budget.json"
        ))?;
        let foreign_exit = foreign["action"]["parameters"]["confinement"]
            .as_object()
            .ok_or("foreign confinement")?
            .values()
            .find_map(|launch| (!launch["terminal"].is_null()).then(|| launch["terminal"].clone()))
            .ok_or("foreign signed exit")?;
        let cases = [
            ("/confinement".to_owned(), json!({})),
            (
                format!("/confinement/{alice}/enforcement"),
                params["confinement"][carol]["enforcement"].clone(),
            ),
            (
                format!("/confinement/{alice}/terminal"),
                foreign_exit.clone(),
            ),
            (
                format!("/confinement/{carol}/terminal"),
                params["confinement"][carol]["enforcement"].clone(),
            ),
            (
                format!("/confinement/{alice}/signed_policy"),
                json!(format!("{}\n", run.confinement[alice].signed_policy)),
            ),
            (
                "/host_record/config/servers/0/command".into(),
                json!(["/bin/another-tool"]),
            ),
            ("/host_record/manifests/0/tools".into(), json!([])),
            ("/observed_at_unix_ms".into(), json!(1)),
        ];
        for (pointer, value) in cases {
            let mut changed = params.clone();
            *changed.pointer_mut(&pointer).ok_or("mutation target")? = value;
            let changed: Outcomes = serde_json::from_value(changed)?;
            assert!(verify(&changed, &pins).is_err(), "accepted {pointer}");
        }
        let mut changed: Outcomes = serde_json::from_value(params.clone())?;
        changed
            .confinement
            .insert("unreferenced".into(), run.confinement[alice].clone());
        assert!(verify(&changed, &pins).is_err());

        // An exit cannot be supplied for a launch that never recorded one.
        let mut changed = params.clone();
        *changed
            .pointer_mut(&format!("/confinement/{carol}/terminal"))
            .ok_or("carol terminal")? = foreign_exit;
        let changed: Outcomes = serde_json::from_value(changed)?;
        assert!(verify(&changed, &pins).is_err());
        Ok(())
    }

    #[test]
    fn clean_exit_outcome_verifies_its_actual_launch_exit() -> Result<(), Box<dyn std::error::Error>>
    {
        let key = PublicKey::from_hex(
            include_str!("../../../../tests/fixtures/process-worker-outcomes/current-native-clean-kernel.pub")
                .trim(),
        )?;
        let signed = crate::receipt_verify::verify_original_receipt(
            include_str!(
                "../../../../tests/fixtures/process-worker-outcomes/current-native-clean.json"
            ),
            &key,
        )?;
        let selected: Value = crate::input::text(include_str!(
            "../../../../tests/fixtures/process-worker-outcomes/current-native-clean-pins.json"
        ))?;
        let pins: BTreeMap<String, PublicKey> = selected["launch_policy_signers"]
            .as_object()
            .ok_or("pins")?
            .iter()
            .map(|(server, value)| {
                Ok((
                    server.clone(),
                    PublicKey::from_hex(value.as_str().ok_or("key")?)?,
                ))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;
        let runtime = selected["runtime_id"].as_str().ok_or("runtime")?;
        let run: Outcomes = serde_json::from_value(signed.action.parameters.clone())?;
        super::super::verify_outcomes(&signed, &run, &key, runtime, &pins)?;
        let report = verify(&run, &pins)?;
        assert_eq!(report.len(), 2);
        assert_eq!(report["erin"]["terminal_verified"], true);
        assert_eq!(report["frank"]["terminal_verified"], true);

        let erin = report["erin"]["receipt_id"].as_str().ok_or("erin")?;
        let frank = report["frank"]["receipt_id"].as_str().ok_or("frank")?;
        let params = &signed.action.parameters;
        let mut matching = params.clone();
        *matching
            .pointer_mut(&format!("/confinement/{erin}/terminal"))
            .ok_or("erin terminal")? = params["confinement"][erin]["terminal"].clone();
        let matching: Outcomes = serde_json::from_value(matching)?;
        assert_eq!(verify(&matching, &pins)?["erin"]["terminal_verified"], true);

        let foreign: Value = crate::input::text(include_str!(
            "../../../../tests/fixtures/process-worker-outcomes/v2-budget.json"
        ))?;
        let foreign_exit = foreign["action"]["parameters"]["confinement"]
            .as_object()
            .ok_or("foreign confinement")?
            .values()
            .find_map(|launch| (!launch["terminal"].is_null()).then(|| launch["terminal"].clone()))
            .ok_or("foreign signed exit")?;
        for substituted in [
            foreign_exit,
            params["confinement"][frank]["terminal"].clone(),
        ] {
            let mut changed = params.clone();
            *changed
                .pointer_mut(&format!("/confinement/{erin}/terminal"))
                .ok_or("erin terminal")? = substituted;
            let changed: Outcomes = serde_json::from_value(changed)?;
            assert!(verify(&changed, &pins).is_err());
        }

        let mut withheld: Outcomes = serde_json::from_value(params.clone())?;
        withheld
            .confinement
            .get_mut(erin)
            .ok_or("erin launch")?
            .terminal = None;
        let withheld = verify(&withheld, &pins)?;
        assert_eq!(withheld["erin"]["terminal_verified"], false);
        assert_eq!(withheld["frank"]["terminal_verified"], true);
        Ok(())
    }
}
