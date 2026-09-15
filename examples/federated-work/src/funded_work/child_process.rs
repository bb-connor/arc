//! Owned native parent loss, followed by collection using only child authority.
use super::{
    child,
    local_chain::LocalChain,
    native::Native,
    process::{Server, SocketSource},
    smoke::setup_on_chain,
};
use crate::common::{self, Result};
use chio_core_types::Keypair;
use serde_json::{json, Value};
use std::{
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
};

pub fn parent_worker(state: &Path) -> Result<Value> {
    let parent_source = Arc::new(SocketSource(state.join("parent.sock")));
    let child_source = Arc::new(SocketSource(state.join("child.sock")));
    let agreement: super::agreement::SignedAgreement =
        common::read(state.join("child/original-agreement.json"))?;
    let allocation = super::allocation::allocation_id(
        &agreement.body.domain.chain_id,
        &agreement.body.domain.escrow,
        &agreement.body.terms()?,
    )?;
    let advance_source = child_source.clone();
    let subcontract = child::executor(
        state,
        child_source,
        Arc::new(move |phase| {
            advance_source
                .request(&json!({"method":"advance","allocation":allocation,"phase":phase}))?;
            Ok(())
        }),
    )?;
    let native = Native::open_configured(
        &state.join("parent"),
        parent_source,
        Arc::new(|point| {
            if point == "after-tool" {
                common::crash()
            } else {
                Ok(())
            }
        }),
        Some(subcontract),
    )?;
    native.execute(
        &common::read(state.join("parent/original-agreement.json"))?,
        &common::read(state.join("parent/original-request.json"))?,
    )
}

pub fn collect_worker(state: &Path, socket: &Path, fault: &str) -> Result<Value> {
    let point = match fault {
        "none" => "none",
        "pay-after-prepare" => "after-prepare",
        "pay-after-broadcast" => "after-broadcast",
        "pay-after-observation" => "after-observation",
        _ => return Err("unsupported child collection checkpoint".into()),
    };
    child::collect(
        state,
        Arc::new(SocketSource(socket.to_owned())),
        Arc::new(move |current| {
            if current == point {
                common::crash()
            } else {
                Ok(())
            }
        }),
    )
}

fn check_child_output(output: std::process::Output) -> Result<Value> {
    if !output.status.success() {
        return Err(format!(
            "child collector failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

pub fn run(state: &Path, fault: &str) -> Result<Value> {
    if ![
        "none",
        "pay-after-prepare",
        "pay-after-broadcast",
        "pay-after-observation",
    ]
    .contains(&fault)
    {
        return Err("unsupported child process-loss scenario".into());
    }
    match std::fs::symlink_metadata(state) {
        Ok(meta) if meta.is_dir() && std::fs::read_dir(state)?.next().is_none() => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(state)?
        }
        _ => return Err("earned child requires an empty disposable directory".into()),
    }
    let chain = Arc::new(LocalChain::start()?);
    let setup = chain.request(json!({"method":"initialize"}))?;
    let parent = setup_on_chain(
        &state.join("parent"),
        chain.clone(),
        &setup,
        &Keypair::generate(),
        "funded-native-parent",
    )?;
    let child_setup = chain.request(json!({"method":"initialize-child"}))?;
    let child = setup_on_chain(
        &state.join("child"),
        chain.clone(),
        &child_setup,
        &common::key(&state.join("parent"))?,
        "funded-native-child",
    )?;
    child::retain(state, &parent, &child)?;
    for scenario in [&parent, &child] {
        chain.request(json!({"method":"pin-verifier","allocation":scenario.funding["allocationId"],"key":scenario.native.policy.verifier_key.to_hex()}))?;
    }
    let parent_request = parent.request;
    let child_request = child.request;
    let parent_id = parent.funding["allocationId"]
        .as_str()
        .ok_or("parent allocation missing")?
        .to_owned();
    let child_id = child.funding["allocationId"]
        .as_str()
        .ok_or("child allocation missing")?
        .to_owned();
    drop(parent.native);
    drop(child.native);
    let parent_socket = state.join("parent.sock");
    let child_socket = state.join("child.sock");
    let mut parent_server = Server::start(&parent_socket, parent_id.clone(), chain.clone())?;
    let mut child_server = Server::start(&child_socket, child_id.clone(), chain.clone())?;
    let killed = Command::new(std::env::current_exe()?)
        .arg("experimental-funded-parent-worker")
        .arg(state)
        .stdin(Stdio::null())
        .output()?;
    if killed.status.signal() != Some(9) {
        return Err(format!(
            "parent did not reach the earned-child SIGKILL boundary: {}",
            String::from_utf8_lossy(&killed.stderr)
        )
        .into());
    }
    parent_server.finish()?;
    let earned = chain.request(json!({"method":"summary","allocation":child_id}))?;
    if earned["state"] != "Payable" || earned["paid"] != "0" {
        return Err("child was not independently payable and unpaid at parent loss".into());
    }
    let parent_native = Native::open(&state.join("parent"), chain.clone())?;
    let original_parent = parent_native.report(&parent_request)?;
    let child_native = Native::open(&state.join("child"), chain.clone())?;
    let original_child = child_native.report(&child_request)?;
    drop(child_native);
    let no_fault: super::Checkpoint = Arc::new(|_| Ok(()));
    super::lifecycle::progress(
        &state.join("parent"),
        &parent_native,
        &parent_request,
        "absent",
        &no_fault,
        &|phase| {
            chain.request(json!({"method":"advance","allocation":parent_id,"phase":phase}))?;
            Ok(())
        },
    )?;
    let parent_report = parent_native.report(&parent_request)?;
    drop(parent_native);
    let after_parent_refund = json!({"parent":chain.request(json!({"method":"summary","allocation":parent_id}))?,
        "child":chain.request(json!({"method":"summary","allocation":child_id}))?});
    let retired = chain.request(json!({"method":"retire-parent"}))?;
    // Exercise the retired signers as negative controls. Collection below must
    // succeed despite both the parent refund signer and child verifier denying.
    use super::observer::FundingSource;
    for (role, request, action) in [
        ("parent", &parent_request, super::settlement::Action::Refund),
        ("child", &child_request, super::settlement::Action::Record),
    ] {
        let native = Native::open(&state.join(role), chain.clone())?;
        let entry = native
            .journal
            .by_request(&request.request_id)?
            .ok_or("retirement original entry missing")?;
        let action = super::settlement::request(&entry, action, &native.policy, &native.journal)?;
        let error = match chain.prepare(&action) {
            Ok(_) => return Err("retired parent or verifier signed new authority".into()),
            Err(error) => error,
        };
        if !error.to_string().contains("signing authority retired") {
            return Err(format!("retirement control failed for another reason: {error}").into());
        }
    }
    let collect = |fault: &str| -> Result<std::process::Output> {
        Command::new(std::env::current_exe()?)
            .arg("experimental-funded-child-collector")
            .arg(state.join("child"))
            .arg(&child_socket)
            .arg(fault)
            .stdin(Stdio::null())
            .output()
            .map_err(Into::into)
    };
    let result: std::process::Output = collect(fault)?;
    let killed_signal = if fault == "none" {
        None
    } else {
        if result.status.signal() != Some(9) {
            return Err(format!(
                "child payout checkpoint did not SIGKILL: {}",
                String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        Some(9)
    };
    let collected = check_child_output(if killed_signal.is_some() {
        collect("none")?
    } else {
        result
    })?;
    // A further independently started collector must retain the exact payout.
    let replay = check_child_output(collect("none")?)?;
    if replay != collected {
        return Err("child collection changed after successful recovery".into());
    }
    child_server.finish()?;
    let final_state = json!({"parent":chain.request(json!({"method":"summary","allocation":parent_id}))?,
        "child":chain.request(json!({"method":"summary","allocation":child_id}))?,
        "balances":chain.request(json!({"method":"family-balances"}))?});
    Ok(
        json!({"parentKilledSignal":9,"childPayKilledSignal":killed_signal,"earned":earned,
        "original":{"parent":original_parent,"child":original_child},"parent":parent_report,"child":collected["replay"],
        "afterParentRefund":after_parent_refund,"retired":retired,"final":final_state}),
    )
}
