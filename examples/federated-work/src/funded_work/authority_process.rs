//! Owned-chain reproduction with keys generated in their originating role paths.
use super::{
    agreement::{Agreement, WorkTerms, AGREEMENT_SCHEMA},
    authority_enrollment::Pins,
    checkpoint_files as files, checkpoint_operator, evidence,
    local_chain::LocalChain,
    native::Native,
    observer::{Domain, FundingSource},
    settlement::{self, Action},
    verifier_operator,
};
use crate::common::{self, digest, Result};
use chio_core_types::PublicKey;
use serde_json::{json, Value};
use std::{ffi::OsStr, fs, path::Path, process::Command, sync::Arc};

fn command(args: &[&OsStr]) -> Result<Value> {
    let output = Command::new(std::env::current_exe()?).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "authority participant failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn generate(state: &Path) -> Result<PublicKey> {
    Ok(serde_json::from_value(
        command(&["init".as_ref(), state.as_os_str()])?["publicKey"].clone(),
    )?)
}

pub fn run(root: &Path, mode: &str) -> Result<Value> {
    run_inner(root, mode, false)
}

pub fn run_peer(root: &Path, mode: &str) -> Result<Value> {
    run_inner(root, mode, true)
}

fn run_inner(root: &Path, mode: &str, peer: bool) -> Result<Value> {
    if !["pay", "reject"].contains(&mode) {
        return Err("authority lifecycle supports pay or reject".into());
    }
    let provider = root.join("provider");
    let buyer = root.join("buyer");
    let operator = root.join("checkpoint-operator");
    let verifier = root.join("verifier");
    let governance = root.join("governance");
    let pins = Pins {
        buyer: generate(&buyer)?,
        provider: generate(&provider)?,
        verifier: generate(&verifier)?,
        checkpoint: generate(&operator.join("checkpoint"))?,
        status: generate(&operator.join("status"))?,
        governance: generate(&governance)?,
    };
    files::write(&root.join("authority-pins.json"), &pins)?;
    let expires = (common::now()? + 3600).to_string();
    command(&[
        "experimental-authority-context".as_ref(),
        governance.as_os_str(),
        operator.join("status").as_os_str(),
        root.join("authority-pins.json").as_os_str(),
        expires.as_ref(),
        root.join("context.json").as_os_str(),
    ])?;
    let chain = Arc::new(LocalChain::start()?);
    let setup = chain.request(json!({"method":"initialize"}))?;
    let domain: Domain = serde_json::from_value(setup["domain"].clone())?;
    let work: WorkTerms = serde_json::from_value(setup["work"].clone())?;
    files::write(&root.join("domain.json"), &domain)?;
    command(&[
        "experimental-provider-enroll".as_ref(),
        provider.as_os_str(),
        root.join("authority-pins.json").as_os_str(),
        root.join("context.json").as_os_str(),
        root.join("domain.json").as_os_str(),
    ])?;
    let native = Native::open(&provider, chain.clone())?;
    let request = native.request(
        "separate-verifier-w0",
        include_str!("../../fixtures/openapi.json"),
        work.submit_by,
    )?;
    // The fixture coordinator assembles bilateral consent. It does not copy
    // keys or give the provider/verifier access to another role's state.
    let agreement = Agreement {
        schema: AGREEMENT_SCHEMA.into(),
        policy_sha256: digest(&native.policy)?,
        authority_uuid: native.policy.authority_uuid.clone(),
        buyer_key: pins.buyer.clone(),
        provider_key: pins.provider.clone(),
        request_id: request.request_id.clone(),
        request_sha256: digest(&request)?,
        finding_context_sha256: digest(&native.policy.finding_context)?,
        required_finding_facets: native.policy.required_finding_facets.clone(),
        domain,
        work,
        capture_waiver_terms: None,
    }
    .sign(&common::key(&buyer)?, &common::key(&provider)?)?;
    files::write(
        &root.join("checkpoint-enrollment.json"),
        &checkpoint_operator::Enrollment {
            schema: checkpoint_operator::ENROLLMENT_SCHEMA.into(),
            authority_uuid: native.policy.authority_uuid.clone(),
            context: native.policy.finding_context.clone(),
        },
    )?;
    files::write(
        &root.join("verifier-enrollment.json"),
        &verifier_operator::Enrollment {
            schema: verifier_operator::ENROLLMENT_SCHEMA.into(),
            policy: native.policy.clone(),
            agreement: agreement.clone(),
        },
    )?;
    command(&[
        "experimental-checkpoint-init".as_ref(),
        operator.as_os_str(),
        root.join("checkpoint-enrollment.json").as_os_str(),
    ])?;
    command(&[
        "experimental-verifier-init".as_ref(),
        verifier.as_os_str(),
        root.join("verifier-enrollment.json").as_os_str(),
    ])?;
    let funding = chain.request(json!({"method":"fund","terms":agreement.body.terms()?}))?;
    let allocation = funding["allocationId"]
        .as_str()
        .ok_or("allocation missing")?
        .to_owned();
    chain.request(json!({"method":"pin-verifier","key":pins.verifier.to_hex()}))?;
    let first = native.execute(&agreement, &request)?;
    drop(native);
    command(&[
        "experimental-checkpoint-export".as_ref(),
        provider.as_os_str(),
        request.request_id.as_ref(),
        root.join("checkpoint-request.json").as_os_str(),
    ])?;
    command(&[
        "experimental-checkpoint-sign".as_ref(),
        operator.as_os_str(),
        root.join("checkpoint-request.json").as_os_str(),
        root.join("checkpoint-response.json").as_os_str(),
    ])?;
    command(&[
        "experimental-checkpoint-import".as_ref(),
        provider.as_os_str(),
        request.request_id.as_ref(),
        root.join("checkpoint-response.json").as_os_str(),
    ])?;
    let native = Native::open(&provider, chain.clone())?;
    let original = native.evidence(&request)?;
    let output = if mode == "reject" {
        json!([])
    } else {
        original.output.clone()
    };
    let submission = evidence::submit(
        &original,
        &output,
        &common::key(&provider)?,
        &native.journal,
    )?;
    native
        .journal
        .retain(&allocation, "submission", &submission)?;
    let entry = native
        .journal
        .by_request(&request.request_id)?
        .ok_or("entry missing")?;
    let checkpoint: super::Checkpoint = Arc::new(|_| Ok(()));
    settlement::drive(
        &entry,
        Action::Submit,
        &native.policy,
        &native.journal,
        chain.as_ref(),
        &checkpoint,
    )?;
    chain.request(json!({"method":"advance","allocation":allocation,"phase":"decision"}))?;
    let socket = root.join("verifier-observer.sock");
    let mut server =
        super::process::Server::start_readonly(&socket, allocation.clone(), chain.clone())?;
    // Verify the operator endpoint cannot prepare or broadcast financial actions.
    let source = super::process::SocketSource(socket.clone());
    let action = settlement::request(&entry, Action::Submit, &native.policy, &native.journal)?;
    if source.prepare(&action).is_ok() {
        return Err("verifier observer allowed transaction preparation".into());
    }
    drop(native);
    let handoff = root.join("verifier-request.json");
    command(&[
        "experimental-verifier-export".as_ref(),
        provider.as_os_str(),
        request.request_id.as_ref(),
        socket.as_os_str(),
        handoff.as_os_str(),
    ])?;
    let decision_file = root.join("decision.json");
    let peer_transport = if peer {
        let report = super::peer_process::exchange(root, &request.request_id, &socket)?;
        server.finish()?;
        report
    } else {
        let missing = root.join("unavailable");
        let no_observer = Command::new(std::env::current_exe()?)
            .args([
                "experimental-verifier-decide".as_ref(),
                verifier.as_os_str(),
                handoff.as_os_str(),
                missing.as_os_str(),
                root.join("unavailable.json").as_os_str(),
            ])
            .output()?;
        if no_observer.status.success() {
            return Err("unavailable observer authorized a verifier decision".into());
        }
        let no_checker = Command::new(std::env::current_exe()?)
            .env("CHIO_FUNDED_PYTHON", &missing)
            .args([
                "experimental-verifier-decide".as_ref(),
                verifier.as_os_str(),
                handoff.as_os_str(),
                socket.as_os_str(),
                root.join("unavailable-checker.json").as_os_str(),
            ])
            .output()?;
        if no_checker.status.success() {
            return Err("unavailable checker authorized a verifier decision".into());
        }
        // Force publication failure after the operator commits its first decision.
        let occupied = root.join("occupied.json");
        fs::write(&occupied, b"preserve original file")?;
        let publication = Command::new(std::env::current_exe()?)
            .args([
                "experimental-verifier-decide".as_ref(),
                verifier.as_os_str(),
                handoff.as_os_str(),
                socket.as_os_str(),
                occupied.as_os_str(),
            ])
            .output()?;
        if publication.status.success() || fs::read(&occupied)? != b"preserve original file" {
            return Err("exclusive publication did not preserve existing output".into());
        }
        fs::remove_file(verifier.join("key.seed"))?;
        server.finish()?;
        let repeated = root.join("decision-replay.json");
        for output in [&decision_file, &repeated] {
            let replayed = Command::new(std::env::current_exe()?)
                .env("CHIO_FUNDED_PYTHON", &missing)
                .args([
                    "experimental-verifier-decide".as_ref(),
                    verifier.as_os_str(),
                    handoff.as_os_str(),
                    missing.as_os_str(),
                    output.as_os_str(),
                ])
                .output()?;
            if !replayed.status.success() {
                return Err(format!(
                    "verifier historical custody replay failed: {}",
                    String::from_utf8_lossy(&replayed.stderr)
                )
                .into());
            }
        }
        if fs::read(&decision_file)? != fs::read(&repeated)? {
            return Err("verifier historical custody changed original decision".into());
        }
        Value::Null
    };
    let import_socket = root.join("provider-observer.sock");
    let mut server =
        super::process::Server::start_readonly(&import_socket, allocation.clone(), chain.clone())?;
    command(&[
        "experimental-verifier-import".as_ref(),
        provider.as_os_str(),
        request.request_id.as_ref(),
        import_socket.as_os_str(),
        decision_file.as_os_str(),
    ])?;
    server.finish()?;
    let native = Native::open(&provider, chain.clone())?;
    let step =
        super::lifecycle::progress(&provider, &native, &request, mode, &checkpoint, &|phase| {
            chain.request(json!({"method":"advance","allocation":allocation,"phase":phase}))?;
            Ok(())
        })?;
    let decision: super::verification::Decision = evidence::read(&decision_file)?;
    files::write(
        &root.join("witness.json"),
        &json!({"agreement":agreement,"submission":submission,
        "context":native.policy.finding_context,"bundle":original.execution,"output":output}),
    )?;
    files::write(
        &root.join("execution-pins.json"),
        &json!({"buyer":pins.buyer,"provider":pins.provider,"verifier":pins.verifier,
        "authorityUuid":native.policy.authority_uuid,"allocationId":allocation}),
    )?;
    drop(native);
    let recovered = Native::open(&provider, chain.clone())?;
    let replay = recovered.execute(&agreement, &request)?;
    let chain_summary = chain.request(json!({"method":"summary","allocation":allocation}))?;
    let provider_has_only_seed = ["buyer", "verifier", "checkpoint", "status", "governance"]
        .iter()
        .all(|role| !provider.join(role).exists());
    Ok(
        json!({"peerTransport":peer_transport,"first":first,"replay":replay,"chain":chain_summary,"verification":step,
        "keysGeneratedInRoleDirectories":true,"decisionReplayWithoutSignerObserverOrChecker":true,
        "providerHasOnlyProviderSeed":provider_has_only_seed,"independentAdministration":false,
        "observerAndCheckerOutagesDenied":true,"publicationFailureRecoveredWithoutDependencies":true,"observerIsReadOnly":true,
        "evaluatedAt":decision.body.finding_assessment.evaluated_at}),
    )
}
