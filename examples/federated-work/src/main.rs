mod buyer;
mod common;
mod funded_work;
mod https;
mod incident;
mod market;
mod payment;
mod provider;
mod resolution;
mod review;
mod subcontract;
#[cfg(test)]
mod tests;
mod work_buyer;

use common::*;
use serde_json::json;
use std::io::Read;
use std::path::Path;

fn run() -> Result<serde_json::Value> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["experimental-context-draft",state,pins,expires,output] => funded_work::authority_enrollment::draft_file(Path::new(state),Path::new(pins),expires.parse()?,Path::new(output)),
        ["experimental-context-attest",state,pins,draft,output] => funded_work::authority_enrollment::attest_file(Path::new(state),Path::new(pins),Path::new(draft),Path::new(output)),
        #[cfg(unix)]
        ["experimental-work-propose",state,intent,input,output] => funded_work::provider_files::propose(Path::new(state),Path::new(intent),Path::new(input),Path::new(output)),
        #[cfg(unix)]
        ["experimental-work-accept",state,intent,proposal,output] => funded_work::provider_files::accept(Path::new(state),Path::new(intent),Path::new(proposal),Path::new(output)),
        #[cfg(unix)]
        ["experimental-provider-execute",state,socket,acceptance] => funded_work::provider_files::execute(Path::new(state),Path::new(socket),Path::new(acceptance)),
        #[cfg(unix)]
        ["experimental-provider-output",state,id,output] => funded_work::provider_files::output(Path::new(state),id,Path::new(output)),
        #[cfg(unix)]
        ["experimental-provider-submit",state,id,socket,candidate] => funded_work::provider_files::submit(Path::new(state),id,Path::new(socket),Path::new(candidate)),
        #[cfg(unix)]
        ["experimental-provider-settle",state,id,socket] => funded_work::provider_files::settle(Path::new(state),id,Path::new(socket)),
        #[cfg(target_os = "linux")]
        ["experimental-isolated-lifecycle",state,mode] => funded_work::isolated_process::run(Path::new(state),mode),
        ["experimental-authority-context",governance,status,pins,expires,output] => funded_work::authority_enrollment::context_file(Path::new(governance),Path::new(status),Path::new(pins),expires.parse()?,Path::new(output)),
        ["experimental-provider-enroll",state,pins,context,domain] => funded_work::authority_enrollment::enroll_files(Path::new(state),Path::new(pins),Path::new(context),Path::new(domain)),
        ["experimental-verifier-init",state,enrollment] => funded_work::verifier_operator::initialize_file(Path::new(state),Path::new(enrollment)),
        #[cfg(unix)]
        ["experimental-verifier-decide",state,request,socket,output] => funded_work::verifier_operator::decide_file(Path::new(state),Path::new(request),Path::new(socket),Path::new(output)),
        #[cfg(unix)]
        ["experimental-verifier-export",state,request,socket,output] => funded_work::verifier_files::export(Path::new(state),request,Path::new(socket),Path::new(output)),
        #[cfg(unix)]
        ["experimental-verifier-import",state,request,socket,input] => funded_work::verifier_files::import(Path::new(state),request,Path::new(socket),Path::new(input)),
        #[cfg(unix)]
        ["experimental-authority-lifecycle",root,mode] => funded_work::authority_process::run(Path::new(root),mode),
        ["experimental-checkpoint-init",state,enrollment] => funded_work::checkpoint_operator::initialize_file(Path::new(state),Path::new(enrollment)),
        ["experimental-checkpoint-sign",state,request,response] => funded_work::checkpoint_operator::sign_file(Path::new(state),Path::new(request),Path::new(response)),
        ["experimental-checkpoint-export",state,request,output] => funded_work::checkpoint_files::export(Path::new(state),request,Path::new(output)),
        ["experimental-checkpoint-import",state,request,input] => funded_work::checkpoint_files::import(Path::new(state),request,Path::new(input)),
        ["experimental-checkpoint-lifecycle",state,mode] => funded_work::checkpoint_process::run(Path::new(state),mode),
        ["experimental-funded-smoke",state] => funded_work::smoke(Path::new(state)),
        #[cfg(unix)]
        ["experimental-funded-child",state,fault] => funded_work::child(Path::new(state),fault),
        #[cfg(unix)]
        ["experimental-funded-parent-worker",state] => funded_work::parent_worker(Path::new(state)),
        #[cfg(unix)]
        ["experimental-funded-child-collector",state,socket,fault] => funded_work::child_collector(Path::new(state),Path::new(socket),fault),
        #[cfg(unix)]
        ["experimental-funded-resolution",state,mode,fault] => funded_work::resolution(Path::new(state),mode,fault),
        #[cfg(unix)]
        ["experimental-funded-resolution-worker",state,socket,fault] => funded_work::resolution_worker(Path::new(state),Path::new(socket),fault),
        #[cfg(unix)]
        ["experimental-funded-lifecycle",state,"unknown"] => funded_work::admission_loss(Path::new(state),true),
        #[cfg(unix)]
        ["experimental-funded-lifecycle",state,"undispatched"] => funded_work::admission_loss(Path::new(state),false),
        ["experimental-funded-lifecycle",state,mode] => funded_work::lifecycle(Path::new(state),mode),
        #[cfg(unix)]
        ["experimental-funded-lifecycle",state,mode,fault] => funded_work::lifecycle_fault(Path::new(state),mode,fault),
        #[cfg(unix)]
        ["experimental-funded-lifecycle-worker",state,socket,mode,fault] => funded_work::lifecycle_worker(Path::new(state),Path::new(socket),mode,fault),
        #[cfg(unix)]
        ["experimental-funded-smoke",state,fault] => funded_work::smoke_fault(Path::new(state),fault),
        #[cfg(unix)]
        ["experimental-funded-worker",state,socket,fault] => funded_work::worker(Path::new(state),Path::new(socket),fault),
        ["experimental-funded-wire-check",file] => {
            let mut bytes = Vec::new();
            std::fs::File::open(file)?.take(funded_work::wire::MAX_ARTIFACT_BYTES as u64 + 1).read_to_end(&mut bytes)?;
            funded_work::wire::parse(&bytes)
        },
        ["check-openapi",file] => {
            let mut input = String::new();
            std::fs::File::open(file)?.take(64 * 1024 + 1).read_to_string(&mut input)?;
            Ok(serde_json::to_value(review::check_openapi(&input)?)?)
        },
        ["init",state] => Ok(json!({"publicKey":init(Path::new(state))?})),
        ["grant",state,buyer] => Ok(serde_json::to_value(provider::grant(Path::new(state),chio_core_types::PublicKey::from_hex(buyer)?)?)?),
        ["grant-session",state,buyer] => Ok(serde_json::to_value(provider::grant_session(Path::new(state),chio_core_types::PublicKey::from_hex(buyer)?)?)?),
        ["enrollment",state,buyer,origin,ca] => crate::https::enrollment(Path::new(state),chio_core_types::PublicKey::from_hex(buyer)?,origin,Path::new(ca)),
        ["serve-https",state,bind,origin,certificate,private_key,fault] => {
            provider::serve_https(Path::new(state),crate::https::HttpsConfig{bind:bind.parse()?,origin,certificate:Path::new(certificate),private_key:Path::new(private_key)},fault)?;
            Ok(json!({}))
        },
        ["serve",state,port] => { provider::serve(Path::new(state),port.parse()?,false)?; Ok(json!({})) },
        ["serve",state,port,"--crash-after-accept"] => { provider::serve(Path::new(state),port.parse()?,true)?; Ok(json!({})) },
        ["serve-work",state,port,fault] => { provider::serve_with_fault(Path::new(state),port.parse()?,fault)?; Ok(json!({})) },
        ["work",state,url] => work_buyer::run(Path::new(state),url,false),
        ["subcontract-recover",state,parent] => subcontract::worker::Worker::load(Path::new(state))?
            .ok_or("no locally activated specialist")?.recover(parent,false),
        ["subcontract-recover",state,parent,"--release-unknown"] => subcontract::worker::Worker::load(Path::new(state))?
            .ok_or("no locally activated specialist")?.recover(parent,true),
        ["work",state,url,"--crash-after-check"] => work_buyer::run(Path::new(state),url,true),
        ["review-request",state,url,file,proof] => work_buyer::request(Path::new(state),url,read(file)?,*proof=="signed"),
        ["verify-work",peers,public] => {
            let peers:Peers=read(peers)?; let public:serde_json::Value=read(public)?;
            let request:review::ReviewRequest=serde_json::from_value(public["request"].clone())?;
            request.validate(&peers)?;
            let (rejected,receipt_id)=review::verify_terminal(&request,&public["delivery"])?;
            Ok(json!({"buyerVerified":true,"reviewRejected":rejected,"receiptId":receipt_id,"externalFundsTransferred":false}))
        },
        ["verify-release",peers,public] => {
            let id=resolution::verify(&read(peers)?,&read(public)?)?;
            Ok(json!({"releaseVerified":true,"operationId":id,"workExecuted":null,"localCreditSettled":true,"externalFundsTransferred":false}))
        },
        ["verify-incident",peers,public] => {
            let peers:Peers=read(peers)?; let public:serde_json::Value=read(public)?;
            let request:review::ReviewRequest=serde_json::from_value(public["request"].clone())?;
            request.validate(&peers)?;
            let incident:incident::Incident=serde_json::from_value(public["incident"].clone())?;
            let operation_id=incident::verify(&request,&incident)?;
            Ok(json!({"incidentVerified":true,"operationId":operation_id,"workExecuted":null,"localCreditSettled":false,"externalFundsTransferred":false}))
        },
        ["buyer",state,url] => buyer::run(Path::new(state),url,false),
        ["buyer",state,url,"--crash-before-send"] => buyer::run(Path::new(state),url,true),
        ["verify-agreement",peers,public] => buyer::verify_public(&read(peers)?,&read(public)?),
        ["snapshot",state] => buyer::snapshot(Path::new(state)),
        ["request",state,url,tool,file] => buyer::request(Path::new(state),url,tool,read(file)?),
        ["sign-quote",state,file] => {
            let agreement=read(file)?;
            Ok(serde_json::to_value(market::QuoteRequest{bid:market::make_bid(&agreement,&key(Path::new(state))?)?,agreement,subcontract_permit:None})?)
        },
        ["probe",path] => Ok(json!({"readable":std::fs::File::open(path).is_ok()})),
        _ => Err("usage: init STATE | grant STATE BUYER_KEY | serve STATE PORT [--crash-after-accept] | buyer STATE URL | snapshot STATE | request STATE URL TOOL FILE | sign-quote STATE AGREEMENT | probe PATH".into()),
    }
}

fn main() {
    match run().and_then(|value| Ok(serde_json::to_string(&value)?)) {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
