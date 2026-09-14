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
        ["experimental-funded-smoke",state] => funded_work::smoke(Path::new(state)),
        #[cfg(unix)]
        ["experimental-funded-smoke",state,fault] => funded_work::smoke_fault(Path::new(state),fault),
        #[cfg(unix)]
        ["experimental-funded-worker",state,socket,fault] => funded_work::worker(Path::new(state),Path::new(socket),fault),
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
