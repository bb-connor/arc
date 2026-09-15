mod buyer;
mod common;
mod market;
mod provider;
#[cfg(test)]
mod tests;

use common::*;
use serde_json::json;
use std::path::Path;

fn run() -> Result<serde_json::Value> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["init",state] => Ok(json!({"publicKey":init(Path::new(state))?})),
        ["grant",state,buyer] => Ok(serde_json::to_value(provider::grant(Path::new(state),chio_core_types::PublicKey::from_hex(buyer)?)?)?),
        ["serve",state,port] => { provider::serve(Path::new(state),port.parse()?,false)?; Ok(json!({})) },
        ["serve",state,port,"--crash-after-accept"] => { provider::serve(Path::new(state),port.parse()?,true)?; Ok(json!({})) },
        ["buyer",state,url] => buyer::run(Path::new(state),url,false),
        ["buyer",state,url,"--crash-before-send"] => buyer::run(Path::new(state),url,true),
        ["verify-agreement",peers,public] => buyer::verify_public(&read(peers)?,&read(public)?),
        ["snapshot",state] => buyer::snapshot(Path::new(state)),
        ["request",state,url,tool,file] => buyer::request(Path::new(state),url,tool,read(file)?),
        ["sign-quote",state,file] => {
            let agreement=read(file)?;
            Ok(serde_json::to_value(market::QuoteRequest{bid:market::make_bid(&agreement,&key(Path::new(state))?)?,agreement})?)
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
