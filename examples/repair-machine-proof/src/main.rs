//! Verify a pinned Cartesi state-transition proof. This does not interpret a
//! transition as a passed repair, authorize a tool call, or release payment.
use std::error::Error;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use bincode::Options;
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use serde::{Deserialize, Serialize};
use serde_json::json;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Expected {
    image_id: String,
    root_before: String,
    cycles: u64,
    root_after: String,
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES { return Err("proof input exceeds 64 MiB".into()); }
    Ok(bytes)
}

fn bytes32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected a 32-byte hex digest".into());
    }
    Ok(hex::decode(value)?.try_into().map_err(|_| "digest length mismatch")?)
}

fn image_id(expected: &Expected) -> Result<[u32; 8]> {
    let bytes = bytes32(&expected.image_id)?;
    let mut words = [0;8];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into()?);
    }
    Ok(words)
}

fn check(receipt: &Receipt, expected: &Expected) -> Result<()> {
    if matches!(receipt.inner, InnerReceipt::Fake(_)) {
        return Err("development receipts are forbidden".into());
    }
    receipt.verify(image_id(expected)?)?;
    let mut journal = Vec::with_capacity(96);
    journal.extend_from_slice(&bytes32(&expected.root_before)?);
    journal.extend_from_slice(&[0;24]);
    journal.extend_from_slice(&expected.cycles.to_be_bytes());
    journal.extend_from_slice(&bytes32(&expected.root_after)?);
    if receipt.journal.bytes != journal {
        return Err("proved transition differs from receiver-selected expectation".into());
    }
    Ok(())
}

fn receipt(path: &Path) -> Result<Receipt> {
    Ok(bincode::DefaultOptions::new().with_fixint_encoding().with_limit(MAX_BYTES).reject_trailing_bytes().deserialize(&read(path)?)?)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|a| a == "image-id") && args.len() == 2 {
        let id = risc0_binfmt::compute_image_id(&read(Path::new(&args[1]))?)?;
        println!("{}", hex::encode(id.as_bytes()));
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "prove") && args.len() == 5 {
        if std::env::var_os("RISC0_DEV_MODE").is_some() { return Err("RISC0_DEV_MODE must be absent".into()); }
        let guest = read(Path::new(&args[1]))?;
        let log = read(Path::new(&args[2]))?;
        let expected: Expected = serde_json::from_slice(&read(Path::new(&args[3]))?)?;
        let actual = risc0_binfmt::compute_image_id(&guest)?;
        if actual.as_bytes() != bytes32(&expected.image_id)? { return Err("unselected proof guest".into()); }
        let env = ExecutorEnv::builder().write_slice(&log).build()?;
        let started = Instant::now();
        let info = default_prover().prove_with_opts(env, &guest, &ProverOpts::composite())?;
        check(&info.receipt, &expected)?;
        let encoded = bincode::serialize(&info.receipt)?;
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&args[4])?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        println!("{}", json!({"stateTransitionVerified":true,"repairContractVerified":false,"receiptBytes":encoded.len(),"proverSeconds":started.elapsed().as_secs_f64(),"receiptKind":"composite"}));
        return Ok(());
    }
    if args.first().is_some_and(|a| a == "verify") && args.len() == 3 {
        let expected: Expected = serde_json::from_slice(&read(Path::new(&args[2]))?)?;
        check(&receipt(Path::new(&args[1]))?, &expected)?;
        println!("{}", json!({"stateTransitionVerified":true,"repairContractVerified":false,"paymentAuthorized":false,"expected":expected}));
        return Ok(());
    }
    Err("usage: image-id GUEST | prove GUEST LOG EXPECTED NEW_RECEIPT | verify RECEIPT EXPECTED".into())
}
