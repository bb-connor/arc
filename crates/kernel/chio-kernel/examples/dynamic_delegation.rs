//! Run with `cargo run -p chio-kernel --example dynamic_delegation`.
mod dynamic_delegation_support;

fn main() -> dynamic_delegation_support::Result {
    let directory = tempfile::tempdir()?;
    let report = dynamic_delegation_support::demonstration(directory.path())?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
