fn main() -> Result<(), Box<dyn std::error::Error>> {
    let report = kernel_work_composition::explore()?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report["violations"] != 0 || report["divergences"] != 0 {
        return Err("bounded exploration failed".into());
    }
    Ok(())
}
