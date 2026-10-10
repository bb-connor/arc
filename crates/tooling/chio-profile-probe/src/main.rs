//! Report whether the profile that built this binary checks integer overflow.
//!
//! A `u64` subtraction below zero either terminates the process or wraps to
//! near `u64::MAX`, and a remaining-budget comparison reads that wrap as
//! unlimited authority. No test in the ordinary suite can observe which
//! happened, because the suite never runs under a shipping profile. This
//! binary does: it reaches the line below and prints only if the build let the
//! wrap happen.

use std::process::ExitCode;

/// Read at run time so constant folding cannot settle the subtraction while
/// compiling and leave the probe measuring a literal instead of the profile.
fn operand(position: usize, default: u64) -> u64 {
    std::env::args()
        .nth(position)
        .and_then(|argument| argument.parse().ok())
        .unwrap_or(default)
}

fn main() -> ExitCode {
    let remaining = operand(1, 0);
    let spent = operand(2, 1);
    let remainder = remaining - spent;
    println!("wrapped: {remaining} - {spent} = {remainder}");
    ExitCode::SUCCESS
}
