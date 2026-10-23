//! `cargo xtask gen signed-fixtures`: regenerate or check every signed fixture
//! set through its owning generator, in a fixed order.
//!
//! Regeneration repeats whole passes until a pass leaves the working tree
//! unchanged. `--check` runs one pass of each generator's check mode, which
//! writes nothing, and fails when any set would change.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::{
    broker_receipt_vectors, cage_vectors, eval_receipt_regen, freeze_vectors,
    recovery_authority_vectors, workspace_root, XtaskError,
};

/// Passes after which a regeneration that has not converged is refused.
const MAX_PASSES: usize = 4;

/// How one step runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Invocation {
    /// `cargo <args>` with extra environment.
    Cargo {
        args: &'static [&'static str],
        env: &'static [(&'static str, &'static str)],
    },
    /// An external program run from the workspace root.
    Program {
        program: &'static str,
        args: &'static [&'static str],
    },
    /// An xtask generator called in process.
    Internal(InternalGenerator),
}

/// In-process xtask generators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InternalGenerator {
    BrokerReceiptVectors,
    CageVectors,
    RecoveryAuthorityVectors,
    EvalReceipt,
    FreezeVectors,
}

/// One signed fixture set and its owning generator.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Step {
    pub(crate) name: &'static str,
    pub(crate) regenerate: Invocation,
    pub(crate) check: Invocation,
}

const fn cargo(args: &'static [&'static str]) -> Invocation {
    Invocation::Cargo { args, env: &[] }
}

const fn cargo_env(
    args: &'static [&'static str],
    env: &'static [(&'static str, &'static str)],
) -> Invocation {
    Invocation::Cargo { args, env }
}

const BINDING_VECTOR_CHECK: Invocation = cargo(&[
    "test",
    "-p",
    "chio-binding-helpers",
    "--test",
    "vector_fixtures",
]);

/// Generators in run order. Bindings first, freeze-vectors last.
pub(crate) const STEPS: &[Step] = &[
    Step {
        name: "bindings receipt vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-binding-helpers",
            "--test",
            "vector_fixtures",
            "--",
            "--ignored",
            "--exact",
            "refresh_receipt_vector_fixture",
        ]),
        check: BINDING_VECTOR_CHECK,
    },
    Step {
        name: "bindings manifest vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-binding-helpers",
            "--test",
            "vector_fixtures",
            "--",
            "--ignored",
            "--exact",
            "regenerate_manifest_vector_fixture",
        ]),
        check: BINDING_VECTOR_CHECK,
    },
    Step {
        name: "bindings capability vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-binding-helpers",
            "--test",
            "vector_fixtures",
            "--",
            "--ignored",
            "--exact",
            "rebless_capability_vector_signatures",
        ]),
        check: BINDING_VECTOR_CHECK,
    },
    Step {
        name: "signing wrapper and committed receipt vectors",
        regenerate: Invocation::Program {
            program: "uv",
            args: &[
                "run",
                "--with-requirements",
                "scripts/gen-signing-wrapper-vectors.requirements.txt",
                "python3",
                "-I",
                "scripts/gen-signing-wrapper-vectors.py",
                "write",
            ],
        },
        check: Invocation::Program {
            program: "uv",
            args: &[
                "run",
                "--with-requirements",
                "scripts/gen-signing-wrapper-vectors.requirements.txt",
                "python3",
                "-I",
                "scripts/gen-signing-wrapper-vectors.py",
                "check",
            ],
        },
    },
    Step {
        name: "broker receipt vectors",
        regenerate: Invocation::Internal(InternalGenerator::BrokerReceiptVectors),
        check: Invocation::Internal(InternalGenerator::BrokerReceiptVectors),
    },
    Step {
        name: "cage vectors",
        regenerate: Invocation::Internal(InternalGenerator::CageVectors),
        check: Invocation::Internal(InternalGenerator::CageVectors),
    },
    Step {
        name: "recovery authority vectors",
        regenerate: Invocation::Internal(InternalGenerator::RecoveryAuthorityVectors),
        check: Invocation::Internal(InternalGenerator::RecoveryAuthorityVectors),
    },
    Step {
        name: "recovery knowledge contract vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "recovery_knowledge_contracts",
            "--",
            "--ignored",
            "--exact",
            "write_shared_vectors",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "recovery_knowledge_contracts",
        ]),
    },
    Step {
        name: "recovery product contract vectors",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-core-types",
                "--test",
                "recovery_product_contracts",
            ],
            &[("CHIO_REGENERATE_RECOVERY_PRODUCT_VECTORS", "1")],
        ),
        check: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "recovery_product_contracts",
        ]),
    },
    Step {
        name: "frost sealed round-two vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-federation-authority",
            "--lib",
            "--",
            "--ignored",
            "--exact",
            "frost_ceremony::sealing::tests::regenerate_sealed_vectors",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-federation-authority",
            "--lib",
            "frost_ceremony::sealing::tests",
        ]),
    },
    Step {
        name: "stop operator config fixtures",
        regenerate: cargo_env(
            &["test", "-p", "chio-kernel", "--lib", "stop::config::tests"],
            &[("CHIO_WRITE_STOP_CONFIG_FIXTURES", "1")],
        ),
        check: cargo(&["test", "-p", "chio-kernel", "--lib", "stop::config::tests"]),
    },
    Step {
        name: "eval receipt vector",
        regenerate: Invocation::Internal(InternalGenerator::EvalReceipt),
        check: Invocation::Internal(InternalGenerator::EvalReceipt),
    },
    Step {
        name: "receipt trace fixtures",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-trace-validate",
                "--test",
                "checked_fixtures",
            ],
            &[("CHIO_UPDATE_TRACE_FIXTURES", "1")],
        ),
        check: cargo(&[
            "test",
            "-p",
            "chio-trace-validate",
            "--test",
            "checked_fixtures",
        ]),
    },
    Step {
        name: "proof-room fixtures",
        regenerate: cargo(&[
            "run",
            "-p",
            "chio-cli",
            "--bin",
            "chio",
            "--",
            "proof",
            "fixture",
            "regenerate",
        ]),
        check: cargo(&[
            "run",
            "-p",
            "chio-cli",
            "--bin",
            "chio",
            "--",
            "proof",
            "fixture",
            "regenerate",
            "--check",
        ]),
    },
    Step {
        name: "finding golden fixture",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-finding",
            "--test",
            "finding",
            "--",
            "--ignored",
            "--exact",
            "regenerate_golden_fixture",
        ]),
        check: cargo(&["test", "-p", "chio-finding", "--test", "finding"]),
    },
    Step {
        name: "finding market golden fixtures",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-finding",
            "--test",
            "market_schemas",
            "--",
            "--ignored",
            "--exact",
            "regenerate_market_golden_fixtures",
        ]),
        check: cargo(&["test", "-p", "chio-finding", "--test", "market_schemas"]),
    },
    Step {
        name: "cognition-market proof-room golden",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-transaction-passport",
            "--test",
            "cognition_market",
            "--",
            "--ignored",
            "--exact",
            "regenerate_cognition_market_golden",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-transaction-passport",
            "--test",
            "cognition_market",
        ]),
    },
    Step {
        name: "adversarial suite manifest",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-adversarial-suite",
            "--test",
            "manifest_emit",
            "--",
            "--ignored",
            "--exact",
            "regenerate",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-adversarial-suite",
            "--test",
            "manifest_emit",
        ]),
    },
    Step {
        name: "attestation v318 migration fixture",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-attest-verify",
            "--features",
            "pq",
            "--test",
            "v318_migration",
            "--",
            "--ignored",
            "--exact",
            "regenerate_fixture",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-attest-verify",
            "--features",
            "pq",
            "--test",
            "v318_migration",
        ]),
    },
    Step {
        name: "replay fixtures",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-cli",
            "--test",
            "replay",
            "--",
            "--ignored",
            "--exact",
            "bless_fixtures",
        ]),
        check: cargo(&["test", "-p", "chio-cli", "--test", "replay"]),
    },
    Step {
        name: "IETF appendix renderings",
        regenerate: Invocation::Program {
            program: "python3",
            args: &[
                "spec/ietf/tools/render_vectors.py",
                "--vectors",
                "tests/bindings/vectors",
                "--out",
                "spec/ietf/generated",
            ],
        },
        check: Invocation::Program {
            program: "python3",
            args: &[
                "spec/ietf/tools/render_vectors.py",
                "--vectors",
                "tests/bindings/vectors",
                "--out",
                "spec/ietf/generated",
                "--check",
            ],
        },
    },
    Step {
        name: "bindings vector manifest",
        regenerate: Invocation::Internal(InternalGenerator::FreezeVectors),
        check: Invocation::Internal(InternalGenerator::FreezeVectors),
    },
];

/// Signed fixture sets that have no owning generator yet.
pub(crate) const UNOWNED_SETS: &[&str] = &[
    "tests/bindings/vectors/signing/v1.json",
    "tests/bindings/vectors/capability/security-binding-v1.json",
    "tests/bindings/vectors/security/key-log/**",
    "tests/bindings/vectors/security/signed-wire/**",
    "tests/bindings/vectors/security/active-defense/**",
    "crates/tooling/chio-conformance/vectors/security/watermark/v1.json",
    "tests/bindings/fixtures/dpop-authority-v1.json",
    "tests/bindings/fixtures/protocol-primitives-v1.json",
    "tests/bindings/fixtures/manifest-consumers.json",
    "spec/schemas/chio-economy/**",
    "spec/schemas/chio-fiscal/v1/fixtures/**",
    "spec/schemas/chio-frost/v1/fixtures/**",
    "spec/schemas/chio-wire/v1/root_authority/examples/**",
    "crates/core/chio-adversarial-suite/cases/**",
    "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/**",
    "crates/products/chio-cli/tests/replay_traffic/fixtures/**",
    "crates/sdk/chio-eval-receipt/tests/fixtures/**",
    "examples/eval-receipt-ingest/metr/out/**",
    "spec/eval/receipt-format.v1.json",
    "crates/trust/chio-attest-loopback/fixtures/**",
    "examples/chio-3vendor/fixtures/**",
    "examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/**",
    "examples/hello-receipt-verify/fixtures/**",
    "docs/demo/fixtures/allow-receipt.json",
    "docs/standards/CHIO_*_EXAMPLE.json",
    "fuzz/corpus/{capability_receipt,eval_receipt_bundle,federation_trust_establishment,fuzz_merkle_checkpoint}/**",
    "sdks/python/chio-temporal/tests/fixtures/caller_delivery_golden_v1.json",
];

pub(crate) fn run(check: bool, require_complete: bool) -> Result<(), XtaskError> {
    if require_complete && !UNOWNED_SETS.is_empty() {
        return Err(unowned_error());
    }
    let root = workspace_root()?;
    if check {
        return check_pass(&root);
    }
    let mut before = tree_state(&root)?;
    for pass in 1..=MAX_PASSES {
        regenerate_pass(&root)?;
        let after = tree_state(&root)?;
        if after == before {
            println!("signed-fixtures: converged after {pass} pass(es)");
            return Ok(());
        }
        before = after;
    }
    Err(XtaskError::Drift(format!(
        "signed-fixtures did not converge within {MAX_PASSES} passes"
    )))
}

fn unowned_error() -> XtaskError {
    XtaskError::Usage(format!(
        "signed fixture sets without an owning generator: {}",
        UNOWNED_SETS.join(", ")
    ))
}

fn regenerate_pass(root: &Path) -> Result<(), XtaskError> {
    for step in STEPS {
        println!("signed-fixtures: regenerate {}", step.name);
        invoke(root, step.regenerate, false)
            .map_err(|error| step_error(step.name, "regenerate", error))?;
    }
    Ok(())
}

fn check_pass(root: &Path) -> Result<(), XtaskError> {
    let mut seen = BTreeSet::new();
    let mut failed = Vec::new();
    for step in STEPS {
        if !seen.insert(format!("{:?}", step.check)) {
            continue;
        }
        println!("signed-fixtures: check {}", step.name);
        if let Err(error) = invoke(root, step.check, true) {
            failed.push(format!("{}: {error}", step.name));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(XtaskError::Drift(format!(
            "signed fixtures would change: {}",
            failed.join("; ")
        )))
    }
}

fn step_error(name: &str, mode: &str, error: XtaskError) -> XtaskError {
    XtaskError::Process(format!(
        "signed-fixtures {mode} step `{name}` failed: {error}"
    ))
}

fn invoke(root: &Path, invocation: Invocation, check: bool) -> Result<(), XtaskError> {
    match invocation {
        Invocation::Cargo { args, env } => {
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let mut command = Command::new(cargo);
            command.args(args).current_dir(root);
            for (key, value) in env {
                command.env(key, value);
            }
            run_command(command, &format!("cargo {}", args.join(" ")))
        }
        Invocation::Program { program, args } => {
            let mut command = Command::new(program);
            command.args(args).current_dir(root);
            run_command(command, &format!("{program} {}", args.join(" ")))
        }
        Invocation::Internal(generator) => run_internal(generator, check),
    }
}

fn run_internal(generator: InternalGenerator, check: bool) -> Result<(), XtaskError> {
    let argv = if check {
        vec!["--check".to_string()]
    } else {
        Vec::new()
    };
    match generator {
        InternalGenerator::BrokerReceiptVectors => broker_receipt_vectors::run(check),
        InternalGenerator::CageVectors => cage_vectors::run(check),
        InternalGenerator::RecoveryAuthorityVectors => recovery_authority_vectors::run(check),
        InternalGenerator::EvalReceipt => eval_receipt_regen::run(argv),
        InternalGenerator::FreezeVectors => freeze_vectors(argv),
    }
}

fn run_command(mut command: Command, label: &str) -> Result<(), XtaskError> {
    let status = command
        .status()
        .map_err(|error| XtaskError::Io(label.to_string(), error))?;
    if status.success() {
        Ok(())
    } else {
        Err(XtaskError::Process(format!(
            "{label} exited {}",
            status
                .code()
                .map_or_else(|| "by signal".to_string(), |code| code.to_string())
        )))
    }
}

/// Porcelain status plus the bytes of every changed or untracked path.
fn tree_state(root: &Path) -> Result<Vec<u8>, XtaskError> {
    let output = Command::new("git")
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .current_dir(root)
        .output()
        .map_err(|error| XtaskError::Io("git status".to_string(), error))?;
    if !output.status.success() {
        return Err(XtaskError::Process("git status failed".to_string()));
    }
    let mut state = output.stdout.clone();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.len() < 4 {
            continue;
        }
        let path = root.join(String::from_utf8_lossy(&entry[3..]).as_ref());
        if path.is_file() {
            let bytes = std::fs::read(&path)
                .map_err(|error| XtaskError::Io(path.display().to_string(), error))?;
            state.extend_from_slice(&bytes);
        }
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_vectors_runs_last() {
        assert_eq!(
            STEPS.last().map(|step| step.regenerate),
            Some(Invocation::Internal(InternalGenerator::FreezeVectors))
        );
    }

    #[test]
    fn step_names_are_unique() {
        let names: BTreeSet<_> = STEPS.iter().map(|step| step.name).collect();
        assert_eq!(names.len(), STEPS.len());
    }

    #[test]
    fn check_invocations_never_carry_regeneration_environment() {
        for step in STEPS {
            if let Invocation::Cargo { env, .. } = step.check {
                assert!(env.is_empty(), "{}", step.name);
            }
            if let Invocation::Cargo { args, .. } = step.check {
                assert!(!args.contains(&"--ignored"), "{}", step.name);
            }
        }
    }

    #[test]
    fn require_complete_names_every_unowned_set() {
        let message = unowned_error().to_string();
        assert!(message.starts_with("usage: signed fixture sets without an owning generator: "));
        for set in UNOWNED_SETS {
            assert!(message.contains(set), "{set}");
        }
    }
}
