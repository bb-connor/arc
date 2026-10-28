//! Execution nonces carry the kernel's boot-selected receipt signature.
//!
//! Every production nonce mint call and every `SignedExecutionNonce` literal in
//! adapter, kernel and control-plane sources must sit at a registered site.
//! Kernel mint sites pass the receipt signing backend, and every constructor
//! signs through a `SigningBackend` rather than a raw keypair. This is a source contract check;
//! the owning kernel tests establish the signed artifacts under every floor.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use syn::visit::Visit;

use super::{collect_rust_sources, source, test_only, FunctionFacts, FunctionVisitor};

const KERNEL_SOURCE_ROOT: &str = "crates/kernel/chio-kernel/src";
const CONTROL_PLANE_SOURCE_ROOT: &str = "crates/platform/chio-control-plane/src";
const SOURCE_ROOTS: &[&str] = &[KERNEL_SOURCE_ROOT, CONTROL_PLANE_SOURCE_ROOT];
const VERIFIED_FIX_SOURCE: &str =
    "crates/platform/chio-control-plane/src/trust_control/finding_verified_fix.rs";
const EXECUTION_NONCE_SOURCE: &str = "crates/kernel/chio-kernel/src/execution_nonce.rs";
const MINT_FUNCTIONS: &[&str] = &[
    "mint_execution_nonce",
    "mint_execution_nonce_with_reservation",
    "mint_for_operation",
];
const SIGNED_NONCE_TYPE: &str = "SignedExecutionNonce";
const RAW_SIGNERS: &[&str] = &[
    "sign",
    "sign_canonical",
    "sign_canonical_shared",
    "sign_shared_canonical",
];
const RECEIPT_SIGNING_BACKEND: &str = "self.receipt_signing_backend()?";

struct MintSite {
    path: &'static str,
    function: &'static str,
    target: &'static str,
    signer_argument: &'static str,
}

const MINT_SITES: &[MintSite] = &[
    MintSite {
        path: EXECUTION_NONCE_SOURCE,
        function: "mint_execution_nonce",
        target: "mint_execution_nonce_with_reservation",
        signer_argument: "(backend,",
    },
    MintSite {
        path: "crates/kernel/chio-kernel/src/kernel/nonce_admission.rs",
        function: "ChioKernel::sign_execution_nonce",
        target: "crate::execution_nonce::mint_execution_nonce_with_reservation",
        signer_argument: RECEIPT_SIGNING_BACKEND,
    },
    MintSite {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/execution_nonce.rs",
        function: "ChioKernel::issue_durable_execution_nonce",
        target: "AdmissionExecutionNonceReservationV1::mint_for_operation",
        signer_argument: RECEIPT_SIGNING_BACKEND,
    },
];

struct ConstructorSite {
    path: &'static str,
    function: &'static str,
    backend_signer: &'static str,
}

const CONSTRUCTOR_SITES: &[ConstructorSite] = &[
    ConstructorSite {
        path: EXECUTION_NONCE_SOURCE,
        function: "mint_execution_nonce_with_reservation",
        backend_signer: "sign_canonical_with_backend",
    },
    ConstructorSite {
        path: "crates/kernel/chio-kernel/src/admission_operation/execution_nonce/profile.rs",
        function: "AdmissionExecutionNonceReservationV1::mint_for_operation",
        backend_signer: "sign_bytes_with_identity",
    },
    ConstructorSite {
        path: VERIFIED_FIX_SOURCE,
        function: "signed_nonce",
        backend_signer: "sign_canonical_with_backend_for_identity",
    },
];

type FileFunctions = Vec<(String, FunctionFacts)>;
type Census = BTreeMap<String, FileFunctions>;

pub(super) fn validate(root: &Path, adapter_sources: &[String]) -> Result<(), String> {
    let mut sources = adapter_sources.to_vec();
    for source_root in SOURCE_ROOTS {
        collect_rust_sources(root, &root.join(source_root), &mut sources)?;
    }
    sources.sort();
    sources.dedup();
    validate_census(&census(root, &sources)?)
}

/// Function facts per physical file. Unlike the mediation census this keeps
/// same-named functions under different `cfg` branches as separate entries.
fn census(root: &Path, sources: &[String]) -> Result<Census, String> {
    let mut parsed = Census::new();
    let mut pending = sources.to_vec();
    while let Some(relative) = pending.pop() {
        if parsed.contains_key(&relative) {
            continue;
        }
        let text = fs::read_to_string(root.join(&relative))
            .map_err(|error| format!("cannot read {relative}: {error}"))?;
        let (functions, includes) = parse_functions(&text, &relative)?;
        let parent = Path::new(&relative)
            .parent()
            .ok_or_else(|| format!("production Rust source has no parent: {relative}"))?;
        for include in includes {
            let included = parent.join(include);
            pending.push(
                included
                    .to_str()
                    .ok_or_else(|| format!("non-UTF-8 include path from {relative}"))?
                    .replace('\\', "/"),
            );
        }
        parsed.insert(relative, functions);
    }
    Ok(parsed)
}

fn parse_functions(text: &str, label: &str) -> Result<(FileFunctions, Vec<String>), String> {
    let syntax = syn::parse_file(text)
        .map_err(|error| format!("cannot parse production Rust source {label}: {error}"))?;
    if test_only(&syntax.attrs) {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut visitor = FunctionVisitor::default();
    visitor.visit_file(&syntax);
    let includes = source::include_paths(&syntax)
        .map_err(|error| format!("cannot inventory includes in {label}: {error}"))?;
    Ok((visitor.functions, includes))
}

fn last_segment(target: &str) -> &str {
    target.rsplit(['.', ':']).next().unwrap_or(target)
}

fn validate_census(census: &Census) -> Result<(), String> {
    let mut failures = Vec::new();
    let mut mints = vec![0_usize; MINT_SITES.len()];
    let mut constructors = vec![0_usize; CONSTRUCTOR_SITES.len()];
    for (path, functions) in census {
        for (function, facts) in functions {
            check_mint_calls(path, function, facts, &mut mints, &mut failures);
            check_constructors(path, function, facts, &mut constructors, &mut failures);
        }
    }
    for (site, count) in MINT_SITES.iter().zip(mints) {
        if count != 1 {
            failures.push(format!(
                "execution nonce mint site must match exactly once: {}::{} -> {} matched {count}",
                site.path, site.function, site.target
            ));
        }
    }
    for (site, count) in CONSTRUCTOR_SITES.iter().zip(constructors) {
        if count != 1 {
            failures.push(format!(
                "execution nonce constructor must match exactly once: {}::{} matched {count}",
                site.path, site.function
            ));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn check_mint_calls(
    path: &str,
    function: &str,
    facts: &FunctionFacts,
    seen: &mut [usize],
    failures: &mut Vec<String>,
) {
    for call in &facts.calls {
        if !MINT_FUNCTIONS.contains(&last_segment(&call.target)) {
            continue;
        }
        let site = MINT_SITES.iter().position(|site| {
            site.path == path && site.function == function && site.target == call.target
        });
        match site {
            Some(index) if call.tokens.contains(MINT_SITES[index].signer_argument) => {
                seen[index] += 1;
            }
            Some(_) => failures.push(format!(
                "execution nonce mint bypasses the receipt signing backend: {path}::{function} -> {}",
                call.target
            )),
            None => failures.push(format!(
                "unregistered execution nonce mint {} in {path}::{function}",
                call.target
            )),
        }
    }
}

fn check_constructors(
    path: &str,
    function: &str,
    facts: &FunctionFacts,
    seen: &mut [usize],
    failures: &mut Vec<String>,
) {
    let literals = facts
        .struct_literals
        .iter()
        .filter(|literal| last_segment(literal) == SIGNED_NONCE_TYPE)
        .count();
    if literals == 0 {
        return;
    }
    let Some(index) = CONSTRUCTOR_SITES
        .iter()
        .position(|site| site.path == path && site.function == function)
    else {
        failures.push(format!(
            "unregistered SignedExecutionNonce construction in {path}::{function}"
        ));
        return;
    };
    seen[index] += literals;
    let calls = facts
        .calls
        .iter()
        .map(|call| last_segment(&call.target))
        .collect::<Vec<_>>();
    if !calls.contains(&CONSTRUCTOR_SITES[index].backend_signer) {
        failures.push(format!(
            "execution nonce constructor does not sign through a SigningBackend: {path}::{function}"
        ));
    }
    if calls.iter().any(|call| RAW_SIGNERS.contains(call)) {
        failures.push(format!(
            "execution nonce constructor signs with a raw keypair: {path}::{function}"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_root;

    fn census_of(files: &[(&str, &str)]) -> Result<Census, String> {
        let mut census = Census::new();
        for (path, text) in files {
            census.insert((*path).to_owned(), parse_functions(text, path)?.0);
        }
        Ok(census)
    }

    fn current_sites() -> Vec<(&'static str, String)> {
        vec![
            (
                EXECUTION_NONCE_SOURCE,
                "fn mint_execution_nonce(backend: &dyn SigningBackend) {
                    mint_execution_nonce_with_reservation(backend, binding, None, None, config, now)
                }
                fn mint_execution_nonce_with_reservation(backend: &dyn SigningBackend) {
                    let (signature, _) = chio_core::crypto::sign_canonical_with_backend(backend, &nonce)?;
                    Ok(SignedExecutionNonce { nonce, signature })
                }"
                .to_owned(),
            ),
            (
                MINT_SITES[1].path,
                "impl ChioKernel {
                    fn sign_execution_nonce(&self) {
                        crate::execution_nonce::mint_execution_nonce_with_reservation(
                            self.receipt_signing_backend()?, binding, hold, request, config, now)
                    }
                }"
                .to_owned(),
            ),
            (
                MINT_SITES[2].path,
                "impl ChioKernel {
                    fn issue_durable_execution_nonce(&self) {
                        AdmissionExecutionNonceReservationV1::mint_for_operation(
                            &expected, retained, self.receipt_signing_backend()?, config, now)
                    }
                }"
                .to_owned(),
            ),
            (
                CONSTRUCTOR_SITES[1].path,
                "impl AdmissionExecutionNonceReservationV1 {
                    fn mint_for_operation(issuer: &dyn SigningBackend) {
                        let outcome = issuer.sign_bytes_with_identity(&bytes)?;
                        let signed = SignedExecutionNonce { nonce, signature: outcome.signature };
                    }
                }"
                .to_owned(),
            ),
            (
                VERIFIED_FIX_SOURCE,
                "fn signed_nonce(receipt: &ChioReceipt, kernel: &dyn SigningBackend) {
                    let (outcome, _) = sign_canonical_with_backend_for_identity(kernel, &receipt.kernel_key, &nonce)?;
                    Ok(SignedExecutionNonce { signature: outcome.signature, nonce })
                }"
                .to_owned(),
            ),
        ]
    }

    fn census_with(
        extra: &[(&str, &str)],
        replace: Option<(usize, &str)>,
    ) -> Result<Census, String> {
        let mut files = current_sites();
        if let Some((index, text)) = replace {
            files[index].1 = text.to_owned();
        }
        let mut owned = files
            .iter()
            .map(|(path, text)| (*path, text.as_str()))
            .collect::<Vec<_>>();
        owned.extend_from_slice(extra);
        census_of(&owned)
    }

    #[test]
    fn workspace_nonce_signing_sites_are_registered() -> Result<(), String> {
        let root = workspace_root().map_err(|error| error.to_string())?;
        let mut sources = Vec::new();
        for source_root in SOURCE_ROOTS {
            collect_rust_sources(&root, &root.join(source_root), &mut sources)?;
        }
        validate_census(&census(&root, &sources)?)
    }

    #[test]
    fn registered_backend_sites_pass() -> Result<(), String> {
        validate_census(&census_with(&[], None)?)
    }

    #[test]
    fn adapter_mint_is_refused() -> Result<(), String> {
        let adapter = "crates/protocol/chio-mcp-edge/src/runtime/nonce.rs";
        let census = census_with(
            &[(
                adapter,
                "fn premint(key: &Keypair) {
                    chio_kernel::mint_execution_nonce(&Ed25519Backend::new(key.clone()), binding, &config, now)
                }",
            )],
            None,
        )?;
        assert_eq!(
            validate_census(&census),
            Err(format!(
                "unregistered execution nonce mint chio_kernel::mint_execution_nonce in {adapter}::premint"
            ))
        );
        Ok(())
    }

    #[test]
    fn adapter_nonce_literal_is_refused() -> Result<(), String> {
        let adapter = "crates/protocol/chio-a2a-edge/src/nonce.rs";
        let census = census_with(
            &[(
                adapter,
                "impl Edge { fn forge(&self) { let _ = chio_core::message::SignedExecutionNonce { nonce, signature: key.sign(&bytes) }; } }",
            )],
            None,
        )?;
        assert_eq!(
            validate_census(&census),
            Err(format!(
                "unregistered SignedExecutionNonce construction in {adapter}::Edge::forge"
            ))
        );
        Ok(())
    }

    #[test]
    fn kernel_mint_with_the_classical_keypair_is_refused() -> Result<(), String> {
        let census = census_with(
            &[],
            Some((
                1,
                "impl ChioKernel {
                    fn sign_execution_nonce(&self) {
                        crate::execution_nonce::mint_execution_nonce_with_reservation(
                            &Ed25519Backend::new(self.config.keypair.clone()), binding, hold, request, config, now)
                    }
                }",
            )),
        )?;
        assert_eq!(
            validate_census(&census),
            Err(format!(
                "execution nonce mint bypasses the receipt signing backend: {}::ChioKernel::sign_execution_nonce -> crate::execution_nonce::mint_execution_nonce_with_reservation\n\
                 execution nonce mint site must match exactly once: {}::ChioKernel::sign_execution_nonce -> crate::execution_nonce::mint_execution_nonce_with_reservation matched 0",
                MINT_SITES[1].path, MINT_SITES[1].path
            ))
        );
        Ok(())
    }

    #[test]
    fn alternate_kernel_mint_path_is_refused() -> Result<(), String> {
        let path = "crates/kernel/chio-kernel/src/kernel/validation/tool_output.rs";
        let census = census_with(
            &[(
                path,
                "impl ChioKernel {
                    fn premint(&self) {
                        crate::execution_nonce::mint_execution_nonce(self.receipt_signing_backend()?, binding, config, now)
                    }
                }",
            )],
            None,
        )?;
        assert_eq!(
            validate_census(&census),
            Err(format!(
                "unregistered execution nonce mint crate::execution_nonce::mint_execution_nonce in {path}::ChioKernel::premint"
            ))
        );
        Ok(())
    }

    #[test]
    fn constructor_signing_with_a_raw_keypair_is_refused() -> Result<(), String> {
        let census = census_with(
            &[],
            Some((
                3,
                "impl AdmissionExecutionNonceReservationV1 {
                    fn mint_for_operation(issuer: &Keypair) {
                        let signed = SignedExecutionNonce { nonce, signature: issuer.sign(&bytes) };
                    }
                }",
            )),
        )?;
        let path = CONSTRUCTOR_SITES[1].path;
        assert_eq!(
            validate_census(&census),
            Err(format!(
                "execution nonce constructor does not sign through a SigningBackend: {path}::AdmissionExecutionNonceReservationV1::mint_for_operation\n\
                 execution nonce constructor signs with a raw keypair: {path}::AdmissionExecutionNonceReservationV1::mint_for_operation"
            ))
        );
        Ok(())
    }

    #[test]
    fn control_plane_authoring_nonce_signed_with_a_raw_keypair_is_refused() -> Result<(), String> {
        let census = census_with(
            &[],
            Some((
                4,
                "fn signed_nonce(receipt: &ChioReceipt, kernel: &Keypair) {
                    Ok(SignedExecutionNonce { signature: kernel.sign(&canonical_json_bytes(&nonce)?), nonce })
                }",
            )),
        )?;
        assert_eq!(
            validate_census(&census),
            Err(format!(
                "execution nonce constructor does not sign through a SigningBackend: {VERIFIED_FIX_SOURCE}::signed_nonce\n\
                 execution nonce constructor signs with a raw keypair: {VERIFIED_FIX_SOURCE}::signed_nonce"
            ))
        );
        Ok(())
    }

    #[test]
    fn unregistered_control_plane_nonce_literal_is_refused() -> Result<(), String> {
        let path =
            "crates/platform/chio-control-plane/src/trust_control/finding_operator_bundle.rs";
        let census = census_with(
            &[(
                path,
                "fn reissue(backend: &dyn SigningBackend) {
                    let (signature, _) = sign_canonical_with_backend(backend, &nonce)?;
                    Ok(SignedExecutionNonce { nonce, signature })
                }",
            )],
            None,
        )?;
        assert_eq!(
            validate_census(&census),
            Err(format!(
                "unregistered SignedExecutionNonce construction in {path}::reissue"
            ))
        );
        Ok(())
    }

    #[test]
    fn test_only_mints_are_not_production_sites() -> Result<(), String> {
        let census = census_with(
            &[(
                "crates/protocol/chio-mcp-edge/src/runtime/fixture.rs",
                "#[cfg(test)] mod tests { fn fixture() { mint_execution_nonce(&backend, binding, &config, now); } }",
            )],
            None,
        )?;
        validate_census(&census)
    }
}
