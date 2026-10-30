//! `cargo xtask gen signed-fixtures`: regenerate or check every signed fixture
//! set through its owning generator, in a fixed order.
//!
//! Regeneration repeats whole passes until a pass leaves the working tree
//! unchanged. `--check` first proves that every committed fixture carrying a
//! signature member has exactly one owner (a step's `owns` pattern or a
//! `CLOSED_SETS` entry), then runs one pass of each generator's check mode,
//! which writes nothing, and fails when any set would change.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::{
    broker_receipt_vectors, cage_vectors, eval_receipt_regen, fixtures, freeze_vectors,
    hash_pinned, recovery_authority_vectors, vector_seeds, workspace_root, XtaskError,
};

/// Passes after which a regeneration that has not converged is refused.
const MAX_PASSES: usize = 4;
/// Fixture trees whose bytes bind the file identity of the SQLite store that
/// generated them, so no two regenerations match. The proof-room check step
/// verifies them against their sources; convergence ignores their bytes.
const SOURCE_BOUND_FIXTURE_DIRS: &[&str] =
    &["fixtures/proof-room/public-stages/recursive-runtime-swarm/"];

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
    VectorSeeds,
    ThreeVendorFixtures,
    FreezeVectors,
}

/// One signed fixture set and its owning generator.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Step {
    pub(crate) name: &'static str,
    pub(crate) regenerate: Invocation,
    pub(crate) check: Invocation,
    /// Repository-relative patterns (`*` within a segment, `**` across
    /// segments) of the signed files this step owns. A step that writes only
    /// inside another step's set owns nothing.
    pub(crate) owns: &'static [&'static str],
}

/// Why a committed file with a signature member has no generator, with the
/// evidence each kind requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClosedKind {
    /// Signature strings that are not a signature over the file's contents.
    /// `fail_closed_test` names the test proving a verifier refuses them.
    Placeholder { fail_closed_test: &'static str },
    /// Bytes pinned by a recorded digest; regenerating breaks the pin. The
    /// signatures are not wrapper signatures.
    HashPinned {
        wrapper_signed: bool,
        pin: &'static str,
    },
    /// Bytes fixed by an upstream standard or authority at `source`.
    External { source: &'static str },
    /// Captured from a host run the workspace cannot reproduce, signed under
    /// `wrapper_id`; the reading tests fail, never skip, when stale.
    ManualRecapture {
        procedure: &'static str,
        wrapper_id: &'static str,
    },
    /// A JSON Schema whose properties name signature members.
    Schema,
    /// A member named like a signature that holds descriptive text.
    Descriptive,
}

/// A committed signed-looking file set that no generator owns.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClosedEntry {
    pub(crate) pattern: &'static str,
    pub(crate) kind: ClosedKind,
    pub(crate) reason: &'static str,
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
        owns: &["tests/bindings/vectors/receipt/v1.json"],
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
        owns: &["tests/bindings/vectors/manifest/v1.json"],
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
        owns: &["tests/bindings/vectors/capability/v1.json"],
    },
    Step {
        name: "bindings signing vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-binding-helpers",
            "--test",
            "vector_fixtures",
            "--",
            "--ignored",
            "--exact",
            "regenerate_signing_vector_fixture",
        ]),
        check: BINDING_VECTOR_CHECK,
        owns: &["tests/bindings/vectors/signing/v1.json"],
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
        owns: &[
            "tests/bindings/vectors/signing/wrapper/v1.json",
            "tests/bindings/vectors/receipt/committed/v1.json",
        ],
    },
    Step {
        name: "capability security binding vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "wire_protocol_schema",
            "--",
            "--ignored",
            "--exact",
            "security_binding::regenerate_security_binding_vectors",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "wire_protocol_schema",
            "security_binding::",
        ]),
        owns: &["tests/bindings/vectors/capability/security-binding-v1.json"],
    },
    Step {
        name: "protocol primitive receipt cases",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "protocol_primitives_generated",
            "--",
            "--ignored",
            "--exact",
            "regenerate_protocol_primitives_receipt_cases",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "protocol_primitives_generated",
        ]),
        owns: &["tests/bindings/fixtures/protocol-primitives-v1.json"],
    },
    Step {
        name: "manifest consumer corpus",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-manifest",
            "--test",
            "manifest_admission",
            "--",
            "--ignored",
            "--exact",
            "regenerate_manifest_consumer_corpus",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-manifest",
            "--test",
            "manifest_admission",
        ]),
        owns: &["tests/bindings/fixtures/manifest-consumers.json"],
    },
    Step {
        name: "key-log vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-keyring",
            "--test",
            "semantic_vectors",
            "--",
            "--ignored",
            "--exact",
            "regenerate_key_log_positives",
        ]),
        check: cargo(&["test", "-p", "chio-keyring", "--test", "semantic_vectors"]),
        owns: &["tests/bindings/vectors/security/key-log/**"],
    },
    Step {
        name: "keyring signed-wire vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-keyring",
            "--lib",
            "--",
            "--ignored",
            "--exact",
            "router::signed_wire_vector_tests::regenerate_keyring_signed_wire_positives",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-keyring",
            "--lib",
            "router::signed_wire_vector_tests",
        ]),
        owns: &[
            "tests/bindings/vectors/security/signed-wire/positive/key-log-*",
            "tests/bindings/vectors/security/signed-wire/positive/keyring-*",
        ],
    },
    Step {
        name: "broker signed-wire vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-secret-broker",
            "--lib",
            "--",
            "--ignored",
            "--exact",
            "audit::signed_wire_vector_tests::regenerate_broker_signed_wire_positives",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-secret-broker",
            "--lib",
            "audit::signed_wire_vector_tests",
        ]),
        owns: &["tests/bindings/vectors/security/signed-wire/positive/broker-*"],
    },
    Step {
        name: "security event signed-wire vector",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "signed_wire_vectors",
            "--",
            "--ignored",
            "--exact",
            "regenerate_signed_wire_security_event",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "signed_wire_vectors",
        ]),
        owns: &["tests/bindings/vectors/security/signed-wire/positive/signed-security-event-*"],
    },
    Step {
        name: "broker receipt vectors",
        regenerate: Invocation::Internal(InternalGenerator::BrokerReceiptVectors),
        check: Invocation::Internal(InternalGenerator::BrokerReceiptVectors),
        owns: &["tests/bindings/vectors/security/broker/**"],
    },
    Step {
        name: "cage vectors",
        regenerate: Invocation::Internal(InternalGenerator::CageVectors),
        check: Invocation::Internal(InternalGenerator::CageVectors),
        owns: &["tests/bindings/vectors/security/cage/**"],
    },
    Step {
        name: "watermark conformance vector",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-decoy",
            "--test",
            "watermark_vectors",
            "--",
            "--ignored",
            "--exact",
            "regenerate_watermark_vectors",
        ]),
        check: cargo(&["test", "-p", "chio-decoy", "--test", "watermark_vectors"]),
        owns: &["crates/tooling/chio-conformance/vectors/security/watermark/**"],
    },
    Step {
        name: "recovery authority vectors",
        regenerate: Invocation::Internal(InternalGenerator::RecoveryAuthorityVectors),
        check: Invocation::Internal(InternalGenerator::RecoveryAuthorityVectors),
        owns: &[
            "spec/vectors/recovery/v1/authority-positive.json",
            "spec/vectors/recovery/v1/authority-contracts.json",
        ],
    },
    Step {
        name: "recovery knowledge contract vectors",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-core-types",
                "--test",
                "recovery_knowledge_contracts",
                "--",
                "--ignored",
                "--exact",
                "write_shared_vectors",
            ],
            &[(
                "CHIO_KNOWLEDGE_VECTOR_OUT",
                "../../../spec/vectors/recovery/v1/knowledge-contracts.json",
            )],
        ),
        check: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "recovery_knowledge_contracts",
        ]),
        owns: &["spec/vectors/recovery/v1/knowledge-contracts.json"],
    },
    Step {
        name: "recovery explanation contract vectors",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-core-types",
                "--test",
                "recovery_explanation_contracts",
                "--",
                "--ignored",
                "--exact",
                "write_shared_vectors",
            ],
            &[(
                "CHIO_EXPLANATION_VECTOR_OUT",
                "../../../spec/vectors/recovery/v1/explanation-contracts.json",
            )],
        ),
        check: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "recovery_explanation_contracts",
        ]),
        owns: &["spec/vectors/recovery/v1/explanation-contracts.json"],
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
        owns: &["spec/vectors/recovery/v1/product-contracts.json"],
    },
    Step {
        name: "recovery semantic contract vectors",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "recovery_semantic_contracts",
            "--",
            "--ignored",
            "--exact",
            "write_semantic_vectors",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-core-types",
            "--test",
            "recovery_semantic_contracts",
        ]),
        owns: &["spec/vectors/recovery/v1/semantic-contracts.json"],
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
        owns: &[
            "crates/trust/chio-federation-authority/tests/fixtures/frost-round2-sealed-v1.json",
        ],
    },
    Step {
        name: "frost published fixtures",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-federation",
            "--test",
            "frost_vectors",
            "--",
            "--ignored",
            "--exact",
            "regenerate_published_frost_fixtures",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-federation",
            "--test",
            "frost_vectors",
            "published_frost_fixtures_are_current_and_verify",
        ]),
        owns: &["spec/schemas/chio-frost/v1/fixtures/**"],
    },
    Step {
        name: "fiscal published fixtures",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-fiscal",
            "--lib",
            "--",
            "--ignored",
            "--exact",
            "lifecycle_tests::regenerate_published_fiscal_fixtures",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-fiscal",
            "--lib",
            "lifecycle_tests::published_fiscal_fixtures_match_runtime_types_and_signatures",
        ]),
        owns: &["spec/schemas/chio-fiscal/v1/fixtures/**"],
    },
    Step {
        name: "vector-projected demo and fuzz seeds",
        regenerate: Invocation::Internal(InternalGenerator::VectorSeeds),
        check: Invocation::Internal(InternalGenerator::VectorSeeds),
        owns: &[
            "docs/demo/fixtures/allow-receipt.json",
            "fuzz/corpus/capability_receipt/binding-*.json",
            "fuzz/corpus/capability_receipt/minimal-receipts.ndjson",
            "fuzz/corpus/capability_receipt/tenant-receipt.json",
            "fuzz/corpus/frost_round2_envelope/**",
            "fuzz/corpus/fuzz_merkle_checkpoint/minimal-receipts.ndjson",
        ],
    },
    Step {
        name: "stop operator config fixtures",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-kernel",
                "--lib",
                "stop::config::tests::committed_fixtures_are_the_generator_output",
                "--",
                "--exact",
            ],
            &[("CHIO_WRITE_STOP_CONFIG_FIXTURES", "1")],
        ),
        check: cargo(&["test", "-p", "chio-kernel", "--lib", "stop::config::tests"]),
        owns: &["crates/kernel/chio-kernel/tests/fixtures/stop_operator_config/**"],
    },
    Step {
        name: "chio-temporal caller delivery golden",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-kernel",
                "--lib",
                "caller_delivery::tests::temporal_golden_is_the_generator_output",
            ],
            &[("CHIO_WRITE_TEMPORAL_GOLDEN", "1")],
        ),
        check: cargo(&[
            "test",
            "-p",
            "chio-kernel",
            "--lib",
            "caller_delivery::tests::temporal_golden_is_the_generator_output",
        ]),
        owns: &["sdks/python/chio-temporal/tests/fixtures/caller_delivery_golden_v1.json"],
    },
    Step {
        name: "eval receipt vector",
        regenerate: Invocation::Internal(InternalGenerator::EvalReceipt),
        check: Invocation::Internal(InternalGenerator::EvalReceipt),
        owns: &["tests/bindings/vectors/eval/v1.json"],
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
        owns: &["formal/tla/trace/fixtures/*.ndjson"],
    },
    Step {
        name: "minimal-passport source fixtures",
        regenerate: cargo(&[
            "test",
            "-p",
            "chio-proof-room",
            "--test",
            "minimal_passport_fixtures",
            "--",
            "--ignored",
            "--exact",
            "regenerate_minimal_passport_fixtures",
        ]),
        check: cargo(&[
            "test",
            "-p",
            "chio-proof-room",
            "--test",
            "minimal_passport_fixtures",
        ]),
        owns: &["fixtures/proof-room/minimal-passport/**"],
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
        owns: &[
            "fixtures/proof-room/*.json",
            "fixtures/proof-room/agent-web/**",
            "fixtures/proof-room/commerce-payments/**",
            "fixtures/proof-room/crypto-context/**",
            "fixtures/proof-room/disclosure-lineage/**",
            "fixtures/proof-room/enterprise-export/**",
            "fixtures/proof-room/finding/**",
            "fixtures/proof-room/first-run/**",
            "fixtures/proof-room/product-overlays/**",
            "fixtures/proof-room/public-settlement/**",
            "fixtures/proof-room/public-stages/**",
            "fixtures/proof-room/runtime-security/**",
            "fixtures/proof-room/swarm-authority/**",
            "fixtures/proof-room/trust-market/**",
            "fixtures/proof-room/workflow-preflight/**",
        ],
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
        owns: &[],
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
        owns: &["crates/trust/chio-attest-verify/tests/fixtures/v318/**"],
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
        owns: &["crates/products/chio-cli/tests/fixtures/replay/**"],
    },
    Step {
        name: "web3 reference artifacts",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-web3",
                "--lib",
                "tests::reference_artifacts_are_the_generator_output",
            ],
            &[("CHIO_WRITE_WEB3_REFERENCE_ARTIFACTS", "1")],
        ),
        check: cargo(&[
            "test",
            "-p",
            "chio-web3",
            "--lib",
            "tests::reference_artifacts",
        ]),
        owns: &[
            "docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json",
            "docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json",
            "docs/standards/CHIO_WEB3_SETTLEMENT_RECEIPT_EXAMPLE.json",
            "docs/standards/CHIO_WEB3_TRUST_PROFILE.json",
        ],
    },
    Step {
        name: "anchor reference artifacts",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-anchor",
                "--lib",
                "reference_artifacts_are_the_generator_output",
            ],
            &[("CHIO_WRITE_WEB3_REFERENCE_ARTIFACTS", "1")],
        ),
        check: cargo(&[
            "test",
            "-p",
            "chio-anchor",
            "--lib",
            "reference_artifacts_are_the_generator_output",
        ]),
        owns: &[
            "docs/standards/CHIO_ANCHOR_DISCOVERY_EXAMPLE.json",
            "docs/standards/CHIO_ANCHOR_PROOF_BUNDLE_EXAMPLE.json",
            "docs/standards/CHIO_FUNCTIONS_REQUEST_EXAMPLE.json",
        ],
    },
    Step {
        name: "three-vendor, attestation loopback and pheromone relay fixtures",
        regenerate: Invocation::Internal(InternalGenerator::ThreeVendorFixtures),
        check: Invocation::Internal(InternalGenerator::ThreeVendorFixtures),
        owns: &[
            "crates/trust/chio-attest-loopback/fixtures/**",
            "examples/chio-3vendor/fixtures/*.json",
            "examples/chio-3vendor/fixtures/pheromone/*.json",
            "examples/chio-3vendor/fixtures/pheromone/relay/alert-assurance/export-bundle/**",
            "examples/chio-3vendor/fixtures/pheromone/relay/peer-directory*.json",
        ],
    },
    Step {
        name: "hello-receipt-verify evidence package",
        regenerate: cargo_env(
            &[
                "test",
                "-p",
                "chio-control-plane",
                "--lib",
                "committed_hello_receipt_fixture_is_the_generator_output",
            ],
            &[("CHIO_WRITE_HELLO_RECEIPT_FIXTURES", "1")],
        ),
        check: cargo(&[
            "test",
            "-p",
            "chio-control-plane",
            "--lib",
            "committed_hello_receipt_fixture_is_the_generator_output",
        ]),
        owns: &["examples/hello-receipt-verify/fixtures/**"],
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
        owns: &[],
    },
    Step {
        name: "signed artifact payload schemas and examples",
        regenerate: Invocation::Program {
            program: "python3",
            args: &["scripts/gen-signed-artifact-schemas.py"],
        },
        check: Invocation::Program {
            program: "python3",
            args: &["scripts/gen-signed-artifact-schemas.py", "--check"],
        },
        owns: &["spec/schemas/signed-artifact-examples/**"],
    },
    Step {
        name: "bindings vector manifest",
        regenerate: Invocation::Internal(InternalGenerator::FreezeVectors),
        check: Invocation::Internal(InternalGenerator::FreezeVectors),
        owns: &[],
    },
];

/// Committed files with a signature member that no generator owns, each with
/// its reason. Closed: a new entry needs a reason a reviewer can check.
pub(crate) const CLOSED_SETS: &[ClosedEntry] = &[
    ClosedEntry {
        pattern: "spec/schemas/chio-wire/v1/root_authority/examples/**",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-core-types --test root_authority_generated_examples \
                               placeholder_example_signatures_are_refused",
        },
        reason: "schema-shape examples: one signature string repeats across differing bodies \
                 and none verifies under any key in the example",
    },
    ClosedEntry {
        pattern: "spec/schemas/chio-economy/*.v1.json",
        kind: ClosedKind::Schema,
        reason: "registered JSON Schemas (spec/schemas/registry.json schemaFile)",
    },
    ClosedEntry {
        pattern: "spec/schemas/chio-tee-frame-v1.json",
        kind: ClosedKind::Schema,
        reason: "registered JSON Schema",
    },
    ClosedEntry {
        pattern: "examples/chio-3vendor/fixtures/runtime-spine/runtime-trust-schema-only.json",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-runtime-core --test placeholder_verifier_trust_bundle \
                               committed_placeholder_verifier_trust_bundle_is_refused",
        },
        reason: "schema-shape example for scripts/check-chio-runtime-spine-fixtures.sh: the \
                 signer key and signature are repeated-byte placeholders",
    },
    ClosedEntry {
        pattern: "fuzz/corpus/capability_receipt/child-request-receipt.json",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-core-types --test placeholder_child_request_receipt \
                               committed_placeholder_child_request_receipt_is_refused",
        },
        reason: "fuzz seed whose all-zero signature exercises the refusal path",
    },
    ClosedEntry {
        pattern: "fuzz/corpus/federation_trust_establishment/invalid-signature-envelope.json",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-federation --test placeholder_handshake_envelope \
                               committed_placeholder_handshake_envelope_is_refused",
        },
        reason: "fuzz seed with an all-zero signature and no capabilities, refused at decoding",
    },
    ClosedEntry {
        pattern: "docs/standards/CHIO_SETTLE_SOLANA_RELEASE_EXAMPLE.json",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-settle --test placeholder_solana_release_example \
                               committed_placeholder_solana_release_example_is_refused",
        },
        reason: "illustrative Solana release document: its ed25519Signature does not verify \
                 under the key it names and it does not decode as a prepared settlement",
    },
    ClosedEntry {
        pattern: "spec/schemas/signed-artifact-schemas.json",
        kind: ClosedKind::Schema,
        reason: "control file of the signed artifact payload schemas; its envelope fragments \
                 and overrides name signature members",
    },
    ClosedEntry {
        pattern: "spec/schemas/signature.v1.json",
        kind: ClosedKind::Schema,
        reason: "registered JSON Schema",
    },
    ClosedEntry {
        pattern: "docs/papers/programmable-sovereignty/bench/**",
        kind: ClosedKind::Descriptive,
        reason: "benchmark results whose `signatures` member names the scheme in prose",
    },
    ClosedEntry {
        pattern: "crates/core/chio-core/tests/fixtures/pq/**",
        kind: ClosedKind::External {
            source: "NIST ACVP ML-DSA-65 known-answer tests (FIPS 204, August 2024)",
        },
        reason: "external known-answer vectors, not Chio-signed",
    },
    ClosedEntry {
        pattern: "crates/trust/chio-attest-verify/sigstore-root/**",
        kind: ClosedKind::External {
            source: "Sigstore public-good TUF trusted_root.json",
        },
        reason: "upstream trust root, not Chio-signed",
    },
    ClosedEntry {
        pattern: "crates/products/chio-cli/tests/replay_traffic/fixtures/**",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-cli --test replay_traffic \
                               replay_from_tee_rejects_the_committed_placeholder_tenant_sig",
        },
        reason: "unsigned TEE capture frames: every tenant_sig is an `ed25519:AAAA...` \
                 placeholder; the tests sign copies at runtime",
    },
    ClosedEntry {
        pattern: "crates/sdk/chio-eval-receipt/tests/fixtures/**",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-eval-receipt --test export_roundtrip \
                               production_verifier_rejects_the_committed_placeholder_bundles",
        },
        reason: "receipt payloads carry the `p2-fixture-signature` placeholder, accepted only \
                 by digest in fixture mode",
    },
    ClosedEntry {
        pattern: "examples/eval-receipt-ingest/metr/out/**",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-eval-receipt --test export_roundtrip \
                               production_verifier_rejects_the_committed_placeholder_bundles",
        },
        reason: "placeholder receipt payloads under a `test-sha256` bundle digest, not a \
                 signature",
    },
    ClosedEntry {
        pattern: "fuzz/corpus/eval_receipt_bundle/**",
        kind: ClosedKind::Placeholder {
            fail_closed_test: "chio-eval-receipt --test export_roundtrip \
                               production_verifier_rejects_the_committed_placeholder_bundles",
        },
        reason: "fuzz seeds built from the placeholder eval bundle and its `test-sha256` digest",
    },
    ClosedEntry {
        pattern: "spec/eval/receipt-format.v1.json",
        kind: ClosedKind::Schema,
        reason: "JSON Schema of the eval report bundle",
    },
    ClosedEntry {
        pattern: "crates/products/chio-cli/tests/fixtures/process-worker-outcomes/**",
        kind: ClosedKind::ManualRecapture {
            procedure: "scripts/recapture-process-worker-outcomes.sh on the x86_64 native-cage \
                        qualification host",
            wrapper_id: "chio.receipt.v1",
        },
        reason: "retained native process-worker evidence; private keys never leave the run, \
                 read by chio-cli process_host::call_evidence::outcomes_native",
    },
    ClosedEntry {
        pattern: "examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/**",
        kind: ClosedKind::HashPinned {
            wrapper_signed: false,
            pin: "examples/internet-of-agents-web3-network/app/tests/fixtures/good-bundle/\
                  bundle-manifest.json",
        },
        reason: "evidence console UI fixture compared by digest only; \
                 hash_pinned::check_web3_good_bundle_unverified fails when a reader or \
                 signature verifier appears",
    },
];

/// Placeholder signatures inside a step-owned file: the step's generator
/// rewrites the file and carries these cases through unchanged.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EmbeddedPlaceholder {
    pub(crate) path: &'static str,
    pub(crate) cases: &'static str,
    pub(crate) fail_closed_test: &'static str,
}

pub(crate) const EMBEDDED_PLACEHOLDERS: &[EmbeddedPlaceholder] = &[EmbeddedPlaceholder {
    path: "tests/bindings/fixtures/protocol-primitives-v1.json",
    cases: "every case outside receipt/record.schema.json",
    fail_closed_test: "chio-core-types --test protocol_primitives_generated \
                       placeholder_case_signatures_are_refused",
}];

/// Signed fixture sets that have no owning generator yet.
pub(crate) const UNOWNED_SETS: &[&str] = &[
    "tests/bindings/fixtures/dpop-authority-v1.json",
    "crates/core/chio-adversarial-suite/cases/**",
];

pub(crate) fn run(check: bool, require_complete: bool) -> Result<(), XtaskError> {
    if require_complete && !UNOWNED_SETS.is_empty() {
        return Err(unowned_error());
    }
    let root = workspace_root()?;
    if check {
        check_coverage(&root)?;
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

/// Fails unless every committed JSON, NDJSON or JSONL file with a signature
/// member has exactly one owner among the steps, `CLOSED_SETS` and
/// `UNOWNED_SETS`.
/// Mutation corpora hold JSON-pointer edits over positives, carry no
/// signature member, and so need no owner.
fn check_coverage(root: &Path) -> Result<(), XtaskError> {
    let output = Command::new("git")
        .args(["ls-files", "-z", "--", "*.json", "*.ndjson", "*.jsonl"])
        .current_dir(root)
        .output()
        .map_err(|error| XtaskError::Io("git ls-files".to_string(), error))?;
    if !output.status.success() {
        return Err(XtaskError::Process("git ls-files failed".to_string()));
    }
    let mut signed = Vec::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let relative = String::from_utf8_lossy(entry).into_owned();
        if !in_coverage_scope(&relative) {
            continue;
        }
        let path = root.join(&relative);
        let bytes = std::fs::read(&path)
            .map_err(|error| XtaskError::Io(path.display().to_string(), error))?;
        if has_signature_member(&String::from_utf8_lossy(&bytes)) {
            signed.push(relative);
        }
    }
    let mut problems = registry_problems();
    problems.extend(coverage_problems(&signed));
    if problems.is_empty() {
        println!(
            "signed-fixtures: {} signed files each have one owner",
            signed.len()
        );
        Ok(())
    } else {
        Err(XtaskError::Drift(format!(
            "signed fixture coverage failed: {}",
            problems.join("; ")
        )))
    }
}

/// Closed entries must state why no generator owns them, and every embedded
/// placeholder must sit in exactly one step-owned file with its cases and
/// fail-closed test named.
fn registry_problems() -> Vec<String> {
    let mut problems = Vec::new();
    for entry in CLOSED_SETS {
        if entry.reason.trim().is_empty() {
            problems.push(format!("closed `{}` has no reason", entry.pattern));
        }
    }
    for entry in EMBEDDED_PLACEHOLDERS {
        let found = owners(entry.path);
        if found.len() != 1 || !found[0].starts_with("step ") {
            problems.push(format!(
                "placeholder `{}` must have one step owner: {found:?}",
                entry.path
            ));
        }
        if entry.cases.trim().is_empty() || entry.fail_closed_test.trim().is_empty() {
            problems.push(format!(
                "placeholder `{}` must name its cases and fail-closed test",
                entry.path
            ));
        }
    }
    problems
}

fn in_coverage_scope(path: &str) -> bool {
    !path.ends_with(".schema.json") && !path.starts_with("third_party/")
}

/// Every owner whose pattern matches `path`, labelled by kind.
fn owners(path: &str) -> Vec<String> {
    let mut found = Vec::new();
    for step in STEPS {
        if step
            .owns
            .iter()
            .any(|pattern| pattern_matches(pattern, path))
        {
            found.push(format!("step `{}`", step.name));
        }
    }
    for entry in CLOSED_SETS {
        if pattern_matches(entry.pattern, path) {
            found.push(format!("closed {:?} `{}`", entry.kind, entry.pattern));
        }
    }
    for pattern in UNOWNED_SETS {
        if pattern_matches(pattern, path) {
            found.push(format!("unowned `{pattern}`"));
        }
    }
    found
}

fn coverage_problems(signed: &[String]) -> Vec<String> {
    let mut problems = Vec::new();
    for path in signed {
        let found = owners(path);
        match found.len() {
            1 => {}
            0 => problems.push(format!("{path} has no owner")),
            _ => problems.push(format!("{path} is owned by {}", found.join(" and "))),
        }
    }
    problems
}

/// Glob match over `/`-separated paths: `*` matches within one segment and
/// `**` matches any run of characters including `/`.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    fn go(pattern: &[u8], path: &[u8]) -> bool {
        match pattern.split_first() {
            None => path.is_empty(),
            Some((b'*', rest)) if rest.first() == Some(&b'*') => {
                let rest = &rest[1..];
                (0..=path.len()).any(|skip| go(rest, &path[skip..]))
            }
            Some((b'*', rest)) => {
                let segment = path
                    .iter()
                    .position(|byte| *byte == b'/')
                    .unwrap_or(path.len());
                (0..=segment).any(|skip| go(rest, &path[skip..]))
            }
            Some((head, rest)) => path.first() == Some(head) && go(rest, &path[1..]),
        }
    }
    go(pattern.as_bytes(), path.as_bytes())
}

/// True when the text has an object member whose name, in snake case and
/// without a `_hex` suffix, is or ends in `sig`, `sigs`, `signature` or
/// `signatures`.
fn has_signature_member(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end] != b'"' {
            end += if bytes[end] == b'\\' { 2 } else { 1 };
        }
        if end >= bytes.len() {
            return false;
        }
        let mut after = end + 1;
        while after < bytes.len() && bytes[after].is_ascii_whitespace() {
            after += 1;
        }
        if bytes.get(after) == Some(&b':') && is_signature_name(&text[start..end]) {
            return true;
        }
        index = end + 1;
    }
    false
}

fn is_signature_name(name: &str) -> bool {
    let mut snake = String::with_capacity(name.len() + 4);
    let mut previous_lower = false;
    for character in name.chars() {
        if character.is_ascii_uppercase() && previous_lower {
            snake.push('_');
        }
        previous_lower = character.is_ascii_lowercase() || character.is_ascii_digit();
        snake.push(character.to_ascii_lowercase());
    }
    let stem = snake.strip_suffix("_hex").unwrap_or(&snake);
    let last = stem.rsplit('_').next().unwrap_or(stem);
    matches!(last, "sig" | "sigs" | "signature" | "signatures")
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
    if let Err(error) = hash_pinned::check_web3_good_bundle_unverified(root) {
        failed.push(format!("web3 good-bundle: {error}"));
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
        InternalGenerator::VectorSeeds => vector_seeds::run(check),
        InternalGenerator::ThreeVendorFixtures => fixtures::regenerate_three_vendor_fixtures(check),
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
        let relative = String::from_utf8_lossy(&entry[3..]);
        if SOURCE_BOUND_FIXTURE_DIRS
            .iter()
            .any(|dir| relative.starts_with(dir))
        {
            continue;
        }
        let path = root.join(relative.as_ref());
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

    #[test]
    fn closed_entries_carry_their_kind_evidence() {
        for entry in CLOSED_SETS {
            let evidence: Vec<&str> = match entry.kind {
                ClosedKind::Placeholder { fail_closed_test } => vec![fail_closed_test],
                ClosedKind::HashPinned {
                    wrapper_signed,
                    pin,
                } => {
                    assert!(!wrapper_signed, "{}", entry.pattern);
                    vec![pin]
                }
                ClosedKind::External { source } => vec![source],
                ClosedKind::ManualRecapture {
                    procedure,
                    wrapper_id,
                } => {
                    assert!(
                        chio_core_types::signed_artifact::registered_wrapper_schema(wrapper_id),
                        "{}",
                        entry.pattern
                    );
                    vec![procedure, wrapper_id]
                }
                ClosedKind::Schema | ClosedKind::Descriptive => Vec::new(),
            };
            for field in evidence {
                assert!(!field.trim().is_empty(), "{}", entry.pattern);
            }
        }
    }

    #[test]
    fn patterns_match_within_and_across_segments() {
        assert!(pattern_matches("a/*.json", "a/b.json"));
        assert!(!pattern_matches("a/*.json", "a/b/c.json"));
        assert!(pattern_matches("a/**", "a/b/c.json"));
        assert!(pattern_matches("a/**/c.json", "a/b/d/c.json"));
        assert!(pattern_matches("a/key-*", "a/key-log-v1.json"));
        assert!(!pattern_matches("a/key-*", "b/key-log-v1.json"));
        assert!(!pattern_matches("a/b.json", "a/b.json.bak"));
    }

    #[test]
    fn signature_members_are_recognized_by_name_only() {
        for text in [
            r#"{"signature":"aa"}"#,
            r#"{"body":{},"kernel_signature" : "aa"}"#,
            r#"{"rosterAuthoritySignature":"aa"}"#,
            r#"{"signatureHex":"aa"}"#,
            r#"{"tenant_sig":"aa"}"#,
            r#"{"signatures":[]}"#,
        ] {
            assert!(has_signature_member(text), "{text}");
        }
        for text in [
            r#"{"note":"signature"}"#,
            r#"{"aggregateSignatureDigest":"aa"}"#,
            r#"{"signing_key":"aa"}"#,
            r#"{"k":"a\"signature\":"}"#,
            r#"["signature"]"#,
        ] {
            assert!(!has_signature_member(text), "{text}");
        }
    }

    #[test]
    fn coverage_rejects_orphaned_and_double_owned_files() {
        let problems = coverage_problems(&[
            "tests/bindings/vectors/signing/v1.json".to_string(),
            "tests/bindings/vectors/not-a-set/v1.json".to_string(),
        ]);
        assert_eq!(
            problems,
            vec!["tests/bindings/vectors/not-a-set/v1.json has no owner".to_string()]
        );
        for step in STEPS {
            for pattern in step.owns {
                for entry in CLOSED_SETS {
                    assert_ne!(*pattern, entry.pattern, "{} is also closed", step.name);
                }
            }
        }
    }

    #[test]
    fn closed_and_placeholder_registries_are_complete() {
        assert_eq!(registry_problems(), Vec::<String>::new());
    }

    #[test]
    fn step_owned_patterns_are_disjoint() {
        let mut problems = Vec::new();
        for (index, step) in STEPS.iter().enumerate() {
            for other in &STEPS[index + 1..] {
                for pattern in step.owns {
                    for theirs in other.owns {
                        if pattern == theirs {
                            problems.push(format!("{pattern}: {} and {}", step.name, other.name));
                        }
                    }
                }
            }
        }
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn committed_signed_fixtures_each_have_one_owner() {
        let result = workspace_root().and_then(|root| check_coverage(&root));
        if let Err(error) = result {
            panic!("{error}");
        }
    }
}
