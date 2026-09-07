//! `chio security provision-reference-runtime` end to end: the material it
//! writes at an enforcing stage, its idempotent rerun, its tamper
//! detection, the linkage rules it applies to helper and target, and what
//! the preflight makes of the result on this host.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_TYPE_SHARED_OBJECT: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;

fn chio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn host_machine() -> u16 {
    match std::env::consts::ARCH {
        "x86_64" => 62,
        _ => 183,
    }
}

/// A minimal 64-bit ELF image: the header, the given program headers, then `body`.
fn synthetic_elf(image_type: u16, segments: &[(u32, u64, u64, u64)], body: &[u8]) -> Vec<u8> {
    let header_bytes = 64 + 56 * segments.len();
    let mut image = vec![0_u8; 64];
    image[..4].copy_from_slice(b"\x7fELF");
    image[4] = 2;
    image[5] = 1;
    image[6] = 1;
    image[16..18].copy_from_slice(&image_type.to_le_bytes());
    image[18..20].copy_from_slice(&host_machine().to_le_bytes());
    image[20..24].copy_from_slice(&1_u32.to_le_bytes());
    image[24..32].copy_from_slice(&(header_bytes as u64).to_le_bytes());
    image[32..40].copy_from_slice(&64_u64.to_le_bytes());
    image[52..54].copy_from_slice(&64_u16.to_le_bytes());
    image[54..56].copy_from_slice(&56_u16.to_le_bytes());
    image[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes());
    for (kind, offset, address, size) in segments {
        let mut header = vec![0_u8; 56];
        header[..4].copy_from_slice(&kind.to_le_bytes());
        header[4..8].copy_from_slice(&5_u32.to_le_bytes());
        header[8..16].copy_from_slice(&offset.to_le_bytes());
        header[16..24].copy_from_slice(&address.to_le_bytes());
        header[24..32].copy_from_slice(&address.to_le_bytes());
        header[32..40].copy_from_slice(&size.to_le_bytes());
        header[40..48].copy_from_slice(&size.to_le_bytes());
        header[48..56].copy_from_slice(&0x1000_u64.to_le_bytes());
        image.extend_from_slice(&header);
    }
    image.extend_from_slice(body);
    image
}

fn write_executable(path: &Path, image: &[u8]) {
    std::fs::write(path, image).expect("write executable");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

/// A static executable: one loadable segment covering the whole image.
fn static_executable(path: &Path, image_type: u16, marker: &[u8]) {
    let size = (64 + 56 + marker.len()) as u64;
    write_executable(
        path,
        &synthetic_elf(image_type, &[(PT_LOAD, 0, 0, size)], marker),
    );
}

/// A dynamically linked executable naming `interpreter`.
fn dynamic_executable(path: &Path, interpreter: &str) {
    let body = format!("{interpreter}\0");
    let start = (64 + 56 * 2) as u64;
    let size = start + body.len() as u64;
    write_executable(
        path,
        &synthetic_elf(
            ELF_TYPE_SHARED_OBJECT,
            &[
                (PT_LOAD, 0, 0, size),
                (PT_INTERP, start, start, body.len() as u64),
            ],
            body.as_bytes(),
        ),
    );
}

struct Fixture {
    root: tempfile::TempDir,
    helper: PathBuf,
    target: PathBuf,
    repository: PathBuf,
    tools: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("fixture root");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let helper = root.path().join("chio-cage-init");
        static_executable(&helper, ELF_TYPE_SHARED_OBJECT, b"helper");
        let target = root.path().join("chio-tool-repo-reader");
        static_executable(&target, ELF_TYPE_EXECUTABLE, b"reader");
        let repository = root.path().join("repository");
        std::fs::create_dir(&repository).expect("repository");
        std::fs::write(repository.join("README.md"), "# reference\n").expect("readme");
        let tools = root.path().join("tools.json");
        std::fs::write(
            &tools,
            serde_json::to_vec(&json!([
                {
                    "name": "read_file",
                    "description": "Read a UTF-8 file inside the root",
                    "inputSchema": { "type": "object", "properties": { "path": { "type": "string" } }, "required": ["path"] },
                    "annotations": { "readOnlyHint": true }
                }
            ]))
            .expect("tools fixture"),
        )
        .expect("write tools fixture");
        Self {
            root,
            helper,
            target,
            repository,
            tools,
        }
    }

    fn output(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn provision(&self, output: &Path, extra: &[&str]) -> Output {
        let mut command = Command::new(chio());
        command
            .args(["security", "provision-reference-runtime", "--output-dir"])
            .arg(output)
            .arg("--cage-init")
            .arg(&self.helper)
            .arg("--tools-fixture")
            .arg(&self.tools)
            .arg("--target")
            .arg(&self.target)
            .arg("--target-arg")
            .arg("--root")
            .arg("--target-arg")
            .arg(&self.repository)
            .arg("--read-path")
            .arg(&self.repository)
            .args([
                "--execution-uid",
                "10001",
                "--execution-gid",
                "10001",
                "--server-id",
                "reference-repo-reader",
            ])
            .args(extra);
        command.output().expect("run provisioner")
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn report(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "report is not JSON: {error}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("read artifact")).expect("artifact JSON")
}

#[test]
fn an_enforced_provision_binds_the_helper_the_grants_and_a_promoted_ledger() {
    let fixture = Fixture::new();
    let output = fixture.output("enforced");
    let first = fixture.provision(&output, &[]);
    assert!(first.status.success(), "{}", stderr(&first));
    let report = report(&first);
    assert_eq!(
        report["schema"],
        "chio.reference-runtime-provision-report.v1"
    );
    assert_eq!(report["securityMode"], "enforced_cage");
    assert_eq!(report["containmentEnforced"], true);
    assert_eq!(report["migrationStage"], "enforced");
    assert_eq!(report["migrationGeneration"], 2);
    assert_eq!(
        report["migrationTransitionDigests"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    assert_eq!(report["cageInitPath"], fixture.helper.to_str().unwrap());
    assert_eq!(
        report["readPaths"],
        json!([fixture.repository.to_str().unwrap()])
    );
    assert_eq!(report["writePaths"], json!([]));
    assert_eq!(report["reviewedToolCount"], 1);
    assert_eq!(
        report["targetArgv"],
        json!([
            fixture.target.to_str().unwrap(),
            "--root",
            fixture.repository.to_str().unwrap()
        ])
    );
    let promotions: Vec<PathBuf> = report["artifacts"]["migrationPromotions"]
        .as_array()
        .expect("promotions")
        .iter()
        .map(|path| PathBuf::from(path.as_str().unwrap()))
        .collect();
    assert_eq!(
        promotions
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        ["cage-migration-shadow.json", "cage-migration-enforced.json"]
    );
    for (promotion, stage) in promotions.iter().zip(["shadow", "enforced"]) {
        let transition = read_json(promotion);
        assert_eq!(
            transition["body"]["to_stage"],
            stage,
            "{}",
            promotion.display()
        );
    }
    let policy = read_json(&output.join("cage-launch-policy.json"));
    assert_eq!(policy["body"]["enterprise_migration"]["stage"], "enforced");
    assert_eq!(
        policy["body"]["enterprise_migration"]["minimum_head"]["minimum_generation"],
        2
    );
    assert_eq!(
        policy["body"]["runtime"]["cage_init_path"],
        fixture.helper.to_str().unwrap()
    );
    assert_eq!(
        policy["body"]["operator_ceilings"]["read_paths"],
        json!([fixture.repository.to_str().unwrap()])
    );
    let manifest = read_json(&output.join("signed-manifest.json"));
    let permissions = &manifest["manifest"]["required_permissions"];
    let permissions = if permissions.is_null() {
        &manifest["manifest"]["requiredPermissions"]
    } else {
        permissions
    };
    let read_paths = if permissions["read_paths"].is_null() {
        &permissions["readPaths"]
    } else {
        &permissions["read_paths"]
    };
    assert_eq!(read_paths, &json!([fixture.repository.to_str().unwrap()]));

    let again = fixture.provision(&output, &[]);
    assert!(again.status.success(), "{}", stderr(&again));
    assert_eq!(
        again.stdout, first.stdout,
        "a rerun revalidates the same material"
    );

    let enforced = output.join("cage-migration-enforced.json");
    let mut bytes = std::fs::read(&enforced).expect("read promotion");
    let last = bytes.len() - 2;
    bytes[last] = if bytes[last] == b'a' { b'b' } else { b'a' };
    std::fs::write(&enforced, bytes).expect("tamper");
    let tampered = fixture.provision(&output, &[]);
    assert!(!tampered.status.success());
    assert!(
        stderr(&tampered).contains("promotion") || stderr(&tampered).contains("tamper"),
        "{}",
        stderr(&tampered)
    );
}

#[test]
fn a_shadow_provision_authorizes_without_containment() {
    let fixture = Fixture::new();
    let output = fixture.output("shadow");
    let provisioned = fixture.provision(&output, &["--stage", "shadow"]);
    assert!(provisioned.status.success(), "{}", stderr(&provisioned));
    let report = report(&provisioned);
    assert_eq!(report["securityMode"], "shadow_legacy_authorized");
    assert_eq!(report["containmentEnforced"], false);
    assert_eq!(report["migrationStage"], "shadow");
    assert_eq!(report["migrationGeneration"], 1);
    assert!(output.join("cage-migration-shadow.json").is_file());
    assert!(!output.join("cage-migration-enforced.json").exists());
    let preflight = Command::new(chio())
        .args(["security", "preflight", "--signed-manifest"])
        .arg(output.join("signed-manifest.json"))
        .arg("--manifest-public-key")
        .arg(
            std::fs::read_to_string(output.join("manifest-public-key"))
                .unwrap()
                .trim(),
        )
        .arg("--cage-policy")
        .arg(output.join("cage-launch-policy.json"))
        .arg("--cage-policy-signer")
        .arg(
            std::fs::read_to_string(output.join("cage-policy-signer"))
                .unwrap()
                .trim(),
        )
        .args(["--server-id", "reference-repo-reader", "--"])
        .arg(&fixture.target)
        .arg("--root")
        .arg(&fixture.repository)
        .output()
        .expect("run preflight");
    let text = String::from_utf8_lossy(&preflight.stdout).into_owned();
    assert!(
        text.contains("launch: legacy_authorized"),
        "{text}{}",
        stderr(&preflight)
    );
}

#[test]
fn the_preflight_treats_enforced_material_as_cage_required() {
    let fixture = Fixture::new();
    let output = fixture.output("enforced");
    let provisioned = fixture.provision(&output, &[]);
    assert!(provisioned.status.success(), "{}", stderr(&provisioned));
    let preflight = Command::new(chio())
        .args([
            "security",
            "preflight",
            "--require-enforcement",
            "--signed-manifest",
        ])
        .arg(output.join("signed-manifest.json"))
        .arg("--manifest-public-key")
        .arg(
            std::fs::read_to_string(output.join("manifest-public-key"))
                .unwrap()
                .trim(),
        )
        .arg("--cage-policy")
        .arg(output.join("cage-launch-policy.json"))
        .arg("--cage-policy-signer")
        .arg(
            std::fs::read_to_string(output.join("cage-policy-signer"))
                .unwrap()
                .trim(),
        )
        .args(["--server-id", "reference-repo-reader", "--"])
        .arg(&fixture.target)
        .arg("--root")
        .arg(&fixture.repository)
        .output()
        .expect("run preflight");
    let text = String::from_utf8_lossy(&preflight.stdout).into_owned();
    assert!(!text.contains("legacy_authorized"), "{text}");
    if cfg!(target_arch = "x86_64") {
        assert!(text.contains("cage"), "{text}");
    } else {
        assert!(text.contains("architecture"), "{text}");
    }
}

#[test]
fn a_dynamic_target_needs_its_runtime_files_and_a_dynamic_helper_is_refused() {
    let fixture = Fixture::new();
    let interpreter = fixture.root.path().join("ld-linux.so");
    static_executable(&interpreter, ELF_TYPE_SHARED_OBJECT, b"loader");
    let dynamic_target = fixture.root.path().join("dynamic-tool");
    dynamic_executable(&dynamic_target, interpreter.to_str().unwrap());

    let mut fixture_with_dynamic_target = Fixture::new();
    fixture_with_dynamic_target.target = dynamic_target.clone();
    let refused = fixture_with_dynamic_target.provision(&fixture.output("dynamic"), &[]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("dynamically linked"),
        "{}",
        stderr(&refused)
    );

    let undeclared = fixture_with_dynamic_target.provision(
        &fixture.output("dynamic-undeclared"),
        &["--runtime-file", interpreter.to_str().unwrap()],
    );
    assert!(!undeclared.status.success());
    assert!(
        stderr(&undeclared).contains("--read-path"),
        "{}",
        stderr(&undeclared)
    );

    let declared = fixture_with_dynamic_target.provision(
        &fixture.output("dynamic-declared"),
        &[
            "--runtime-file",
            interpreter.to_str().unwrap(),
            "--read-path",
            interpreter.to_str().unwrap(),
        ],
    );
    assert!(declared.status.success(), "{}", stderr(&declared));
    let report = report(&declared);
    assert_eq!(
        report["runtimeFiles"],
        json!([interpreter.to_str().unwrap()])
    );

    let mut fixture_with_dynamic_helper = Fixture::new();
    let bad_helper = fixture_with_dynamic_helper
        .root
        .path()
        .join("dynamic-helper");
    static_executable(&bad_helper, ELF_TYPE_EXECUTABLE, b"not-pie");
    fixture_with_dynamic_helper.helper = bad_helper;
    let refused = fixture_with_dynamic_helper.provision(&fixture.output("bad-helper"), &[]);
    assert!(!refused.status.success());
    assert!(
        stderr(&refused).contains("static position-independent"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn the_demo_provisioner_keeps_its_disabled_stage_report() {
    let fixture = Fixture::new();
    let output = fixture.output("demo");
    let provisioned = Command::new(chio())
        .args(["security", "provision-native-mcp-demo", "--output-dir"])
        .arg(&output)
        .arg("--tools-fixture")
        .arg(&fixture.tools)
        .arg("--target")
        .arg(&fixture.target)
        .args([
            "--execution-uid",
            "10001",
            "--execution-gid",
            "10001",
            "--server-id",
            "demo-reader",
        ])
        .output()
        .expect("run demo provisioner");
    assert!(provisioned.status.success(), "{}", stderr(&provisioned));
    let report = report(&provisioned);
    assert_eq!(report["schema"], "chio.native-mcp-demo-provision-report.v1");
    assert_eq!(report["securityMode"], "disabled_legacy_authorized_demo");
    assert_eq!(report["migrationStage"], "disabled");
    assert_eq!(report["migrationGeneration"], 0);
    for absent in ["cageInitPath", "readPaths", "migrationTransitionDigests"] {
        assert!(
            report.get(absent).is_none(),
            "{absent} must not appear in the demo report"
        );
    }
    assert!(report["artifacts"].get("migrationPromotions").is_none());
}
