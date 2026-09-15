//! Portable artifact checking without access to the publishing receiver. A
//! bundle and signed claim cannot establish a private reference's history.
use super::*;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::decision::Decision;

const PACKET_SCHEMA: &str = "checked-repair-bundle.experimental.v1";
const MAX_BUNDLE: usize = 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Packet {
    schema: String,
    commit: String,
    bundle_sha256: String,
    artifact_sha256: String,
    base_sha256: BTreeMap<String, String>,
}

// The result asserts a locally checked artifact, never private execution.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckedArtifact {
    schema: &'static str,
    commit: String,
    artifact_sha256: String,
    bundle_sha256: String,
    verifier_executable_sha256: String,
    artifact_passed: bool,
    publication_history_verified: bool,
    receiver_execution_verified: bool,
    receiver_signature_required: bool,
    checked_commit_cases: usize,
}

fn bundle_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_BUNDLE as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BUNDLE {
        return Err("bundle exceeds one MiB".into());
    }
    Ok(bytes)
}

fn pack_offset(bytes: &[u8], packet: &Packet) -> Result<usize> {
    let expected = format!(
        "# v3 git bundle\n@object-format=sha256\n{} {REFERENCE}\n\n",
        oid(&packet.commit)?
    );
    if !bytes.starts_with(expected.as_bytes()) {
        return Err("bundle must contain exactly the fixed SHA-256 reference without prerequisites or filters".into());
    }
    let offset = expected.len();
    let header = bytes
        .get(offset..offset + 12)
        .ok_or("pack header missing")?;
    let count = u32::from_be_bytes(header[8..12].try_into()?);
    if &header[..8] != b"PACK\0\0\0\x02" || count == 0 || count > 64 {
        return Err("unsupported pack version or object count".into());
    }
    Ok(offset)
}

pub fn worker(base: &Path, packet_dir: &Path, directory: &Path) -> Result<()> {
    // Launcher-owned probes are test evidence, not part of acceptance policy.
    if Path::new("/audit-probes.json").exists() {
        let paths: Vec<String> = read(Path::new("/audit-probes.json"))?;
        for path in &paths {
            if std::fs::File::open(path).is_ok() {
                return Err("auditor can read publishing receiver state".into());
            }
        }
        write_once(
            &directory.join("isolation-probes.json"),
            &json!({"deniedHostPaths":paths.len(),"packetReadOnly":std::fs::OpenOptions::new().write(true).open(packet_dir.join("manifest.json")).is_err()}),
        )?;
    }
    let packet: Packet = read(&packet_dir.join("manifest.json"))?;
    let base_sha256 = sources(base)?
        .into_iter()
        .map(|(name, text)| (name, sha256_hex(text.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    if packet.schema != PACKET_SCHEMA || packet.base_sha256 != base_sha256 {
        return Err("packet changed the auditor's trusted base contract".into());
    }
    let bytes = bundle_bytes(&packet_dir.join("repair.bundle"))?;
    if sha256_hex(&bytes) != packet.bundle_sha256 {
        return Err("bundle transport digest differs".into());
    }
    pack_offset(&bytes, &packet)?;
    let repo = directory.join("imported");
    std::fs::create_dir(&repo)?;
    trusted_git(&repo, &["init", "--quiet", "--object-format=sha256"])?;
    std::fs::write(repo.join("repair.bundle"), bytes)?;
    // Native Git validates object hashes. No checkout, producer configuration,
    // alternates or external object store is imported.
    trusted_git(
        &repo,
        &[
            "-c",
            "pack.threads=1",
            "bundle",
            "unbundle",
            "/work/repair.bundle",
        ],
    )?;
    trusted_git(&repo, &["fsck", "--strict", "--full"])?;
    let files = FILES
        .into_iter()
        .map(|name| {
            Ok((
                name.into(),
                trusted_git(&repo, &["show", &format!("{}:{name}", packet.commit)])?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let repair = Repair { base_sha256, files };
    if hash(&repair)? != packet.artifact_sha256 {
        return Err("bundle source differs from artifact digest".into());
    }
    let intent = Intent {
        reference: REFERENCE.into(),
        expected_old: ZERO.into(),
        target_commit: packet.commit.clone(),
        repair: repair.clone(),
    };
    verify_tree(&repo, &intent)?;
    check_owned_artifact(
        &directory.join("local-checks"),
        &repair.base_sha256,
        &serde_json::to_value(&repair)?,
    )?;
    let result = CheckedArtifact {
        schema: "locally-checked-repair.experimental.v1",
        commit: packet.commit,
        artifact_sha256: packet.artifact_sha256,
        bundle_sha256: packet.bundle_sha256,
        verifier_executable_sha256: sha256_hex(&std::fs::read(std::env::current_exe()?)?),
        artifact_passed: true,
        publication_history_verified: false,
        receiver_execution_verified: false,
        receiver_signature_required: false,
        checked_commit_cases: 7,
    };
    write_once(&directory.join("checked-artifact.json"), &result)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn isolated_audit(
    base: &Path,
    packet: &Path,
    output: &Path,
    probes: Option<&Path>,
) -> Result<Value> {
    std::fs::create_dir_all(output)?;
    let mut command = Command::new("/usr/bin/bwrap");
    // The trusted auditor creates inner checker namespaces. Candidate
    // namespaces disable further user namespaces as in report 21.
    command.env_clear().args([
        "--unshare-all",
        "--unshare-user",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--ro-bind",
        "/usr/lib",
        "/usr/lib",
        "--symlink",
        "usr/lib",
        "/lib",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        "16777216",
        "--tmpfs",
        "/tmp",
    ]);
    for path in [
        "/usr/bin/bwrap",
        "/usr/bin/git",
        "/usr/bin/dash",
        "/usr/bin/python3.12",
        "/usr/bin/prlimit",
    ] {
        command.args(["--ro-bind", path, path]);
    }
    command
        .arg("--ro-bind")
        .arg(std::env::current_exe()?)
        .arg("/app/chio")
        .arg("--ro-bind")
        .arg(std::fs::canonicalize(base)?)
        .arg("/base")
        .arg("--ro-bind")
        .arg(std::fs::canonicalize(packet)?)
        .arg("/packet")
        .arg("--bind")
        .arg(std::fs::canonicalize(output)?)
        .arg("/audit")
        .args(["--chdir", "/audit"]);
    if let Some(probes) = probes {
        command
            .arg("--ro-bind")
            .arg(probes)
            .arg("/audit-probes.json");
    }
    command.args([
        "--",
        "/usr/bin/prlimit",
        "--as=536870912",
        "--fsize=8388608",
        "--cpu=20",
        "--nofile=128",
        "--",
        "/app/chio",
        "--repair-audit-worker",
        "/base",
        "/packet",
        "/audit",
    ]);
    capture(command)
}

pub fn audit(base: &Path, packet: &Path, output: &Path) -> Result<Value> {
    let process = isolated_audit(base, packet, output, None)?;
    write_once(&output.join("audit-process.json"), &process)?;
    if process["success"] != true {
        return Err(format!("artifact audit failed: {process}").into());
    }
    Ok(serde_json::from_str(
        process["stdout"].as_str().ok_or("auditor output absent")?,
    )?)
}

fn export_packet(
    directory: &Path,
    owner: &Owner,
    packet_dir: &Path,
    published: bool,
) -> Result<Packet> {
    std::fs::create_dir_all(packet_dir)?;
    let repo = directory.join("review-repo");
    let source_ref = if published {
        REFERENCE
    } else {
        "refs/heads/export-only"
    };
    if !published {
        // Export does not require the alleged publication reference. An
        // advertised name in a bundle header cannot prove that name existed.
        trusted_git(
            &repo,
            &["update-ref", source_ref, &owner.intent.target_commit, ZERO],
        )?;
    }
    trusted_git(
        &repo,
        &[
            "bundle",
            "create",
            "--version=3",
            "/work/export.bundle",
            source_ref,
        ],
    )?;
    let mut bytes = bundle_bytes(&repo.join("export.bundle"))?;
    if !published {
        let end = bytes
            .windows(2)
            .position(|s| s == b"\n\n")
            .ok_or("bundle header absent")?
            + 2;
        let header = std::str::from_utf8(&bytes[..end])?.replace(source_ref, REFERENCE);
        bytes = [header.as_bytes(), &bytes[end..]].concat();
        assert!(current_ref(&repo)?.is_none());
    }
    let packet = Packet {
        schema: PACKET_SCHEMA.into(),
        commit: owner.intent.target_commit.clone(),
        bundle_sha256: sha256_hex(&bytes),
        artifact_sha256: hash(&owner.intent.repair)?,
        base_sha256: owner.intent.repair.base_sha256.clone(),
    };
    pack_offset(&bytes, &packet)?;
    std::fs::write(packet_dir.join("repair.bundle"), bytes)?;
    write_once(&packet_dir.join("manifest.json"), &packet)?;
    Ok(packet)
}

struct FalsePublisher(Value);
#[async_trait::async_trait]
impl ToolServerConnection for FalsePublisher {
    fn server_id(&self) -> &str {
        "checked-git-publication"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["publish".into()]
    }
    async fn invoke(
        &self,
        _tool: &str,
        _args: Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Ok(self.0.clone())
    }
}

fn false_completion(directory: &Path, owner: &Owner) -> Result<Value> {
    let key = Keypair::from_seed_hex(&std::fs::read_to_string(directory.join("key.seed"))?)?;
    let host = directory.join("dishonest-receiver");
    std::fs::create_dir(&host)?;
    let mut kernel = crate::workload::configured_kernel(&host, key.clone())?;
    let claim = json!({"schema":"observed-git-publication.experimental.v1","intentSha256":hash(&owner.intent)?,"artifactSha256":hash(&owner.intent.repair)?,"reference":REFERENCE,"commit":owner.intent.target_commit,"observedPublished":true});
    kernel.register_tool_server(Box::new(FalsePublisher(claim)));
    let reply = crate::workload::invoke_authorized(
        &kernel,
        &key,
        "checked-git-publication",
        "publish",
        serde_json::to_value(&owner.intent)?,
        "false-publication",
    )?;
    assert_eq!(reply.verdict, Verdict::Allow);
    response(&host, "reply", &reply)?;
    assert!(current_ref(&directory.join("review-repo"))?.is_none());
    assert_eq!(
        Gate::open(&owner.backend, directory, &owner.rule)?
            .status(&owner.rule)?
            .0,
        "waiting"
    );
    read(&host.join("reply.json"))
}

fn authenticate_claim(reply: &Value, key: &PublicKey, intent: &Intent) -> Result<()> {
    let receipt: ChioReceipt = serde_json::from_value(reply["receipt"].clone())?;
    if receipt.kernel_key != *key
        || !receipt.verify_signature()?
        || !receipt.action.verify_hash()?
        || receipt.decision != Some(Decision::Allow)
        || reply["allowed"] != true
        || receipt.action.parameters != serde_json::to_value(intent)?
        || receipt.tool_server != "checked-git-publication"
        || receipt.tool_name != "publish"
        || receipt.content_hash != hash(&reply["output"])?
        || reply["output"]["intentSha256"] != hash(intent)?
        || reply["output"]["artifactSha256"] != hash(&intent.repair)?
        || reply["output"]["commit"] != intent.target_commit
        || reply["output"]["reference"] != REFERENCE
        || reply["output"]["observedPublished"] != true
    {
        return Err("receiver claim failed authenticated binding".into());
    }
    Ok(())
}

fn successful_reply(directory: &Path) -> Result<Value> {
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path().join("reply.json");
        if path.is_file() {
            return read(&path);
        }
    }
    Err("receiver reply absent".into())
}

pub fn compare(root: &Path, baseline: &Path, candidate: &Path) -> Result<Value> {
    let root = std::fs::canonicalize(root)?;
    let old = sources(baseline)?;
    let base = old
        .iter()
        .map(|(name, text)| (name.clone(), sha256_hex(text.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    let good = Repair {
        base_sha256: base.clone(),
        files: sources(candidate)?,
    };
    let bad = Repair {
        base_sha256: base.clone(),
        files: old,
    };
    let contract = json!({"schema":"portable-repair-check.experimental.v1","baseSha256":base,"paths":FILES,"requests":requests(),"hooks":HOOKS,"scope":"Delivered source passes the auditor's finite contract; no private publication-history assertion","checkerSha256":sha256_hex(include_bytes!("repair.rs")),"driverSha256":sha256_hex(DRIVER.as_bytes()),"auditorSha256":sha256_hex(include_bytes!("repair_git_audit.rs")),"isolationSha256":sha256_hex(include_bytes!("isolation.rs"))});
    write_once(&root.join("auditor-contract.json"), &contract)?;
    let cases = [
        "honest_published",
        "signed_buggy",
        "signed_unpublished",
        "unsigned_valid",
        "changed_base",
        "changed_target",
        "corrupt_pack",
        "wrong_reference",
        "too_many_objects",
        "oversized_bundle",
    ];
    let mut profiles = BTreeMap::new();
    for backend in BACKENDS {
        let backend_dir = root.join(backend);
        std::fs::create_dir(&backend_dir)?;
        check_owned_artifact(
            &backend_dir.join("receiver-check"),
            &base,
            &serde_json::to_value(&good)?,
        )?;
        let mut owners = Vec::new();
        let mut packets = Vec::new();
        let mut replies = Vec::new();
        for (name, repair, published) in [
            ("honest", &good, true),
            ("buggy", &bad, true),
            ("unpublished", &good, false),
        ] {
            let directory = backend_dir.join("receivers").join(name);
            // The buggy owner intentionally lies about checking, violating the
            // trust assumption rather than forging any signature.
            let owner = provision(&directory, backend, repair, &contract)?;
            let reply = if published {
                finish(&directory, true)?;
                successful_reply(&directory)?
            } else {
                false_completion(&directory, &owner)?
            };
            authenticate_claim(&reply, &owner.rule.verifier_key, &owner.intent)?;
            assert!(
                authenticate_claim(&reply, &Keypair::generate().public_key(), &owner.intent)
                    .is_err()
            );
            let packet_dir = backend_dir.join("exported").join(name);
            let packet = export_packet(&directory, &owner, &packet_dir, published)?;
            write_once(&packet_dir.join("receiver-claim.json"), &reply)?;
            packets.push((packet_dir, packet));
            replies.push(reply);
            owners.push((directory, owner));
        }
        let probe_paths = owners
            .iter()
            .flat_map(|(path, _)| {
                [
                    path.join("key.seed"),
                    path.join("receiver.sqlite"),
                    path.join("review-repo/.git/config"),
                ]
            })
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>();
        for path in &probe_paths {
            assert!(std::fs::File::open(path).is_ok());
        }
        let probes = backend_dir.join("auditor-probes.json");
        write_once(&probes, &probe_paths)?;
        let mut rows = Vec::new();
        for case in cases {
            let index = match case {
                "signed_buggy" => 1,
                "signed_unpublished" => 2,
                _ => 0,
            };
            let (source, original) = &packets[index];
            let packet_dir = backend_dir.join("packets").join(case);
            std::fs::create_dir_all(&packet_dir)?;
            let mut packet = original.clone();
            let mut bytes = bundle_bytes(&source.join("repair.bundle"))?;
            match case {
                "changed_base" => {
                    packet
                        .base_sha256
                        .insert(FILES[0].into(), sha256_hex(b"chosen by producer"));
                }
                "changed_target" => {
                    packet.commit = ZERO.into();
                }
                "corrupt_pack" => {
                    let last = bytes.last_mut().ok_or("empty pack")?;
                    *last ^= 1;
                }
                "wrong_reference" => {
                    let offset = pack_offset(&bytes, &packet)?;
                    let header = std::str::from_utf8(&bytes[..offset])?
                        .replace(REFERENCE, "refs/heads/other");
                    bytes = [header.as_bytes(), &bytes[offset..]].concat();
                }
                "too_many_objects" => {
                    let offset = pack_offset(&bytes, &packet)?;
                    bytes[offset + 8..offset + 12].copy_from_slice(&65u32.to_be_bytes());
                }
                "oversized_bundle" => {
                    bytes.resize(MAX_BUNDLE + 1, 0);
                }
                _ => {}
            }
            // Recompute the hash so corrupted packs reach structural checks.
            packet.bundle_sha256 = sha256_hex(&bytes);
            std::fs::write(packet_dir.join("repair.bundle"), bytes)?;
            write_once(&packet_dir.join("manifest.json"), &packet)?;
            if case != "unsigned_valid" {
                write_once(&packet_dir.join("receiver-claim.json"), &replies[index])?;
            }
            let output = backend_dir.join("audits").join(case);
            let process = isolated_audit(baseline, &packet_dir, &output, Some(&probes))?;
            write_once(&output.join("audit-process.json"), &process)?;
            let accepted = matches!(
                case,
                "honest_published" | "signed_unpublished" | "unsigned_valid"
            );
            assert_eq!(process["success"], accepted, "{backend} {case}: {process}");
            let isolation: Value = read(&output.join("isolation-probes.json"))?;
            assert_eq!(isolation["deniedHostPaths"], 9);
            assert_eq!(isolation["packetReadOnly"], true);
            let observed = if accepted {
                let value: Value = read(&output.join("checked-artifact.json"))?;
                assert_eq!(value["publicationHistoryVerified"], false);
                assert_eq!(value["receiverExecutionVerified"], false);
                assert_eq!(value["artifactPassed"], true);
                assert_eq!(value["receiverSignatureRequired"], false);
                Some(value)
            } else {
                assert!(!output.join("checked-artifact.json").exists());
                None
            };
            rows.push(json!({"case":case,"artifactAccepted":accepted,"receiverClaimSignatureValid":case!="unsigned_valid","publicationActuallyOccurred":index!=2,"publicationHistoryVerified":false,"receiverStatePathsDenied":9,"packetReadOnly":true,"checkedCommitCases":observed.map(|v|v["checkedCommitCases"].clone())}));
        }
        profiles.insert(backend, rows);
    }
    assert_eq!(profiles["chio"], profiles["ledger"]);
    let report = json!({"experiment":"portable-artifact-checking-without-receiver-truth","chio":profiles["chio"],"ledger":profiles["ledger"],"gateSeparationObserved":false,"privatePublicationHistoryVerified":false,"auditorNeedsReceiverKeyOrStore":false,"pairedScenarios":10,"receiverChecks":2,"auditorBehaviorChecks":8,"checkedGitCommitCases":70,"limits":["Receiver honesty is unnecessary for the delivered source's finite checked property; local auditor, checker, Git, Python and host remain trusted","Signed claims authenticate statements but do not prove private publication history or receiver execution","All runs share one host; auditor processes cannot mount receiver state, but independent administration is not qualified","One MiB bundle, 64 packed objects, per-process resource limits and namespace isolation are not aggregate denial-of-service qualification","No succinct proof, generic correctness, fair exchange, production activation or novelty claim"]});
    write_once(&root.join("artifact-audit-comparison.json"), &report)?;
    Ok(report)
}
