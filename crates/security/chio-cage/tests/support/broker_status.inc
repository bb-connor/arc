//! The real broker profile permits status inspection without descriptor transfer.
use super::*;
use std::fs::File;
use std::os::unix::net::UnixStream;

pub(super) fn check_broker_descriptor_status() {
    let target = required_path("CHIO_CAGE_TEST_BROKER_FCNTL");
    for (descriptor, operation, permitted) in [
        ("8", "1", true),  // F_GETFD on the original broker socket.
        ("7", "1", false), // F_GETFD on any other descriptor.
        ("8", "0", false), // F_DUPFD must never create another broker slot.
        ("8", "2", false), // F_SETFD cannot alter the retained slot's flags.
    ] {
        let signer = Keypair::from_seed(&[76; 32]);
        let mut manifest = signed_manifest(&signer, None, None).manifest;
        manifest
            .required_permissions
            .as_mut()
            .test_expect("native permissions")
            .native_syscall_profile = NativeSyscallProfile::BrokeredNativeV1;
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(
                sign_manifest(&manifest, &signer).test_unwrap(),
                &signer.public_key(),
                RuntimeToolTopology::brokered(),
            )
            .test_unwrap();
        let ceilings = OperatorCeilings::new(
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::from([NativeSyscallProfile::BrokeredNativeV1]),
        )
        .with_forbidden_paths(BTreeSet::new());
        let admitted = admit_authorized(
            registry
                .authorize_cage_manifest(&manifest.server_id)
                .test_unwrap(),
            &ceilings,
        )
        .test_unwrap();
        let runtime = retain_runtime_resources(
            &RuntimeResourcePaths::new(
                cage_init_helper(),
                target.clone(),
                std::env::temp_dir(),
                BTreeSet::new(),
                execution_identity(),
            )
            .with_target_argv(vec![
                target.to_str().test_unwrap().into(),
                descriptor.into(),
                operation.into(),
            ]),
        )
        .test_unwrap();
        let (socket, _peer) = UnixStream::pair().test_unwrap();
        let broker = chio_cage::retain_broker_ipc(
            File::from(OwnedFd::from(socket)),
            "12".repeat(32),
            chio_cage::BrokerPeerIdentity::current_process().test_unwrap(),
        )
        .test_unwrap();
        let compiled = compile(admitted, runtime, &BTreeMap::new(), Some(broker)).test_unwrap();
        let record = launch(compiled, CageLaunchOptions::default())
            .test_unwrap()
            .wait()
            .test_unwrap();
        let exit = record.exit.test_expect("observed probe exit");
        if permitted {
            assert_eq!(exit.exit_code, Some(0), "broker descriptor remains usable");
        } else {
            assert_eq!(exit.signal, Some(libc::SIGSYS), "unreviewed fcntl denied");
        }
    }
}
