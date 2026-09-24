//! Real filters constrain native close-on-exec and broker status operations.
use super::*;
use std::fs::File;
use std::os::unix::net::UnixStream;

pub(super) fn check_descriptor_status() {
    let target = required_path("CHIO_CAGE_TEST_BROKER_FCNTL");
    use NativeSyscallProfile::{BrokeredNativeV1, NativeMinimalV1, NativeStandardV1};
    for (profile, descriptor, operation, flags, permitted) in [
        (BrokeredNativeV1, "8", "1", "0", true),
        (BrokeredNativeV1, "7", "1", "0", false),
        (BrokeredNativeV1, "8", "0", "0", false),
        (BrokeredNativeV1, "8", "2", "0", false),
        (NativeMinimalV1, "0", "2", "1", true),
        (NativeMinimalV1, "0", "2", "0", false),
        (NativeMinimalV1, "0", "0", "0", false),
        (NativeStandardV1, "0", "2", "1", true),
        (NativeStandardV1, "0", "2", "0", false),
        (NativeStandardV1, "0", "0", "0", false),
    ] {
        let brokered = profile == BrokeredNativeV1;
        let signer = Keypair::from_seed(&[76; 32]);
        let mut manifest = signed_manifest(&signer, None, None).manifest;
        manifest
            .required_permissions
            .as_mut()
            .test_expect("native permissions")
            .native_syscall_profile = profile;
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(
                sign_manifest(&manifest, &signer).test_unwrap(),
                &signer.public_key(),
                if brokered {
                    RuntimeToolTopology::brokered()
                } else {
                    RuntimeToolTopology::local()
                },
            )
            .test_unwrap();
        let ceilings = OperatorCeilings::new(
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::from([profile]),
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
                flags.into(),
            ]),
        )
        .test_unwrap();
        let (socket, _peer) = UnixStream::pair().test_unwrap();
        let broker = brokered.then(|| {
            chio_cage::retain_broker_ipc(
                File::from(OwnedFd::from(socket)),
                "12".repeat(32),
                chio_cage::BrokerPeerIdentity::current_process().test_unwrap(),
            )
            .test_unwrap()
        });
        let compiled = compile(admitted, runtime, &BTreeMap::new(), broker).test_unwrap();
        let record = launch(compiled, CageLaunchOptions::default())
            .test_unwrap()
            .wait()
            .test_unwrap();
        let exit = record.exit.test_expect("observed probe exit");
        if permitted {
            assert_eq!(
                exit.exit_code,
                Some(0),
                "reviewed descriptor operation works"
            );
        } else {
            assert_eq!(exit.signal, Some(libc::SIGSYS), "unreviewed fcntl denied");
        }
    }
}
