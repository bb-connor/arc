use nono::{AccessMode, CapabilitySet, CapabilitySource, FsCapability, NetworkMode};
use std::path::PathBuf;

fn grant(access: AccessMode, source: CapabilitySource, is_file: bool) -> FsCapability {
    FsCapability {
        original: PathBuf::from("/review/same-resource"),
        resolved: PathBuf::from("/review/same-resource"),
        access,
        is_file,
        source,
    }
}

fn normalize(mut entries: Vec<FsCapability>, reverse: bool) -> CapabilitySet {
    if reverse {
        entries.reverse();
    }
    let mut caps = CapabilitySet::new().block_network();
    for entry in entries {
        caps.add_fs(entry);
    }
    caps.deduplicate();
    caps
}

const MODES: [AccessMode; 3] = [AccessMode::Read, AccessMode::Write, AccessMode::ReadWrite];

#[test]
fn explicit_grant_wins_over_every_system_permission_in_either_order() {
    for explicit in [CapabilitySource::User, CapabilitySource::Profile] {
        for implicit in [
            CapabilitySource::System,
            CapabilitySource::Group("base".into()),
        ] {
            for selected in MODES {
                for inherited in MODES {
                    for reverse in [false, true] {
                        for is_file in [false, true] {
                            let caps = normalize(
                                vec![
                                    grant(selected, explicit.clone(), is_file),
                                    grant(inherited, implicit.clone(), is_file),
                                ],
                                reverse,
                            );
                            assert_eq!(caps.fs_capabilities().len(), 1);
                            let actual = &caps.fs_capabilities()[0];
                            assert_eq!(actual.source, explicit);
                            assert_eq!(
                                actual.access, selected,
                                "inherited={inherited:?}, reverse={reverse}"
                            );
                        }
                    }
                }
            }
        }
    }
}

fn permission_bits(access: AccessMode) -> u8 {
    match access {
        AccessMode::Read => 1,
        AccessMode::Write => 2,
        AccessMode::ReadWrite => 3,
    }
}

#[test]
fn same_provenance_tier_keeps_the_union_of_explicit_permissions() {
    for (left_source, right_source) in [
        (CapabilitySource::User, CapabilitySource::Profile),
        (
            CapabilitySource::System,
            CapabilitySource::Group("base".into()),
        ),
    ] {
        for left in MODES {
            for right in MODES {
                for reverse in [false, true] {
                    let caps = normalize(
                        vec![
                            grant(left, left_source.clone(), true),
                            grant(right, right_source.clone(), true),
                        ],
                        reverse,
                    );
                    assert_eq!(caps.fs_capabilities().len(), 1);
                    assert_eq!(
                        permission_bits(caps.fs_capabilities()[0].access),
                        permission_bits(left) | permission_bits(right),
                    );
                }
            }
        }
    }
}

#[test]
fn discarded_system_merges_cannot_leak_into_a_later_explicit_grant() {
    let inherited = [
        grant(AccessMode::Read, CapabilitySource::System, true),
        grant(
            AccessMode::Write,
            CapabilitySource::Group("base".into()),
            true,
        ),
    ];
    for selected in [AccessMode::Read, AccessMode::Write] {
        for insertion in 0..=2 {
            for reverse in [false, true] {
                let mut entries = inherited.to_vec();
                entries.insert(insertion, grant(selected, CapabilitySource::User, true));
                let caps = normalize(entries, reverse);
                assert_eq!(caps.fs_capabilities().len(), 1);
                assert_eq!(caps.fs_capabilities()[0].source, CapabilitySource::User);
                assert_eq!(caps.fs_capabilities()[0].access, selected);
            }
        }
    }
}

#[test]
fn file_and_directory_grants_remain_distinct() {
    let caps = normalize(
        vec![
            grant(AccessMode::Read, CapabilitySource::User, true),
            grant(AccessMode::Write, CapabilitySource::System, false),
        ],
        false,
    );
    assert_eq!(caps.fs_capabilities().len(), 2);
    assert_eq!(caps.fs_capabilities()[0].access, AccessMode::Read);
    assert_eq!(caps.fs_capabilities()[1].access, AccessMode::Write);
}

#[test]
fn chio_selected_constructor_has_no_path_or_port_grants() {
    let caps = CapabilitySet::new().block_network();
    assert_eq!(caps.network_mode(), &NetworkMode::Blocked);
    assert!(caps.fs_capabilities().is_empty());
    assert!(caps.unix_socket_capabilities().is_empty());
    assert!(caps.tcp_connect_ports().is_empty());
    assert!(caps.tcp_bind_ports().is_empty());
    assert!(caps.localhost_ports().is_empty());
    assert!(!caps.extensions_enabled());
}
