use std::path::Path;

use chio_store_sqlite::SqliteCapabilityAuthority;

/// Model the operator's out-of-band provisioning before any peer HTTP starts.
/// Only the first node holds the initial signing key. Followers receive public
/// trust and a signed envelope, never the custodian's private seed.
pub(super) fn provision_cluster_authorities(directory: &Path, names: &[&str]) {
    let (custodian_name, followers) = names.split_first().expect("cluster custodian");
    let custodian = SqliteCapabilityAuthority::open(directory.join(custodian_name))
        .expect("open cluster custodian");
    let anchor = custodian
        .initialize_replication("cli-cluster-fixture")
        .expect("initialize authenticated cluster stream");
    let envelope = custodian.signed_snapshot().expect("sign initial authority");
    for name in followers {
        let follower =
            SqliteCapabilityAuthority::open(directory.join(name)).expect("open cluster follower");
        follower
            .pin_replication_anchor(&anchor)
            .expect("provision public cluster anchor");
        follower
            .apply_signed_snapshot(&envelope)
            .expect("provision authenticated initial envelope");
    }
}
