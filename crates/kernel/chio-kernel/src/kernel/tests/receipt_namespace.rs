use super::*;

#[test]
fn identical_request_ids_do_not_merge_authenticated_namespaces() {
    let kernel = make_kernel(make_config());
    let local = kernel
        .receipt_request_namespace_digest("shared-id")
        .unwrap();
    let tenant_a = {
        let _scope =
            kernel.scope_receipt_tenant_id_for_request("shared-id", Some("tenant-a".into()));
        kernel
            .receipt_request_namespace_digest("shared-id")
            .unwrap()
    };
    let tenant_b = {
        let _scope =
            kernel.scope_receipt_tenant_id_for_request("shared-id", Some("tenant-b".into()));
        kernel
            .receipt_request_namespace_digest("shared-id")
            .unwrap()
    };
    assert_ne!(tenant_a, tenant_b);
    assert_ne!(local, tenant_a);
    assert_ne!(local, tenant_b);
    assert_eq!(
        kernel
            .receipt_request_namespace_digest("shared-id")
            .unwrap(),
        local
    );
}

#[test]
fn namespace_is_stable_across_requests_for_the_same_authority() {
    let config = make_config();
    let mut second_config = make_config();
    second_config.keypair = config.keypair.clone();
    let first = make_kernel(config);
    let second = make_kernel(second_config);
    assert_eq!(
        first
            .receipt_request_namespace_digest("first-request")
            .unwrap(),
        second
            .receipt_request_namespace_digest("second-request")
            .unwrap()
    );
}
