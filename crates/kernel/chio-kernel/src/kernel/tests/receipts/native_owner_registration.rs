fn require_registered_receipt_store(
    kernel: &ChioKernel,
    expected: &AppendOnlyReceiptStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let configured = kernel
        .receipt_store
        .as_deref()
        .ok_or("missing receipt sink")?;
    let registration = kernel
        .native_receipt_store_registration
        .as_ref()
        .ok_or("missing native receipt registration")?;
    let owner = registration
        .downcast_ref::<AppendOnlyReceiptStore>()
        .ok_or("wrong concrete receipt backend")?;
    let expected_sink: &dyn ReceiptStore = expected;
    assert!(std::ptr::addr_eq(configured, expected_sink));
    assert!(std::ptr::addr_eq(configured, registration.receipt_store()));
    assert!(std::ptr::eq(owner, expected));
    Ok(())
}

#[test]
fn native_receipt_registration_retains_and_reinstalls_the_same_arc(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::NativeReceiptStoreRegistration;

    let mut kernel = make_kernel(make_config());
    let store = Arc::new(AppendOnlyReceiptStore);
    let retained = Arc::downgrade(&store);
    kernel.set_native_receipt_store(NativeReceiptStoreRegistration::new(Arc::clone(&store)))?;
    require_registered_receipt_store(&kernel, &store)?;
    drop(store);
    let same_store = retained
        .upgrade()
        .ok_or("registration lost its owned store")?;
    require_registered_receipt_store(&kernel, &same_store)?;
    kernel
        .set_native_receipt_store(NativeReceiptStoreRegistration::new(Arc::clone(&same_store)))?;
    require_registered_receipt_store(&kernel, &same_store)
}

#[test]
fn successful_ordinary_receipt_replacements_clear_native_registration(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::NativeReceiptStoreRegistration;

    let mut kernel = make_kernel(make_config());
    for setter in 0..3 {
        let original = Arc::new(AppendOnlyReceiptStore);
        kernel.set_native_receipt_store(NativeReceiptStoreRegistration::new(original))?;
        let replacement: Arc<dyn ReceiptStore> = Arc::new(AppendOnlyReceiptStore);
        match setter {
            0 => kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore))?,
            1 => kernel.set_receipt_store_handle(Arc::clone(&replacement))?,
            _ => kernel.try_set_receipt_store_handle(Arc::clone(&replacement))?,
        }
        assert!(kernel.native_receipt_store_registration.is_none());
        if setter != 0 {
            let configured = kernel.receipt_store.as_ref().ok_or("missing replacement")?;
            assert!(Arc::ptr_eq(configured, &replacement));
        }
    }
    Ok(())
}

#[test]
fn failed_receipt_replacements_preserve_the_configured_native_owner(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::NativeReceiptStoreRegistration;

    let mut kernel = make_kernel(make_config());
    let original = Arc::new(AppendOnlyReceiptStore);
    kernel.set_native_receipt_store(NativeReceiptStoreRegistration::new(Arc::clone(&original)))?;
    assert!(kernel
        .set_receipt_store(Box::new(FailingCheckpointHydrationReceiptStore))
        .is_err());
    require_registered_receipt_store(&kernel, &original)?;
    assert!(kernel
        .set_receipt_store_handle(Arc::new(FailingCheckpointHydrationReceiptStore))
        .is_err());
    require_registered_receipt_store(&kernel, &original)?;
    assert!(kernel
        .try_set_receipt_store_handle(Arc::new(FailingCheckpointHydrationReceiptStore))
        .is_err());
    require_registered_receipt_store(&kernel, &original)?;
    assert!(kernel
        .set_native_receipt_store(NativeReceiptStoreRegistration::new(Arc::new(
            FailingCheckpointHydrationReceiptStore,
        )))
        .is_err());
    require_registered_receipt_store(&kernel, &original)
}

#[test]
fn successful_native_receipt_replacement_switches_both_registered_views(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::NativeReceiptStoreRegistration;

    let mut kernel = make_kernel(make_config());
    let original = Arc::new(AppendOnlyReceiptStore);
    kernel.set_native_receipt_store(NativeReceiptStoreRegistration::new(Arc::clone(&original)))?;
    let replacement = Arc::new(AppendOnlyReceiptStore);
    assert!(!Arc::ptr_eq(&original, &replacement));
    kernel.set_native_receipt_store(NativeReceiptStoreRegistration::new(Arc::clone(
        &replacement,
    )))?;
    require_registered_receipt_store(&kernel, &replacement)
}
