//! Kernel store port errors carry a closed, copyable IO fault kind and never
//! the `std::io::Error` that produced it.

use std::io::{Error, ErrorKind};

use chio_kernel::{
    AuthorityStoreError, BudgetStoreError, IoFault, ReceiptStoreError, RevocationStoreError,
};

const LEAKED_TEXT: &str = "/var/lib/chio/secret-path";

fn closed<T: Copy + Eq + std::fmt::Debug>(fault: T) -> T {
    fault
}

fn os_error(kind: ErrorKind) -> Error {
    Error::new(kind, LEAKED_TEXT)
}

#[test]
fn every_store_port_error_folds_io_into_a_closed_fault() {
    let receipt = ReceiptStoreError::from(os_error(ErrorKind::PermissionDenied));
    let ReceiptStoreError::Io(fault) = receipt else {
        panic!("receipt store io error must fold into Io: {receipt:?}");
    };
    assert_eq!(closed(fault), IoFault::PermissionDenied);

    let revocation = RevocationStoreError::from(os_error(ErrorKind::NotFound));
    let RevocationStoreError::Io(fault) = revocation else {
        panic!("revocation store io error must fold into Io: {revocation:?}");
    };
    assert_eq!(closed(fault), IoFault::NotFound);

    let budget = BudgetStoreError::from(os_error(ErrorKind::StorageFull));
    let BudgetStoreError::Io(fault) = budget else {
        panic!("budget store io error must fold into Io: {budget:?}");
    };
    assert_eq!(closed(fault), IoFault::StorageFull);

    let authority = AuthorityStoreError::from(os_error(ErrorKind::ReadOnlyFilesystem));
    let AuthorityStoreError::Io(fault) = authority else {
        panic!("authority store io error must fold into Io: {authority:?}");
    };
    assert_eq!(closed(fault), IoFault::ReadOnlyFilesystem);
}

#[test]
fn store_port_errors_never_render_the_os_error_text() {
    let rendered = [
        ReceiptStoreError::from(os_error(ErrorKind::Other)).to_string(),
        RevocationStoreError::from(os_error(ErrorKind::Other)).to_string(),
        BudgetStoreError::from(os_error(ErrorKind::Other)).to_string(),
        AuthorityStoreError::from(os_error(ErrorKind::Other)).to_string(),
    ];
    for message in rendered {
        assert!(!message.contains(LEAKED_TEXT), "{message}");
    }
}

#[test]
fn io_fault_mapping_is_pinned() {
    let table = [
        (ErrorKind::NotFound, IoFault::NotFound),
        (ErrorKind::PermissionDenied, IoFault::PermissionDenied),
        (ErrorKind::AlreadyExists, IoFault::AlreadyExists),
        (ErrorKind::NotADirectory, IoFault::NotADirectory),
        (ErrorKind::IsADirectory, IoFault::IsADirectory),
        (ErrorKind::DirectoryNotEmpty, IoFault::DirectoryNotEmpty),
        (ErrorKind::ReadOnlyFilesystem, IoFault::ReadOnlyFilesystem),
        (ErrorKind::StorageFull, IoFault::StorageFull),
        (ErrorKind::FileTooLarge, IoFault::FileTooLarge),
        (ErrorKind::ResourceBusy, IoFault::ResourceBusy),
        (ErrorKind::CrossesDevices, IoFault::CrossesDevices),
        (ErrorKind::WouldBlock, IoFault::WouldBlock),
        (ErrorKind::Interrupted, IoFault::Interrupted),
        (ErrorKind::TimedOut, IoFault::TimedOut),
        (ErrorKind::InvalidInput, IoFault::InvalidInput),
        (ErrorKind::InvalidData, IoFault::InvalidData),
        (ErrorKind::UnexpectedEof, IoFault::UnexpectedEof),
        (ErrorKind::WriteZero, IoFault::WriteZero),
        (ErrorKind::Unsupported, IoFault::Unsupported),
        (ErrorKind::OutOfMemory, IoFault::OutOfMemory),
        (ErrorKind::Other, IoFault::Other),
        (ErrorKind::BrokenPipe, IoFault::Other),
        (ErrorKind::ConnectionReset, IoFault::Other),
    ];
    for (kind, fault) in table {
        assert_eq!(IoFault::from(kind), fault, "{kind:?}");
        assert_eq!(IoFault::from(&Error::from(kind)), fault, "{kind:?}");
    }
}
