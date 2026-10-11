//! Measure allocations by the real report-data functions on this test thread.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

use chio_attest_verify::{expect_report_data, QuoteVerificationContext};
use chio_core_types::crypto::PublicKey;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Default)]
struct AllocationCounts {
    alloc: usize,
    zeroed: usize,
    realloc: usize,
}

impl AllocationCounts {
    const ZERO: Self = Self {
        alloc: 0,
        zeroed: 0,
        realloc: 0,
    };

    fn total(self) -> usize {
        self.alloc
            .saturating_add(self.zeroed)
            .saturating_add(self.realloc)
    }
}

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<AllocationCounts> = const { Cell::new(AllocationCounts::ZERO) };
}

enum AllocationKind {
    Alloc,
    Zeroed,
    Realloc,
}

fn record(kind: AllocationKind) {
    if ACTIVE.try_with(Cell::get) == Ok(true) {
        let _ = COUNTS.try_with(|cell| {
            let mut counts = cell.get();
            let count = match kind {
                AllocationKind::Alloc => &mut counts.alloc,
                AllocationKind::Zeroed => &mut counts.zeroed,
                AllocationKind::Realloc => &mut counts.realloc,
            };
            *count = count.saturating_add(1);
            cell.set(counts);
        });
    }
}

struct CountingAllocator;

// SAFETY: Every allocation request is forwarded unchanged to System. The
// thread-local counters neither allocate nor change pointer/layout ownership.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(AllocationKind::Alloc);
        // SAFETY: The caller's valid allocation layout is forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(AllocationKind::Zeroed);
        // SAFETY: The caller's valid allocation layout is forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(AllocationKind::Realloc);
        // SAFETY: The caller's live pointer, original layout and new size are
        // forwarded to the same allocator that owns the allocation.
        unsafe { System.realloc(pointer, layout, size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The caller's pointer and layout are forwarded unchanged to
        // the same allocator that owns the allocation.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct Measurement;

impl Drop for Measurement {
    fn drop(&mut self) {
        let _ = ACTIVE.try_with(|active| active.set(false));
    }
}

fn measure<T>(operation: impl FnOnce() -> T) -> (T, AllocationCounts) {
    assert!(!ACTIVE.with(Cell::get), "allocation scopes cannot nest");
    COUNTS.with(|counts| counts.set(AllocationCounts::ZERO));
    ACTIVE.with(|active| active.set(true));
    let measurement = Measurement;
    let output = operation();
    drop(measurement);
    (output, COUNTS.with(Cell::get))
}

#[test]
fn counter_is_calibrated_with_real_allocation_and_growth() {
    let (bytes, counts) = measure(|| {
        let mut bytes = black_box(Vec::with_capacity(1));
        bytes.push(black_box(7u8));
        bytes.push(black_box(9u8));
        black_box(bytes)
    });
    assert_eq!(bytes, [7, 9]);
    assert!(counts.alloc > 0, "allocation counter is inert: {counts:?}");
    assert!(counts.realloc > 0, "growth counter is inert: {counts:?}");

    let (zeroes, counts) = measure(|| black_box(vec![0u8; 64]));
    assert_eq!(zeroes, [0; 64]);
    assert!(counts.zeroed > 0, "zeroed counter is inert: {counts:?}");
}

struct Fixture {
    key: PublicKey,
    root: [u8; 32],
    expected: [u8; 64],
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut bytes = [black_box(7u8); 65];
    bytes[0] = 4;
    let key = PublicKey::from_p256_sec1(&bytes)?;
    let root = [9; 32];
    let mut hash = Sha256::new();
    hash.update(key.to_hex().as_bytes());
    hash.update(root);
    let mut expected = [0; 64];
    expected[..32].copy_from_slice(&hash.finalize());
    Ok(Fixture {
        key,
        root,
        expected,
    })
}

#[test]
fn p256_report_data_hashes_wire_bytes_without_allocating() -> Result<(), Box<dyn std::error::Error>>
{
    let Fixture {
        key,
        root,
        expected,
    } = fixture()?;
    let (actual, counts) =
        measure(|| black_box(expect_report_data(black_box(&key), black_box(&root))));
    assert_eq!(actual, expected);
    assert_eq!(counts.total(), 0, "report-data allocations: {counts:?}");
    Ok(())
}

#[test]
fn p256_context_report_data_does_not_allocate() -> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        key,
        root,
        expected,
    } = fixture()?;
    let context = QuoteVerificationContext::new(&key, &root);
    let (actual, counts) = measure(|| black_box(black_box(&context).expected_report_data()));
    assert_eq!(actual, expected);
    assert_eq!(
        counts.total(),
        0,
        "context report-data allocations: {counts:?}"
    );
    Ok(())
}
