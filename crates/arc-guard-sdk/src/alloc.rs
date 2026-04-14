// Stub -- allocator will be implemented after tests are written.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn alloc_positive_size_returns_nonzero() {
        reset_allocations();
        let ptr = arc_alloc(100);
        assert_ne!(ptr, 0, "arc_alloc(100) should return a non-zero pointer");
        reset_allocations();
    }

    #[test]
    fn alloc_zero_returns_zero() {
        reset_allocations();
        let ptr = arc_alloc(0);
        assert_eq!(ptr, 0, "arc_alloc(0) should return 0");
        reset_allocations();
    }

    #[test]
    fn alloc_negative_returns_zero() {
        reset_allocations();
        let ptr = arc_alloc(-1);
        assert_eq!(ptr, 0, "arc_alloc(-1) should return 0");
        reset_allocations();
    }

    #[test]
    fn alloc_multiple_returns_different_pointers() {
        reset_allocations();
        let p1 = arc_alloc(64);
        let p2 = arc_alloc(64);
        assert_ne!(p1, 0);
        assert_ne!(p2, 0);
        assert_ne!(p1, p2, "Two allocations should return different pointers");
        reset_allocations();
    }

    #[test]
    fn free_does_not_panic() {
        reset_allocations();
        let ptr = arc_alloc(32);
        // Free a valid allocation
        arc_free(ptr, 32);
        // Free an invalid allocation (should not panic)
        arc_free(999, 999);
        reset_allocations();
    }
}
