//! Mount identity probe shared by GNU and musl Linux builds.

use rustix::fs::{statx, AtFlags, StatxFlags, CWD};

pub(super) fn available() -> bool {
    // Use the syscall ABI independently of a libc wrapper. Success alone is
    // insufficient: older kernels may omit the requested mount identity.
    statx(CWD, "/", AtFlags::empty(), StatxFlags::MNT_ID)
        .is_ok_and(|stat| has_mount_id(stat.stx_mask))
}

fn has_mount_id(mask: u32) -> bool {
    StatxFlags::from_bits_retain(mask).contains(StatxFlags::MNT_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_id_requires_an_explicit_result_bit() {
        assert!(!has_mount_id(0));
        assert!(!has_mount_id(StatxFlags::BASIC_STATS.bits()));
        assert!(has_mount_id(StatxFlags::MNT_ID.bits()));
        assert!(has_mount_id((StatxFlags::BASIC_STATS | StatxFlags::MNT_ID).bits()));
    }

    #[test]
    fn host_probe_is_safe_when_supported_or_unavailable() {
        let _observed = available();
    }
}
