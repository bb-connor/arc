//! Retention behavior tests (co-archive-and-delete, watermark, chain
//! exemption, size convergence, recovery).

include!("retention/foundations.inc");
include!("retention/rotation.inc");
include!("retention/repair.inc");
include!("retention/health.inc");
include!("retention/tombstones.inc");
include!("retention/commit_guard.inc");
include!("retention/iou_and_identity.inc");
include!("retention/archive_security.inc");
include!("retention/archive_ownership.inc");
