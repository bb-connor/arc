include!("ports_parts/part_01.rs");
include!("ports_parts/part_02.rs");
include!("ports_parts/part_03.rs");
include!("ports_parts/part_04.rs");

#[cfg(feature = "std")]
#[path = "egress_projection.rs"]
mod egress_projection;
#[cfg(feature = "std")]
pub use egress_projection::*;

#[cfg(feature = "std")]
#[path = "issuance_projection.rs"]
mod issuance_projection;
#[cfg(feature = "std")]
pub use issuance_projection::*;
