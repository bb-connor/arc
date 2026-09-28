#[path = "event_consumer/admission_request.rs"]
mod admission_request;
#[cfg(test)]
#[path = "event_consumer/test_clocks.rs"]
mod test_clocks;
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/event_consumer_parts/part_01.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/event_consumer_parts/part_03.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/event_consumer_parts/part_04.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/event_consumer_parts/part_02.inc"
));
