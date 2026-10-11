#[path = "expansion_tests.rs"]
mod expansion_tests;

use super::{
    event_time_is_ordered_and_within, merge_validated_group_watermark, GroupWatermarkKnowledge,
    ValidatedGroupWatermarkMerge, MAX_JSON_SAFE_INTEGER,
};

#[test]
fn event_time_window_rejects_reverse_and_expired_sequences() {
    assert!(event_time_is_ordered_and_within(120, 100, 20));
    assert!(!event_time_is_ordered_and_within(99, 100, 20));
    assert!(!event_time_is_ordered_and_within(121, 100, 20));
}

#[test]
fn committed_group_watermark_rejects_contradictory_values() {
    assert_eq!(
        GroupWatermarkKnowledge::committed(0, 10),
        GroupWatermarkKnowledge::Contradictory { unix_ms: 0 }
    );
    assert_eq!(
        GroupWatermarkKnowledge::committed(11, 10),
        GroupWatermarkKnowledge::Contradictory { unix_ms: 11 }
    );
    assert_eq!(
        GroupWatermarkKnowledge::committed(
            MAX_JSON_SAFE_INTEGER.saturating_add(1),
            MAX_JSON_SAFE_INTEGER.saturating_add(1),
        ),
        GroupWatermarkKnowledge::Contradictory {
            unix_ms: MAX_JSON_SAFE_INTEGER.saturating_add(1),
        }
    );
    assert_eq!(
        GroupWatermarkKnowledge::committed(9, 10),
        GroupWatermarkKnowledge::Committed { unix_ms: 9 }
    );
}

#[test]
fn validated_group_watermark_merge_is_numerically_monotonic() {
    let committed_90 = GroupWatermarkKnowledge::Committed { unix_ms: 90 };
    assert_eq!(
        merge_validated_group_watermark(GroupWatermarkKnowledge::Unknown, committed_90,),
        ValidatedGroupWatermarkMerge::Accepted(committed_90)
    );
    assert_eq!(
        merge_validated_group_watermark(committed_90, GroupWatermarkKnowledge::Unknown,),
        ValidatedGroupWatermarkMerge::Accepted(committed_90)
    );
    assert_eq!(
        merge_validated_group_watermark(
            committed_90,
            GroupWatermarkKnowledge::Committed { unix_ms: 100 },
        ),
        ValidatedGroupWatermarkMerge::Accepted(GroupWatermarkKnowledge::Committed { unix_ms: 100 })
    );
    assert_eq!(
        merge_validated_group_watermark(
            committed_90,
            GroupWatermarkKnowledge::Committed { unix_ms: 80 },
        ),
        ValidatedGroupWatermarkMerge::Regression {
            retained: committed_90,
        }
    );
}
