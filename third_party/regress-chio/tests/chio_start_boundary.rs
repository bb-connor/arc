use regress::Regex;

// Byte offsets in `find` which split a UTF-8 character panic,
// while out-of-range offsets simply yield no matches (JS `lastIndex` semantics).
// Regression test for #159.
#[test]
fn test_find_from_char_boundaries() {
    let re = Regex::new(".").unwrap();

    // Valid boundary offsets in a multi-byte string keep working.
    let text = "a😀b"; // bytes: 'a'=0, '😀'=1..5, 'b'=5
    assert_eq!(re.find_from(text, 0).next().unwrap().range(), 0..1);
    assert_eq!(re.find_from(text, 1).next().unwrap().range(), 1..5);
    assert_eq!(re.find_from(text, 5).next().unwrap().range(), 5..6);
    assert!(re.find_from(text, text.len()).next().is_none());

    // A start inside a multi-byte character must panic cleanly rather than
    // reading out of bounds.
    let panics_with_boundary = |f: &dyn Fn()| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(f))
            .err()
            .and_then(|p| p.downcast_ref::<&str>().copied())
            .is_some_and(|msg| msg.contains("char boundary"))
    };

    // Start inside a 4-byte character.
    assert!(panics_with_boundary(&|| {
        let _ = re.find_from("😀", 3).next();
    }));
    // Start inside a 2-byte character.
    assert!(panics_with_boundary(&|| {
        let _ = re.find_from("é", 1).next();
    }));

    // An out-of-range start is not an error: it yields no matches, mirroring
    // JavaScript's `lastIndex` semantics rather than panicking.
    assert!(re.find_from("abc", 4).next().is_none());
    assert!(re.find_from("abc", 100).next().is_none());

    // The ascii entry point steps byte-by-byte, so a start inside a multi-byte
    // character is memory-safe and must NOT panic (it treats each byte as an
    // element).
    assert_eq!(re.find_from_ascii("😀", 3).next().unwrap().range(), 3..4);
    // An out-of-range ascii start likewise yields no matches, not a panic.
    assert!(re.find_from_ascii("abc", 4).next().is_none());
}
