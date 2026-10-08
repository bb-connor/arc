use chio_security_types::ports::BoundedVec;
use serde::{Deserialize, Deserializer};
use std::cell::Cell;

thread_local! {
    static DECODED_ELEMENTS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug)]
struct ObservedElement(String);

impl<'de> Deserialize<'de> for ObservedElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        DECODED_ELEMENTS.with(|count| count.set(count.get() + 1));
        String::deserialize(deserializer).map(Self)
    }
}

#[test]
fn excess_sequence_element_is_refused_before_its_decoder_runs(
) -> Result<(), Box<dyn std::error::Error>> {
    for (limit, input, expected_decodes) in [
        (0, r#"["extra"]"#, 0),
        (2, r#"["one","two",{"unexpected":"object"}]"#, 2),
    ] {
        DECODED_ELEMENTS.with(|count| count.set(0));
        let error = match limit {
            0 => serde_json::from_str::<BoundedVec<ObservedElement, 0>>(input).err(),
            2 => serde_json::from_str::<BoundedVec<ObservedElement, 2>>(input).err(),
            _ => return Err("unsupported test bound".into()),
        }
        .ok_or("oversized sequence was accepted")?;
        assert!(
            error
                .to_string()
                .contains("collection exceeds the item limit"),
            "{error}"
        );
        DECODED_ELEMENTS.with(|count| assert_eq!(count.get(), expected_decodes));
    }
    Ok(())
}

#[test]
fn empty_and_exact_capacity_sequences_preserve_values() -> Result<(), Box<dyn std::error::Error>> {
    DECODED_ELEMENTS.with(|count| count.set(0));
    let empty: BoundedVec<ObservedElement, 0> = serde_json::from_str("[]")?;
    assert!(empty.is_empty());
    DECODED_ELEMENTS.with(|count| assert_eq!(count.get(), 0));
    let exact: BoundedVec<ObservedElement, 2> = serde_json::from_str(r#"["one","two"]"#)?;
    assert_eq!(
        exact
            .as_slice()
            .iter()
            .map(|item| item.0.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
    DECODED_ELEMENTS.with(|count| assert_eq!(count.get(), 2));
    Ok(())
}
