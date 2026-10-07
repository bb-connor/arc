//! Private immutable label storage has four bounded contiguous allocations.
use crate::recovery::RecoveryRuntimeError;
use chio_security_types::InformationLabel;
use chio_security_types::flow::{
    Compartment, DEFAULT_LABEL_LIMITS, MAX_FLOW_IDENTIFIER_BYTES, PrincipalId,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy)]
struct Span {
    offset: u32,
    bytes: u16,
}

struct Owner {
    name: Span,
    reader_start: u16,
    reader_count: u16,
}

enum Shape {
    Top,
    Known {
        strings: Box<str>,
        owners: Box<[Owner]>,
        readers: Box<[Span]>,
        compartments: Box<[Span]>,
    },
}

pub(super) struct FlatLabel(Shape);

impl core::fmt::Debug for FlatLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FlatLabel([redacted])")
    }
}

fn invalid() -> RecoveryRuntimeError {
    RecoveryRuntimeError::UnsupportedProfile
}

fn add(total: usize, amount: usize) -> Result<usize, RecoveryRuntimeError> {
    total.checked_add(amount).ok_or_else(invalid)
}

fn span(strings: &mut String, value: &str) -> Result<Span, RecoveryRuntimeError> {
    if value.len() > MAX_FLOW_IDENTIFIER_BYTES {
        return Err(invalid());
    }
    let result = Span {
        offset: u32::try_from(strings.len()).map_err(|_| invalid())?,
        bytes: u16::try_from(value.len()).map_err(|_| invalid())?,
    };
    strings.push_str(value);
    Ok(result)
}

fn value(strings: &str, span: Span) -> Result<&str, RecoveryRuntimeError> {
    let start = usize::try_from(span.offset).map_err(|_| invalid())?;
    let end = add(start, usize::from(span.bytes))?;
    strings.get(start..end).ok_or_else(invalid)
}

impl FlatLabel {
    pub(super) fn new(label: InformationLabel) -> Result<Self, RecoveryRuntimeError> {
        let InformationLabel::Known {
            owners,
            compartments,
            ..
        } = label
        else {
            return Ok(Self(Shape::Top));
        };
        let limits = DEFAULT_LABEL_LIMITS;
        if owners.len() > limits.max_owners()
            || compartments.len() > limits.max_compartments()
            || owners.iter().any(|(owner, readers)| {
                readers.len() > limits.max_readers_per_owner() || !readers.contains(owner)
            })
        {
            return Err(invalid());
        }
        let reader_count = owners
            .values()
            .try_fold(0usize, |total, readers| add(total, readers.len()))?;
        let string_bytes = owners
            .iter()
            .flat_map(|(owner, readers)| core::iter::once(owner).chain(readers))
            .map(PrincipalId::as_str)
            .chain(compartments.iter().map(Compartment::as_str))
            .try_fold(0usize, |total, identifier| {
                if identifier.len() > MAX_FLOW_IDENTIFIER_BYTES {
                    return Err(invalid());
                }
                add(total, identifier.len())
            })?;
        let mut strings = String::with_capacity(string_bytes);
        let mut flat_owners = Vec::with_capacity(owners.len());
        let mut flat_readers = Vec::with_capacity(reader_count);
        let mut flat_compartments = Vec::with_capacity(compartments.len());
        for (owner, readers) in owners {
            let name = span(&mut strings, owner.as_str())?;
            let reader_start = u16::try_from(flat_readers.len()).map_err(|_| invalid())?;
            let reader_count = u16::try_from(readers.len()).map_err(|_| invalid())?;
            for reader in readers {
                flat_readers.push(span(&mut strings, reader.as_str())?);
            }
            flat_owners.push(Owner {
                name,
                reader_start,
                reader_count,
            });
        }
        for compartment in compartments.iter() {
            flat_compartments.push(span(&mut strings, compartment.as_str())?);
        }
        if strings.len() != string_bytes {
            return Err(invalid());
        }
        Ok(Self(Shape::Known {
            strings: strings.into_boxed_str(),
            owners: flat_owners.into_boxed_slice(),
            readers: flat_readers.into_boxed_slice(),
            compartments: flat_compartments.into_boxed_slice(),
        }))
    }

    pub(super) fn expand(&self) -> Result<InformationLabel, RecoveryRuntimeError> {
        let Shape::Known {
            strings,
            owners,
            readers,
            compartments,
        } = &self.0
        else {
            return Ok(InformationLabel::Top);
        };
        let mut full_owners = BTreeMap::new();
        for owner in owners.iter() {
            let start = usize::from(owner.reader_start);
            let end = add(start, usize::from(owner.reader_count))?;
            let encoded_readers = readers.get(start..end).ok_or_else(invalid)?;
            let name = PrincipalId::new(value(strings, owner.name)?).map_err(|_| invalid())?;
            let mut full_readers = BTreeSet::new();
            for reader in encoded_readers {
                let reader = PrincipalId::new(value(strings, *reader)?).map_err(|_| invalid())?;
                if !full_readers.insert(reader) {
                    return Err(invalid());
                }
            }
            if full_owners.insert(name, full_readers).is_some() {
                return Err(invalid());
            }
        }
        let mut full_compartments = BTreeSet::new();
        for compartment in compartments.iter() {
            let compartment =
                Compartment::new(value(strings, *compartment)?).map_err(|_| invalid())?;
            if !full_compartments.insert(compartment) {
                return Err(invalid());
            }
        }
        InformationLabel::try_known(full_owners, full_compartments).map_err(|_| invalid())
    }

    pub(super) fn resident_bytes(&self) -> Result<usize, RecoveryRuntimeError> {
        let mut bytes = core::mem::size_of::<Self>();
        if let Shape::Known {
            strings,
            owners,
            readers,
            compartments,
        } = &self.0
        {
            for amount in [
                strings.len(),
                core::mem::size_of_val(owners.as_ref()),
                core::mem::size_of_val(readers.as_ref()),
                core::mem::size_of_val(compartments.as_ref()),
            ] {
                bytes = add(bytes, amount)?;
            }
        }
        Ok(bytes)
    }

    pub(super) fn maximum_resident_bytes() -> Result<usize, RecoveryRuntimeError> {
        let limits = DEFAULT_LABEL_LIMITS;
        let owners = limits.max_owners();
        let readers = owners
            .checked_mul(limits.max_readers_per_owner())
            .ok_or_else(invalid)?;
        let compartments = limits.max_compartments();
        let identifiers = add(add(owners, readers)?, compartments)?;
        let mut bytes = core::mem::size_of::<Self>();
        for amount in [
            identifiers
                .checked_mul(MAX_FLOW_IDENTIFIER_BYTES)
                .ok_or_else(invalid)?,
            owners
                .checked_mul(core::mem::size_of::<Owner>())
                .ok_or_else(invalid)?,
            readers
                .checked_mul(core::mem::size_of::<Span>())
                .ok_or_else(invalid)?,
            compartments
                .checked_mul(core::mem::size_of::<Span>())
                .ok_or_else(invalid)?,
        ] {
            bytes = add(bytes, amount)?;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn flat_labels_preserve_unicode_byte_spans_and_conservative_top() -> TestResult {
        let owner = PrincipalId::new("owner:😀")?;
        let label = InformationLabel::try_known(
            BTreeMap::from([(
                owner.clone(),
                BTreeSet::from([owner, PrincipalId::new("reader:\"é\\漢字")?]),
            )]),
            BTreeSet::from([Compartment::new("compartment:α😀")?]),
        )?;
        let compact = FlatLabel::new(label.clone())?;
        assert_eq!(compact.expand()?, label);
        assert!(compact.resident_bytes()? <= FlatLabel::maximum_resident_bytes()?);
        assert!(matches!(
            FlatLabel::new(InformationLabel::Top)?.expand()?,
            InformationLabel::Top
        ));
        assert!(!format!("{compact:?}").contains("漢字"));
        Ok(())
    }

    #[test]
    fn maximum_structural_labels_fit_the_checked_flat_and_encoded_reservations() -> TestResult {
        let limits = DEFAULT_LABEL_LIMITS;
        let mut owners = BTreeMap::new();
        for index in 0..limits.max_owners() {
            let prefix = format!("owner:{index:02}:");
            let owner = PrincipalId::new(format!(
                "{prefix}{}",
                "\"".repeat(MAX_FLOW_IDENTIFIER_BYTES - prefix.len())
            ))?;
            let mut readers = BTreeSet::from([owner.clone()]);
            for reader in 1..limits.max_readers_per_owner() {
                let prefix = format!("reader:{index:02}:{reader:03}:");
                readers.insert(PrincipalId::new(format!(
                    "{prefix}{}",
                    "\"".repeat(MAX_FLOW_IDENTIFIER_BYTES - prefix.len())
                ))?);
            }
            owners.insert(owner, readers);
        }
        let compartments = (0..limits.max_compartments())
            .map(|index| {
                let prefix = format!("compartment:{index:02}:");
                Compartment::new(format!(
                    "{prefix}{}",
                    "\"".repeat(MAX_FLOW_IDENTIFIER_BYTES - prefix.len())
                ))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let label = InformationLabel::try_known(owners, compartments)?;
        let encoded_bound = super::super::bounds::maximum_label_wire_bytes()?;
        let encoded = super::super::bounds::measure(&label, encoded_bound)?;
        assert!(encoded <= encoded_bound);
        let compact = FlatLabel::new(label.clone())?;
        assert!(compact.resident_bytes()? <= FlatLabel::maximum_resident_bytes()?);
        assert_eq!(compact.expand()?, label);
        Ok(())
    }
}
