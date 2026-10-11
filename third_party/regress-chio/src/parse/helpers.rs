use super::*;

pub(super) fn error<S, T>(text: S) -> Result<T, Error>
where
    S: ToString,
{
    Err(Error {
        text: text.to_string(),
    })
}

pub(super) fn make_cat(nodes: ir::NodeList) -> ir::Node {
    match nodes.len() {
        0 => ir::Node::Empty,
        1 => nodes.into_iter().next().unwrap(),
        _ => ir::Node::Cat(nodes),
    }
}

pub(super) fn make_alt(nodes: ir::NodeList) -> ir::Node {
    let mut mright = None;
    for node in nodes.into_iter().rev() {
        match mright {
            None => mright = Some(node),
            Some(right) => mright = Some(ir::Node::Alt(Box::new(node), Box::new(right))),
        }
    }
    mright.unwrap_or(ir::Node::Empty)
}

/// \return a CodePointSet for a given character escape (positive or negative).
/// See ES9 21.2.2.12.
/// Returns the positive (non-inverted) code point set for a character class.
pub(super) fn codepoints_from_class_positive(ct: CharacterClassType) -> CodePointSet {
    let mut cps;
    match ct {
        CharacterClassType::Digits => {
            cps = CodePointSet::from_sorted_disjoint_intervals(charclasses::DIGITS.to_vec())
        }
        CharacterClassType::Words => {
            cps = CodePointSet::from_sorted_disjoint_intervals(charclasses::WORD_CHARS.to_vec())
        }
        CharacterClassType::Spaces => {
            cps = CodePointSet::from_sorted_disjoint_intervals(charclasses::WHITESPACE.to_vec());
            for &iv in charclasses::LINE_TERMINATOR.iter() {
                cps.add(iv)
            }
        }
    }
    cps
}

/// Returns code points for a character class, optionally inverted.
pub(super) fn codepoints_from_class(ct: CharacterClassType, positive: bool) -> CodePointSet {
    let cps = codepoints_from_class_positive(ct);
    if positive { cps } else { cps.inverted() }
}

/// \return a Bracket for a given character escape (positive or negative).
/// For icase mode, we expand the positive set first, then invert if needed.
pub(super) fn make_bracket_class(ct: CharacterClassType, positive: bool, icase: bool) -> ir::Node {
    // Get the positive (non-inverted) set, perform any icase expansion, then maybe invert.
    let mut cps = codepoints_from_class_positive(ct);
    if icase {
        cps = unicode::add_icase_code_points(cps);
    }
    if !positive {
        cps = cps.inverted();
    }
    ir::Node::Bracket(BracketContents { invert: false, cps })
}

pub(super) fn add_class_atom(bc: &mut BracketContents, atom: ClassAtom) {
    match atom {
        ClassAtom::CodePoint(c) => bc.cps.add_one(c),
        ClassAtom::CharacterClass {
            class_type,
            positive,
        } => {
            bc.cps.add_set(codepoints_from_class(class_type, positive));
        }
        ClassAtom::Range { iv, negate } => {
            if negate {
                bc.cps.add_set(iv.inverted());
            } else {
                bc.cps.add_set(iv);
            }
        }
    }
}
