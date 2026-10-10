//! Bounded, byte-preserving candidates for exact decoy lookups.
//!
//! Inspect keys and string values, including common header, cookie, URL and
//! command delimiters. This is not a decoder or arbitrary substring search.
//! Every emission is charged before deduplication; repeated inputs cannot hide
//! work behind a small unique set. Complete collection precedes any lookup.

use chio_security_types::ports::{PortError, PortResult};
use serde_json::Value;

const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 4096;
const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_CANDIDATES: usize = 4096;
const MAX_CANDIDATE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default)]
struct Candidates<'a> {
    values: Vec<&'a str>,
    nodes: usize,
    input_bytes: usize,
    candidate_bytes: usize,
}

pub(super) fn collect(arguments: &Value) -> PortResult<Vec<&str>> {
    let mut candidates = Candidates::default();
    candidates.visit(arguments, 0)?;
    candidates.values.sort_unstable();
    candidates.values.dedup();
    Ok(candidates.values)
}

impl<'a> Candidates<'a> {
    fn visit(&mut self, value: &'a Value, depth: usize) -> PortResult<()> {
        if depth > MAX_DEPTH {
            return Err(PortError::invalid_data());
        }
        charge(&mut self.nodes, 1, MAX_NODES)?;
        match value {
            Value::String(text) => self.text(text),
            Value::Array(values) => {
                for value in values {
                    self.visit(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Object(values) => {
                for (key, value) in values {
                    charge(&mut self.nodes, 1, MAX_NODES)?;
                    self.text(key)?;
                    self.visit(value, depth + 1)?;
                }
                Ok(())
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        }
    }

    fn text(&mut self, text: &'a str) -> PortResult<()> {
        charge(&mut self.input_bytes, text.len(), MAX_INPUT_BYTES)?;
        self.emit(text)?;
        for word in text.split(word_separator) {
            self.emit(word)?;
            for field in word.split([';', ',', '&', '?', '(', ')', '[', ']', '{', '}']) {
                self.emit(field)?;
                if let Some((_, value)) = field.split_once('=') {
                    self.emit(value)?;
                }
            }
        }
        for atom in text.split(|character: char| {
            character.is_whitespace()
                || (character.is_ascii_punctuation() && !matches!(character, '.' | '-' | '_'))
        }) {
            self.emit(atom)?;
        }
        Ok(())
    }

    fn emit(&mut self, value: &'a str) -> PortResult<()> {
        if value.is_empty() {
            return Ok(());
        }
        if self.values.len() >= MAX_CANDIDATES {
            return Err(PortError::invalid_data());
        }
        charge(&mut self.candidate_bytes, value.len(), MAX_CANDIDATE_BYTES)?;
        self.values.push(value);
        Ok(())
    }
}

fn word_separator(character: char) -> bool {
    character.is_whitespace() || matches!(character, '\'' | '"' | '`')
}

fn charge(used: &mut usize, amount: usize, limit: usize) -> PortResult<()> {
    *used = used
        .checked_add(amount)
        .filter(|total| *total <= limit)
        .ok_or_else(PortError::invalid_data)?;
    Ok(())
}
