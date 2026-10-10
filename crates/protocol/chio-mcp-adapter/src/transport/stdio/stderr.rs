//! Diagnostics never retain an unbounded line from a confined child.

use std::io::{self, BufRead};

const MAX_FRAGMENT_BYTES: usize = 8 * 1024;

/// Preserve ordinary lines and emit bounded fragments for long records. Invalid
/// UTF-8 is diagnostic data, so it must never stop draining the producer's pipe.
pub(super) fn drain(reader: &mut impl BufRead, mut emit: impl FnMut(&[u8])) -> io::Result<()> {
    let mut fragment = Vec::with_capacity(MAX_FRAGMENT_BYTES);
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if available.is_empty() {
            if !fragment.is_empty() {
                emit(&fragment);
            }
            return Ok(());
        }
        let limit = (MAX_FRAGMENT_BYTES - fragment.len()).min(available.len());
        let newline = available[..limit].iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(limit, |index| index + 1);
        fragment.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            fragment.pop();
            if fragment.last() == Some(&b'\r') {
                fragment.pop();
            }
            emit(&fragment);
            fragment.clear();
        } else if fragment.len() == MAX_FRAGMENT_BYTES {
            emit(&fragment);
            fragment.clear();
        }
    }
}

/// Escape diagnostic control characters, preserving ordinary Unicode. Both
/// lossy conversion and escaping are bounded by the fixed input fragment size.
pub(super) fn diagnostic_text(bytes: &[u8]) -> String {
    let bytes = &bytes[..bytes.len().min(MAX_FRAGMENT_BYTES)];
    let mut text = String::with_capacity(bytes.len().saturating_mul(8));
    for character in String::from_utf8_lossy(bytes).chars() {
        text.extend(character.escape_debug());
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;
    use std::io::{BufReader, Cursor, Read};

    #[test]
    fn unterminated_stream_emits_fixed_fragments_and_a_bounded_tail() {
        let size = 3 * MAX_FRAGMENT_BYTES + 17;
        let input = io::repeat(b'x').take(size as u64);
        let mut reader = BufReader::with_capacity(13, input);
        let mut lengths = Vec::new();
        drain(&mut reader, |fragment| {
            assert!(fragment.len() <= MAX_FRAGMENT_BYTES);
            assert!(fragment.iter().all(|byte| *byte == b'x'));
            lengths.push(fragment.len());
        })
        .test_expect("drain an unterminated byte stream");
        assert_eq!(
            lengths,
            [
                MAX_FRAGMENT_BYTES,
                MAX_FRAGMENT_BYTES,
                MAX_FRAGMENT_BYTES,
                17
            ]
        );
        assert_eq!(lengths.iter().sum::<usize>(), size);
    }

    #[test]
    fn ordinary_lines_partial_utf8_and_invalid_diagnostics_keep_draining() {
        let input = b"ordinary\r\n\xe2\x82\xac\n\xff\x1b[31m\nlast";
        let mut reader = BufReader::with_capacity(1, input.as_slice());
        let mut lines = Vec::new();
        drain(&mut reader, |fragment| {
            lines.push(diagnostic_text(fragment))
        })
        .test_expect("drain all diagnostics");
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "ordinary");
        assert_eq!(lines[1], "\u{20ac}");
        assert!(lines[2].contains('\u{fffd}'));
        assert!(!lines[2].chars().any(char::is_control));
        assert_eq!(lines[3], "last");
    }

    #[test]
    fn escaping_remains_bounded_for_invalid_bytes_and_controls() {
        for byte in [0xff, 0x1b, 0] {
            let bytes = vec![byte; 2 * MAX_FRAGMENT_BYTES];
            let text = diagnostic_text(&bytes);
            assert!(text.len() <= 8 * MAX_FRAGMENT_BYTES);
            assert!(!text.chars().any(char::is_control));
        }
    }

    struct InterruptedOnce {
        first: bool,
        inner: Cursor<Vec<u8>>,
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.first {
                self.first = false;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.inner.read(bytes)
        }
    }

    #[test]
    fn interrupted_read_does_not_discard_a_diagnostic() {
        let mut reader = BufReader::new(InterruptedOnce {
            first: true,
            inner: Cursor::new(b"hello\n".to_vec()),
        });
        let mut fragments = Vec::new();
        drain(&mut reader, |fragment| fragments.push(fragment.to_vec()))
            .test_expect("retry interrupted stderr read");
        assert_eq!(fragments, [b"hello".to_vec()]);
    }
}
