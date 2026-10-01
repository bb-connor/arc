//! ELF linkage of a launch target, read the way the cage reads it.
//!
//! The cage admits a target that is statically linked, or one whose ELF
//! interpreter and shared objects are declared as runtime files. The
//! provisioner reads the same headers before it binds a target, so a
//! dynamic target without declared runtime files fails at provisioning
//! rather than at every launch. The cage re-validates at launch; this is
//! the early, operator-facing half of that check.

use std::fmt;
use std::path::PathBuf;

const ELF_HEADER_BYTES: usize = 64;
const PROGRAM_HEADER_BYTES: usize = 56;
const MAX_PROGRAM_HEADERS: u16 = 512;
const MAX_DYNAMIC_ENTRIES: usize = 4096;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_TYPE_SHARED_OBJECT: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;

/// How an executable expects to be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExecutableLinkage {
    /// No interpreter and no shared object: the kernel loads it alone.
    Static { position_independent: bool },
    /// Needs its interpreter and the named shared objects at run time.
    Dynamic {
        interpreter: Option<PathBuf>,
        needed: Vec<String>,
    },
}

impl fmt::Display for ExecutableLinkage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static {
                position_independent: true,
            } => write!(f, "static position-independent executable"),
            Self::Static {
                position_independent: false,
            } => write!(f, "static executable"),
            Self::Dynamic {
                interpreter,
                needed,
            } => {
                write!(f, "dynamically linked")?;
                if let Some(interpreter) = interpreter {
                    write!(f, " through {}", interpreter.display())?;
                }
                if !needed.is_empty() {
                    write!(f, " needing {}", needed.join(", "))?;
                }
                Ok(())
            }
        }
    }
}

/// Why the bytes are not an executable the cage could load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LinkageError {
    NotElf64LittleEndian,
    Truncated(&'static str),
    Malformed(&'static str),
}

impl fmt::Display for LinkageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotElf64LittleEndian => write!(f, "not a 64-bit little-endian ELF image"),
            Self::Truncated(what) => write!(f, "ELF image is truncated at its {what}"),
            Self::Malformed(what) => write!(f, "ELF image has a malformed {what}"),
        }
    }
}

impl std::error::Error for LinkageError {}

struct Segment {
    kind: u32,
    offset: u64,
    address: u64,
    file_size: u64,
}

fn u16_at(content: &[u8], offset: usize) -> Option<u16> {
    content
        .get(offset..offset.checked_add(2)?)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
}

fn u32_at(content: &[u8], offset: usize) -> Option<u32> {
    content
        .get(offset..offset.checked_add(4)?)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
}

fn u64_at(content: &[u8], offset: usize) -> Option<u64> {
    content
        .get(offset..offset.checked_add(8)?)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
}

fn range(content: &[u8], offset: u64, size: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let length = usize::try_from(size).ok()?;
    content.get(start..start.checked_add(length)?)
}

/// Read the ELF headers of `content` and report how it links.
pub(crate) fn inspect_executable_linkage(content: &[u8]) -> Result<ExecutableLinkage, LinkageError> {
    let header = content
        .get(..ELF_HEADER_BYTES)
        .ok_or(LinkageError::Truncated("header"))?;
    if &header[..4] != b"\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(LinkageError::NotElf64LittleEndian);
    }
    let image_type = u16_at(content, 16).ok_or(LinkageError::Truncated("header"))?;
    let position_independent = match image_type {
        ELF_TYPE_EXECUTABLE => false,
        ELF_TYPE_SHARED_OBJECT => true,
        _ => return Err(LinkageError::Malformed("image type")),
    };
    let table_offset = u64_at(content, 32).ok_or(LinkageError::Truncated("header"))?;
    let entry_size = u16_at(content, 54).ok_or(LinkageError::Truncated("header"))?;
    let entry_count = u16_at(content, 56).ok_or(LinkageError::Truncated("header"))?;
    if usize::from(entry_size) != PROGRAM_HEADER_BYTES || entry_count == 0 || entry_count > MAX_PROGRAM_HEADERS {
        return Err(LinkageError::Malformed("program header table"));
    }
    let table_size = u64::from(entry_count)
        .checked_mul(PROGRAM_HEADER_BYTES as u64)
        .ok_or(LinkageError::Malformed("program header table"))?;
    let table = range(content, table_offset, table_size).ok_or(LinkageError::Truncated("program header table"))?;
    let mut segments = Vec::with_capacity(usize::from(entry_count));
    for entry in table.chunks_exact(PROGRAM_HEADER_BYTES) {
        segments.push(Segment {
            kind: u32_at(entry, 0).ok_or(LinkageError::Truncated("program header"))?,
            offset: u64_at(entry, 8).ok_or(LinkageError::Truncated("program header"))?,
            address: u64_at(entry, 16).ok_or(LinkageError::Truncated("program header"))?,
            file_size: u64_at(entry, 32).ok_or(LinkageError::Truncated("program header"))?,
        });
    }

    let mut interpreter = None;
    for segment in segments.iter().filter(|segment| segment.kind == PT_INTERP) {
        if interpreter.is_some() {
            return Err(LinkageError::Malformed("interpreter segment"));
        }
        let bytes = range(content, segment.offset, segment.file_size)
            .ok_or(LinkageError::Truncated("interpreter segment"))?;
        let path = terminated_string(bytes).ok_or(LinkageError::Malformed("interpreter segment"))?;
        if !path.starts_with('/') {
            return Err(LinkageError::Malformed("interpreter path"));
        }
        interpreter = Some(PathBuf::from(path));
    }

    let mut needed = Vec::new();
    for segment in segments.iter().filter(|segment| segment.kind == PT_DYNAMIC) {
        let table = range(content, segment.offset, segment.file_size)
            .ok_or(LinkageError::Truncated("dynamic segment"))?;
        let mut needed_offsets = Vec::new();
        let mut string_table = None;
        let mut string_table_size = None;
        for (index, entry) in table.chunks_exact(16).enumerate() {
            if index >= MAX_DYNAMIC_ENTRIES {
                return Err(LinkageError::Malformed("dynamic table"));
            }
            let tag = u64_at(entry, 0).ok_or(LinkageError::Truncated("dynamic entry"))?;
            let value = u64_at(entry, 8).ok_or(LinkageError::Truncated("dynamic entry"))?;
            match tag {
                DT_NULL => break,
                DT_NEEDED => needed_offsets.push(value),
                DT_STRTAB => string_table = Some(value),
                DT_STRSZ => string_table_size = Some(value),
                _ => {}
            }
        }
        if needed_offsets.is_empty() {
            continue;
        }
        let (Some(address), Some(size)) = (string_table, string_table_size) else {
            return Err(LinkageError::Malformed("dynamic string table"));
        };
        let file_offset = segments
            .iter()
            .filter(|segment| segment.kind == PT_LOAD)
            .find_map(|segment| {
                let relative = address.checked_sub(segment.address)?;
                (relative < segment.file_size).then(|| segment.offset.checked_add(relative))?
            })
            .ok_or(LinkageError::Malformed("dynamic string table"))?;
        let strings = range(content, file_offset, size).ok_or(LinkageError::Truncated("dynamic string table"))?;
        for offset in needed_offsets {
            let start = usize::try_from(offset).ok().filter(|start| *start < strings.len());
            let name = start
                .and_then(|start| terminated_string(&strings[start..]))
                .ok_or(LinkageError::Malformed("shared object name"))?;
            needed.push(name.to_string());
        }
    }

    if interpreter.is_none() && needed.is_empty() {
        Ok(ExecutableLinkage::Static { position_independent })
    } else {
        Ok(ExecutableLinkage::Dynamic { interpreter, needed })
    }
}

fn terminated_string(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|byte| *byte == 0)?;
    let text = std::str::from_utf8(&bytes[..end]).ok()?;
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One program header of a synthetic image.
    pub(crate) struct SyntheticSegment {
        pub(crate) kind: u32,
        pub(crate) offset: u64,
        pub(crate) address: u64,
        pub(crate) file_size: u64,
    }

    /// A 64-bit little-endian ELF image whose program headers follow the
    /// ELF header and whose remaining bytes are `body`.
    pub(crate) fn synthetic_elf(image_type: u16, segments: &[SyntheticSegment], body: &[u8]) -> Vec<u8> {
        let mut image = vec![0_u8; ELF_HEADER_BYTES];
        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        image[16..18].copy_from_slice(&image_type.to_le_bytes());
        image[18..20].copy_from_slice(&183_u16.to_le_bytes());
        image[20..24].copy_from_slice(&1_u32.to_le_bytes());
        image[32..40].copy_from_slice(&(ELF_HEADER_BYTES as u64).to_le_bytes());
        image[52..54].copy_from_slice(&(ELF_HEADER_BYTES as u16).to_le_bytes());
        image[54..56].copy_from_slice(&(PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        image[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes());
        for segment in segments {
            let mut header = vec![0_u8; PROGRAM_HEADER_BYTES];
            header[..4].copy_from_slice(&segment.kind.to_le_bytes());
            header[4..8].copy_from_slice(&5_u32.to_le_bytes());
            header[8..16].copy_from_slice(&segment.offset.to_le_bytes());
            header[16..24].copy_from_slice(&segment.address.to_le_bytes());
            header[24..32].copy_from_slice(&segment.address.to_le_bytes());
            header[32..40].copy_from_slice(&segment.file_size.to_le_bytes());
            header[40..48].copy_from_slice(&segment.file_size.to_le_bytes());
            header[48..56].copy_from_slice(&0x1000_u64.to_le_bytes());
            image.extend_from_slice(&header);
        }
        image.extend_from_slice(body);
        image
    }

    fn body_offset(segment_count: usize) -> u64 {
        (ELF_HEADER_BYTES + segment_count * PROGRAM_HEADER_BYTES) as u64
    }

    #[test]
    fn static_images_are_recognized_by_type() {
        let body = [0xd5, 0x03, 0x20, 0x1f];
        let load = SyntheticSegment {
            kind: PT_LOAD,
            offset: 0,
            address: 0,
            file_size: body_offset(1) + body.len() as u64,
        };
        let executable = synthetic_elf(ELF_TYPE_EXECUTABLE, &[load], &body);
        assert_eq!(
            inspect_executable_linkage(&executable),
            Ok(ExecutableLinkage::Static { position_independent: false })
        );
        let load = SyntheticSegment {
            kind: PT_LOAD,
            offset: 0,
            address: 0,
            file_size: body_offset(1) + body.len() as u64,
        };
        let pie = synthetic_elf(ELF_TYPE_SHARED_OBJECT, &[load], &body);
        assert_eq!(
            inspect_executable_linkage(&pie),
            Ok(ExecutableLinkage::Static { position_independent: true })
        );
    }

    #[test]
    fn dynamic_images_report_their_interpreter_and_shared_objects() {
        let interpreter = b"/lib/ld-linux-aarch64.so.1\0";
        let strings = b"\0libc.so.6\0libm.so.6\0";
        let mut dynamic = Vec::new();
        for (tag, value) in [
            (DT_NEEDED, 1_u64),
            (DT_NEEDED, 11),
            (DT_STRTAB, 0x2000 + interpreter.len() as u64),
            (DT_STRSZ, strings.len() as u64),
            (DT_NULL, 0),
        ] {
            dynamic.extend_from_slice(&tag.to_le_bytes());
            dynamic.extend_from_slice(&value.to_le_bytes());
        }
        let start = body_offset(3);
        let segments = [
            SyntheticSegment {
                kind: PT_INTERP,
                offset: start,
                address: 0x2000,
                file_size: interpreter.len() as u64,
            },
            SyntheticSegment {
                kind: PT_LOAD,
                offset: start,
                address: 0x2000,
                file_size: (interpreter.len() + strings.len() + dynamic.len()) as u64,
            },
            SyntheticSegment {
                kind: PT_DYNAMIC,
                offset: start + (interpreter.len() + strings.len()) as u64,
                address: 0x2000 + (interpreter.len() + strings.len()) as u64,
                file_size: dynamic.len() as u64,
            },
        ];
        let mut body = Vec::new();
        body.extend_from_slice(interpreter);
        body.extend_from_slice(strings);
        body.extend_from_slice(&dynamic);
        let image = synthetic_elf(ELF_TYPE_SHARED_OBJECT, &segments, &body);
        let linkage = inspect_executable_linkage(&image).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            linkage,
            ExecutableLinkage::Dynamic {
                interpreter: Some(PathBuf::from("/lib/ld-linux-aarch64.so.1")),
                needed: vec!["libc.so.6".to_string(), "libm.so.6".to_string()],
            }
        );
        assert_eq!(
            linkage.to_string(),
            "dynamically linked through /lib/ld-linux-aarch64.so.1 needing libc.so.6, libm.so.6"
        );
    }

    #[test]
    fn malformed_images_are_refused() {
        assert_eq!(
            inspect_executable_linkage(b"\x7fELF"),
            Err(LinkageError::Truncated("header"))
        );
        let mut wrong_class = synthetic_elf(ELF_TYPE_EXECUTABLE, &[], &[]);
        wrong_class[4] = 1;
        assert_eq!(
            inspect_executable_linkage(&wrong_class),
            Err(LinkageError::NotElf64LittleEndian)
        );
        assert_eq!(
            inspect_executable_linkage(&synthetic_elf(ELF_TYPE_EXECUTABLE, &[], &[])),
            Err(LinkageError::Malformed("program header table"))
        );
        assert_eq!(
            inspect_executable_linkage(&synthetic_elf(1, &[], &[])),
            Err(LinkageError::Malformed("image type"))
        );
        let truncated = synthetic_elf(
            ELF_TYPE_EXECUTABLE,
            &[SyntheticSegment { kind: PT_INTERP, offset: 4096, address: 0, file_size: 16 }],
            &[],
        );
        assert_eq!(
            inspect_executable_linkage(&truncated),
            Err(LinkageError::Truncated("interpreter segment"))
        );
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn the_test_executable_is_dynamically_linked() {
        let image = std::fs::read(std::env::current_exe().unwrap_or_else(|error| panic!("{error}")))
            .unwrap_or_else(|error| panic!("{error}"));
        match inspect_executable_linkage(&image) {
            Ok(ExecutableLinkage::Dynamic { interpreter: Some(interpreter), needed }) => {
                assert!(interpreter.is_absolute());
                assert!(needed.iter().any(|name| name.starts_with("libc.so")), "{needed:?}");
            }
            other => panic!("unexpected linkage for the test executable: {other:?}"),
        }
    }
}
