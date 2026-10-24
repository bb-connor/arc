//! Behavioral tests consume frozen independent byte vectors and real map nodes.

use super::encoding::{
    decode_value, encode_value, key_digest, key_encoding, value_digest, verify_value_key, Class,
    Payload, Row, Tier,
};
use super::tree::{batch_update, empty_digest, lookup, Node, NodeSink, NodeSource};
use super::{Digest, Error, Result};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Memory {
    nodes: BTreeMap<Digest, Node>,
    reads: usize,
    writes: usize,
    unavailable: bool,
}

impl NodeSource for Memory {
    fn load(&mut self, digest: Digest) -> Result<Option<Node>> {
        self.reads += 1;
        if self.unavailable {
            return Err(Error::Source);
        }
        Ok(self.nodes.get(&digest).cloned())
    }
}

impl NodeSink for Memory {
    fn store(&mut self, digest: Digest, node: Node) -> Result<()> {
        if self.nodes.get(&digest).is_some_and(|prior| prior != &node) {
            return Err(Error::Conflict);
        }
        self.writes += 1;
        self.nodes.insert(digest, node);
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    provenance: String,
    keys: Vec<KeyVector>,
    pointers: Vec<PointerVector>,
    facts: Vec<FactVector>,
    values: Vec<ValueVector>,
    maps: Vec<MapVector>,
    worst_case: WorstCase,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyVector {
    authority: String,
    class_tag: u8,
    fields: Vec<String>,
    encoded_hex: String,
    digest_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PointerVector {
    name: String,
    tier: u8,
    version: u64,
    value_hex: String,
    encoded_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FactVector {
    class_tag: u8,
    body_hex: String,
    encoded_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueVector {
    class_tag: u8,
    rows: Vec<RowVector>,
    encoded_hex: String,
    digest_hex: String,
    key_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RowVector {
    table: String,
    image_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MapVector {
    name: String,
    entries: Vec<EntryVector>,
    root_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryVector {
    key_hex: String,
    payload_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorstCase {
    present_zero_hex: String,
    present_one_hex: String,
    absent_hex: String,
    inclusion_reads: usize,
    absence_reads: usize,
}

fn fixture() -> std::result::Result<Fixture, serde_json::Error> {
    serde_json::from_str(include_str!("fixtures/native-cold-v1-vectors.json"))
}

fn digest(text: &str) -> std::result::Result<Digest, Box<dyn std::error::Error>> {
    Ok(hex::decode(text)?
        .try_into()
        .map_err(|_| "fixture digest length differs")?)
}

fn pointer(version: u64) -> Payload {
    Payload::Pointer {
        tier: Tier::Cold,
        version,
        value_digest: [0x11; 32],
    }
}

fn leaf(key: Digest, version: u64) -> Result<Node> {
    Ok(Node::Leaf {
        key,
        payload: pointer(version).encode()?,
    })
}

fn seed(memory: &mut Memory, node: Node) -> Result<Digest> {
    let digest = node.digest()?;
    memory.nodes.insert(digest, node);
    Ok(digest)
}

fn rows(vector: &ValueVector) -> std::result::Result<Vec<Row>, hex::FromHexError> {
    vector
        .rows
        .iter()
        .map(|row| {
            Ok(Row {
                table: row.table.clone(),
                image: hex::decode(&row.image_hex)?,
            })
        })
        .collect()
}

#[test]
fn golden_keys_separate_every_class_and_field_boundary() -> TestResult {
    let vectors = fixture()?;
    assert_eq!(vectors.schema, "chio.native-cold-test-vectors.v1");
    assert!(vectors.provenance.contains("Independent Python hashlib"));
    for vector in vectors.keys {
        let class = Class::from_tag(vector.class_tag)?;
        let fields: Vec<&str> = vector.fields.iter().map(String::as_str).collect();
        assert_eq!(
            key_encoding(&vector.authority, class, &fields)?,
            hex::decode(vector.encoded_hex)?
        );
        assert_eq!(
            key_digest(&vector.authority, class, &fields)?,
            digest(&vector.digest_hex)?
        );
    }
    assert_ne!(
        key_digest("a", Class::Lineage, &["ab", "c"])?,
        key_digest("a", Class::Lineage, &["a", "bc"])?
    );
    Ok(())
}

#[test]
fn golden_payloads_pin_tier_version_and_fact_domains() -> TestResult {
    let vectors = fixture()?;
    for vector in vectors.pointers {
        assert!(!vector.name.is_empty());
        let payload = Payload::Pointer {
            tier: Tier::from_tag(vector.tier)?,
            version: vector.version,
            value_digest: digest(&vector.value_hex)?,
        };
        let bytes = hex::decode(vector.encoded_hex)?;
        assert_eq!(payload.encode()?, bytes);
        assert_eq!(Payload::decode(&bytes)?, payload);
    }
    for vector in vectors.facts {
        let payload = Payload::Fact {
            class: Class::from_tag(vector.class_tag)?,
            body: hex::decode(vector.body_hex)?,
        };
        let bytes = hex::decode(vector.encoded_hex)?;
        assert_eq!(payload.encode()?, bytes);
        assert_eq!(Payload::decode(&bytes)?, payload);
    }
    Ok(())
}

#[test]
fn golden_values_preserve_exact_retained_images_and_key_binding() -> TestResult {
    for vector in fixture()?.values {
        let class = Class::from_tag(vector.class_tag)?;
        let rows = rows(&vector)?;
        let bytes = hex::decode(&vector.encoded_hex)?;
        assert_eq!(encode_value(class, &rows)?, bytes);
        assert_eq!(decode_value(class, &bytes)?, rows);
        assert_eq!(value_digest(class, &bytes)?, digest(&vector.digest_hex)?);
        verify_value_key("authority", class, digest(&vector.key_hex)?, &bytes)?;
    }
    Ok(())
}

#[test]
fn golden_roots_match_the_independent_full_set_reference() -> TestResult {
    for vector in fixture()?.maps {
        let updates = vector
            .entries
            .iter()
            .map(|entry| {
                Ok((
                    digest(&entry.key_hex)?,
                    Payload::decode(&hex::decode(&entry.payload_hex)?)?,
                ))
            })
            .collect::<std::result::Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let root = batch_update(&mut Memory::default(), empty_digest(), &updates)?;
        assert_eq!(root, digest(&vector.root_hex)?, "{}", vector.name);
    }
    Ok(())
}

#[test]
fn authenticated_lookup_returns_inclusion_and_compressed_absence() -> TestResult {
    let key = [0; 32];
    let mut memory = Memory::default();
    let root = seed(&mut memory, leaf(key, 1)?)?;
    assert_eq!(lookup(&mut memory, root, key)?, Some(pointer(1)));
    assert_eq!(memory.reads, 1);
    memory.reads = 0;
    assert_eq!(lookup(&mut memory, root, [0xff; 32])?, None);
    assert_eq!(memory.reads, 1);
    memory.reads = 0;
    assert_eq!(lookup(&mut memory, empty_digest(), key)?, None);
    assert_eq!(memory.reads, 0);
    Ok(())
}

#[test]
fn pointer_updates_preserve_old_roots_and_values() -> TestResult {
    let mut memory = Memory::default();
    let key = [0; 32];
    let first = batch_update(&mut memory, empty_digest(), &[(key, pointer(1))])?;
    let second_payload = Payload::Pointer {
        tier: Tier::Hot,
        version: 2,
        value_digest: [0x22; 32],
    };
    let second = batch_update(&mut memory, first, &[(key, second_payload.clone())])?;
    assert_ne!(first, second);
    assert_eq!(lookup(&mut memory, first, key)?, Some(pointer(1)));
    assert_eq!(lookup(&mut memory, second, key)?, Some(second_payload));
    Ok(())
}

#[test]
fn insertion_order_and_batch_partition_do_not_change_the_root() -> TestResult {
    let updates: Vec<_> = [0, 64, 128, 192]
        .into_iter()
        .enumerate()
        .map(|(index, byte)| {
            let mut key = [0; 32];
            key[0] = byte;
            (key, pointer(index as u64 + 1))
        })
        .collect();
    let mut memory = Memory::default();
    let expected = batch_update(&mut memory, empty_digest(), &updates)?;
    for order in [[3, 2, 1, 0], [1, 3, 0, 2], [2, 0, 3, 1]] {
        let mut memory = Memory::default();
        let mut root = empty_digest();
        for index in order {
            root = batch_update(&mut memory, root, &[updates[index].clone()])?;
        }
        assert_eq!(root, expected);
        for (key, payload) in &updates {
            assert_eq!(lookup(&mut memory, root, *key)?, Some(payload.clone()));
        }
    }
    Ok(())
}

#[test]
fn a_batch_rebuilds_shared_paths_once() -> TestResult {
    let updates: Vec<_> = (0..8_u8)
        .map(|index| {
            let mut key = [0; 32];
            key[0] = index * 32;
            (key, pointer(u64::from(index) + 1))
        })
        .collect();
    let mut memory = Memory::default();
    let root = batch_update(&mut memory, empty_digest(), &updates)?;
    assert_ne!(root, empty_digest());
    assert_eq!(memory.writes, 15, "eight leaves and seven shared branches");
    let prior_writes = memory.writes;
    assert_eq!(batch_update(&mut memory, root, &updates)?, root);
    assert_eq!(memory.writes, prior_writes);
    Ok(())
}

#[test]
fn worst_case_walk_reads_257_nodes_and_absence_reads_256() -> TestResult {
    let vectors = fixture()?.worst_case;
    let mut memory = Memory::default();
    let zero = digest(&vectors.present_zero_hex)?;
    let one = digest(&vectors.present_one_hex)?;
    let root = batch_update(
        &mut memory,
        empty_digest(),
        &[(zero, pointer(1)), (one, pointer(2))],
    )?;
    for (key, version) in [(zero, 1), (one, 2)] {
        memory.reads = 0;
        assert_eq!(lookup(&mut memory, root, key)?, Some(pointer(version)));
        assert_eq!(memory.reads, vectors.inclusion_reads);
    }
    memory.reads = 0;
    assert_eq!(
        lookup(&mut memory, root, digest(&vectors.absent_hex)?)?,
        None
    );
    assert_eq!(memory.reads, vectors.absence_reads);
    Ok(())
}

#[test]
fn absence_requires_an_authenticated_nonempty_sibling_branch() -> TestResult {
    let mut memory = Memory::default();
    let left = seed(&mut memory, leaf([0; 32], 1)?)?;
    let mut other_key = [0; 32];
    other_key[0] = 64;
    let right = seed(&mut memory, leaf(other_key, 2)?)?;
    let child = seed(&mut memory, Node::Branch { left, right })?;
    let root = seed(
        &mut memory,
        Node::Branch {
            left: child,
            right: empty_digest(),
        },
    )?;
    assert_eq!(lookup(&mut memory, root, [0x80; 32])?, None);
    assert_eq!(memory.reads, 2);
    memory.nodes.remove(&child);
    assert_eq!(
        lookup(&mut memory, root, [0x80; 32]),
        Err(Error::MissingNode)
    );
    memory.nodes.insert(child, leaf([0; 32], 3)?);
    assert_eq!(
        lookup(&mut memory, root, [0x80; 32]),
        Err(Error::NodeDigest)
    );
    Ok(())
}

#[test]
fn an_empty_sibling_beside_a_leaf_is_noncanonical_on_both_paths() -> TestResult {
    let mut memory = Memory::default();
    let child = seed(&mut memory, leaf([0; 32], 1)?)?;
    let root = seed(
        &mut memory,
        Node::Branch {
            left: child,
            right: empty_digest(),
        },
    )?;
    assert_eq!(lookup(&mut memory, root, [0; 32]), Err(Error::Shape));
    assert_eq!(lookup(&mut memory, root, [0x80; 32]), Err(Error::Shape));
    assert_eq!(
        batch_update(&mut memory, root, &[([0; 32], pointer(2))]),
        Err(Error::Shape)
    );
    Ok(())
}

#[test]
fn a_new_key_cannot_repair_a_noncanonical_predecessor_sibling() -> TestResult {
    let mut memory = Memory::default();
    let child = seed(&mut memory, leaf([0xff; 32], 1)?)?;
    let root = seed(
        &mut memory,
        Node::Branch {
            left: empty_digest(),
            right: child,
        },
    )?;
    assert_eq!(
        batch_update(&mut memory, root, &[([0; 32], pointer(2))]),
        Err(Error::Shape),
        "an inserted left key must not hide the predecessor's invalid right leaf"
    );
    Ok(())
}

#[test]
fn two_empty_children_never_prove_absence() -> TestResult {
    let mut memory = Memory::default();
    let root = seed(
        &mut memory,
        Node::Branch {
            left: empty_digest(),
            right: empty_digest(),
        },
    )?;
    assert_eq!(lookup(&mut memory, root, [0; 32]), Err(Error::Shape));
    Ok(())
}

#[test]
fn misplaced_leaf_never_proves_absence() -> TestResult {
    let mut memory = Memory::default();
    let left = seed(&mut memory, leaf([0x80; 32], 1)?)?;
    let right = seed(&mut memory, leaf([0; 32], 2)?)?;
    let root = seed(&mut memory, Node::Branch { left, right })?;
    assert_eq!(lookup(&mut memory, root, [0; 32]), Err(Error::Placement));
    assert_eq!(lookup(&mut memory, root, [0x80; 32]), Err(Error::Placement));
    Ok(())
}

#[test]
fn a_branch_at_depth_256_is_refused() -> TestResult {
    let mut memory = Memory::default();
    let left = seed(&mut memory, leaf([0; 32], 1)?)?;
    let right = seed(&mut memory, leaf([0xff; 32], 2)?)?;
    let mut root = seed(&mut memory, Node::Branch { left, right })?;
    for _ in 0..256 {
        root = seed(&mut memory, Node::Branch { left: root, right })?;
    }
    assert_eq!(lookup(&mut memory, root, [0; 32]), Err(Error::Depth));
    assert!(memory.reads <= 257);
    Ok(())
}

#[test]
fn missing_and_corrupt_nodes_refuse_inclusion_and_absence() -> TestResult {
    let mut memory = Memory::default();
    let root = seed(&mut memory, leaf([0; 32], 1)?)?;
    memory.nodes.remove(&root);
    assert_eq!(lookup(&mut memory, root, [0; 32]), Err(Error::MissingNode));
    assert_eq!(
        lookup(&mut memory, root, [0xff; 32]),
        Err(Error::MissingNode)
    );
    memory.nodes.insert(root, leaf([0; 32], 2)?);
    assert_eq!(lookup(&mut memory, root, [0; 32]), Err(Error::NodeDigest));
    assert_eq!(
        lookup(&mut memory, root, [0xff; 32]),
        Err(Error::NodeDigest)
    );
    assert_eq!(batch_update(&mut memory, root, &[]), Err(Error::NodeDigest));
    Ok(())
}

#[test]
fn storage_errors_are_never_converted_to_absence() -> TestResult {
    let mut memory = Memory {
        unavailable: true,
        ..Memory::default()
    };
    assert_eq!(lookup(&mut memory, [1; 32], [0; 32]), Err(Error::Source));
    Ok(())
}

#[test]
fn authenticated_malformed_payloads_never_prove_absence() -> TestResult {
    let payload = b"not-a-native-cold-payload".to_vec();
    let key = [0; 32];
    let mut hash = Sha256::new();
    hash.update(b"chio.native-cold.leaf.v1\0");
    hash.update(key);
    hash.update(Sha256::digest(&payload));
    let root: Digest = hash.finalize().into();
    let mut memory = Memory::default();
    memory.nodes.insert(root, Node::Leaf { key, payload });
    assert_eq!(lookup(&mut memory, root, [0xff; 32]), Err(Error::Encoding));
    Ok(())
}

#[test]
fn duplicate_batch_keys_are_refused() {
    assert_eq!(
        batch_update(
            &mut Memory::default(),
            empty_digest(),
            &[([0; 32], pointer(1)), ([0; 32], pointer(2))]
        ),
        Err(Error::DuplicateKey)
    );
}

#[test]
fn keys_refuse_unknown_classes_wrong_arity_and_oversized_identifiers() -> TestResult {
    for tag in 0..=255 {
        assert_eq!(Class::from_tag(tag).is_ok(), (1..=9).contains(&tag));
    }
    assert_eq!(
        key_encoding("", Class::Lineage, &["t", "l"]),
        Err(Error::Encoding)
    );
    assert_eq!(
        key_encoding("a", Class::Lineage, &["t"]),
        Err(Error::Encoding)
    );
    assert_eq!(
        key_encoding("a", Class::Lineage, &["t", ""]),
        Err(Error::Encoding)
    );
    assert_eq!(
        key_encoding(&"a".repeat(513), Class::Lineage, &["t", "l"]),
        Err(Error::Encoding)
    );
    assert_eq!(
        key_encoding("a", Class::Lineage, &["t", &"l".repeat(513)]),
        Err(Error::Encoding)
    );
    key_encoding(&"a".repeat(512), Class::Lineage, &["t", &"l".repeat(512)])?;
    Ok(())
}

#[test]
fn pointers_refuse_zero_versions_unknown_tiers_and_trailing_bytes() -> TestResult {
    assert_eq!(pointer(0).encode(), Err(Error::Encoding));
    pointer(u64::MAX).encode()?;
    assert_eq!(Tier::from_tag(0), Err(Error::Encoding));
    assert_eq!(Tier::from_tag(3), Err(Error::Encoding));
    let bytes = pointer(1).encode()?;
    for length in 0..bytes.len() {
        assert_eq!(Payload::decode(&bytes[..length]), Err(Error::Encoding));
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(Payload::decode(&trailing), Err(Error::Encoding));
    let mut wrong_domain = bytes;
    wrong_domain[0] ^= 1;
    assert_eq!(Payload::decode(&wrong_domain), Err(Error::Encoding));
    Ok(())
}

#[test]
fn facts_refuse_versioned_classes_and_noncanonical_witness_lengths() {
    for class in [Class::Lineage, Class::Principal, Class::Epoch, Class::Grant] {
        assert_eq!(
            Payload::Fact {
                class,
                body: vec![0; 32]
            }
            .encode(),
            Err(Error::Encoding)
        );
    }
    for length in [0, 31, 33, 63, 65, 257] {
        assert_eq!(
            Payload::Fact {
                class: Class::Membership,
                body: vec![0; length]
            }
            .encode(),
            Err(Error::Encoding)
        );
    }
}

#[test]
fn values_refuse_bad_counts_truncation_trailing_bytes_and_unknown_tables() -> TestResult {
    let vector = fixture()?.values.remove(0);
    let bytes = hex::decode(&vector.encoded_hex)?;
    for length in [0, 7, 8, 9, bytes.len() - 1] {
        assert_eq!(
            decode_value(Class::Lineage, &bytes[..length]),
            Err(Error::Encoding)
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        decode_value(Class::Lineage, &trailing),
        Err(Error::Encoding)
    );
    let mut huge_count = bytes.clone();
    huge_count[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        decode_value(Class::Lineage, &huge_count),
        Err(Error::Encoding)
    );
    let mut huge_length = bytes;
    huge_length[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        decode_value(Class::Lineage, &huge_length),
        Err(Error::Encoding)
    );
    assert_eq!(encode_value(Class::Lineage, &[]), Err(Error::Encoding));
    assert_eq!(
        encode_value(Class::Membership, &rows(&vector)?),
        Err(Error::Encoding)
    );
    let mut unknown = rows(&vector)?;
    unknown[0].table = "untrusted_table".into();
    assert_eq!(encode_value(Class::Lineage, &unknown), Err(Error::Encoding));
    Ok(())
}

#[test]
fn values_refuse_noncanonical_or_malformed_retained_images() -> TestResult {
    let vector = fixture()?.values.remove(0);
    let mut rows = rows(&vector)?;
    rows[0].image.push(b' ');
    assert_eq!(encode_value(Class::Lineage, &rows), Err(Error::Encoding));
    rows[0].image = b"[]".to_vec();
    assert_eq!(encode_value(Class::Lineage, &rows), Err(Error::Encoding));
    rows[0].image = vec![b'0'; 16_777_217];
    assert_eq!(encode_value(Class::Lineage, &rows), Err(Error::Encoding));
    Ok(())
}

#[test]
fn grant_values_refuse_duplicate_rows_and_noncanonical_row_order() -> TestResult {
    let duplicate_vector = fixture()?.values.remove(4);
    let valid_rows = rows(&duplicate_vector)?;
    assert_eq!(
        encode_value(Class::Grant, &valid_rows)?,
        hex::decode(&duplicate_vector.encoded_hex)?
    );
    // Keep the valid five-row shape and per-table counts. Only duplicated
    // identity or outbox content may reject either otherwise-valid value.
    for (first, second) in [(0, 1), (2, 3)] {
        let mut duplicate_rows = valid_rows.clone();
        assert_eq!(duplicate_rows[first].table, duplicate_rows[second].table);
        assert_ne!(duplicate_rows[first], duplicate_rows[second]);
        duplicate_rows[second] = duplicate_rows[first].clone();
        assert_eq!(
            encode_value(Class::Grant, &duplicate_rows),
            Err(Error::Encoding)
        );
    }

    let vector = fixture()?.values.remove(3);
    let mut rows = rows(&vector)?;
    rows.reverse();
    assert_eq!(
        encode_value(Class::Grant, &rows)?,
        hex::decode(&vector.encoded_hex)?
    );
    let mut encoded = (rows.len() as u64).to_be_bytes().to_vec();
    for row in rows {
        encoded.extend((row.table.len() as u64).to_be_bytes());
        encoded.extend(row.table.as_bytes());
        encoded.extend((row.image.len() as u64).to_be_bytes());
        encoded.extend(row.image);
    }
    assert_eq!(decode_value(Class::Grant, &encoded), Err(Error::Encoding));
    Ok(())
}

#[test]
fn a_valid_value_of_another_key_or_authority_is_refused() -> TestResult {
    for vector in fixture()?.values {
        let class = Class::from_tag(vector.class_tag)?;
        let bytes = hex::decode(&vector.encoded_hex)?;
        assert_eq!(
            verify_value_key("authority", class, [0; 32], &bytes),
            Err(Error::Binding)
        );
        assert_eq!(
            verify_value_key("other-authority", class, digest(&vector.key_hex)?, &bytes),
            Err(Error::Binding)
        );
    }
    Ok(())
}
