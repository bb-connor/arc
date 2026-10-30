use alloc::format;
use alloc::string::{String, ToString};

use super::{
    checkpoint_note_text, open_checkpoint_note, open_note, parse_checkpoint_text,
    sign_checkpoint_note, sign_note, NoteVerifier, SignedNoteError,
};
use crate::crypto::Keypair;
use crate::hashing::Hash;
use crate::receipt::checkpoint::{KernelCheckpoint, KernelCheckpointBody, CHECKPOINT_SCHEMA};

type TestResult = core::result::Result<(), alloc::boxed::Box<dyn std::error::Error>>;

/// The example note and verifier key of c2sp.org/signed-note.
const SPEC_VKEY: &str = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
const SPEC_NOTE: &str = "This is an example message.\n\n\
— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n";

/// The example checkpoint body of c2sp.org/tlog-checkpoint.
const SPEC_CHECKPOINT_TEXT: &str =
    "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n";

fn note_signer() -> Keypair {
    Keypair::from_seed(&[61_u8; 32])
}

fn kernel_checkpoint(signer: &Keypair) -> core::result::Result<KernelCheckpoint, crate::Error> {
    let body = KernelCheckpointBody {
        schema: CHECKPOINT_SCHEMA.to_string(),
        checkpoint_seq: 3,
        batch_start_seq: 11,
        batch_end_seq: 20,
        tree_size: 20,
        merkle_root: Hash::from_bytes([0xa7; 32]),
        issued_at: 1_792_234_800,
        kernel_key: signer.public_key(),
        previous_checkpoint_sha256: None,
        chain_root: None,
    };
    let (signature, _) = signer.sign_canonical(&body)?;
    Ok(KernelCheckpoint { body, signature })
}

fn spec_verifier() -> core::result::Result<NoteVerifier, SignedNoteError> {
    NoteVerifier::from_vkey(SPEC_VKEY)
}

#[test]
fn spec_note_opens_under_its_verifier_key() -> TestResult {
    let verifier = spec_verifier()?;

    assert_eq!(verifier.to_vkey(), SPEC_VKEY);
    assert_eq!(verifier.key_id(), [0x53, 0x0d, 0x90, 0x3a]);
    assert_eq!(
        open_note(SPEC_NOTE, &[verifier])?,
        "This is an example message.\n"
    );
    Ok(())
}

#[test]
fn one_byte_text_change_is_an_invalid_signature() -> TestResult {
    let changed = SPEC_NOTE.replacen("example message", "example massage", 1);

    assert_eq!(
        open_note(&changed, &[spec_verifier()?]),
        Err(SignedNoteError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn unknown_key_name_or_key_hash_is_refused() -> TestResult {
    let other_name = SPEC_NOTE.replacen("example.com/foo", "example.com/bar", 1);
    let other_hash = SPEC_NOTE.replacen("Uw2Q", "Uw2R", 1);

    assert_eq!(
        open_note(&other_name, &[spec_verifier()?]),
        Err(SignedNoteError::UnknownKey)
    );
    assert_eq!(
        open_note(&other_hash, &[spec_verifier()?]),
        Err(SignedNoteError::UnknownKey)
    );
    assert_eq!(open_note(SPEC_NOTE, &[]), Err(SignedNoteError::UnknownKey));
    Ok(())
}

#[test]
fn verifier_key_with_a_wrong_key_id_is_refused() {
    let wrong = SPEC_VKEY.replacen("530d903a", "530d903b", 1);

    assert_eq!(
        NoteVerifier::from_vkey(&wrong),
        Err(SignedNoteError::MalformedVerifierKey)
    );
    assert_eq!(
        NoteVerifier::from_vkey("example.com/foo"),
        Err(SignedNoteError::MalformedVerifierKey)
    );
}

#[test]
fn malformed_notes_are_refused() -> TestResult {
    let verifiers = [spec_verifier()?];
    let (text, signature_line) = SPEC_NOTE.split_once("\n\n").ok_or("spec note shape")?;
    let cases = [
        String::new(),
        format!("{text}\n{signature_line}"),
        format!("{text}\n\n"),
        format!("{text}\n\n{}", signature_line.trim_end()),
        format!("{text}\n\n{signature_line}\n"),
        format!("{text}\n\n{signature_line}extra\n"),
        format!("{text}\n\n- {signature_line}"),
        format!("{text}\r\n\r\n{signature_line}"),
    ];
    for case in &cases {
        assert_eq!(
            open_note(case, &verifiers),
            Err(SignedNoteError::MalformedNote),
            "accepted {case:?}"
        );
    }
    Ok(())
}

#[test]
fn signed_note_round_trips_and_carries_the_spec_signature_shape() -> TestResult {
    let signer = note_signer();
    let verifier = NoteVerifier::new("log.example/chio", &signer.public_key())?;
    let note = sign_note("hello\n", "log.example/chio", &signer)?;

    assert!(note.starts_with("hello\n\n\u{2014} log.example/chio "));
    assert!(note.ends_with("=\n"));
    assert_eq!(open_note(&note, &[verifier.clone()])?, "hello\n");
    assert_eq!(NoteVerifier::from_vkey(&verifier.to_vkey())?, verifier);
    Ok(())
}

#[test]
fn invalid_key_names_are_refused() {
    let signer = note_signer();

    for name in ["", "a b", "a+b", "a\nb"] {
        assert_eq!(
            NoteVerifier::new(name, &signer.public_key()),
            Err(SignedNoteError::InvalidKeyName)
        );
        assert_eq!(
            sign_note("hello\n", name, &signer),
            Err(SignedNoteError::InvalidKeyName)
        );
    }
}

#[test]
fn note_text_must_end_in_a_newline_without_control_characters() {
    let signer = note_signer();

    for text in ["", "no newline", "a\u{0}b\n", "a\tb\n"] {
        assert_eq!(
            sign_note(text, "log.example/chio", &signer),
            Err(SignedNoteError::MalformedNote),
            "signed {text:?}"
        );
    }
}

#[test]
fn spec_checkpoint_body_parses() -> TestResult {
    let parsed = parse_checkpoint_text(SPEC_CHECKPOINT_TEXT)?;

    assert_eq!(parsed.origin, "example.com/behind-the-sofa");
    assert_eq!(parsed.tree_size, 20_852_163);
    assert_eq!(
        parsed.root_hash.to_hex(),
        "0ac5186a91863e8e1d90c808014aa89bf5da8e3ee1d9f07630f0378f68f1ab62"
    );
    Ok(())
}

#[test]
fn malformed_checkpoint_bodies_are_refused() {
    let root = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=";
    let cases = [
        String::new(),
        format!("\n20852163\n{root}\n"),
        format!("origin\n020852163\n{root}\n"),
        format!("origin\n+20852163\n{root}\n"),
        format!("origin\n-1\n{root}\n"),
        format!("origin\n18446744073709551616\n{root}\n"),
        format!("origin\n20852163 \n{root}\n"),
        "origin\n20852163\n".to_string(),
        format!("origin\n20852163\n{}\n", root.trim_end_matches('=')),
        format!("origin\n20852163\n{}\n", &root[..40]),
        format!("origin\n20852163\n{}\n", root.replacen('/', "_", 1)),
        format!("origin\n20852163\n{root}"),
        format!("origin\n20852163\n{}\n", root.replacen("2I=", "2J=", 1)),
        format!("origin\n20852163\n{root}\n\n"),
    ];
    for case in &cases {
        assert_eq!(
            parse_checkpoint_text(case),
            Err(SignedNoteError::MalformedCheckpoint),
            "accepted {case:?}"
        );
    }
}

#[test]
fn checkpoint_extension_lines_are_refused() {
    let root = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=";

    assert_eq!(
        parse_checkpoint_text(&format!("origin\n1\n{root}\nextension\n")),
        Err(SignedNoteError::ExtensionLine)
    );
}

#[test]
fn kernel_checkpoint_projects_to_a_tlog_checkpoint_body() -> TestResult {
    let signer = note_signer();
    let checkpoint = kernel_checkpoint(&signer)?;
    let text = checkpoint_note_text(&checkpoint, "log.example/chio", &signer.public_key())?;

    assert_eq!(
        text,
        "log.example/chio\n20\np6enp6enp6enp6enp6enp6enp6enp6enp6enp6enp6c=\n"
    );
    let parsed = parse_checkpoint_text(&text)?;
    assert_eq!(parsed.tree_size, 20);
    assert_eq!(parsed.root_hash, checkpoint.body.merkle_root);
    Ok(())
}

#[test]
fn signed_checkpoint_note_round_trips() -> TestResult {
    let signer = note_signer();
    let checkpoint = kernel_checkpoint(&signer)?;
    let verifier = NoteVerifier::new("log.example/chio", &signer.public_key())?;
    let note = sign_checkpoint_note(&checkpoint, "log.example/chio", "log.example/chio", &signer)?;
    let opened = open_checkpoint_note(&note, &[verifier])?;

    assert_eq!(opened.origin, "log.example/chio");
    assert_eq!(opened.tree_size, 20);
    assert_eq!(opened.root_hash, checkpoint.body.merkle_root);
    Ok(())
}

#[test]
fn one_byte_root_change_in_a_signed_checkpoint_note_is_an_invalid_signature() -> TestResult {
    let signer = note_signer();
    let checkpoint = kernel_checkpoint(&signer)?;
    let verifier = NoteVerifier::new("log.example/chio", &signer.public_key())?;
    let note = sign_checkpoint_note(&checkpoint, "log.example/chio", "log.example/chio", &signer)?;
    let changed = note.replacen("p6enp6", "p6enp7", 1);

    assert_ne!(changed, note);
    assert_eq!(
        open_checkpoint_note(&changed, &[verifier]),
        Err(SignedNoteError::InvalidSignature)
    );
    Ok(())
}

#[test]
fn checkpoint_note_requires_the_signing_kernel_key() -> TestResult {
    let signer = note_signer();
    let other = Keypair::from_seed(&[62_u8; 32]);
    let checkpoint = kernel_checkpoint(&signer)?;

    assert_eq!(
        sign_checkpoint_note(&checkpoint, "log.example/chio", "log.example/chio", &other),
        Err(SignedNoteError::CheckpointNotSignedByKey)
    );
    let mut tampered = checkpoint;
    tampered.body.tree_size += 1;
    assert_eq!(
        sign_checkpoint_note(&tampered, "log.example/chio", "log.example/chio", &signer),
        Err(SignedNoteError::CheckpointNotSignedByKey)
    );
    Ok(())
}

#[test]
fn checkpoint_note_text_with_extension_lines_is_refused_after_opening() -> TestResult {
    let signer = note_signer();
    let verifier = NoteVerifier::new("log.example/chio", &signer.public_key())?;
    let root = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=";
    let note = sign_note(
        &format!("log.example/chio\n1\n{root}\nextension\n"),
        "log.example/chio",
        &signer,
    )?;

    assert_eq!(
        open_checkpoint_note(&note, &[verifier]),
        Err(SignedNoteError::ExtensionLine)
    );
    Ok(())
}
