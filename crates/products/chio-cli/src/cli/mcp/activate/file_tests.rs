use super::*;

#[test]
fn an_edit_after_loading_aborts_replacement_and_removes_the_temporary_file(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("client.json");
    std::fs::write(&path, b"original")?;
    let snapshot = ConfigFile::open(&path)?;
    std::fs::write(&path, b"new operator settings")?;
    assert!(snapshot.replace(b"proposed settings").is_err());
    assert_eq!(std::fs::read(&path)?, b"new operator settings");
    assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn a_replaced_inode_is_a_conflict_even_when_its_contents_match(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("client.json");
    std::fs::write(&path, b"original")?;
    let snapshot = ConfigFile::open(&path)?;
    let other = root.path().join("other.json");
    std::fs::write(&other, b"original")?;
    std::fs::rename(other, &path)?;
    assert!(snapshot.replace(b"proposed settings").is_err());
    assert_eq!(std::fs::read(&path)?, b"original");
    assert_eq!(std::fs::read_dir(root.path())?.count(), 1);
    Ok(())
}

#[test]
fn replacing_the_parent_directory_aborts_the_update() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let parent = root.path().join("config");
    std::fs::create_dir(&parent)?;
    let path = parent.join("client.json");
    std::fs::write(&path, b"original")?;
    let snapshot = ConfigFile::open(&path)?;
    let moved = root.path().join("moved");
    std::fs::rename(&parent, &moved)?;
    std::fs::create_dir(&parent)?;
    std::fs::write(&path, b"replacement directory settings")?;
    assert!(snapshot.replace(b"proposed settings").is_err());
    assert_eq!(std::fs::read(&path)?, b"replacement directory settings");
    assert_eq!(std::fs::read(moved.join("client.json"))?, b"original");
    assert_eq!(std::fs::read_dir(&parent)?.count(), 1);
    Ok(())
}
