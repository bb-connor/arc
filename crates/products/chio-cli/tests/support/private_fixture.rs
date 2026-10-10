use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

/// Create fresh private fixture material without a broad-permission interval.
pub(crate) fn write_private_file(path: &Path, bytes: impl AsRef<[u8]>) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes.as_ref())?;
    file.sync_all()
}
