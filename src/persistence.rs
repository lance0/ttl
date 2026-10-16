//! Publish complete files without truncating the previous saved version.

use anyhow::{Context, Result};
use std::io::{BufWriter, Write};
use std::path::Path;

/// Write and sync a private temporary file beside the destination, then replace
/// the destination atomically. Failed writes leave the original file intact;
/// the temporary file is removed on error or unwind. NamedTempFile uses 0600 on
/// Unix, so preference API keys are never published with broader permissions.
pub(crate) fn atomic_write(
    path: &Path,
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".ttl-")
        .tempfile_in(parent)
        .with_context(|| format!("Failed to create temporary save in {}", parent.display()))?;
    {
        let mut buffered = BufWriter::new(temporary.as_file_mut());
        write(&mut buffered)?;
        buffered.flush()?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("Failed to replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_write_keeps_previous_file_and_removes_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saved.json");
        std::fs::write(&path, b"previous complete save").unwrap();
        let result = atomic_write(&path, |writer| {
            writer.write_all(b"incomplete replacement")?;
            anyhow::bail!("simulated disk write failure");
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"previous complete save");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failed_publish_preserves_destination_and_cleans_temporary() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("existing-directory");
        std::fs::create_dir(&destination).unwrap();
        std::fs::write(destination.join("keep"), b"original").unwrap();
        assert!(atomic_write(&destination, |writer| Ok(writer.write_all(b"new")?)).is_err());
        assert_eq!(
            std::fs::read(destination.join("keep")).unwrap(),
            b"original"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn interrupted_writer_keeps_previous_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saved.toml");
        std::fs::write(&path, b"previous").unwrap();
        let result = std::panic::catch_unwind(|| {
            let _ = atomic_write(&path, |writer| {
                writer.write_all(b"partial")?;
                panic!("simulated interrupted serialization");
            });
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"previous");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn successful_save_replaces_longer_previous_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("saved.toml");
        std::fs::write(&path, b"a much longer previous file").unwrap();
        atomic_write(&path, |writer| Ok(writer.write_all(b"complete")?)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"complete");
    }
}
