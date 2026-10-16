//! Publish complete files without truncating the previous saved version.

use anyhow::{Context, Result};
use std::io::{BufWriter, Write};
use std::path::Path;

/// Write and sync a temporary file beside the destination, then replace the
/// destination atomically. Failed writes leave the original file intact; the
/// temporary file is removed on error or unwind. `private` keeps tempfile's
/// 0600 mode on Unix (preference API keys); otherwise the file gets the usual
/// 0666 & umask. An existing symlink is followed so dotfile links survive.
pub(crate) fn atomic_write(
    path: &Path,
    private: bool,
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let path = resolved.as_path();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut builder = tempfile::Builder::new();
    builder.prefix(".ttl-");
    #[cfg(unix)]
    if !private {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o666));
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut temporary = builder
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
        let result = atomic_write(&path, false, |writer| {
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
        assert!(atomic_write(&destination, false, |writer| Ok(writer.write_all(b"new")?)).is_err());
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
            let _ = atomic_write(&path, false, |writer| {
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
        atomic_write(&path, false, |writer| Ok(writer.write_all(b"complete")?)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"complete");
    }

    #[cfg(unix)]
    #[test]
    fn follows_symlinks_and_uses_default_permissions_unless_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("dotfiles-config.toml");
        let link = dir.path().join("config.toml");
        std::fs::write(&target, b"old").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        atomic_write(&link, true, |w| Ok(w.write_all(b"new")?)).unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(
            target.metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );

        let plain = dir.path().join("plain");
        let export = dir.path().join("export.json");
        std::fs::File::create(&plain).unwrap();
        atomic_write(&export, false, |w| Ok(w.write_all(b"{}")?)).unwrap();
        assert_eq!(
            export.metadata().unwrap().permissions().mode(),
            plain.metadata().unwrap().permissions().mode()
        );
    }
}
