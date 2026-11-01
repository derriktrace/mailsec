// MPL-2.0. Mailsec adaptation of the onenote.rs CVE-2026-46671 fix.
// Upstream: c9267b2c96e2542be7e7b557d67318e81b733585.
// Uses std only to preserve Cisco's 0.3.1 API and offline dependency graph.
use std::io::{Error, ErrorKind, Result};
use std::path::{Component, Path, PathBuf};

fn invalid_path() -> Error {
    Error::new(ErrorKind::InvalidData, "invalid notebook entry path")
}

pub(super) fn resolve_entry_path(base_dir: &Path, entry: &str) -> Result<PathBuf> {
    let entry_path = Path::new(entry);
    if entry_path.is_absolute() {
        return Err(invalid_path());
    }
    let mut relative = PathBuf::new();
    for component in entry_path.components() {
        match component {
            Component::Normal(name) => {
                let name = name.to_str().ok_or_else(invalid_path)?;
                // Reject Windows separators/drive syntax too, when running on Unix.
                if name.chars().any(|c| c.is_control() || "<>:\"|?*\\".contains(c))
                    || name.ends_with('.') || name.ends_with(' ')
                {
                    return Err(invalid_path());
                }
                relative.push(name);
            }
            Component::CurDir => (),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_path());
            }
        }
    }
    if relative.as_os_str().is_empty() {
        return Err(invalid_path());
    }
    let candidate = base_dir.join(relative);
    if candidate.exists() {
        let base_canonical = base_dir.canonicalize()?;
        let candidate_canonical = candidate.canonicalize()?;
        if !candidate_canonical.starts_with(base_canonical) {
            return Err(invalid_path());
        }
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "mailsec-onenote-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); }
    }
    #[test]
    fn accepts_normal_relative_sections_and_nonexistent_entries() {
        let dir = Fixture::new();
        std::fs::create_dir(dir.0.join("group")).unwrap();
        std::fs::write(dir.0.join("group/section.one"), b"section").unwrap();
        assert_eq!(resolve_entry_path(&dir.0, "./group/section.one").unwrap(), dir.0.join("group/section.one"));
        assert_eq!(resolve_entry_path(&dir.0, "missing.one").unwrap(), dir.0.join("missing.one"));
    }
    #[test]
    fn rejects_parent_absolute_windows_and_empty_paths() {
        let dir = Fixture::new();
        for entry in ["../outside.one", "group/../../outside.one", "/etc/passwd", "C:\\outside.one", "..\\outside.one", "", ".", "./", "bad\0.one", "bad\n.one", "bad?.one"] {
            assert!(resolve_entry_path(&dir.0, entry).is_err(), "accepted {entry:?}");
        }
    }
    #[cfg(unix)]
    #[test]
    fn rejects_file_and_directory_symlink_escapes() {
        let dir = Fixture::new();
        let outside = Fixture::new();
        std::fs::write(outside.0.join("section.one"), b"outside").unwrap();
        std::os::unix::fs::symlink(outside.0.join("section.one"), dir.0.join("file.one")).unwrap();
        std::os::unix::fs::symlink(&outside.0, dir.0.join("group")).unwrap();
        assert!(resolve_entry_path(&dir.0, "file.one").is_err());
        assert!(resolve_entry_path(&dir.0, "group/section.one").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn permits_symlink_whose_target_is_within_notebook() {
        let dir = Fixture::new();
        std::fs::write(dir.0.join("section.one"), b"inside").unwrap();
        std::os::unix::fs::symlink(dir.0.join("section.one"), dir.0.join("link.one")).unwrap();
        assert!(resolve_entry_path(&dir.0, "link.one").is_ok());
    }
}
