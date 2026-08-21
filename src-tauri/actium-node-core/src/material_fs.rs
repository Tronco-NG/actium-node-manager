//! Filesystem backend for the Supervisor material plane.
//!
//! Unix uses privileged NOFOLLOW primitives; Windows rejects reparse points and
//! relies on the Supervisor service ACL established at install time.

use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterialFsReject {
    Symlink,
    Hardlink,
    SpecialFile,
    InvalidPath,
    TooLarge,
    NotFound,
    Io,
}

impl MaterialFsReject {
    pub fn code(self) -> &'static str {
        match self {
            Self::Symlink => "MATERIAL_FS_SYMLINK_REJECTED",
            Self::Hardlink => "MATERIAL_FS_HARDLINK_REJECTED",
            Self::SpecialFile => "MATERIAL_FS_SPECIAL_FILE_REJECTED",
            Self::InvalidPath => "MATERIAL_FS_INVALID_PATH",
            Self::TooLarge => "MATERIAL_FS_TOO_LARGE",
            Self::NotFound => "MATERIAL_FS_NOT_FOUND",
            Self::Io => "MATERIAL_FS_IO",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecureFileMeta {
    pub len: u64,
    pub is_symlink: bool,
    pub unix_uid: Option<u32>,
    pub unix_mode: Option<u32>,
}

pub trait MaterialFilesystemBackend: Send + Sync {
    fn ensure_dir(&self, path: &Path) -> Result<(), String>;
    fn write_bytes_exclusive(&self, path: &Path, bytes: &[u8]) -> Result<(), String>;
    fn read_regular_file_bounded(&self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, String>;
    fn inspect_regular_file(&self, path: &Path) -> Result<(u64, u64), String>;
    fn reject_unsafe_tree(
        &self,
        root: &Path,
        max_files: usize,
        max_total: u64,
    ) -> Result<(), String>;
    fn list_relative_files(&self, root: &Path) -> Result<Vec<String>, String>;
    fn remove_path_if_exists(&self, path: &Path) -> Result<(), String>;
    fn rename_path(&self, from: &Path, to: &Path) -> Result<(), String>;
    fn path_exists(&self, path: &Path) -> bool;
    fn is_dir(&self, path: &Path) -> bool;
    fn inspect_secure_file(&self, path: &Path) -> Result<SecureFileMeta, String>;
    fn directory_stats(&self, root: &Path) -> Result<(usize, u64), String>;
    fn child_dir_count(&self, root: &Path) -> Result<usize, String>;
}

pub fn validate_relative_component(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(format!(
            "{}: invalid path component",
            MaterialFsReject::InvalidPath.code()
        ));
    }
    Ok(())
}

pub fn normalize_relative_path(path: &str) -> Result<String, String> {
    let path = path.trim();
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') {
        return Err(format!(
            "{}: absolute or empty path rejected",
            MaterialFsReject::InvalidPath.code()
        ));
    }
    let mut parts = Vec::new();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(name) => {
                let name = name
                    .to_str()
                    .ok_or_else(|| format!("{}: non-utf8", MaterialFsReject::InvalidPath.code()))?;
                validate_relative_component(name)?;
                parts.push(name.to_string());
            }
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "{}: path traversal rejected",
                    MaterialFsReject::InvalidPath.code()
                ));
            }
        }
    }
    if parts.is_empty() {
        return Err(format!(
            "{}: empty normalized path",
            MaterialFsReject::InvalidPath.code()
        ));
    }
    Ok(parts.join("/"))
}

pub fn path_under_prefix(relative: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        let prefix = prefix.trim_end_matches('/');
        relative == prefix || relative.starts_with(&format!("{prefix}/"))
    })
}

#[derive(Debug, Default, Clone)]
pub struct StdMaterialFilesystem;

impl MaterialFilesystemBackend for StdMaterialFilesystem {
    fn ensure_dir(&self, path: &Path) -> Result<(), String> {
        std::fs::create_dir_all(path).map_err(|error| {
            format!(
                "{}: mkdir {}: {error}",
                MaterialFsReject::Io.code(),
                path.display()
            )
        })
    }

    fn write_bytes_exclusive(&self, path: &Path, bytes: &[u8]) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            self.ensure_dir(parent)?;
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| {
                format!(
                    "{}: create {}: {error}",
                    MaterialFsReject::Io.code(),
                    path.display()
                )
            })?;
        file.write_all(bytes).map_err(|error| {
            format!(
                "{}: write {}: {error}",
                MaterialFsReject::Io.code(),
                path.display()
            )
        })?;
        file.sync_all().map_err(|error| {
            format!(
                "{}: sync {}: {error}",
                MaterialFsReject::Io.code(),
                path.display()
            )
        })?;
        Ok(())
    }

    fn read_regular_file_bounded(&self, path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
        #[cfg(unix)]
        {
            return crate::privileged_fs::read_regular_file_nofollow_bounded(path, max_bytes)?
                .ok_or_else(|| {
                    format!("{}: {}", MaterialFsReject::NotFound.code(), path.display())
                });
        }
        #[cfg(not(unix))]
        {
            windows_reject_reparse(path)?;
            let meta = std::fs::metadata(path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    format!("{}: {}", MaterialFsReject::NotFound.code(), path.display())
                } else {
                    format!("{}: {}", MaterialFsReject::Io.code(), error)
                }
            })?;
            if !meta.is_file() {
                return Err(format!(
                    "{}: {} is not a regular file",
                    MaterialFsReject::SpecialFile.code(),
                    path.display()
                ));
            }
            if meta.len() as usize > max_bytes {
                return Err(format!(
                    "{}: {} exceeds max bytes",
                    MaterialFsReject::TooLarge.code(),
                    path.display()
                ));
            }
            std::fs::read(path).map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))
        }
    }

    fn inspect_regular_file(&self, path: &Path) -> Result<(u64, u64), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::symlink_metadata(path)
                .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "{}: {}",
                    MaterialFsReject::Symlink.code(),
                    path.display()
                ));
            }
            if !meta.is_file() {
                return Err(format!(
                    "{}: {}",
                    MaterialFsReject::SpecialFile.code(),
                    path.display()
                ));
            }
            if meta.nlink() > 1 {
                return Err(format!(
                    "{}: {}",
                    MaterialFsReject::Hardlink.code(),
                    path.display()
                ));
            }
            Ok((meta.len(), meta.nlink()))
        }
        #[cfg(not(unix))]
        {
            windows_reject_reparse(path)?;
            let meta = std::fs::metadata(path)
                .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
            if !meta.is_file() {
                return Err(format!(
                    "{}: {}",
                    MaterialFsReject::SpecialFile.code(),
                    path.display()
                ));
            }
            Ok((meta.len(), 1))
        }
    }

    fn reject_unsafe_tree(
        &self,
        root: &Path,
        max_files: usize,
        max_total: u64,
    ) -> Result<(), String> {
        let mut stack = vec![root.to_path_buf()];
        let mut files = 0usize;
        let mut total = 0u64;
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir).map_err(|error| {
                format!(
                    "{}: readdir {}: {error}",
                    MaterialFsReject::Io.code(),
                    dir.display()
                )
            })?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
                let path = entry.path();
                let ft = entry
                    .file_type()
                    .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
                if ft.is_symlink() {
                    return Err(format!(
                        "{}: {}",
                        MaterialFsReject::Symlink.code(),
                        path.display()
                    ));
                }
                if ft.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !ft.is_file() {
                    return Err(format!(
                        "{}: {}",
                        MaterialFsReject::SpecialFile.code(),
                        path.display()
                    ));
                }
                let (len, nlink) = self.inspect_regular_file(&path)?;
                if nlink > 1 {
                    return Err(format!(
                        "{}: {}",
                        MaterialFsReject::Hardlink.code(),
                        path.display()
                    ));
                }
                files = files.saturating_add(1);
                total = total.saturating_add(len);
                if files > max_files {
                    return Err(format!(
                        "{}: file count exceeds limit",
                        MaterialFsReject::TooLarge.code()
                    ));
                }
                if total > max_total {
                    return Err(format!(
                        "{}: total bytes exceed limit",
                        MaterialFsReject::TooLarge.code()
                    ));
                }
            }
        }
        Ok(())
    }

    fn list_relative_files(&self, root: &Path) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        let mut stack = vec![(root.to_path_buf(), String::new())];
        while let Some((dir, prefix)) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(|| {
                    format!("{}: non-utf8 name", MaterialFsReject::InvalidPath.code())
                })?;
                validate_relative_component(name)?;
                let relative = if prefix.is_empty() {
                    name.to_string()
                } else {
                    format!("{prefix}/{name}")
                };
                let path = entry.path();
                let ft = entry
                    .file_type()
                    .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
                if ft.is_symlink() {
                    return Err(format!(
                        "{}: {}",
                        MaterialFsReject::Symlink.code(),
                        path.display()
                    ));
                }
                if ft.is_dir() {
                    stack.push((path, relative));
                } else if ft.is_file() {
                    out.push(relative);
                } else {
                    return Err(format!(
                        "{}: {}",
                        MaterialFsReject::SpecialFile.code(),
                        path.display()
                    ));
                }
            }
        }
        out.sort();
        Ok(out)
    }

    fn remove_path_if_exists(&self, path: &Path) -> Result<(), String> {
        if !path.exists() {
            return Ok(());
        }
        if path.is_dir() {
            std::fs::remove_dir_all(path)
                .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))
        } else {
            std::fs::remove_file(path)
                .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))
        }
    }

    fn rename_path(&self, from: &Path, to: &Path) -> Result<(), String> {
        if let Some(parent) = to.parent() {
            self.ensure_dir(parent)?;
        }
        std::fs::rename(from, to)
            .map_err(|error| format!("{}: rename: {error}", MaterialFsReject::Io.code()))
    }

    fn path_exists(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn is_dir(&self, path: &Path) -> bool {
        std::fs::symlink_metadata(path)
            .map(|meta| meta.file_type().is_dir())
            .unwrap_or(false)
    }

    fn inspect_secure_file(&self, path: &Path) -> Result<SecureFileMeta, String> {
        let meta = std::fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                format!("{}: {}", MaterialFsReject::NotFound.code(), path.display())
            } else {
                format!("{}: {error}", MaterialFsReject::Io.code())
            }
        })?;
        let is_symlink = meta.file_type().is_symlink();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(SecureFileMeta {
                len: meta.len(),
                is_symlink,
                unix_uid: Some(meta.uid()),
                unix_mode: Some(meta.mode()),
            })
        }
        #[cfg(windows)]
        {
            windows_reject_reparse(path)?;
            Ok(SecureFileMeta {
                len: meta.len(),
                is_symlink,
                unix_uid: None,
                unix_mode: None,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(SecureFileMeta {
                len: meta.len(),
                is_symlink,
                unix_uid: None,
                unix_mode: None,
            })
        }
    }

    fn directory_stats(&self, root: &Path) -> Result<(usize, u64), String> {
        if !self.is_dir(root) {
            return Ok((0, 0));
        }
        let files = self.list_relative_files(root)?;
        let mut total = 0u64;
        for rel in &files {
            let (len, _) = self.inspect_regular_file(&root.join(rel))?;
            total = total.saturating_add(len);
        }
        Ok((files.len(), total))
    }

    fn child_dir_count(&self, root: &Path) -> Result<usize, String> {
        if !self.is_dir(root) {
            return Ok(0);
        }
        let mut count = 0usize;
        let entries = std::fs::read_dir(root).map_err(|error| {
            format!(
                "{}: readdir {}: {error}",
                MaterialFsReject::Io.code(),
                root.display()
            )
        })?;
        for entry in entries {
            let entry =
                entry.map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
            let ft = entry
                .file_type()
                .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
            if ft.is_symlink() {
                return Err(format!(
                    "{}: {}",
                    MaterialFsReject::Symlink.code(),
                    entry.path().display()
                ));
            }
            if ft.is_dir() {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }
}

#[cfg(windows)]
fn windows_reject_reparse(path: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let meta = std::fs::symlink_metadata(path)
        .map_err(|error| format!("{}: {error}", MaterialFsReject::Io.code()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "{}: reparse point rejected at {}",
            MaterialFsReject::Symlink.code(),
            path.display()
        ));
    }
    Ok(())
}

pub fn generation_dir_name(
    authority_epoch: u64,
    generation: u64,
    revision: u64,
    content_digest_hex: &str,
) -> String {
    let short = if content_digest_hex.len() >= 12 {
        &content_digest_hex[..12]
    } else {
        content_digest_hex
    };
    format!("{authority_epoch}-{generation}-{revision}-{short}")
}

pub fn material_capability_root(node_root: &Path, capability: &str) -> PathBuf {
    node_root
        .join("state")
        .join("supervisor")
        .join("material")
        .join(capability)
}

pub fn material_root(node_root: &Path) -> PathBuf {
    node_root.join("state").join("supervisor").join("material")
}

pub fn material_inbox_root(node_root: &Path) -> PathBuf {
    material_root(node_root).join("_inbox")
}

pub fn material_trust_store_path(node_root: &Path) -> PathBuf {
    node_root
        .join("state")
        .join("supervisor")
        .join("trust")
        .join("material-trust-store-v1.json")
}
