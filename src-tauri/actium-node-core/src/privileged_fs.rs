//! Frontera privilegiada no-follow para storage writable por workloads.
//!
//! chown(2)/chmod(2) y std::fs::set_permissions siguen symlinks. Un uid 1000
//! puede plantar un symlink y convertir al Supervisor CAP_CHOWN en confused
//! deputy. Todas las mutaciones de ownership/mode sobre esos árboles deben
//! abrir la entrada con O_NOFOLLOW (y openat2 RESOLVE_NO_SYMLINKS en Linux)
//! y operar sobre el descriptor.

use nix::errno::Errno;
use nix::fcntl::{open, openat, OFlag};
use nix::sys::stat::{fchmod, fstat, mkdirat, FileStat, Mode, SFlag};
use nix::unistd::{fchown, Gid, Uid};
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub const WORKLOAD_SYMLINK_REJECTED: &str = "WORKLOAD_SYMLINK_REJECTED";
pub const WORKLOAD_SPECIAL_FILE_REJECTED: &str = "WORKLOAD_SPECIAL_FILE_REJECTED";

fn open_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK
}

fn dir_flags() -> OFlag {
    open_flags() | OFlag::O_DIRECTORY
}

pub struct PrivilegedDir {
    fd: OwnedFd,
    display: String,
}

fn take_fd(raw: RawFd) -> OwnedFd {
    // Safety: open/openat/openat2 devolvieron un fd nuevo de nuestra propiedad.
    unsafe { OwnedFd::from_raw_fd(raw) }
}

fn nix_err(context: &str, error: Errno) -> String {
    if matches!(error, Errno::ELOOP | Errno::EMLINK) {
        format!("{WORKLOAD_SYMLINK_REJECTED}: {context}: {error}")
    } else {
        format!("{context}: {error}")
    }
}

fn open_nofollow(
    dirfd: Option<RawFd>,
    name: &Path,
    flags: OFlag,
    create_mode: Mode,
) -> Result<OwnedFd, String> {
    let label = name.display().to_string();
    #[cfg(target_os = "linux")]
    if let Some(fd) = dirfd {
        use nix::fcntl::{openat2, OpenHow, ResolveFlag};
        let how = OpenHow::new()
            .flags(flags)
            .mode(create_mode)
            .resolve(ResolveFlag::RESOLVE_NO_SYMLINKS | ResolveFlag::RESOLVE_BENEATH);
        match openat2(fd, name, how) {
            Ok(raw) => return Ok(take_fd(raw)),
            Err(Errno::ENOSYS) | Err(Errno::EINVAL) => {}
            Err(error) => return Err(nix_err(&format!("openat2 {label}"), error)),
        }
    }
    match openat(dirfd, name, flags, create_mode) {
        Ok(raw) => Ok(take_fd(raw)),
        Err(error) => Err(nix_err(&format!("openat {label}"), error)),
    }
}

fn reject_unexpected(stat: &FileStat, label: &str) -> Result<(), String> {
    let kind = SFlag::from_bits_truncate(stat.st_mode);
    if kind.contains(SFlag::S_IFLNK) {
        return Err(format!(
            "{WORKLOAD_SYMLINK_REJECTED}: {label} es un symlink."
        ));
    }
    if kind.contains(SFlag::S_IFREG) || kind.contains(SFlag::S_IFDIR) {
        return Ok(());
    }
    Err(format!(
        "{WORKLOAD_SPECIAL_FILE_REJECTED}: {label} no es un archivo o directorio regular."
    ))
}

fn reclaim_fd(fd: RawFd, uid: u32, gid: u32, mode: u32, label: &str) -> Result<(), String> {
    fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(|error| format!("No se pudo fchown {label} a {uid}:{gid}: {error}"))?;
    fchmod(fd, Mode::from_bits_truncate(mode))
        .map_err(|error| format!("No se pudo fchmod {label} a {mode:o}: {error}"))
}

impl PrivilegedDir {
    pub fn open_path(path: &Path) -> Result<Self, String> {
        let raw = open(path, dir_flags(), Mode::empty())
            .map_err(|error| nix_err(&format!("open {}", path.display()), error))?;
        let fd = take_fd(raw);
        let stat =
            fstat(fd.as_raw_fd()).map_err(|error| format!("fstat {}: {error}", path.display()))?;
        reject_unexpected(&stat, &path.display().to_string())?;
        if !SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFDIR) {
            return Err(format!(
                "{WORKLOAD_SPECIAL_FILE_REJECTED}: {} no es un directorio.",
                path.display()
            ));
        }
        Ok(Self {
            fd,
            display: path.display().to_string(),
        })
    }

    pub fn ensure_dir(&self, name: &str) -> Result<Self, String> {
        validate_name(name)?;
        let child = Path::new(name);
        match mkdirat(
            Some(self.fd.as_raw_fd()),
            child,
            Mode::from_bits_truncate(0o750),
        ) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => {
                return Err(format!(
                    "No se pudo mkdirat {}/{name}: {error}",
                    self.display
                ))
            }
        }
        let fd = open_nofollow(Some(self.fd.as_raw_fd()), child, dir_flags(), Mode::empty())?;
        let stat = fstat(fd.as_raw_fd())
            .map_err(|error| format!("fstat {}/{name}: {error}", self.display))?;
        reject_unexpected(&stat, &format!("{}/{}", self.display, name))?;
        if !SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFDIR) {
            return Err(format!(
                "{WORKLOAD_SPECIAL_FILE_REJECTED}: {}/{name} no es un directorio.",
                self.display
            ));
        }
        Ok(Self {
            fd,
            display: format!("{}/{}", self.display, name),
        })
    }

    pub fn reclaim(&self, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
        reclaim_fd(self.fd.as_raw_fd(), uid, gid, mode, &self.display)
    }

    pub fn reclaim_entry(&self, name: &str, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
        validate_name(name)?;
        let fd = open_nofollow(
            Some(self.fd.as_raw_fd()),
            Path::new(name),
            open_flags(),
            Mode::empty(),
        )?;
        let label = format!("{}/{}", self.display, name);
        let stat = fstat(fd.as_raw_fd()).map_err(|error| format!("fstat {label}: {error}"))?;
        reject_unexpected(&stat, &label)?;
        reclaim_fd(fd.as_raw_fd(), uid, gid, mode, &label)
    }

    pub fn copy_file_if_missing(&self, name: &str, source: &Path) -> Result<(), String> {
        validate_name(name)?;
        let meta = match std::fs::symlink_metadata(source) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "No se pudo inspeccionar {}: {error}",
                    source.display()
                ))
            }
        };
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(format!(
                "{WORKLOAD_SPECIAL_FILE_REJECTED}: origen legacy {} no es un archivo regular.",
                source.display()
            ));
        }
        match open_nofollow(
            Some(self.fd.as_raw_fd()),
            Path::new(name),
            open_flags(),
            Mode::empty(),
        ) {
            Ok(_) => return Ok(()),
            Err(error) if error.contains(WORKLOAD_SYMLINK_REJECTED) => return Err(error),
            Err(_) => {}
        }
        let fd = open_nofollow(
            Some(self.fd.as_raw_fd()),
            Path::new(name),
            open_flags() | OFlag::O_CREAT | OFlag::O_EXCL,
            Mode::from_bits_truncate(0o600),
        )?;
        let bytes = std::fs::read(source)
            .map_err(|error| format!("No se pudo leer {}: {error}", source.display()))?;
        let mut file = std::fs::File::from(fd);
        use std::io::Write;
        file.write_all(&bytes)
            .map_err(|error| format!("No se pudo migrar {name} hacia {}: {error}", self.display))
    }

    pub fn reclaim_workload_children(&self) -> Result<(), String> {
        for name in self.list_names()? {
            let Some(name) = name.to_str() else {
                return Err(format!(
                    "{WORKLOAD_SPECIAL_FILE_REJECTED}: entrada no UTF-8 en {}.",
                    self.display
                ));
            };
            let fd = open_nofollow(
                Some(self.fd.as_raw_fd()),
                Path::new(name),
                open_flags(),
                Mode::empty(),
            )?;
            let label = format!("{}/{}", self.display, name);
            let stat = fstat(fd.as_raw_fd()).map_err(|error| format!("fstat {label}: {error}"))?;
            reject_unexpected(&stat, &label)?;
            let (uid, gid, mode) =
                if SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFDIR) {
                    (1000, 1000, 0o750)
                } else {
                    (1000, 1000, 0o600)
                };
            reclaim_fd(fd.as_raw_fd(), 0, 0, mode, &label)?;
            reclaim_fd(fd.as_raw_fd(), uid, gid, mode, &label)?;
        }
        Ok(())
    }

    pub fn reject_unsafe_entries(&self, skip: &[&str]) -> Result<(), String> {
        for name in self.list_names()? {
            let Some(name) = name.to_str() else {
                return Err(format!(
                    "{WORKLOAD_SPECIAL_FILE_REJECTED}: entrada no UTF-8 en {}.",
                    self.display
                ));
            };
            if skip.contains(&name) {
                continue;
            }
            let fd = open_nofollow(
                Some(self.fd.as_raw_fd()),
                Path::new(name),
                open_flags(),
                Mode::empty(),
            )?;
            let label = format!("{}/{}", self.display, name);
            let stat = fstat(fd.as_raw_fd()).map_err(|error| format!("fstat {label}: {error}"))?;
            reject_unexpected(&stat, &label)?;
        }
        Ok(())
    }

    fn list_names(&self) -> Result<Vec<OsString>, String> {
        let dup = nix::unistd::dup(self.fd.as_raw_fd())
            .map_err(|error| format!("dup {}: {error}", self.display))?;
        let mut dir = nix::dir::Dir::from_fd(dup)
            .map_err(|error| format!("fdopendir {}: {error}", self.display))?;
        let mut names = Vec::new();
        for entry in dir.iter() {
            let entry = entry.map_err(|error| format!("readdir {}: {error}", self.display))?;
            let raw = entry.file_name();
            let name = OsStr::from_bytes(raw.to_bytes());
            if name == "." || name == ".." {
                continue;
            }
            names.push(name.to_os_string());
        }
        Ok(names)
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(format!(
            "{WORKLOAD_SPECIAL_FILE_REJECTED}: nombre de entrada invalido."
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use uuid::Uuid;

    #[test]
    fn rechaza_symlink_sin_seguir_el_objetivo() {
        let root = std::env::temp_dir().join(format!("actium-privfs-{}", Uuid::new_v4()));
        let dir = root.join("agent");
        let target = root.join("target");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&target, b"untouched\n").unwrap();
        symlink(&target, dir.join("evil")).unwrap();
        let opened = PrivilegedDir::open_path(&dir).unwrap();
        let error = opened
            .reclaim_workload_children()
            .expect_err("el symlink no puede reconciliarse");
        assert!(error.contains(WORKLOAD_SYMLINK_REJECTED), "{error}");
        assert_eq!(fs::read(&target).unwrap(), b"untouched\n");
        assert!(fs::symlink_metadata(dir.join("evil"))
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(root);
    }
}
