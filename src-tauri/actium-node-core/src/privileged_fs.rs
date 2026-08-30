//! Frontera privilegiada no-follow para storage writable por workloads.
//!
//! chown(2)/chmod(2) y std::fs::set_permissions siguen symlinks. Un uid 1000
//! puede plantar un symlink y convertir al Supervisor CAP_CHOWN en confused
//! deputy.
//!
//! Un objeto 0750/0600 1000:1000 no se puede abrir O_RDONLY sin
//! CAP_DAC_OVERRIDE. El reclaim es de dos etapas:
//! 1. fstatat + fchownat descriptor-relative con AT_SYMLINK_NOFOLLOW
//!    (CAP_CHOWN, sin abrir el objeto);
//! 2. openat/openat2 O_NOFOLLOW sobre el inode ya root-owned y
//!    fchmod/fchown sobre el FD.
//!
//! El parent queda root-owned y no escribible por el workload antes de
//! mutar hijos. Nunca se usa chown(2)/chmod(2) por pathname.

use nix::errno::Errno;
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, fstat, fstatat, mkdirat, FileStat, Mode, SFlag};
use nix::unistd::{fchown, fchownat, Gid, Uid};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

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

fn inode_type(stat: &FileStat) -> SFlag {
    SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT
}

fn reject_unexpected(stat: &FileStat, label: &str) -> Result<(), String> {
    let kind = inode_type(stat);
    if kind == SFlag::S_IFLNK {
        return Err(format!(
            "{WORKLOAD_SYMLINK_REJECTED}: {label} es un symlink."
        ));
    }
    if kind == SFlag::S_IFREG {
        if stat.st_nlink > 1 {
            return Err(format!(
                "{WORKLOAD_SPECIAL_FILE_REJECTED}: {label} tiene enlaces duros adicionales (st_nlink={}).",
                stat.st_nlink
            ));
        }
        return Ok(());
    }
    if kind == SFlag::S_IFDIR {
        return Ok(());
    }
    Err(format!(
        "{WORKLOAD_SPECIAL_FILE_REJECTED}: {label} no es un archivo o directorio regular."
    ))
}

fn inspect_child(dirfd: RawFd, name: &Path, label: &str) -> Result<FileStat, String> {
    fstatat(Some(dirfd), name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| nix_err(&format!("fstatat {label}"), error))
}

fn reclaim_child_owner(
    dirfd: RawFd,
    name: &Path,
    uid: u32,
    gid: u32,
    label: &str,
) -> Result<(), String> {
    fchownat(
        Some(dirfd),
        name,
        Some(Uid::from_raw(uid)),
        Some(Gid::from_raw(gid)),
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|error| format!("No se pudo fchownat {label} a {uid}:{gid}: {error}"))
}

/// chmod mientras el FD sigue root-owned; chown al final.
fn apply_owner_mode(fd: RawFd, uid: u32, gid: u32, mode: u32, label: &str) -> Result<(), String> {
    fchmod(fd, Mode::from_bits_truncate(mode))
        .map_err(|error| format!("No se pudo fchmod {label} a {mode:o}: {error}"))?;
    fchown(fd, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
        .map_err(|error| format!("No se pudo fchown {label} a {uid}:{gid}: {error}"))
}

fn two_stage_reclaim(
    parent: RawFd,
    name: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    label: &str,
    directory: bool,
) -> Result<OwnedFd, String> {
    let stat = inspect_child(parent, name, label)?;
    reject_unexpected(&stat, label)?;
    let is_dir = inode_type(&stat) == SFlag::S_IFDIR;
    if directory && !is_dir {
        return Err(format!(
            "{WORKLOAD_SPECIAL_FILE_REJECTED}: {label} no es un directorio."
        ));
    }
    if !directory && is_dir {
        return Err(format!(
            "{WORKLOAD_SPECIAL_FILE_REJECTED}: {label} no es un archivo regular."
        ));
    }
    reclaim_child_owner(parent, name, 0, 0, label)?;
    let flags = if directory { dir_flags() } else { open_flags() };
    let fd = open_nofollow(Some(parent), name, flags, Mode::empty())?;
    let opened = fstat(fd.as_raw_fd()).map_err(|error| format!("fstat {label}: {error}"))?;
    reject_unexpected(&opened, label)?;
    apply_owner_mode(fd.as_raw_fd(), uid, gid, mode, label)?;
    Ok(fd)
}

pub fn read_regular_file_nofollow_bounded(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    if !path.is_absolute() {
        return Err(format!(
            "{WORKLOAD_SPECIAL_FILE_REJECTED}: origen legacy {} no es absoluto.",
            path.display()
        ));
    }
    let mut current = take_fd(
        open(Path::new("/"), dir_flags(), Mode::empty())
            .map_err(|error| nix_err("open /", error))?,
    );
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let is_last = index + 1 == components.len();
                let flags = if is_last { open_flags() } else { dir_flags() };
                match open_nofollow(
                    Some(current.as_raw_fd()),
                    Path::new(name),
                    flags,
                    Mode::empty(),
                ) {
                    Ok(next) => current = next,
                    Err(error)
                        if error.contains("ENOENT")
                            || error.contains("No such file")
                            || error.contains("No existe") =>
                    {
                        return Ok(None);
                    }
                    Err(error) => return Err(error),
                }
            }
            _ => {
                return Err(format!(
                    "{WORKLOAD_SPECIAL_FILE_REJECTED}: origen legacy {} tiene un componente invalido.",
                    path.display()
                ))
            }
        }
    }
    let stat = fstat(current.as_raw_fd())
        .map_err(|error| format!("fstat {}: {error}", path.display()))?;
    reject_unexpected(&stat, &path.display().to_string())?;
    if inode_type(&stat) != SFlag::S_IFREG {
        return Err(format!(
            "{WORKLOAD_SPECIAL_FILE_REJECTED}: origen legacy {} no es un archivo regular.",
            path.display()
        ));
    }
    if stat.st_size as usize > max_bytes {
        return Err(format!(
            "{WORKLOAD_SPECIAL_FILE_REJECTED}: origen legacy {} excede el tamano maximo permitido ({} > {} bytes).",
            path.display(),
            stat.st_size,
            max_bytes
        ));
    }
    let mut file = std::fs::File::from(current);
    let mut bytes = Vec::with_capacity(std::cmp::min(stat.st_size as usize, max_bytes));
    file.by_ref()
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("No se pudo leer {}: {error}", path.display()))?;
    if bytes.len() > max_bytes {
        return Err(format!(
            "{WORKLOAD_SPECIAL_FILE_REJECTED}: origen legacy {} excede el tamano maximo permitido.",
            path.display()
        ));
    }
    Ok(Some(bytes))
}

#[allow(dead_code)]
pub fn read_regular_file_nofollow(path: &Path) -> Result<Option<Vec<u8>>, String> {
    read_regular_file_nofollow_bounded(path, 1024 * 1024)
}

pub fn ensure_absolute_dir_nofollow(path: &Path) -> Result<PrivilegedDir, String> {
    if !path.is_absolute() {
        return Err(format!(
            "{WORKLOAD_SPECIAL_FILE_REJECTED}: {} no es una ruta absoluta.",
            path.display()
        ));
    }
    let mut current = PrivilegedDir::open_path(Path::new("/"))?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                let name_str = name.to_str().ok_or_else(|| {
                    format!("{WORKLOAD_SPECIAL_FILE_REJECTED}: componente de ruta no UTF-8.")
                })?;
                current = current.open_or_create_dir(name_str)?;
            }
            Component::CurDir => continue,
            _ => {
                return Err(format!(
                    "{WORKLOAD_SPECIAL_FILE_REJECTED}: componente de ruta no valido en {}.",
                    path.display()
                ));
            }
        }
    }
    Ok(current)
}

impl PrivilegedDir {
    pub fn open_path(path: &Path) -> Result<Self, String> {
        let raw = open(path, dir_flags(), Mode::empty())
            .map_err(|error| nix_err(&format!("open {}", path.display()), error))?;
        let fd = take_fd(raw);
        let stat =
            fstat(fd.as_raw_fd()).map_err(|error| format!("fstat {}: {error}", path.display()))?;
        reject_unexpected(&stat, &path.display().to_string())?;
        if inode_type(&stat) != SFlag::S_IFDIR {
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

    /// Open an existing child directory, or create it. Does not chown an
    /// already-present mount point (so `/srv` or `/mnt` stay intact).
    pub fn open_or_create_dir(&self, name: &str) -> Result<Self, String> {
        validate_name(name)?;
        let child = Path::new(name);
        let label = format!("{}/{}", self.display, name);
        match inspect_child(self.fd.as_raw_fd(), child, &label) {
            Ok(stat) => {
                reject_unexpected(&stat, &label)?;
                if inode_type(&stat) != SFlag::S_IFDIR {
                    return Err(format!(
                        "{WORKLOAD_SPECIAL_FILE_REJECTED}: {label} no es un directorio."
                    ));
                }
                let fd = open_nofollow(Some(self.fd.as_raw_fd()), child, dir_flags(), Mode::empty())?;
                Ok(Self {
                    fd,
                    display: label,
                })
            }
            Err(error)
                if error.contains("ENOENT")
                    || error.contains("No such file")
                    || error.contains("No existe") =>
            {
                match mkdirat(
                    Some(self.fd.as_raw_fd()),
                    child,
                    Mode::from_bits_truncate(0o750),
                ) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(Errno::EROFS) => {
                        return Err(format!(
                            "No se pudo crear storage personalizado en {label}: Read-only file system (os error 30). Montá el disco pesado en /srv, /mnt, /media, /volumeN, /data, /actium o /actium-lab (el Supervisor no puede escribir fuera de esos orígenes)."
                        ));
                    }
                    Err(error) => {
                        return Err(format!("No se pudo mkdirat {label}: {error}"));
                    }
                }
                let fd = open_nofollow(Some(self.fd.as_raw_fd()), child, dir_flags(), Mode::empty())?;
                Ok(Self {
                    fd,
                    display: label,
                })
            }
            Err(error) => Err(error),
        }
    }

    pub fn ensure_dir(&self, name: &str) -> Result<Self, String> {
        validate_name(name)?;
        let child = Path::new(name);
        let label = format!("{}/{}", self.display, name);
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
        let fd = two_stage_reclaim(
            self.fd.as_raw_fd(),
            child,
            0,
            0,
            0o750,
            &label,
            true,
        )?;
        Ok(Self {
            fd,
            display: label,
        })
    }

    pub fn reclaim(&self, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
        apply_owner_mode(self.fd.as_raw_fd(), uid, gid, mode, &self.display)
    }

    pub fn reclaim_entry(&self, name: &str, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
        validate_name(name)?;
        let label = format!("{}/{}", self.display, name);
        match inspect_child(self.fd.as_raw_fd(), Path::new(name), &label) {
            Err(error)
                if error.contains("ENOENT")
                    || error.contains("No such file")
                    || error.contains("No existe") =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
            Ok(stat) => {
                reject_unexpected(&stat, &label)?;
            }
        }
        let _ = two_stage_reclaim(
            self.fd.as_raw_fd(),
            Path::new(name),
            uid,
            gid,
            mode,
            &label,
            false,
        )?;
        Ok(())
    }

    pub fn copy_file_if_missing(&self, name: &str, source: &Path) -> Result<(), String> {
        validate_name(name)?;
        let label = format!("{}/{}", self.display, name);
        // 1. Inspeccionar destino PRIMERO, sin leer source innecesariamente.
        match inspect_child(self.fd.as_raw_fd(), Path::new(name), &label) {
            Ok(stat) => {
                reject_unexpected(&stat, &label)?;
                if inode_type(&stat) == SFlag::S_IFREG {
                    // Destino ya existe como archivo regular: no tocar.
                    return Ok(());
                }
                return Err(format!(
                    "{WORKLOAD_SPECIAL_FILE_REJECTED}: {label} no es un archivo regular."
                ));
            }
            Err(error)
                if error.contains("ENOENT")
                    || error.contains("No such file")
                    || error.contains("No existe") => {}
            Err(error) => return Err(error),
        }
        // 2. Destino no existe: ahora sí leer source de forma acotada.
        let source_bytes = match read_regular_file_nofollow_bounded(source, 1024 * 1024)? {
            Some(bytes) => bytes,
            None => return Ok(()),
        };
        // 3. Crear destino con FD WRITABLE (O_WRONLY, no O_RDONLY).
        let write_flags = OFlag::O_WRONLY
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC
            | OFlag::O_CREAT
            | OFlag::O_EXCL;
        let fd = open_nofollow(
            Some(self.fd.as_raw_fd()),
            Path::new(name),
            write_flags,
            Mode::from_bits_truncate(0o600),
        )?;
        let mut file = std::fs::File::from(fd);
        use std::io::Write;
        file.write_all(&source_bytes)
            .map_err(|error| format!("No se pudo migrar {name} hacia {}: {error}", self.display))?;
        file.sync_all()
            .map_err(|error| format!("No se pudo sincronizar {name} en {}: {error}", self.display))
    }


    pub fn reclaim_workload_children(&self) -> Result<(), String> {
        for name in self.list_names()? {
            let Some(name) = name.to_str() else {
                return Err(format!(
                    "{WORKLOAD_SPECIAL_FILE_REJECTED}: entrada no UTF-8 en {}.",
                    self.display
                ));
            };
            let label = format!("{}/{}", self.display, name);
            let stat = inspect_child(self.fd.as_raw_fd(), Path::new(name), &label)?;
            reject_unexpected(&stat, &label)?;
            let (uid, gid, mode, directory) =
                if inode_type(&stat) == SFlag::S_IFDIR {
                    (1000, 1000, 0o750, true)
                } else {
                    (1000, 1000, 0o600, false)
                };
            let _ = two_stage_reclaim(
                self.fd.as_raw_fd(),
                Path::new(name),
                uid,
                gid,
                mode,
                &label,
                directory,
            )?;
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
            let label = format!("{}/{}", self.display, name);
            let stat = inspect_child(self.fd.as_raw_fd(), Path::new(name), &label)?;
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

    #[test]
    fn rechaza_hardlink_adicional_st_nlink() {
        let root = std::env::temp_dir().join(format!("actium-privfs-hl-{}", Uuid::new_v4()));
        let dir = root.join("agent");
        let external = root.join("external");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&external, b"original-file\n").unwrap();
        std::fs::hard_link(&external, dir.join("linked")).unwrap();
        let opened = PrivilegedDir::open_path(&dir).unwrap();
        let error = opened
            .reclaim_workload_children()
            .expect_err("el hardlink adicional no puede reconciliarse");
        assert!(error.contains(WORKLOAD_SPECIAL_FILE_REJECTED), "{error}");
        assert!(error.contains("enlaces duros adicionales"), "{error}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn read_regular_file_nofollow_bounded_rechaza_exceso() {
        let root = std::env::temp_dir().join(format!("actium-privfs-bound-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let file_path = root.join("large.bin");
        fs::write(&file_path, vec![0u8; 1024]).unwrap();

        // 512 bytes max debe rechazar
        let err = read_regular_file_nofollow_bounded(&file_path, 512)
            .expect_err("debe rechazar archivo que excede max_bytes");
        assert!(err.contains(WORKLOAD_SPECIAL_FILE_REJECTED), "{err}");
        assert!(err.contains("excede el tamano maximo permitido"), "{err}");

        // 2048 bytes max debe permitir
        let content = read_regular_file_nofollow_bounded(&file_path, 2048)
            .expect("debe permitir archivo dentro del limite")
            .expect("archivo debe existir");
        assert_eq!(content.len(), 1024);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn open_or_create_dir_crea_hijo_sin_tocar_el_padre() {
        let root = std::env::temp_dir().join(format!("actium-privfs-mkdir-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let opened = PrivilegedDir::open_path(&root).unwrap();
        let child = opened.open_or_create_dir("dvr").unwrap();
        assert!(root.join("dvr").is_dir());
        let again = opened.open_or_create_dir("dvr").unwrap();
        assert_eq!(child.display, again.display);
        let nested = ensure_absolute_dir_nofollow(&root.join("radio-saf").join("objects")).unwrap();
        assert!(root.join("radio-saf").join("objects").is_dir());
        assert!(nested.display.ends_with("radio-saf/objects"));
        let _ = fs::remove_dir_all(root);
    }
}

