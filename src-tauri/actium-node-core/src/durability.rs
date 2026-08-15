use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityGuarantee {
    PosixDirectorySynced,
    WindowsWriteThrough,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationOutcome {
    NotPublished,
    PublishedButDurabilityUnknown,
    PublishedDurably(DurabilityGuarantee),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationFailure {
    pub outcome: PublicationOutcome,
    pub message: String,
}

impl PublicationFailure {
    fn not_published(message: impl Into<String>) -> Self {
        Self {
            outcome: PublicationOutcome::NotPublished,
            message: message.into(),
        }
    }

    fn durability_unknown(message: impl Into<String>) -> Self {
        Self {
            outcome: PublicationOutcome::PublishedButDurabilityUnknown,
            message: message.into(),
        }
    }

    fn published_durably(guarantee: DurabilityGuarantee, message: impl Into<String>) -> Self {
        Self {
            outcome: PublicationOutcome::PublishedDurably(guarantee),
            message: message.into(),
        }
    }
}

pub fn publish_immutable<F>(
    final_path: &Path,
    bytes: &[u8],
    mut fault: F,
) -> Result<DurabilityGuarantee, PublicationFailure>
where
    F: FnMut(&str) -> Result<(), String>,
{
    let directory = final_path.parent().ok_or_else(|| {
        PublicationFailure::not_published("La publicacion durable no posee directorio padre.")
    })?;
    fs::create_dir_all(directory).map_err(|error| {
        PublicationFailure::not_published(format!(
            "No se pudo crear {}: {error}",
            directory.display()
        ))
    })?;
    fault("before_temp_write").map_err(PublicationFailure::not_published)?;
    if final_path.exists() {
        return Err(PublicationFailure::not_published(format!(
            "El destino inmutable ya existe: {}.",
            final_path.display()
        )));
    }
    let temporary = temporary_path(final_path);
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("No se pudo crear temporal durable: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("No se pudo escribir temporal durable: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("No se pudo sincronizar temporal durable: {error}"))?;
        Ok::<(), String>(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(PublicationFailure::not_published(error));
    }
    if let Err(error) = fault("after_temp_sync") {
        let _ = fs::remove_file(&temporary);
        return Err(PublicationFailure::not_published(error));
    }
    publish_path(&temporary, final_path, false).map_err(PublicationFailure::not_published)?;
    if let Err(error) = fault("after_rename_before_directory_sync") {
        return Err(PublicationFailure::durability_unknown(error));
    }
    let guarantee =
        sync_parent_directory(directory).map_err(PublicationFailure::durability_unknown)?;
    if let Err(error) = fault("directory_sync") {
        return Err(PublicationFailure::durability_unknown(error));
    }
    if let Err(error) = fault("after_durable_publication") {
        return Err(PublicationFailure::published_durably(guarantee, error));
    }
    Ok(guarantee)
}

pub fn replace_durable<F>(
    final_path: &Path,
    bytes: &[u8],
    mut fault: F,
) -> Result<DurabilityGuarantee, PublicationFailure>
where
    F: FnMut(&str) -> Result<(), String>,
{
    let directory = final_path.parent().ok_or_else(|| {
        PublicationFailure::not_published("El reemplazo durable no posee directorio padre.")
    })?;
    fs::create_dir_all(directory).map_err(|error| {
        PublicationFailure::not_published(format!(
            "No se pudo crear {}: {error}",
            directory.display()
        ))
    })?;
    fault("before_temp_write").map_err(PublicationFailure::not_published)?;
    let temporary = temporary_path(final_path);
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("No se pudo crear temporal durable: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("No se pudo escribir temporal durable: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("No se pudo sincronizar temporal durable: {error}"))?;
        Ok::<(), String>(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(PublicationFailure::not_published(error));
    }
    if let Err(error) = fault("after_temp_sync") {
        let _ = fs::remove_file(&temporary);
        return Err(PublicationFailure::not_published(error));
    }
    publish_path(&temporary, final_path, true).map_err(PublicationFailure::not_published)?;
    if let Err(error) = fault("after_rename_before_directory_sync") {
        return Err(PublicationFailure::durability_unknown(error));
    }
    let guarantee =
        sync_parent_directory(directory).map_err(PublicationFailure::durability_unknown)?;
    if let Err(error) = fault("directory_sync") {
        return Err(PublicationFailure::durability_unknown(error));
    }
    if let Err(error) = fault("after_durable_publication") {
        return Err(PublicationFailure::published_durably(guarantee, error));
    }
    Ok(guarantee)
}

fn temporary_path(path: &Path) -> PathBuf {
    path.with_extension(format!("tmp-{}", Uuid::new_v4()))
}

#[cfg(unix)]
fn publish_path(source: &Path, target: &Path, replace: bool) -> Result<(), String> {
    if !replace && target.exists() {
        return Err(format!(
            "El destino inmutable ya existe: {}.",
            target.display()
        ));
    }
    fs::rename(source, target).map_err(|error| {
        format!(
            "No se pudo publicar {} como {}: {error}",
            source.display(),
            target.display()
        )
    })
}

#[cfg(windows)]
fn publish_path(source: &Path, target: &Path, replace: bool) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    if !replace && target.exists() {
        return Err(format!(
            "El destino inmutable ya existe: {}.",
            target.display()
        ));
    }
    let source = windows_extended_path(source)?;
    let target = windows_extended_path(target)?;
    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let target_wide = target
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = MOVEFILE_WRITE_THROUGH
        | if replace {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    let result = unsafe { MoveFileExW(source_wide.as_ptr(), target_wide.as_ptr(), flags) };
    if result == 0 {
        return Err(format!(
            "MoveFileExW no pudo publicar {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_extended_path(path: &Path) -> Result<PathBuf, String> {
    use std::ffi::OsString;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("No se pudo resolver ruta durable: {error}"))?
            .join(path)
    };
    let normalized = absolute.to_string_lossy().replace('/', r"\");
    let value = normalized.as_str();
    if value.starts_with(r"\\?\") {
        return Ok(absolute);
    }
    if let Some(unc) = value.strip_prefix(r"\\") {
        return Ok(PathBuf::from(OsString::from(format!(r"\\?\UNC\{unc}"))));
    }
    Ok(PathBuf::from(OsString::from(format!(r"\\?\{value}"))))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<DurabilityGuarantee, String> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("No se pudo sincronizar {}: {error}", path.display()))?;
    Ok(DurabilityGuarantee::PosixDirectorySynced)
}

#[cfg(windows)]
fn sync_parent_directory(_path: &Path) -> Result<DurabilityGuarantee, String> {
    // Windows no ofrece una barrera portable de directorio equivalente a fsync(2).
    // publish_path usa MOVEFILE_WRITE_THROUGH y esta garantia se informa sin
    // equipararla a un fsync de directorio POSIX.
    Ok(DurabilityGuarantee::WindowsWriteThrough)
}
