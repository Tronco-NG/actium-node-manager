use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub fn path_identity(path: &Path) -> String {
    let value = path.to_string_lossy().replace('/', "\\");
    if cfg!(target_os = "windows") {
        value.to_lowercase()
    } else {
        value
    }
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("La ruta de seguridad debe ser absoluta.".to_string());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err("La ruta intenta escapar de la raiz del sistema.".to_string());
                }
            }
        }
    }
    Ok(normalized)
}

pub fn resolve_for_boundary(path: &Path) -> Result<PathBuf, String> {
    let normalized = lexical_absolute(path)?;
    let mut existing = normalized.as_path();
    let mut missing = Vec::new();
    while !existing.exists() {
        let name = existing
            .file_name()
            .ok_or_else(|| format!("No se pudo resolver la ruta {}.", path.display()))?;
        missing.push(name.to_os_string());
        existing = existing
            .parent()
            .ok_or_else(|| format!("No se pudo resolver la ruta {}.", path.display()))?;
    }
    let mut resolved = fs::canonicalize(existing).map_err(|error| {
        format!(
            "No se pudo canonicalizar el limite existente {}: {error}",
            existing.display()
        )
    })?;
    for name in missing.iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

pub fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = path_identity(path);
    let root = path_identity(root).trim_end_matches('\\').to_string();
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|remainder| remainder.starts_with('\\'))
}

pub fn validated_descendant(path: &Path, root: &Path) -> Result<PathBuf, String> {
    let path = resolve_for_boundary(path)?;
    let root = resolve_for_boundary(root)?;
    if path_identity(&path) == path_identity(&root) || !path_is_within(&path, &root) {
        return Err(format!(
            "La ruta {} queda fuera de la raiz autorizada {}.",
            path.display(),
            root.display()
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::validated_descendant;
    use std::path::Path;

    #[test]
    fn rechaza_traversal_fuera_de_la_raiz_autorizada() {
        let root = std::env::temp_dir().join("actium-node-manager-boundary");
        let escaped = root.join("node").join("..").join("..").join("outside");
        assert!(validated_descendant(&escaped, &root).is_err());
    }

    #[test]
    fn acepta_descendiente_aunque_aun_no_exista() {
        let root = std::env::temp_dir().join("actium-node-manager-boundary");
        let node = root.join("nodes").join("actium-lab-node-01");
        let validated = validated_descendant(&node, &root).expect("ruta Lab valida");
        assert!(validated.ends_with(Path::new("nodes").join("actium-lab-node-01")));
    }
}
