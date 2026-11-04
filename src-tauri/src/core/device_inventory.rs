//! Explicitly local, read-only inspection; does not open the library database,
//! publish channel data, or execute deployment requests.
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct Inventory {
    pub skills: Vec<InventorySkill>,
    pub warnings: Vec<String>,
    pub complete: bool,
}

#[derive(Debug, Serialize)]
pub struct InventorySkill {
    pub name: String,
    pub symlink: bool,
}

/// Windows junctions and other reparse points must obey the same allowlist
/// as symlinks even when Rust reports their file type as a directory.
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_type().is_symlink()
            || (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Inspect one explicitly selected agent directory. Directory links are only
/// followed into explicitly allowed roots; no file contents are read.
pub fn inspect(agent_dir: &Path, allowed_roots: &[PathBuf]) -> Inventory {
    let mut report = Inventory { skills: Vec::new(), warnings: Vec::new(), complete: true };
    let mut roots = Vec::new();
    for root in allowed_roots {
        match fs::canonicalize(root) {
            Ok(root) if root.is_dir() => roots.push(root),
            _ => {
                report.complete = false;
                report.warnings.push("an allowed root is unavailable".into());
            }
        }
    }
    let entries = match fs::read_dir(agent_dir) {
        Ok(entries) => entries,
        Err(_) => {
            report.complete = false;
            report.warnings.push("agent directory is unavailable".into());
            return report;
        }
    };
    for item in entries {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                report.complete = false;
                report.warnings.push("an agent entry could not be read".into());
                continue;
            }
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                report.complete = false;
                report.warnings.push("an agent entry name is not UTF-8".into());
                continue;
            }
        };
        let ty = match entry.file_type() {
            Ok(ty) => ty,
            Err(_) => {
                report.complete = false;
                report.warnings.push(format!("{name}: entry type unavailable"));
                continue;
            }
        };
        let path = entry.path();
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                report.complete = false;
                report.warnings.push(format!("{name}: entry metadata unavailable"));
                continue;
            }
        };
        let linked = is_link_or_reparse(&metadata);
        if !ty.is_dir() && !linked {
            continue;
        }
        let resolved = match fs::canonicalize(&path) {
            Ok(resolved) => resolved,
            Err(_) => {
                report.complete = false;
                report.warnings.push(format!("{name}: link or directory unavailable"));
                continue;
            }
        };
        if linked && !roots.iter().any(|root| resolved.starts_with(root)) {
            report.complete = false;
            report.warnings.push(format!("{name}: link target outside allowed roots"));
            continue;
        }
        if !resolved.is_dir() {
            if linked {
                report.complete = false;
                report.warnings.push(format!("{name}: link target is not a directory"));
            }
            continue;
        }
        let skill_file = resolved.join("SKILL.md");
        match fs::symlink_metadata(&skill_file) {
            Ok(meta) if is_link_or_reparse(&meta) => {
                report.complete = false;
                report.warnings.push(format!("{name}: SKILL.md is a link and was skipped"));
            }
            Ok(meta) if meta.file_type().is_file() => report.skills.push(InventorySkill {
                name,
                symlink: linked,
            }),
            Ok(_) => {},
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {},
            Err(_) => {
                report.complete = false;
                report.warnings.push(format!("{name}: SKILL.md could not be inspected"));
            }
        }
    }
    report.skills.sort_by(|a, b| a.name.cmp(&b.name));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_inventory_reports_direct_skill_and_missing_directory() {
        let temp = tempfile::tempdir().unwrap();
        let agent = temp.path().join("agent");
        fs::create_dir_all(agent.join("demo")).unwrap();
        fs::write(agent.join("demo/SKILL.md"), "test").unwrap();
        fs::create_dir_all(agent.join("not-a-skill")).unwrap();
        let result = inspect(&agent, &[]);
        assert!(result.complete);
        assert_eq!(result.skills.len(), 1);
        assert_eq!(result.skills[0].name, "demo");
        assert!(!result.skills[0].symlink);
        assert!(!inspect(&temp.path().join("missing"), &[]).complete);
    }

    #[cfg(unix)]
    #[test]
    fn device_inventory_only_follows_explicitly_allowed_directory_links() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let agent = temp.path().join("agent");
        let library = temp.path().join("library");
        let foreign = temp.path().join("foreign");
        fs::create_dir_all(&agent).unwrap();
        fs::create_dir_all(library.join("skill")).unwrap();
        fs::create_dir_all(&foreign).unwrap();
        fs::write(library.join("skill/SKILL.md"), "test").unwrap();
        fs::write(foreign.join("SKILL.md"), "private").unwrap();
        symlink(library.join("skill"), agent.join("approved")).unwrap();
        symlink(&foreign, agent.join("outside")).unwrap();
        symlink(temp.path().join("missing"), agent.join("broken")).unwrap();
        let result = inspect(&agent, &[library]);
        assert!(!result.complete);
        assert_eq!(result.skills.len(), 1);
        assert_eq!(result.skills[0].name, "approved");
        assert!(result.skills[0].symlink);
        assert_eq!(result.warnings.len(), 2);
        assert_eq!(fs::read_to_string(foreign.join("SKILL.md")).unwrap(), "private");
    }
    #[cfg(windows)]
    #[test]
    fn device_inventory_windows_junctions_require_allowed_root() {
        let temp = tempfile::tempdir().unwrap();
        let agent = temp.path().join("agent");
        let library = temp.path().join("library");
        let foreign = temp.path().join("foreign");
        fs::create_dir_all(&agent).unwrap();
        fs::create_dir_all(library.join("skill")).unwrap();
        fs::create_dir_all(&foreign).unwrap();
        fs::write(library.join("skill/SKILL.md"), "test").unwrap();
        fs::write(foreign.join("SKILL.md"), "private").unwrap();
        junction::create(library.join("skill"), agent.join("approved")).unwrap();
        junction::create(&foreign, agent.join("outside")).unwrap();
        let denied = inspect(&agent, &[]);
        assert!(!denied.complete);
        assert!(denied.skills.is_empty());
        assert_eq!(denied.warnings.len(), 2);
        let result = inspect(&agent, &[library]);
        assert!(!result.complete);
        assert_eq!(result.skills.len(), 1);
        assert_eq!(result.skills[0].name, "approved");
        assert!(result.skills[0].symlink);
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(fs::read_to_string(foreign.join("SKILL.md")).unwrap(), "private");

        let vanished = temp.path().join("vanished");
        fs::create_dir_all(&vanished).unwrap();
        junction::create(&vanished, agent.join("broken")).unwrap();
        fs::remove_dir(&vanished).unwrap();
        let broken = inspect(&agent, &[]);
        assert!(!broken.complete);
        assert!(broken.skills.is_empty());
        assert!(broken.warnings.iter().any(|warning| warning.contains("broken")));

    }

}
