//! Library layers: user-named subdirectories of the central skills root
//! that group skills without changing per-agent deployment behavior.
//!
//! A layer is a depth-1 directory under [`central_repo::skills_dir`] that is
//! not itself a skill (no `SKILL.md`). A skill lives either at the root
//! (ungrouped) or inside exactly one layer; its metadata `path` (and DB
//! `central_path`) records the full relative location, e.g. `E470C/ppt-master`.
//!
//! Moving or renaming never touches Agent directories: deployed folder names
//! derive from the last path component only ([`super::sync_engine::
//! target_dir_name`]), so a layer rename is invisible to every tool. What it
//! does change is the git-backup tree layout — nested paths round-trip
//! through the metadata projection, which already supports multi-component
//! relative paths.
//!
//! Every mutating operation runs under the central repository lock and
//! performs the three steps that keep the app consistent (move the
//! directory, update the DB row, patch the metadata JSON) as one unit.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

use super::audit_log::AuditDraft;
use super::central_repo;
use super::repo_lock::RepoLock;
use super::scanner;
use super::skill_metadata;
use super::skill_store::SkillStore;

/// Directories that are never treated as layers (mirrors the scanner's skip
/// list plus the metadata namespace).
pub const RESERVED_LAYER_NAMES: &[&str] = &[
    ".hub",
    ".git",
    "node_modules",
    ".skills-manager",
];

pub const MAX_LAYER_NAME_LEN: usize = 64;

#[derive(Debug, Serialize)]
pub struct LibraryLayer {
    pub name: String,
    pub skill_count: usize,
}

#[derive(Debug, Serialize)]
pub struct SkillLayerAssignment {
    pub skill_id: String,
    pub skill_name: String,
    pub layer: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LibraryLayersOverview {
    pub layers: Vec<LibraryLayer>,
    pub assignments: Vec<SkillLayerAssignment>,
}

/// Validates and normalizes a layer name. Layer names are user-defined
/// display labels that double as directory names, so filesystem-hostile
/// characters, traversal, and reserved names are refused; CJK and spaces
/// are fine.
pub fn validate_layer_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        bail!("层名不能为空");
    }
    if trimmed.len() > MAX_LAYER_NAME_LEN {
        bail!("层名过长（最多 {MAX_LAYER_NAME_LEN} 个字符）");
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') {
        bail!("层名不能以点开头或结尾");
    }
    const FORBIDDEN: &[char] = &['/', '\\', ':', '*', '?', '"', '<', '>', '|'];
    if trimmed.chars().any(|c| FORBIDDEN.contains(&c) || c.is_control()) {
        bail!("层名不能包含以下字符：/ \\ : * ? \" < > |");
    }
    if trimmed.contains("..") {
        bail!("层名不能包含连续两个点");
    }
    if RESERVED_LAYER_NAMES.iter().any(|r| r.eq_ignore_ascii_case(trimmed)) {
        bail!("层名与系统保留目录名冲突：{trimmed}");
    }
    Ok(trimmed.to_string())
}

fn metadata_skill_json(skill_id: &str) -> PathBuf {
    central_repo::skills_dir()
        .join(".skills-manager")
        .join("skills")
        .join(format!("{skill_id}.json"))
}

/// Relative location of a skill inside the skills root (`name` or
/// `layer/name`). Mirrors sync_metadata's projection.
fn relative_location(central_path: &Path) -> Result<String> {
    let root = central_repo::skills_dir();
    let relative = central_path
        .strip_prefix(&root)
        .with_context(|| format!("技能路径超出技能库根目录：{}", central_path.display()))?;
    Ok(relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/"))
}

fn layer_of_location(location: &str) -> Option<String> {
    let (first, rest) = location.split_once('/')?;
    if rest.is_empty() {
        None
    } else {
        Some(first.to_string())
    }
}

/// Keeps the metadata JSON's `path` in step with the DB. The file can be
/// absent (fresh installs before the first backup projection); in that case
/// the next projection regenerates it from the DB, which is already updated.
fn patch_metadata_path(skill_id: &str, location: &str) -> Result<()> {
    let path = metadata_skill_json(skill_id);
    if !path.exists() {
        return Ok(());
    }
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("元数据文件损坏：{}", path.display()))?;
    value["path"] = serde_json::Value::String(location.to_string());
    std::fs::write(&path, serde_json::to_vec_pretty(&value)?)
        .with_context(|| format!("无法写入元数据：{}", path.display()))?;
    Ok(())
}

fn layer_dir(name: &str) -> PathBuf {
    central_repo::skills_dir().join(name)
}

fn dir_is_layer(dir: &Path) -> bool {
    dir.is_dir() && !skill_metadata::is_valid_skill_dir(dir)
}

/// Creates the layer directory. Idempotent for existing layers; refuses if
/// the name is taken by a root-level skill directory.
pub fn create_layer(store: &SkillStore, name: &str) -> Result<String> {
    let name = validate_layer_name(name)?;
    let _lock = RepoLock::acquire_foreground("create layer")?;
    let dir = layer_dir(&name);
    if dir.exists() {
        if skill_metadata::is_valid_skill_dir(&dir) {
            bail!("\"{name}\" 已是一个技能目录，不能作为层名");
        }
        return Ok(name); // layer already exists
    }
    std::fs::create_dir(&dir).with_context(|| format!("无法创建层目录 {}", dir.display()))?;
    store.log_audit(AuditDraft::new("library.layer_create").ok().detail(format!("layer {name}")));
    Ok(name)
}

/// Lists on-disk layers unioned with layer prefixes referenced by the DB.
/// Skill counts come from the store (the DB is what the UI shows).
pub fn overview(store: &SkillStore) -> Result<LibraryLayersOverview> {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut assignments = Vec::new();
    for skill in store.get_all_skills()? {
        let layer = relative_location(Path::new(&skill.central_path))
            .ok()
            .and_then(|location| layer_of_location(&location));
        if let Some(layer) = &layer {
            *counts.entry(layer.clone()).or_insert(0) += 1;
        }
        assignments.push(SkillLayerAssignment {
            skill_id: skill.id.clone(),
            skill_name: skill.name.clone(),
            layer,
        });
    }
    let root = central_repo::skills_dir();
    if let Ok(entries) = std::fs::read_dir(&root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !dir_is_layer(&entry.path()) || RESERVED_LAYER_NAMES.contains(&name.as_str()) {
                continue;
            }
            counts.entry(name).or_insert(0);
        }
    }
    let layers = counts
        .into_iter()
        .map(|(name, skill_count)| LibraryLayer { name, skill_count })
        .collect();
    Ok(LibraryLayersOverview { layers, assignments })
}

pub fn list_layers(store: &SkillStore) -> Result<Vec<LibraryLayer>> {
    Ok(overview(store)?.layers)
}

/// Moves a skill (its library directory) into `layer`, or to the root when
/// `layer` is `None`. The skill id, tags, preset membership, and deployment
/// records are preserved — only the location and its two records change.
/// Deployed copies in Agent directories are untouched: their folder names
/// derive from the last path component, which does not change.
pub fn move_skill_to_layer(store: &SkillStore, skill_id: &str, layer: Option<&str>) -> Result<()> {
    let _lock = RepoLock::acquire_foreground("move skill into layer")?;
    let record = store
        .get_skill_by_id(skill_id)?
        .ok_or_else(|| anyhow::anyhow!("技能不存在：{skill_id}"))?;
    let old = PathBuf::from(&record.central_path);
    if !old.is_dir() {
        bail!("技能目录不存在：{}", old.display());
    }
    let location = relative_location(&old)?;
    let current_layer = layer_of_location(&location);
    if current_layer.as_deref() == layer {
        bail!("技能已经在目标位置");
    }

    let name = old
        .file_name()
        .context("技能目录名缺失")?
        .to_string_lossy()
        .to_string();
    let (target, location) = match layer {
        Some(layer) => {
            let layer = validate_layer_name(layer)?;
            let dir = layer_dir(&layer);
            if !dir.exists() {
                std::fs::create_dir(&dir).with_context(|| format!("无法创建层目录 {}", dir.display()))?;
            }
            let target = dir.join(&name);
            let location = format!("{layer}/{name}");
            (target, location)
        }
        None => (central_repo::skills_dir().join(&name), name.clone()),
    };
    if target.exists() {
        bail!("目标位置已存在同名目录：{}", target.display());
    }

    std::fs::rename(&old, &target)
        .with_context(|| format!("移动目录失败：{} → {}", old.display(), target.display()))?;
    if let Err(err) = store.update_skill_central_path(skill_id, &target.to_string_lossy()) {
        let _ = std::fs::rename(&target, &old);
        return Err(err).context("数据库更新失败，已回滚目录移动");
    }
    if let Err(err) = patch_metadata_path(skill_id, &location) {
        let _ = std::fs::rename(&target, &old);
        let _ = store.update_skill_central_path(skill_id, &old.to_string_lossy());
        return Err(err).context("元数据更新失败，已回滚目录移动与数据库");
    }

    store.log_audit(
        AuditDraft::new("library.skill_move")
            .ok()
            .skill(skill_id, &name)
            .detail(format!("moved into layer {:?}", layer.unwrap_or_default())),
    );
    Ok(())
}

/// Renames a layer. All skills inside keep their ids and records; their
/// directories, DB paths, and metadata paths follow the rename.
pub fn rename_layer(store: &SkillStore, old: &str, new: &str) -> Result<String> {
    let new = validate_layer_name(new)?;
    let _lock = RepoLock::acquire_foreground("rename layer")?;
    validate_layer_name(old)?;
    if old == new {
        return Ok(new);
    }
    let old_dir = layer_dir(old);
    if !old_dir.is_dir() {
        bail!("层不存在：{old}");
    }
    let new_dir = layer_dir(&new);
    if new_dir.exists() {
        bail!("目标层已存在：{new}");
    }

    std::fs::rename(&old_dir, &new_dir)
        .with_context(|| format!("重命名目录失败：{} → {}", old_dir.display(), new_dir.display()))?;
    if let Err(err) = relocate_layer_members(store, old, |old_location| {
        old_location.replacen(&format!("{old}/"), &format!("{new}/"), 1)
    }) {
        let _ = std::fs::rename(&new_dir, &old_dir);
        return Err(err).context("更新层内技能失败，已回滚目录重命名");
    }
    store.log_audit(
        AuditDraft::new("library.layer_rename")
            .ok()
            .detail(format!("layer {old} → {new}")),
    );
    Ok(new)
}

/// Deletes a layer directory. Refuses while any skill (per DB or on disk)
/// still lives inside it.
pub fn delete_layer(store: &SkillStore, name: &str) -> Result<()> {
    let _lock = RepoLock::acquire_foreground("delete layer")?;
    let dir = layer_dir(name);
    if !dir.is_dir() {
        bail!("层不存在：{name}");
    }
    let occupied = store.get_all_skills()?.iter().any(|skill| {
        relative_location(Path::new(&skill.central_path))
            .map(|location| layer_of_location(&location).as_deref() == Some(name))
            .unwrap_or(false)
    }) || !scanner::collect_skill_dirs(&dir).is_empty();
    if occupied {
        bail!("层 {name} 内还有技能，清空后才能删除");
    }
    std::fs::remove_dir(&dir).with_context(|| format!("删除层目录失败：{}", dir.display()))?;
    store.log_audit(
        AuditDraft::new("library.layer_delete")
            .ok()
            .detail(format!("layer {name}")),
    );
    Ok(())
}

/// Rewrites every skill's location for a layer-level rename. `map_location`
/// receives the old relative location and returns the new one.
fn relocate_layer_members(
    store: &SkillStore,
    old: &str,
    map_location: impl Fn(&str) -> String,
) -> Result<()> {
    for skill in store.get_all_skills()? {
        let location = match relative_location(Path::new(&skill.central_path)) {
            Ok(location) => location,
            Err(_) => continue,
        };
        if layer_of_location(&location).as_deref() != Some(old) {
            continue;
        }
        let new_location = map_location(&location);
        let target = central_repo::skills_dir().join(&new_location);
        store.update_skill_central_path(&skill.id, &target.to_string_lossy())?;
        patch_metadata_path(&skill.id, &new_location)?;
    }
    Ok(())
}

/// Deploy-time collision guard: two skills whose library locations share the
/// same final directory name would deploy into the same Agent folder. With a
/// flat library that was impossible; with layers it is a legitimate setup
/// that needs an explicit decision, so deployment refuses with the
/// conflicting names instead of silently overwriting.
pub fn assert_no_target_name_conflicts(
    store: &SkillStore,
    tool: &str,
    skill_ids: &[String],
) -> Result<()> {
    use std::collections::BTreeMap;
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in skill_ids {
        let record = store
            .get_skill_by_id(id)?
            .ok_or_else(|| anyhow::anyhow!("技能不存在：{id}"))?;
        let name = Path::new(&record.central_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        by_name.entry(name).or_default().push(record.name);
    }
    for (name, skills) in by_name {
        if skills.len() > 1 {
            bail!(
                "部署冲突：以下技能都会部署为 Agent 目录 \"{name}\"（工具 {tool}），\
                 请先把其中一些移到其他层或重命名：{}",
                skills.join("、")
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::central_repo;
    use tempfile::tempdir;

    struct TestEnv {
        _lock: std::sync::MutexGuard<'static, ()>,
        _tmp: tempfile::TempDir,
        store: SkillStore,
    }

    impl TestEnv {
        fn new() -> Self {
            let lock = central_repo::test_base_dir_lock();
            let tmp = tempdir().unwrap();
            let base = tmp.path().join("base");
            std::fs::create_dir_all(&base).unwrap();
            central_repo::set_test_base_dir_override(Some(base.clone()));
            let store = SkillStore::new(&base.join("test.db")).unwrap();
            TestEnv { _lock: lock, _tmp: tmp, store }
        }

        fn seed_skill(&self, id: &str, name: &str, location: Option<&str>) -> PathBuf {
            let dir = match location {
                Some(layer) => central_repo::skills_dir().join(layer).join(name),
                None => central_repo::skills_dir().join(name),
            };
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("SKILL.md"), format!("---\nname: {name}\n---\n")).unwrap();
            let metadata_location = match location {
                Some(layer) => format!("{layer}/{name}"),
                None => name.to_string(),
            };
            self.store
                .upsert_skill(&crate::core::skill_store::SkillRecord {
                    id: id.to_string(),
                    name: name.to_string(),
                    description: None,
                    source_type: "local".to_string(),
                    source_ref: None,
                    source_ref_resolved: None,
                    source_subpath: None,
                    source_branch: None,
                    source_revision: None,
                    remote_revision: None,
                    central_path: dir.to_string_lossy().to_string(),
                    content_hash: None,
                    enabled: true,
                    created_at: 0,
                    updated_at: 0,
                    status: "ok".to_string(),
                    update_status: "unknown".to_string(),
                    last_checked_at: None,
                    last_check_error: None,
                })
                .unwrap();
            self.write_metadata(id, &metadata_location, name);
            dir
        }

        fn write_metadata(&self, id: &str, location: &str, name: &str) {
            let dir = central_repo::skills_dir().join(".skills-manager").join("skills");
            std::fs::create_dir_all(&dir).unwrap();
            let value = serde_json::json!({
                "schema": 1, "id": id, "path": location, "enabled": true,
                "name": name, "source": {"source_type": "local"}
            });
            std::fs::write(
                dir.join(format!("{id}.json")),
                serde_json::to_vec_pretty(&value).unwrap(),
            )
            .unwrap();
        }

        fn metadata_path_of(&self, id: &str) -> String {
            let raw = std::fs::read(
                central_repo::skills_dir()
                    .join(".skills-manager")
                    .join("skills")
                    .join(format!("{id}.json")),
            )
            .unwrap();
            serde_json::from_slice::<serde_json::Value>(&raw).unwrap()["path"]
                .as_str()
                .unwrap()
                .to_string()
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            central_repo::set_test_base_dir_override(None);
        }
    }

    fn record(store: &SkillStore, id: &str) -> crate::core::skill_store::SkillRecord {
        store.get_skill_by_id(id).unwrap().unwrap()
    }

    #[test]
    fn layer_name_validation() {
        assert_eq!(validate_layer_name("  E470C ").unwrap(), "E470C");
        assert_eq!(validate_layer_name("本机技能").unwrap(), "本机技能");
        assert_eq!(validate_layer_name("work 2026").unwrap(), "work 2026");
        assert!(validate_layer_name("").is_err());
        assert!(validate_layer_name("a/b").is_err());
        assert!(validate_layer_name("a\\b").is_err());
        assert!(validate_layer_name("..").is_err());
        assert!(validate_layer_name(".hidden").is_err());
        assert!(validate_layer_name("name.").is_err());
        assert!(validate_layer_name("a..b").is_err());
        assert!(validate_layer_name(".skills-manager").is_err());
        assert!(validate_layer_name("NODE_MODULES").is_err());
        assert!(validate_layer_name(&"长".repeat(65)).is_err());
    }

    #[test]
    fn move_into_layer_updates_dir_db_and_metadata() {
        let env = TestEnv::new();
        let dir = env.seed_skill("s1", "demo", None);

        move_skill_to_layer(&env.store, "s1", Some("E470C")).unwrap();

        let moved = record(&env.store, "s1");
        assert!(moved.central_path.replace('/', "\\").contains("E470C\\demo")
            || moved.central_path.contains("E470C/demo"));
        assert!(Path::new(&moved.central_path).join("SKILL.md").is_file());
        assert!(!dir.join("SKILL.md").is_file(), "old location vacated");
        assert_eq!(env.metadata_path_of("s1"), "E470C/demo");
    }

    #[test]
    fn move_to_root_and_back_preserves_everything() {
        let env = TestEnv::new();
        env.seed_skill("s1", "demo", Some("E470C"));

        move_skill_to_layer(&env.store, "s1", None).unwrap();
        let at_root = record(&env.store, "s1");
        assert_eq!(env.metadata_path_of("s1"), "demo");
        assert!(at_root.central_path.ends_with("demo"));

        move_skill_to_layer(&env.store, "s1", Some("E470C")).unwrap();
        assert_eq!(env.metadata_path_of("s1"), "E470C/demo");
    }

    #[test]
    fn move_refuses_existing_target() {
        let env = TestEnv::new();
        env.seed_skill("s1", "demo", None);
        env.seed_skill("s2", "demo", Some("E470C"));

        let err = move_skill_to_layer(&env.store, "s1", Some("E470C")).unwrap_err();
        assert!(err.to_string().contains("同名"));
        // Both records untouched.
        assert!(record(&env.store, "s1").central_path.ends_with("demo"));
        assert!(record(&env.store, "s2").central_path.contains("E470C"));
    }

    #[test]
    fn move_noop_reports_already_there() {
        let env = TestEnv::new();
        env.seed_skill("s1", "demo", Some("E470C"));
        assert!(move_skill_to_layer(&env.store, "s1", Some("E470C")).is_err());
    }

    #[test]
    fn rename_layer_moves_all_members() {
        let env = TestEnv::new();
        env.seed_skill("s1", "demo", Some("E470C"));
        env.seed_skill("s2", "other", Some("E470C"));
        env.seed_skill("s3", "root-skill", None);

        let new_name = rename_layer(&env.store, "E470C", "笔记本").unwrap();
        assert_eq!(new_name, "笔记本");
        assert!(record(&env.store, "s1").central_path.contains("笔记本"));
        assert_eq!(env.metadata_path_of("s1"), "笔记本/demo");
        assert_eq!(env.metadata_path_of("s2"), "笔记本/other");
        // Root skill untouched.
        assert_eq!(env.metadata_path_of("s3"), "root-skill");
    }

    #[test]
    fn rename_refuses_existing_target_layer() {
        let env = TestEnv::new();
        env.seed_skill("s1", "demo", Some("E470C"));
        create_layer(&env.store, "工作").unwrap();
        assert!(rename_layer(&env.store, "E470C", "工作").is_err());
        // Rollback: member still readable at the old location.
        assert_eq!(env.metadata_path_of("s1"), "E470C/demo");
    }

    #[test]
    fn delete_layer_refuses_while_skills_inside() {
        let env = TestEnv::new();
        env.seed_skill("s1", "demo", Some("E470C"));
        assert!(delete_layer(&env.store, "E470C").is_err());

        move_skill_to_layer(&env.store, "s1", None).unwrap();
        delete_layer(&env.store, "E470C").unwrap();
        assert!(!layer_dir("E470C").exists());
    }

    #[test]
    fn overview_counts_assignments_and_layers() {
        let env = TestEnv::new();
        env.seed_skill("s1", "demo", Some("E470C"));
        env.seed_skill("s2", "demo2", None);
        create_layer(&env.store, "空层").unwrap();

        let overview = overview(&env.store).unwrap();
        let e470c = overview.layers.iter().find(|l| l.name == "E470C").unwrap();
        assert_eq!(e470c.skill_count, 1);
        assert!(overview.layers.iter().any(|l| l.name == "空层" && l.skill_count == 0));
        assert!(!overview.layers.iter().any(|l| l.name == "demo2"));
        let s1 = overview
            .assignments
            .iter()
            .find(|a| a.skill_id == "s1")
            .unwrap();
        assert_eq!(s1.layer.as_deref(), Some("E470C"));
        let s2 = overview
            .assignments
            .iter()
            .find(|a| a.skill_id == "s2")
            .unwrap();
        assert_eq!(s2.layer, None);
    }

    #[test]
    fn deploy_name_conflict_detected_across_layers() {
        let env = TestEnv::new();
        env.seed_skill("s1", "demo", None);
        env.seed_skill("s2", "demo", Some("E470C"));

        let ids = vec!["s1".to_string(), "s2".to_string()];
        let err = assert_no_target_name_conflicts(&env.store, "codex", &ids).unwrap_err();
        assert!(err.to_string().contains("部署冲突"));

        let ids = vec!["s1".to_string()];
        assert!(assert_no_target_name_conflicts(&env.store, "codex", &ids).is_ok());
    }
}
