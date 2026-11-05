//! Experimental native deployment prototype. Compiled only for isolated tests.
//! It accepts an already managed skill and a separately approved, empty target.
//! It does not install, update, remove, publish receipts, or consume commands.
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

use super::{
    central_repo, content_hash, devices,
    repo_lock::RepoLock,
    skill_store::{SkillStore, SkillTargetRecord},
    sync_engine::{self, ReplacePolicy},
    sync_metadata,
};

/// Check every entry without following links. The existing copy fallback in
/// sync_engine follows file links, so this guard is mandatory before using it.
/// This remains subject to filesystem races from processes outside RepoLock.
fn reject_linked_or_special_sources(root: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.context("cannot inspect complete source tree")?;
        let metadata = std::fs::symlink_metadata(entry.path())?;
        let ft = metadata.file_type();
        #[cfg(windows)]
        let reparse = {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes() & 0x400 != 0
        };
        #[cfg(not(windows))]
        let reparse = false;
        if ft.is_symlink() || reparse || (!ft.is_dir() && !ft.is_file()) {
            bail!("source contains a link, reparse point or special file");
        }
    }
    Ok(())
}

/// Deploy exactly one existing central-library skill to an explicitly mapped,
/// currently empty agent slot. Existing targets and records are never adopted.
/// Failure after filesystem creation preserves evidence and refuses retry:
/// an operator must reconcile it, rather than assuming rollback succeeded.
pub(crate) fn deploy_new_slot(
    store: &SkillStore,
    skill_id: &str,
    agent_key: &str,
    approved_agent_root: &Path,
) -> Result<PathBuf> {
    devices::validate_agent_key(agent_key)?;
    let _lock = RepoLock::acquire_foreground("experimental native device deploy")?;
    let skill = store.get_skill_by_id(skill_id)?
        .ok_or_else(|| anyhow!("managed skill not found"))?;
    if !skill.enabled { bail!("managed skill is disabled"); }

    let library = std::fs::canonicalize(central_repo::skills_dir())
        .context("central library is unavailable")?;
    let source = std::fs::canonicalize(&skill.central_path)
        .context("managed skill directory is unavailable")?;
    if !source.starts_with(&library) || source == library || !source.is_dir() {
        bail!("managed skill is outside the central library");
    }
    let manifest = std::fs::symlink_metadata(source.join("SKILL.md"))
        .context("skill manifest is unavailable")?;
    if !manifest.file_type().is_file() || manifest.file_type().is_symlink() {
        bail!("skill manifest must be an ordinary file");
    }
    reject_linked_or_special_sources(&source)?;
    let source_hash = content_hash::hash_directory(&source)?;
    if skill.content_hash.as_deref() != Some(source_hash.as_str()) {
        bail!("managed library content changed since the recorded hash");
    }

    let root = std::fs::canonicalize(approved_agent_root)
        .context("approved agent directory is unavailable")?;
    if !root.is_dir() { bail!("approved agent root is not a directory"); }
    let name = sync_engine::target_dir_name(&source, &skill.name);
    let name_path = Path::new(&name);
    if name_path.components().count() != 1
        || !matches!(name_path.components().next(), Some(std::path::Component::Normal(_)))
    { bail!("invalid target name"); }
    let target = root.join(name_path);
    match std::fs::symlink_metadata(&target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("target already exists; refusing adoption or overwrite"),
        Err(e) => return Err(e).context("target cannot be inspected"),
    }
    let records = store.get_all_targets()?;
    if records.iter().any(|row| (row.skill_id == skill.id && row.tool == agent_key)
        || Path::new(&row.target_path) == target) {
        bail!("a deployment record already claims this slot");
    }

    let configured_mode = store.get_setting("sync_mode")?;
    let mode = sync_engine::sync_mode_for_tool(agent_key, configured_mode.as_deref());
    let actual = sync_engine::sync_skill(&source, &target, mode, ReplacePolicy::NoClobber)?;
    let verified = match actual {
        sync_engine::SyncMode::Symlink => {
            std::fs::canonicalize(&target).ok().as_deref() == Some(source.as_path())
        }
        sync_engine::SyncMode::Copy => {
            reject_linked_or_special_sources(&target).is_ok()
                && content_hash::list_content_files_strict(&target).is_ok()
                && content_hash::hash_directory(&target).ok().as_deref() == Some(source_hash.as_str())
        }
    };
    if !verified {
        bail!("created target could not be verified; target preserved for manual recovery");
    }
    // Detect a central edit during the filesystem operation, before recording.
    reject_linked_or_special_sources(&source)?;
    if content_hash::hash_directory(&source)? != source_hash {
        bail!("central source changed during deployment; target preserved for manual recovery");
    }
    let row = SkillTargetRecord {
        id: uuid::Uuid::new_v4().to_string(),
        skill_id: skill.id.clone(),
        tool: agent_key.to_string(),
        target_path: target.to_string_lossy().to_string(),
        mode: actual.as_str().to_string(),
        status: "ok".to_string(),
        synced_at: Some(chrono::Utc::now().timestamp_millis()),
        last_error: None,
        source_hash: Some(source_hash),
    };
    store.insert_target(&row).context("deployment record failed; target preserved for manual recovery")?;
    let verified_rows = store.get_targets_for_skill(&skill.id)?;
    if !verified_rows.iter().any(|saved| saved.tool == row.tool
        && saved.target_path == row.target_path && saved.mode == row.mode) {
        bail!("deployment record could not be verified; target preserved for manual recovery");
    }
    sync_metadata::write_all_from_db_unlocked(store)
        .context("metadata publication failed; target and database record preserved for recovery")?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::skill_store::SkillRecord;
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        base: PathBuf,
        agent: PathBuf,
        source: PathBuf,
        db: PathBuf,
        store: SkillStore,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("manager");
            let source = base.join("skills").join("sample");
            let agent = dir.path().join("fake-agent");
            std::fs::create_dir_all(&source).unwrap();
            std::fs::create_dir_all(&agent).unwrap();
            std::fs::write(source.join("SKILL.md"), "# sample").unwrap();
            central_repo::set_test_base_dir_override(Some(base.clone()));
            let db = base.join("skills-manager.db");
            let store = SkillStore::new(&db).unwrap();
            let hash = content_hash::hash_directory(&source).unwrap();
            store.insert_skill(&SkillRecord {
                id: "fixture-skill".into(), name: "sample".into(), description: None,
                source_type: "git".into(), source_ref: Some("https://example.invalid/repo.git".into()),
                source_ref_resolved: None, source_subpath: None, source_branch: None,
                source_revision: None, remote_revision: None,
                central_path: source.to_string_lossy().into_owned(), content_hash: Some(hash),
                enabled: true, created_at: 1, updated_at: 1, status: "ok".into(),
                update_status: "up_to_date".into(), last_checked_at: None, last_check_error: None,
            }).unwrap();
            Self { _dir: dir, base, agent, source, db, store }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { central_repo::set_test_base_dir_override(None); }
    }

    #[test]
    fn native_deploy_creates_a_visible_target_record() {
        let _guard = central_repo::test_base_dir_lock();
        let f = Fixture::new();
        let target = deploy_new_slot(&f.store, "fixture-skill", "codex", &f.agent).unwrap();
        assert_eq!(std::fs::read_to_string(target.join("SKILL.md")).unwrap(), "# sample");
        let rows = f.store.get_targets_for_skill("fixture-skill").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].tool, "codex");
        assert_eq!(Path::new(&rows[0].target_path), target);
        assert!(f.store.get_skill_by_id("fixture-skill").unwrap().is_some());
        assert_eq!(std::fs::read_to_string(f.source.join("SKILL.md")).unwrap(), "# sample");
    }

    #[test]
    fn native_deploy_refuses_existing_foreign_target() {
        let _guard = central_repo::test_base_dir_lock();
        let f = Fixture::new();
        let target = f.agent.join("sample");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("SKILL.md"), "foreign").unwrap();
        assert!(deploy_new_slot(&f.store, "fixture-skill", "codex", &f.agent).is_err());
        assert_eq!(std::fs::read_to_string(target.join("SKILL.md")).unwrap(), "foreign");
        assert!(f.store.get_targets_for_skill("fixture-skill").unwrap().is_empty());
    }

    #[test]
    fn native_deploy_preserves_target_when_record_insert_fails() {
        let _guard = central_repo::test_base_dir_lock();
        let f = Fixture::new();
        let conn = rusqlite::Connection::open(&f.db).unwrap();
        conn.execute_batch("CREATE TRIGGER fail_fixture_target BEFORE INSERT ON skill_targets BEGIN SELECT RAISE(FAIL, 'fixture failure'); END;").unwrap();
        let error = deploy_new_slot(&f.store, "fixture-skill", "codex", &f.agent).unwrap_err();
        assert!(format!("{error:#}").contains("target preserved"));
        assert_eq!(std::fs::read_to_string(f.agent.join("sample").join("SKILL.md")).unwrap(), "# sample");
        assert!(f.store.get_targets_for_skill("fixture-skill").unwrap().is_empty());
        assert!(deploy_new_slot(&f.store, "fixture-skill", "codex", &f.agent).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn native_deploy_refuses_link_in_source() {
        let _guard = central_repo::test_base_dir_lock();
        let f = Fixture::new();
        std::os::unix::fs::symlink(&f.base, f.source.join("foreign")).unwrap();
        assert!(deploy_new_slot(&f.store, "fixture-skill", "codex", &f.agent).is_err());
        assert_eq!(std::fs::read_dir(&f.agent).unwrap().count(), 0);
    }
    #[cfg(windows)]
    #[test]
    fn native_deploy_refuses_junction_in_source() {
        let _guard = central_repo::test_base_dir_lock();
        let f = Fixture::new();
        junction::create(&f.base, f.source.join("foreign")).unwrap();
        assert!(deploy_new_slot(&f.store, "fixture-skill", "codex", &f.agent).is_err());
        assert_eq!(std::fs::read_dir(&f.agent).unwrap().count(), 0);
    }
}
