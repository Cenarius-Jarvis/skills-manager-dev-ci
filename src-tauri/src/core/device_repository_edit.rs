//! Applying one published document to a tracked skill on the target device.
use anyhow::{bail, Context, Result};
use git2::{Oid, Repository};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use super::{
    central_repo, content_hash, device_signed_executor::authorized_agent_root, device_skill_mirror,
    devices, repo_lock::RepoLock, signed_channel::SignedCommandPayload, skill_metadata,
    skill_store::{SkillStore, SkillTargetRecord}, sync_engine::{self, ReplacePolicy},
};

/// A custom SSH alias is accepted only when local SSH configuration resolves
/// it to GitHub. Its repository path must still match the signed source.
fn normalized_origin(origin: &str) -> Option<String> {
    if let Some(url) = devices::github_https_url(origin) {
        return Some(url);
    }
    let (host, path) = origin.strip_prefix("git@")?.split_once(':')?;
    if host.starts_with('-') || !host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_')) {
        return None;
    }
    let output = std::process::Command::new("ssh").args(["-G", host]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let config = String::from_utf8(output.stdout).ok()?;
    let resolved = config.lines().find_map(|line| line.strip_prefix("hostname "))?;
    if !matches!(resolved, "github.com" | "ssh.github.com") {
        return None;
    }
    devices::github_https_url(&format!("https://github.com/{path}"))
}

fn install_document(path: &Path, bytes: &[u8], permissions: fs::Permissions) -> Result<()> {
    let mut staged = tempfile::NamedTempFile::new_in(path.parent().context("missing document directory")?)?;
    staged.write_all(bytes)?;
    staged.as_file().set_permissions(permissions)?;
    staged.as_file().sync_all()?;
    staged.persist(path)?;
    Ok(())
}

/// Return None for a source unrelated to this device's own library; the
/// standard managed Git deployment path handles that case.
pub fn apply(store: &SkillStore, payload: &SignedCommandPayload) -> Result<Option<PathBuf>> {
    let root = central_repo::skills_dir();
    let Ok(local) = Repository::open(&root) else { return Ok(None); };
    let Ok(origin) = local.find_remote("origin") else { return Ok(None); };
    let url = payload.skill_url.as_deref().context("repository edit has no source")?;
    let origin_url = origin.url().unwrap_or_default();
    let matches = origin_url == url || normalized_origin(origin_url)
        .zip(devices::github_https_url(url))
        .is_some_and(|(from, to)| from.eq_ignore_ascii_case(&to));
    if !matches { return Ok(None); }

    let _lock = RepoLock::acquire_foreground("apply published repository skill edit")?;
    let subpath = payload.skill_subpath.as_deref().unwrap_or(".");
    let directory = if subpath == "." { root.clone() } else { root.join(subpath) };
    let skill = store.get_skill_by_central_path(&directory.to_string_lossy())?
        .context("published path is not a registered skill in this device library")?;
    let central = directory.canonicalize()?;
    let root_canonical = root.canonicalize()?;
    if central != root_canonical.join(if subpath == "." { "" } else { subpath }) {
        bail!("published skill path traverses a link");
    }
    let document = central.join("SKILL.md");
    let metadata = fs::symlink_metadata(&document)?;
    if !metadata.is_file() { bail!("tracked SKILL.md must be a regular file"); }
    let GitAgentTargets { existing, selected } = agent_targets(store, payload, &skill.id, &central)?;

    let (_tmp, checkout) = devices::fetch_skill_source(url, payload.skill_branch.as_deref())?;
    let fetched = Repository::open(checkout)?;
    let tip = fetched.head()?.peel_to_commit()?.id();
    let revision = Oid::from_str(payload.skill_commit.as_deref().context("repository edit has no pinned commit")?)?;
    if tip != revision && !fetched.graph_descendant_of(tip, revision)? {
        bail!("pinned commit is not on the configured skill branch");
    }
    let commit = fetched.find_commit(revision)?;
    if commit.parent_count() != 1 { bail!("repository edit must have exactly one parent"); }
    let parent = commit.parent(0)?;
    let old = device_skill_mirror::document_blob(&fetched, &parent, subpath)?;
    let new = device_skill_mirror::document_blob(&fetched, &commit, subpath)?;
    let manifest = if subpath == "." { PathBuf::from("SKILL.md") } else { Path::new(subpath).join("SKILL.md") };
    let old_tree = parent.tree()?;
    let new_tree = commit.tree()?;
    let diff = fetched.diff_tree_to_tree(Some(&old_tree), Some(&new_tree), None)?;
    if diff.deltas().len() != 1 || diff.deltas().any(|delta|
        delta.old_file().path() != Some(manifest.as_path()) || delta.new_file().path() != Some(manifest.as_path())) {
        bail!("the published commit changes files outside the selected SKILL.md");
    }
    let tracked = local.head()?.peel_to_tree()?.get_path(&manifest)?;
    if !matches!(tracked.filemode(), 0o100644 | 0o100755) {
        bail!("the destination Git library does not track a regular SKILL.md");
    }
    let current = fs::read(&document)?;
    if current != old && current != new {
        bail!("SKILL.md was modified locally or the device is at a different repository revision");
    }
    let published = std::str::from_utf8(&new)?;
    let permissions = metadata.permissions();
    if current != new {
        install_document(&document, &new, permissions.clone())?;
    }

    let result = (|| -> Result<()> {
        let hash = content_hash::hash_directory(&central)?;
        let description = skill_metadata::parse_frontmatter(published).description;
        if let Some(path) = selected.as_ref() {
            let actual = sync_engine::sync_skill(&central, path, sync_engine::SyncMode::Symlink, ReplacePolicy::NoClobber)?;
            if let Err(err) = store.insert_target(&SkillTargetRecord {
                id: uuid::Uuid::new_v4().to_string(), skill_id: skill.id.clone(),
                tool: payload.agent_key.clone(), target_path: path.to_string_lossy().into_owned(),
                mode: actual.as_str().into(), status: "ok".into(), synced_at: Some(chrono::Utc::now().timestamp_millis()),
                source_hash: Some(hash.clone()), last_error: None,
            }) {
                sync_engine::remove_target(path)?;
                return Err(err);
            }
        }
        store.with_conn_mut(|conn| {
            let tx = conn.transaction()?;
            let now = chrono::Utc::now().timestamp_millis();
            tx.execute("UPDATE skills SET description=?2,content_hash=?3,updated_at=?4 WHERE id=?1",
                rusqlite::params![skill.id, description, hash, now])?;
            tx.execute("UPDATE skill_targets SET source_hash=?2,synced_at=?3 WHERE skill_id=?1",
                rusqlite::params![skill.id, hash, now])?;
            tx.commit()?;
            Ok(())
        })
    })();
    if let Err(err) = result {
        if current != new { install_document(&document, &current, permissions)?; }
        return Err(err);
    }
    Ok(Some(selected.or(existing).context("target deployment missing")?))
}

struct GitAgentTargets {
    existing: Option<PathBuf>,
    selected: Option<PathBuf>,
}

fn agent_targets(store: &SkillStore, payload: &SignedCommandPayload, skill_id: &str, central: &Path) -> Result<GitAgentTargets> {
    let agent_root = authorized_agent_root(store, &payload.agent_key)?
        .context("agent is not authorized on this device")?;
    let agent_root = agent_root.canonicalize().context("authorized agent directory is unavailable")?;
    let mut existing = None;
    for row in store.get_targets_for_skill(skill_id)? {
        let path = PathBuf::from(&row.target_path);
        if !path.symlink_metadata()?.file_type().is_symlink() || path.canonicalize()? != central {
            bail!("existing deployment is not a verified link to this library skill");
        }
        if row.tool == payload.agent_key {
            if path.parent().and_then(|p| p.canonicalize().ok()).as_deref() != Some(agent_root.as_path()) {
                bail!("existing deployment is outside the authorized agent directory");
            }
            existing = Some(path);
        }
    }
    let selected = match &existing {
        Some(_) => None,
        None => {
            let name = payload.skill_name.as_deref().context("repository edit has no skill name")?;
            devices::validate_skill_name(name)?;
            let path = agent_root.join(name);
            match path.symlink_metadata() {
                Ok(_) => bail!("existing agent path is not managed for this skill"),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            Some(path)
        }
    };
    Ok(GitAgentTargets { existing, selected })
}
