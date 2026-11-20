use std::sync::Arc;
use anyhow::{bail, Context, Result};
use git2::Oid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::State;
use crate::core::{
    device_identity, device_skill_mirror as mirror,
    devices, signed_channel, skill_store::SkillStore,
};
use crate::core::device_skill_mirror::{Draft, MirrorSnapshot};

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(work).await
        .map_err(|_| "device repository operation did not finish".to_string())?
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn device_skill_mirror_list(store: State<'_, Arc<SkillStore>>, device_id: String, source_id: String) -> Result<MirrorSnapshot, String> {
    let store = store.inner().clone();
    blocking(move || mirror::list(&mirror::bound_source(&store, &device_id, &source_id)?)).await
}

#[tauri::command]
pub async fn device_skill_mirror_refresh(store: State<'_, Arc<SkillStore>>, device_id: String, source_id: String) -> Result<MirrorSnapshot, String> {
    let store = store.inner().clone();
    blocking(move || mirror::refresh(&mirror::bound_source(&store, &device_id, &source_id)?)).await
}

#[tauri::command]
pub async fn device_skill_mirror_read(store: State<'_, Arc<SkillStore>>, device_id: String, source_id: String, skill_path: String) -> Result<Draft, String> {
    let store = store.inner().clone();
    blocking(move || mirror::read(&mirror::bound_source(&store, &device_id, &source_id)?, &skill_path)).await
}

#[tauri::command]
pub async fn device_skill_mirror_save(store: State<'_, Arc<SkillStore>>, device_id: String, source_id: String, skill_path: String, base_commit: String, content: String) -> Result<Draft, String> {
    let store = store.inner().clone();
    blocking(move || mirror::save(&mirror::bound_source(&store, &device_id, &source_id)?, &skill_path, &base_commit, content)).await
}

#[derive(Serialize)]
pub struct PublishResult {
    commit: String,
    queued: bool,
    instruction_id: Option<String>,
    message: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PendingPublication {
    base: String,
    content_hash: String,
    revision: String,
    channel_scope: String,
    message: signed_channel::SignedChannelMessage,
}

fn skill_key(name: &str, path: &str) -> String {
    if devices::validate_skill_name(name).is_ok() {
        return name.to_string();
    }
    let leaf = path.rsplit('/').next().unwrap_or(path);
    if devices::validate_skill_name(leaf).is_ok() {
        return leaf.to_string();
    }
    format!("skill-{}", &hex::encode(Sha256::digest(path.as_bytes()))[..12])
}

fn publish(store: &SkillStore, device: &str, id: &str, path: &str, agent: &str) -> Result<PublishResult> {
    devices::validate_agent_key(agent)?;
    let source = mirror::bound_source(store, device, id)?;
    let _lock = mirror::lock(&source)?;
    let identity = device_identity::load_existing_identity(store)?;
    if identity.device_id == device {
        bail!("select a paired remote device");
    }
    let paired = store.with_conn(|conn| {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM device_trusted_keys_v1 WHERE device_id=?1 AND purpose=?2 AND active=1)",
            rusqlite::params![device, "receipt"], |row| row.get::<_, bool>(0),
        )?)
    })?;
    if !paired {
        bail!("pair with this device before publishing");
    }
    let channel = devices::channel_url(store).context("configure the device channel first")?;
    let channel_branch = devices::channel_branch(store);
    let scope = crate::core::device_receipts::channel_scope(&channel, &channel_branch);
    let skill_url = devices::github_https_url(&source.url).unwrap_or_else(|| source.url.clone());
    devices::validate_skill_url(Some(&skill_url))?;
    let draft = mirror::read(&source, path)?;
    if !draft.has_draft {
        bail!("save a draft before publishing");
    }
    let pending_path = mirror::draft_file(&source, path).with_extension("publication.json");
    let hash = hex::encode(Sha256::digest(draft.content.as_bytes()));
    let (repo, tip) = mirror::fetch(&source)?;

    let pending = match mirror::load_json::<PendingPublication>(&pending_path)? {
        Some(saved) => {
            if saved.base != draft.head_commit || saved.content_hash != hash || saved.channel_scope != scope {
                bail!("a previous publication for this skill is pending in a different state");
            }
            let payload: signed_channel::SignedCommandPayload = serde_json::from_str(&saved.message.payload_json)?;
            if payload.agent_key != agent || payload.target_device != device {
                bail!("retry this publication with the original target agent");
            }
            saved
        }
        None => {
            if tip.to_string() != draft.head_commit {
                bail!("repository has newer changes; keep the draft and review against the current revision");
            }
            let base = repo.find_commit(tip)?;
            if mirror::document_blob(&repo, &base, path)? == draft.content.as_bytes() {
                bail!("the draft has no changes to publish");
            }
            let snapshot = mirror::list(&source)?;
            let skill = snapshot.skills.iter().find(|s| s.path == path).context("skill is no longer in the cache")?;
            let tree = repo.find_tree(mirror::edited_document_tree(&repo, &base.tree()?, path, draft.content.as_bytes())?)?;
            let author_name = devices::local_device_name(store);
            let signature = git2::Signature::now(&author_name, "skills-manager@users.noreply.github.com")?;
            let revision = repo.commit(None, &signature, &signature, "Update skill documentation from Skills Manager", &tree, &[&base])?.to_string();
            let payload = signed_channel::SignedCommandPayload {
                schema: signed_channel::SIGNED_COMMAND_SCHEMA,
                action: devices::ACTION_APPLY_REPOSITORY_EDIT.into(),
                skill_url: Some(skill_url), skill_branch: Some(source.branch.clone()),
                skill_subpath: (path != ".").then(|| path.to_string()),
                skill_commit: Some(revision.clone()), skill_name: Some(skill_key(&skill.name, path)), agent_key: agent.into(),
                issued_by: identity.device_id.clone(), issued_by_name: Some(author_name), target_device: device.into(),
            };
            let message = signed_channel::create_signed_command(&identity, device, &payload, chrono::Utc::now().timestamp(), signed_channel::DEFAULT_COMMAND_TTL_SECS)?;
            let pending = PendingPublication { base: draft.head_commit, content_hash: hash, revision, channel_scope: scope, message };
            mirror::write_json(&pending_path, &pending)?;
            pending
        }
    };

    let revision = Oid::from_str(&pending.revision)?;
    if tip.to_string() == pending.base {
        let refspec = format!("{revision}:refs/heads/{}", source.branch);
        mirror::network_git(&repo, &source, &["-c", "core.hooksPath=/dev/null", "push", "--", &source.url, &refspec])?;
    } else if tip != revision {
        bail!("the repository branch moved before this update could be queued");
    }

    let payload: signed_channel::SignedCommandPayload = serde_json::from_str(&pending.message.payload_json)?;
    let id = pending.message.envelope.message_id.clone();
    let row = super::devices::publish_prepared_signed_instruction(&store, &channel, &channel_branch, &payload, &pending.message);
    match row {
        Ok(_) => {
            if mirror::save_snapshot(&source, &repo, revision).is_ok() {
                std::fs::remove_file(mirror::draft_file(&source, path))?;
                std::fs::remove_file(pending_path)?;
            }
            Ok(PublishResult { commit: pending.revision, queued: true, instruction_id: Some(id), message: None })
        }
        Err(err) => {
            log::warn!("skill commit was pushed but device request is pending: {err}");
            Ok(PublishResult { commit: pending.revision, queued: false, instruction_id: None,
                message: Some("Git commit published. Retry this draft with the same agent to send the device request.".into()) })
        }
    }
}

#[tauri::command]
pub async fn device_skill_publish(store: State<'_, Arc<SkillStore>>, device_id: String, source_id: String, skill_path: String, agent_key: String) -> Result<PublishResult, String> {
    let store = store.inner().clone();
    blocking(move || publish(&store, &device_id, &source_id, &skill_path, &agent_key)).await
}
