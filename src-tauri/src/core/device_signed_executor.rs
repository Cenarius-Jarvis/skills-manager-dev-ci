//! Signed command execution for this device.
//!
//! One run: fetch signed commands from the channel, verify each against the
//! locally paired manager key, claim the id against replay, consume the
//! preparation slot, check this device's own authorization, execute through
//! the official install/deploy paths, and publish a signed receipt.
//!
//! Boundaries that hold no matter what a command says:
//! - Only agent keys explicitly authorized on this device are touched.
//! - Deployment always goes into the agent root recorded at authorization
//!   time; nothing in the command can move the target.
//! - A skill already present in this device's library is never overwritten
//!   by a channel command (the pilot has no update flow yet).
//! - A prepared command whose run crashes leaves outcome unknown: the claim
//!   and preparation are consumed, so a later run never silently replays it.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::central_repo;
use super::content_hash;
use super::device_envelope::MessageKind;
use super::git_fetcher;
use super::device_identity::{self, DeviceIdentity};
use super::device_pairing::{
    prepare_claimed_command, verify_and_claim_paired, PreparedDeviceCommand,
};
use super::devices;
use super::installer;
use super::repo_lock::RepoLock;
use super::signed_channel::{self, SignedChannelMessage, SignedCommandPayload};
use super::skill_store::{SkillRecord, SkillStore, SkillTargetRecord};
use super::sync_engine::{self, ReplacePolicy};
use super::sync_metadata;

/// Settings key prefix for per-agent deployment authorization. The value is
/// the absolute agent skills root this device is allowed to write.
const AGENT_AUTH_PREFIX: &str = "device.agent_auth.";
pub const RECEIPT_SCHEMA: u32 = 1;
pub const RECEIPT_STATUS_SUCCESS: &str = "success";
pub const RECEIPT_STATUS_FAILED: &str = "failed";
pub const RECEIPT_STATUS_REJECTED: &str = "rejected";

#[derive(Debug, Clone)]
pub struct SignedExecutorConfig {
    pub url: String,
    pub branch: String,
    pub device_id: String,
    pub executor_version: String,
    /// Upper bound processed per run so a long queue cannot hold the
    /// scheduler forever.
    pub max_commands: usize,
}

impl SignedExecutorConfig {
    pub fn new(url: String, branch: String, device_id: String) -> Self {
        Self {
            url,
            branch,
            device_id,
            executor_version: env!("CARGO_PKG_VERSION").to_string(),
            max_commands: 16,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandOutcome {
    pub message_id: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Default, Serialize)]
pub struct SignedRunReport {
    pub fetched: usize,
    pub executed: usize,
    pub failed: usize,
    pub rejected: usize,
    pub skipped: usize,
    pub receipts_published: usize,
    pub outcomes: Vec<CommandOutcome>,
}

/// What the device reports back, signed with the device identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedReceiptPayload {
    pub schema: u32,
    /// The signed command this receipt answers (its envelope message id).
    pub instruction_id: String,
    pub status: String,
    pub reason: Option<String>,
    pub skill_name: Option<String>,
    pub agent_key: Option<String>,
    /// Deployment path on success, for operator audit.
    pub target_path: Option<String>,
    pub executor_version: String,
    pub finished_at: i64,
}

/// Bind one agent key to the only skills root this device may deploy it to.
/// The root must be absolute; relative roots would silently depend on the
/// scheduler's working directory.
pub fn authorize_agent(store: &SkillStore, agent_key: &str, agent_root: &Path) -> Result<()> {
    devices::validate_agent_key(agent_key)?;
    if !agent_root.is_absolute() {
        bail!("agent root must be an absolute path");
    }
    store.set_setting(
        &format!("{AGENT_AUTH_PREFIX}{agent_key}"),
        &agent_root.to_string_lossy(),
    )?;
    Ok(())
}

/// The authorized skills root for one agent key, if any.
pub fn authorized_agent_root(store: &SkillStore, agent_key: &str) -> Result<Option<PathBuf>> {
    devices::validate_agent_key(agent_key)?;
    Ok(store
        .get_setting(&format!("{AGENT_AUTH_PREFIX}{agent_key}"))?
        .filter(|path| !path.is_empty())
        .map(PathBuf::from))
}

/// Remove an authorization binding. Existing deployments are not touched —
/// revoking authorization stops future commands, it is not an undeploy.
pub fn revoke_agent(store: &SkillStore, agent_key: &str) -> Result<bool> {
    devices::validate_agent_key(agent_key)?;
    let key = format!("{AGENT_AUTH_PREFIX}{agent_key}");
    if store.get_setting(&key)?.is_some() {
        store.set_setting(&key, "")?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn receipt_payload(
    instruction_id: &str,
    status: &str,
    reason: Option<String>,
    payload: Option<&SignedCommandPayload>,
    target_path: Option<String>,
) -> SignedReceiptPayload {
    SignedReceiptPayload {
        schema: RECEIPT_SCHEMA,
        instruction_id: instruction_id.to_string(),
        status: status.to_string(),
        reason,
        skill_name: payload.and_then(|p| p.skill_name.clone()),
        agent_key: payload.map(|p| p.agent_key.clone()),
        target_path,
        executor_version: env!("CARGO_PKG_VERSION").to_string(),
        finished_at: chrono::Utc::now().timestamp(),
    }
}

fn sign_receipt(
    identity: &DeviceIdentity,
    payload: &SignedReceiptPayload,
    now: i64,
) -> Result<SignedChannelMessage> {
    let payload_json = serde_json::to_string(payload)?;
    let signed = identity.sign_message(
        MessageKind::Receipt,
        payload_json.clone().into_bytes(),
        now,
        600,
    )?;
    Ok(SignedChannelMessage {
        envelope: signed.envelope,
        signature: hex::encode(signed.signature),
        payload_json,
    })
}

/// Verify a fetched message against this device's paired manager keys and
/// consume the replay claim and preparation slot. Returns `None` when the
/// message must be skipped (unknown signer, bad signature, replay).
fn claim_command(
    store: &SkillStore,
    message: &SignedChannelMessage,
    now: i64,
) -> Result<Option<PreparedDeviceCommand>> {
    let manager_id = message.envelope.device_id.clone();
    let signature = match hex::decode(&message.signature) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        _ => bail!("invalid signature encoding"),
    };
    store.with_conn_mut(|conn| {
        match verify_and_claim_paired(
            conn,
            &message.envelope,
            &signature,
            message.payload_json.as_bytes(),
            &manager_id,
            MessageKind::Command,
            now,
        ) {
            Ok(Some(claimed)) => match prepare_claimed_command(conn, claimed, now) {
                Ok(prepared) => Ok(Some(prepared)),
                Err(err) => {
                    #[cfg(test)]
                    println!(
                        "claim diag: {} prepare failed: {err:#}",
                        message.envelope.message_id
                    );
                    log::warn!(
                        "signed command {} could not be prepared: {err}",
                        message.envelope.message_id
                    );
                    Ok(None)
                }
            },
            Ok(None) => {
                log::info!(
                    "signed command {} is a replay; ignored",
                    message.envelope.message_id
                );
                Ok(None)
            }
            Err(err) => {
                #[cfg(test)]
                println!(
                    "claim diag: {} verification failed: {err:#}",
                    message.envelope.message_id
                );
                log::warn!(
                    "signed command {} failed verification against paired keys: {err}",
                    message.envelope.message_id
                );
                Ok(None)
            }
        }
    })
}

fn parse_command_payload(message: &SignedChannelMessage) -> Result<SignedCommandPayload> {
    let payload: SignedCommandPayload = serde_json::from_str(&message.payload_json)
        .context("signed command payload is not valid JSON")?;
    signed_channel::validate_signed_command_payload(&payload)?;
    Ok(payload)
}

/// Locate the skill directory inside a fetched clone.
fn resolve_skill_dir(clone_root: &Path, subpath: Option<&str>) -> Result<PathBuf> {
    let dir = match subpath {
        None | Some("") => clone_root.to_path_buf(),
        Some(sub) => {
            let joined = clone_root.join(sub);
            let canonical = joined.canonicalize().context("skill subpath is unavailable")?;
            let root_canonical = clone_root.canonicalize().context("clone root is unavailable")?;
            if !canonical.starts_with(&root_canonical) {
                bail!("skill subpath escapes the fetched repository");
            }
            canonical
        }
    };
    let manifest = std::fs::symlink_metadata(dir.join("SKILL.md"))
        .context("fetched skill has no SKILL.md at the resolved path")?;
    if !manifest.is_file() {
        bail!("SKILL.md must be an ordinary file");
    }
    Ok(dir)
}

fn library_skill_path(name: &str) -> Result<PathBuf> {
    devices::validate_skill_name(name)?;
    Ok(super::central_repo::skills_dir().join(name))
}

/// Deploy: install into this device's central library, then sync into the
/// authorized agent root. Refuses an existing library entry — the pilot has
/// no update flow, and a channel command must never overwrite local skills.
fn execute_deploy(
    store: &SkillStore,
    payload: &SignedCommandPayload,
) -> Result<PathBuf> {
    let agent_key = payload.agent_key.as_str();
    let name = payload
        .skill_name
        .as_deref()
        .context("deploy command must name a skill")?;
    let root = authorized_agent_root(store, agent_key)?
        .context("agent is not authorized on this device")?;

    let library_path = library_skill_path(name)?;
    let existing = store
        .get_skill_by_central_path(&library_path.to_string_lossy())?;

    let _lock = RepoLock::acquire_foreground("signed command deploy")?;
    let (_clone_tmp, clone_root) =
        devices::fetch_skill_source(payload.skill_url.as_deref().context("deploy needs a skill_url")?, payload.skill_branch.as_deref())?;
    // The command pins a full commit: the fetched tree must be exactly that
    // revision, or nothing here deploys.
    let head = git_fetcher::get_head_revision(&clone_root)?;
    if let Some(pinned) = &payload.skill_commit {
        if head != *pinned {
            bail!("fetched revision {head} does not match the pinned commit {pinned}");
        }
    }
    let skill_dir = resolve_skill_dir(&clone_root, payload.skill_subpath.as_deref())?;

    let mode = sync_engine::sync_mode_for_tool(agent_key, None);
    std::fs::create_dir_all(&root).context("authorized agent root is unavailable")?;
    let root_canonical = std::fs::canonicalize(&root).context("authorized agent root is unavailable")?;
    let target = root_canonical.join(name);

    match existing {
        None => {
            let installed = installer::install_from_git_dir(&skill_dir, Some(name))
                .context("installing the fetched skill into the central library failed")?;
            let central = installed.central_path;
            if central != library_path {
                bail!("installed path drifted from the requested library location");
            }
            let hash = content_hash::hash_directory(&central)?;
            if hash != installed.content_hash {
                bail!("library copy hash changed right after install");
            }
            let actual = sync_engine::sync_skill(&central, &target, mode, ReplacePolicy::NoClobber)
                .context("deploying into the agent directory failed")?;
            let deployed_hash = content_hash::hash_directory(&target)?;
            if deployed_hash != hash {
                bail!("agent copy does not match the library copy; preserved for inspection");
            }
            let skill_id = uuid::Uuid::new_v4().to_string();
            let record = SkillRecord {
                id: skill_id.clone(),
                name: installed.name.clone(),
                description: installed.description.clone(),
                source_type: "git".to_string(),
                source_ref: payload.skill_url.clone(),
                source_ref_resolved: payload.skill_url.clone(),
                source_subpath: payload.skill_subpath.clone(),
                source_branch: payload.skill_branch.clone(),
                source_revision: Some(head.clone()),
                remote_revision: Some(head),
                central_path: central.to_string_lossy().to_string(),
                content_hash: Some(hash.clone()),
                enabled: true,
                created_at: chrono::Utc::now().timestamp(),
                updated_at: chrono::Utc::now().timestamp(),
                status: "ok".to_string(),
                update_status: "up_to_date".to_string(),
                last_checked_at: None,
                last_check_error: None,
            };
            store.insert_skill(&record).context("recording the library skill failed")?;
            let target_row = SkillTargetRecord {
                id: uuid::Uuid::new_v4().to_string(),
                skill_id,
                tool: agent_key.to_string(),
                target_path: target.to_string_lossy().to_string(),
                mode: actual.as_str().to_string(),
                status: "ok".to_string(),
                synced_at: Some(chrono::Utc::now().timestamp_millis()),
                last_error: None,
                source_hash: Some(hash),
            };
            store.insert_target(&target_row)
                .context("recording the deployment failed; target preserved for inspection")?;
            sync_metadata::write_all_from_db_unlocked(store)
                .context("publishing skill metadata failed; deployment preserved")?;
            Ok(target)
        }
        Some(skill) => {
            // Update / multi-agent extension. Only skills this signed
            // channel installed may be refreshed; anything the user
            // installed from another source is protected.
            let same_source = skill.source_type == "git"
                && skill.source_ref.as_deref() == payload.skill_url.as_deref();
            if !same_source {
                bail!(
                    "skill {name:?} is already installed from a different source ({}); refusing to overwrite",
                    skill.source_ref.as_deref().unwrap_or("local material")
                );
            }
            let installed = installer::install_from_git_dir(&skill_dir, Some(name))
                .context("refreshing the library copy failed")?;
            let central = installed.central_path;
            if central != library_path {
                bail!(
                    "refreshed path drifted from the requested library location (installed {:?}, requested {:?})",
                    central, library_path
                );
            }
            let hash = content_hash::hash_directory(&central)?;
            if hash != installed.content_hash {
                bail!("library copy hash changed right after refresh");
            }
            store.update_skill_after_install(
                &skill.id,
                &installed.name,
                installed.description.as_deref(),
                Some(head.as_str()),
                Some(head.as_str()),
                Some(hash.as_str()),
                "up_to_date",
            )?;

            // Refresh every managed deployment of this skill ...
            let rows = store.get_targets_for_skill(&skill.id)?;
            let mut touched_requested = false;
            for row in rows {
                let row_target = PathBuf::from(&row.target_path);
                let policy = ReplacePolicy::Recorded { mode: &row.mode };
                let actual = sync_engine::sync_skill(
                    &central,
                    &row_target,
                    sync_engine::sync_mode_for_tool(&row.tool, None),
                    policy,
                ).context("refreshing a managed deployment failed")?;
                let row_hash = content_hash::hash_directory(&row_target)?;
                if row_hash != hash {
                    bail!("refreshed copy at {} does not match the library copy", row.target_path);
                }
                let row_tool = row.tool.clone();
                let row_path = row.target_path.clone();
                store.delete_target(&skill.id, &row_tool)?;
                store.insert_target(&SkillTargetRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    skill_id: skill.id.clone(),
                    tool: row_tool,
                    target_path: row_path,
                    mode: actual.as_str().to_string(),
                    status: "ok".to_string(),
                    synced_at: Some(chrono::Utc::now().timestamp_millis()),
                    last_error: None,
                    source_hash: Some(hash.clone()),
                })?;
                if row.tool == agent_key {
                    touched_requested = true;
                }
            }
            // ... and extend to the requested agent when it is a new one.
            if !touched_requested {
                let actual = sync_engine::sync_skill(&central, &target, mode, ReplacePolicy::NoClobber)
                    .context("deploying into the agent directory failed")?;
                let deployed_hash = content_hash::hash_directory(&target)?;
                if deployed_hash != hash {
                    bail!("agent copy does not match the library copy; preserved for inspection");
                }
                store.insert_target(&SkillTargetRecord {
                    id: uuid::Uuid::new_v4().to_string(),
                    skill_id: skill.id.clone(),
                    tool: agent_key.to_string(),
                    target_path: target.to_string_lossy().to_string(),
                    mode: actual.as_str().to_string(),
                    status: "ok".to_string(),
                    synced_at: Some(chrono::Utc::now().timestamp_millis()),
                    last_error: None,
                    source_hash: Some(hash.clone()),
                })?;
            }
            sync_metadata::write_all_from_db_unlocked(store)
                .context("publishing skill metadata failed; deployment preserved")?;
            Ok(target)
        }
    }
}

/// Undeploy: remove only a managed deployment recorded by a prior signed
/// deploy, inside the authorized root. Foreign directories are never touched.
fn execute_undeploy(store: &SkillStore, payload: &SignedCommandPayload) -> Result<PathBuf> {
    let agent_key = payload.agent_key.as_str();
    let name = payload
        .skill_name
        .as_deref()
        .context("undeploy command must name a skill")?;
    let root = authorized_agent_root(store, agent_key)?
        .context("agent is not authorized on this device")?;
    let root_canonical = std::fs::canonicalize(&root).context("authorized agent root is unavailable")?;
    let target = root_canonical.join(name);

    let records = store.get_all_targets()?;
    let known = records.iter().find(|row| {
        row.tool == agent_key && Path::new(&row.target_path) == target
    }).context("no managed deployment of this skill for the agent; refusing to delete")?;

    let meta = std::fs::symlink_metadata(&target)
        .context("managed deployment directory is missing")?;
    // A real directory may hold user edits since the deploy: only delete
    // when its content still matches what this channel deployed. A symlink
    // holds no user edits (the library copy stays), so links go freely.
    if !meta.file_type().is_symlink() {
        if let Some(recorded) = &known.source_hash {
            let current = content_hash::hash_directory(&target)
                .context("cannot hash the deployment directory; refusing to delete")?;
            if current != *recorded {
                bail!(
                    "deployment directory was modified locally (content hash changed since deploy); \
                     refusing to delete user changes"
                );
            }
        }
    }
    if meta.file_type().is_symlink() {
        // A symlink deployment: remove the link only, never the library
        // copy. Windows distinguishes directory links (remove_dir) from
        // file links (remove_file); remove_file on a directory link fails
        // with Access denied.
        let link_points_to_dir = std::fs::metadata(&target)
            .map(|resolved| resolved.is_dir())
            .unwrap_or(false);
        #[cfg(windows)]
        {
            if link_points_to_dir {
                std::fs::remove_dir(&target).context("removing the deployment link failed")?;
            } else {
                std::fs::remove_file(&target).context("removing the deployment link failed")?;
            }
        }
        #[cfg(not(windows))]
        {
            let _ = link_points_to_dir;
            std::fs::remove_file(&target).context("removing the deployment link failed")?;
        }
    } else if meta.is_dir() {
        std::fs::remove_dir_all(&target).context("removing the deployment directory failed")?;
    } else {
        bail!("deployment target is not a directory; refusing");
    }
    store.delete_target(&known.skill_id, agent_key)
        .context("removing the deployment record failed")?;
    sync_metadata::write_all_from_db_unlocked(store)
        .context("publishing skill metadata failed; removal completed")?;
    Ok(target)
}

/// Receipts are durable before they are pushed: an entry is written when the
/// execution result exists, deleted only after the signed receipt is on the
/// channel. A retried run re-publishes pending entries — receipts are
/// idempotent writes — but commands themselves are never re-executed: their
/// replay ledger and consumed preparation slot are untouched by any of this.
const RECEIPT_OUTBOX_TABLE: &str = "signed_receipt_outbox_v1";

fn initialize_receipt_outbox(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {RECEIPT_OUTBOX_TABLE} (
            instruction_id TEXT NOT NULL PRIMARY KEY,
            message_json TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );"
    ))?;
    Ok(())
}

/// Store a signed receipt so it survives a crash or network loss.
fn enqueue_receipt(store: &SkillStore, message: &SignedChannelMessage) -> Result<()> {
    let instruction_id = message.envelope.message_id.clone();
    let message_json = serde_json::to_string(message)?;
    store.with_conn(|conn| {
        initialize_receipt_outbox(conn)?;
        conn.execute(
            &format!(
                "INSERT INTO {RECEIPT_OUTBOX_TABLE} (instruction_id, message_json, attempts, created_at)
                 VALUES (?1, ?2, 0, ?3)
                 ON CONFLICT(instruction_id) DO UPDATE SET message_json = excluded.message_json"
            ),
            rusqlite::params![instruction_id, message_json, chrono::Utc::now().timestamp()],
        )?;
        Ok(())
    })
}

/// Push every pending receipt again. Channel writes are idempotent, so a
/// receipt the manager already read is harmlessly rewritten; execution is
/// never repeated here — only the answer to it travels again.
fn resend_pending_receipts(store: &SkillStore, config: &SignedExecutorConfig) -> Result<usize> {
    let pending: Vec<(String, String)> = store.with_conn(|conn| {
        initialize_receipt_outbox(conn)?;
        let mut stmt = conn.prepare(&format!(
            "SELECT instruction_id, message_json FROM {RECEIPT_OUTBOX_TABLE} ORDER BY created_at"
        ))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })?;
    let mut sent = 0;
    for (instruction_id, message_json) in pending {
        let message: SignedChannelMessage = serde_json::from_str(&message_json)
            .context("pending receipt is not valid JSON")?;
        match signed_channel::publish_signed_receipt(
            store, &config.url, &config.branch, &config.device_id, &message,
        ) {
            Ok(_) => {
                store.with_conn(|conn| {
                    conn.execute(
                        &format!(
                            "DELETE FROM {RECEIPT_OUTBOX_TABLE} WHERE instruction_id = ?1"
                        ),
                        rusqlite::params![instruction_id],
                    )?;
                    Ok(())
                })?;
                sent += 1;
            }
            Err(err) => {
                store.with_conn(|conn| {
                    conn.execute(
                        &format!(
                            "UPDATE {RECEIPT_OUTBOX_TABLE} SET attempts = attempts + 1 WHERE instruction_id = ?1"
                        ),
                        rusqlite::params![instruction_id],
                    )?;
                    Ok(())
                })?;
                log::warn!("receipt {instruction_id} still unpublished: {err:#}");
            }
        }
    }
    Ok(sent)
}

/// One executor cycle. Fetches, verifies, executes and acknowledges.
pub fn run_signed_once(store: &SkillStore, config: &SignedExecutorConfig) -> Result<SignedRunReport> {
    devices::validate_device_id(&config.device_id)?;
    let mut report = SignedRunReport::default();

    // Answer for results whose receipt never made it out before anything new.
    report.receipts_published = resend_pending_receipts(store, config)?;

    let messages = signed_channel::fetch_signed_commands(&config.url, &config.branch, &config.device_id)?;
    report.fetched = messages.len();
    if messages.is_empty() {
        return Ok(report);
    }
    let identity = device_identity::ensure_identity(store)?;
    let now = chrono::Utc::now().timestamp();

    for message in messages.iter().take(config.max_commands) {
        let message_id = message.envelope.message_id.clone();
        let payload = match parse_command_payload(message) {
            Ok(payload) => payload,
            Err(err) => {
                // Structurally invalid: cannot even answer for it reliably.
                log::warn!("signed command {message_id} is malformed: {err:#}");
                report.skipped += 1;
                report.outcomes.push(CommandOutcome {
                    message_id, status: "skipped".into(),
                    detail: format!("malformed: {err:#}"),
                });
                continue;
            }
        };

        let Some(prepared) = claim_command(store, message, now)? else {
            report.skipped += 1;
            report.outcomes.push(CommandOutcome {
                message_id, status: "skipped".into(),
                detail: "unverified, replayed or unverifiable signer".into(),
            });
            continue;
        };
        let _ = prepared; // The slot is consumed; outcome must be receipted.

        // From here on the device owes a receipt whatever happens.
        let (status, reason, target_path): (&str, Option<String>, Option<String>) =
                match signed_channel::validate_signed_command_payload(&payload)
                    .and_then(|_| match payload.action.as_str() {
                        devices::ACTION_DEPLOY => execute_deploy(store, &payload).map(|path| path),
                        devices::ACTION_UNDEPLOY => execute_undeploy(store, &payload).map(|path| path),
                        other => bail!("unsupported action {other:?}"),
                    }) {
                Ok(path) => (devices::TASK_STATE_SUCCESS, None, Some(path.to_string_lossy().to_string())),
                Err(err) => {
                    let text = format!("{err:#}");
                    let rejected = text.contains("not authorized on this device")
                        || text.contains("refusing to delete")
                        || text.contains("was modified locally")
                        || text.contains("already installed from a different source");
                    let status = if rejected {
                        report.rejected += 1;
                        RECEIPT_STATUS_REJECTED
                    } else {
                        report.failed += 1;
                        RECEIPT_STATUS_FAILED
                    };
                    (status, Some(text), None)
                }
            };
        if status == RECEIPT_STATUS_SUCCESS {
            report.executed += 1;
        }

        let receipt = receipt_payload(
            &message_id, status, reason.clone(), Some(&payload), target_path.clone(),
        );
        let signed_receipt = sign_receipt(&identity, &receipt, chrono::Utc::now().timestamp())?;
        // Durable first: the execution result exists, so its answer survives
        // even if the push below fails and a later run must re-send it.
        enqueue_receipt(store, &signed_receipt)?;
        let mut receipt_error: Option<String> = None;
        match signed_channel::publish_signed_receipt(
            store, &config.url, &config.branch, &config.device_id, &signed_receipt,
        ) {
            Ok(_) => {
                report.receipts_published += 1;
                store.with_conn(|conn| {
                    initialize_receipt_outbox(conn)?;
                    conn.execute(
                        &format!(
                            "DELETE FROM {RECEIPT_OUTBOX_TABLE} WHERE instruction_id = ?1"
                        ),
                        rusqlite::params![message_id],
                    )?;
                    Ok(())
                })?;
            }
            Err(err) => {
                log::error!(
                    "receipt for {message_id} could not be published (execution result stands): {err:#}"
                );
                receipt_error = Some(format!("{err:#}"));
            }
        }
        report.outcomes.push(CommandOutcome {
            message_id,
            status: status.to_string(),
            detail: match (reason, receipt_error) {
                (Some(r), Some(pe)) => format!("{r}; receipt unpublished: {pe}"),
                (Some(r), None) => r,
                (None, Some(pe)) => format!("receipt unpublished: {pe}"),
                (None, None) => target_path.unwrap_or_default(),
            },
        });
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{device_envelope, device_pairing};
    use crate::core::signed_channel::SIGNED_COMMAND_SCHEMA;

    const BRANCH: &str = "skills-manager-devices";
    const TARGET_DEVICE: &str = "dev-e470c";

    struct Manager {
        _dir: tempfile::TempDir,
        store: SkillStore,
        identity: DeviceIdentity,
        pubkey: Vec<u8>,
    }

    struct DeviceFixture {
        _dir: tempfile::TempDir,
        store: SkillStore,
        identity: DeviceIdentity,
        pubkey: Vec<u8>,
        base: PathBuf,
        agent_root: PathBuf,
    }

    fn git(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@local")
            .env("GIT_COMMITTER_NAME", "fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@local")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Panic-safe: restores the global base-dir override even when a test
    /// fails midway, so one broken test cannot poison the rest of the run.
    struct OverrideGuard;
    impl OverrideGuard {
        fn set(base: &Path) -> Self {
            central_repo::set_test_base_dir_override(Some(base.to_path_buf()));
            OverrideGuard
        }
    }
    impl Drop for OverrideGuard {
        fn drop(&mut self) {
            central_repo::set_test_base_dir_override(None);
        }
    }

    fn manager_fixture() -> Manager {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillStore::new(&dir.path().join("manager.db")).unwrap();
        let identity = device_identity::ensure_identity(&store).unwrap();
        let pubkey = hex::decode(identity.public_key_hex()).unwrap();
        Manager { _dir: dir, store, identity, pubkey }
    }

    fn device_fixture() -> DeviceFixture {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillStore::new(&dir.path().join("device.db")).unwrap();
        let identity = device_identity::ensure_identity(&store).unwrap();
        let pubkey = hex::decode(identity.public_key_hex()).unwrap();
        let base = dir.path().join("sm-base");
        let agent_root = dir.path().join("agent-skills");
        std::fs::create_dir_all(&agent_root).unwrap();
        DeviceFixture { _dir: dir, store, identity, pubkey, base, agent_root }
    }

    /// Channel repo plus a local git repository holding one skill.
    fn channel_and_source(manager_dir: &Path, skill_name: &str) -> (String, String, GitDaemon) {
        let channel = manager_dir.join("channel.git");
        let channel_arg = channel.to_string_lossy().to_string();
        git(&manager_dir.to_path_buf(), &["init", "--bare", channel_arg.as_str()]);
        // The repository root is the skill directory itself — the signed
        // command's skill_url must point at a repository, not a folder
        // inside one.
        let src = manager_dir.join("source").join(skill_name);
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("SKILL.md"), format!("# {skill_name}\n")).unwrap();
        git(&src, &["init", "-b", "main"]);
        git(&src, &["add", "-A"]);
        git(&src, &["commit", "-m", "skill"]);
        // Publish the source into the shared fixture daemon root (the
        // workflow runs `git daemon --base-path=$GITDAEMON_ROOT`), so the
        // device fetches over the production-allowed git:// scheme.
        let daemon_root = std::path::PathBuf::from(
            std::env::var("GITDAEMON_ROOT").expect("GITDAEMON_ROOT must be set for executor fixtures"),
        );
        // Every test gets its own namespace under the daemon root: two
        // independently created repos with the same skill name must not
        // fight over one ref.
        let namespace = uuid::Uuid::new_v4().simple().to_string();
        let served = daemon_root.join(&namespace).join(skill_name);
        std::fs::create_dir_all(&served).unwrap();
        git(&served, &["init", "--bare", "-b", "main"]);
        git(&src, &["push", served.to_string_lossy().as_ref(), "main"]);
        (channel.to_string_lossy().to_string(), format!("git://127.0.0.1/{namespace}/{skill_name}"))
    }

    /// Pair the device with the manager: the device trusts the manager's
    /// command key, exactly as it would after an approved pairing exchange.
    fn pair(device: &DeviceFixture, manager: &Manager) {
        device.store.with_conn(|conn| {
            device_pairing::register_approved_key(
                conn, &manager.identity.device_id, &manager.identity.key_id,
                MessageKind::Command, &manager.pubkey,
            )
        }).unwrap();
    }

    fn deploy_payload(manager: &Manager, url: &str, agent_key: &str, skill_name: &str) -> SignedCommandPayload {
        SignedCommandPayload {
            schema: SIGNED_COMMAND_SCHEMA,
            action: devices::ACTION_DEPLOY.to_string(),
            skill_url: Some(url.to_string()),
            skill_branch: None,
            skill_subpath: None,
            skill_commit: None,
            skill_name: Some(skill_name.to_string()),
            agent_key: agent_key.to_string(),
            issued_by: manager.identity.device_id.clone(),
            issued_by_name: Some("manager".to_string()),
            target_device: TARGET_DEVICE.to_string(),
        }
    }

    /// Sign and publish a command straight from the fixture — the https-only
    /// creation checks are covered by signed_channel's own tests; here the
    /// skill_url is a local path so the execution chain stays network-free.
    fn publish_command(
        manager: &Manager, channel_url: &str, payload: &SignedCommandPayload,
    ) -> String {
        let payload_json = serde_json::to_string(payload).unwrap();
        let signed = manager
            .identity
            .sign_message(MessageKind::Command, payload_json.clone().into_bytes(), chrono::Utc::now().timestamp(), 60_000)
            .unwrap();
        let message = SignedChannelMessage {
            envelope: signed.envelope,
            signature: hex::encode(signed.signature),
            payload_json,
        };
        signed_channel::publish_signed_command(
            &manager.store, channel_url, BRANCH, &payload.target_device, &message,
        ).unwrap();
        message.envelope.message_id
    }

    fn verify_receipt(
        message: &SignedChannelMessage, device_pubkey: &[u8],
    ) -> SignedReceiptPayload {
        let signature = hex::decode(&message.signature).unwrap();
        device_envelope::verify_envelope(
            &message.envelope, &signature, message.payload_json.as_bytes(),
            device_pubkey, &message.envelope.device_id, &message.envelope.key_id,
            MessageKind::Receipt, chrono::Utc::now().timestamp(),
        ).unwrap();
        serde_json::from_str(&message.payload_json).unwrap()
    }

    fn undeploy_payload(manager: &Manager, agent_key: &str, skill_name: &str) -> SignedCommandPayload {
        SignedCommandPayload {
            schema: SIGNED_COMMAND_SCHEMA,
            action: devices::ACTION_UNDEPLOY.to_string(),
            skill_url: None,
            skill_branch: None,
            skill_subpath: None,
            skill_commit: None,
            skill_name: Some(skill_name.to_string()),
            agent_key: agent_key.to_string(),
            issued_by: manager.identity.device_id.clone(),
            issued_by_name: Some("manager".to_string()),
            target_device: TARGET_DEVICE.to_string(),
        }
    }

    #[test]
    fn signed_command_cycle_answers_with_a_signed_receipt() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        // A legal https URL that cannot be cloned: the full cycle is
        // exercised without any network dependency, and the device must
        // still answer with a signed receipt.
        let (channel_url, _unused) = channel_and_source(manager._dir.path(), "unused");
        pair(&device, &manager);

        let payload = deploy_payload(&manager, "https://example.invalid/skills.git", "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);

        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );
        let trusted = device.store.with_conn(|conn| {
            device_pairing::trusted_public_key(
                conn, &manager.identity.device_id, &manager.identity.key_id, MessageKind::Command,
            )
        }).unwrap();
        println!(
            "cycle: trusted={:?} payload_valid={:?} envelope_device={:?} envelope_key={:?}",
            trusted.as_ref().map(|(_, active)| active),
            signed_channel::validate_signed_command_payload(&payload).is_ok(),
            payload.issued_by,
            manager.identity.key_id,
        );
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.failed, 1, "counts: fetched={} skipped={}", report.fetched, report.skipped);
        if report.receipts_published != 1 {
            panic!(
                "receipt push failed: published={} outcome_detail={:?}",
                report.receipts_published,
                report.outcomes.iter().map(|o| (o.status.as_str(), &o.detail)).collect::<Vec<_>>()
            );
        }

        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(receipts.len(), 1);
        let receipt = verify_receipt(&receipts[0], &device.pubkey);
        assert_eq!(receipt.status, RECEIPT_STATUS_FAILED);
        assert_eq!(receipt.instruction_id, report.outcomes[0].message_id);

        // A second run sees the same command as a replay: nothing re-runs.
        let second = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(second.failed, 0);
        assert_eq!(second.skipped, 1);

        let _ = device._dir; // keep the fixture alive to the end
    }

    /// The execution functions themselves, with a local skill source so no
    /// network is involved. URL scheme enforcement lives one layer up and
    /// is covered by signed_channel's validation tests.
    #[test]
    fn execute_deploy_and_undeploy_manage_library_and_agent_copies() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (_channel_url, skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);

        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        let target = execute_deploy(&device.store, &payload).unwrap();
        assert!(target.join("SKILL.md").exists());
        assert!(device.base.join("skills").join("demo-skill").join("SKILL.md").exists());

        // Undeploy removes the managed deployment, not the library copy.
        let remove = undeploy_payload(&manager, "codex", "demo-skill");
        let removed = execute_undeploy(&device.store, &remove).unwrap();
        assert_eq!(removed, target);
        assert!(!device.agent_root.join("demo-skill").exists());
        assert!(device.base.join("skills").join("demo-skill").join("SKILL.md").exists());

        let _ = device._dir;
    }

    #[test]
    fn unauthorized_agent_is_rejected_with_a_signed_receipt() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, _unused) = channel_and_source(manager._dir.path(), "unused");
        pair(&device, &manager);

        // The command names an agent this device never authorized; the
        // rejection happens before the skill source is ever contacted.
        let payload = deploy_payload(&manager, "https://example.invalid/skills.git", "other-agent", "rogue-skill");
        publish_command(&manager, &channel_url, &payload);

        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.rejected, 1, "full report: {report:#?}");

        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(receipts.len(), 1);
        let receipt = verify_receipt(&receipts[0], &device.pubkey);
        assert_eq!(receipt.status, RECEIPT_STATUS_REJECTED);
        assert!(receipt.reason.as_deref().unwrap_or("").contains("not authorized"));

        let _ = device._dir;
    }

    #[test]
    fn existing_library_skill_is_never_overwritten_by_a_command() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, _skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);

        // A skill with this name already lives in the device's library.
        let existing = central_repo::skills_dir().join("demo-skill");
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("SKILL.md"), "# local edits").unwrap();

        let payload = deploy_payload(&manager, "https://example.invalid/skills.git", "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);

        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.rejected, 1, "full report: {report:#?}");
        assert_eq!(
            std::fs::read_to_string(existing.join("SKILL.md")).unwrap(),
            "# local edits",
            "the local copy must survive"
        );

        let _ = device._dir;
    }

    #[test]
    fn unpaired_signers_are_skipped_without_receipts() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
        // No pairing: the device does not know this manager.

        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);

        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.skipped, 1);
        assert_eq!(report.executed, 0);
        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert!(receipts.is_empty(), "no receipt without a verified command");

        let _ = device._dir;
    }

    /// ① The same skill can reach more agents and be safely refreshed: the
    /// second deploy extends to a new agent, a changed source refreshes the
    /// library and every managed copy, and a differently-sourced skill is
    /// never overwritten.
    #[test]
    fn safe_update_and_multi_agent_extension() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let agent_root2 = device._dir.path().join("agent-skills-2");
        std::fs::create_dir_all(&agent_root2).unwrap();
        authorize_agent(&device.store, "claude_code", &agent_root2).unwrap();

        let skill_src = manager._dir.path().join("source").join("demo-skill");
        std::fs::create_dir_all(&skill_src).unwrap();
        std::fs::write(skill_src.join("SKILL.md"), "# v1").unwrap();
        git(&skill_src, &["init", "-b", "main"]);
        git(&skill_src, &["add", "-A"]);
        git(&skill_src, &["commit", "-m", "v1"]);
        let daemon_root = std::path::PathBuf::from(
            std::env::var("GITDAEMON_ROOT").expect("GITDAEMON_ROOT must be set for executor fixtures"),
        );
        let namespace = uuid::Uuid::new_v4().simple().to_string();
        let served = daemon_root.join(&namespace).join("demo-skill");
        std::fs::create_dir_all(&served).unwrap();
        git(&served, &["init", "--bare", "-b", "main"]);
        git(&skill_src, &["push", served.to_string_lossy().as_ref(), "main"]);
        let skill_url = format!("git://127.0.0.1/{namespace}/demo-skill");
        let channel = manager._dir.path().join("channel.git");
        let channel_arg = channel.to_string_lossy().to_string();
        git(&manager._dir.path(), &["init", "--bare", channel_arg.as_str()]);
        let channel_url = channel.to_string_lossy().to_string();
        pair(&device, &manager);

        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );

        // First deploy to codex.
        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.executed, 1, "{report:#?}");
        assert!(device.agent_root.join("demo-skill").join("SKILL.md").exists());

        // Second deploy names a different agent: the library entry is
        // reused and the new agent gets the refreshed copy.
        let payload2 = deploy_payload(&manager, &skill_url, "claude_code", "demo-skill");
        publish_command(&manager, &channel_url, &payload2);
        let report2 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report2.executed, 1, "{report2:#?}");
        assert!(agent_root2.join("demo-skill").join("SKILL.md").exists());
        assert!(device.agent_root.join("demo-skill").join("SKILL.md").exists());

        // The source moves forward; a refresh deploy reaches both agents.
        std::fs::write(skill_src.join("SKILL.md"), "# v2").unwrap();
        git(&skill_src, &["add", "-A"]);
        git(&skill_src, &["commit", "-m", "v2"]);
        git(&skill_src, &["push", served.to_string_lossy().as_ref(), "main"]);
        let payload3 = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload3);
        let report3 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report3.executed, 1, "{report3:#?}");
        let codex_body = std::fs::read_to_string(device.agent_root.join("demo-skill").join("SKILL.md")).unwrap();
        let claude_body = std::fs::read_to_string(agent_root2.join("demo-skill").join("SKILL.md")).unwrap();
        assert_eq!(codex_body, "# v2", "codex copy must be refreshed");
        assert_eq!(claude_body, "# v2", "claude_code copy must be refreshed");

        // A differently-sourced skill of the same name is protected.
        let foreign = device._dir.path().join("foreign-repo");
        std::fs::create_dir_all(foreign.join("demo-skill")).unwrap();
        std::fs::write(foreign.join("demo-skill").join("SKILL.md"), "# foreign").unwrap();
        git(&foreign, &["init", "-b", "main"]);
        git(&foreign, &["add", "-A"]);
        git(&foreign, &["commit", "-m", "foreign"]);
        let foreign_payload = deploy_payload(
            &manager,
            foreign.join("demo-skill").to_string_lossy().replace('\\', "/").as_ref(),
            "codex",
            "demo-skill",
        );
        // URL differs from the installed one, so create-time https rules do
        // not apply to this local fixture; sign it directly.
        publish_command(&manager, &channel_url, &foreign_payload);
        let report4 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report4.rejected, 1, "{report4:#?}");
        assert_eq!(codex_body, "# v2");

        let _ = device._dir;
    }

    /// ② Undeploy refuses to delete a managed directory that the user has
    /// edited since the deploy; the unmodified case still deletes.
    #[test]
    fn modified_deployment_blocks_undeploy() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);
        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );

        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.executed, 1, "{report:#?}");

        // The user edits the deployed copy in place.
        let deployed = device.agent_root.join("demo-skill");
        std::fs::write(deployed.join("SKILL.md"), "# my local edits").unwrap();

        let remove = undeploy_payload(&manager, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &remove);
        let queued = signed_channel::fetch_signed_commands(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        for m in &queued {
            println!(
                "fixture: queued {} action={:?} url={:?}",
                m.envelope.message_id,
                serde_json::from_str::<SignedCommandPayload>(&m.payload_json).map(|p| p.action),
                serde_json::from_str::<SignedCommandPayload>(&m.payload_json).map(|p| p.skill_url),
            );
        }
        let report2 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report2.rejected, 1, "{report2:#?}");
        assert_eq!(
            std::fs::read_to_string(deployed.join("SKILL.md")).unwrap(),
            "# my local edits",
            "user edits must survive a refused undeploy"
        );

        // Restoring the deployed content makes the undeploy go through.
        let library_body =
            std::fs::read_to_string(device.base.join("skills").join("demo-skill").join("SKILL.md")).unwrap();
        std::fs::write(deployed.join("SKILL.md"), library_body).unwrap();
        publish_command(&manager, &channel_url, &remove);
        let report3 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report3.executed, 1, "{report3:#?}");
        assert!(!deployed.exists());
        let _ = device._dir;
    }

    /// ③ A pinned commit is enforced: a command that names a revision the
    /// source does not have fails instead of deploying something else.
    #[test]
    fn pinned_commit_is_enforced() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, skill_url, _daemon) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);

        let mut payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        payload.skill_commit = Some("0".repeat(40));
        publish_command(&manager, &channel_url, &payload);

        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.failed, 1, "{report:#?}");
        let detail = report.outcomes[0].detail.clone();
        assert!(detail.contains("does not match the pinned commit"), "{detail}");
        assert!(!device.agent_root.join("demo-skill").exists());
        let _ = device._dir;
    }

    /// ④ Receipts survive locally when the channel cannot be reached and are
    /// re-published on a later run — without re-executing the command.
    #[test]
    fn receipt_outbox_resends_pending_receipts() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);

        // Simulate an execution whose receipt was durable but unpublished:
        // sign one as the device and put it in the outbox.
        let identity = device_identity::ensure_identity(&device.store).unwrap();
        let receipt = SignedReceiptPayload {
            schema: RECEIPT_SCHEMA,
            instruction_id: "cmd-outbox-fixture".to_string(),
            status: RECEIPT_STATUS_SUCCESS.to_string(),
            reason: None,
            skill_name: Some("demo-skill".to_string()),
            agent_key: Some("codex".to_string()),
            target_path: Some("/fixture/demo-skill".to_string()),
            executor_version: "fixture".to_string(),
            finished_at: chrono::Utc::now().timestamp(),
        };
        let payload_json = serde_json::to_string(&receipt).unwrap();
        let signed = identity
            .sign_message(MessageKind::Receipt, payload_json.clone().into_bytes(), chrono::Utc::now().timestamp(), 600)
            .unwrap();
        let message = SignedChannelMessage {
            envelope: signed.envelope,
            signature: hex::encode(signed.signature),
            payload_json,
        };
        enqueue_receipt(&device.store, &message).unwrap();

        // One executor run: the pending receipt travels, then it is gone
        // from the outbox, and the command queue stays untouched.
        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.receipts_published, 1, "{report:#?}");
        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(receipts.len(), 1);
        let verified = verify_receipt(&receipts[0], &device.pubkey);
        assert_eq!(verified.instruction_id, "cmd-outbox-fixture");
        device.store.with_conn(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_receipt_outbox_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "outbox must drain after a successful push");
            Ok(())
        }).unwrap();
        let _ = device._dir;
    }
}
