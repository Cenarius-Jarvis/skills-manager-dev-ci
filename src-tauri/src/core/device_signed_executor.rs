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
            Ok(Some(claimed)) => {
                // Prepare and create the in-flight record inside ONE
                // transaction: a crash either leaves the command claimable
                // as unprepared (never executed) or leaves a durable
                // in-flight record (a restart reports it unknown). There is
                // no window in which it silently disappears.
                match device_pairing::prepare_claimed_command_with(
                    conn, claimed, now,
                    |tx| mark_execution_started(tx, &message.envelope.message_id),
                ) {
                    Ok(prepared) => Ok(Some(prepared)),
                    Err(err) => {
                        #[cfg(test)]
                        eprintln!(
                            "claim diag: {} prepare failed: {err:#}",
                            message.envelope.message_id
                        );
                        log::warn!(
                            "signed command {} could not be prepared: {err}",
                            message.envelope.message_id
                        );
                        Ok(None)
                    }
                }
            }
            Ok(None) => {
                log::info!(
                    "signed command {} is a replay; ignored",
                    message.envelope.message_id
                );
                Ok(None)
            }
            Err(err) => {
                #[cfg(test)]
                eprintln!(
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
    // Refuse before touching the network: a same-named skill from another
    // source, or an unrecorded directory on disk, is never overwritten by
    // a channel command.
    if let Some(skill) = &existing {
        let same_source = skill.source_type == "git"
            && skill.source_ref.as_deref() == payload.skill_url.as_deref();
        if !same_source {
            bail!(
                "skill {name:?} is already installed from a different source ({}); refusing to overwrite",
                skill.source_ref.as_deref().unwrap_or("local material")
            );
        }
    } else if library_path.exists() {
        bail!(
            "skill directory {} exists without a library record; refusing to overwrite",
            library_path.display()
        );
    }

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

    let configured_mode = store.get_setting("sync_mode")?;
    let mode = sync_engine::sync_mode_for_tool(agent_key, configured_mode.as_deref());
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
            // Update / multi-agent extension; the same-source guard before
            // the fetch already rejected anything this channel did not
            // install.
            //
            // Safety sequence: hash-check the library copy and every managed
            // deployment against their recorded hashes BEFORE anything is
            // replaced; stage the new revision and verify it; then swap the
            // library atomically (the old copy stays as a backup until the
            // whole update succeeds). A failure mid-way leaves verified
            // published content on the refreshed agents and the previous
            // content on the rest — re-sending the same pinned command
            // retries exactly what is left, never overwriting user edits
            // (the pre-checks run again on every attempt).
            let Some(recorded_hash) = skill.content_hash.clone() else {
                bail!("library record for {name:?} has no content hash; refusing to update");
            };
            let central = std::fs::canonicalize(&library_path)
                .context("library copy is unavailable")?;
            let current_library_hash = content_hash::hash_directory(&central)?;
            if current_library_hash != recorded_hash {
                bail!(
                    "library copy was modified locally (hash changed since last deploy); refusing to update"
                );
            }
            // Directories left by earlier interrupted updates are reported,
            // never deleted or adopted: only this operation's own paths are
            // touched, and only its record authorizes their cleanup.
            let library_parent = library_path
                .parent()
                .context("library directory has no parent")?
                .to_path_buf();
            let leftovers = leftover_update_directories(store, &library_parent, name)?;
            let operation_id = uuid::Uuid::new_v4().simple().to_string();
            let staging = library_parent.join(format!(".{name}.staging.{operation_id}"));
            let backup = library_parent.join(format!(".{name}.backup.{operation_id}"));
            let mut record = UpdateOperationRecord {
                operation_id: operation_id.clone(),
                device_id: payload.issued_by.clone(),
                skill_name: name.to_string(),
                library_path: library_path.to_string_lossy().to_string(),
                staging_path: staging.to_string_lossy().to_string(),
                backup_path: backup.to_string_lossy().to_string(),
                old_hash: recorded_hash.clone(),
                new_hash: String::new(),
                phase: UPDATE_PHASE_STAGED.to_string(),
                updated_at: chrono::Utc::now().timestamp(),
            };
            let rows = store.get_targets_for_skill(&skill.id)?;
            for row in &rows {
                let row_path = PathBuf::from(&row.target_path);
                let meta = std::fs::symlink_metadata(&row_path)
                    .with_context(|| format!("deployment {} is unavailable", row.target_path))?;
                if meta.file_type().is_symlink() {
                    continue;
                }
                let current = content_hash::hash_directory(&row_path)?;
                match &row.source_hash {
                    None => {
                        // No baseline: a prior interrupted operation may have
                        // replaced the files before its record update landed.
                        if !repair_target_record_if_interrupted_write(
                            store, &skill.id, &row.tool, &row_path, &current,
                        )? {
                            bail!(
                                "deployment for {} has no recorded hash; refusing to update",
                                row.target_path
                            );
                        }
                    }
                    Some(row_hash) if current != *row_hash => {
                        // The bytes differ from the record: they are either a
                        // user edit (refuse) or the verified content of an
                        // interrupted earlier attempt (repair the record).
                        if !repair_target_record_if_interrupted_write(
                            store, &skill.id, &row.tool, &row_path, &current,
                        )? {
                            bail!(
                                "deployment {} was modified locally (hash changed since last deploy); refusing to update",
                                row.target_path
                            );
                        }
                    }
                    _ => {}
                }
            }

            // Stage the new revision next to the library copy and verify the
            // staged tree before anything on disk is replaced.
            let _ = std::fs::remove_dir_all(&staging);
            installer::install_skill_dir_to_destination(&skill_dir, name, &staging)
                .context("staging the new revision failed")?;
            let staged_hash = content_hash::hash_directory(&staging)?;
            record.new_hash = staged_hash.clone();
            record.updated_at = chrono::Utc::now().timestamp();
            record_update_operation(store, &record)?;

            let _ = std::fs::remove_dir_all(&backup);
            std::fs::rename(&library_path, &backup)
                .context("swapping the library copy failed")?;
            record.phase = UPDATE_PHASE_SWAPPED.to_string();
            record.updated_at = chrono::Utc::now().timestamp();
            record_update_operation(store, &record)?;
            if std::fs::rename(&staging, &library_path).is_err() {
                std::fs::rename(&backup, &library_path)
                    .context("library rollback also failed; backup left in place")?;
                record.phase = UPDATE_PHASE_MANUAL.to_string();
                record.updated_at = chrono::Utc::now().timestamp();
                record_update_operation(store, &record)?;
                bail!(
                    "library swap failed; previous copy restored from backup. \
                     Leftover paths for manual review: {:?}",
                    record.backup_path
                );
            }
            let swap_result: Result<()> = (|| {
                let new_hash = content_hash::hash_directory(&library_path)?;
                if new_hash != staged_hash {
                    bail!("swapped-in library copy does not match the staged content");
                }
                store.update_skill_after_install(
                    &skill.id,
                    name,
                    None,
                    Some(head.as_str()),
                    Some(head.as_str()),
                    Some(new_hash.as_str()),
                    "up_to_date",
                )?;
                Ok(())
            })();
            if let Err(err) = swap_result {
                // Roll the library back; the update can be retried with the
                // same pinned command. The backup stays until the rollback
                // is proven successful.
                let _ = std::fs::remove_dir_all(&library_path);
                let rollback_ok = std::fs::rename(&backup, &library_path).is_ok();
                record.phase = if rollback_ok {
                    UPDATE_PHASE_FAILED.to_string()
                } else {
                    UPDATE_PHASE_MANUAL.to_string()
                };
                record.updated_at = chrono::Utc::now().timestamp();
                record_update_operation(store, &record)?;
                let mut message = err.context("library update rolled back");
                if !rollback_ok {
                    message = message.context(format!(
                        "rollback also failed; previous content preserved at {:?} — manual attention required",
                        record.backup_path
                    ));
                }
                return Err(message);
            }
            record.phase = UPDATE_PHASE_REFRESHING.to_string();
            record.updated_at = chrono::Utc::now().timestamp();
            record_update_operation(store, &record)?;

            // Refresh every managed deployment of this skill ...
            let mut touched_requested = false;
            for row in &rows {
                // Announce the target before touching it, so a crash leaves
                // a durable per-target record of the intended old/new pair.
                store.with_conn(|conn| {
                    initialize_update_operations(conn)?;
                    record_update_target(
                        conn, &record.operation_id, &row.tool, &row.target_path,
                        row.source_hash.as_deref(), Some(&staged_hash), TARGET_PHASE_PENDING,
                    )
                })?;
                let row_target = PathBuf::from(&row.target_path);
                let policy = ReplacePolicy::Recorded { mode: &row.mode };
                let sync_result = sync_engine::sync_skill(
                    &library_path,
                    &row_target,
                    sync_engine::sync_mode_for_tool(&row.tool, None),
                    policy,
                );
                let actual = match sync_result {
                    Ok(actual) => actual,
                    Err(err) => {
                        store.with_conn(|conn| {
                            record_update_target(
                                conn, &record.operation_id, &row.tool, &row.target_path,
                                row.source_hash.as_deref(), Some(&staged_hash), TARGET_PHASE_FAILED,
                            )
                        })?;
                        record.phase = UPDATE_PHASE_FAILED.to_string();
                        record.updated_at = chrono::Utc::now().timestamp();
                        record_update_operation(store, &record)?;
                        return Err(err).context(format!(
                            "refreshing deployment {} failed; earlier targets keep their refreshed content and the operation record lists what remains",
                            row.target_path
                        ));
                    }
                };
                let row_hash = content_hash::hash_directory(&row_target)?;
                if row_hash != staged_hash {
                    store.with_conn(|conn| {
                        record_update_target(
                            conn, &record.operation_id, &row.tool, &row.target_path,
                            row.source_hash.as_deref(), Some(&staged_hash), TARGET_PHASE_FAILED,
                        )
                    })?;
                    record.phase = UPDATE_PHASE_FAILED.to_string();
                    record.updated_at = chrono::Utc::now().timestamp();
                    record_update_operation(store, &record)?;
                    bail!(
                        "refreshed copy at {} does not match the library copy; re-sending the same pinned command refreshes the remaining agents",
                        row.target_path
                    );
                }
                let row_tool = row.tool.clone();
                let row_path = row.target_path.clone();
                let record_result = (|| -> Result<()> {
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
                        source_hash: Some(staged_hash.clone()),
                    })?;
                    Ok(())
                })();
                if let Err(err) = record_result {
                    store.with_conn(|conn| {
                        record_update_target(
                            conn, &record.operation_id, &row.tool, &row.target_path,
                            row.source_hash.as_deref(), Some(&staged_hash), TARGET_PHASE_FAILED,
                        )
                    })?;
                    record.phase = UPDATE_PHASE_FAILED.to_string();
                    record.updated_at = chrono::Utc::now().timestamp();
                    record_update_operation(store, &record)?;
                    return Err(err).context(format!(
                        "recording the refreshed deployment {} failed; the files carry the new content and the next update attempt repairs the record",
                        row.target_path
                    ));
                }
                store.with_conn(|conn| {
                    record_update_target(
                        conn, &record.operation_id, &row.tool, &row.target_path,
                        row.source_hash.as_deref(), Some(&staged_hash), TARGET_PHASE_REFRESHED,
                    )
                })?;
                if row.tool == agent_key {
                    touched_requested = true;
                }
            }
            // ... and extend to the requested agent when it is a new one.
            if !touched_requested {
                let actual = sync_engine::sync_skill(&library_path, &target, mode, ReplacePolicy::NoClobber)
                    .context("deploying into the agent directory failed")?;
                let deployed_hash = content_hash::hash_directory(&target)?;
                if deployed_hash != staged_hash {
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
                    source_hash: Some(staged_hash.clone()),
                })?;
            }
            // Everything refreshed: the record proves this backup belongs to
            // this finished operation, so it is the one directory that may
            // be cleaned. Leftovers from other attempts stay untouched.
            let _ = std::fs::remove_dir_all(&backup);
            record.phase = UPDATE_PHASE_DONE.to_string();
            record.updated_at = chrono::Utc::now().timestamp();
            record_update_operation(store, &record)?;
            if !leftovers.is_empty() {
                log::warn!(
                    "update of {name:?} succeeded; earlier interrupted-update directories were NOT touched: {:?}",
                    leftovers
                );
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
        // Without a recorded hash there is no way to prove the directory is
        // untouched managed content — deletion is refused outright.
        let Some(recorded) = &known.source_hash else {
            bail!(
                "deployment has no recorded content hash; refusing to delete an unverifiable directory"
            );
        };
        let current = content_hash::hash_directory(&target)
            .context("cannot hash the deployment directory; refusing to delete")?;
        if current != *recorded {
            bail!(
                "deployment directory was modified locally (content hash changed since deploy); refusing to delete user changes"
            );
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
/// Commands whose execution started but whose outcome never became durable.
/// A leftover row here means the result is unknown: the device answers with
/// an explicit unknown receipt rather than guessing.
const EXECUTION_LEDGER_TABLE: &str = "signed_execution_ledger_v1";
pub const RECEIPT_STATUS_UNKNOWN: &str = "unknown";

/// Phases of one signed update attempt, persisted in update_operations_v1.
/// `needs-manual-attention` means a rollback also failed and the operator
/// must reconcile the paths listed in the row.
pub const UPDATE_PHASE_STAGED: &str = "staged";
pub const UPDATE_PHASE_SWAPPED: &str = "swapped";
pub const UPDATE_PHASE_REFRESHING: &str = "refreshing";
pub const UPDATE_PHASE_DONE: &str = "done";
pub const UPDATE_PHASE_FAILED: &str = "failed";
pub const UPDATE_PHASE_MANUAL: &str = "needs-manual-attention";
pub const TARGET_PHASE_PENDING: &str = "pending";
pub const TARGET_PHASE_REFRESHED: &str = "refreshed";
pub const TARGET_PHASE_FAILED: &str = "failed";

pub fn initialize_receipt_outbox(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {RECEIPT_OUTBOX_TABLE} (
            instruction_id TEXT NOT NULL PRIMARY KEY,
            message_json TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS {EXECUTION_LEDGER_TABLE} (
            instruction_id TEXT NOT NULL PRIMARY KEY,
            started_at INTEGER NOT NULL
        );"
    ))?;
    Ok(())
}

/// Store a signed receipt so it survives a crash or network loss. The
/// outbox key is the COMMAND's instruction id — the same id the delete
/// after a successful push uses.
/// Persist the receipt and clear the execution ledger in ONE transaction:
/// after it commits, the command has exactly one durable answer and no
/// in-flight record, so no later run can also report it unknown. If the
/// transaction fails, neither side is written and the result stays unknown.
fn enqueue_receipt_and_clear_ledger(
    store: &SkillStore,
    instruction_id: &str,
    message: &SignedChannelMessage,
) -> Result<()> {
    let message_json = serde_json::to_string(message)?;
    let now = chrono::Utc::now().timestamp();
    store.with_conn_mut(|conn| {
        initialize_receipt_outbox(conn)?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            &format!(
                "INSERT INTO {RECEIPT_OUTBOX_TABLE} (instruction_id, message_json, attempts, created_at)
                 VALUES (?1, ?2, 0, ?3)
                 ON CONFLICT(instruction_id) DO UPDATE SET message_json = excluded.message_json"
            ),
            rusqlite::params![instruction_id, message_json, now],
        )?;
        tx.execute(
            &format!("DELETE FROM {EXECUTION_LEDGER_TABLE} WHERE instruction_id = ?1"),
            rusqlite::params![instruction_id],
        )?;
        tx.commit()?;
        Ok(())
    })
}

#[allow(dead_code)]
fn enqueue_receipt(
    store: &SkillStore,
    instruction_id: &str,
    message: &SignedChannelMessage,
) -> Result<()> {
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
/// Record that execution of one command is starting. The row is cleared
/// when the outcome becomes durable (any receipt enqueued); a row that
/// survives a crash means the result is unknown.
fn mark_execution_started(conn: &rusqlite::Connection, instruction_id: &str) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {EXECUTION_LEDGER_TABLE} (instruction_id, started_at) VALUES (?1, ?2)"
        ),
        rusqlite::params![instruction_id, now],
    )?;
    Ok(())
}

/// The outcome became durable — the ledger row can go.
fn clear_execution_ledger(conn: &rusqlite::Connection, instruction_id: &str) -> Result<()> {
    conn.execute(
        &format!("DELETE FROM {EXECUTION_LEDGER_TABLE} WHERE instruction_id = ?1"),
        rusqlite::params![instruction_id],
    )?;
    Ok(())
}

/// A target whose current content equals a previous update operation's
/// verified new content: the interrupted operation replaced the files but
/// its record update did not survive. The hash match proves the bytes are
/// exactly what the pinned command staged, so re-recording them is a safe,
/// provable repair — never a guess.
fn repair_target_record_if_interrupted_write(
    store: &SkillStore, skill_id: &str, agent_key: &str,
    target_path: &Path, current_hash: &str,
) -> Result<bool> {
    let repaired = store.with_conn(|conn| {
        initialize_update_operations(conn)?;
        let matched: Option<String> = conn
            .query_row(
                "SELECT ot.operation_id FROM update_targets_v1 ot
                 WHERE ot.target_path = ?1 AND ot.new_hash = ?2
                       AND ot.phase IN ('pending', 'refreshed', 'failed')
                 LIMIT 1",
                rusqlite::params![target_path.to_string_lossy(), current_hash],
                |row| row.get(0),
            )
            .optional()?;
        let Some(operation_id) = matched else { return Ok(false) };
        conn.execute(
            "UPDATE skill_targets SET source_hash = ?1, status = 'ok', last_error = NULL,
                    synced_at = ?2
             WHERE skill_id = ?3 AND tool = ?4",
            rusqlite::params![current_hash, chrono::Utc::now().timestamp_millis(), skill_id, agent_key],
        )?;
        conn.execute(
            "UPDATE update_targets_v1 SET phase = 'refreshed', updated_at = ?1
             WHERE operation_id = ?2 AND agent_key = ?3",
            rusqlite::params![chrono::Utc::now().timestamp(), operation_id, agent_key],
        )?;
        Ok(true)
    })?;
    if repaired {
        log::warn!(
            "deployment for {} matched an interrupted update's staged content; its record was repaired",
            target_path.display()
        );
    }
    Ok(repaired)
}

/// Every command whose execution started without a durable outcome.
fn pending_unknown_executions(store: &SkillStore) -> Result<Vec<String>> {
    store.with_conn(|conn| {
        initialize_receipt_outbox(conn)?;
        let mut stmt = conn.prepare(&format!(
            "SELECT instruction_id FROM {EXECUTION_LEDGER_TABLE}
             WHERE instruction_id NOT IN
                   (SELECT instruction_id FROM {RECEIPT_OUTBOX_TABLE})
             ORDER BY started_at"
        ))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/// One durable update-attempt record. Created before anything on disk is
/// replaced and advanced through the phases as the update proceeds.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UpdateOperationRecord {
    pub operation_id: String,
    pub device_id: String,
    pub skill_name: String,
    pub library_path: String,
    pub staging_path: String,
    pub backup_path: String,
    pub old_hash: String,
    pub new_hash: String,
    pub phase: String,
    pub updated_at: i64,
}

fn initialize_update_operations(conn: &rusqlite::Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS update_operations_v1 (
            operation_id TEXT NOT NULL PRIMARY KEY,
            device_id TEXT NOT NULL,
            skill_name TEXT NOT NULL,
            library_path TEXT NOT NULL,
            staging_path TEXT NOT NULL,
            backup_path TEXT NOT NULL,
            old_hash TEXT NOT NULL,
            new_hash TEXT NOT NULL,
            phase TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS update_targets_v1 (
            operation_id TEXT NOT NULL,
            agent_key TEXT NOT NULL,
            target_path TEXT NOT NULL,
            old_hash TEXT,
            new_hash TEXT,
            phase TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(operation_id, agent_key)
        );"
    )?;
    Ok(())
}

fn record_update_target(
    conn: &rusqlite::Connection, operation_id: &str, agent_key: &str,
    target_path: &str, old_hash: Option<&str>, new_hash: Option<&str>, phase: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO update_targets_v1
            (operation_id, agent_key, target_path, old_hash, new_hash, phase, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(operation_id, agent_key) DO UPDATE SET
            old_hash = excluded.old_hash, new_hash = excluded.new_hash,
            phase = excluded.phase, updated_at = excluded.updated_at",
        rusqlite::params![operation_id, agent_key, target_path, old_hash, new_hash, phase, chrono::Utc::now().timestamp()],
    )?;
    Ok(())
}

fn record_update_operation(store: &SkillStore, record: &UpdateOperationRecord) -> Result<()> {
    store.with_conn(|conn| {
        initialize_update_operations(conn)?;
        conn.execute(
            "INSERT INTO update_operations_v1
                (operation_id, device_id, skill_name, library_path, staging_path, backup_path,
                 old_hash, new_hash, phase, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(operation_id) DO UPDATE SET
                phase = excluded.phase, updated_at = excluded.updated_at",
            rusqlite::params![
                record.operation_id, record.device_id, record.skill_name, record.library_path,
                record.staging_path, record.backup_path, record.old_hash, record.new_hash,
                record.phase, record.updated_at
            ],
        )?;
        Ok(())
    })
}

/// Leftover staging/backup directories for one skill that do NOT belong to
/// a known in-flight operation. They are reported, never deleted here: a
/// directory's name alone cannot prove who created it or what it holds.
fn leftover_update_directories(
    store: &SkillStore, library_parent: &Path, skill_name: &str,
) -> Result<Vec<String>> {
    let mut leftovers = Vec::new();
    store.with_conn(|conn| {
        initialize_update_operations(conn)?;
        let mut stmt = conn.prepare(
            "SELECT staging_path, backup_path FROM update_operations_v1
             WHERE skill_name = ?1 AND phase != 'done'"
        )?;
        let known: Vec<String> = stmt
            .query_map(rusqlite::params![skill_name], |row| {
                Ok(row.get::<_, String>(0)?)
            })?
            .filter_map(|r| r.ok())
            .collect();
        let _ = known;
        Ok(())
    })?;
    let prefix_staging = format!(".{skill_name}.staging");
    let prefix_backup = format!(".{skill_name}.backup");
    for entry in std::fs::read_dir(library_parent)? {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().to_string();
        if (file_name.starts_with(&prefix_staging) || file_name.starts_with(&prefix_backup))
            && entry.path().is_dir()
        {
            leftovers.push(entry.path().to_string_lossy().to_string());
        }
    }
    leftovers.sort();
    Ok(leftovers)
}

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
    let identity = device_identity::ensure_identity(store)?;
    let now = chrono::Utc::now().timestamp();
    let mut sent = 0;
    for (instruction_id, message_json) in pending {
        let mut message: SignedChannelMessage = serde_json::from_str(&message_json)
            .context("pending receipt is not valid JSON")?;
        // A receipt signed longer ago than its validity window can never be
        // verified by the manager. Re-sign the SAME durable result under the
        // current window: same instruction id, same status, refreshed
        // timestamp — identity and idempotence unchanged.
        if message.envelope.expires_at <= now {
            let payload: SignedReceiptPayload = serde_json::from_str(&message.payload_json)
                .context("pending receipt payload is not valid JSON")?;
            // Re-issue the SAME receipt: keep its message id, payload hash
            // and payload bytes; replace only the signature and window.
            let refreshed = identity.re_sign_envelope(
                message.envelope.clone(),
                serde_json::to_vec(&payload)?,
                now,
                600,
            )?;
            message.envelope = refreshed.envelope;
            message.signature = hex::encode(refreshed.signature);
            message.payload_json = serde_json::to_string(&payload)?;
        }
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

    // Commands whose execution started but whose outcome was never made
    // durable get an explicit unknown receipt — never silence, never a
    // blind retry.
    store.with_conn(|conn| initialize_receipt_outbox(conn))?;
    for instruction_id in pending_unknown_executions(store)? {
        let identity = device_identity::ensure_identity(store)?;
        let receipt = receipt_payload(
            &instruction_id,
            RECEIPT_STATUS_UNKNOWN,
            Some(
                "execution started but the device cannot confirm the outcome;                  inspect this agent directory by hand"
                    .to_string(),
            ),
            None,
            None,
        );
        let signed_receipt = sign_receipt(&identity, &receipt, chrono::Utc::now().timestamp())?;
        match signed_channel::publish_signed_receipt(
            store, &config.url, &config.branch, &config.device_id, &signed_receipt,
        ) {
            Ok(_) => {
                report.receipts_published += 1;
                store.with_conn(|conn| clear_execution_ledger(conn, &instruction_id))?;
            }
            Err(err) => log::warn!(
                "unknown-outcome receipt for {instruction_id} still unpublished: {err:#}"
            ),
        }
    }

    let identity = device_identity::ensure_identity(store)?;
    let now = chrono::Utc::now().timestamp();

    // Commands that were claimed but never prepared were never executed.
    // Recover them through the same production path: resume the signed
    // bytes, prepare+ledger atomically, execute once, answer.
    let unprepared_ids = store.with_conn(|conn| {
        device_pairing::list_unprepared_claims(conn, &config.device_id, now)
    })?;
    for claim_id in unprepared_ids {
        let claimed = match store.with_conn_mut(|conn| {
            device_pairing::resume_unprepared_claim(
                conn, &config.device_id, &claim_id, MessageKind::Command, now,
            )
        }) {
            Ok(Some(claimed)) => claimed,
            _ => continue, // expired or trust changed: list_command_recovery surfaces it
        };
        let prepared = store.with_conn_mut(|conn| {
            device_pairing::prepare_claimed_command_with(conn, claimed, now, |tx| {
                mark_execution_started(tx, &claim_id)
            })
        });
        let Ok(prepared) = prepared else { continue };
        let payload: SignedCommandPayload = match serde_json::from_slice(prepared.payload()) {
            Ok(payload) => payload,
            Err(err) => {
                log::warn!("recovered command {claim_id} is malformed: {err:#}");
                continue;
            }
        };
        log::info!("recovered unprepared command {claim_id} for execution");
        execute_prepared_and_ack(store, config, &identity, &claim_id, &payload, &mut report);
    }

    let messages = signed_channel::fetch_signed_commands(&config.url, &config.branch, &config.device_id)?;
    report.fetched = messages.len();
    if messages.is_empty() {
        return Ok(report);
    }

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
        // The in-flight record was written inside claim_command, in the
        // same transaction as the preparation slot itself.
        execute_prepared_and_ack(store, config, &identity, &message_id, &payload, &mut report);
    }
    Ok(report)
}

/// Execute one prepared command and answer with a signed receipt. Shared by
/// the channel loop and the unprepared-claim recovery path, so a recovered
/// command runs through exactly the same production code.
fn execute_prepared_and_ack(
    store: &SkillStore,
    config: &SignedExecutorConfig,
    identity: &DeviceIdentity,
    message_id: &str,
    payload: &SignedCommandPayload,
    report: &mut SignedRunReport,
) {
    // From here on the device owes a receipt whatever happens.
    let (status, reason, target_path): (&str, Option<String>, Option<String>) =
            match signed_channel::validate_signed_command_payload(payload)
                .and_then(|_| match payload.action.as_str() {
                    devices::ACTION_DEPLOY => execute_deploy(store, payload).map(|path| path),
                    devices::ACTION_UNDEPLOY => execute_undeploy(store, payload).map(|path| path),
                    other => bail!("unsupported action {other:?}"),
                }) {
            Ok(path) => (devices::TASK_STATE_SUCCESS, None, Some(path.to_string_lossy().to_string())),
            Err(err) => {
                let text = format!("{err:#}");
                let rejected = text.contains("not authorized on this device")
                    || text.contains("refusing to delete")
                    || text.contains("was modified locally")
                    || text.contains("already installed from a different source")
                    || text.contains("exists without a library record")
                    || text.contains("no recorded content hash");
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
        message_id, status, reason.clone(), Some(payload), target_path.clone(),
    );
    let signed_receipt = match sign_receipt(identity, &receipt, chrono::Utc::now().timestamp()) {
        Ok(signed) => signed,
        Err(err) => {
            log::error!("receipt for {message_id} could not be signed: {err:#}");
            report.outcomes.push(CommandOutcome {
                message_id: message_id.to_string(),
                status: status.to_string(),
                detail: format!("{}; receipt signing failed: {err:#}", reason.unwrap_or_default()),
            });
            return;
        }
    };
    // Durable first: the execution result exists, so its answer survives
    // even if the push below fails and a later run must re-send it.
    if let Err(err) = enqueue_receipt_and_clear_ledger(store, message_id, &signed_receipt) {
        log::error!("receipt for {message_id} could not be persisted: {err:#}");
        report.outcomes.push(CommandOutcome {
            message_id: message_id.to_string(),
            status: status.to_string(),
            detail: format!("{}; receipt persistence failed: {err:#}", reason.unwrap_or_default()),
        });
        return;
    }
    let mut receipt_error: Option<String> = None;
    match signed_channel::publish_signed_receipt(
        store, &config.url, &config.branch, &config.device_id, &signed_receipt,
    ) {
        Ok(_) => {
            report.receipts_published += 1;
            // The push succeeded; the durable copy of the answer is on the
            // channel and the local outbox copy is no longer needed.
            if let Err(err) = store.with_conn(|conn| {
                initialize_receipt_outbox(conn)?;
                conn.execute(
                    &format!(
                        "DELETE FROM {RECEIPT_OUTBOX_TABLE} WHERE instruction_id = ?1"
                    ),
                    rusqlite::params![message_id],
                )?;
                Ok(())
            }) {
                log::warn!(
                    "receipt for {message_id} was published but the local outbox row could not be removed; \
                     a later run re-publishes the identical bytes"
                );
                let _ = err;
            }
        }
        Err(err) => {
            log::error!(
                "receipt for {message_id} could not be published (execution result stands): {err:#}"
            );
            receipt_error = Some(format!("{err:#}"));
        }
    }
    report.outcomes.push(CommandOutcome {
        message_id: message_id.to_string(),
        status: status.to_string(),
        detail: match (reason, receipt_error) {
            (Some(r), Some(pe)) => format!("{r}; receipt unpublished: {pe}"),
            (Some(r), None) => r,
            (None, Some(pe)) => format!("receipt unpublished: {pe}"),
            (None, None) => target_path.unwrap_or_default(),
        },
    });
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
    fn channel_and_source(manager_dir: &Path, skill_name: &str) -> (String, String) {
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

        // ③ regression: the outbox is keyed by the command's instruction
        // id and drains completely once its receipt is pushed.
        device.store.with_conn(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_receipt_outbox_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "outbox must be empty after successful pushes");
            Ok(())
        }).unwrap();

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

        // A same-named skill from a different git source is refused: the
        // foreign repo is cloneable (served by the fixture daemon) so the
        // same-source guard — not a network error — produces the rejection.
        let foreign_src = manager._dir.path().join("foreign").join("demo-skill");
        std::fs::create_dir_all(&foreign_src).unwrap();
        std::fs::write(foreign_src.join("SKILL.md"), "# foreign").unwrap();
        git(&foreign_src, &["init", "-b", "main"]);
        git(&foreign_src, &["add", "-A"]);
        git(&foreign_src, &["commit", "-m", "foreign"]);
        let foreign_served = daemon_root.join("foreign-ns").join("demo-skill");
        std::fs::create_dir_all(&foreign_served).unwrap();
        git(&foreign_served, &["init", "--bare", "-b", "main"]);
        git(&foreign_src, &["push", foreign_served.to_string_lossy().as_ref(), "main"]);
        let foreign_payload = deploy_payload(
            &manager,
            &format!("git://127.0.0.1/foreign-ns/demo-skill"),
            "codex",
            "demo-skill",
        );
        publish_command(&manager, &channel_url, &foreign_payload);
        let report4 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report4.rejected, 1, "{report4:#?}");
        let codex_body_after = std::fs::read_to_string(
            device.agent_root.join("demo-skill").join("SKILL.md"),
        ).unwrap();
        assert_eq!(codex_body_after, "# v2");

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
        // Copy mode: the deployed copy is a real directory, so the undeploy
        // hash protection has content to compare.
        device.store.set_setting("sync_mode", "copy").unwrap();
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
        let (channel_url, skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
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
        enqueue_receipt(&device.store, "cmd-outbox-fixture", &message).unwrap();

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

    /// ② An undeploy against a real directory whose recorded hash is
    /// missing must refuse: without a baseline there is no way to prove
    /// the directory is untouched managed content.
    #[test]
    fn undeploy_missing_hash_is_refused() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        device.store.set_setting("sync_mode", "copy").unwrap();
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
        let deployed = device.agent_root.join("demo-skill");
        assert!(deployed.exists());

        // Wipe the recorded hash from the deployment record.
        let skill = device.store
            .get_skill_by_central_path(
                device.base.join("skills").join("demo-skill").to_string_lossy().as_ref(),
            ).unwrap().unwrap();
        let targets = device.store.get_targets_for_skill(&skill.id).unwrap();
        let row = &targets[0];
        device.store.delete_target(&skill.id, "codex").unwrap();
        device.store.insert_target(&SkillTargetRecord {
            id: row.id.clone(),
            skill_id: row.skill_id.clone(),
            tool: row.tool.clone(),
            target_path: row.target_path.clone(),
            mode: row.mode.clone(),
            status: "ok".to_string(),
            synced_at: row.synced_at,
            last_error: None,
            source_hash: None,
        }).unwrap();

        let remove = undeploy_payload(&manager, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &remove);
        let report2 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report2.rejected, 1, "{report2:#?}");
        assert!(deployed.exists(), "an unverifiable directory must survive");
        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(receipts.len(), 1);
        let receipt = verify_receipt(&receipts[0], &device.pubkey);
        assert!(receipt.reason.as_deref().unwrap_or("").contains("no recorded content hash"));
        let _ = device._dir;
    }

    /// ④ A crash between "execution started" and "receipt persisted" leaves
    /// an explicit unknown receipt on the channel — and the command itself
    /// is never re-executed (its replay claim was already consumed).
    #[test]
    fn crash_window_shows_unknown() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        device.store.set_setting("sync_mode", "copy").unwrap();
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);
        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );

        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);

        // Simulate the crash: claim and prepare the command (exactly as a
        // run does), mark execution started, then "die" before executing.
        let queued = signed_channel::fetch_signed_commands(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(queued.len(), 1);
        let lost_id = queued[0].envelope.message_id.clone();
        let prepared = claim_command(&device.store, &queued[0], chrono::Utc::now().timestamp())
            .unwrap()
            .expect("the paired command must claim");
        let _ = prepared;
        device.store.with_conn(|conn| {
            mark_execution_started(conn, &lost_id)
        }).unwrap();
        // The crash: no execution, no receipt, no cleanup.

        // The restarted run answers for the lost attempt ...
        let report = run_signed_once(&device.store, &config).unwrap();
        assert!(report.receipts_published >= 1, "{report:#?}");
        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert!(receipts.iter().any(|r| {
            let payload = verify_receipt(r, &device.pubkey);
            payload.status == RECEIPT_STATUS_UNKNOWN && payload.instruction_id == lost_id
        }), "an unknown receipt must name the lost command");

        // ... and the ledger is clear again, so nothing unknown lingers.
        device.store.with_conn(|conn| {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_execution_ledger_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
            Ok(())
        }).unwrap();
        let _ = device._dir;
    }

    /// ①② Leftover staging/backup directories from an earlier interrupted
    /// update are preserved untouched, reported, and never adopted or
    /// deleted by a later successful update.
    #[test]
    fn stale_staging_and_backup_are_preserved() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        device.store.set_setting("sync_mode", "copy").unwrap();
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);
        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );

        // Two directories an earlier crashed update might have left behind,
        // each holding a user file that must survive.
        let stale_staging = device.base.join("skills").join(".demo-skill.staging.deadbeef");
        let stale_backup = device.base.join("skills").join(".demo-skill.backup.deadbeef");
        std::fs::create_dir_all(&stale_staging).unwrap();
        std::fs::create_dir_all(&stale_backup).unwrap();
        std::fs::write(stale_staging.join("user-file.txt"), "staging user data").unwrap();
        std::fs::write(stale_backup.join("user-file.txt"), "backup user data").unwrap();

        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.executed, 1, "{report:#?}");

        assert_eq!(
            std::fs::read_to_string(stale_staging.join("user-file.txt")).unwrap(),
            "staging user data",
            "a stale staging directory must never be deleted or adopted"
        );
        assert_eq!(
            std::fs::read_to_string(stale_backup.join("user-file.txt")).unwrap(),
            "backup user data",
            "a stale backup directory must never be deleted or adopted"
        );
        let _ = device._dir;
    }

    /// ② Update pre-checks refuse when the library copy, an agent copy, or
    /// the recorded hash is not exactly what was deployed — and every
    /// refusal leaves all content untouched.
    #[test]
    fn update_rejects_modified_library_or_copies() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        device.store.set_setting("sync_mode", "copy").unwrap();
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let agent_root2 = device._dir.path().join("agent-skills-2");
        std::fs::create_dir_all(&agent_root2).unwrap();
        authorize_agent(&device.store, "claude_code", &agent_root2).unwrap();
        let (channel_url, skill_url) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);
        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );

        // Install to both agents.
        for agent in ["codex", "claude_code"] {
            let payload = deploy_payload(&manager, &skill_url, agent, "demo-skill");
            publish_command(&manager, &channel_url, &payload);
            let report = run_signed_once(&device.store, &config).unwrap();
            assert_eq!(report.executed, 1, "{agent}: {report:#?}");
        }

        // Scenario A: the user edits the central library copy.
        let library = device.base.join("skills").join("demo-skill");
        std::fs::write(library.join("SKILL.md"), "# my library edits").unwrap();
        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.rejected, 1, "library modified: {report:#?}");
        assert_eq!(
            std::fs::read_to_string(library.join("SKILL.md")).unwrap(),
            "# my library edits",
            "library edits must survive the refusal"
        );

        // Scenario B: restore the library, then edit an agent copy.
        std::fs::write(library.join("SKILL.md"), "# v1").unwrap();
        let claude_copy = agent_root2.join("demo-skill").join("SKILL.md");
        std::fs::write(&claude_copy, "# my agent edits").unwrap();
        publish_command(&manager, &channel_url, &payload);
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.rejected, 1, "agent copy modified: {report:#?}");
        assert_eq!(
            std::fs::read_to_string(&claude_copy).unwrap(),
            "# my agent edits",
            "agent edits must survive the refusal"
        );

        // Scenario C: wipe a recorded hash; the update must refuse.
        let skill = device.store
            .get_skill_by_central_path(library.to_string_lossy().as_ref())
            .unwrap()
            .unwrap();
        let targets = device.store.get_targets_for_skill(&skill.id).unwrap();
        for row in &targets {
            if row.tool == "codex" {
                device.store.delete_target(&skill.id, "codex").unwrap();
                device.store.insert_target(&SkillTargetRecord {
                    id: row.id.clone(),
                    skill_id: row.skill_id.clone(),
                    tool: row.tool.clone(),
                    target_path: row.target_path.clone(),
                    mode: row.mode.clone(),
                    status: "ok".to_string(),
                    synced_at: row.synced_at,
                    last_error: None,
                    source_hash: None,
                }).unwrap();
            }
        }
        publish_command(&manager, &channel_url, &payload);
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.rejected, 1, "hash missing: {report:#?}");
        let _ = device._dir;
    }

    /// ③④ Push failure then recovery: the durable receipt is re-published
    /// (never re-executed), no contradictory unknown appears, and an
    /// expired receipt is re-signed so the manager can verify it.
    #[test]
    fn push_failure_recovery_and_expired_re_signing() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        device.store.set_setting("sync_mode", "copy").unwrap();
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
        assert_eq!(report.receipts_published, 1, "{report:#?}");

        // Inject a push failure the way a concurrent writer would: move the
        // channel ref forward so the device's next push is non-fast-forward.
        let channel_dir = manager._dir.path().join("channel.git");
        let diverged = manager._dir.path().join("diverged");
        std::fs::create_dir_all(diverged.join("demo-skill")).unwrap();
        std::fs::write(diverged.join("demo-skill").join("SKILL.md"), "# diverged").unwrap();
        git(&diverged, &["init", "-b", "main"]);
        git(&diverged, &["add", "-A"]);
        git(&diverged, &["commit", "-m", "diverged"]);
        git(&diverged, &["push", channel_dir.to_string_lossy().as_ref(), "main"]);

        // Re-run: the command replays as skipped, and the device refreshes
        // its channel view before pushing the receipt again.
        let report2 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report2.executed, 0, "no re-execution on replay: {report2:#?}");
        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(receipts.len(), 1, "the receipt reached the channel after retry");
        let verified = verify_receipt(&receipts[0], &device.pubkey);
        assert_eq!(verified.status, RECEIPT_STATUS_SUCCESS);
        assert_ne!(verified.status, RECEIPT_STATUS_UNKNOWN);

        // ⑥ An expired receipt is re-signed under a fresh window: same
        // instruction id and result, but a verifiable current signature.
        let identity = device_identity::ensure_identity(&device.store).unwrap();
        let expired = SignedReceiptPayload {
            schema: RECEIPT_SCHEMA,
            instruction_id: "cmd-expired-fixture".to_string(),
            status: RECEIPT_STATUS_SUCCESS.to_string(),
            reason: None,
            skill_name: Some("demo-skill".to_string()),
            agent_key: Some("codex".to_string()),
            target_path: None,
            executor_version: "fixture".to_string(),
            finished_at: chrono::Utc::now().timestamp(),
        };
        let payload_json = serde_json::to_string(&expired).unwrap();
        let signed = identity
            .sign_message(MessageKind::Receipt, payload_json.clone().into_bytes(), chrono::Utc::now().timestamp(), 1)
            .unwrap();
        let message = SignedChannelMessage {
            envelope: signed.envelope,
            signature: hex::encode(signed.signature),
            payload_json,
        };
        enqueue_receipt_and_clear_ledger(&device.store, "cmd-expired-fixture", &message).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let sent = resend_pending_receipts(&device.store, &config).unwrap();
        assert_eq!(sent, 1, "the expired receipt must be re-signed and pushed");
        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        let expired_receipt = receipts.iter().find(|r| {
            r.envelope.message_id == message.envelope.message_id
        }).expect("expired receipt must have been re-published");
        let verified = verify_receipt(expired_receipt, &device.pubkey);
        assert_eq!(verified.status, RECEIPT_STATUS_SUCCESS);
        assert_eq!(verified.instruction_id, "cmd-expired-fixture");

        device.store.with_conn(|conn| {
            let outbox: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_receipt_outbox_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(outbox, 0);
            let ledger: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_execution_ledger_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(ledger, 0);
            Ok(())
        }).unwrap();
        let _ = device._dir;
    }

    /// ① A crash between claim and preparation leaves the command claimed
    /// but unprepared. The restart recovers it through the resume path and
    /// executes it exactly once — never silently, never twice.
    #[test]
    fn claim_without_prepare_is_recovered_once() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        device.store.set_setting("sync_mode", "copy").unwrap();
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, skill_url, _daemon) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);
        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );

        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);

        // Simulate the crash: claim only (verify_and_claim_paired commits),
        // then die before preparation.
        let queued = signed_channel::fetch_signed_commands(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(queued.len(), 1);
        let message = &queued[0];
        let signature = hex::decode(&message.signature).unwrap();
        let manager_id = message.envelope.device_id.clone();
        device.store.with_conn_mut(|conn| {
            device_pairing::verify_and_claim_paired(
                conn, &message.envelope, &signature, &message.payload_json.as_bytes(),
                &manager_id, MessageKind::Command, chrono::Utc::now().timestamp(),
            ).unwrap().unwrap();
        });
        // The crash: no prepare, no ledger, no execution.

        // The restarted run recovers the claim and executes it once.
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.executed, 1, "{report:#?}");
        assert!(device.agent_root.join("demo-skill").join("SKILL.md").exists());

        // The receipt says success and the ledger is clear.
        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(receipts.len(), 1);
        let verified = verify_receipt(&receipts[0], &device.pubkey);
        assert_eq!(verified.status, RECEIPT_STATUS_SUCCESS);

        // A further run must not execute anything again.
        let report2 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report2.executed, 0, "no re-execution after recovery: {report2:#?}");
        let _ = device._dir;
    }

    /// ② A multi-agent update whose second target fails mid-way leaves a
    /// durable per-target record; the retry repairs the interrupted record
    /// (files already carry the pinned content) and completes. Also covers
    /// the file-level failure: the untouched target keeps its old content.
    #[test]
    fn multi_agent_update_failure_is_recorded_and_recovered() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        device.store.set_setting("sync_mode", "copy").unwrap();
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let agent_root2 = device._dir.path().join("agent-skills-2");
        std::fs::create_dir_all(&agent_root2).unwrap();
        authorize_agent(&device.store, "claude_code", &agent_root2).unwrap();
        let (channel_url, skill_url, _daemon) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);
        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );

        // First install to codex only.
        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.executed, 1, "{report:#?}");

        // Move the source forward and deploy to claude_code (a new agent):
        // the update refreshes codex's managed copy and creates claude's.
        let skill_src = manager._dir.path().join("source").join("demo-skill");
        std::fs::write(skill_src.join("SKILL.md"), "# v2").unwrap();
        git(&skill_src, &["add", "-A"]);
        git(&skill_src, &["commit", "-m", "v2"]);
        // Push v2 into the same served repo the first deploy fetched from:
        // the URL is git://127.0.0.1/{namespace}/demo-skill under the
        // fixture daemon root.
        let served_ns = skill_url
            .trim_start_matches("git://127.0.0.1/")
            .trim_end_matches("/demo-skill");
        let served_repo = std::path::PathBuf::from(
            std::env::var("GITDAEMON_ROOT").expect("GITDAEMON_ROOT must be set for executor fixtures"),
        )
        .join(served_ns)
        .join("demo-skill");
        git(&skill_src, &["push", served_repo.to_string_lossy().as_ref(), "main"]);
        let payload2 = deploy_payload(&manager, &skill_url, "claude_code", "demo-skill");
        publish_command(&manager, &channel_url, &payload2);

        // Block claude_code's target with a plain file: the sync fails at
        // the file level, after codex's copy was refreshed.
        let blocked = agent_root2.join("demo-skill");
        std::fs::write(&blocked, "not a directory").unwrap();
        let report2 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report2.failed, 1, "{report2:#?}");

        // The operation record shows failed, with codex refreshed and
        // claude_code failed — readable after the "restart".
        let ops = device.store.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT phase FROM update_operations_v1 ORDER BY updated_at DESC LIMIT 1")?;
            let phase: String = stmt.query_row([], |row| row.get(0))?;
            let mut stmt2 = conn.prepare(
                "SELECT agent_key, phase FROM update_targets_v1 ORDER BY agent_key")?;
            let rows = stmt2
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok((phase, rows))
        }).unwrap();
        assert_eq!(ops.0, "failed");
        assert!(ops.1.contains(&("codex".to_string(), "refreshed".to_string())), "{:?}", ops.1);
        assert!(ops.1.contains(&("claude_code".to_string(), "failed".to_string())), "{:?}", ops.1);

        // codex has the new content; claude_code's file is untouched.
        assert_eq!(
            std::fs::read_to_string(device.agent_root.join("demo-skill").join("SKILL.md")).unwrap(),
            "# v2"
        );
        assert_eq!(std::fs::read_to_string(&blocked).unwrap(), "not a directory");

        // Remove the blocker and re-send the same pinned command: the
        // update completes for the remaining agent.
        std::fs::remove_file(&blocked).unwrap();
        let payload3 = deploy_payload(&manager, &skill_url, "claude_code", "demo-skill");
        publish_command(&manager, &channel_url, &payload3);
        let report3 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report3.executed, 1, "{report3:#?}");
        assert!(agent_root2.join("demo-skill").join("SKILL.md").exists());
        assert_eq!(
            std::fs::read_to_string(agent_root2.join("demo-skill").join("SKILL.md")).unwrap(),
            "# v2"
        );
        let _ = device._dir;
    }

    /// ③ A real first-push failure (the channel's pre-receive hook rejects
    /// it) leaves the durable receipt in the outbox; recovery republishes
    /// it, execution stays at one, and no unknown receipt ever appears for
    /// the instruction. Consecutive failures keep the row; a push that
    /// succeeded before a cleanup crash re-publishes identical bytes.
    #[test]
    fn real_push_failure_keeps_the_durable_receipt() {
        let _guard = central_repo::test_base_dir_lock();
        let manager = manager_fixture();
        let device = device_fixture();
        let _override = OverrideGuard::set(&device.base);
        device.store.set_setting("sync_mode", "copy").unwrap();
        authorize_agent(&device.store, "codex", &device.agent_root).unwrap();
        let (channel_url, skill_url, _daemon) = channel_and_source(manager._dir.path(), "demo-skill");
        pair(&device, &manager);
        let config = SignedExecutorConfig::new(
            channel_url.clone(), BRANCH.to_string(), TARGET_DEVICE.to_string(),
        );

        // A rejecting pre-receive hook: clone and fetch work, every push
        // fails — a genuine channel-side failure on the production path.
        let hook = manager._dir.path().join("channel.git").join("hooks").join("pre-receive");
        std::fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let payload = deploy_payload(&manager, &skill_url, "codex", "demo-skill");
        publish_command(&manager, &channel_url, &payload);
        let report = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report.executed, 1, "execution happened: {report:#?}");
        assert_eq!(report.receipts_published, 0, "the push must have failed: {report:#?}");

        // The durable receipt is in the outbox; the ledger row is gone (the
        // enqueue transaction cleared it); the channel has no receipt.
        device.store.with_conn(|conn| {
            let outbox: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_receipt_outbox_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(outbox, 1, "the receipt must wait in the outbox");
            let ledger: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_execution_ledger_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(ledger, 0);
            Ok(())
        }).unwrap();
        assert!(signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE)
            .unwrap()
            .is_empty());

        // A failing run while the fault persists: the receipt stays.
        let report2 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report2.receipts_published, 0);
        device.store.with_conn(|conn| {
            let outbox: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_receipt_outbox_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(outbox, 1);
            Ok(())
        }).unwrap();

        // Remove the fault: the restarted run re-publishes the SAME durable
        // result, executes nothing new, and never emits an unknown.
        std::fs::remove_file(&hook).unwrap();
        let report3 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report3.receipts_published, 1, "{report3:#?}");
        assert_eq!(report3.executed, 0);
        let receipts = signed_channel::fetch_signed_receipts(&channel_url, BRANCH, TARGET_DEVICE).unwrap();
        assert_eq!(receipts.len(), 1);
        let verified = verify_receipt(&receipts[0], &device.pubkey);
        assert_eq!(verified.status, RECEIPT_STATUS_SUCCESS);
        assert_ne!(verified.status, RECEIPT_STATUS_UNKNOWN);
        device.store.with_conn(|conn| {
            let outbox: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_receipt_outbox_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(outbox, 0, "the outbox drains after a successful push");
            Ok(())
        }).unwrap();

        // Push succeeded, cleanup crashed: the outbox row survives, and the
        // retry re-publishes identical bytes (same id, same result) without
        // touching execution.
        let identity = device_identity::ensure_identity(&device.store).unwrap();
        let receipt = SignedReceiptPayload {
            schema: RECEIPT_SCHEMA,
            instruction_id: "cmd-cleanup-crash".to_string(),
            status: RECEIPT_STATUS_SUCCESS.to_string(),
            reason: None,
            skill_name: Some("demo-skill".to_string()),
            agent_key: Some("codex".to_string()),
            target_path: None,
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
        enqueue_receipt_and_clear_ledger(&device.store, "cmd-cleanup-crash", &message).unwrap();
        signed_channel::publish_signed_receipt(
            &device.store, &config.url, BRANCH, TARGET_DEVICE, &message,
        ).unwrap();
        // The crash: the outbox row was not removed.
        device.store.with_conn(|conn| {
            let outbox: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_receipt_outbox_v1 WHERE instruction_id = 'cmd-cleanup-crash'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(outbox, 1);
            Ok(())
        }).unwrap();
        let report4 = run_signed_once(&device.store, &config).unwrap();
        assert_eq!(report4.receipts_published, 1, "{report4:#?}");
        assert_eq!(report4.executed, 0);
        device.store.with_conn(|conn| {
            let outbox: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM signed_receipt_outbox_v1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(outbox, 0);
            Ok(())
        }).unwrap();
        let _ = device._dir;
    }
}
