//! Tauri commands for the Devices page (multi-device management, see
//! docs/devices.md). All channel IO runs on the blocking thread pool; the
//! Rust-side entry points are shared with the CLI executor.

use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tauri::State;

use crate::core::audit_log::AuditDraft;
use crate::core::devices::{self, DeviceInstruction, DeviceInstructionRow, DeviceManifest};
use crate::core::error::AppError;
use crate::core::skill_store::SkillStore;

const PUBLISH_ATTEMPTS: u32 = 3;
const DEFAULT_INSTRUCTION_TTL_SECS: i64 = 7 * 24 * 3600;
const MIN_INSTRUCTION_TTL_SECS: i64 = 60;
const MAX_INSTRUCTION_TTL_SECS: i64 = 30 * 24 * 3600;

#[derive(Debug, Serialize)]
pub struct ChannelStatus {
    pub configured: bool,
    pub url_redacted: Option<String>,
    pub branch: String,
    pub local_device_id: String,
    pub local_device_name: String,
    pub online_threshold_secs: i64,
}

#[derive(Debug, Serialize)]
pub struct DeviceWithStatus {
    pub id: String,
    pub name: String,
    pub platform: Option<String>,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub online: bool,
    /// What this device last *reported*: per-agent deployed skills. This is
    /// the device's word about reality, never a local fact.
    pub skill_records: Vec<devices::DeviceSkillRecordRow>,
}

#[derive(Debug, Serialize)]
pub struct DevicesPage {
    pub channel: ChannelStatus,
    pub devices: Vec<DeviceWithStatus>,
    pub instructions: Vec<DeviceInstructionRow>,
}

fn input_err(err: anyhow::Error) -> AppError {
    AppError::invalid_input(err.to_string())
}

fn git_err(err: anyhow::Error) -> AppError {
    AppError::classify_git_error(err.to_string())
}

/// Channel pushes race with other writers (another manager, an executor);
/// a rejected non-fast-forward push is resolved by re-cloning, so a couple
/// of attempts ride out normal contention.
fn with_retry<T>(mut op: impl FnMut() -> anyhow::Result<T>) -> anyhow::Result<T> {
    let mut last = None;
    for attempt in 0..PUBLISH_ATTEMPTS {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) => {
                last = Some(err);
                if attempt + 1 < PUBLISH_ATTEMPTS {
                    std::thread::sleep(Duration::from_millis(1500));
                }
            }
        }
    }
    Err(last.unwrap())
}

fn channel_config_status(store: &SkillStore) -> Result<ChannelStatus, AppError> {
    let local_device_id = devices::local_device_id(store).map_err(|e| AppError::db(e))?;
    Ok(ChannelStatus {
        configured: devices::channel_url(store).is_some(),
        url_redacted: devices::channel_url(store).map(|url| devices::redact_url(&url)),
        branch: devices::channel_branch(store),
        local_device_id,
        local_device_name: devices::local_device_name(store),
        online_threshold_secs: devices::online_threshold_secs(store),
    })
}

fn build_page(store: &SkillStore) -> Result<DevicesPage, AppError> {
    let now = chrono::Utc::now().timestamp();
    let threshold = devices::online_threshold_secs(store);
    let mut devices_out = Vec::new();
    for row in store.get_devices().map_err(|e| AppError::db(e))? {
        let online = devices::is_device_online(row.last_seen_at, threshold, now);
        let skill_records = store
            .get_device_skill_records(Some(&row.id))
            .map_err(|e| AppError::db(e))?;
        devices_out.push(DeviceWithStatus {
            id: row.id,
            name: row.name,
            platform: row.platform,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
            online,
            skill_records,
        });
    }
    let instructions = store
        .get_device_instructions(None)
        .map_err(|e| AppError::db(e))?;
    Ok(DevicesPage {
        channel: channel_config_status(store)?,
        devices: devices_out,
        instructions,
    })
}

pub fn get_page_internal(store: &SkillStore) -> Result<DevicesPage, AppError> {
    build_page(store)
}

/// Fetches the channel and rebuilds the DB projection, then returns the fresh
/// page. Purely additive on the DB side: a failed or partial import is
/// repaired by the next refresh, never by the user.
pub fn refresh_channel_internal(store: &SkillStore) -> Result<DevicesPage, AppError> {
    let url = devices::channel_url(store).ok_or_else(|| {
        AppError::invalid_input("Device channel is not configured")
    })?;
    let branch = devices::channel_branch(store);
    let snapshot =
        with_retry(|| devices::fetch_channel_snapshot(&url, &branch)).map_err(git_err)?;
    devices::import_snapshot(store, &snapshot).map_err(|e| AppError::db(e))?;
    build_page(store)
}

pub fn set_channel_config_internal(
    store: &SkillStore,
    url: Option<String>,
    branch: Option<String>,
) -> Result<(), AppError> {
    devices::set_channel_config(store, url.as_deref(), branch.as_deref()).map_err(input_err)
}

fn manifest_from_row(row: &devices::DeviceRow) -> DeviceManifest {
    DeviceManifest {
        schema: devices::DEVICE_PROTOCOL_VERSION,
        id: row.id.clone(),
        name: row.name.clone(),
        platform: row.platform.clone(),
        first_seen: row.created_at,
        executor_version: None,
    }
}

pub fn add_device_internal(
    store: &SkillStore,
    name: &str,
    platform: Option<&str>,
) -> Result<devices::DeviceRow, AppError> {
    let name = name.trim();
    devices::validate_device_name(name).map_err(input_err)?;
    // A fresh unique id; the local machine keeps its own id from
    // `local_device_id`, so the two can never collide.
    let device_id = format!("dev-{}", uuid::Uuid::new_v4().simple());
    let row = devices::DeviceRow {
        id: device_id,
        name: name.to_string(),
        platform: platform.map(|p| p.trim().to_string()).filter(|p| !p.is_empty()),
        created_at: chrono::Utc::now().timestamp(),
        last_seen_at: None,
        last_state_commit: None,
    };
    store.upsert_device(&row).map_err(|e| AppError::db(e))?;
    store.log_audit(
        AuditDraft::new("device.add")
            .ok()
            .detail(format!("device {} registered", row.id)),
    );

    // Publish the identity so the device (and its executor) can see the
    // registration even before this app refreshes again. A channel failure
    // does not undo the local registration: the next successful publish
    // (any instruction) carries the manifest along.
    if let Some(url) = devices::channel_url(store) {
        let branch = devices::channel_branch(store);
        let manifest = manifest_from_row(&row);
        with_retry(|| devices::publish_instructions(&url, &branch, Some(&manifest), &[]))
            .map_err(git_err)?;
    }
    Ok(row)
}

pub fn remove_device_internal(store: &SkillStore, device_id: &str) -> Result<(), AppError> {
    devices::validate_device_id(device_id).map_err(input_err)?;
    store
        .get_device(device_id)
        .map_err(|e| AppError::db(e))?
        .ok_or_else(|| AppError::not_found(format!("device {device_id} not found")))?;
    store.delete_device(device_id).map_err(|e| AppError::db(e))?;
    store.log_audit(
        AuditDraft::new("device.remove")
            .ok()
            .detail(format!("device {device_id} removed from this app's projection")),
    );
    // The channel keeps the device's files; pruning them is a separate
    // explicit action so a removal here can never destroy evidence of what a
    // device actually executed.
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn create_instruction_internal(
    store: &SkillStore,
    device_id: &str,
    action: &str,
    skill_url: Option<&str>,
    skill_branch: Option<&str>,
    skill_subpath: Option<&str>,
    skill_name: Option<&str>,
    agent_key: &str,
    ttl_secs: Option<i64>,
) -> Result<DeviceInstructionRow, AppError> {
    let device = store
        .get_device(device_id)
        .map_err(|e| AppError::db(e))?
        .ok_or_else(|| AppError::not_found(format!("device {device_id} not found")))?;

    let ttl = ttl_secs
        .unwrap_or(DEFAULT_INSTRUCTION_TTL_SECS)
        .clamp(MIN_INSTRUCTION_TTL_SECS, MAX_INSTRUCTION_TTL_SECS);
    let now = chrono::Utc::now().timestamp();
    let instruction = DeviceInstruction {
        schema: devices::DEVICE_PROTOCOL_VERSION,
        id: format!("inst-{}", uuid::Uuid::new_v4().simple()),
        device_id: device.id.clone(),
        action: action.to_string(),
        skill_url: skill_url.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        skill_branch: skill_branch
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        skill_subpath: skill_subpath
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        skill_name: skill_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        agent_key: agent_key.to_string(),
        created_at: now,
        expires_at: Some(now + ttl),
        created_by: Some(devices::local_device_name(store)),
    };
    devices::validate_instruction(&instruction).map_err(input_err)?;

    let url = devices::channel_url(store).ok_or_else(|| {
        AppError::invalid_input("Device channel is not configured")
    })?;
    let branch = devices::channel_branch(store);
    let manifest = manifest_from_row(&device);
    // Publishing here is the moment of record: until the push succeeds, no
    // device can see the request, so the DB row is written only afterwards.
    let head = with_retry(|| {
        devices::publish_instructions(&url, &branch, Some(&manifest), std::slice::from_ref(&instruction))
    })
    .map_err(git_err)?;

    let row = DeviceInstructionRow {
        id: instruction.id.clone(),
        device_id: instruction.device_id.clone(),
        action: instruction.action.clone(),
        skill_url: instruction.skill_url.clone(),
        skill_branch: instruction.skill_branch.clone(),
        skill_subpath: instruction.skill_subpath.clone(),
        skill_name: instruction.skill_name.clone(),
        agent_key: instruction.agent_key.clone(),
        created_at: instruction.created_at,
        expires_at: instruction.expires_at,
        created_by: instruction.created_by.clone(),
        instruction_commit: Some(head),
        receipt_commit: None,
        state: devices::TASK_STATE_PENDING.to_string(),
        receipt_status: None,
        receipt_reason: None,
        receipt_detail: None,
        receipt_at: None,
        executor_version: None,
    };
    store.upsert_device_instruction(&row).map_err(|e| AppError::db(e))?;
    store.log_audit(
        AuditDraft::new("device.instruct")
            .ok()
            .tool(instruction.agent_key.as_str())
            .detail(format!(
                "{} requested on device {} for skill {:?} ({})",
                instruction.action, device.name, instruction.skill_name, instruction.id
            )),
    );
    Ok(row)
}

// ── Tauri commands ──

#[tauri::command]
pub async fn devices_get_page(
    store: State<'_, Arc<SkillStore>>,
) -> Result<DevicesPage, AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || get_page_internal(&store)).await?
}

#[tauri::command]
pub async fn devices_refresh_channel(
    store: State<'_, Arc<SkillStore>>,
) -> Result<DevicesPage, AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || refresh_channel_internal(&store)).await?
}

#[tauri::command]
pub async fn devices_set_channel_config(
    store: State<'_, Arc<SkillStore>>,
    url: Option<String>,
    branch: Option<String>,
) -> Result<(), AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        set_channel_config_internal(&store, url, branch)
    })
    .await?
}

#[tauri::command]
pub async fn devices_add_device(
    store: State<'_, Arc<SkillStore>>,
    name: String,
    platform: Option<String>,
) -> Result<devices::DeviceRow, AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        add_device_internal(&store, &name, platform.as_deref())
    })
    .await?
}

#[tauri::command]
pub async fn devices_remove_device(
    store: State<'_, Arc<SkillStore>>,
    device_id: String,
) -> Result<(), AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || remove_device_internal(&store, &device_id)).await?
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn devices_create_instruction(
    store: State<'_, Arc<SkillStore>>,
    device_id: String,
    action: String,
    skill_url: Option<String>,
    skill_branch: Option<String>,
    skill_subpath: Option<String>,
    skill_name: Option<String>,
    agent_key: String,
    ttl_secs: Option<i64>,
) -> Result<DeviceInstructionRow, AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        create_instruction_internal(
            &store,
            &device_id,
            &action,
            skill_url.as_deref(),
            skill_branch.as_deref(),
            skill_subpath.as_deref(),
            skill_name.as_deref(),
            &agent_key,
            ttl_secs,
        )
    })
    .await?
}
