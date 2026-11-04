//! Multi-device management over a Git-based control channel (see
//! docs/devices.md).
//!
//! The channel is a dedicated Git remote + branch holding small JSON files:
//! per-device identity, state reports, deployment instructions and receipts.
//! Both the managing app and the device-side executor talk only to that
//! remote — no direct network link between machines is assumed.
//!
//! Layering here mirrors the rest of `core/`:
//! - wire structs + validation + state derivation (pure, unit-tested),
//! - channel IO via short-lived git clones (stateless; every operation
//!   re-clones so a crash cannot leave a half-written working copy),
//! - DB import through [`crate::core::skill_store::SkillStore`] methods
//!   (projection only — the channel stays the source of truth).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::git_command::git_command;
use super::git_credentials::credential_env_for_url;
use super::skill_store::SkillStore;

pub const DEVICE_PROTOCOL_VERSION: u32 = 1;

// ── Settings keys ──

pub const SETTING_DEVICE_CHANNEL_URL: &str = "device_channel_url";
pub const SETTING_DEVICE_CHANNEL_BRANCH: &str = "device_channel_branch";
pub const SETTING_DEVICE_LOCAL_ID: &str = "device_local_id";
pub const SETTING_DEVICE_LOCAL_NAME: &str = "device_local_name";
pub const SETTING_DEVICE_ONLINE_THRESHOLD_SECS: &str = "device_online_threshold_secs";

pub const DEFAULT_CHANNEL_BRANCH: &str = "skills-manager-devices";
pub const DEFAULT_ONLINE_THRESHOLD_SECS: i64 = 900;

// ── Task states (device_instructions.state) ──

pub const TASK_STATE_PENDING: &str = "pending";
pub const TASK_STATE_EXECUTING: &str = "executing";
pub const TASK_STATE_SUCCESS: &str = "success";
pub const TASK_STATE_FAILED: &str = "failed";
pub const TASK_STATE_DEVICE_OFFLINE: &str = "device_offline";
pub const TASK_STATE_STALE: &str = "stale";
pub const TASK_STATE_EXPIRED: &str = "expired";

pub const ACTION_DEPLOY: &str = "deploy";
pub const ACTION_UNDEPLOY: &str = "undeploy";

const RECEIPT_STATUS_SUCCESS: &str = "success";
const RECEIPT_STATUS_FAILED: &str = "failed";
const RECEIPT_STATUS_REJECTED: &str = "rejected";

// ── Channel wire structs ──
//
// Parsing is strict (`deny_unknown_fields`): a typo'd or hostile field must
// surface as a warning on refresh, never silently change device state.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceManifest {
    pub schema: u32,
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub first_seen: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStateReport {
    pub schema: u32,
    pub device_id: String,
    pub reported_at: i64,
    /// Instruction ids the executor has picked up but not finished. Purely
    /// informational for the UI ("executing"); receipts remain the only
    /// source of a final outcome.
    #[serde(default)]
    pub executing: Vec<String>,
    #[serde(default)]
    pub agents: Vec<AgentStateReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStateReport {
    pub key: String,
    #[serde(default)]
    pub skills: Vec<AgentSkillReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSkillReport {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployed_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInstruction {
    pub schema: u32,
    pub id: String,
    pub device_id: String,
    /// `deploy` or `undeploy` — deliberately the only two remote actions.
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_subpath: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_name: Option<String>,
    pub agent_key: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReceipt {
    pub schema: u32,
    pub instruction_id: String,
    pub device_id: String,
    /// `success`, `failed` or `rejected` (rejected = the executor refused,
    /// e.g. allow-list or conflict — nothing was written).
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Commit in which the instruction file was first published (resolved via
    /// git log, not the head of the fetch — the channel advances when devices
    /// push receipts and state). A receipt whose commit differs from the
    /// instruction's publish commit is displayed as stale, never as success;
    /// re-publishing an instruction changes its commit and invalidates older
    /// receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_version: Option<String>,
    pub finished_at: i64,
}

// ── DB row structs (mirrors of the device tables) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    pub platform: Option<String>,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub last_state_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSkillRecordRow {
    pub device_id: String,
    pub agent_key: String,
    pub skill_name: String,
    pub content_hash: Option<String>,
    pub deployed_at: Option<i64>,
    pub reported_commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInstructionRow {
    pub id: String,
    pub device_id: String,
    pub action: String,
    pub skill_url: Option<String>,
    pub skill_branch: Option<String>,
    pub skill_subpath: Option<String>,
    pub skill_name: Option<String>,
    pub agent_key: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub created_by: Option<String>,
    pub instruction_commit: Option<String>,
    pub receipt_commit: Option<String>,
    pub state: String,
    pub receipt_status: Option<String>,
    pub receipt_reason: Option<String>,
    pub receipt_detail: Option<String>,
    pub receipt_at: Option<i64>,
    pub executor_version: Option<String>,
}

// ── Validation ──

pub fn validate_device_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        bail!("invalid device id {id:?}: expected 1-64 characters of [A-Za-z0-9-]");
    }
    Ok(())
}

pub fn validate_instruction_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        bail!("invalid instruction id {id:?}: expected 1-64 characters of [A-Za-z0-9-]");
    }
    Ok(())
}

pub fn validate_agent_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 64
        || !key
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    {
        bail!("invalid agent key {key:?}: expected 1-64 characters of [a-z0-9_-]");
    }
    Ok(())
}

/// Only network schemes are accepted: instructions travel through untrusted
/// machines, and `file://` would let a channel writer copy arbitrary local
/// paths into an agent directory. `git://` stays allowed for air-gapped LAN
/// mirrors served by `git daemon`. The executor authenticates via the same
/// per-host credential storage as Git Backup — never via URLs (checked below).
pub fn validate_skill_url(url: Option<&str>) -> Result<()> {
    let url = url.ok_or_else(|| anyhow::anyhow!("skill_url is required for deploy"))?;
    let ok = url.starts_with("https://") || url.starts_with("git://");
    if !ok {
        bail!("skill_url must use https:// or git://");
    }
    if url.len() > 500
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
        || url.contains('@')
    {
        bail!("skill_url must be a plain network URL without embedded credentials");
    }
    Ok(())
}

/// Subpaths end up inside filesystem paths on the device: reject traversal
/// and separators that are not part of a plain repo-relative POSIX path.
pub fn validate_skill_subpath(subpath: Option<&str>) -> Result<()> {
    let subpath = match subpath {
        None => return Ok(()),
        Some(s) if s.is_empty() => return Ok(()),
        Some(s) => s,
    };
    if subpath.len() > 256 || subpath.contains('\\') || subpath.contains("..") {
        bail!("invalid skill_subpath {subpath:?}");
    }
    let segments = subpath.split('/');
    if subpath.starts_with('/') || subpath.ends_with('/') {
        bail!("invalid skill_subpath {subpath:?}");
    }
    if segments.clone().any(|s| s.is_empty() || s == ".") {
        bail!("invalid skill_subpath {subpath:?}");
    }
    Ok(())
}

pub fn validate_device_name(name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() || name.len() > 100 {
        bail!("device name must be 1-100 characters");
    }
    Ok(())
}

pub fn validate_instruction(inst: &DeviceInstruction) -> Result<()> {
    validate_instruction_id(&inst.id)?;
    validate_device_id(&inst.device_id)?;
    validate_agent_key(&inst.agent_key)?;
    if inst.schema != DEVICE_PROTOCOL_VERSION {
        bail!("unsupported instruction schema {}", inst.schema);
    }
    match inst.action.as_str() {
        ACTION_DEPLOY => {
            validate_skill_url(inst.skill_url.as_deref())?;
            validate_skill_subpath(inst.skill_subpath.as_deref())?;
            if inst.skill_name.as_deref().unwrap_or("").trim().is_empty() {
                bail!("skill_name is required for deploy");
            }
        }
        ACTION_UNDEPLOY => {
            if inst.skill_name.as_deref().unwrap_or("").trim().is_empty() {
                bail!("skill_name is required for undeploy");
            }
            validate_skill_subpath(inst.skill_subpath.as_deref())?;
        }
        other => bail!("unknown instruction action {other:?}"),
    }
    if inst.created_at <= 0 {
        bail!("instruction created_at must be a unix timestamp");
    }
    if let Some(expires) = inst.expires_at {
        if expires <= inst.created_at {
            bail!("instruction expires_at must be after created_at");
        }
    }
    Ok(())
}

pub fn validate_manifest(manifest: &DeviceManifest) -> Result<()> {
    if manifest.schema != DEVICE_PROTOCOL_VERSION {
        bail!("unsupported device manifest schema {}", manifest.schema);
    }
    validate_device_id(&manifest.id)?;
    validate_device_name(&manifest.name)?;
    if manifest.first_seen <= 0 {
        bail!("device manifest first_seen must be a unix timestamp");
    }
    Ok(())
}

pub fn validate_state_report(report: &DeviceStateReport) -> Result<()> {
    if report.schema != DEVICE_PROTOCOL_VERSION {
        bail!("unsupported state report schema {}", report.schema);
    }
    validate_device_id(&report.device_id)?;
    if report.reported_at <= 0 {
        bail!("state report reported_at must be a unix timestamp");
    }
    for id in &report.executing {
        validate_instruction_id(id)?;
    }
    for agent in &report.agents {
        validate_agent_key(&agent.key)?;
        for skill in &agent.skills {
            if skill.name.trim().is_empty() || skill.name.len() > 200 {
                bail!("invalid skill name in state report: {:?}", skill.name);
            }
        }
    }
    Ok(())
}

pub const RECEIPT_REASONS: &[&str] = &[
    "none",
    "conflict",
    "expired",
    "unknown_agent",
    "unauthorized_device",
    "invalid_instruction",
    "execution_error",
    "publish_error",
];

pub fn validate_receipt(receipt: &DeviceReceipt) -> Result<()> {
    if receipt.schema != DEVICE_PROTOCOL_VERSION {
        bail!("unsupported receipt schema {}", receipt.schema);
    }
    validate_instruction_id(&receipt.instruction_id)?;
    validate_device_id(&receipt.device_id)?;
    match receipt.status.as_str() {
        RECEIPT_STATUS_SUCCESS | RECEIPT_STATUS_FAILED | RECEIPT_STATUS_REJECTED => {}
        other => bail!("unknown receipt status {other:?}"),
    }
    if let Some(reason) = &receipt.reason {
        if !RECEIPT_REASONS.contains(&reason.as_str()) {
            bail!("unknown receipt reason {reason:?}");
        }
    }
    if receipt.finished_at <= 0 {
        bail!("receipt finished_at must be a unix timestamp");
    }
    if receipt.status == RECEIPT_STATUS_SUCCESS && receipt.instruction_commit.is_none() {
        // A success must name the commit it acted on; without it the outcome
        // cannot be told apart from a stale success and is refused outright.
        bail!("success receipt must record instruction_commit");
    }
    Ok(())
}

/// Receipts are only meaningful against their instruction: ids and device
/// must match, or the receipt is refused on import.
pub fn validate_receipt_against(receipt: &DeviceReceipt, inst: &DeviceInstruction) -> Result<()> {
    validate_receipt(receipt)?;
    if receipt.instruction_id != inst.id {
        bail!(
            "receipt {} does not match instruction {}",
            receipt.instruction_id,
            inst.id
        );
    }
    if receipt.device_id != inst.device_id {
        bail!(
            "receipt device {} does not match instruction device {}",
            receipt.device_id,
            inst.device_id
        );
    }
    Ok(())
}

// ── State derivation ──

/// The receipt slice the derivation needs, so both `DeviceReceipt` values and
/// imported DB rows can drive the same rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptView<'a> {
    pub status: &'a str,
    pub instruction_commit: Option<&'a str>,
}

/// Single source of truth for the states shown in the UI (docs/devices.md):
/// receipt verdicts first, then TTL, then device freshness, then in-flight.
pub fn derive_task_state(
    expires_at: Option<i64>,
    instruction_commit: Option<&str>,
    receipt: Option<ReceiptView<'_>>,
    executing: bool,
    last_seen_at: Option<i64>,
    online_threshold_secs: i64,
    now: i64,
) -> &'static str {
    if let Some(receipt) = receipt {
        let verified = match (receipt.instruction_commit, instruction_commit) {
            (Some(rc), Some(ic)) => rc == ic,
            _ => false,
        };
        if !verified {
            // A receipt for another commit (or without one) must not stand in
            // for the current instruction — including a stale success.
            return TASK_STATE_STALE;
        }
        return if receipt.status == RECEIPT_STATUS_SUCCESS {
            TASK_STATE_SUCCESS
        } else {
            TASK_STATE_FAILED
        };
    }
    if let Some(expires) = expires_at {
        if now > expires {
            return TASK_STATE_EXPIRED;
        }
    }
    let last_seen_fresh = last_seen_at
        .map(|seen| now - seen <= online_threshold_secs)
        .unwrap_or(false);
    if !last_seen_fresh {
        return TASK_STATE_DEVICE_OFFLINE;
    }
    if executing {
        return TASK_STATE_EXECUTING;
    }
    TASK_STATE_PENDING
}

// ── Settings helpers ──

pub fn channel_branch(store: &SkillStore) -> String {
    store
        .get_setting(SETTING_DEVICE_CHANNEL_BRANCH)
        .ok()
        .flatten()
        .filter(|b| !b.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_CHANNEL_BRANCH.to_string())
}

pub fn channel_url(store: &SkillStore) -> Option<String> {
    store
        .get_setting(SETTING_DEVICE_CHANNEL_URL)
        .ok()
        .flatten()
        .filter(|u| !u.trim().is_empty())
}

pub fn set_channel_config(store: &SkillStore, url: Option<&str>, branch: Option<&str>) -> Result<()> {
    if let Some(branch) = branch {
        validate_branch_name(branch)?;
        store.set_setting(SETTING_DEVICE_CHANNEL_BRANCH, branch.trim())?;
    }
    match url {
        Some(url) => {
            let url = url.trim();
            if !url.is_empty() {
                if !url.starts_with("https://") || url.chars().any(|c| c.is_whitespace()) {
                    bail!("channel URL must be a plain https URL");
                }
                store.set_setting(SETTING_DEVICE_CHANNEL_URL, url)?;
            } else {
                store.set_setting(SETTING_DEVICE_CHANNEL_URL, "")?;
            }
        }
        None => {}
    }
    Ok(())
}

pub fn validate_branch_name(branch: &str) -> Result<()> {
    let branch = branch.trim();
    let ok = !branch.is_empty()
        && branch.len() <= 100
        && !branch.starts_with('-')
        && !branch.contains("..")
        && branch
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        && !branch.ends_with('/')
        && !branch.ends_with(".lock");
    if ok {
        Ok(())
    } else {
        bail!("invalid branch name {branch:?}");
    }
}

/// Stable id for the local device, generated on first use. Also used by the
/// executor CLI so the app and the executor agree on who "this machine" is.
pub fn local_device_id(store: &SkillStore) -> Result<String> {
    if let Some(id) = store.get_setting(SETTING_DEVICE_LOCAL_ID)? {
        if !id.trim().is_empty() {
            return Ok(id);
        }
    }
    let id = format!("dev-{}", uuid::Uuid::new_v4().simple());
    store.set_setting(SETTING_DEVICE_LOCAL_ID, &id)?;
    Ok(id)
}

pub fn local_device_name(store: &SkillStore) -> String {
    if let Ok(Some(name)) = store.get_setting(SETTING_DEVICE_LOCAL_NAME) {
        if !name.trim().is_empty() {
            return name;
        }
    }
    gethostname::gethostname().to_string_lossy().to_string()
}

pub fn set_local_device_name(store: &SkillStore, name: &str) -> Result<()> {
    validate_device_name(name)?;
    store.set_setting(SETTING_DEVICE_LOCAL_NAME, name.trim())
}

pub fn online_threshold_secs(store: &SkillStore) -> i64 {
    store
        .get_setting(SETTING_DEVICE_ONLINE_THRESHOLD_SECS)
        .ok()
        .flatten()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_ONLINE_THRESHOLD_SECS)
}

pub fn is_device_online(last_seen_at: Option<i64>, threshold_secs: i64, now: i64) -> bool {
    last_seen_at
        .map(|seen| now - seen <= threshold_secs)
        .unwrap_or(false)
}

// ── Channel IO (git) ──

/// Strips userinfo from a URL before it lands in an error message or log.
pub fn redact_url(url: &str) -> String {
    if let Some(scheme_end) = url.find("://") {
        let rest = &url[scheme_end + 3..];
        if let Some(at) = rest.find('@') {
            let host_part = &rest[at + 1..];
            return format!("{}://***@{}", &url[..scheme_end], host_part);
        }
    }
    url.to_string()
}

fn run_git(dir: Option<&Path>, creds_for_url: Option<&str>, args: &[&str]) -> Result<String> {
    let mut cmd: Command = git_command();
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    if let Some(url) = creds_for_url {
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        for (key, value) in credential_env_for_url(url) {
            cmd.env(key, value);
        }
    }
    let output = cmd
        .args(args)
        .output()
        .with_context(|| format!("failed to run git {}", args.first().unwrap_or(&"")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// A short-lived working copy of the channel branch. Everything is cloned,
/// edited and pushed within one call, so a crash never leaves state behind —
/// channels are a few JSON files, a full clone is cheap.
fn prepare_working_copy(url: &str, branch: &str) -> Result<(tempfile::TempDir, PathBuf)> {
    let tmp = tempfile::tempdir().context("failed to create temp dir for device channel")?;
    let dir = tmp.path().to_path_buf();
    let clone_ok = run_git(
        None,
        Some(url),
        &[
            "clone",
            "--branch",
            branch,
            "--single-branch",
            url,
            &dir.to_string_lossy(),
        ],
    )
    .is_ok();
    if !clone_ok {
        // Likely an empty remote (or the branch does not exist yet): start the
        // branch from scratch. If the remote actually had history, the push
        // below is rejected as non-fast-forward and surfaces as an error.
        run_git(None, None, &["init", "-b", branch, &dir.to_string_lossy()])?;
        run_git(Some(&dir), None, &["remote", "add", "origin", url])?;
    }
    Ok((tmp, dir))
}

fn commit_and_push(dir: &Path, url: &str, branch: &str, author: &str, message: &str) -> Result<String> {
    run_git(Some(dir), None, &["add", "-A"])?;
    let staged = run_git(Some(dir), None, &["status", "--porcelain"])?;
    if !staged.trim().is_empty() {
        run_git(
            Some(dir),
            None,
            &[
                "-c",
                &format!("user.name={author}"),
                "-c",
                "user.email=devices@skills-manager.local",
                "commit",
                "-m",
                message,
            ],
        )?;
        run_git(Some(dir), Some(url), &["push", "origin", branch])?;
    }
    Ok(run_git(Some(dir), None, &["rev-parse", "HEAD"])?.trim().to_string())
}

fn ensure_protocol_file(dir: &Path) -> Result<()> {
    let path = dir.join("protocol.json");
    if !path.exists() {
        std::fs::write(
            &path,
            format!("{{\"schema\": {DEVICE_PROTOCOL_VERSION}}}\n"),
        )
        .context("failed to write protocol.json")?;
    }
    Ok(())
}

fn device_dir_name(device_id: &str) -> Result<String> {
    validate_device_id(device_id)?;
    Ok(format!("devices/{device_id}"))
}

/// Publishes device identity and (re)publishes instructions. Returns the head
/// commit the files landed at — recorded as the instruction's import commit,
/// which later receipt matching is checked against.
pub fn publish_instructions(
    url: &str,
    branch: &str,
    manifest: Option<&DeviceManifest>,
    instructions: &[DeviceInstruction],
) -> Result<String> {
    for inst in instructions {
        validate_instruction(inst)?;
    }
    if let Some(manifest) = manifest {
        validate_manifest(manifest)?;
    }
    let (_tmp, dir) = prepare_working_copy(url, branch)?;
    ensure_protocol_file(&dir)?;
    if let Some(manifest) = manifest {
        let base = dir.join(device_dir_name(&manifest.id)?);
        std::fs::create_dir_all(&base)?;
        let path = base.join("device.json");
        std::fs::write(&path, serde_json::to_vec_pretty(manifest)?)?;
    }
    for inst in instructions {
        let base = dir.join(device_dir_name(&inst.device_id)?).join("instructions");
        std::fs::create_dir_all(&base)?;
        let path = base.join(format!("{}.json", inst.id));
        std::fs::write(&path, serde_json::to_vec_pretty(inst)?)?;
    }
    let author = manifest
        .map(|m| m.name.clone())
        .unwrap_or_else(|| "Skills Manager".to_string());
    commit_and_push(&dir, url, branch, &author, "devices: update instructions")
}

pub fn publish_receipt(url: &str, branch: &str, receipt: &DeviceReceipt) -> Result<String> {
    publish_executor_update(url, branch, std::slice::from_ref(receipt), None)
}

/// Publishes a batch of receipts plus the executor's state report in a single
/// commit: one clone, one push — fewer round-trips on flaky links.
pub fn publish_executor_update(
    url: &str,
    branch: &str,
    receipts: &[DeviceReceipt],
    state: Option<&DeviceStateReport>,
) -> Result<String> {
    for receipt in receipts {
        validate_receipt(receipt)?;
    }
    if let Some(report) = state {
        validate_state_report(report)?;
    }
    let (_tmp, dir) = prepare_working_copy(url, branch)?;
    ensure_protocol_file(&dir)?;
    for receipt in receipts {
        let base = dir
            .join(device_dir_name(&receipt.device_id)?)
            .join("receipts");
        std::fs::create_dir_all(&base)?;
        let path = base.join(format!("{}.json", receipt.instruction_id));
        std::fs::write(&path, serde_json::to_vec_pretty(receipt)?)?;
    }
    if let Some(report) = state {
        let base = dir.join(device_dir_name(&report.device_id)?);
        std::fs::create_dir_all(&base)?;
        let path = base.join("state.json");
        std::fs::write(&path, serde_json::to_vec_pretty(report)?)?;
    }
    commit_and_push(&dir, url, branch, "Skills Manager", "devices: executor update")
}

/// Clones a skill source repository to a temp dir for the executor. Returns
/// the temp dir (must stay alive while the source is read) and the checkout
/// path.
pub fn fetch_skill_source(url: &str, branch: Option<&str>) -> Result<(tempfile::TempDir, PathBuf)> {
    let tmp = tempfile::tempdir().context("failed to create temp dir for skill source")?;
    let dir = tmp.path().to_path_buf();
    let mut args: Vec<String> = vec!["clone".to_string()];
    if let Some(branch) = branch {
        args.push("--branch".to_string());
        args.push(branch.to_string());
    }
    args.push(url.to_string());
    args.push(dir.to_string_lossy().to_string());
    let argrefs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_git(None, Some(url), &argrefs)?;
    Ok((tmp, dir))
}

/// Skill directory names become filesystem paths on the device: enforce a
/// conservative charset so a channel file can never smuggle a separator or
/// traversal into the target path.
pub fn validate_skill_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 100
        && name != "."
        && name != ".."
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(())
    } else {
        bail!("invalid skill name {name:?}");
    }
}

pub fn publish_state_report(url: &str, branch: &str, report: &DeviceStateReport) -> Result<String> {
    validate_state_report(report)?;
    let (_tmp, dir) = prepare_working_copy(url, branch)?;
    ensure_protocol_file(&dir)?;
    let base = dir.join(device_dir_name(&report.device_id)?);
    std::fs::create_dir_all(&base)?;
    let path = base.join("state.json");
    std::fs::write(&path, serde_json::to_vec_pretty(report)?)?;
    commit_and_push(&dir, url, branch, "Skills Manager", "devices: report state")
}

#[derive(Debug, Default)]
pub struct ChannelSnapshot {
    pub head_commit: String,
    pub manifests: Vec<DeviceManifest>,
    pub states: Vec<DeviceStateReport>,
    pub instructions: Vec<(DeviceInstruction, String)>,
    pub receipts: Vec<(DeviceReceipt, String)>,
    /// Channel files that failed validation. They are skipped — one bad file
    /// must not blind the whole page — but they are never silent.
    pub warnings: Vec<String>,
}

fn parse_json_file<T: for<'de> Deserialize<'de>>(
    path: &Path,
    warnings: &mut Vec<String>,
) -> Option<T> {
    // Optional files (device.json / state.json) are routinely absent — that
    // is normal channel state, not a problem. Only a file that exists but
    // cannot be read or parsed is worth a warning.
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            warnings.push(format!("{}: unreadable ({err})", path.display()));
            return None;
        }
    };
    match serde_json::from_slice::<T>(&bytes) {
        Ok(value) => Some(value),
        Err(err) => {
            warnings.push(format!("{}: invalid ({err})", path.display()));
            None
        }
    }
}

/// Resolves the commit in which a channel file was first added. Receipt
/// matching is checked against this commit, so it must be the instruction's
/// actual publish commit — not the head of whatever refresh happens to see
/// the file first (the device may act, and land receipts, before the
/// manager's first import).
fn file_creation_commit(dir: &Path, rel_path: &str) -> Option<String> {
    let out = run_git(
        Some(dir),
        None,
        &[
            "log",
            "--format=%H",
            "--diff-filter=A",
            "-1",
            "--",
            rel_path,
        ],
    )
    .ok()?;
    let commit = out.trim().to_string();
    if commit.is_empty() {
        None
    } else {
        Some(commit)
    }
}

/// Reads the whole channel and validates everything it can. Items that fail
/// validation are dropped with a warning rather than aborting the refresh.
pub fn fetch_channel_snapshot(url: &str, branch: &str) -> Result<ChannelSnapshot> {
    let (tmp, dir) = prepare_working_copy(url, branch)?;
    // A freshly initialized channel has no commits yet; that is normal.
    let head_commit = run_git(Some(&dir), None, &["rev-parse", "--verify", "HEAD"])
        .unwrap_or_default()
        .trim()
        .to_string();
    let mut snapshot = ChannelSnapshot {
        head_commit: head_commit.clone(),
        ..Default::default()
    };

    let devices_root = dir.join("devices");
    let device_entries = match std::fs::read_dir(&devices_root) {
        Ok(entries) => entries,
        Err(_) => return Ok(snapshot), // fresh channel, nothing published yet
    };

    for entry in device_entries.flatten() {
        let device_id = entry.file_name().to_string_lossy().to_string();
        if device_id.starts_with('.') {
            continue;
        }
        if validate_device_id(&device_id).is_err() {
            snapshot
                .warnings
                .push(format!("devices/{device_id}: skipped, invalid device id"));
            continue;
        }
        let device_dir = entry.path();

        if let Some(manifest) =
            parse_json_file::<DeviceManifest>(&device_dir.join("device.json"), &mut snapshot.warnings)
        {
            match validate_manifest(&manifest) {
                Ok(()) => snapshot.manifests.push(manifest),
                Err(err) => snapshot
                    .warnings
                    .push(format!("devices/{device_id}/device.json: {err}")),
            }
        }

        if let Some(report) =
            parse_json_file::<DeviceStateReport>(&device_dir.join("state.json"), &mut snapshot.warnings)
        {
            match validate_state_report(&report) {
                Ok(()) => snapshot.states.push(report),
                Err(err) => snapshot
                    .warnings
                    .push(format!("devices/{device_id}/state.json: {err}")),
            }
        }

        for file_name in ["instructions", "receipts"] {
            let sub = device_dir.join(file_name);
            let files = match std::fs::read_dir(&sub) {
                Ok(files) => files,
                Err(_) => continue,
            };
            for file in files.flatten() {
                let name = file.file_name().to_string_lossy().to_string();
                if !name.ends_with(".json") {
                    continue;
                }
                let id = name.trim_end_matches(".json").to_string();
                if validate_instruction_id(&id).is_err() {
                    snapshot
                        .warnings
                        .push(format!("devices/{device_id}/{file_name}/{name}: invalid id"));
                    continue;
                }
                if file_name == "instructions" {
                    if let Some(inst) =
                        parse_json_file::<DeviceInstruction>(&file.path(), &mut snapshot.warnings)
                    {
                        // The filename is part of the contract: an instruction
                        // claiming a different id than its file is refused.
                        if inst.id != id {
                            snapshot.warnings.push(format!(
                                "devices/{device_id}/instructions/{name}: id mismatch"
                            ));
                            continue;
                        }
                        match validate_instruction(&inst) {
                            Ok(()) => {
                                let commit = file_creation_commit(
                                    &dir,
                                    &format!("devices/{device_id}/instructions/{name}"),
                                )
                                .unwrap_or_else(|| head_commit.clone());
                                snapshot.instructions.push((inst, commit));
                            }
                            Err(err) => snapshot.warnings.push(format!(
                                "devices/{device_id}/instructions/{name}: {err}"
                            )),
                        }
                    }
                } else if let Some(receipt) =
                    parse_json_file::<DeviceReceipt>(&file.path(), &mut snapshot.warnings)
                {
                    match validate_receipt(&receipt) {
                        Ok(()) => snapshot.receipts.push((receipt, head_commit.clone())),
                        Err(err) => snapshot.warnings.push(format!(
                            "devices/{device_id}/receipts/{name}: {err}"
                        )),
                    }
                }
            }
        }
    }

    Ok(snapshot)
}

// ── Import (channel → DB projection) ──

#[derive(Debug, Default, Serialize)]
pub struct ImportSummary {
    pub devices: usize,
    pub states: usize,
    pub instructions: usize,
    pub receipts: usize,
    pub warnings: Vec<String>,
}

/// Rebuilds the DB projection from a snapshot. Idempotent: re-importing the
/// same snapshot is a no-op, and a partially imported (or wiped) database is
/// repaired by the next import. Receipt matching preserves each instruction's
/// first-seen commit so a re-published instruction cannot silently re-validate
/// an old receipt.
pub fn import_snapshot(store: &SkillStore, snapshot: &ChannelSnapshot) -> Result<ImportSummary> {
    let mut summary = ImportSummary {
        warnings: snapshot.warnings.clone(),
        ..Default::default()
    };
    let now = chrono::Utc::now().timestamp();

    let mut manifests_by_id: HashMap<String, &DeviceManifest> = HashMap::new();
    for manifest in &snapshot.manifests {
        manifests_by_id.insert(manifest.id.clone(), manifest);
    }
    let mut states_by_id: HashMap<String, &DeviceStateReport> = HashMap::new();
    for report in &snapshot.states {
        states_by_id.insert(report.device_id.clone(), report);
    }

    // Devices referenced anywhere in the snapshot get a row, so instructions
    // (FK) can attach even before the device's own manifest arrives.
    let mut referenced: Vec<String> = manifests_by_id.keys().cloned().collect();
    referenced.extend(states_by_id.keys().cloned());
    referenced.extend(snapshot.instructions.iter().map(|(i, _)| i.device_id.clone()));
    referenced.extend(snapshot.receipts.iter().map(|(r, _)| r.device_id.clone()));
    referenced.sort();
    referenced.dedup();

    for device_id in &referenced {
        let (name, platform, created_at) = match manifests_by_id.get(device_id) {
            Some(m) => (m.name.clone(), m.platform.clone(), m.first_seen),
            None => (device_id.clone(), None, now),
        };
        store.upsert_device(&DeviceRow {
            id: device_id.clone(),
            name,
            platform,
            created_at,
            last_seen_at: None,
            last_state_commit: None,
        })?;
        summary.devices += 1;
    }

    for report in &snapshot.states {
        store.update_device_last_seen(&report.device_id, report.reported_at, &snapshot.head_commit)?;
        let rows: Vec<DeviceSkillRecordRow> = report
            .agents
            .iter()
            .flat_map(|agent| {
                agent.skills.iter().map(move |skill| DeviceSkillRecordRow {
                    device_id: report.device_id.clone(),
                    agent_key: agent.key.clone(),
                    skill_name: skill.name.clone(),
                    content_hash: skill.content_hash.clone(),
                    deployed_at: skill.deployed_at,
                    reported_commit: Some(snapshot.head_commit.clone()),
                })
            })
            .collect();
        store.replace_device_skill_records(&report.device_id, &rows)?;
        summary.states += 1;
    }

    for (inst, commit) in &snapshot.instructions {
        let row = DeviceInstructionRow {
            id: inst.id.clone(),
            device_id: inst.device_id.clone(),
            action: inst.action.clone(),
            skill_url: inst.skill_url.clone(),
            skill_branch: inst.skill_branch.clone(),
            skill_subpath: inst.skill_subpath.clone(),
            skill_name: inst.skill_name.clone(),
            agent_key: inst.agent_key.clone(),
            created_at: inst.created_at,
            expires_at: inst.expires_at,
            created_by: inst.created_by.clone(),
            instruction_commit: Some(commit.clone()),
            receipt_commit: None,
            state: TASK_STATE_PENDING.to_string(),
            receipt_status: None,
            receipt_reason: None,
            receipt_detail: None,
            receipt_at: None,
            executor_version: None,
        };
        store.upsert_device_instruction(&row)?;
        summary.instructions += 1;
    }

    for (receipt, _commit) in &snapshot.receipts {
        if let Some(existing) = store.get_device_instruction(&receipt.instruction_id)? {
            let inst = DeviceInstruction {
                schema: DEVICE_PROTOCOL_VERSION,
                id: existing.id.clone(),
                device_id: existing.device_id.clone(),
                action: existing.action.clone(),
                skill_url: existing.skill_url.clone(),
                skill_branch: existing.skill_branch.clone(),
                skill_subpath: existing.skill_subpath.clone(),
                skill_name: existing.skill_name.clone(),
                agent_key: existing.agent_key.clone(),
                created_at: existing.created_at,
                expires_at: existing.expires_at,
                created_by: existing.created_by.clone(),
            };
            if let Err(err) = validate_receipt_against(receipt, &inst) {
                summary
                    .warnings
                    .push(format!("receipt {}: refused ({err})", receipt.instruction_id));
                continue;
            }
            store.set_device_instruction_receipt(
                &receipt.instruction_id,
                &receipt.status,
                receipt.reason.as_deref(),
                receipt.detail.as_deref(),
                receipt.instruction_commit.as_deref(),
                receipt.finished_at,
                receipt.executor_version.as_deref(),
            )?;
            summary.receipts += 1;
        }
    }

    // Recompute the projection for every instruction: cheap (a handful of
    // rows) and immune to ordering effects between receipts and states.
    let threshold = online_threshold_secs(store);
    let executing_by_device: HashMap<String, Vec<String>> = states_by_id
        .iter()
        .map(|(id, report)| (id.clone(), report.executing.clone()))
        .collect();
    let devices = store.get_devices()?;
    let last_seen_by_id: HashMap<String, Option<i64>> = devices
        .iter()
        .map(|d| (d.id.clone(), d.last_seen_at))
        .collect();

    for row in store.get_device_instructions(None)? {
        let executing = executing_by_device
            .get(&row.device_id)
            .map(|ids| ids.contains(&row.id))
            .unwrap_or(false);
        let receipt = row.receipt_status.as_deref().map(|status| ReceiptView {
            status,
            instruction_commit: row.receipt_commit.as_deref(),
        });
        let state = derive_task_state(
            row.expires_at,
            row.instruction_commit.as_deref(),
            receipt,
            executing,
            last_seen_by_id.get(&row.device_id).copied().flatten(),
            threshold,
            now,
        );
        if state != row.state {
            store.set_device_instruction_state(&row.id, state)?;
        }
    }

    Ok(summary)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn instruction(id: &str) -> DeviceInstruction {
        DeviceInstruction {
            schema: DEVICE_PROTOCOL_VERSION,
            id: id.to_string(),
            device_id: "dev-test".to_string(),
            action: ACTION_DEPLOY.to_string(),
            skill_url: Some("https://example.com/skills.git".to_string()),
            skill_branch: Some("main".to_string()),
            skill_subpath: Some("skills/demo".to_string()),
            skill_name: Some("demo".to_string()),
            agent_key: "codex".to_string(),
            created_at: 1_000,
            expires_at: Some(2_000),
            created_by: Some("tester".to_string()),
        }
    }

    #[test]
    fn instruction_validation_accepts_and_rejects() {
        assert!(validate_instruction(&instruction("inst-ok")).is_ok());

        let mut bad = instruction("inst-bad");
        bad.action = "shell".to_string();
        assert!(validate_instruction(&bad).is_err(), "unknown actions refused");

        let mut bad = instruction("inst-bad");
        bad.skill_url = Some("http://example.com/skills.git".to_string());
        assert!(validate_instruction(&bad).is_err(), "non-https refused");

        let mut git_proto = instruction("inst-git");
        git_proto.skill_url = Some("git://example.com/skills.git".to_string());
        assert!(validate_instruction(&git_proto).is_ok(), "git:// allowed for LAN mirrors");

        let mut bad = instruction("inst-bad");
        bad.skill_url = Some("file:///etc/passwd".to_string());
        assert!(validate_instruction(&bad).is_err(), "file:// refused");

        let mut bad = instruction("inst-bad");
        bad.skill_url = Some("https://token@example.com/skills.git".to_string());
        assert!(validate_instruction(&bad).is_err(), "embedded credentials refused");

        let mut bad = instruction("inst-bad");
        bad.skill_subpath = Some("skills/../../etc".to_string());
        assert!(validate_instruction(&bad).is_err(), "traversal refused");

        let mut bad = instruction("inst-bad");
        bad.agent_key = "Bad Key".to_string();
        assert!(validate_instruction(&bad).is_err(), "agent key charset enforced");

        let mut bad = instruction("inst-bad");
        bad.expires_at = Some(500);
        assert!(validate_instruction(&bad).is_err(), "TTL must outlive creation");
    }

    #[test]
    fn unknown_fields_are_refused() {
        let raw = br#"{
            "schema": 1,
            "id": "inst-x",
            "device_id": "dev-x",
            "action": "deploy",
            "skill_url": "https://example.com/s.git",
            "agent_key": "codex",
            "created_at": 1,
            "extra_field": true
        }"#;
        let parsed: Result<DeviceInstruction, _> = serde_json::from_slice(raw);
        assert!(parsed.is_err(), "deny_unknown_fields must refuse extras");

        let receipt_raw = br#"{
            "schema": 1,
            "instruction_id": "inst-x",
            "device_id": "dev-x",
            "status": "success",
            "instruction_commit": "abc",
            "finished_at": 5,
            "hijacked": "field"
        }"#;
        let parsed: Result<DeviceReceipt, _> = serde_json::from_slice(receipt_raw);
        assert!(parsed.is_err());
    }

    #[test]
    fn success_receipt_without_commit_is_refused() {
        let receipt = DeviceReceipt {
            schema: DEVICE_PROTOCOL_VERSION,
            instruction_id: "inst-x".to_string(),
            device_id: "dev-x".to_string(),
            status: RECEIPT_STATUS_SUCCESS.to_string(),
            reason: None,
            instruction_commit: None,
            detail: None,
            executor_version: None,
            finished_at: 5,
        };
        assert!(validate_receipt(&receipt).is_err());

        let with_commit = DeviceReceipt {
            instruction_commit: Some("abc".to_string()),
            ..receipt
        };
        assert!(validate_receipt(&with_commit).is_ok());
    }

    #[test]
    fn receipt_must_belong_to_its_instruction() {
        let inst = instruction("inst-a");
        let receipt = DeviceReceipt {
            schema: DEVICE_PROTOCOL_VERSION,
            instruction_id: "inst-b".to_string(),
            device_id: "dev-test".to_string(),
            status: RECEIPT_STATUS_SUCCESS.to_string(),
            reason: None,
            instruction_commit: Some("abc".to_string()),
            detail: None,
            executor_version: None,
            finished_at: 5,
        };
        assert!(validate_receipt_against(&receipt, &inst).is_err());

        let receipt = DeviceReceipt {
            instruction_id: "inst-a".to_string(),
            device_id: "dev-other".to_string(),
            ..receipt
        };
        assert!(validate_receipt_against(&receipt, &inst).is_err());
    }

    #[test]
    fn task_state_rules() {
        let now = 10_000;
        let seen = |ago: i64| Some(now - ago);

        // Pending: fresh device, no receipt, in TTL.
        assert_eq!(
            derive_task_state(Some(20_000), Some("c1"), None, false, seen(60), 900, now),
            TASK_STATE_PENDING
        );
        // Executing requires a fresh heartbeat; a stale one means the device
        // died mid-run and must show offline, not executing.
        assert_eq!(
            derive_task_state(Some(20_000), Some("c1"), None, true, seen(60), 900, now),
            TASK_STATE_EXECUTING
        );
        assert_eq!(
            derive_task_state(Some(20_000), Some("c1"), None, true, seen(2_000), 900, now),
            TASK_STATE_DEVICE_OFFLINE
        );
        // No report at all → offline, regardless of the instruction.
        assert_eq!(
            derive_task_state(Some(20_000), Some("c1"), None, false, None, 900, now),
            TASK_STATE_DEVICE_OFFLINE
        );
        // TTL passed without a receipt → expired even while the device is fresh.
        assert_eq!(
            derive_task_state(Some(9_000), Some("c1"), None, false, seen(60), 900, now),
            TASK_STATE_EXPIRED
        );
        // Success only when the receipt names the very commit we imported.
        assert_eq!(
            derive_task_state(
                Some(20_000),
                Some("c1"),
                Some(ReceiptView { status: "success", instruction_commit: Some("c1") }),
                false,
                seen(60),
                900,
                now
            ),
            TASK_STATE_SUCCESS
        );
        // A success for an older commit is stale, never success.
        assert_eq!(
            derive_task_state(
                Some(20_000),
                Some("c2"),
                Some(ReceiptView { status: "success", instruction_commit: Some("c1") }),
                false,
                seen(60),
                900,
                now
            ),
            TASK_STATE_STALE
        );
        // Failed for the current commit shows failed.
        assert_eq!(
            derive_task_state(
                Some(20_000),
                Some("c1"),
                Some(ReceiptView { status: "rejected", instruction_commit: Some("c1") }),
                false,
                seen(60),
                900,
                now
            ),
            TASK_STATE_FAILED
        );
    }

    #[test]
    fn subpath_validation() {
        assert!(validate_skill_subpath(Some("skills/demo")).is_ok());
        assert!(validate_skill_subpath(Some("")).is_ok());
        assert!(validate_skill_subpath(Some("skills/../demo")).is_err());
        assert!(validate_skill_subpath(Some("a\\b")).is_err());
        assert!(validate_skill_subpath(Some("/abs")).is_err());
        assert!(validate_skill_subpath(Some("a//b")).is_err());
        assert!(validate_skill_subpath(Some("a/./b")).is_err());
    }

    #[test]
    fn url_redaction() {
        assert_eq!(redact_url("https://example.com/repo.git"), "https://example.com/repo.git");
        assert_eq!(
            redact_url("https://user:secret@example.com/repo.git"),
            "https://***@example.com/repo.git"
        );
    }

    /// End-to-end over a local bare remote: publish instructions, read them
    /// back, publish receipts, and confirm the derived states — the same file
    /// flow the real channel uses, minus the network.
    #[test]
    fn channel_roundtrip_instructions_and_receipts() {
        let tmp = tempfile::tempdir().unwrap();
        let remote_path = tmp.path().join("channel.git");
        std::fs::create_dir_all(&remote_path).unwrap();
        run_git(None, None, &["init", "--bare", &remote_path.to_string_lossy()]).unwrap();
        // Plain filesystem path as the remote URL (portable across platforms).
        let remote_url = remote_path.to_string_lossy().to_string();

        let inst = instruction("inst-roundtrip");
        let head = publish_instructions(&remote_url, "devices-test", None, &[inst.clone()]).unwrap();
        assert_eq!(head.len(), 40, "publish returns the pushed head commit");

        let snapshot = fetch_channel_snapshot(&remote_url, "devices-test").unwrap();
        assert_eq!(snapshot.instructions.len(), 1);
        assert_eq!(snapshot.instructions[0].0.id, "inst-roundtrip");
        assert!(snapshot.warnings.is_empty(), "{:?}", snapshot.warnings);

        // A receipt for the commit the instruction landed at → success.
        let receipt = DeviceReceipt {
            schema: DEVICE_PROTOCOL_VERSION,
            instruction_id: inst.id.clone(),
            device_id: inst.device_id.clone(),
            status: RECEIPT_STATUS_SUCCESS.to_string(),
            reason: Some("none".to_string()),
            instruction_commit: Some(snapshot.instructions[0].1.clone()),
            detail: None,
            executor_version: Some("test".to_string()),
            finished_at: 2_500,
        };
        publish_receipt(&remote_url, "devices-test", &receipt).unwrap();

        let snapshot = fetch_channel_snapshot(&remote_url, "devices-test").unwrap();
        assert_eq!(snapshot.receipts.len(), 1);
        assert_eq!(
            derive_task_state(
                inst.expires_at,
                Some(&snapshot.instructions[0].1),
                Some(ReceiptView {
                    status: &snapshot.receipts[0].0.status,
                    instruction_commit: snapshot.receipts[0].0.instruction_commit.as_deref(),
                }),
                false,
                Some(2_400),
                900,
                2_500
            ),
            TASK_STATE_SUCCESS
        );
    }

    #[test]
    fn publish_refuses_invalid_instructions() {
        let tmp = tempfile::tempdir().unwrap();
        let remote_path = tmp.path().join("channel.git");
        let remote_url = remote_path.to_string_lossy().to_string();
        let mut inst = instruction("inst-bad");
        inst.skill_subpath = Some("../escape".to_string());
        assert!(publish_instructions(&remote_url, "devices-test", None, &[inst]).is_err());
    }

    #[test]
    fn import_snapshot_projects_channel_into_db() {
        let tmp = tempfile::tempdir().unwrap();
        let store = SkillStore::new(&tmp.path().join("test.db")).unwrap();

        let inst = instruction("inst-import");
        let manifest = DeviceManifest {
            schema: DEVICE_PROTOCOL_VERSION,
            id: "dev-test".to_string(),
            name: "Test Dev".to_string(),
            platform: Some("linux".to_string()),
            first_seen: 900,
            executor_version: Some("1.0".to_string()),
        };
        let state = DeviceStateReport {
            schema: DEVICE_PROTOCOL_VERSION,
            device_id: "dev-test".to_string(),
            reported_at: 5_000,
            executing: vec![],
            agents: vec![AgentStateReport {
                key: "codex".to_string(),
                skills: vec![AgentSkillReport {
                    name: "demo".to_string(),
                    content_hash: Some("hash-1".to_string()),
                    deployed_at: Some(4_000),
                }],
            }],
        };
        let mut snapshot = ChannelSnapshot {
            head_commit: "c0ffee".to_string(),
            ..Default::default()
        };
        snapshot.manifests.push(manifest);
        snapshot.states.push(state);
        snapshot.instructions.push((inst.clone(), "c0ffee".to_string()));

        let summary = import_snapshot(&store, &snapshot).unwrap();
        assert_eq!(summary.devices, 1);
        assert_eq!(summary.states, 1);
        assert_eq!(summary.instructions, 1);

        let devices = store.get_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "Test Dev");
        assert_eq!(devices[0].last_seen_at, Some(5_000));
        assert_eq!(devices[0].last_state_commit.as_deref(), Some("c0ffee"));

        let records = store.get_device_skill_records(Some("dev-test")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].agent_key, "codex");
        assert_eq!(records[0].skill_name, "demo");

        // No receipt, TTL (2_000) long past the import-time clock: the
        // projection must say expired, never pending or success.
        let rows = store.get_device_instructions(None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, TASK_STATE_EXPIRED);
        assert_eq!(rows[0].instruction_commit.as_deref(), Some("c0ffee"));

        // A receipt for the matching commit flips the state to failed;
        // a receipt for another device must be refused with a warning.
        let matching = DeviceReceipt {
            schema: DEVICE_PROTOCOL_VERSION,
            instruction_id: inst.id.clone(),
            device_id: inst.device_id.clone(),
            status: RECEIPT_STATUS_FAILED.to_string(),
            reason: Some("conflict".to_string()),
            instruction_commit: Some("c0ffee".to_string()),
            detail: Some("target not managed".to_string()),
            executor_version: Some("1.0".to_string()),
            finished_at: 6_000,
        };
        snapshot.receipts.push((matching, "c0ffee".to_string()));
        let summary = import_snapshot(&store, &snapshot).unwrap();
        assert_eq!(summary.receipts, 1);
        let rows = store.get_device_instructions(None).unwrap();
        assert_eq!(rows[0].state, TASK_STATE_FAILED);
        assert_eq!(rows[0].receipt_reason.as_deref(), Some("conflict"));

        snapshot.receipts.clear();
        snapshot.receipts.push((
            DeviceReceipt {
                schema: DEVICE_PROTOCOL_VERSION,
                instruction_id: inst.id.clone(),
                device_id: "dev-impersonator".to_string(),
                status: RECEIPT_STATUS_SUCCESS.to_string(),
                instruction_commit: Some("c0ffee".to_string()),
                reason: None,
                detail: None,
                executor_version: None,
                finished_at: 7_000,
            },
            "c0ffee".to_string(),
        ));
        let summary = import_snapshot(&store, &snapshot).unwrap();
        assert_eq!(summary.receipts, 0);
        assert!(summary.warnings.iter().any(|w| w.contains("refused")));
        let rows = store.get_device_instructions(None).unwrap();
        assert_eq!(rows[0].state, TASK_STATE_FAILED, "impersonated receipt must not flip state");
    }
}
