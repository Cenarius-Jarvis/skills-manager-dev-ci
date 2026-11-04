//! Device-side executor (see docs/devices.md): a one-shot CLI component that
//! pulls deployment instructions from the control channel, executes them
//! against operator-mapped agent directories, and publishes receipts plus a
//! state report.
//!
//! Design constraints, in priority order:
//! - Never touch anything the executor did not deploy itself. Every action is
//!   journaled locally first; a target path with no journal record is a hard
//!   conflict and is reported, not overwritten.
//! - No resident process: `run_once` fetches, executes, publishes, exits. A
//!   scheduler (cron/systemd timer) or a human invokes it.
//! - The executor owns exactly one directory of state — `device-executor/`
//!   under the app base dir (its journal, its lock file) — and talks only to
//!   the configured channel remote.

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::devices::{
    self, AgentSkillReport, AgentStateReport, DeviceInstruction, DeviceReceipt, DeviceStateReport,
};
use super::central_repo;

const EXECUTOR_STATE_DIR: &str = "device-executor";
const JOURNAL_FILE: &str = "journal.jsonl";
const LOCK_FILE: &str = "executor.lock";

const JOURNAL_STARTED: &str = "started";
const JOURNAL_COMPLETED: &str = "completed";

// Receipt reasons used by this module (validated against devices::RECEIPT_REASONS).
const REASON_CONFLICT: &str = "conflict";
const REASON_EXPIRED: &str = "expired";
const REASON_UNKNOWN_AGENT: &str = "unknown_agent";
const REASON_INVALID_INSTRUCTION: &str = "invalid_instruction";
const REASON_EXECUTION_ERROR: &str = "execution_error";

/// One agent the operator explicitly mapped for this executor. Keys outside
/// this list are refused with `unknown_agent` — the allow-list is the whole
/// authorization model.
#[derive(Debug, Clone)]
pub struct AgentMapping {
    pub key: String,
    pub dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub url: String,
    pub branch: String,
    pub device_id: String,
    pub agents: Vec<AgentMapping>,
    pub max_instructions: usize,
    pub dry_run: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct ExecutorRunReport {
    pub device_id: String,
    pub channel_commit: Option<String>,
    pub considered: usize,
    pub executed: usize,
    pub rejected: usize,
    pub skipped: usize,
    /// True when another executor run held the lock and this one exited
    /// immediately — a benign scheduler overlap, not a failure.
    pub skipped_because_locked: bool,
    /// False when the results (receipts + state) could not be pushed after
    /// retries — the journal keeps them, the next run re-publishes.
    pub published: bool,
    pub publish_error: Option<String>,
    pub details: Vec<String>,
    pub warnings: Vec<String>,
}

/// Append-only journal (JSON lines). One record per state transition; it is
/// both the idempotency guard (a completed instruction is never re-run) and
/// the ownership record that decides which targets the executor may touch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEntry {
    pub instruction_id: String,
    pub instruction_commit: String,
    pub action: String,
    pub agent_key: String,
    pub target: String,
    pub status: String,
    pub ts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DeviceReceipt>,
    /// Fingerprint of the exact deployed tree after a successful write.
    /// Legacy journals without this field do not grant destructive access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_fingerprint: Option<String>,
}

pub struct Journal {
    path: PathBuf,
    entries: Vec<JournalEntry>,
}

impl Journal {
    pub fn load(path: &Path) -> Result<Self> {
        let mut entries = Vec::new();
        match std::fs::read(path) {
            Ok(bytes) => {
                for line in String::from_utf8_lossy(&bytes).lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let entry: JournalEntry = serde_json::from_str(line)
                        .with_context(|| format!("corrupt journal line in {}", path.display()))?;
                    entries.push(entry);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err).context("failed to read executor journal"),
        }
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    pub fn append(&mut self, entry: JournalEntry) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open journal {}", self.path.display()))?;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        self.entries.push(entry);
        Ok(())
    }

    /// A finished run of this exact instruction (same channel commit) — the
    /// skip guard for idempotent re-execution.
    fn completed(&self, instruction_id: &str, commit: &str) -> Option<&JournalEntry> {
        self.entries.iter().find(|e| {
            e.instruction_id == instruction_id
                && e.instruction_commit == commit
                && e.status == JOURNAL_COMPLETED
        })
    }

    /// Only the latest successful completed deploy grants ownership, and only
    /// of the exact on-disk tree recorded after that deploy. Started, failed,
    /// legacy, and completed undeploy records cannot grant ownership.
    fn owned_fingerprint(&self, target: &str) -> Option<&str> {
        self.entries.iter().rev()
            .find(|e| e.target == target && e.status == JOURNAL_COMPLETED)
            .filter(|e| e.action == devices::ACTION_DEPLOY)
            .filter(|e| e.receipt.as_ref().is_some_and(|r| r.status == "success"))
            .and_then(|e| e.target_fingerprint.as_deref())
    }

    /// Instructions started but never finished — the previous run died
    /// mid-flight. Reported as "executing" until a receipt resolves them.
    fn unfinished_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();
        for e in &self.entries {
            if e.status == JOURNAL_STARTED
                && !self
                    .entries
                    .iter()
                    .any(|f| f.instruction_id == e.instruction_id && f.status != JOURNAL_STARTED)
            {
                if !ids.contains(&e.instruction_id) {
                    ids.push(e.instruction_id.clone());
                }
            }
        }
        ids
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Why an instruction could not be applied. `reason` feeds the receipt; the
/// executor never converts a refusal into a success.
#[derive(Debug)]
pub struct Reject {
    pub reason: &'static str,
    pub detail: String,
}

fn reject(reason: &'static str, detail: impl Into<String>) -> Reject {
    Reject {
        reason,
        detail: detail.into(),
    }
}

fn hash_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .with_context(|| format!("failed to create {}", dst.display()))?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        #[cfg(windows)]
        if file_type.is_dir() && junction::exists(entry.path())? {
            bail!("refusing junction in skill source: {}", entry.path().display());
        }
        if file_type.is_symlink() {
            bail!(
                "refusing symlink in skill source: {}",
                entry.path().display()
            );
        }
        let to = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &to)
                .with_context(|| format!("failed to copy {}", entry.path().display()))?;
        } else {
            bail!("refusing special file in skill source: {}", entry.path().display());
        }
    }
    Ok(())
}


/// Hash a directory tree without following links. Include directory names,
/// file names, lengths and bytes in a deterministic order. Any unreadable,
/// non-UTF8, symbolic-link or special entry fails closed.
fn fingerprint_tree(root: &Path) -> Result<String> {
    fn visit(path: &Path, relative: &Path, hasher: &mut Sha256) -> Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        let ty = meta.file_type();
        #[cfg(windows)]
        if ty.is_dir() && junction::exists(path)? {
            bail!("refusing junction: {}", path.display());
        }
        if ty.is_symlink() {
            bail!("refusing symbolic link: {}", path.display());
        }
        let rel = relative.to_str().context("non-UTF8 path in deployed skill")?;
        let rel_bytes = rel.as_bytes();
        if ty.is_dir() {
            hasher.update(b"D");
            hasher.update((rel_bytes.len() as u64).to_be_bytes());
            hasher.update(rel_bytes);
            let mut children = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
            children.sort_by_key(|e| e.file_name());
            for child in children {
                visit(&child.path(), &relative.join(child.file_name()), hasher)?;
            }
        } else if ty.is_file() {
            hasher.update(b"F");
            hasher.update((rel_bytes.len() as u64).to_be_bytes());
            hasher.update(rel_bytes);
            let data = std::fs::read(path)?;
            hasher.update((data.len() as u64).to_be_bytes());
            hasher.update(data);
        } else {
            bail!("refusing special file: {}", path.display());
        }
        Ok(())
    }
    if !std::fs::symlink_metadata(root)?.file_type().is_dir() {
        bail!("deployed target is not a real directory");
    }
    let mut hasher = Sha256::new();
    visit(root, Path::new(""), &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

fn require_owned_target(journal: &Journal, key: &str, target: &Path) -> Result<(), Reject> {
    let expected = journal.owned_fingerprint(key).ok_or_else(|| reject(
        REASON_CONFLICT,
        format!("{} has no verified successful deploy; refusing modification", target.display()),
    ))?;
    let actual = fingerprint_tree(target).map_err(|err| reject(
        REASON_CONFLICT,
        format!("cannot safely verify {}: {err}", target.display()),
    ))?;
    if actual != expected {
        return Err(reject(REASON_CONFLICT, format!(
            "{} changed since deployment; refusing modification", target.display()
        )));
    }
    Ok(())
}

fn journal_target(agent_key: &str, target: &Path) -> String {
    format!("{agent_key}::{}", target.display())
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

fn base_entry(inst: &DeviceInstruction, commit: &str, target: &str, status: &str) -> JournalEntry {
    JournalEntry {
        instruction_id: inst.id.clone(),
        instruction_commit: commit.to_string(),
        action: inst.action.clone(),
        agent_key: inst.agent_key.clone(),
        target: target.to_string(),
        status: status.to_string(),
        ts: now_ts(),
        receipt: None,
        target_fingerprint: None,
    }
}

/// Deploys one skill directory into the mapped agent directory. Returns the
/// target path. The started journal record is written here; the caller owns
/// the completed record (it carries the receipt), so a crash between copy and
/// journal leaves an unverified partial target that needs manual review.
pub fn apply_deploy(
    agent_root: &Path,
    inst: &DeviceInstruction,
    source_dir: &Path,
    commit: &str,
    journal: &mut Journal,
) -> Result<PathBuf, Reject> {
    let skill_name = inst
        .skill_name
        .as_deref()
        .ok_or_else(|| reject(REASON_INVALID_INSTRUCTION, "deploy instruction without skill_name"))?;
    if let Err(err) = devices::validate_skill_name(skill_name) {
        return Err(reject(REASON_INVALID_INSTRUCTION, err.to_string()));
    }
    if !std::fs::symlink_metadata(source_dir)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false)
    {
        return Err(reject(REASON_INVALID_INSTRUCTION, "skill source must be a real directory"));
    }
    if !source_dir.join("SKILL.md").is_file() {
        return Err(reject(
            REASON_INVALID_INSTRUCTION,
            format!("skill source has no SKILL.md: {}", source_dir.display()),
        ));
    }
    let target = agent_root.join(skill_name);
    let target_str = journal_target(&inst.agent_key, &target);
    let existed = match std::fs::symlink_metadata(&target) {
        Ok(_) => { require_owned_target(journal, &target_str, &target)?; true }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(err) => return Err(reject(REASON_CONFLICT, format!(
            "cannot inspect {}: {err}", target.display()
        ))),
    };
    // Build the new tree separately: copying directly into an existing file
    // could modify an unrelated file through a hard link. Keep the old tree
    // until the replacement is ready and ownership has been rechecked.
    std::fs::create_dir_all(agent_root)
        .map_err(|err| reject(REASON_EXECUTION_ERROR, err.to_string()))?;
    let staging = tempfile::Builder::new().prefix(".skills-executor-stage-")
        .tempdir_in(agent_root)
        .map_err(|err| reject(REASON_EXECUTION_ERROR, err.to_string()))?;
    let next = staging.path().join("next");
    copy_dir_recursive(source_dir, &next)
        .map_err(|err| reject(REASON_EXECUTION_ERROR, err.to_string()))?;
    if existed {
        require_owned_target(journal, &target_str, &target)?;
    } else {
        match std::fs::symlink_metadata(&target) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err(reject(REASON_CONFLICT, "target appeared during staging")),
            Err(err) => return Err(reject(REASON_CONFLICT, err.to_string())),
        }
    }
    journal
        .append(base_entry(inst, commit, &target_str, JOURNAL_STARTED))
        .map_err(|err| reject(REASON_EXECUTION_ERROR, err.to_string()))?;
    let previous = staging.path().join("previous");
    if existed {
        std::fs::rename(&target, &previous)
            .map_err(|err| reject(REASON_EXECUTION_ERROR, format!("could not stage previous target: {err}")))?;
    }
    if let Err(err) = std::fs::rename(&next, &target) {
        if existed {
            if let Err(rollback_err) = std::fs::rename(&previous, &target) {
                // Preserve the old directory for manual recovery.
                let recovery = staging.keep();
                return Err(reject(REASON_EXECUTION_ERROR, format!(
                    "replacement failed: {err}; rollback failed: {rollback_err}; previous files preserved at {}",
                    recovery.join("previous").display()
                )));
            }
        }
        return Err(reject(REASON_EXECUTION_ERROR, format!("replacement failed: {err}")));
    }
    Ok(target)
}

/// Removes a previously deployed skill. Only paths with a journal record are
/// eligible; anything else is a conflict and stays untouched.
pub fn apply_undeploy(
    agent_root: &Path,
    inst: &DeviceInstruction,
    commit: &str,
    journal: &mut Journal,
) -> Result<PathBuf, Reject> {
    let skill_name = inst.skill_name.as_deref().ok_or_else(|| {
        reject(REASON_INVALID_INSTRUCTION, "undeploy instruction without skill_name")
    })?;
    if let Err(err) = devices::validate_skill_name(skill_name) {
        return Err(reject(REASON_INVALID_INSTRUCTION, err.to_string()));
    }
    let target = agent_root.join(skill_name);
    let target_str = journal_target(&inst.agent_key, &target);
    require_owned_target(journal, &target_str, &target)?;
    journal
        .append(base_entry(inst, commit, &target_str, JOURNAL_STARTED))
        .map_err(|err| reject(REASON_EXECUTION_ERROR, err.to_string()))?;
    if target.symlink_metadata().is_ok() {
        std::fs::remove_dir_all(&target)
            .map_err(|err| reject(REASON_EXECUTION_ERROR, format!("{}: {err}", target.display())))?;
    }
    Ok(target)
}

fn make_receipt(
    inst: &DeviceInstruction,
    commit: &str,
    status: &str,
    reason: Option<&str>,
    detail: Option<String>,
) -> DeviceReceipt {
    DeviceReceipt {
        schema: devices::DEVICE_PROTOCOL_VERSION,
        instruction_id: inst.id.clone(),
        device_id: inst.device_id.clone(),
        status: status.to_string(),
        reason: reason.map(|r| r.to_string()),
        instruction_commit: Some(commit.to_string()),
        detail,
        executor_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        finished_at: now_ts(),
    }
}

fn scan_agent_skills(agent_root: &Path) -> Vec<AgentSkillReport> {
    let mut reports = Vec::new();
    let Ok(entries) = std::fs::read_dir(agent_root) else {
        return reports;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() || path.is_symlink() {
            continue;
        }
        let skill_md = path.join("SKILL.md");
        if !skill_md.is_file() {
            continue;
        }
        let content_hash = hash_file(&skill_md).ok();
        let deployed_at = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);
        reports.push(AgentSkillReport {
            name: entry.file_name().to_string_lossy().to_string(),
            content_hash,
            deployed_at,
        });
    }
    reports.sort_by(|a, b| a.name.cmp(&b.name));
    reports
}

/// Runs one executor cycle. On entry, an exclusive lock is taken for the
/// whole run; a concurrent run (scheduler overlap) exits immediately with
/// `considered = 0` instead of queueing behind itself.
pub fn run_once(config: &ExecutorConfig) -> Result<ExecutorRunReport> {
    let state_dir = central_repo::base_dir().join(EXECUTOR_STATE_DIR);
    std::fs::create_dir_all(&state_dir).context("failed to create executor state dir")?;

    let mut report = ExecutorRunReport {
        device_id: config.device_id.clone(),
        ..Default::default()
    };

    let lock_path = state_dir.join(LOCK_FILE);
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("failed to open executor lock {}", lock_path.display()))?;
    if lock_file.try_lock_exclusive().is_err() {
        report.skipped_because_locked = true;
        report
            .details
            .push("another executor run holds the lock; skipped".to_string());
        return Ok(report);
    }

    let mut journal = Journal::load(&state_dir.join(JOURNAL_FILE))?;
    let snapshot = devices::fetch_channel_snapshot(&config.url, &config.branch)?;
    report.channel_commit = Some(snapshot.head_commit.clone());
    report.warnings.extend(snapshot.warnings);

    let now = now_ts();
    let mut receipts: Vec<DeviceReceipt> = Vec::new();

    for (inst, commit) in &snapshot.instructions {
        if inst.device_id != config.device_id {
            continue;
        }
        report.considered += 1;
        if report.considered > config.max_instructions {
            report
                .details
                .push(format!("instruction {} deferred: per-run cap reached", inst.id));
            break;
        }

        if let Some(entry) = journal.completed(&inst.id, commit) {
            report.skipped += 1;
            if let Some(receipt) = &entry.receipt {
                receipts.push(receipt.clone());
            }
            continue;
        }

        if let Err(err) = devices::validate_instruction(inst) {
            report.rejected += 1;
            let receipt = make_receipt(inst, commit, "rejected", Some(REASON_INVALID_INSTRUCTION), Some(err.to_string()));
            append_with_receipt(&mut journal, inst, commit, "rejected", &receipt)?;
            receipts.push(receipt);
            continue;
        }

        let agent_dir = config
            .agents
            .iter()
            .find(|m| m.key == inst.agent_key)
            .map(|m| m.dir.clone());
        let agent_dir = match agent_dir {
            Some(dir) => dir,
            None => {
                report.rejected += 1;
                let receipt = make_receipt(
                    inst,
                    commit,
                    "rejected",
                    Some(REASON_UNKNOWN_AGENT),
                    Some(format!("agent {} is not in this executor's allow-list", inst.agent_key)),
                );
                append_with_receipt(&mut journal, inst, commit, "rejected", &receipt)?;
                receipts.push(receipt);
                continue;
            }
        };

        if let Some(expires_at) = inst.expires_at {
            if now > expires_at {
                report.rejected += 1;
                let receipt = make_receipt(
                    inst,
                    commit,
                    "rejected",
                    Some(REASON_EXPIRED),
                    Some(format!("instruction expired at {expires_at}")),
                );
                append_with_receipt(&mut journal, inst, commit, "rejected", &receipt)?;
                receipts.push(receipt);
                continue;
            }
        }

        if config.dry_run {
            report
                .details
                .push(format!("dry-run: would {} {:?}", inst.action, inst.skill_name));
            continue;
        }

        let outcome = (|| -> Result<PathBuf, Reject> {
            match inst.action.as_str() {
                devices::ACTION_DEPLOY => {
                    let (tmp, dir) = devices::fetch_skill_source(
                        inst.skill_url.as_deref().unwrap_or_default(),
                        inst.skill_branch.as_deref(),
                    )
                    .map_err(|err| reject(REASON_EXECUTION_ERROR, err.to_string()))?;
                    let source_dir = match inst.skill_subpath.as_deref() {
                        Some("") | None => dir.clone(),
                        Some(sub) => dir.join(sub),
                    };
                    // Subpaths must not escape the fetched checkout via an
                    // intermediate symlink, even if their text is valid.
                    let canonical_root = dir.canonicalize()
                        .map_err(|e| reject(REASON_EXECUTION_ERROR, e.to_string()))?;
                    let canonical_source = source_dir.canonicalize()
                        .map_err(|e| reject(REASON_EXECUTION_ERROR, e.to_string()))?;
                    if !canonical_source.starts_with(&canonical_root) {
                        return Err(reject(REASON_INVALID_INSTRUCTION, "skill source escapes checkout"));
                    }
                    let result = apply_deploy(&agent_dir, inst, &source_dir, commit, &mut journal);
                    drop(tmp);
                    result
                }
                devices::ACTION_UNDEPLOY => apply_undeploy(&agent_dir, inst, commit, &mut journal),
                other => Err(reject(
                    REASON_INVALID_INSTRUCTION,
                    format!("unknown action {other:?}"),
                )),
            }
        })();

        match outcome {
            Ok(target) => {
                report.executed += 1;
                let receipt = make_receipt(
                    inst,
                    commit,
                    "success",
                    Some("none"),
                    Some(format!("{} at {}", inst.action, target.display())),
                );
                // The completed record (carrying the receipt) is written here,
                // after the action: a crash before this point leaves only a
                // started trace. An interrupted deploy requires manual
                // review before a later run can modify its partial target.
                let mut entry = base_entry(
                    inst,
                    commit,
                    &journal_target(&inst.agent_key, &target),
                    JOURNAL_COMPLETED,
                );
                if inst.action == devices::ACTION_DEPLOY {
                    entry.target_fingerprint = Some(fingerprint_tree(&target)
                        .context("failed to fingerprint deployed target; refusing to claim ownership")?);
                }
                entry.receipt = Some(receipt.clone());
                if let Err(err) = journal.append(entry) {
                    bail!("failed to journal completion for {}: {err}", inst.id);
                }
                receipts.push(receipt);
            }
            Err(rej) => {
                report.rejected += 1;
                let receipt = make_receipt(inst, commit, "rejected", Some(rej.reason), Some(rej.detail));
                append_with_receipt(&mut journal, inst, commit, "rejected", &receipt)?;
                receipts.push(receipt);
            }
        }
    }

    // State report: what this executor manages right now. Started-but-not-
    // finished instructions (a crashed previous run) are reported as
    // executing so the UI does not quietly forget them.
    let agents = config
        .agents
        .iter()
        .map(|m| AgentStateReport {
            key: m.key.clone(),
            skills: scan_agent_skills(&m.dir),
        })
        .collect();
    let state = DeviceStateReport {
        schema: devices::DEVICE_PROTOCOL_VERSION,
        device_id: config.device_id.clone(),
        reported_at: now,
        executing: journal.unfinished_ids(),
        agents,
    };

    for attempt in 0..3 {
        match devices::publish_executor_update(&config.url, &config.branch, &receipts, Some(&state))
        {
            Ok(_) => {
                report.published = true;
                break;
            }
            Err(err) => {
                report.publish_error = Some(err.to_string());
                if attempt < 2 {
                    std::thread::sleep(std::time::Duration::from_millis(1500));
                }
            }
        }
    }

    Ok(report)
}

fn append_with_receipt(
    journal: &mut Journal,
    inst: &DeviceInstruction,
    commit: &str,
    status: &str,
    receipt: &DeviceReceipt,
) -> Result<()> {
    // Rejections claim no target: ownership must never be granted by a
    // refusal, only by a real write or removal.
    let mut entry = base_entry(inst, commit, "", status);
    entry.receipt = Some(receipt.clone());
    journal.append(entry)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::central_repo;

    fn instruction(action: &str, skill_name: &str) -> DeviceInstruction {
        DeviceInstruction {
            schema: devices::DEVICE_PROTOCOL_VERSION,
            id: format!("inst-{skill_name}-{action}"),
            device_id: "dev-test".to_string(),
            action: action.to_string(),
            skill_url: Some("https://example.com/skills.git".to_string()),
            skill_branch: Some("main".to_string()),
            skill_subpath: Some("demo".to_string()),
            skill_name: Some(skill_name.to_string()),
            agent_key: "codex".to_string(),
            created_at: 1_000,
            expires_at: Some(9_999_999),
            created_by: Some("tester".to_string()),
        }
    }

    fn skill_source(root: &Path, name: &str) -> PathBuf {
        let dir = root.join(name);
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("SKILL.md"), format!("# {name}\n")).unwrap();
        std::fs::write(dir.join("assets").join("note.txt"), "data").unwrap();
        dir
    }

    struct TestEnv {
        _lock: std::sync::MutexGuard<'static, ()>,
        _tmp: tempfile::TempDir,
        base: PathBuf,
    }

    impl TestEnv {
        fn new() -> Self {
            let lock = central_repo::test_base_dir_lock();
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().join("base");
            std::fs::create_dir_all(&base).unwrap();
            central_repo::set_test_base_dir_override(Some(base.clone()));
            TestEnv { _lock: lock, _tmp: tmp, base }
        }

        fn journal(&self) -> Journal {
            Journal::load(&self.base.join(EXECUTOR_STATE_DIR).join(JOURNAL_FILE)).unwrap()
        }
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            central_repo::set_test_base_dir_override(None);
        }
    }

    fn complete_deploy(journal: &mut Journal, inst: &DeviceInstruction, commit: &str, target: &Path) {
        let mut entry = base_entry(inst, commit, &journal_target(&inst.agent_key, target), JOURNAL_COMPLETED);
        entry.target_fingerprint = Some(fingerprint_tree(target).unwrap());
        entry.receipt = Some(make_receipt(inst, commit, "success", Some("none"), None));
        journal.append(entry).unwrap();
    }

    #[test]
    fn deploy_writes_target_and_journals_ownership() {
        let env = TestEnv::new();
        let agent_root = env.base.join("agents").join("codex");
        std::fs::create_dir_all(&agent_root).unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();

        let target = apply_deploy(&agent_root, &inst, &source, "c1", &mut journal).unwrap();
        assert!(target.join("SKILL.md").is_file());
        assert!(target.join("assets").join("note.txt").is_file());
        assert_eq!(journal.len(), 1, "started record; completion is the caller's receipt");
    }

    #[test]
    fn deploy_refuses_to_overwrite_a_foreign_directory() {
        let env = TestEnv::new();
        let agent_root = env.base.join("agents").join("codex");
        let target = agent_root.join("demo");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("SKILL.md"), "# someone else's skill\n").unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();

        let err = apply_deploy(&agent_root, &inst, &source, "c1", &mut journal).unwrap_err();
        assert_eq!(err.reason, REASON_CONFLICT);
        // Nothing was modified — the pre-existing skill is intact.
        assert_eq!(
            std::fs::read_to_string(target.join("SKILL.md")).unwrap(),
            "# someone else's skill\n"
        );
    }

    #[test]
    fn redeploying_own_target_is_allowed_and_idempotent() {
        let env = TestEnv::new();
        let agent_root = env.base.join("agents").join("codex");
        std::fs::create_dir_all(&agent_root).unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();

        let target = apply_deploy(&agent_root, &inst, &source, "c1", &mut journal).unwrap();
        complete_deploy(&mut journal, &inst, "c1", &target);
        let before = std::fs::read_to_string(agent_root.join("demo").join("SKILL.md")).unwrap();

        // Same instruction, same commit: run_once's skip path uses completed();
        // a re-invocation of apply_deploy on its own target must still work.
        apply_deploy(&agent_root, &inst, &source, "c1", &mut journal).unwrap();
        let after = std::fs::read_to_string(agent_root.join("demo").join("SKILL.md")).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn undeploy_only_removes_journaled_targets() {
        let env = TestEnv::new();
        let agent_root = env.base.join("agents").join("codex");
        std::fs::create_dir_all(&agent_root).unwrap();

        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();
        let target = apply_deploy(&agent_root, &inst, &source, "c1", &mut journal).unwrap();
        complete_deploy(&mut journal, &inst, "c1", &target);
        assert!(agent_root.join("demo").join("SKILL.md").is_file());

        // Foreign target is refused.
        let foreign = agent_root.join("not-ours");
        std::fs::create_dir_all(&foreign).unwrap();
        let undeploy = instruction("undeploy", "not-ours");
        let err = apply_undeploy(&agent_root, &undeploy, "c2", &mut journal).unwrap_err();
        assert_eq!(err.reason, REASON_CONFLICT);
        assert!(foreign.is_dir(), "foreign directory must survive");

        // Our own target is removed.
        let undeploy = instruction("undeploy", "demo");
        apply_undeploy(&agent_root, &undeploy, "c2", &mut journal).unwrap();
        assert!(!agent_root.join("demo").exists());
    }

    #[test]
    fn symlink_in_skill_source_is_refused() {
        #[cfg(unix)]
        {
            let env = TestEnv::new();
            let agent_root = env.base.join("agents").join("codex");
            std::fs::create_dir_all(&agent_root).unwrap();
            let source = skill_source(&env.base, "tricky");
            std::os::unix::fs::symlink("/etc", source.join("escape")).unwrap();
            let inst = instruction("deploy", "tricky");
            let mut journal = env.journal();
            let err = apply_deploy(&agent_root, &inst, &source, "c1", &mut journal).unwrap_err();
            assert_eq!(err.reason, REASON_EXECUTION_ERROR);
            assert!(!agent_root.join("tricky").join("escape").exists());
        }
    }


    #[test]
    fn changed_or_replaced_target_cannot_be_overwritten_or_removed() {
        let env = TestEnv::new();
        let agent = env.base.join("agent");
        std::fs::create_dir_all(&agent).unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();
        let target = apply_deploy(&agent, &inst, &source, "c1", &mut journal).unwrap();
        complete_deploy(&mut journal, &inst, "c1", &target);

        std::fs::write(target.join("assets").join("note.txt"), "user changes").unwrap();
        assert_eq!(apply_deploy(&agent, &inst, &source, "c2", &mut journal).unwrap_err().reason, REASON_CONFLICT);
        assert_eq!(apply_undeploy(&agent, &instruction("undeploy", "demo"), "c2", &mut journal).unwrap_err().reason, REASON_CONFLICT);
        assert_eq!(std::fs::read_to_string(target.join("assets").join("note.txt")).unwrap(), "user changes");
    }

    #[test]
    fn started_and_legacy_records_do_not_claim_existing_directory() {
        let env = TestEnv::new();
        let agent = env.base.join("agent");
        let target = agent.join("demo");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("SKILL.md"), "foreign").unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();
        let key = journal_target(&inst.agent_key, &target);
        journal.append(base_entry(&inst, "c1", &key, JOURNAL_STARTED)).unwrap();
        assert_eq!(apply_deploy(&agent, &inst, &source, "c1", &mut journal).unwrap_err().reason, REASON_CONFLICT);
        let mut legacy = base_entry(&inst, "c0", &key, JOURNAL_COMPLETED);
        legacy.receipt = Some(make_receipt(&inst, "c0", "success", Some("none"), None));
        journal.append(legacy).unwrap();
        assert_eq!(apply_undeploy(&agent, &instruction("undeploy", "demo"), "c2", &mut journal).unwrap_err().reason, REASON_CONFLICT);
        assert_eq!(std::fs::read_to_string(target.join("SKILL.md")).unwrap(), "foreign");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_inserted_in_owned_target_is_conflict() {
        let env = TestEnv::new();
        let agent = env.base.join("agent");
        std::fs::create_dir_all(&agent).unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();
        let target = apply_deploy(&agent, &inst, &source, "c1", &mut journal).unwrap();
        complete_deploy(&mut journal, &inst, "c1", &target);
        let external = env.base.join("external");
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("note.txt"), "untouched").unwrap();
        std::fs::remove_dir_all(target.join("assets")).unwrap();
        std::os::unix::fs::symlink(&external, target.join("assets")).unwrap();
        assert_eq!(apply_deploy(&agent, &inst, &source, "c2", &mut journal).unwrap_err().reason, REASON_CONFLICT);
        assert_eq!(std::fs::read_to_string(external.join("note.txt")).unwrap(), "untouched");
    }


    #[test]
    fn verified_tree_can_be_updated_then_removed() {
        let env = TestEnv::new();
        let agent = env.base.join("agent");
        std::fs::create_dir_all(&agent).unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();
        let target = apply_deploy(&agent, &inst, &source, "c1", &mut journal).unwrap();
        complete_deploy(&mut journal, &inst, "c1", &target);
        std::fs::write(source.join("SKILL.md"), "updated").unwrap();
        apply_deploy(&agent, &inst, &source, "c2", &mut journal).unwrap();
        complete_deploy(&mut journal, &inst, "c2", &target);
        assert_eq!(std::fs::read_to_string(target.join("SKILL.md")).unwrap(), "updated");
        apply_undeploy(&agent, &instruction("undeploy", "demo"), "c3", &mut journal).unwrap();
        assert!(!target.exists());
    }

    #[cfg(windows)]
    #[test]
    fn junction_inserted_in_owned_target_is_conflict() {
        let env = TestEnv::new();
        let agent = env.base.join("agent");
        std::fs::create_dir_all(&agent).unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();
        let target = apply_deploy(&agent, &inst, &source, "c1", &mut journal).unwrap();
        complete_deploy(&mut journal, &inst, "c1", &target);
        let external = env.base.join("external");
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("note.txt"), "untouched").unwrap();
        std::fs::remove_dir_all(target.join("assets")).unwrap();
        junction::create(&external, target.join("assets")).unwrap();
        assert_eq!(apply_deploy(&agent, &inst, &source, "c2", &mut journal).unwrap_err().reason, REASON_CONFLICT);
        assert_eq!(std::fs::read_to_string(external.join("note.txt")).unwrap(), "untouched");
    }


    #[test]
    fn update_does_not_write_through_hardlinks_in_existing_target() {
        let env = TestEnv::new();
        let agent = env.base.join("agent");
        std::fs::create_dir_all(&agent).unwrap();
        let source = skill_source(&env.base, "demo");
        let inst = instruction("deploy", "demo");
        let mut journal = env.journal();
        let target = apply_deploy(&agent, &inst, &source, "c1", &mut journal).unwrap();
        let external = env.base.join("external.txt");
        std::fs::write(&external, "data").unwrap();
        std::fs::remove_file(target.join("assets").join("note.txt")).unwrap();
        std::fs::hard_link(&external, target.join("assets").join("note.txt")).unwrap();
        complete_deploy(&mut journal, &inst, "c1", &target);
        std::fs::write(source.join("assets").join("note.txt"), "updated").unwrap();
        apply_deploy(&agent, &inst, &source, "c2", &mut journal).unwrap();
        assert_eq!(std::fs::read_to_string(&external).unwrap(), "data");
        assert_eq!(std::fs::read_to_string(target.join("assets").join("note.txt")).unwrap(), "updated");
    }

    #[test]
    fn run_once_publishes_state_report_for_empty_channel() {
        let env = TestEnv::new();
        let remote = env.base.join("channel.git");
        std::fs::create_dir_all(&remote).unwrap();
        devices_run_git_init(&remote);
        // Plain filesystem paths are the portable local-remote form; git
        // treats them as local remotes on every platform.
        let url = remote.to_string_lossy().to_string();
        let agent_root = env.base.join("agents").join("codex");
        std::fs::create_dir_all(&agent_root).unwrap();
        skill_source(&agent_root, "present-skill");

        let config = ExecutorConfig {
            url: url.clone(),
            branch: "devices-test".to_string(),
            device_id: "dev-exec".to_string(),
            agents: vec![AgentMapping {
                key: "codex".to_string(),
                dir: agent_root.clone(),
            }],
            max_instructions: 10,
            dry_run: false,
        };
        let report = run_once(&config).unwrap();
        assert_eq!(report.considered, 0);
        assert!(report.published, "publish error: {:?}", report.publish_error);

        // The state report must be readable back from the channel.
        let snapshot = devices::fetch_channel_snapshot(&url, "devices-test").unwrap();
        assert_eq!(snapshot.states.len(), 1);
        assert_eq!(snapshot.states[0].device_id, "dev-exec");
        assert_eq!(snapshot.states[0].agents.len(), 1);
        assert_eq!(snapshot.states[0].agents[0].key, "codex");
        assert_eq!(snapshot.states[0].agents[0].skills.len(), 1);
        assert_eq!(snapshot.states[0].agents[0].skills[0].name, "present-skill");
    }

    fn devices_run_git_init(path: &Path) {
        std::process::Command::new("git")
            .args(["init", "--bare", &path.to_string_lossy()])
            .output()
            .unwrap();
    }

    /// The full loop, end to end: the manager publishes an instruction on the
    /// channel, the executor fetches the skill over the real `git://` network
    /// path (a local `git daemon` stands in for the remote skill repo — the
    /// URL validator only accepts network schemes, by design), deploys into a
    /// simulated agent directory and publishes its receipt, and a fresh import
    /// derives "success". Also covers the conflict path: a foreign directory
    /// with the target name must survive untouched and produce a rejected
    /// receipt.
    #[test]
    fn end_to_end_instruction_cycle_publishes_receipt() {
        let env = TestEnv::new();

        // Skill source served by a local git daemon (git:// is accepted by
        // the URL validator; local paths are not, and that is the point).
        let source_repo = env.base.join("source-repo");
        std::fs::create_dir_all(&source_repo).unwrap();
        devices_run_git_init(&source_repo);
        let work = env.base.join("source-work");
        run_git_quiet(&[
            "clone",
            &source_repo.to_string_lossy(),
            &work.to_string_lossy(),
        ]);
        let skill_dir = work.join("skills").join("pilot-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join("SKILL.md"), "# pilot-skill\n").unwrap();
        run_git_quiet(&["-C", &work.to_string_lossy(), "add", "-A"]);
        run_git_quiet(&[
            "-C",
            &work.to_string_lossy(),
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-m",
            "skill",
        ]);
        run_git_quiet(&["-C", &work.to_string_lossy(), "push", "origin", "HEAD"]);

        let daemon = spawn_git_daemon(&env.base);
        let mut daemon = daemon;
        let source_url = format!("git://127.0.0.1:{}/source-repo", daemon.port);
        wait_for_daemon(&source_url);

        // Channel remote.
        let channel = env.base.join("channel.git");
        std::fs::create_dir_all(&channel).unwrap();
        devices_run_git_init(&channel);
        let channel_url = channel.to_string_lossy().to_string();

        // Manager side: register the device and publish the deploy request.
        let store = crate::core::skill_store::SkillStore::new(&env.base.join("db.sqlite")).unwrap();
        let device_row = crate::core::devices::DeviceRow {
            id: "dev-e2e".to_string(),
            name: "E2E Device".to_string(),
            platform: Some("linux".to_string()),
            created_at: 1_000,
            last_seen_at: None,
            last_state_commit: None,
        };
        store.upsert_device(&device_row).unwrap();
        let inst = crate::core::devices::DeviceInstruction {
            schema: devices::DEVICE_PROTOCOL_VERSION,
            id: "inst-e2e".to_string(),
            device_id: "dev-e2e".to_string(),
            action: devices::ACTION_DEPLOY.to_string(),
            skill_url: Some(source_url),
            skill_branch: None,
            skill_subpath: Some("skills/pilot-skill".to_string()),
            skill_name: Some("pilot-skill".to_string()),
            agent_key: "codex".to_string(),
            // Real-clock TTL: the executor checks expiry against the wall
            // clock, so a fixed fake timestamp would be rejected as expired.
            created_at: now_ts(),
            expires_at: Some(now_ts() + 86_400),
            created_by: Some("manager".to_string()),
        };
        devices::publish_instructions(
            &channel_url,
            "devices-test",
            Some(&crate::core::devices::DeviceManifest {
                schema: devices::DEVICE_PROTOCOL_VERSION,
                id: "dev-e2e".to_string(),
                name: "E2E Device".to_string(),
                platform: Some("linux".to_string()),
                first_seen: 1_000,
                executor_version: None,
            }),
            &[inst.clone()],
        )
        .unwrap();

        // Executor side: one run deploys into the simulated agent directory.
        let agent_root = env.base.join("agents").join("codex");
        std::fs::create_dir_all(&agent_root).unwrap();
        // A foreign directory with the target name must survive untouched.
        let foreign = agent_root.join("pilot-skill");
        std::fs::create_dir_all(&foreign).unwrap();
        std::fs::write(foreign.join("SKILL.md"), "# not ours\n").unwrap();

        let config = ExecutorConfig {
            url: channel_url.clone(),
            branch: "devices-test".to_string(),
            device_id: "dev-e2e".to_string(),
            agents: vec![AgentMapping {
                key: "codex".to_string(),
                dir: agent_root.clone(),
            }],
            max_instructions: 10,
            dry_run: false,
        };
        let report = run_once(&config).unwrap();
        assert_eq!(report.executed, 0, "conflict: nothing deployed");
        assert_eq!(report.rejected, 1);
        assert!(report.published, "{:?}", report.publish_error);
        assert_eq!(
            std::fs::read_to_string(foreign.join("SKILL.md")).unwrap(),
            "# not ours\n",
            "foreign directory must survive"
        );

        // Manager side: refresh sees the rejection, then clears the conflict
        // and re-runs, which now succeeds and reports success.
        let snapshot = devices::fetch_channel_snapshot(&channel_url, "devices-test").unwrap();
        devices::import_snapshot(&store, &snapshot).unwrap();
        let rows = store.get_device_instructions(None).unwrap();
        assert_eq!(rows[0].state, devices::TASK_STATE_FAILED);

        std::fs::remove_dir_all(&foreign).unwrap();
        let report = run_once(&config).unwrap();
        assert_eq!(report.executed, 1, "{:?}", report.details);
        assert!(agent_root.join("pilot-skill").join("SKILL.md").is_file());

        let snapshot = devices::fetch_channel_snapshot(&channel_url, "devices-test").unwrap();
        devices::import_snapshot(&store, &snapshot).unwrap();
        let rows = store.get_device_instructions(None).unwrap();
        assert_eq!(rows[0].state, devices::TASK_STATE_SUCCESS);
        assert_eq!(rows[0].receipt_status.as_deref(), Some("success"));
        assert_eq!(
            rows[0].receipt_commit.as_deref(),
            rows[0].instruction_commit.as_deref(),
            "receipt must match the instruction commit"
        );
        // The device is alive from the manager's point of view.
        let devs = store.get_devices().unwrap();
        assert!(devs[0].last_seen_at.is_some());

        daemon.kill();
    }

    /// A minimal git daemon handle: random port, kill on demand (and on
    /// drop, so a failing assertion cannot leak a server past the test).
    struct GitDaemon {
        child: std::process::Child,
        port: u16,
    }

    impl GitDaemon {
        fn kill(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for GitDaemon {
        fn drop(&mut self) {
            self.kill();
        }
    }

    fn spawn_git_daemon(base: &Path) -> GitDaemon {
        // Try a handful of random ports; a CI runner may have one busy.
        let mut seed = std::process::id() as u64;
        for _ in 0..10 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let port = 20000 + (seed % 20000) as u16;
            let child = std::process::Command::new("git")
                .args([
                    "daemon",
                    "--reuseaddr",
                    "--listen=127.0.0.1",
                    &format!("--port={port}"),
                    &format!("--base-path={}", base.display()),
                    "--export-all",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            if let Ok(mut child) = child {
                std::thread::sleep(std::time::Duration::from_millis(300));
                if child.try_wait().unwrap_or(None).is_none() {
                    return GitDaemon { child, port };
                }
            }
        }
        panic!("could not start git daemon for the e2e test");
    }

    fn wait_for_daemon(url: &str) {
        for _ in 0..20 {
            let probe = std::process::Command::new("git")
                .args(["ls-remote", url])
                .env("GIT_TERMINAL_PROMPT", "0")
                .output();
            if let Ok(out) = probe {
                if out.status.success() {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        panic!("git daemon never became reachable at {url}");
    }

    fn run_git_quiet(args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
