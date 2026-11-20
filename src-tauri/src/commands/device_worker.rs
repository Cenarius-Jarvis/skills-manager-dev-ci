//! Opt-in execution while the receiving desktop app is open.
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{path::PathBuf, process::Stdio, sync::Arc, time::Duration};
use tauri::State;
use crate::core::{
    central_repo, device_identity, device_signed_executor as executor, devices,
    skill_store::SkillStore, tool_adapters,
};

const ENABLED: &str = "device.worker.enabled";
const USE_SSH: &str = "device.worker.github_ssh";
const LAST_SUCCESS: &str = "device.worker.last_success";
const LAST_ERROR: &str = "device.worker.last_error";

#[derive(Serialize)]
pub struct WorkerStatus {
    enabled: bool,
    github_ssh: bool,
    last_success_at: Option<i64>,
    last_error: Option<String>,
    authorized_agents: Vec<String>,
}

fn status(store: &SkillStore) -> Result<WorkerStatus> {
    let authorizations = store.with_conn(|conn| {
        let mut stmt = conn.prepare("SELECT key FROM settings WHERE key LIKE 'device.agent_auth.%' AND length(value)>0 ORDER BY key")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })?;
    Ok(WorkerStatus {
        enabled: store.get_setting(ENABLED)?.as_deref() == Some("true"),
        github_ssh: store.get_setting(USE_SSH)?.as_deref() == Some("true"),
        last_success_at: store.get_setting(LAST_SUCCESS)?.and_then(|s| s.parse().ok()),
        last_error: store.get_setting(LAST_ERROR)?.filter(|s| !s.is_empty()),
        authorized_agents: authorizations.into_iter().filter_map(|key| key.strip_prefix("device.agent_auth.").map(str::to_owned)).collect(),
    })
}

fn cli() -> Result<PathBuf> {
    let path = std::env::current_exe()?.parent().context("application has no install directory")?
        .join(if cfg!(windows) { "skills-manager-cli.exe" } else { "skills-manager-cli" });
    if !path.is_file() {
        bail!("automatic processing requires the CLI packaged with this application");
    }
    Ok(path)
}

fn run_once(store: &SkillStore, config: &WorkerStatus, report: bool) -> Result<bool> {
    let url = devices::channel_url(store).context("configure the device channel first")?;
    let branch = devices::channel_branch(store);
    let path = cli()?;
    // Prefer the destination library's own SSH alias for its origin. Other
    // GitHub repositories may be accessed with the normal GitHub SSH key.
    let library_route = config.github_ssh.then(|| -> Option<(String, String)> {
        let repo = git2::Repository::open(central_repo::skills_dir()).ok()?;
        let remote = repo.find_remote("origin").ok()?;
        let route = remote.url()?.strip_prefix("git@")?;
        let origin = format!("git@{route}");
        let https = crate::core::device_repository_edit::normalized_origin(&origin)?;
        Some((origin, https))
    }).flatten();
    let build_command = |action: &str| {
        let mut cmd = std::process::Command::new(&path);
        cmd.args(["--json", "devices", action, "--url", &url, "--branch", &branch])
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=12")
            .env("GIT_HTTP_LOW_SPEED_LIMIT", "1000").env("GIT_HTTP_LOW_SPEED_TIME", "20");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        if config.github_ssh {
            cmd.env("GIT_CONFIG_COUNT", if library_route.is_some() { "2" } else { "1" })
                .env("GIT_CONFIG_KEY_0", "url.git@github.com:.insteadOf")
                .env("GIT_CONFIG_VALUE_0", "https://github.com/");
            if let Some((origin, https)) = &library_route {
                cmd.env("GIT_CONFIG_KEY_1", format!("url.{origin}.insteadOf"))
                    .env("GIT_CONFIG_VALUE_1", https);
            }
        }
        cmd
    };
    let identity = device_identity::load_existing_identity(store)?;
    let mut execute = build_command("run-signed");
    execute.arg("--device-id").arg(&identity.device_id);
    if !execute.status()?.success() {
        bail!("could not process the device channel; check Git access and network");
    }
    store.set_setting(LAST_SUCCESS, &chrono::Utc::now().timestamp().to_string())?;
    if !report || config.authorized_agents.is_empty() {
        return Ok(false);
    }
    let mut inventory = build_command("report-state");
    for agent in &config.authorized_agents {
        if let Some(root) = executor::authorized_agent_root(store, agent)? {
            inventory.arg("--agent").arg(format!("{agent}={}", root.display()));
        }
    }
    inventory.arg("--allowed-root").arg(central_repo::skills_dir());
    if !inventory.status()?.success() {
        bail!("requests checked, but agent inventory could not be reported");
    }
    Ok(true)
}

pub fn start(store: Arc<SkillStore>) {
    tauri::async_runtime::spawn(async move {
        let mut last_report = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let shared = store.clone();
            let due = chrono::Utc::now().timestamp().saturating_sub(last_report) >= 300;
            let outcome = tauri::async_runtime::spawn_blocking(move || {
                let config = status(&shared)?;
                if !config.enabled || config.authorized_agents.is_empty() { return Ok(false); }
                match run_once(&shared, &config, due) {
                    Ok(reported) => {
                        shared.set_setting(LAST_ERROR, "")?;
                        Ok(reported)
                    }
                    Err(err) => {
                        shared.set_setting(LAST_ERROR, &err.to_string())?;
                        Err(err)
                    }
                }
            }).await;
            if matches!(outcome, Ok(Ok(true))) {
                last_report = chrono::Utc::now().timestamp();
            }
        }
    });
}

#[tauri::command]
pub fn device_worker_status(store: State<'_, Arc<SkillStore>>) -> Result<WorkerStatus, String> {
    status(&store).map_err(|err| err.to_string())
}

#[tauri::command]
pub fn device_worker_set(store: State<'_, Arc<SkillStore>>, enabled: bool, github_ssh: bool) -> Result<WorkerStatus, String> {
    let change = || -> Result<WorkerStatus> {
        if enabled {
            cli()?;
            devices::channel_url(&store).context("configure the device channel first")?;
            device_identity::load_existing_identity(&store)?;
            if status(&store)?.authorized_agents.is_empty() {
                bail!("authorize at least one installed agent first");
            }
        }
        store.set_setting(USE_SSH, if github_ssh { "true" } else { "false" })?;
        store.set_setting(ENABLED, if enabled { "true" } else { "false" })?;
        status(&store)
    };
    change().map_err(|err| err.to_string())
}

#[tauri::command]
pub fn device_worker_authorize(store: State<'_, Arc<SkillStore>>, agent_key: String, allow: bool) -> Result<WorkerStatus, String> {
    let change = || -> Result<WorkerStatus> {
        if allow {
            let adapter = tool_adapters::find_adapter_with_store(&store, &agent_key)
                .context("choose a supported local agent")?;
            let root = adapter.skills_dir();
            if !root.is_dir() {
                bail!("the agent's local skills directory does not exist");
            }
            executor::authorize_agent(&store, &agent_key, &root)?;
        } else {
            executor::revoke_agent(&store, &agent_key)?;
        }
        status(&store)
    };
    change().map_err(|err| err.to_string())
}
