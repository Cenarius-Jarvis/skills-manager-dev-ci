#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use app_lib::core::{repository_sources as repos, skill_store::SkillStore};
use tauri::State;

struct Preview {
    store: Arc<SkillStore>,
    // Dropped after the store so SQLite handles are closed before cleanup.
    _temporary_directory: tempfile::TempDir,
}

#[tauri::command]
fn repository_sources_list(state: State<'_, Preview>) -> Result<Vec<repos::RepositorySource>, String> {
    state.store.list_repository_sources().map_err(|e| e.to_string())
}

#[tauri::command]
fn repository_sources_add(
    state: State<'_, Preview>, name: String, device_id: Option<String>,
    url: String, branch: String, skills_root: String,
) -> Result<repos::RepositorySource, String> {
    // The preview labels sources by name only; it never connects to a device.
    if device_id.is_some() { return Err("device association is unavailable in this preview".into()); }
    repos::add_source(&state.store, &name, None, &url, &branch, &skills_root).map_err(|e| e.to_string())
}

#[tauri::command]
fn repository_sources_remove(state: State<'_, Preview>, id: String) -> Result<bool, String> {
    state.store.delete_repository_source(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn repository_sources_snapshot(state: State<'_, Preview>, id: String) -> Result<Option<repos::RepositorySnapshot>, String> {
    state.store.get_repository_snapshot(&id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn repository_sources_refresh(state: State<'_, Preview>, id: String) -> Result<repos::RepositorySnapshot, String> {
    let store = state.store.clone();
    tauri::async_runtime::spawn_blocking(move || repos::refresh_source(&store, &id).map_err(|e| e.to_string()))
        .await.map_err(|_| "repository refresh task failed".to_string())?
}

fn main() {
    let temp = tempfile::Builder::new().prefix("skills-repo-preview-").tempdir()
        .expect("failed to create temporary preview directory");
    let store = SkillStore::new(&temp.path().join("preview.db"))
        .expect("failed to initialize temporary preview store");
    tauri::Builder::default()
        .manage(Preview { store: Arc::new(store), _temporary_directory: temp })
        .invoke_handler(tauri::generate_handler![
            repository_sources_list, repository_sources_add, repository_sources_remove,
            repository_sources_snapshot, repository_sources_refresh
        ])
        .run(tauri::generate_context!("tauri.repository-preview.conf.json"))
        .expect("repository preview failed");
}
