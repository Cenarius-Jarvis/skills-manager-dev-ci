//! Tauri entry points for explicitly configured independent repository sources.
//! Refresh only reads a temporary Git clone and saves a local snapshot.
use std::sync::Arc;
use tauri::State;
use crate::core::repository_sources::{self, RepositorySource, RepositorySnapshot};
use crate::core::skill_store::SkillStore;

#[tauri::command]
pub async fn repository_sources_list(store: State<'_, Arc<SkillStore>>) -> Result<Vec<RepositorySource>, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || store.list_repository_sources().map_err(|e| e.to_string()))
        .await.map_err(|_| "repository source list failed".to_string())?
}

#[tauri::command]
pub async fn repository_sources_add(
    store: State<'_, Arc<SkillStore>>, name: String, device_id: Option<String>,
    url: String, branch: String, skills_root: String,
) -> Result<RepositorySource, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move ||
        repository_sources::add_source(&store, &name, device_id, &url, &branch, &skills_root)
            .map_err(|e| e.to_string()))
        .await.map_err(|_| "repository source creation failed".to_string())?
}

#[tauri::command]
pub async fn repository_sources_remove(store: State<'_, Arc<SkillStore>>, id: String) -> Result<bool, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || store.delete_repository_source(&id).map_err(|e| e.to_string()))
        .await.map_err(|_| "repository source removal failed".to_string())?
}

#[tauri::command]
pub async fn repository_sources_snapshot(store: State<'_, Arc<SkillStore>>, id: String) -> Result<Option<RepositorySnapshot>, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || store.get_repository_snapshot(&id).map_err(|e| e.to_string()))
        .await.map_err(|_| "repository snapshot read failed".to_string())?
}

#[tauri::command]
pub async fn repository_sources_refresh(store: State<'_, Arc<SkillStore>>, id: String) -> Result<RepositorySnapshot, String> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || repository_sources::refresh_source(&store, &id).map_err(|e| e.to_string()))
        .await.map_err(|_| "repository source refresh failed".to_string())?
}
