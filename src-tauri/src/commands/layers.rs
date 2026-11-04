//! Tauri commands for library layers (see `core/library_layers.rs`): user-
//! named subdirectories of the central skills root that group skills
//! without changing per-agent deployment behavior.

use std::sync::Arc;
use tauri::State;

use crate::core::error::AppError;
use crate::core::library_layers::{self, LibraryLayersOverview};
use crate::core::skill_store::SkillStore;

fn input_err(err: anyhow::Error) -> AppError {
    AppError::invalid_input(err.to_string())
}

#[tauri::command]
pub async fn library_layers_get(
    store: State<'_, Arc<SkillStore>>,
) -> Result<LibraryLayersOverview, AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        library_layers::overview(&store).map_err(input_err)
    })
    .await?
}

#[tauri::command]
pub async fn library_layer_create(
    store: State<'_, Arc<SkillStore>>,
    name: String,
) -> Result<String, AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        library_layers::create_layer(&store, &name).map_err(input_err)
    })
    .await?
}

#[tauri::command]
pub async fn library_layer_rename(
    store: State<'_, Arc<SkillStore>>,
    old: String,
    new: String,
) -> Result<String, AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        library_layers::rename_layer(&store, &old, &new).map_err(input_err)
    })
    .await?
}

#[tauri::command]
pub async fn library_layer_delete(
    store: State<'_, Arc<SkillStore>>,
    name: String,
) -> Result<(), AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        library_layers::delete_layer(&store, &name).map_err(input_err)
    })
    .await?
}

#[tauri::command]
pub async fn library_skill_move(
    store: State<'_, Arc<SkillStore>>,
    skill_id: String,
    layer: Option<String>,
) -> Result<(), AppError> {
    let store = store.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        library_layers::move_skill_to_layer(&store, &skill_id, layer.as_deref())
            .map_err(input_err)
    })
    .await?
}
