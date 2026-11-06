#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use std::path::Path;
use app_lib::core::{repository_sources as repos, skill_store::SkillStore};
use tauri::State;

struct PreviewResources {
    store: SkillStore,
}

struct Preview {
    resources: Arc<PreviewResources>,
}

#[tauri::command]
fn repository_sources_list(state: State<'_, Preview>) -> Result<Vec<repos::RepositorySource>, String> {
    state.resources.store.list_repository_sources().map_err(|e| e.to_string())
}

#[tauri::command]
fn repository_sources_add(
    state: State<'_, Preview>, name: String, device_id: Option<String>,
    url: String, branch: String, skills_root: String,
) -> Result<repos::RepositorySource, String> {
    // The preview labels sources by name only; it never connects to a device.
    if device_id.is_some() { return Err("device association is unavailable in this preview".into()); }
    repos::add_source(&state.resources.store, &name, None, &url, &branch, &skills_root).map_err(|e| e.to_string())
}

#[tauri::command]
fn repository_sources_remove(state: State<'_, Preview>, id: String) -> Result<bool, String> {
    state.resources.store.delete_repository_source(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn repository_sources_snapshot(state: State<'_, Preview>, id: String) -> Result<Option<repos::RepositorySnapshot>, String> {
    state.resources.store.get_repository_snapshot(&id).map_err(|e| e.to_string())
}

#[tauri::command]
async fn repository_sources_refresh(state: State<'_, Preview>, id: String) -> Result<repos::RepositorySnapshot, String> {
    let resources = state.resources.clone();
    tauri::async_runtime::spawn_blocking(move || repos::refresh_source(&resources.store, &id).map_err(|e| e.to_string()))
        .await.map_err(|_| "repository refresh task failed".to_string())?
}

fn open_preview_store_at(directory: &Path) -> anyhow::Result<SkillStore> {
    std::fs::create_dir_all(directory)?;
    // SkillStore creates its encryption key if missing. Serialize startup across
    // processes so simultaneous first launches cannot replace each other's key.
    let lock = std::fs::OpenOptions::new().create(true).read(true).write(true)
        .open(directory.join("initialize.lock"))?;
    fs2::FileExt::lock_exclusive(&lock)?;
    let result = SkillStore::new(&directory.join("preview.db"));
    fs2::FileExt::unlock(&lock)?;
    result
}

fn main() {
    let data_dir = dirs::data_local_dir()
        .expect("cannot find local application data directory")
        .join("dev.skillsmanager.repositoryreadonlypreview")
        .join("preview-store");
    let store = open_preview_store_at(&data_dir)
        .expect("failed to initialize isolated preview store");
    tauri::Builder::default()
        .manage(Preview { resources: Arc::new(PreviewResources { store }) })
        .invoke_handler(tauri::generate_handler![
            repository_sources_list, repository_sources_add, repository_sources_remove,
            repository_sources_snapshot, repository_sources_refresh
        ])
        .run(tauri::generate_context!("tauri.repository-preview.conf.json"))
        .expect("repository preview failed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_preview_context_uses_visible_isolated_configuration() {
        let context: tauri::Context<tauri::Wry> = tauri::generate_context!("tauri.repository-preview.conf.json");
        let config = context.config();
        assert_eq!(config.identifier, "dev.skillsmanager.repositoryreadonlypreview");
        assert_eq!(config.app.windows.len(), 1);
        assert!(config.app.windows[0].visible, "preview window must be visible");
        assert_eq!(config.app.windows[0].title, "Skills Manager · 双仓库只读预览");
    }

    #[test]
    fn preview_sources_and_last_snapshot_survive_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("isolated-preview");
        let store = open_preview_store_at(&directory).unwrap();
        let source = repos::add_source(&store, "test-device", None,
            "https://example.invalid/user/repo.git", "main", "").unwrap();
        let sequence = store.reserve_repository_refresh(&source.id).unwrap();
        let snapshot = repos::RepositorySnapshot {
            source_id: source.id.clone(),
            head_commit: "test-commit".into(),
            fetched_at: 1,
            observed_at: sequence,
            skills: vec![repos::RepositorySkill { name: "demo".into(), relative_path: "demo".into() }],
        };
        store.save_repository_snapshot(&snapshot).unwrap();
        drop(store);
        let reopened = open_preview_store_at(&directory).unwrap();
        assert_eq!(reopened.list_repository_sources().unwrap().len(), 1);
        let restored = reopened.get_repository_snapshot(&source.id).unwrap().unwrap();
        assert_eq!(restored.head_commit, "test-commit");
        assert_eq!(restored.skills[0].name, "demo");
        assert!(!temp.path().join(".skills-manager").exists());
    }
    #[test]
    fn simultaneous_first_launch_preserves_shared_encryption_key() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("race-preview");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2).map(|index| {
            let directory = directory.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let store = open_preview_store_at(&directory).unwrap();
                repos::add_source(&store, &format!("source-{index}"), None,
                    "https://example.invalid/user/repo.git", "main", "").unwrap();
            })
        }).collect();
        for worker in workers { worker.join().unwrap(); }
        let reopened = open_preview_store_at(&directory).unwrap();
        assert_eq!(reopened.list_repository_sources().unwrap().len(), 2);
    }

}
