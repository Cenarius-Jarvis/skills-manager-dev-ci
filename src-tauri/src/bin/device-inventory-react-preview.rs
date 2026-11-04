#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[path = "../core/device_inventory.rs"]
mod device_inventory;

/// Standalone preview only. No database, channel, bridge, or deployment service.
#[tauri::command]
async fn devices_inspect_local(
    agent_dir: String,
    allowed_roots: Vec<String>,
) -> Result<device_inventory::Inventory, String> {
    let path = agent_dir.trim().to_string();
    if path.is_empty() {
        return Err("agent directory is required".into());
    }
    if allowed_roots.iter().any(|root| root.trim().is_empty()) {
        return Err("allowed roots must not be empty".into());
    }
    tauri::async_runtime::spawn_blocking(move || {
        let roots: Vec<std::path::PathBuf> = allowed_roots
            .iter()
            .map(|root| std::path::PathBuf::from(root.as_str()))
            .collect();
        device_inventory::inspect(std::path::Path::new(&path), &roots)
    })
    .await
    .map_err(|_| "inventory inspection failed".to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![devices_inspect_local])
        .run(tauri::generate_context!("tauri.inventory-react.conf.json"))
        .expect("inventory component preview failed");
}
