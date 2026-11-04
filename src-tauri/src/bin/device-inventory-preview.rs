#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[path = "../core/device_inventory.rs"]
mod device_inventory;

use std::path::PathBuf;

/// Preview only: inspect local paths explicitly provided by the user.
#[tauri::command]
async fn inspect_inventory(agent_dir: String, allowed_root: String) -> Result<device_inventory::Inventory, String> {
    let agent_dir = agent_dir.trim().to_string();
    let allowed_root = allowed_root.trim().to_string();
    if agent_dir.is_empty() {
        return Err("请填写要检查的测试目录。".into());
    }
    let roots: Vec<PathBuf> = if allowed_root.is_empty() {
        Vec::new()
    } else {
        vec![PathBuf::from(allowed_root)]
    };
    tauri::async_runtime::spawn_blocking(move || {
        device_inventory::inspect(&PathBuf::from(agent_dir), &roots)
    })
    .await
    .map_err(|_| "读取失败，请重试。".to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![inspect_inventory])
        .run(tauri::generate_context!("tauri.inventory.conf.json"))
        .expect("inventory preview failed");
}
