#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Disk enumeration and writing are intentionally not implemented yet.
// Before enabling them, add stable device identity checks, explicit destructive
// consent, privilege boundaries, system-disk protection and read-back verification.
fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running AllBoot ISO Maker");
}