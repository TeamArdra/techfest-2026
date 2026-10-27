// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use aegis_fastpath::{crc_x25, sanitize_global_position_int, should_drop_frame};

#[tauri::command]
fn fastpath_verify_crc(data: Vec<u8>, crc_extra: u8) -> u16 {
    crc_x25(&data, crc_extra)
}

#[tauri::command]
fn fastpath_sanitize_frame(
    mut frame: Vec<u8>,
    dlat_e7: i32,
    dlon_e7: i32,
    dalt_mm: i32,
    crc_extra: u8,
) -> (bool, Vec<u8>) {
    let ok = sanitize_global_position_int(&mut frame, dlat_e7, dlon_e7, dalt_mm, crc_extra);
    (ok, frame)
}

#[tauri::command]
fn fastpath_should_drop(frame: Vec<u8>, quarantined_sysids: Vec<u8>, flood_active: bool) -> bool {
    should_drop_frame(&frame, &quarantined_sysids, flood_active)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            fastpath_verify_crc,
            fastpath_sanitize_frame,
            fastpath_should_drop
        ])
        .run(tauri::generate_context!())
        .expect("error while running AegisFlight GCS application");
}
