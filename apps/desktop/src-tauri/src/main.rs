//! Desktop binary entry point; mobile platforms enter through
//! `basementen_vault_lib::run` (see lib.rs).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    basementen_vault_lib::run()
}
