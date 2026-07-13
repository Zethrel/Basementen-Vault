# Basementen Vault — desktop app

Tauri 2 shell over the `desktop-core` crate. The UI is plain HTML/CSS/JS in
`ui/` — no Node, no build step; assets are embedded into the binary at
compile time.

## Building

Linux build dependencies (Debian/Ubuntu):

```sh
sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libxdo-dev
```

macOS and Windows need no extra system packages beyond a Rust toolchain.

```sh
cargo build --release -p basementen-vault-desktop
./target/release/basementen-vault-desktop
```

To produce installers/bundles (`.deb`, `.dmg`, `.msi`), flip
`bundle.active` to `true` in `src-tauri/tauri.conf.json` and use
`cargo tauri build` (requires `cargo install tauri-cli`).

## Architecture

- `src-tauri/src/main.rs` — command layer only: session lifecycle (login,
  offline unlock, auto-lock watchdog), marshalling between the UI and
  `desktop-core`. Dropping the session zeroizes all key material.
- `desktop-core` — SQLite local replica (offline-first), API client with
  token rotation, item schema/search, password generator. Fully unit- and
  integration-tested headlessly, including against a real server over TCP.
- `ui/` — screens: setup (register/login), Recovery Kit display, unlock,
  vault (search, item editor, password generator, copy with 30 s clipboard
  auto-clear).

Deferred (tracked in the plan): OS keychain / biometric quick-unlock and a
system-tray quick search.
