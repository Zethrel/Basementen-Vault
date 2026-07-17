# Mobile builds (Android / iOS)

The mobile apps are the **same Tauri application** as the desktop app
(`apps/desktop`): same Rust core, same command layer, same UI. The UI is
responsive — below 700 px it switches to a phone layout (full-screen list,
slide-over item detail with a back button, larger touch targets) — and the
crate is already structured for mobile entry points (`lib.rs` with
`#[cfg_attr(mobile, tauri::mobile_entry_point)]`, `staticlib`/`cdylib`
crate types).

> Plan note: the original plan proposed Flutter/Kotlin Multiplatform for
> mobile. Tauri 2's mobile support replaces that — one codebase instead of
> three, and the audited Rust crypto core runs in-process on every platform.

## Android

Prerequisites (on your development machine):

1. Android Studio, or plain SDK + NDK:
   - SDK Platform 34+, Build-Tools, Platform-Tools, **NDK 26+**
   - JDK 17
2. Environment: `ANDROID_HOME` and `NDK_HOME` set, e.g.
   ```sh
   export ANDROID_HOME="$HOME/Android/Sdk"
   export NDK_HOME="$ANDROID_HOME/ndk/26.3.11579264"
   ```
3. Rust targets and the Tauri CLI:
   ```sh
   rustup target add aarch64-linux-android armv7-linux-androideabi \
                     i686-linux-android x86_64-linux-android
   cargo install tauri-cli
   ```

Generate the Android project once, then build:

```sh
cd apps/desktop
cargo tauri android init      # generates src-tauri/gen/android
cargo tauri android dev       # run on a connected device/emulator
cargo tauri android build     # release .apk/.aab (set up signing first)
```

### Test APK from CI (no local toolchain needed)

The **Android test APK** workflow (`.github/workflows/android.yml`) builds a
**debug** APK in CI. A debug build is auto-signed with the Android debug
keystore, so it installs on any device with "install unknown apps" enabled — no
release keystore or signing secrets required. Run it from the Actions tab
(*workflow_dispatch*): leave the tag blank to just get a downloadable APK
artifact, or pass a release tag (e.g. `v1.0.0-beta.6`) to also attach the APK to
that release. This is for **testing only** — a Play Store build still needs a
real release keystore and an `.aab` (see RELEASE_CHECKLIST §Mobile).

## iOS (requires a Mac)

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
cargo install tauri-cli
cd apps/desktop
cargo tauri ios init          # generates the Xcode project
cargo tauri ios dev           # run on simulator/device
cargo tauri ios build         # App Store / ad-hoc build via Xcode signing
```

## Talking to your home server from a phone

- **Tailscale (recommended):** install Tailscale on the phone; use your
  server's tailnet name as the Server URL in the app. Works everywhere,
  nothing exposed publicly.
- **Public HTTPS:** any valid-certificate domain works out of the box.
- Plain `http://` URLs are blocked by the OS on both platforms except
  loopback — put TLS (Caddy) or a VPN in front of the server.

## Mobile-specific follow-ups (tracked for M5.x)

- Biometric unlock (Face ID / BiometricPrompt) wrapping a hardware-backed
  cached key — same design as the desktop keychain quick-unlock
- iOS AutoFill credential provider / Android Autofill service integration
- Background sync scheduling and push-style change nudges (the SSE endpoint
  already exists server-side)
