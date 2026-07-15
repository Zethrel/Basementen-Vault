# Fuzzing

Coverage-guided ([cargo-fuzz] / libFuzzer) harnesses for Basementen Vault's
**untrusted-input parsers** — the surfaces an attacker or a corrupt file can
reach. They complement the property-based (`proptest`) tests in the crates; the
goal here is to prove these parsers never panic, hang, or exhaust memory on
hostile bytes.

This is a **standalone crate**, deliberately detached from the workspace (it
needs a nightly toolchain and the libFuzzer runtime), so it never affects the
stable `cargo build --workspace` / `cargo test --workspace` used by CI.

## Targets

| Target | Function under test | Surface |
|--------|--------------------|---------|
| `import_csv` | `desktop_core::import_csv` | CSV import from other managers (largest untrusted-file surface) |
| `import_encrypted` | `desktop_core::import_encrypted` | encrypted-export decode: JSON envelope → KDF-param validation → Argon2 → AEAD → payload JSON |
| `item_from_plaintext` | `desktop_core::Item::from_plaintext` | decrypted-item JSON decode |

Each target ignores the `Ok`/`Err` result — a finding is a **panic, hang, or
OOM**, which libFuzzer reports as a crash.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz          # or: cargo binstall cargo-fuzz

# From this directory:
cargo +nightly fuzz run import_csv
cargo +nightly fuzz run import_encrypted
cargo +nightly fuzz run item_from_plaintext

# Time-boxed (what CI runs):
cargo +nightly fuzz run import_csv -- -max_total_time=30
```

A committed seed `corpus/<target>/` gets the fuzzer past the format gates (e.g.
a structurally valid export envelope) so the deeper stages get real coverage.
Crash reproducers land in `artifacts/<target>/` — re-run one with
`cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>`.

CI runs a short smoke of every target on each push (`.github/workflows/fuzz.yml`);
longer campaigns are run locally or out-of-band.

[cargo-fuzz]: https://github.com/rust-fuzz/cargo-fuzz
