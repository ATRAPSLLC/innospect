# innospect

A pure-Rust parser for [Inno Setup](https://jrsoftware.org/isinfo.php) installer
binaries. Provides typed access to the loader stub overlay, setup headers, every
typed record stream, and on-demand file extraction across Inno Setup 5.0 through
the 7.x preview series - including the modern XChaCha20 / `euFiles` / `euFull`
encryption modes and the legacy ARC4 + SHA-1 / MD5 password-verifier path.

Built for **malware analysis** and **reverse engineering**. The crate is
adversarial-input-safe: `unsafe_code`, panicking unwraps, slice indexing, and
arithmetic-with-side-effects are all denied at the lib root.

[![Crates.io](https://img.shields.io/crates/v/innospect.svg)](https://crates.io/crates/innospect)
[![Docs.rs](https://img.shields.io/docsrs/innospect)](https://docs.rs/innospect)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Features

- **PE locator** - both the modern signature-scan path (5.1.5+) and the legacy
  `0x30` file-offset pointer used by pre-5.1.5 installers; tolerates BlackBox /
  GOG re-packagers.
- **Setup-0 decompression** - Stored / Zlib / LZMA1 / LZMA2 across every
  documented version cutover, with the standalone-encryption-header path for
  6.5+ and the inline-verifier path for 6.4.x.
- **Setup-1 file extraction** - solid-LZMA chunks with per-file BCJ inverse
  filtering (4108 / 5200 / 5.3.9-flip variants) and SHA-256 / SHA-1 / MD5 /
  CRC-32 / Adler-32 checksum verification at EOF.
- **Per-version `TSetupHeader`** - every `String` / `AnsiString` / count / tail
  field across the 1.x..7.x history, with `[Files]` / `[Run]` / `[Icons]` /
  `[Registry]` / `[INI]` / `[Components]` / `[Tasks]` / `[Types]` / `[Languages]`
  / `[CustomMessages]` / `[Permissions]` records typed individually.
- **Encryption** - XChaCha20 with PBKDF2-SHA-256 key derivation (Inno 6.4+);
  ARC4 with salted SHA-1 (5.3.9..6.4) or MD5 (4.2..5.3.9); CRC32 verifier
  (pre-4.2). Password trial via `from_bytes_with_passwords`.
- **Embedded `[Code]` / IFPS** - re-exports the
  [`pascalscript`](https://crates.io/crates/pascalscript) container parser; the
  `inno_api_description` table maps Inno-runtime imports
  (`RegWriteStringValue`, `Exec`, `ShellExec`, …) to one-line summaries for
  triage.
- **Analysis API** - `exec_commands()` / `registry_ops()` / `shortcuts()` walk
  the relevant record streams and tag each entry with install-vs-uninstall
  phase, registry-write classification, or icon-target resolution.
- **Uninstaller reconstruction** - `extract_uninstaller()` patches the loader
  stub bytes back to the canonical `InUn` form.

## Quick start

```rust,ignore
use innospect::{HeaderOption, InnoInstaller, RegistryOpKind};

let bytes = std::fs::read("setup.exe")?;
let inst = InnoInstaller::from_bytes(&bytes)?;

let v = inst.version();
println!("Inno {}.{}.{}.{}  {}", v.a, v.b, v.c, v.d, v.marker_str());

if let Some(h) = inst.header() {
    println!("AppName: {}", h.app_name().unwrap_or(""));
    println!("Files:   {}", h.counts().files);
    println!("Encrypted: {}", h.has_option(HeaderOption::Password));
}

// Extract every file (skipping the uninstaller-stub entry).
for (file, contents) in inst.extract_files().filter_map(Result::ok) {
    println!("{} -> {} bytes", file.destination, contents.len());
}

// Analysis: exec commands, registry writes, resolved shortcut targets.
for cmd in inst.exec_commands() {
    println!("{:?} {} {}", cmd.phase, cmd.filename(), cmd.parameters());
}
let writes = inst
    .registry_ops()
    .filter(|op| op.kind == RegistryOpKind::Write)
    .count();
println!("Registry writes: {writes}");
```

For password-protected installers:

```rust,ignore
use innospect::{Error, InnoInstaller};

let bytes = std::fs::read("encrypted-setup.exe")?;
match InnoInstaller::from_bytes_with_passwords(&bytes, &["test123"]) {
    Ok(inst)                   => println!("Unlocked with {:?}", inst.password_used()),
    Err(Error::PasswordRequired) => eprintln!("Installer is encrypted; no password supplied"),
    Err(Error::WrongPassword)    => eprintln!("None of the candidate passwords matched"),
    Err(e)                       => eprintln!("Parse failed: {e}"),
}
```

A full inspection tool ships in `examples/dump.rs`:

```bash
cargo run --example dump -- path/to/setup.exe
```

## Coverage

End-to-end tested against:

- Real-world: HeidiSQL 12.17 (6.4.0.1), ImageMagick 7.1.2 (6.1.0).
- Synthetic plain matrix: 5.0.8, 5.1.14, 5.2.3, 5.3.11, 5.4.3, 5.5.5, 5.5.7,
  6.0.0u, 6.3.0, 6.4.3, 6.5.2, 6.5.2-alt, 6.6.1, 6.7.0, 7.0.0-preview-3.
- Synthetic encrypted matrix (password `test123`): same version ladder for
  `enc-files-*` (per-chunk encryption) plus `enc-full-*` for 6.5.2+ (`euFull`
  whole-stream encryption).

Format paths recognized but not yet exercised by the public sample matrix:
4.x, 3.x / 2.x, 16-bit 1.2.x, ISX (My Inno Setup Extensions), and multi-slice
(`DiskSpanning=yes`).

## Minimum Rust version

1.88 (edition 2024). Pinned by `rust-version` in `Cargo.toml`; the CI matrix
exercises both `1.88` and `stable`.

## License

Copyright 2026 ATRAPS LLC. Licensed under the Apache License,
Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
