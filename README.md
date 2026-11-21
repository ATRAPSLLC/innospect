# innospect

A pure-Rust parser for [Inno Setup](https://jrsoftware.org/isinfo.php) installer
binaries. Provides typed access to the loader stub overlay, setup headers, every
typed record stream, and on-demand file extraction across Inno Setup 1.2.10
through 7.1.1 - including the modern XChaCha20 / `euFiles` / `euFull`
encryption modes, the legacy ARC4 + SHA-1 / MD5 password-verifier path, and
disk-spanning installers whose files are in slice files beside them.

Built for **malware analysis** and **reverse engineering**. The crate is
adversarial-input-safe: `unsafe_code`, panicking unwraps, slice indexing, and
arithmetic-with-side-effects are all denied at the lib root.

[![Crates.io](https://img.shields.io/crates/v/innospect.svg)](https://crates.io/crates/innospect)
[![Docs.rs](https://img.shields.io/docsrs/innospect)](https://docs.rs/innospect)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Features

- **Loader** - the modern signature-scan path (5.1.5+) and the legacy `0x30`
  file-offset pointer of earlier installers, in a PE or, for 16-bit 1.2.x, an
  NE executable.
- **Setup-0 decompression** - Stored / Zlib / LZMA1 / LZMA2 across every
  documented version cutover, with the standalone-encryption-header path for
  6.5+ and the inline-verifier path for 6.4.x. Both blocks are read to their
  last byte, so a layout misread fails instead of returning garbage.
- **Setup-1 file extraction** - stored, zlib, bzip2, LZMA1 and LZMA2 chunks,
  solid or per file, with per-file BCJ inverse filtering (4108 / 5200 /
  5.3.9-flip variants) and SHA-256 / SHA-1 / MD5 / CRC-32 / Adler-32 checksum
  verification at EOF; from the installer itself or from its slice files
  (`with_slices`, `slice_file_name`), chunks spanning them included.
- **Hostile input** - no `unsafe`, no panics, and bounded allocation:
  decompression stops where the files it serves end, and a setup-0 block may
  not decompress past 256 MiB.
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
- **Wizard images and DLLs** - `wizard_images()` / `wizard_images_dark()` (BMP
  or PNG, every size the script lists), and the decompressor, decryption
  (`ISCrypt.dll`) and 7-Zip DLLs Setup extracts before it installs.
- **Uninstaller reconstruction** - `extract_uninstaller()` patches the loader
  stub bytes back to the canonical `InUn` form (5.0+), or extracts the separate
  `Uninst.e32` earlier releases store as a file.

## Quick start

```rust,ignore
use innospect::{HeaderOption, InnoInstaller, RegistryOpKind};

let bytes = std::fs::read("setup.exe")?;
let inst = InnoInstaller::from_bytes(&bytes)?;

println!("Inno {} ({})", inst.version(), inst.version().marker_str());

if let Some(h) = inst.header() {
    println!("AppName: {}", h.app_name().unwrap_or(""));
    println!("Files:   {}", h.counts().files);
    println!("Encrypted: {}  password: {}", inst.is_encrypted(), inst.has_password());
    println!("Restart:   {}", h.has_option(HeaderOption::AlwaysRestart));
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

For a disk-spanning installer, supply its slice files:

```rust,ignore
let inst = InnoInstaller::from_bytes(&bytes)?;
let names: Vec<String> = (0..inst.slice_count())
    .map(|i| inst.slice_file_name(i, "setup.exe"))
    .collect();
let slices: Vec<Vec<u8>> = names.iter().map(std::fs::read).collect::<Result<_, _>>()?;
let slices: Vec<&[u8]> = slices.iter().map(Vec::as_slice).collect();
let inst = inst.with_slices(&slices)?;
```

A full inspection tool ships in `examples/dump.rs`:

```bash
cargo run --example dump -- path/to/setup.exe
```

## Supported versions

| Inno Setup      | Parse | Extract | Checked against |
| --------------- | ----- | ------- | --------------- |
| 1.2.10 (16-bit) | yes   | yes     | upstream source; 1.2.16's own package |
| 1.2.10 (32-bit) | yes   | yes     | upstream source only (no compiler survives) |
| 1.3.25 to 4.2.6 | yes   | yes     | upstream source; one compiler per setup data marker |
| 5.0.0 to 7.1.1  | yes   | yes     | upstream source; one compiler per marker, ANSI and Unicode |

Not supported: My Inno Setup Extensions (ISX) installers are recognised but
untested; BlackBox, GOG and GOG Galaxy repackagings are not detected; 7.2.0
waits for its release.

## Coverage

Every fixture but one is built from a script in `tests/samples/build/` by the
official Inno Setup compilers, run under Wine in Docker (`build-wine.sh`), and
committed:

- Plain: every setup data marker from 5.0.0 to 7.1.1, those from 5.3.0 to 5.5.x
  in both the ANSI and the Unicode edition, plus 5.6.1 (both), a second 6.5.2
  build (nondeterminism), a 64-bit 7.1.1 installer, and zip, bzip2 and stored
  builds (5.5.7, 7.1.1).
- Encrypted (password `test123`): the same ladder for `enc-files-*` (per-chunk
  encryption), plus `enc-full-*` (`euFull` whole-stream encryption) for 6.5.2+.
- Password only (`Password=` without encryption): 5.5.7, 6.4.3, 7.0.2, 7.1.1.
- Every record stream (`full.iss`, including every registry operation and a
  file stored uncompressed): 6.1.0, 6.4.0, 6.4.2, 7.0.2, 7.1.1 and a 64-bit
  7.1.1 installer; a compiled `[Code]` script (`code.iss`): 6.4.3.
- Dark-mode and back wizard images and the 7-Zip DLL (`modern.iss`): 6.6.1,
  6.7.0, 7.1.1. Every stored DLL is checked against its compiler's own file.
- Before 5.0 (`legacy.iss`, every record type 1.3 knows, plus types,
  components and tasks from 2.0): one compiler for each setup data marker from
  1.3.25 to 4.2.6, 1.3.26 through 4.2.7, among them 3.0.4 and 4.2.4, which
  write the markers `(3.0.3)` and `(4.2.3)` with a layout of their own; and
  bzip2, LZMA and zip builds where the method changes the format (2.0.19 to
  4.2.7).
- 1.2.x: Inno Setup 1.2.16's own 16-bit package, as published, the one
  fixture not built here (no 32-bit 1.2 compiler survives, and Wine cannot run
  the 16-bit one).
- Disk spanning (`spanning.iss`): one build per slice-file generation, 1.3.26,
  2.0.19, 4.0.8, 4.2.7, 5.5.7, 6.5.1 and 7.1.1, with a chunk across three
  slices.
- 7.0.0 previews 2 and 3, which write the same SetupID with different key
  derivations: encrypted, `euFull` and password-only builds of each.

The setup header's string table is also checked against upstream's own
`TSetupHeader` declaration for every format marker whose source is available,
1.2.10 (32- and 16-bit) through 7.1.1, both layouts written as `(4.2.3)`
included.

Format paths recognized but not exercised by a fixture: the 32-bit 1.2.x build
(its records are checked against upstream's layouts) and ISX.

## Minimum Rust version

1.88 (edition 2024). Pinned by `rust-version` in `Cargo.toml`; the CI matrix
exercises both `1.88` and `stable`.

## License

Copyright 2026 ATRAPS LLC. Licensed under the Apache License,
Version 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
