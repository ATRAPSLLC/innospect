# Test samples

Real-world and synthetic Inno Setup installers used as parser
fixtures by `tests/integration.rs`. Binaries are **not checked in**
(`Cargo.toml` `exclude`, `.gitignore`); fetch the public ones with
the commands below and rebuild the synthetic ones from
[`build/`](build/) on the Windows host.

## Layout

```
tests/samples/
├── heidisql-setup.exe          # real-world, fetched
├── imagemagick-setup.exe       # real-world, fetched
├── plain/                      # synthetic, no encryption
├── encrypted/                  # synthetic, password = "test123"
│   └── payload.txt             # canonical 21-byte fixture
├── quarantine/                 # samples that reveal known parser gaps
└── build/                      # build-toolchain + .iss sources
    ├── build-toolchain.ps1
    ├── uninstall-inno.ps1
    ├── plain.iss
    ├── encrypted.iss
    ├── encrypted-full.iss
    └── payload.txt
```

The `payload.txt` content (`Inno test payload v1\n`, 21 bytes) is
identical in [`build/`](build/) and [`encrypted/`](encrypted/);
`encrypted/payload.txt` is the canonical fixture the integration
test asserts against post-decrypt.

## Real-world samples (top-level)

| File                    | Inno marker                          | SetupLdr family                            | Source |
| ----------------------- | ------------------------------------ | ------------------------------------------ | ------ |
| `heidisql-setup.exe`    | `Inno Setup Setup Data (6.4.0.1)`    | `72446c507453cde6d77b0b2a` (5.1.5+ family) | HeidiSQL 12.17 release |
| `imagemagick-setup.exe` | `Inno Setup Setup Data (6.1.0) (u)`  | `72446c507453cde6d77b0b2a` (5.1.5+ family) | ImageMagick 7.1.2-21   |

```bash
curl -Lo tests/samples/heidisql-setup.exe \
  https://github.com/HeidiSQL/HeidiSQL/releases/download/12.17/HeidiSQL_12.17.0.7270_Setup.exe

curl -Lo tests/samples/imagemagick-setup.exe \
  https://github.com/ImageMagick/ImageMagick/releases/download/7.1.2-21/ImageMagick-7.1.2-21-Q16-HDRI-x86-static.exe
```

Both have the post-5.1.5 `rDlPtS…` SetupLdr magic in the PE
resource (`RESEARCH.md` §2.3).

## Synthetic - plain (`plain/`)

No encryption. Used by `plain_samples_parse_and_extract`, which
asserts every sample parses cleanly, reports `is_encrypted() ==
false`, reconstructs an uninstaller via `extract_uninstaller()`,
and yields the canonical `payload.txt` via `extract_files()`.

| File                       | Inno version    | Notes                                         |
| -------------------------- | --------------- | --------------------------------------------- |
| `plain-tool5_0_8.exe`      | 5.0.8           | Pre-`AppSupportPhone` / interleaved-AnsiString header (1.3.0..5.2.5 layout) |
| `plain-tool5_1_14.exe`     | 5.1.14          | Adds `AppSupportPhone`; still pre-5.2.5 AnsiString placement                |
| `plain-tool5_2_3.exe`      | 5.2.3           | Pre-5.2.5 AnsiString placement + `UninstallerSignature` (5.2.1..5.3.10)     |
| `plain-tool5_3_11.exe`     | 5.3.11          | First post-5.2.5 / post-5.3.10 release in our matrix                        |
| `plain-tool5_4_3.exe`      | 5.4.3           | Mid-5.x coverage                                                            |
| `plain-tool5_5_5.exe`      | 5.5.5           | Pre-`SetupMutex` (5.5.6+) header                                            |
| `plain-tool5_5_7.exe`      | 5.5.7           | Pre-Unicode-default ANSI build path           |
| `plain-tool6_0_0u.exe`     | 6.0.0 (Unicode) | 6.x ANSI/Unicode boundary                     |
| `plain-tool6_3_0.exe`      | 6.3.0           | Last pre-architectures-string release         |
| `plain-tool6_4_3.exe`      | 6.4.3           | First XChaCha20-era release                   |
| `plain-tool6_5_2.exe`      | 6.5.2           | First standalone-encryption-header release    |
| `plain-tool6_5_2-alt.exe`  | 6.5.2           | Same script, second build - nondeterminism check |
| `plain-tool6_6_1.exe`      | 6.6.1           | Mid-range 6.x coverage                        |
| `plain-tool7_0_0_1.exe`    | 7.0.0-preview-3 | Buggy-PBKDF2 marker `(7,0,0,1)` regression sample |

**Gap:** no `plain-tool6_7_0.exe`. The 6.7.0 toolchain run only
produced encrypted variants. Rebuild with `-Tag is-6_7_0` (no
`-WithFull` needed for the plain output) to fill it in.

## Synthetic - encrypted (`encrypted/`)

All share password **`test123`** and the canonical `payload.txt`
(21 bytes, `Inno test payload v1\n`). Used by
`encrypted_samples_parse_and_unlock`, which asserts:

1. `is_encrypted()` returns `true`.
2. Empty password list → `Error::PasswordRequired`.
3. Wrong password (`"nope"`) → `Error::WrongPassword`.
4. `"test123"` unlocks; `password_used()` reports `Some("test123")`.
5. `payload.txt` extracts to the canonical bytes.
6. For `enc-full-*`: setup-0 itself decrypts to non-empty bytes
   and the header parses post-decrypt.

| File                            | Inno version    | Mode      | Cipher / verifier                                     |
| ------------------------------- | --------------- | --------- | ----------------------------------------------------- |
| `enc-files-tool5_0_8.exe`       | 5.0.8           | per-chunk | ARC4 + MD5 (pre-5.3.9 legacy verifier)                |
| `enc-files-tool5_1_14.exe`      | 5.1.14          | per-chunk | ARC4 + MD5                                            |
| `enc-files-tool5_2_3.exe`       | 5.2.3           | per-chunk | ARC4 + MD5                                            |
| `enc-files-tool5_3_11.exe`      | 5.3.11          | per-chunk | ARC4 + salted SHA-1 (5.3.9+ verifier)                 |
| `enc-files-tool5_4_3.exe`       | 5.4.3           | per-chunk | ARC4 + salted SHA-1                                   |
| `enc-files-tool5_5_5.exe`       | 5.5.5           | per-chunk | ARC4 + salted SHA-1                                   |
| `enc-files-tool5_5_7.exe`       | 5.5.7           | per-chunk | ARC4 + salted SHA-1                                   |
| `enc-files-tool6_0_0u.exe`      | 6.0.0 (Unicode) | per-chunk | ARC4 + SHA-1                                          |
| `enc-files-tool6_3_0.exe`       | 6.3.0           | per-chunk | ARC4 + SHA-1 (last pre-6.4 ARC4 release)              |
| `enc-files-tool6_4_3.exe`       | 6.4.3           | euFiles   | XChaCha20 / inline `PasswordTest` (PBKDF2)            |
| `enc-files-tool6_5_2.exe`       | 6.5.2           | euFiles   | XChaCha20 / `TSetupEncryptionHeader`                  |
| `enc-files-tool6_5_2-alt.exe`   | 6.5.2           | euFiles   | XChaCha20 - nondeterminism rebuild                    |
| `enc-files-tool6_6_1.exe`       | 6.6.1           | euFiles   | XChaCha20                                             |
| `enc-files-tool6_7_0.exe`       | 6.7.0           | euFiles   | XChaCha20                                             |
| `enc-files-tool7_0_0_1.exe`     | 7.0.0-preview-3 | euFiles   | XChaCha20 with **buggy PBKDF2** (XOR'd `U_1`)         |
| `enc-full-tool6_5_2.exe`        | 6.5.2           | euFull    | XChaCha20 / `sccCompressedBlocks1/2`                  |
| `enc-full-tool6_5_2-alt.exe`    | 6.5.2           | euFull    | XChaCha20 - nondeterminism rebuild                    |
| `enc-full-tool6_6_1.exe`        | 6.6.1           | euFull    | XChaCha20                                             |
| `enc-full-tool6_7_0.exe`        | 6.7.0           | euFull    | XChaCha20                                             |
| `enc-full-tool7_0_0_1.exe`      | 7.0.0-preview-3 | euFull    | XChaCha20 with buggy PBKDF2                           |

Pre-6.4 samples (`5_5_7`, `6_0_0u`, `6_3_0`) predate
`TSetupEncryptionHeader`, so `dump`'s `encryption:` line will
read `None` even though the installer is password-protected. The
legacy indicator lives in the setup-header `Options` bitset:
`inst.has_option(HeaderOption::Password)` returns `true`.

## Quarantine (`quarantine/`)

Samples that successfully build but currently fail parse - each
pinpoints a specific format-coverage gap and serves as a
regression fixture for the eventual fix. These are **not** walked
by `plain_samples_parse_and_extract` /
`encrypted_samples_parse_and_unlock`; once the corresponding
ToDo Stage 3 ladder lands, the matching pair moves back to
`plain/` + `encrypted/`.

No samples currently quarantined - every produced sample pair parses
and its `payload.txt` extracts cleanly. The pre-5.5 ladder
(5.0.8..5.4.3) was promoted into `plain/` + `encrypted/` once the
header parser learnt the per-version `String` / `AnsiString` field
walk, the 5.2.1..5.3.10 `UninstallerSignature` field, and the
pre-5.5.0 `TSetupHeaderOption` bit table (mirroring innoextract's
`header::load_flags`).

## Filename convention

Outputs are named by `build-toolchain.ps1`'s slug - `Version` with
`.` replaced by `_`, optional `-alt` for nondeterminism rebuilds,
`_ansi` for explicit pre-5.3 ANSI builds:

```
plain-tool<slug>[-alt|_ansi].exe
enc-files-tool<slug>[-alt|_ansi].exe   # euFiles (or pre-6.5 ARC4 chunk-encrypt)
enc-full-tool<slug>[-alt|_ansi].exe    # euFull, 6.5+ only (-WithFull)
```

## Building (Windows host)

The single source of truth is
[`build/build-toolchain.ps1`](build/build-toolchain.ps1), which
uninstalls every existing Inno Setup, fetches the requested
version, installs it, locates `ISCC.exe` via the registry entry
whose `DisplayVersion` matches, and builds `plain.iss` +
`encrypted.iss` (+ `encrypted-full.iss` when `-WithFull` is set).

```powershell
# On the Windows sample-build host, in %USERPROFILE%\inno-test\:
.\build-toolchain.ps1 -Version 5.5.7  -Tag is-5_5_7
.\build-toolchain.ps1 -Version 6.0.0  -Tag is-6_0_0
.\build-toolchain.ps1 -Version 6.3.0  -Tag is-6_3_0
.\build-toolchain.ps1 -Version 6.4.3  -Tag is-6_4_3
.\build-toolchain.ps1 -Version 6.5.2  -Tag is-6_5_2 -WithFull
.\build-toolchain.ps1 -Version 6.6.1  -Tag is-6_6_1 -WithFull
.\build-toolchain.ps1 -Version 6.7.0  -Tag is-6_7_0 -WithFull
.\build-toolchain.ps1 -Version 7.0.0  -Tag is-7_0_0 -WithFull
```

Outputs land alongside the script as `plain-tool<slug>.exe`,
`enc-files-tool<slug>.exe`, and (with `-WithFull`)
`enc-full-tool<slug>.exe`.

### Transferring outputs back

```bash
# From the dev workstation, with the build host's SSH config aliased
# (e.g. as `inno-build`):
scp 'inno-build:inno-test/plain-tool*.exe'    tests/samples/plain/
scp 'inno-build:inno-test/enc-files-tool*.exe' tests/samples/encrypted/
scp 'inno-build:inno-test/enc-full-tool*.exe'  tests/samples/encrypted/
```

## Coverage gaps

Versions and edge cases not yet in the matrix:

- **Plain 6.7.0** - see note above; trivial rebuild.
- **4.x** representative - needs older VC runtime on the host.
- **3.x / 2.x / 1.5** - pre-4.0.9 setup-loader paths.
- **16-bit 1.2.x** - pre-PE setup loader; needs a separate build
  script. Validates `BITS16` flag and `i1.2.10--16` legacy marker.
- **ISX (`My Inno Setup Extensions ≤ 3.0.6.1`)** - validates
  `Variant::Isx` discrimination.
- **Multi-slice** - `DiskSpanning=yes` + small `DiskSliceSize`,
  unblocks the multi-slice extraction path.
- **7.0.0.3+** - once a fix-bearing 7.x ISCC ships, validates
  `CompiledCodeVersion` / `Bitness` claims and lets us replace the
  marker-keyed PBKDF2 gate with a `SetupBinVersion` check.

## Ad-hoc inspection

```bash
cargo run --quiet --example dump tests/samples/encrypted/enc-files-tool6_4_3.exe \
  | grep -E 'encryption|version'
```
