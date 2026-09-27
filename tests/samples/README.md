# Test samples

Inno Setup installers used as parser fixtures by
`tests/integration.rs`, every one built here from a script in
[`build/`](build/) by the official compilers, run under Wine. They are
committed, so CI runs on them; nothing here is third-party, so there is
nothing to redistribute. They are left out of the published crate
(`Cargo.toml` `exclude`). `build/build-wine.sh --all` rebuilds them all
(see [Building](#building)).

## Layout

```
tests/samples/
├── plain/                      # synthetic, no encryption
├── encrypted/                  # synthetic, password = "test123"
│   └── payload.txt             # canonical 21-byte fixture
├── full/                       # synthetic, every record stream
├── code/                       # synthetic, a compiled [Code] script
├── quarantine/                 # samples that reveal known parser gaps
└── build/                      # the compiler image + .iss sources
    ├── build-wine.sh           # builds fixtures under Wine, in Docker
    ├── versions.txt            # the compiler matrix
    ├── Dockerfile
    ├── install-inno.sh
    ├── plain.iss
    ├── encrypted.iss
    ├── encrypted-full.iss
    ├── full.iss
    ├── full/                   # full.iss's payload
    ├── code.iss
    └── payload.txt
```

The `payload.txt` content (`Inno test payload v1\n`, 21 bytes) is
identical in [`build/`](build/) and [`encrypted/`](encrypted/);
`encrypted/payload.txt` is the canonical fixture the integration
test asserts against post-decrypt.

## Synthetic - every record stream (`full/`)

What the suite once read from third-party installers (HeidiSQL,
ImageMagick), stated in a script instead, so every value a test asserts
is in [`build/full.iss`](build/full.iss) or its payload
[`build/full/`](build/full/): six languages including non-Latin
codepages, custom messages, a license, tasks, icons that resolve to an
installed file, registry writes under HKCR, HKCU and HKLM, a post-install
launcher and an `isreadme` viewer, and a compiled script importing the
Inno API. Built with the two compilers whose formats those installers
exercised, each with that installer's compression layout:

| File                   | Inno marker                          | Layout |
| ---------------------- | ------------------------------------ | ------ |
| `full-tool6_4_0.exe`   | `Inno Setup Setup Data (6.4.0.1)`    | LZMA2, one solid chunk; SHA-256 checksums; `x64compatible` as a header string |
| `full-tool6_1_0.exe`   | `Inno Setup Setup Data (6.1.0) (u)`  | LZMA1, one chunk per file, the executable through the x86 filter; SHA-1 checksums; packed architecture sets and back colours in the fixed tail |

## Synthetic - compiled script (`code/`)

A `[Code]` section with one routine per construct a PascalScript
consumer has to model: arithmetic on parameters and locals, a `var`
parameter, a global written in a callee, every comparison, `for`,
`while` and `case`, record fields and static and dynamic arrays,
`try`/`finally` and `try`/`except` with a raise, strings, the Inno
API and a DLL import. See [`build/code.iss`](build/code.iss).

| File                   | Inno version | Notes |
| ---------------------- | ------------ | ----- |
| `code-tool6_4_3.exe`   | 6.4.3        | 9 internal procedures, 2 `try` blocks |

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
| `plain-tool6_7_0.exe`      | 6.7.0           | Latest 6.x                                    |
| `plain-tool7_0_0_1.exe`    | 7.0.0-preview-3 | Buggy-PBKDF2 marker `(7,0,0,1)` regression sample |

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

Outputs are named by their `versions.txt` slug - the version with
`.` replaced by `_` - with `-alt` for nondeterminism rebuilds:

```
plain-tool<slug>[-alt].exe
enc-files-tool<slug>[-alt].exe   # euFiles (or pre-6.5 ARC4 chunk-encrypt)
enc-full-tool<slug>[-alt].exe    # euFull, 6.5+ only
<script>-tool<slug>.exe          # anything else, in <script>/
```

## Building

[`build/build-wine.sh`](build/build-wine.sh) runs the official
compilers under Wine in a Docker image ([`build/Dockerfile`](build/Dockerfile)),
with `build/` bind-mounted, and files each output where the tests
look for it:

```bash
tests/samples/build/build-wine.sh --all              # the whole matrix
tests/samples/build/build-wine.sh 6_4_3 plain code   # one compiler, named scripts
tests/samples/build/build-wine.sh --alt 6_5_2 plain  # a nondeterminism rebuild
```

The matrix is [`build/versions.txt`](build/versions.txt): each row names
a fixture slug, the exact installer it is built with (the Unicode or
ANSI build, beta or preview, that its version marker calls for) and the
scripts compiled with it. The image installs every row, plus the
`ISCrypt.dll` add-on the pre-6.4 compilers need to encrypt, and is
rebuilt automatically when the matrix changes.

It replaces the Windows build host these fixtures were first made on.
Control: rebuilt under Wine, 34 of the 35 fixtures that host produced
parse identically (version marker, loader family, compression,
encryption, header strings, entry counts, files, and the extracted
payload). The 35th, `enc-full-tool6_7_0.exe`, had been built from an
earlier `encrypted-full.iss` and differed in exactly what that script
has since changed; the rebuild is current.

## Coverage gaps

Versions and edge cases not yet in the matrix:

- **4.x** representative - no 4.x installer is in the matrix yet.
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
