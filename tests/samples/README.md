# Test samples

Inno Setup installers used as parser fixtures by
`tests/integration.rs`, every one but those in [`official/`](official/)
built here from a script in [`build/`](build/) by the official compilers,
run under Wine. They are committed, so CI runs on them. They are left out
of the published crate
(`Cargo.toml` `exclude`). `build/build-wine.sh --all` rebuilds them all
(see [Building](#building)).

## Layout

```
tests/samples/
├── plain/                      # synthetic, no encryption
├── encrypted/                  # synthetic, password = "test123"
│   └── payload.txt             # canonical 21-byte fixture
├── full/                       # synthetic, every record stream
├── password/                   # synthetic, a password without encryption
├── code/                       # synthetic, a compiled [Code] script
├── legacy/                     # synthetic, one per setup data marker before 5.0
├── modern/                     # synthetic, dark-mode and back images, the 7-Zip DLL
├── spanning/                   # synthetic, disk spanning: each fixture with its <fixture>.slices/
├── official/                   # upstream's own 1.2.16 package, as published
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
    ├── legacy.iss
    ├── modern.iss
    ├── modern/                 # modern.iss's two PNG images
    ├── spanning.iss            # disk spanning, 4.0+
    ├── spanning-legacy.iss     # disk spanning, 1.x / 2.x dialect
    ├── spanning/               # their payload, random.bin
    ├── list-dlls.sh            # writes compiler-dlls.txt from the image
    ├── compiler-dlls.txt       # SHA-256 of each compiler's stored DLLs
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
installed file, a file stored without compression (`nocompression`, a
chunk of its own), registry entries under HKCR, HKCU, HKLM and HKA with
every value type and one entry for each thing Setup can do with an entry
(each `RegistryOpKind`), a post-install launcher and an `isreadme` viewer,
and a compiled script importing the Inno API. Built with the two compilers whose formats those installers
exercised, each with that installer's compression layout:

| File                   | Inno marker                          | Layout |
| ---------------------- | ------------------------------------ | ------ |
| `full-tool6_4_0.exe`   | `Inno Setup Setup Data (6.4.0.1)`    | LZMA2, one solid chunk; SHA-256 checksums; `x64compatible` as a header string |
| `full-tool6_1_0.exe`   | `Inno Setup Setup Data (6.1.0) (u)`  | LZMA1, one chunk per file, the executable through the x86 filter; SHA-1 checksums; packed architecture sets and back colours in the fixed tail |

## Synthetic - before 5.0 (`legacy/`)

[`build/legacy.iss`](build/legacy.iss), in the script dialect every
compiler from 1.3 accepts, built once per setup data marker from 1.3.25
to 4.2.6, each by the last release that writes it (a beta or pre-release
where only one does). Every record type 1.3 knows is there once - a
directory, the payload, an icon, an INI entry, a registry value, an
install and an uninstall delete, a run and an uninstall-run entry - and
two types, two components and a task, which 1.3 skips. Used by
`legacy_samples_carry_what_legacy_iss_states`, which pins each file's
marker and the version its records read as, and checks every record,
the checksum family, the payload and the uninstaller (before 5.0 a
program of its own, stored as a file). `legacy-bzip-*` (2.0.19, 4.0.8,
4.1.4, 4.1.5, 4.2.7), `legacy-lzma-tool4_1_5` and `legacy-zip-tool4_2_7`
compress with that method instead of the default (zip before 4.1.8,
LZMA from it): the per-file bzip2 flag before 4.0.1, the `BzipUsed`
header option before 4.1.5, and each release's decompressor DLL.

| Files                                  | Marker                    | Notes |
| -------------------------------------- | ------------------------- | ----- |
| `legacy-tool1_3_26.exe`                | `1.3.25`                  | no language options; one wizard image; built through 2.0.19's `ISCC.exe` |
| `legacy-tool2_0_19.exe`                | `2.0.18`                  | `TSetupLangOptions`; two wizard images |
| `legacy-tool3_0_0.exe` .. `3_0_7`      | `3.0.0a` `3.0.1` `3.0.3` `3.0.5` | 3.0.0, 3.0.2, 3.0.3 betas and 3.0.7 |
| `legacy-tool3_0_4.exe`                 | `3.0.3`                   | the 3.0.4 layout (`PrivilegesRequired`) under 3.0.3's marker |
| `legacy-tool4_0_0.exe` .. `4_0_8`      | `4.0.0a` `4.0.1` `4.0.3` `4.0.5` | 4.0.0 pre-release, 4.0.2 and 4.0.4 betas, 4.0.8; the last pre-4.0.9 block header |
| `legacy-tool4_0_9.exe` .. `4_2_7`      | `4.0.9` to `4.2.6`        | one per marker; 4.1.1 writes `4.1.0`, 4.1.7 `4.1.6`, 4.2.7 `4.2.6` |
| `legacy-tool4_2_4.exe`                 | `4.2.3`                   | the 4.2.4 layout (four more header strings) under 4.2.3's marker |

## Upstream's own (`official/`)

`isetup16-1.2.16.exe` is Inno Setup 1.2.16's 16-bit package, as
published at files.jrsoftware.org/is/1.2/ (SHA-256
`9f4fbab8039f40cd3ea6dcbe34de0d4d40ed4037bc1c9737027b20181e461dc5`): the
one 1.2 installer there is. No 32-bit 1.2 compiler survives, and Wine
cannot run the 16-bit one to build a script. Redistributed unmodified under
its license, [`official/LICENSE-1.2.16.txt`](official/LICENSE-1.2.16.txt)
(from `issrc-1.2.16.zip`). It is a 16-bit NE executable with SetupID
`i1.2.10--16`. `official_1_2_16_16bit_package_parses_and_extracts`
checks its header, records, every file it extracts and their DOS time
stamps against what innoextract 1.9 extracts from it.

## Synthetic - wizard images and the 7-Zip DLL (`modern/`)

[`build/modern.iss`](build/modern.iss), built with 6.6.1, 6.7.0 and
7.1.1: `WizardStyle=modern dynamic`, so the compiler stores dark-mode
images (its built-in dark large image, distinct from the light one); the
small image [`build/modern/small.png`](build/modern/) for both modes,
which the compiler stores as "same as light"; from 6.7 the back image
`build/modern/back.png`; and `ArchiveExtraction=full`, which stores the
compiler's `is7z.dll`. Used by `modern_samples_carry_dark_and_back_images`.

## Synthetic - password only (`password/`)

[`build/password.iss`](build/password.iss): `Password=test123` without
`Encryption=`, so Setup asks for the password and the files are stored in
clear. Built once per place the verifier has lived: the pre-6.4 header
(5.5.7), the 6.4 header tail (6.4.3), and the 6.5+ encryption header
(7.0.0 previews 2 and 3, 7.0.2, 7.1.1); the previews write the same
SetupID with different key derivations, standard in preview 2 and the
buggy one in preview 3. Used by
`password_only_samples_check_the_password_and_encrypt_nothing`.

## Synthetic - disk spanning (`spanning/`)

[`build/spanning.iss`](build/spanning.iss) (4.0.8, 4.2.7, 5.5.7, 6.5.1,
7.1.1) and [`build/spanning-legacy.iss`](build/spanning-legacy.iss)
(1.3.26, 2.0.19) put the files in slice files beside the installer, one
build per generation of the slice file: `<base>.<n>` before 2.0,
`<base>-<n>.bin` named after the header's base name to 4.x and after the
installer from 5.0, with a letter per slice from 4.0 (`SlicesPerDisk`),
`idska32` with a 32-bit size to 6.5.1 and `idskb32` with a 64-bit one from
6.5.2. The payload, `build/spanning/random.bin`, does not compress, so a
chunk crosses from one slice into the next. Each fixture's slices are in
`spanning-tool<slug>.slices/`, under the names their compiler gave them
(`build-wine.sh` moves them there). Used by
`spanning_samples_extract_from_their_slice_files`, which checks that
`slice_file_name` names exactly those files, that extraction needs them,
and that every file extracts with them.

## Stored DLLs (`build/compiler-dlls.txt`)

A compiler stores its own decompressor DLL (`isbunzip.dll`,
`isunzlib.dll`, `isunlzma.dll`) and 7-Zip library in the installers that
need them, and the encrypted pre-6.4 ones carry `ISCrypt.dll`.
[`build/list-dlls.sh`](build/list-dlls.sh) writes the SHA-256 of every
such file in every compiler in the image to `compiler-dlls.txt`, and
`every_fixture_carries_its_wizard_images_and_dlls` checks each DLL a
fixture stores against its compiler's own (`ISCrypt.dll` against the
hash `install-inno.sh` pins).

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
asserts every sample parses cleanly, reports `is_encrypted()` and
`has_password()` false, parses with a candidate-password list too, reconstructs an uninstaller via `extract_uninstaller()`,
and yields the canonical `payload.txt` via `extract_files()`.

| File                       | Inno version    | What it pins |
| -------------------------- | --------------- | ------------ |
| `plain-tool5_0_8.exe`      | 5.0.8           | AnsiStrings interleaved with the Strings (before 5.2.5); before `AppSupportPhone` |
| `plain-tool5_1_14.exe`     | 5.1.14          | `AppSupportPhone` |
| `plain-tool5_2_3.exe`      | 5.2.3           | `SignedUninstallerSignature` (5.2.1 to 5.3.9) |
| `plain-tool5_3_11.exe`     | 5.3.11 Unicode  | AnsiStrings after the Strings; SHA-1 checksums |
| `plain-tool5_4_3.exe`      | 5.4.3 Unicode   | SetupID 5.4.2 |
| `plain-tool5_5_5.exe`      | 5.5.5 Unicode   | SetupID 5.5.0; before `SetupMutex` |
| `plain-tool5_5_7.exe`      | 5.5.7           | SetupID 5.5.7, ANSI |
| `plain-tool6_0_0u.exe`     | 6.0.0           | the first Unicode-only release |
| `plain-tool6_3_0.exe`      | 6.3.0           | architectures as string expressions (from 6.3.0) |
| `plain-tool6_4_2.exe`      | 6.4.2           | SetupID 6.4.2; SHA-256 checksums |
| `plain-tool6_4_3.exe`      | 6.4.3           | SetupID 6.4.3 (`SignMode` and the legacy location flags gone) |
| `plain-tool6_5_2.exe`      | 6.5.2           | 64-bit chunk offsets; PNG wizard images; the encryption header (from 6.5.0) |
| `plain-tool6_5_2-alt.exe`  | 6.5.2           | Same script, second build - nondeterminism check |
| `plain-tool6_6_1.exe`      | 6.6.1           | dark-mode image lists |
| `plain-tool6_7_0.exe`      | 6.7.0           | 64-bit block sizes; back images |
| `plain-tool7_0_0_1.exe`    | 7.0.0 preview 3 | SetupID 7.0.0.1 |
| `plain-tool7_0_2.exe`      | 7.0.2           | SetupID 7.0.0.3 (7.0.0 to 7.1.0): `CompiledCodeVersion`, `Bitness` |
| `plain-tool7_1_1.exe`      | 7.1.1           | SetupID 7.1.1 (`BaseFilename` gone) |

Beyond the table, `plain.iss` is built once for every other 5.x and 6.x
setup data marker, by the last release that writes it (5.0.0, 5.0.2 and
5.0.3 betas, 5.1.1 beta, 5.1.6, 5.1.9, 5.1.12, 5.2.0, 5.2.2, 5.3.2 beta,
5.3.4 to 5.3.9, 5.5.6, 6.5.1, 6.6.0); each marker from 5.3.0 to 5.5.x in
both editions (a slug ending `u` is the Unicode build; `5_3_11a`, `5_4_3a`
and `5_5_5a` are the ANSI builds beside the Unicode `5_3_11`, `5_4_3` and
`5_5_5`); and 5.5.8 (Unicode) and 5.6.1 (both), which write 5.5.7's
marker, 5.6.1 with counted wizard-image lists. `-zip`, `-bzip` (5.5.7,
7.1.1) and `-none` (7.1.1) builds compress with that method instead; the
walker checks the method and that `-none` marks no chunk compressed.

## Synthetic - encrypted (`encrypted/`)

All share password **`test123`** and the canonical `payload.txt`
(21 bytes, `Inno test payload v1\n`). Used by
`encrypted_samples_parse_and_unlock`, which asserts:

1. `is_encrypted()` and `has_password()` return `true`.
2. Empty password list → `Error::PasswordRequired`.
3. Wrong password (`"nope"`) → `Error::WrongPassword`.
4. `"test123"` unlocks; `password_used()` reports `Some("test123")`.
5. `payload.txt` extracts to the canonical bytes.
6. For `enc-full-*`: setup-0 itself decrypts to non-empty bytes
   and the header parses post-decrypt.

| File                            | Inno version    | Mode      | Cipher / verifier |
| ------------------------------- | --------------- | --------- | ----------------- |
| `enc-files-tool5_0_8.exe` .. `5_2_3` | 5.0.8, 5.1.14, 5.2.3 | per-chunk | ARC4 + MD5 (before 5.3.9), `ISCrypt.dll` |
| `enc-files-tool5_3_11.exe` .. `6_3_0` | 5.3.11 to 6.3.0 | per-chunk | ARC4 + salted SHA-1, `ISCrypt.dll` |
| `enc-files-tool6_4_2.exe`, `6_4_3` | 6.4.2, 6.4.3 | euFiles | XChaCha20, PBKDF2-SHA-256, verifier in the header |
| `enc-files-tool6_5_2.exe` .. `7_1_1` | 6.5.2 to 7.1.1 | euFiles | XChaCha20, `TSetupEncryptionHeader` (from 6.5.0) |
| `enc-files-tool7_0_0p2.exe`     | 7.0.0 preview 2 | euFiles   | SetupID 7.0.0.1, standard PBKDF2 |
| `enc-files-tool7_0_0_1.exe`     | 7.0.0 preview 3 | euFiles   | SetupID 7.0.0.1, **buggy PBKDF2** (`U_1` dropped) |
| `enc-full-tool6_5_2.exe` .. `7_1_1` | 6.5.2 to 7.1.1 | euFull | XChaCha20 over setup-0 too (`sccCompressedBlocks1/2`) |
| `enc-full-tool7_0_0p2.exe`, `7_0_0_1` | 7.0.0 previews 2, 3 | euFull | as their `enc-files` builds |

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
`encrypted_samples_parse_and_unlock`; once the parser covers the
gap, the sample moves to the directory its script builds into.

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

The 1.x to 4.x packages are unpacked with innoextract instead of run:
their compilers need nothing else installed, and 1.3.26's Setup never
returns under Wine. 1.3.26 has no command-line compiler, and its
`Compil32.exe /cc` hangs the same way, so it compiles through 2.0.19's
`ISCC.exe`, a front end for the `ISCmplr.dll` beside it whose interface
the two releases declare identically. Before 5.0 ISCC takes no `/Q`, and
every compiler before 5.0 needs CRLF line endings in the script.

It replaces the Windows build host these fixtures were first made on.
Control: rebuilt under Wine, 34 of the 35 fixtures that host produced
parse identically (version marker, loader family, compression,
encryption, header strings, entry counts, files, and the extracted
payload). The 35th, `enc-full-tool6_7_0.exe`, had been built from an
earlier `encrypted-full.iss` and differed in exactly what that script
has since changed; the rebuild is current.

## Coverage gaps

Versions and edge cases not yet in the matrix:

- **32-bit 1.2.x** - no 32-bit 1.2 compiler survives; the format is
  checked against upstream's record layouts only. The 16-bit build has
  one installer, upstream's own (`official/`).
- **ISX (`My Inno Setup Extensions ≤ 3.0.6.1`)** - validates
  `Variant::Isx` discrimination.
- **Encryption before 5.0** - `ISCrypt.dll` from 4.2.2 to 4.2.x and the
  CRC-32 password check before 4.2.0 have no fixture.
- **7.2.0** - waits for its release.

## Ad-hoc inspection

```bash
cargo run --quiet --example dump tests/samples/encrypted/enc-files-tool6_4_3.exe \
  | grep -E 'encryption|version'
```
