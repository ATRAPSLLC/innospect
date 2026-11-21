# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-21

Every Inno Setup release from 1.2.10 to 7.1.1 now parses and extracts, the 16-bit 1.2.x
builds and disk-spanning installers included, and every setup-0 block is read to its last
byte: a layout that leaves bytes over is an error, not a silent misread.

### Breaking changes

- `bit()` and `set_to_bits()` on the flag enums return `u128` (were `u64`): `HeaderOption` has
  71 members, and the 7 from bit 64 on had `bit()` 0, so `set_to_bits` dropped them. The new
  `index()` gives a flag's position in `ORDER`, which stays append-only.
- `DataEntry::start_offset` is `u64` (was `u32`). From 6.5.2 the field is 64-bit on disk;
  values past 4 GiB were clamped and negative ones folded to their magnitude, and a negative
  offset is now an error.
- `InnoInstaller::is_encrypted` now means the data is encrypted (`euFiles` / `euFull`, or before
  6.4.0 the header's `EncryptionUsed`). It was also true for an installer that only asks for a
  password, whose files are stored in clear; the new `has_password` reports that.
- `RegistryOpKind` is `#[non_exhaustive]` and has the new kinds `CreateKey`, `ReplaceValue`,
  `ReplaceKey` and `UninstallOnly` (see Fixed).
- New public fields on record structs, among them `LanguageEntry::language_name_utf16`,
  `RegistryEntry::data` and `root_key_raw`, and the `HeaderTail` values listed under Added.
- `Error::MultiSliceChunk` now means a chunk longer than the slice files it names hold, and
  `Error::ExternalSlice` a slice file that was not supplied.

### Added

- **Older releases.** Installers before 4.0.9 (SetupID 1.2.10 to 4.0.5) had their setup-0
  blocks skipped and now parse and extract. For 1.2.x the setup data follows the 12-byte
  marker, every record but the data entries follows a u32 holding its size, and the license
  and info texts follow the header (the `HeaderAnsi` text fields). The 16-bit build has
  two-byte `Integer` and `Cardinal` fields, unpadded three-byte sets, a DOS date and time per
  data entry, registry entries with no root key or value name (the default value under
  `HKEY_CLASSES_ROOT`, as now reported), and an NE container. Before 4.0 the wizard images and
  bzip2 DLL are read past, and from 2.0.1 the one `TSetupLangOptions` record is
  `languages()[0]`.
- **Shared SetupIDs.** An installer that does not parse under its marker's layout is parsed
  under the release that kept writing that marker after changing the records (`(3.0.3)` by
  3.0.4, `(4.2.3)` by 4.2.4, and after innoextract `(1.3.21)` and `(2.0.1)`), and `version()`
  reports that release.
- **Disk spanning.** `InnoInstaller::with_slices` takes the slice files of a `DiskSpanning=yes`
  installer, checking each one's ID and size (`idska16`, `idska32`, and from 6.5.2 `idskb32`
  with a 64-bit size), and reads chunks that run from one slice into the next.
  `uses_slice_files`, `slice_count` and `slice_file_name` give the names Setup looks for by
  release (`<base>.<n>` before 2.0, `<base>-<n>.bin` to 4.x, the installer's own name from 5.0,
  a letter per slice from 4.0). New `Error::BadSlice`.
- **The rest of setup-0.** `InnoInstaller::wizard_images` / `wizard_images_dark` (with
  `WizardImageKind`: large, small, and from 6.7.0 back), `decompressor_dll`, `decryption_dll`
  and `seven_zip_dll`, following every release's layout: one image of each size before 5.6.0,
  counted lists from 5.6.0, dark-mode lists from 6.6.0, back images from 6.7.0; the
  decompressor DLL by method and release, `ISCrypt.dll` from 4.2.2 to 6.4.0, the 7-Zip DLL from
  6.5.0. 5.6.x writes 5.5.7's SetupID with the counted lists; both forms are tried under it.
- `Error::TrailingData`: a setup-0 block, or a 1.2.x record, holds bytes past the last thing
  Setup reads from it, the sign of a wrong layout.
- `Error::TooLarge`, for the allocation limits under Fixed.
- Header values that were read past: `HeaderTail::wizard_image_back_color`,
  `wizard_small_image_back_color`, `wizard_back_color` and their `*_dynamic_dark` variants,
  `wizard_image_opacity`, `wizard_back_image_opacity`, `wizard_dark_style` (`WizardDarkStyle`),
  `wizard_light_control_styling` (`WizardLightControlStyling`), `install_mode` (`InstallMode`),
  `uninstall_style` (`UninstallStyle`), `signed_uninstaller_original_size`,
  `signed_uninstaller_header_checksum` and `lead_bytes`; `HeaderString::UninstallIconName`
  (before 3.0.0) and `HeaderAnsi::SignedUninstallerSignature` (5.2.1 to 5.3.9), so every
  header string field is now exposed; `LanguageEntry::dialog_font_base_scale_height` /
  `dialog_font_base_scale_width` (6.6.0+, where `dialog_font_standard_height` is now 0).
- 22 `HeaderOption` variants (`Uninstallable`, `DisableDirPage`, `ChangesAssociations`,
  `CreateUninstallRegKey`, `ChangesEnvironment`, `BzipUsed`, `WizardModern`,
  `RedirectionGuard`, ...).
- `RegistryData`, `RegistryEntry::data`, `RegistryEntry::root_key_raw` and
  `RegistryHive::Auto`.
- `ExecIter::new`, `RegistryOpIter::new` and `ShortcutIter::new`, to walk any `[Run]` /
  `[Registry]` / `[Icons]` + `[Files]` slices, not only an installer's own.
- `impl Display for Version` (`6.4.0.1 (u)`, `1.2.10 (16-bit)`), and stable `as_str` /
  `Display` names on `ExecPhase`, `OffsetTableGeneration`, `BlockCompression`,
  `PrivilegesRequiredOverride` and `HeaderString` / `HeaderAnsi` (upstream's field names).

### Fixed

- **Header and record layouts**, each read one or more fields off:
  - 7.1.1 failed to parse: it dropped `BaseFilename` from the header, now absent from 7.1.1 on.
  - 6.4.2: `CloseApplicationsFilterExcludes` arrived with SetupID 6.4.2, not 6.4.3.
  - 6.5.0 and 6.5.1 read 8 bytes too many: the two wizard image colours arrived with 6.5.2.
  - 4.0.9 to 5.0.3 read the header tail at the wrong offset, misaligning every later record;
    `WizardSmallImageBackColor` and `InstallMode` were read for the wrong releases, and the
    entry counts were read whether or not the release has the record type.
  - 7.0+ `[Run]` / `[UninstallRun]` entries read `OnLog` before the six condition strings
    instead of after them.
  - Unicode 5.3.x with a signed uninstaller read the `AnsiString` signature as UTF-16.
- **Flags.** `TSetupHeader.Options` decoded one bit late in Unicode 5.5.x from bit 39 and in
  6.6.x from bit 41, and flags with no `HeaderOption` counterpart were dropped; one ladder in
  upstream's declaration order now covers every format. As in innoextract,
  `AllowCancelDuringInstall` is set before 4.0.9 and `AllowNetworkDrive` before 5.5.0.
  `FileFlag::CreateAllSubDirs` (SetupID 5.0.4) and `Architecture::Arm64` (5.5.7) were missed
  where a release appended them without a new SetupID, 1.3.26 read icon flags 1 and 2 one bit
  late (SetupID 1.3.25 now follows 1.3.26), and `HeaderOption::DisableFinishedPage` was never
  decoded for 1.2.x.
- 3.0.0 to 3.0.2 installers lost their restart setting: the auto/no/yes byte now sets
  `AlwaysRestart` / `RestartIfNeededByRun`, as innoextract does.
- **Registry.** `HKA` entries decoded as `HKCU`; they are now `RegistryHive::Auto`.
  `RegistryEntry::value_text` misread most value types (from 4.1.4 a `dword` or `qword` is
  stored as text, a `binary` value is one byte per character, and ANSI strings were decoded as
  UTF-16); the value is now decoded once by type and version into `RegistryEntry::data`.
  `RegistryOpKind` now follows Setup's `ProcessRegistryEntries` branch for branch: a
  `deletekey` / `deletevalue` entry with a value type deletes and then writes, and
  `ValueType: none` without a delete flag only creates the key.
- **Languages.** The language name of every ANSI installer from 4.2.2 decoded as `E\0n\0g\0...`:
  upstream stores it as UTF-16 there in every build. Before 4.2.2, `codepage` is now the one
  Windows uses for the `LANGID` (1251 for Russian, 932 for Japanese, ...) rather than always
  1252.
- **Passwords.** `from_bytes_with_passwords` failed with `WrongPassword` on every 6.5+ installer
  without a password; candidates are now tried only when the header's `Password` option is
  set. 7.0.0 preview 2 installers rejected the right password, because preview 3's PBKDF2 bug
  was applied to every SetupID 7.0.0.1 installer; both derivations are now tried under it.
- **Extraction.** A `nocompression` file could not be extracted, and nothing could before 4.1.5:
  the method is now chosen per chunk as Setup does (stored without `ChunkCompressed`, bzip2
  with the pre-4.0.1 `BZipped`, else the header's, which before 4.1.5 follows `BzipUsed`). An
  unknown `CompressMethod` byte is now `UnsupportedCompression` and a short chunk
  `ChunkSizeMismatch`, both instead of `Truncated`. `extract_uninstaller` returned the patched
  installer for releases before 5.0, whose uninstaller is the stored `Uninst.e32`, now
  extracted.
- **Hostile input.** A record count or a chunk's stated size could make the parser allocate
  without bound, and decompression ran to the stream's end. Reservations are now capped by the
  bytes there are, a chunk decompresses no further than its files reach, and a setup-0 block
  no further than 256 MiB (`Error::TooLarge`).
- `OffsetTable::total_size` was 0 before 6.5.0, and the generation docs had the v1/v2 boundary
  wrong (v2 starts at 6.5.0).
- `InnoInstaller::shortcuts` matched an icon's target to a file case-sensitively; paths are now
  compared ignoring case, as Windows does.
- `Version::marker_str` of a 1.2.x installer ran on past the 12-byte marker.

### Changed

- Raised `pascalscript` to 0.2.1 and `lzma-rust2` to 0.25.
- `PasswordRequired` / `WrongPassword` say "has a password" rather than "is encrypted", and the
  docs of `HeaderTail::compiled_code_version` and the entry `bitness` fields (marker 7.0.0.3+)
  are corrected.
- Internal restructuring, no public path moved: the parsing and stream machinery moved to
  private modules (`loader`, `stream`, `util`), and the crate no longer uses `pub(crate)` or
  `pub(super)`.

### Tests

- **Layout oracle.** Every setup-0 record of every SetupID marker whose source is available
  (1.2.10 through 7.1.1, ANSI, Unicode and 16-bit builds) is checked against upstream's
  `Struct.pas`: each record must consume exactly its declared fields, each set bit and enum
  value must decode to the member upstream declares, and every string field must land on the
  crate field that exposes it. `tests/samples/build/gen-layouts.py` generates the table.
- **Fixture matrix**, built by the official compilers under Wine in Docker:
  - every setup data marker from 1.3.25 to 7.1.1 (`legacy.iss` for 28 compilers from 1.3.26 to
    4.2.7, and from 5.3.0 to 5.5.x both editions), 5.6.1, 7.0.0 preview 2 and 7.1.1 64-bit
    builds;
  - compression variants where the method changes the format (`<name>-zip`, `-bzip`, `-lzma`,
    `-none`), `modern.iss` (dark-mode and back images, the 7-Zip DLL), `password.iss`, and
    `spanning.iss` / `spanning-legacy.iss`, one per slice-file generation;
  - `full.iss` gains HKA, every registry value type and `RegistryOpKind`, 32-bit and 64-bit
    entries, and a `nocompression` file;
  - and, not built but redistributed unmodified under its license, Inno Setup 1.2.16's own
    16-bit package (`official/`), checked against innoextract 1.9.
- Each fixture is checked against what its script states: header strings, records, payload,
  uninstaller, wizard images and DLLs (stored DLLs against the compiler's own,
  `build/compiler-dlls.txt`), slice names and extraction across slices.
- Unit tests for the flag bits, the allocation and block limits (a zlib bomb), and the slice
  reader with bad headers.

## [0.2.0] - 2026-09-26

### Changed

- **Breaking:** raised `pascalscript` to 0.2.0. innospect re-exports it as
  `innospect::pascalscript`, so its API changes reach callers of this crate:
  `ProcDisasm::branch_target()` / `branch_targets()` are removed
  (`Instruction::branch_targets()` now returns every branch form in IFPS-blob
  coordinates), `FlagGoto`'s field is renamed `offset`, and
  `SetStackPointerToCopy` is now `SetStackPointerToCopy { dest, src }`. The release
  also fixes the decoding of `cm_spc` (any procedure containing it failed to decode)
  and the coordinates of `flaggoto` and the exception-handler sections, and adds
  procedure signatures, stack maps and operand accessors. See the `pascalscript`
  changelog for details.
- Raised `lzma-rust2` from 0.18 to 0.21 (no source changes needed; drops the
  `multiversion` transitive dependency) and `encoding_rs` to 0.8.42.

### Tests

- Every fixture is now built from a script in `tests/samples/build/` by the official
  Inno Setup compilers running under Wine in Docker (`build-wine.sh`, with the compiler
  matrix in `versions.txt`), replacing the Windows build host and its PowerShell
  toolchain. Rebuilt this way, 34 of the 35 existing fixtures parse identically; the
  35th, `enc-full-tool6_7_0.exe`, had been built from an older `encrypted-full.iss` and
  is rebuilt from the current one.
- The third-party HeidiSQL and ImageMagick installers are replaced by `full.iss`, built
  with Inno Setup 6.4.0 and 6.1.0 to cover the same formats and compression layouts.
  Every value the tests assert is stated in the script or its payload, so the
  assertions are now exact rather than lower bounds.
- Added `code.iss` (`code-tool6_4_3.exe`), a compiled `[Code]` script, with tests that
  every script branch lands on an instruction of its own procedure and every
  procedure's stack frame matches its declaration.
- The fixtures are committed, and a missing one now fails the integration tests instead
  of skipping them. The new `every_matrix_fixture_is_present` test derives the expected
  set from `versions.txt` and fails on any fixture that is missing or not in the matrix,
  and the encrypted walker requires both euFiles and euFull samples.

## [0.1.4] - 2026-09-18

### Changed

- LZMA1 and LZMA2 decoding now uses `lzma-rust2` instead of `lzma-rs` (about 1.4x faster
  on LZMA1, still pure Rust), and `flate2` uses the `zlib-rs` backend instead of
  `miniz_oxide`. The LZMA2 dictionary size is taken from the property byte Inno writes
  ahead of each chunk, so installers built with large dictionaries (for example
  `lzma2/ultra64`) decode correctly. `lzma-rs` remains a dev-dependency for test fixtures.
  Contributed by @maboloshi in #3.
- Replaced em-dashes and en-dashes with plain ASCII hyphens throughout rustdoc comments,
  the README, and test-sample notes, so generated documentation renders consistently.
  This also touches a few runtime strings: the one-line summaries returned by
  `inno_api_description` and the section banners printed by the `dump` example.
- Raised the `pascalscript` minimum to 0.1.3 (documentation-only release upstream).
- Refreshed dependencies and raised the manifest minimums to the current releases:
  `bitflags` 2.13.2, `chacha20` 0.10.2, `codepage` 0.1.3, `encoding_rs` 0.8.41,
  `flate2` 1.1.10.
- Updated CI and publish workflows from `actions/checkout@v4` to `actions/checkout@v7`.
- UTF-16LE decoding now pairs bytes with `as_chunks::<2>()` instead of `chunks_exact(2)`
  plus a slice copy, which clears the new `chunks_exact_to_as_chunks` lint on current
  stable Clippy. Also dropped a test import that newer compilers report as unused.

## [0.1.3] - 2026-08-09

### Fixed

- `repository` pointed at `github.com/BinFlip/inno-rs`, which does not exist. Every
  published version so far has carried a dead repository link on crates.io. It now points
  at the real repository, `github.com/ATRAPSLLC/innospect`.

### Changed

- Recorded ATRAPS LLC as copyright holder and added a `NOTICE` file. No functional change.
- Dropped the deprecated `authors` field.
- Raised the `pascalscript` minimum to 0.1.2. `Container` is re-exported publicly, so that
  release's backward-branch resolution fix is part of this crate's effective API surface.
- Refreshed remaining dependencies (`cargo update`); `bitflags` moved to 2.13.1.
- Publishing now uses crates.io trusted publishing instead of a stored registry token.

## [0.1.2] - 2026-07-06

### Fixed

- Header string-table parsing for Inno Setup 6.4.3+ installers that carry a
  `[Code]` section (or non-empty license/info text) no longer fails with
  `invalid UTF-16LE in CloseApplicationsFilterExcludes`. The `String` fields
  added since 6.3.0 (`CloseApplicationsFilterExcludes`, `SevenZipLibraryName`,
  `UsePrevious*`) are now read ahead of the `AnsiString` tail, matching
  `TSetupHeader`'s all-strings-then-all-ansistrings serialization
  (GitHub [#1](https://github.com/ATRAPSLLC/innospect/issues/1)).

### Added

- Codepage-aware string decoding via `LanguageCodepage::decode`: UTF-16LE for
  modern Unicode builds and Windows ANSI code pages (cp1251 / cp1252 / cp932 / …)
  for legacy installers, with a lossy replacement fallback for unmappable pages.
  `LanguageEntry` name / language-name accessors now decode through it.
- Public `from_raw` inverse constructors on record enums, for reconstructing
  typed values from stored raw discriminants: `FileEntryType`, `SignMode`,
  `Bitness`, `DeleteTargetType`, `CloseOnExit`, `RunWait`, `SetupTypeKind`,
  `RegistryHive`, `RegistryValueType`, and `LanguageCodepage`.

### Changed

- Bumped dependencies: `bitflags` 2.11.1 → 2.13.0, `goblin` 0.10.5 → 0.10.7,
  `chacha20` 0.10.0 → 0.10.1.

### Added (dependencies)

- `encoding_rs` 0.8.35 and `codepage` 0.1.2, for the codepage-aware decoding above.

## [0.1.1] - 2026-06-09

- Initial published release.

[0.3.0]: https://github.com/ATRAPSLLC/innospect/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ATRAPSLLC/innospect/releases/tag/v0.1.1
