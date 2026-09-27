# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ATRAPSLLC/innospect/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ATRAPSLLC/innospect/releases/tag/v0.1.1
