//! Integration tests for the Inno Setup parser.
//!
//! Fixtures live under `tests/samples/`; see
//! `tests/samples/README.md` for fetch commands. Sample binaries are
//! gitignored, so these tests gracefully `eprintln` + return early if
//! the fixtures aren't present locally.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use std::{collections::BTreeSet, io::Read, path::PathBuf};

use innospect::{
    Architecture, CompressMethod, Compression, DataChecksum, DataFlag, DeleteTargetType,
    EncryptionMode, Error, FileEntryType, HeaderAnsi, HeaderOption, HeaderString, InnoInstaller,
    RegistryData, RegistryHive, RunWait, SetupLdrFamily, Variant, WizardImageKind,
    analysis::{ExecPhase, RegistryOpKind},
    overlay::offsettable::OffsetTableGeneration,
    pascalscript::{FrameSlot, Opcode, ProcKind, VarRef},
};

/// Reads `tests/samples/<name>`. The fixtures are committed, so a missing
/// one fails the test rather than skipping it.
fn sample(name: &str) -> Vec<u8> {
    let path: PathBuf = format!("{}/tests/samples/{name}", env!("CARGO_MANIFEST_DIR")).into();
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (fixtures are committed; see tests/samples/README.md)",
            path.display()
        )
    })
}

/// Lists every `*.exe` directly under `tests/samples/<subdir>/`. A missing
/// directory fails the test; callers assert on how many they tested.
fn samples_in(subdir: &str) -> Vec<(String, PathBuf)> {
    let dir: PathBuf = format!("{}/tests/samples/{subdir}", env!("CARGO_MANIFEST_DIR")).into();
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.expect("read_dir entry");
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("exe") {
            continue;
        }
        let name = path
            .iter()
            .next_back()
            .and_then(|s| s.to_str())
            .map(str::to_owned)
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        out.push((name, path));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn rejects_non_pe_input() {
    let result = InnoInstaller::from_bytes(b"not a PE");
    assert!(matches!(result, Err(innospect::Error::NotPe)));
}

#[test]
fn rejects_bare_pe_with_no_inno_payload() {
    // Minimal valid-MZ buffer that is otherwise zeroed - no SetupLdr
    // magic, no legacy 0x30 pointer.
    let mut buf = vec![0u8; 4096];
    buf[0] = b'M';
    buf[1] = b'Z';
    let err = InnoInstaller::from_bytes(&buf).unwrap_err();
    assert!(
        matches!(err, innospect::Error::NotInnoSetup),
        "expected NotInnoSetup, got {err:?}"
    );
}

/// **The 6.4 format, every record stream.** `full.iss` built with Inno
/// Setup 6.4.0, which writes the `(6.4.0.1)` data marker: LZMA2 files in one
/// solid chunk, six languages, a license, tasks, icons, registry writes and a
/// compiled script. Every value asserted is stated in `build/full.iss` or
/// computed from the payload in `build/full/`.
#[test]
fn full_6_4_0_1_identifies() {
    let bytes = sample("full/full-tool6_4_0.exe");
    let inst = InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| {
        panic!("full 6.4.0 parse failed: {e}");
    });

    let v = inst.version();
    assert_eq!(
        (v.a, v.b, v.c, v.d),
        (6, 4, 0, 1),
        "marker = {:?}",
        v.marker_str()
    );
    // The 6.4 marker carries no `(u)` suffix.
    assert!(!v.is_unicode(), "marker = {:?}", v.marker_str());
    assert!(!v.is_isx());
    assert!(!v.is_16bit());
    assert_eq!(v.marker_str(), "Inno Setup Setup Data (6.4.0.1)");
    assert_eq!(inst.variant(), Variant::Stock);
    assert_eq!(inst.setup_ldr_family(), SetupLdrFamily::V5_1_5);
    // 6.4.0.1 predates the 6.5.2 v2 bump - record-version 1.
    assert_eq!(
        inst.offset_table().source.generation,
        OffsetTableGeneration::V1,
    );
    assert_eq!(inst.offset_table().version_id, 1);
    assert_eq!(inst.compression(), Compression::Lzma1);
    // No password is set.
    assert!(matches!(
        inst.encryption().map(|e| e.mode),
        None | Some(EncryptionMode::None),
    ));
    // 6.4 stores `ArchitecturesAllowed` as the string
    // `"x64compatible"`; the accessor scans it down to {Amd64}.
    let arches = inst.architecture().expect("architecture set present");
    assert_eq!(arches.len(), 1);
    assert!(arches.contains(&Architecture::Amd64));
    // Setup-0 decompression must produce a non-trivial buffer; a
    // 6.4-era installer's header block is several KB at minimum.
    let setup0 = inst.decompressed_setup0();
    assert!(
        setup0.len() > 1024,
        "decompressed setup-0 was {} bytes",
        setup0.len()
    );

    // TSetupHeader.
    let header = inst.header().expect("full has a parsable header");
    assert_eq!(header.app_name(), Some("Inno Test (full)"));
    assert_eq!(header.app_id(), Some("InnoTestFull"));
    assert_eq!(header.app_version(), Some("2.3.4.5"));
    assert_eq!(header.app_publisher(), Some("BinFlip"));
    assert_eq!(header.default_dir_name(), Some("{autopf}\\InnoTestFull"));
    // ChangesAssociations is a 6.0+ field - verify it parsed via the
    // generic accessor too.
    assert!(header.string(HeaderString::ChangesAssociations).is_some());

    let counts = header.counts();
    // Nine payload files (one of them stored uncompressed) and the
    // uninstaller; each payload file its own location. Four icons, 19
    // registry entries, and two run entries: the launcher, and the "view
    // the README" entry `isreadme` adds.
    assert_eq!(counts.languages, 6);
    assert_eq!(counts.files, 10);
    assert_eq!(counts.file_locations, 9);
    assert_eq!(counts.icons, 4);
    assert_eq!(counts.registry, 19);
    assert_eq!(counts.run, 2);
    // 6.4.0.1 predates 6.5.0, so NumISSigKeyEntries is absent.
    assert_eq!(counts.iss_sig_keys, None);

    // Embedded blobs - convenience accessors fold empty wire
    // strings to None. The script has a license and compiled code, no
    // info screens; the license is `build/full/license.txt` verbatim.
    let license = inst.license_text().expect("license_text present");
    assert_eq!(license.len(), 1852, "license was {} bytes", license.len());
    assert_eq!(license, header.ansi(HeaderAnsi::LicenseText).unwrap());
    assert!(inst.info_before().is_none(), "no InfoBeforeFile");
    assert!(inst.info_after().is_none(), "no InfoAfterFile");
    let compiled = inst
        .compiled_code_bytes()
        .expect("compiled_code_bytes present");
    assert!(
        compiled.len() > 100,
        "PascalScript blob was {} bytes",
        compiled.len(),
    );
    // PascalScript blobs canonically start with `IFPS`.
    assert_eq!(
        &compiled[..4],
        b"IFPS",
        "compiled code blob did not start with IFPS magic",
    );
    // Parsed IFPS Container view (full table walk).
    let cc = inst
        .compiledcode()
        .expect("compiledcode() returns Some")
        .expect("IFPS Container parses");
    assert_eq!(cc.bytes().len(), compiled.len());
    assert_eq!(cc.types().len() as u32, cc.header().type_count);
    assert_eq!(cc.procs().len() as u32, cc.header().proc_count);
    assert_eq!(cc.vars().len() as u32, cc.header().var_count);
    assert!(
        cc.header().proc_count > 0,
        "expected at least one procedure, got {}",
        cc.header().proc_count,
    );

    // Inno-API name lookup: at least one proc imports a known
    // security-relevant function (registry, exec, file ops, …).
    let known_imports: usize = cc
        .procs()
        .iter()
        .filter_map(|p| match &p.kind {
            ProcKind::External(ext) => Some(ext.name),
            _ => None,
        })
        .filter(|name_bytes| {
            std::str::from_utf8(name_bytes)
                .ok()
                .and_then(|n| inst.inno_api_description(n))
                .is_some()
        })
        .count();
    assert!(
        known_imports > 0,
        "the [Code] script imports RegQueryStringValue, a known Inno API",
    );

    // Bytecode disassembly: every internal proc must decode
    // cleanly into at least one instruction, and the very last
    // one must be Return (Cm_R = 9) - script-defined procs end
    // with Ret.
    let mut total_instructions = 0usize;
    let mut external_returns_none = 0usize;
    for proc_index in 0..(cc.procs().len() as u32) {
        let disasm = cc
            .disassemble(proc_index)
            .unwrap_or_else(|e| panic!("disassemble proc {proc_index}: {e}"));
        match disasm {
            Some(d) => {
                assert!(
                    !d.instructions.is_empty(),
                    "internal proc {proc_index} decoded to 0 instructions",
                );
                let last = d
                    .instructions
                    .last()
                    .expect("non-empty checked above")
                    .opcode
                    .raw_byte();
                assert_eq!(
                    last, 9,
                    "internal proc {proc_index} did not end with Return (got opcode 0x{last:02x})",
                );
                total_instructions += d.instructions.len();
            }
            None => external_returns_none += 1,
        }
    }
    assert!(
        total_instructions > 0,
        "expected at least one decoded instruction across the script",
    );
    assert!(
        external_returns_none > 0,
        "expected disassemble() to return None for external procs",
    );

    // Container summary line - triage-friendly one-liner.
    let summary = format!("{}", cc.display_summary());
    assert!(summary.starts_with("IFPS build "));
    assert!(summary.contains("internal"));
    assert!(summary.contains("external"));

    // Symbolic Display: the first internal proc renders without
    // panicking and contains the proc's export name in the
    // header line.
    let first_internal = (0..(cc.procs().len() as u32))
        .find(|&i| {
            matches!(
                cc.procs().get(i as usize).map(|p| &p.kind),
                Some(ProcKind::Internal(_)),
            )
        })
        .expect("at least one internal proc");
    let disasm = cc
        .disassemble(first_internal)
        .unwrap()
        .expect("internal proc has bytecode");
    let rendered = format!("{}", cc.display(&disasm));
    // First line should carry the proc's export name (the first internal
    // proc is the synthetic "!MAIN").
    assert!(
        rendered
            .lines()
            .next()
            .is_some_and(|line| line.contains("MAIN")),
        "first internal proc disasm header missing recognizable name:\n{rendered}",
    );
    // Every subsequent line begins with `  0x` (indented hex
    // offset). Skip the header line.
    for line in rendered.lines().skip(1) {
        assert!(
            line.is_empty() || line.starts_with("  0x"),
            "unexpected disasm line: {line:?}",
        );
    }

    // Fixed numeric tail.
    let tail_size = header
        .records_offset()
        .saturating_sub(header.tail_start_offset());
    assert_eq!(
        tail_size, 113,
        "6.4.0.1 fixed tail size mismatch (expected 113, see research-notes/11-fixed-tail.md)",
    );
    let tail = header.tail();
    // 6.4 dropped BackColor / BackColor2.
    assert!(tail.back_color.is_none());
    assert!(tail.back_color2.is_none());
    // 6.4 carries the inline encryption metadata (PasswordTest +
    // KDF salt + iterations + nonce).
    assert!(tail.password_test.is_some());
    assert!(tail.encryption_kdf_salt.is_some());
    assert!(tail.encryption_kdf_iterations.is_some());
    assert!(tail.encryption_base_nonce.is_some());
    // No password set on the installer ⇒ HeaderOption::Password
    // bit is clear.
    assert!(!header.has_option(HeaderOption::Password));
    // CreateAppDir is the universal default.
    assert!(header.has_option(HeaderOption::CreateAppDir));
    // Options bitset is 6 bytes wide for 6.4.x.
    assert_eq!(tail.options_raw.len(), 6);
    // 6.4 architectures are header strings (already read above), not
    // packed-set bytes here.
    assert!(tail.architectures_allowed.is_none());

    // Second block stream (data records).
    let data = inst.data_block();
    assert!(!data.is_empty(), "second block (data records) was empty",);

    // Lightweight records.
    assert_eq!(inst.languages().len(), 6);
    // Every language's standard custom messages and the script's own:
    // the record stream holds what the header counted.
    assert_eq!(inst.messages().len(), counts.custom_messages as usize);
    assert_eq!(inst.permissions().len(), 0);
    assert_eq!(inst.types().len(), 0);
    assert_eq!(inst.components().len(), 0);
    assert_eq!(inst.tasks().len(), 5);

    // Languages: first entry is en-US (LangID 0x0409), the first the
    // script declares.
    let first_lang = &inst.languages()[0];
    assert_eq!(first_lang.language_id, 0x0409, "expected en-US first");
    assert_eq!(first_lang.codepage, innospect::LanguageCodepage::Utf16Le);
    assert_eq!(
        first_lang.language_name_string().as_deref(),
        Some("English"),
    );
    // The compiler-supplied `name` identifier is whatever the script
    // declared (commonly "english", "default", or just "en"); we
    // only require it to be non-empty.
    assert!(
        first_lang.name_string().is_some_and(|s| !s.is_empty()),
        "first language has empty name",
    );
    // Every language must decode cleanly under its declared codepage.
    for l in inst.languages() {
        assert!(
            l.language_name_string().is_some(),
            "bad language_name decode"
        );
    }

    // CustomMessages: the standard language files carry the canonical
    // Inno set - "NameAndVersion" is present in every installer that uses
    // them. Each
    // CustomMessage's `language` index must point at a valid
    // [Languages] slot (or be None for the default).
    let name_and_version_utf16: Vec<u8> = "NameAndVersion"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(
        inst.messages()
            .iter()
            .any(|m| m.name == name_and_version_utf16),
        "NameAndVersion message missing",
    );
    let lang_count = inst.languages().len();
    for m in inst.messages() {
        if let Some(idx) = m.language {
            assert!(
                (idx as usize) < lang_count,
                "message references missing language index {idx}",
            );
        }
    }

    // The script's five tasks, in order.
    let tasks: Vec<_> = inst.tasks().iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        tasks,
        ["desktopicon", "quicklaunch", "associate", "startup", "docs"]
    );

    // Heavy records. Counts must match the header table.
    assert_eq!(inst.directories().len(), 0);
    assert_eq!(inst.files().len(), 10);
    assert_eq!(inst.icons().len(), 4);
    assert_eq!(inst.ini_entries().len(), 0);
    assert_eq!(inst.registry_entries().len(), 19);
    assert_eq!(inst.install_deletes().len(), 0);
    assert_eq!(inst.uninstall_deletes().len(), 0);
    assert_eq!(inst.run_entries().len(), 2);
    assert_eq!(inst.uninstall_runs().len(), 0);
    assert_eq!(inst.file_locations().len(), 9);

    // Files: first entry is the uninstaller (location_index ==
    // u32::MAX); the second is the headline binary.
    assert_eq!(inst.files()[0].location_index, u32::MAX);
    let main_exe = inst
        .files()
        .iter()
        .find(|f| f.destination.ends_with("app.exe"))
        .expect("app.exe missing from files");
    // Main binary is the first chunk → file-location[0].
    assert_eq!(main_exe.location_index, 0);

    // The HKCU and HKLM writes name the application's key.
    assert!(
        inst.registry_entries()
            .iter()
            .any(|r| r.subkey.contains("InnoTestFull")),
        "expected a registry entry with subkey containing InnoTestFull",
    );
    // File-association entries: 4 of the 7 are under HKCR.
    let hkcr_count = inst
        .registry_entries()
        .iter()
        .filter(|r| matches!(r.hive, innospect::RegistryHive::ClassesRoot))
        .count();
    assert_eq!(hkcr_count, 4, "HKCR registry entries");

    // Icons: the headline shortcut points at app.exe.
    let group_lnk = inst
        .icons()
        .iter()
        .find(|i| i.name.contains("Inno Test Full"))
        .expect("missing Start Menu icon");
    assert!(group_lnk.filename.ends_with("app.exe"));

    // The launcher is a post-install run entry.
    let launcher = inst
        .run_entries()
        .iter()
        .find(|r| r.name.ends_with("app.exe"))
        .expect("the app.exe launcher");
    assert!(launcher.flags.contains(&innospect::RunFlag::PostInstall));

    // Analysis-API roundtrip: exec_commands tags the install-time
    // entry, registry_ops classifies HKCR file-association writes,
    // and shortcuts resolves the Start Menu icon to the
    // app.exe FileEntry.
    // Both run entries are install-time commands: the launcher and the
    // README viewer.
    let exec: Vec<_> = inst.exec_commands().collect();
    assert_eq!(exec.len(), 2, "exec_commands should yield 2 entries");
    assert!(exec.iter().all(|e| e.phase == ExecPhase::Install));
    assert!(exec.iter().any(|e| e.filename().ends_with("app.exe")));

    let writes = inst
        .registry_ops()
        .filter(|op| op.kind == RegistryOpKind::Write)
        .count();
    assert!(
        writes >= 4,
        "expected at least 4 registry writes, got {writes}",
    );

    let resolved = inst.shortcuts().filter(|s| s.target.is_some()).count();
    assert!(
        resolved >= 1,
        "at least one shortcut should resolve to a [Files] entry",
    );

    // File locations: the solid chunk holds app.exe's 64 KiB of
    // pseudo-random bytes, which do not compress.
    let fl = &inst.file_locations()[0];
    assert!(
        fl.chunk_compressed_size > 60 * 1024,
        "the solid chunk should be > 60 KiB compressed, was {}",
        fl.chunk_compressed_size,
    );
    // SHA-256 checksum (6.4+).
    assert!(matches!(fl.checksum, innospect::DataChecksum::Sha256(_)));

    // Streaming extraction with checksum verification.
    let main_exe = inst
        .files()
        .iter()
        .find(|f| f.destination.ends_with("app.exe"))
        .expect("app.exe missing");
    let bytes = inst.extract_to_vec(main_exe).expect("extract app.exe");
    assert_eq!(bytes.len(), 65_536, "app.exe size");
    assert_eq!(&bytes[..2], b"MZ", "app.exe should start with MZ");

    // Uninstaller reconstruction: same length as the input, MZ
    // header preserved, and the four bytes at offset 0x30 are the
    // uninstaller marker `b"InUn"`.
    let installer_bytes = inst.input();
    let unins = inst
        .extract_uninstaller()
        .expect("the installer ships an uninstaller");
    assert_eq!(
        unins.len(),
        installer_bytes.len(),
        "uninstaller size matches input",
    );
    assert_eq!(&unins[..2], b"MZ", "uninstaller starts with MZ");
    assert_eq!(&unins[0x30..0x34], b"InUn", "uninstaller marker");
    // Bytes outside the patched range are unchanged from the input.
    assert_eq!(&unins[..0x30], &installer_bytes[..0x30]);
    assert_eq!(&unins[0x34..], &installer_bytes[0x34..]);

    // Solid LZMA proof: license.txt lives in the same chunk as
    // app.exe but at a non-zero chunk_sub_offset. Both
    // extractions must succeed - the second hits the OnceLock cache.
    let license = inst
        .files()
        .iter()
        .find(|f| f.destination.ends_with("license.txt"))
        .expect("license.txt missing");
    let lic_bytes = inst.extract_to_vec(license).expect("extract license.txt");
    assert_eq!(lic_bytes.len(), 1852, "license.txt size");

    // Streaming: read via io::Read and verify post-EOF reads return 0.
    let mut reader = inst.extract(license).expect("re-extract via Read");
    let mut sink = Vec::new();
    reader.read_to_end(&mut sink).expect("streaming read");
    assert_eq!(sink.len(), 1852);
    let mut tail = [0u8; 16];
    assert_eq!(reader.read(&mut tail).expect("post-EOF read"), 0);

    // Bulk: every non-uninstaller file extracts and verifies.
    let mut extracted = 0usize;
    let mut total = 0u64;
    for f in inst.files() {
        if f.location_index == u32::MAX {
            continue;
        }
        let bytes = inst
            .extract_to_vec(f)
            .unwrap_or_else(|e| panic!("extract {:?}: {e}", f.destination));
        total = total.saturating_add(bytes.len() as u64);
        extracted = extracted.saturating_add(1);
    }
    assert_eq!(extracted, 9);
    // app.exe 65536 + license.txt 1852 + readme.txt 21 + stored.txt 21 +
    // doc1..5, each 22 bytes repeated 10 * i times: 220 * (1 + 2 + 3 + 4 +
    // 5) = 3300.
    assert_eq!(total, 70_730);
}

/// **The 6.1 format.** `full.iss` built with Inno Setup 6.1.0: a Unicode
/// build, LZMA1 with one chunk per file and the executable through the x86
/// filter, SHA-1 checksums, and the packed architecture sets and back colours
/// of the pre-6.3 fixed tail.
#[test]
fn full_6_1_0_identifies() {
    let bytes = sample("full/full-tool6_1_0.exe");
    let inst = InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| {
        panic!("full 6.1.0 parse failed: {e}");
    });

    let v = inst.version();
    assert_eq!(
        (v.a, v.b, v.c, v.d),
        (6, 1, 0, 0),
        "marker = {:?}",
        v.marker_str()
    );
    assert!(v.is_unicode());
    assert_eq!(inst.variant(), Variant::Stock);
    assert_eq!(inst.setup_ldr_family(), SetupLdrFamily::V5_1_5);
    assert_eq!(
        inst.offset_table().source.generation,
        OffsetTableGeneration::V1,
    );
    assert_eq!(inst.compression(), Compression::Lzma1);
    // 6.1.0 predates the 6.4 encryption-header path; encryption()
    // returns None for older versions because per-chunk encryption
    // metadata isn't surfaced through that accessor.
    assert!(inst.encryption().is_none());
    // Setup-0 decompression must produce a non-trivial buffer.
    let setup0 = inst.decompressed_setup0();
    assert!(
        setup0.len() > 1024,
        "decompressed setup-0 was {} bytes",
        setup0.len()
    );

    // TSetupHeader.
    let header = inst.header().expect("full has a parsable header");
    assert_eq!(header.app_name(), Some("Inno Test (full)"));
    assert_eq!(header.app_publisher(), Some("BinFlip"));
    assert_eq!(header.app_version(), Some("2.3.4.5"));
    assert_eq!(header.default_dir_name(), Some("{autopf}\\InnoTestFull"));

    let counts = header.counts();
    assert_eq!(counts.languages, 6);
    assert_eq!(counts.files, 10);
    assert_eq!(counts.file_locations, 9);
    assert_eq!(counts.icons, 4);
    assert_eq!(counts.registry, 19);
    assert_eq!(counts.iss_sig_keys, None);

    // Fixed numeric tail.
    let tail_size = header
        .records_offset()
        .saturating_sub(header.tail_start_offset());
    assert_eq!(
        tail_size, 103,
        "6.1.0 fixed tail size mismatch (expected 103, see research-notes/11-fixed-tail.md)",
    );
    let tail = header.tail();
    // 6.1 still carries BackColor / BackColor2.
    assert!(tail.back_color.is_some());
    assert!(tail.back_color2.is_some());
    // 6.1 uses SHA1 + 8-byte salt.
    assert!(tail.legacy_password_sha1.is_some());
    assert!(tail.legacy_password_salt.is_some());
    assert!(tail.password_test.is_none());
    // 6.1 stores architectures as packed-set bytes here.
    assert!(tail.architectures_allowed.is_some());
    assert!(tail.architectures_install_in_64bit_mode.is_some());
    // CreateAppDir is the universal default.
    assert!(header.has_option(HeaderOption::CreateAppDir));
    assert_eq!(tail.options_raw.len(), 6);

    // Second block stream (data records).
    let data = inst.data_block();
    assert!(!data.is_empty(), "second block (data records) was empty",);

    // Lightweight records.
    assert_eq!(inst.languages().len(), 6);
    assert_eq!(inst.permissions().len(), 0);

    let lang = &inst.languages()[0];
    assert_eq!(lang.language_id, 0x0409, "expected en-US");
    assert_eq!(lang.codepage, innospect::LanguageCodepage::Utf16Le);
    assert_eq!(lang.language_name_string().as_deref(), Some("English"));
    assert!(
        lang.name_string().is_some_and(|s| !s.is_empty()),
        "first language has empty name",
    );

    // Heavy records.
    assert_eq!(inst.directories().len(), 0);
    assert_eq!(inst.files().len(), 10);
    assert_eq!(inst.icons().len(), 4);
    assert_eq!(inst.registry_entries().len(), 19);
    assert_eq!(inst.run_entries().len(), 2);
    assert_eq!(inst.file_locations().len(), 9);

    // Uninstaller is files[0].
    assert_eq!(inst.files()[0].location_index, u32::MAX);
    assert!(
        inst.files()
            .iter()
            .any(|f| f.destination.ends_with("app.exe")),
        "app.exe missing from files",
    );
    assert!(
        inst.registry_entries()
            .iter()
            .any(|r| r.subkey.contains("InnoTestFull")),
        "no InnoTestFull subkey in registry entries",
    );
    // The script writes two values under LocalMachine, one of them 64-bit
    // (`HKLM64`).
    let hklm_count = inst
        .registry_entries()
        .iter()
        .filter(|r| matches!(r.hive, innospect::RegistryHive::LocalMachine))
        .count();
    assert_eq!(hklm_count, 2, "HKLM entries");

    // 6.1.0 uses SHA-1 for file-location checksums (5.3.9..6.4.0).
    assert!(matches!(
        inst.file_locations()[0].checksum,
        innospect::DataChecksum::Sha1(_)
    ));

    // Extract app.exe (LZMA1 + 5309 BCJ on a pre-6.4 build - a
    // different code path than the 6.4 build's solid LZMA2).
    // Checksum verification is enforced internally; the mere fact
    // that extract_to_vec returns `Ok` proves the checksum matched.
    let app = inst
        .files()
        .iter()
        .find(|f| f.destination.ends_with("app.exe"))
        .expect("app.exe missing");
    let bytes = inst.extract_to_vec(app).expect("extract app.exe");
    assert_eq!(bytes.len(), 65_536, "app.exe size");
    assert_eq!(&bytes[..2], b"MZ", "app.exe should start with MZ");

    // Bulk extraction across one chunk per file, which exercises the
    // OnceLock chunk cache differently from the 6.4 build's single
    // solid chunk.
    let mut extracted = 0usize;
    for f in inst.files() {
        if f.location_index == u32::MAX {
            continue;
        }
        let _ = inst
            .extract_to_vec(f)
            .unwrap_or_else(|e| panic!("extract {:?}: {e}", f.destination));
        extracted = extracted.saturating_add(1);
    }
    assert_eq!(extracted, 9);
}

/// Walks `tests/samples/modern/`: `modern.iss` (6.6.1, 6.7.0, 7.1.1) asks
/// for dark-mode images (`WizardStyle=modern dynamic`), gives the small
/// image the same file in both modes, from 6.7 a back image, and the full
/// 7-Zip library. The script's own PNGs come back byte for byte, the dark
/// large image is the compiler's built-in one, distinct from the light, the
/// dark small list is stored as "same as light", and the 7-Zip DLL is the
/// compiler's `is7z.dll`
/// ([`every_fixture_carries_its_wizard_images_and_dlls`]).
#[test]
fn modern_samples_carry_dark_and_back_images() {
    let file = |name: &str| {
        std::fs::read(format!(
            "{}/tests/samples/build/modern/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap_or_else(|e| panic!("build/modern/{name}: {e}"))
    };
    let small = file("small.png");
    let back = file("back.png");
    let mut tested = 0usize;
    for (name, path) in samples_in("modern") {
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
        let inst =
            InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
        let v = inst.version();
        assert!(v.at_least(6, 6, 0), "{name}: modern.iss needs 6.6");

        assert_eq!(
            inst.wizard_images(WizardImageKind::Small),
            [&small[..]],
            "{name}: small"
        );
        assert_eq!(
            inst.wizard_images_dark(WizardImageKind::Small),
            None,
            "{name}: dark small is the light one"
        );
        let large = inst.wizard_images(WizardImageKind::Large);
        let dark_large = inst
            .wizard_images_dark(WizardImageKind::Large)
            .unwrap_or_else(|| panic!("{name}: no dark large images"));
        assert!(!dark_large.is_empty(), "{name}: dark large images");
        assert_ne!(dark_large, large, "{name}: dark large is the light one");
        for image in dark_large {
            assert!(
                image.starts_with(b"\x89PNG"),
                "{name}: dark large not a PNG"
            );
        }

        if v.at_least(6, 7, 0) {
            assert_eq!(
                inst.wizard_images(WizardImageKind::Back),
                [&back[..]],
                "{name}: back"
            );
            // No dark back image is named: an empty list.
            assert_eq!(
                inst.wizard_images_dark(WizardImageKind::Back),
                Some(Vec::new()),
                "{name}: dark back"
            );
        } else {
            assert!(
                inst.wizard_images(WizardImageKind::Back).is_empty(),
                "{name}: back"
            );
            assert_eq!(
                inst.wizard_images_dark(WizardImageKind::Back),
                None,
                "{name}: dark back"
            );
        }
        assert_eq!(
            inst.header()
                .and_then(|h| h.string(HeaderString::SevenZipLibraryName)),
            Some("is7z.dll"),
            "{name}: SevenZipLibraryName"
        );
        assert!(inst.seven_zip_dll().is_some(), "{name}: 7-Zip DLL");
        let extracted: Vec<_> = inst
            .extract_files()
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("{name}: extract_files: {e}"));
        let [(_, payload)] = &extracted[..] else {
            panic!("{name}: extracted {} files", extracted.len());
        };
        assert_eq!(
            payload.as_slice(),
            b"Inno test payload v1\n",
            "{name}: payload"
        );
        tested += 1;
    }
    assert_eq!(tested, 3, "modern samples");
}

/// Walks `tests/samples/spanning/`: `spanning.iss` / `spanning-legacy.iss`
/// built once per slice-file generation, each fixture with the slice files
/// its compiler wrote, under their own names, in `<fixture>.slices/`.
/// `slice_file_name` must name exactly those files; without them a file
/// fails with `ExternalSlice`, with them every file extracts, a chunk
/// crossing from one slice into the next included; and each slice starts
/// with its release's ID.
#[test]
fn spanning_samples_extract_from_their_slice_files() {
    let random = std::fs::read(format!(
        "{}/tests/samples/build/spanning/random.bin",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read build/spanning/random.bin");
    let mut tested = 0usize;
    for (name, path) in samples_in("spanning") {
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
        let inst =
            InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
        let v = inst.version().clone();
        assert!(inst.uses_slice_files(), "{name}: slice files");

        // The names Setup looks for, against the files the compiler wrote
        // (for the installer `spanning.exe`, as it was built).
        let dir = path.with_extension("slices");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|e| e.expect("entry").file_name().into_string().expect("utf-8"))
            .collect();
        on_disk.sort();
        let names: Vec<String> = (0..inst.slice_count())
            .map(|i| inst.slice_file_name(i, "spanning.exe"))
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(sorted, on_disk, "{name}: slice file names");

        // Without the slices, no file can be read.
        let payload = inst
            .files()
            .iter()
            .find(|f| f.destination.ends_with("payload.txt"))
            .unwrap_or_else(|| panic!("{name}: payload.txt"));
        assert!(
            matches!(inst.extract_to_vec(payload), Err(Error::ExternalSlice)),
            "{name}: extract without slices"
        );
        // Something that is not a slice is refused.
        assert!(
            matches!(
                InnoInstaller::from_bytes(&bytes)
                    .unwrap()
                    .with_slices(&[&bytes[..]]),
                Err(Error::BadSlice { index: 0, .. })
            ),
            "{name}: not a slice"
        );

        let slices: Vec<Vec<u8>> = names
            .iter()
            .map(|n| std::fs::read(dir.join(n)).unwrap_or_else(|e| panic!("{name}: {n}: {e}")))
            .collect();
        let id: &[u8] = if v.at_least(6, 5, 2) {
            b"idskb32\x1a"
        } else {
            b"idska32\x1a"
        };
        for (slice, n) in slices.iter().zip(&names) {
            assert_eq!(&slice[..8], id, "{name}: {n} ID");
        }
        let refs: Vec<&[u8]> = slices.iter().map(Vec::as_slice).collect();
        let inst = inst
            .with_slices(&refs)
            .unwrap_or_else(|e| panic!("{name}: with_slices: {e}"));
        assert!(
            inst.file_locations()
                .iter()
                .any(|d| d.first_slice != d.last_slice),
            "{name}: no chunk crosses slices"
        );
        let extracted: Vec<_> = inst
            .extract_files()
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("{name}: extract_files: {e}"));
        let mut randoms = 0usize;
        let mut payloads = 0usize;
        for (file, data) in &extracted {
            if file.destination.ends_with(".bin") {
                assert_eq!(data, &random, "{name}: {}", file.destination);
                randoms += 1;
            } else if file.destination.ends_with("payload.txt") {
                assert_eq!(
                    data.as_slice(),
                    b"Inno test payload v1\n",
                    "{name}: payload"
                );
                payloads += 1;
            }
        }
        // `spanning-legacy.iss` stores the random file once, `spanning.iss`
        // five times.
        let expected_randoms = if v.at_least(4, 0, 0) { 5 } else { 1 };
        assert_eq!((randoms, payloads), (expected_randoms, 1), "{name}: files");
        tested += 1;
    }
    assert_eq!(tested, 7, "spanning samples");
}

/// `ISCrypt.dll` as `build/install-inno.sh` pins it: the encryption add-on
/// the pre-6.4 compilers store in every encrypted installer.
const ISCRYPT_SHA256: &str = "2f6294f9aa09f59a574b5dcd33be54e16b39377984f3d5658cda44950fa0f8fc";

/// `build/compiler-dlls.txt` (`build/list-dlls.sh`): the SHA-256 of each
/// DLL a compiler stores, by compiler slug and file name.
fn compiler_dlls() -> std::collections::BTreeMap<(String, String), String> {
    let path = format!(
        "{}/tests/samples/build/compiler-dlls.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .lines()
        .map(|line| {
            let [slug, file, sha256] = line.split_whitespace().collect::<Vec<_>>()[..] else {
                panic!("{path}: malformed row {line:?}");
            };
            ((slug.to_owned(), file.to_owned()), sha256.to_owned())
        })
        .collect()
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The decompressor DLL Setup needs for `method` in release `v`
/// (`Main.pas` / `Setup.MainFunc.pas`): for bzip2, before 4.1.5 the
/// `BzipUsed` option's method; in 4.1.5 for LZMA too; from 4.2.6 for zip.
fn decompressor_for(
    v: &innospect::Version,
    method: Option<CompressMethod>,
) -> Option<&'static str> {
    match method? {
        CompressMethod::Bzip2 => Some("isbunzip.dll"),
        CompressMethod::Zlib if v.at_least(4, 2, 6) => Some("isunzlib.dll"),
        CompressMethod::Lzma1 if v.at_least(4, 1, 5) && !v.at_least(4, 1, 6) => {
            Some("isunlzma.dll")
        }
        _ => None,
    }
}

/// Every fixture: the wizard images and DLLs after the records read back
/// and end the records block, which parsing checks. Each image is a BMP or
/// a PNG; before 5.6.0 there is one of each size, the small from 2.0.0;
/// dark-mode lists exist from 6.6.0 and back images from 6.7.0. An
/// encrypted installer from 4.2.2 to 6.4.0 carries the very `ISCrypt.dll`
/// the image gave its compiler, and a stored decompressor or 7-Zip DLL is
/// byte for byte its compiler's own file.
#[test]
fn every_fixture_carries_its_wizard_images_and_dlls() {
    let dlls = compiler_dlls();
    let mut tested = 0usize;
    let mut decryption_dlls = 0usize;
    let mut decompressor_dlls = BTreeSet::new();
    let mut seven_zip_dlls = 0usize;
    for dir in [
        "plain",
        "encrypted",
        "full",
        "code",
        "password",
        "legacy",
        "official",
        "modern",
    ] {
        for (name, path) in samples_in(dir) {
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
            let inst = InnoInstaller::from_bytes_with_passwords(&bytes, &["test123"])
                .unwrap_or_else(|e| panic!("{name}: parse: {e}"));
            let v = inst.version().clone();
            for kind in [
                WizardImageKind::Large,
                WizardImageKind::Small,
                WizardImageKind::Back,
            ] {
                let images = inst.wizard_images(kind);
                let expected = match kind {
                    WizardImageKind::Large => true,
                    WizardImageKind::Small => v.at_least(2, 0, 0),
                    // Only `modern.iss` names a back image.
                    _ => dir == "modern" && v.at_least(6, 7, 0),
                };
                assert_eq!(!images.is_empty(), expected, "{name}: {kind} images");
                if !v.at_least(5, 6, 0) {
                    assert!(images.len() <= 1, "{name}: {kind} images before 5.6");
                }
                for image in images {
                    assert!(
                        image.starts_with(b"BM") || image.starts_with(b"\x89PNG"),
                        "{name}: {kind} image is neither BMP nor PNG"
                    );
                }
                let dark = inst.wizard_images_dark(kind);
                if dir == "modern" {
                    continue; // `modern_samples_carry_dark_and_back_images`.
                }
                let has_dark =
                    v.at_least(6, 6, 0) && (kind != WizardImageKind::Back || v.at_least(6, 7, 0));
                assert_eq!(dark.is_some(), has_dark, "{name}: {kind} dark images");
                // The script names no dark images: the compiler writes an
                // empty list.
                assert_eq!(dark.map_or(0, |d| d.len()), 0, "{name}: {kind} dark");
            }
            let wants_iscrypt = inst.is_encrypted() && v.at_least(4, 2, 2) && !v.at_least(6, 4, 0);
            match inst.decryption_dll() {
                Some(dll) => {
                    assert!(wants_iscrypt, "{name}: decryption DLL");
                    assert_eq!(sha256_hex(dll), ISCRYPT_SHA256, "{name}: ISCrypt.dll");
                    decryption_dlls += 1;
                }
                None => assert!(!wants_iscrypt, "{name}: no decryption DLL"),
            }

            // A stored DLL is its compiler's own file.
            let own = |file: &str| -> String {
                let slug = name
                    .rsplit_once("-tool")
                    .map(|(_, rest)| rest.trim_end_matches(".exe").trim_end_matches("-alt"))
                    .unwrap_or_else(|| panic!("{name}: no compiler slug"));
                dlls.get(&(slug.to_owned(), file.to_owned()))
                    .unwrap_or_else(|| panic!("{name}: compiler {slug} has no {file}"))
                    .clone()
            };
            let method = inst.header().and_then(|h| h.tail().compress_method);
            match (inst.decompressor_dll(), decompressor_for(&v, method)) {
                (Some(dll), Some(file)) => {
                    assert_eq!(sha256_hex(dll), own(file), "{name}: {file}");
                    decompressor_dlls.insert(file);
                }
                (None, None) => {}
                (got, want) => panic!(
                    "{name}: decompressor DLL of {:?} bytes, expected {want:?}",
                    got.map(<[u8]>::len)
                ),
            }
            let seven_zip = inst
                .header()
                .and_then(|h| h.string(HeaderString::SevenZipLibraryName))
                .filter(|n| !n.is_empty())
                .map(str::to_lowercase);
            match (inst.seven_zip_dll(), seven_zip) {
                (Some(dll), Some(file)) => {
                    assert_eq!(sha256_hex(dll), own(&file), "{name}: {file}");
                    seven_zip_dlls += 1;
                }
                (None, None) => {}
                (got, want) => panic!(
                    "{name}: 7-Zip DLL of {:?} bytes, expected {want:?}",
                    got.map(<[u8]>::len)
                ),
            }
            tested += 1;
        }
    }
    assert!(tested > 80, "only {tested} fixtures");
    assert_eq!(decryption_dlls, 9, "encrypted fixtures from 5.0.8 to 6.3.0");
    assert_eq!(
        decompressor_dlls,
        ["isbunzip.dll", "isunlzma.dll", "isunzlib.dll"]
            .into_iter()
            .collect(),
        "every decompressor DLL"
    );
    assert!(seven_zip_dlls >= 3, "only {seven_zip_dlls} 7-Zip DLLs");
}

/// The `<name>-<variant>` builds `build/build-wine.sh` knows.
const VARIANTS: &[&str] = &["x64", "zip", "bzip", "lzma", "none"];

/// **Every fixture the matrix builds is committed, and nothing else.** The
/// expected set is derived from `build/versions.txt` with the naming
/// `build/build-wine.sh` files outputs under, so a fixture missing from a
/// checkout fails here instead of shrinking what the directory walkers test.
#[test]
fn every_matrix_fixture_is_present() {
    let root = format!("{}/tests/samples", env!("CARGO_MANIFEST_DIR"));
    let matrix = std::fs::read_to_string(format!("{root}/build/versions.txt"))
        .expect("read build/versions.txt");

    let mut expected = BTreeSet::new();
    for line in matrix.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let [slug, _url, scripts] = fields[..] else {
            panic!("versions.txt: malformed row {line:?}");
        };
        let scripts: Vec<&str> = scripts.split(',').collect();
        let suffixes: &[&str] = if scripts.contains(&"alt") {
            &["", "-alt"]
        } else {
            &[""]
        };
        for &script in scripts.iter().filter(|&&s| s != "alt") {
            // `<name>-<variant>` is `<name>.iss` built with one directive
            // changed, filed beside it with `-<variant>` before `-tool`.
            let (base, arch) = match script.rsplit_once('-') {
                Some((base, variant)) if VARIANTS.contains(&variant) => {
                    (base, &script[base.len()..])
                }
                _ => (script, ""),
            };
            for suffix in suffixes {
                expected.insert(match base {
                    "plain" => format!("plain/plain{arch}-tool{slug}{suffix}.exe"),
                    "encrypted" => format!("encrypted/enc-files{arch}-tool{slug}{suffix}.exe"),
                    "encrypted-full" => {
                        format!("encrypted/enc-full{arch}-tool{slug}{suffix}.exe")
                    }
                    // `spanning-legacy.iss` builds into `spanning/`.
                    "spanning-legacy" => format!("spanning/spanning{arch}-tool{slug}{suffix}.exe"),
                    other => format!("{other}/{other}{arch}-tool{slug}{suffix}.exe"),
                });
            }
        }
    }

    let dirs: BTreeSet<&str> = expected
        .iter()
        .filter_map(|p| p.split_once('/').map(|(dir, _)| dir))
        .collect();
    let present: BTreeSet<String> = dirs
        .iter()
        .flat_map(|dir| {
            samples_in(dir)
                .into_iter()
                .map(move |(name, _)| format!("{dir}/{name}"))
        })
        .collect();

    let missing: Vec<_> = expected.difference(&present).collect();
    let unexpected: Vec<_> = present.difference(&expected).collect();
    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "fixtures out of step with build/versions.txt\n  missing: {missing:?}\n  not in the matrix: {unexpected:?}",
    );
}

/// Walks `tests/samples/plain/` and parses every `*.exe`. Each sample
/// must report no encryption, expose a parsable header, and extract
/// the canonical 21-byte `payload.txt` cleanly. Fails if the directory
/// is missing or empty, so a missing matrix can't silently degrade to a
/// no-op; [`every_matrix_fixture_is_present`] catches a single missing file.
#[test]
fn plain_samples_parse_and_extract() {
    let samples = samples_in("plain");
    let mut tested = 0usize;
    for (name, path) in samples {
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
        let inst =
            InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: parse: {e}"));

        assert!(!inst.is_encrypted(), "{name}: should not be encrypted");
        assert!(!inst.has_password(), "{name}: should have no password");
        // SetupLdr refuses a file shorter than TotalSize; an unsigned
        // installer is exactly that long.
        assert_eq!(
            inst.offset_table().total_size,
            bytes.len() as u64,
            "{name}: TotalSize"
        );

        // A candidate list is not a demand: an installer with no password
        // parses with one, or with an empty one, as it does without, and
        // records no match. Every 6.5+ installer carries an encryption
        // header, so its presence must not be read as "has a password".
        for candidates in [&["test123", "nope"][..], &[]] {
            let with = InnoInstaller::from_bytes_with_passwords(&bytes, candidates)
                .unwrap_or_else(|e| panic!("{name}: parse with {candidates:?}: {e}"));
            assert_eq!(with.password_used(), None, "{name}: password_used");
            assert_eq!(with.files().len(), inst.files().len(), "{name}: files");
        }
        assert_eq!(
            inst.header().and_then(|h| h.string(HeaderString::AppName)),
            Some("Inno Test (plain)"),
            "{name}: AppName",
        );
        // No `[Code]`: from marker 7.0.0.3 the field is there and zero.
        let v = inst.version();
        assert_eq!(
            inst.header().and_then(|h| h.tail().compiled_code_version),
            v.at_least_4(7, 0, 0, 3).then_some(0),
            "{name}: CompiledCodeVersion",
        );

        let header = inst
            .header()
            .unwrap_or_else(|| panic!("{name}: header missing"));
        // `plain.iss` compresses with LZMA; a `-zip`, `-bzip` or `-none`
        // build with its method, and `-none` stores every chunk as is.
        let (variant, _) =
            fixture_name(&name, "plain").unwrap_or_else(|| panic!("{name}: not a plain.iss build"));
        let method = match variant {
            Some(v) if v != "x64" => variant_method(v),
            _ => CompressMethod::Lzma1,
        };
        assert_eq!(
            header.tail().compress_method,
            Some(method),
            "{name}: method"
        );
        assert_eq!(
            inst.languages()
                .first()
                .and_then(|l| l.language_name_string())
                .as_deref(),
            Some("English"),
            "{name}: language name"
        );
        for location in inst.file_locations() {
            assert_eq!(
                location.flags.contains(&DataFlag::ChunkCompressed),
                method != CompressMethod::Stored,
                "{name}: ChunkCompressed"
            );
        }
        assert!(
            header.counts().files >= 1,
            "{name}: expected at least 1 file, got {}",
            header.counts().files,
        );

        // Uninstaller reconstruction: the build-toolchain `.iss`
        // files don't set Uninstallable=no, so every sample must
        // ship an uninstaller stub. Patched bytes match the
        // original input length and carry the `InUn` marker.
        let unins = inst
            .extract_uninstaller()
            .unwrap_or_else(|e| panic!("{name}: extract_uninstaller: {e}"));
        assert_eq!(unins.len(), bytes.len(), "{name}: uninstaller size");
        assert_eq!(&unins[0x30..0x34], b"InUn", "{name}: marker");

        // Bulk path: extract_files() walks the file table and
        // skips the uninstaller-stub entry (loc=u32::MAX). Build
        // toolchain installs a single payload.txt, so the bulk
        // iterator should yield exactly one item that matches the
        // single-call extract result.
        let bulk: Vec<_> = inst
            .extract_files()
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("{name}: extract_files: {e}"));
        assert_eq!(
            bulk.len(),
            1,
            "{name}: bulk yielded {} entries, expected 1 (uninstaller stub filtered)",
            bulk.len(),
        );
        let (bulk_file, bulk_bytes) = &bulk[0];
        assert!(
            bulk_file.destination.ends_with("payload.txt"),
            "{name}: bulk first entry was {:?}",
            bulk_file.destination,
        );
        assert_eq!(
            bulk_bytes.as_slice(),
            b"Inno test payload v1\n",
            "{name}: bulk payload bytes mismatch",
        );
        tested = tested.saturating_add(1);
    }
    assert!(
        tested > 0,
        "no plain samples found under tests/samples/plain/"
    );
    eprintln!("plain_samples_parse_and_extract: tested {tested} sample(s)");
}

/// A fixture name split into its `-<variant>` (see [`VARIANTS`]) and its
/// compiler slug: `legacy-bzip-tool4_0_8.exe` is `(Some("bzip"), "4_0_8")`.
fn fixture_name<'a>(name: &'a str, script: &str) -> Option<(Option<&'a str>, &'a str)> {
    let rest = name.strip_prefix(script)?.strip_suffix(".exe")?;
    let rest = rest.strip_suffix("-alt").unwrap_or(rest);
    let (variant, slug) = rest.split_once("-tool")?;
    let variant = match variant.strip_prefix('-') {
        Some(v) if VARIANTS.contains(&v) => Some(v),
        Some(_) => return None,
        None if variant.is_empty() => None,
        None => return None,
    };
    Some((variant, slug))
}

/// The method a `-<variant>` build compresses with.
fn variant_method(variant: &str) -> CompressMethod {
    match variant {
        "zip" => CompressMethod::Zlib,
        "bzip" => CompressMethod::Bzip2,
        "lzma" => CompressMethod::Lzma1,
        "none" => CompressMethod::Stored,
        other => panic!("{other}: not a compression variant"),
    }
}

/// The setup data marker each `legacy.iss` fixture carries and the
/// version its records are read as. They differ where a release changed
/// the records and kept the marker: 3.0.4 writes `(3.0.3)`, 4.2.4 writes
/// `(4.2.3)`.
const LEGACY: &[(&str, &str, (u8, u8, u8))] = &[
    ("1_3_26", "1.3.25", (1, 3, 25)),
    ("2_0_19", "2.0.18", (2, 0, 18)),
    ("3_0_0", "3.0.0a", (3, 0, 0)),
    ("3_0_2", "3.0.1", (3, 0, 1)),
    ("3_0_3", "3.0.3", (3, 0, 3)),
    ("3_0_4", "3.0.3", (3, 0, 4)),
    ("3_0_7", "3.0.5", (3, 0, 5)),
    ("4_0_0", "4.0.0a", (4, 0, 0)),
    ("4_0_2", "4.0.1", (4, 0, 1)),
    ("4_0_4", "4.0.3", (4, 0, 3)),
    ("4_0_8", "4.0.5", (4, 0, 5)),
    ("4_0_9", "4.0.9", (4, 0, 9)),
    ("4_0_10", "4.0.10", (4, 0, 10)),
    ("4_0_11", "4.0.11", (4, 0, 11)),
    ("4_1_1", "4.1.0", (4, 1, 0)),
    ("4_1_2", "4.1.2", (4, 1, 2)),
    ("4_1_3", "4.1.3", (4, 1, 3)),
    ("4_1_4", "4.1.4", (4, 1, 4)),
    ("4_1_5", "4.1.5", (4, 1, 5)),
    ("4_1_7", "4.1.6", (4, 1, 6)),
    ("4_1_8", "4.1.8", (4, 1, 8)),
    ("4_2_0", "4.2.0", (4, 2, 0)),
    ("4_2_1", "4.2.1", (4, 2, 1)),
    ("4_2_2", "4.2.2", (4, 2, 2)),
    ("4_2_3", "4.2.3", (4, 2, 3)),
    ("4_2_4", "4.2.3", (4, 2, 4)),
    ("4_2_5", "4.2.5", (4, 2, 5)),
    ("4_2_7", "4.2.6", (4, 2, 6)),
];

/// Walks `tests/samples/legacy/`: `legacy.iss` built by one Inno Setup per
/// setup data marker from 1.3.25 to 4.2.6. Every record the script states
/// reads back, the payload extracts, and so does the uninstaller, which
/// before 5.0 is a program of its own stored as a file.
#[test]
fn legacy_samples_carry_what_legacy_iss_states() {
    let mut seen = BTreeSet::new();
    for (name, path) in samples_in("legacy") {
        let (variant, slug) = fixture_name(&name, "legacy")
            .unwrap_or_else(|| panic!("{name}: not a legacy.iss build"));
        let &(_, marker, (a, b, c)) = LEGACY
            .iter()
            .find(|(s, _, _)| *s == slug)
            .unwrap_or_else(|| panic!("{name}: not in LEGACY"));
        if variant.is_none() {
            seen.insert(slug.to_string());
        }

        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
        let inst =
            InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
        let v = inst.version();
        assert_eq!(
            v.marker_str(),
            format!("Inno Setup Setup Data ({marker})"),
            "{name}: marker"
        );
        assert_eq!((v.a, v.b, v.c, v.d), (a, b, c, 0), "{name}: layout version");
        assert!(
            !inst.is_encrypted() && !inst.has_password(),
            "{name}: password"
        );
        assert_eq!(
            inst.offset_table().total_size,
            bytes.len() as u64,
            "{name}: TotalSize"
        );

        let header = inst
            .header()
            .unwrap_or_else(|| panic!("{name}: header missing"));
        // `legacy.iss` names no method: zip before 4.1.8, LZMA from it.
        let method = variant.map_or(
            if v.at_least(4, 1, 8) {
                CompressMethod::Lzma1
            } else {
                CompressMethod::Zlib
            },
            variant_method,
        );
        assert_eq!(
            header.tail().compress_method,
            Some(method),
            "{name}: method"
        );
        // 2.0.17 to 4.0.1 mark each bzip2 file; from 4.0.1 the header says.
        let per_file_bzip = method == CompressMethod::Bzip2 && !v.at_least(4, 0, 1);
        for location in inst.file_locations() {
            assert_eq!(
                location.flags.contains(&DataFlag::BZipped),
                per_file_bzip,
                "{name}: BZipped"
            );
        }
        for (field, value) in [
            (HeaderString::AppName, "Inno Test (legacy)"),
            (HeaderString::AppVerName, "Inno Test (legacy) 1.0.0"),
            (HeaderString::AppPublisher, "BinFlip"),
            (HeaderString::AppPublisherUrl, "https://example.invalid/"),
            (HeaderString::DefaultDirName, "{pf}\\InnoTestLegacy"),
            (HeaderString::DefaultGroupName, "Inno Test Legacy"),
        ] {
            assert_eq!(header.string(field), Some(value), "{name}: {field:?}");
        }

        // One `TSetupLangOptions` from 2.0.1, a language entry from 4.0.
        let languages = usize::from(v.at_least(2, 0, 1));
        assert_eq!(inst.languages().len(), languages, "{name}: languages");
        // UTF-16 from 4.2.2 in these ANSI builds too.
        if let Some(language) = inst.languages().first() {
            assert_eq!(
                language.language_name_string().as_deref(),
                Some("English"),
                "{name}: language name"
            );
        }
        // 1.3 skips the sections it does not know.
        let (types, components, tasks) = if v.at_least(2, 0, 0) {
            (2, 2, 1)
        } else {
            (0, 0, 0)
        };
        assert_eq!(inst.types().len(), types, "{name}: types");
        assert_eq!(inst.components().len(), components, "{name}: components");
        assert_eq!(inst.tasks().len(), tasks, "{name}: tasks");
        if types > 0 {
            let names: Vec<_> = inst.types().iter().map(|t| t.name.as_str()).collect();
            assert_eq!(names, ["full", "custom"], "{name}: types");
            assert!(inst.types()[1].is_custom, "{name}: custom type");
            let component = &inst.components()[0];
            assert_eq!(
                (component.name.as_str(), component.types.as_str()),
                // The compiler stores the list comma-separated.
                ("main", "full,custom"),
                "{name}: component"
            );
            assert_eq!(inst.tasks()[0].name, "desktopicon", "{name}: task");
            assert_eq!(
                inst.tasks()[0].description,
                "Create a desktop icon",
                "{name}: task"
            );
        }

        let dirs: Vec<_> = inst.directories().iter().map(|d| d.name.as_str()).collect();
        assert_eq!(dirs, ["{app}\\data"], "{name}: dirs");
        let [icon] = inst.icons() else {
            panic!("{name}: icons {:?}", inst.icons().len());
        };
        assert_eq!(
            (icon.name.as_str(), icon.filename.as_str()),
            ("{group}\\Payload", "{app}\\payload.txt"),
            "{name}: icon"
        );
        let [ini] = inst.ini_entries() else {
            panic!("{name}: ini entries {:?}", inst.ini_entries().len());
        };
        assert_eq!(
            (
                ini.inifile.as_str(),
                ini.section.as_str(),
                ini.key.as_str(),
                ini.value.as_str()
            ),
            ("{app}\\legacy.ini", "Main", "Version", "1.0.0"),
            "{name}: ini"
        );
        let [reg] = inst.registry_entries() else {
            panic!("{name}: registry {:?}", inst.registry_entries().len());
        };
        assert_eq!(reg.hive, RegistryHive::CurrentUser, "{name}: hive");
        assert_eq!(
            (reg.subkey.as_str(), reg.value_name.as_str()),
            ("Software\\InnoTestLegacy", "Path"),
            "{name}: registry key"
        );
        assert_eq!(
            reg.data,
            RegistryData::String("{app}".into()),
            "{name}: registry data"
        );
        let deletes =
            |entries: &[innospect::DeleteEntry]| -> Vec<(String, Option<DeleteTargetType>)> {
                entries
                    .iter()
                    .map(|d| (d.name.clone(), d.target_type))
                    .collect()
            };
        assert_eq!(
            deletes(inst.install_deletes()),
            [(
                "{app}\\stale.txt".to_string(),
                Some(DeleteTargetType::Files)
            )],
            "{name}: install deletes"
        );
        assert_eq!(
            deletes(inst.uninstall_deletes()),
            [(
                "{app}\\data".to_string(),
                Some(DeleteTargetType::FilesAndSubdirs)
            )],
            "{name}: uninstall deletes"
        );
        let [run] = inst.run_entries() else {
            panic!("{name}: run {:?}", inst.run_entries().len());
        };
        assert_eq!(run.name, "{app}\\payload.txt", "{name}: run");
        assert_eq!(run.wait, Some(RunWait::NoWait), "{name}: run wait");
        let [unrun] = inst.uninstall_runs() else {
            panic!("{name}: uninstall run {:?}", inst.uninstall_runs().len());
        };
        assert_eq!(
            (unrun.name.as_str(), unrun.parameters.as_str()),
            ("{sys}\\cmd.exe", "/c echo Inno test uninstall"),
            "{name}: uninstall run"
        );

        // Adler-32 before 4.0.1, CRC-32 to 4.2.0, MD5 after.
        for location in inst.file_locations() {
            let expected = match location.checksum {
                DataChecksum::Adler32(_) => !v.at_least(4, 0, 1),
                DataChecksum::Crc32(_) => v.at_least(4, 0, 1) && !v.at_least(4, 2, 0),
                DataChecksum::Md5(_) => v.at_least(4, 2, 0),
                _ => false,
            };
            assert!(expected, "{name}: checksum {:?}", location.checksum);
        }

        // Before 5.0 the uninstaller is a stored file: extract_files yields
        // it beside the payload, and extract_uninstaller returns it.
        let extracted: Vec<_> = inst
            .extract_files()
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_else(|e| panic!("{name}: extract_files: {e}"));
        let [(unins_entry, unins), (payload_entry, payload)] = &extracted[..] else {
            panic!("{name}: extracted {} files", extracted.len());
        };
        assert_eq!(
            unins_entry.file_type,
            Some(FileEntryType::UninstExe),
            "{name}: first file"
        );
        assert!(payload_entry.destination.ends_with("payload.txt"), "{name}");
        assert_eq!(
            payload.as_slice(),
            b"Inno test payload v1\n",
            "{name}: payload"
        );
        assert_eq!(&unins[..2], b"MZ", "{name}: uninstaller");
        let uninstaller = inst
            .extract_uninstaller()
            .unwrap_or_else(|e| panic!("{name}: extract_uninstaller: {e}"));
        assert_eq!(&uninstaller, unins, "{name}: extract_uninstaller");
    }
    let expected: BTreeSet<String> = LEGACY.iter().map(|(s, _, _)| s.to_string()).collect();
    assert_eq!(seen, expected, "tests/samples/legacy/ against LEGACY");
}

/// The one 1.2 installer there is: Inno Setup 1.2.16's own 16-bit package,
/// as published (`tests/samples/official/`). Its 12-byte `i1.2.10--16`
/// marker, the NE container, the size-prefixed records, the 16-bit field
/// widths and DOS time stamps all read back to what innoextract 1.9 reports
/// for the same file: every extracted file and time stamp matched it.
#[test]
fn official_1_2_16_16bit_package_parses_and_extracts() {
    use sha2::{Digest, Sha256};
    let bytes = sample("official/isetup16-1.2.16.exe");
    let digest = |data: &[u8]| -> String {
        Sha256::digest(data)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    };
    assert_eq!(
        digest(&bytes),
        "9f4fbab8039f40cd3ea6dcbe34de0d4d40ed4037bc1c9737027b20181e461dc5",
        "the package as published"
    );
    let inst = InnoInstaller::from_bytes(&bytes).expect("parse");
    let v = inst.version();
    assert_eq!((v.a, v.b, v.c, v.d), (1, 2, 10, 0));
    assert!(v.is_16bit());
    assert_eq!(v.marker_str(), "i1.2.10--16\x1a");
    assert_eq!(inst.variant(), Variant::Legacy1210);
    assert_eq!(inst.offset_table().total_size, bytes.len() as u64);

    let header = inst.header().expect("header");
    assert_eq!(header.string(HeaderString::AppName), Some("Inno Setup"));
    assert_eq!(
        header.string(HeaderString::AppVerName),
        Some("Inno Setup version 1.2.16 (16-bit)")
    );
    assert_eq!(
        header.string(HeaderString::DefaultDirName),
        Some("{sd}\\ISETUP")
    );
    // Before 1.3.0 the license and info texts follow the header; this
    // package has none.
    for field in [
        HeaderAnsi::LicenseText,
        HeaderAnsi::InfoBeforeText,
        HeaderAnsi::InfoAfterText,
    ] {
        assert_eq!(header.ansi(field), Some(&[][..]), "{field:?}");
    }
    let counts = header.counts();
    assert_eq!(
        (
            counts.files,
            counts.file_locations,
            counts.icons,
            counts.ini_entries,
            counts.uninstall_deletes
        ),
        (14, 13, 2, 1, 7)
    );
    let icons: Vec<_> = inst
        .icons()
        .iter()
        .map(|i| (i.name.as_str(), i.filename.as_str()))
        .collect();
    assert_eq!(
        icons,
        [
            ("{group}\\Setup Compiler (16-bit)", "{app}\\COMPIL16.EXE"),
            ("{group}\\Documentation (16-bit)", "{app}\\ISETUP.HLP"),
        ]
    );

    let extracted: Vec<_> = inst
        .extract_files()
        .collect::<Result<Vec<_>, _>>()
        .expect("extract_files");
    assert_eq!(extracted.len(), 14);
    // Hashes and DOS times (UTC) as innoextract 1.9 extracts them.
    for (destination, sha256, time) in [
        (
            "{app}\\COMPIL16.EXE",
            "c42ff94c38376e1f3a0a3d8913ae2540921345f58ff3c534dc4c87e57905b02f",
            956_020_800,
        ),
        (
            "{app}\\UNINST.E16",
            "7867c2526fc59a8d2d770b028170fb62799164e94fac0d876f9ed74c3e705af7",
            956_020_800,
        ),
        (
            "{app}\\SAMPLE16\\README.TXT",
            "8cb5a1067b66e78c21d16a457f7732eb68345af897a91ab61d9247b314f66b75",
            906_253_740,
        ),
    ] {
        let (file, data) = extracted
            .iter()
            .find(|(f, _)| f.destination == destination)
            .unwrap_or_else(|| panic!("{destination} not extracted"));
        assert_eq!(digest(data), sha256, "{destination}");
        let location = &inst.file_locations()[file.location_index as usize];
        assert_eq!(location.timestamp_seconds, time, "{destination}");
        assert!(
            matches!(location.checksum, DataChecksum::Adler32(_)),
            "{destination}"
        );
    }
    // Before 5.0 the uninstaller is a file of its own.
    let uninstaller = inst.extract_uninstaller().expect("extract_uninstaller");
    assert_eq!(
        digest(&uninstaller),
        "7867c2526fc59a8d2d770b028170fb62799164e94fac0d876f9ed74c3e705af7"
    );
}

/// Walks `tests/samples/password/`: `password.iss`, a `Password=` without
/// `Encryption=`, across the three places the verifier has lived (the pre-6.4
/// header hash, the 6.4 header tail, the 6.5+ encryption header with
/// `euNone`). Setup asks for the password, so a candidate list must contain
/// it; nothing is encrypted, so the payload extracts with or without it.
#[test]
fn password_only_samples_check_the_password_and_encrypt_nothing() {
    let mut eras = BTreeSet::new();
    for (name, path) in samples_in("password") {
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
        let inst =
            InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
        let header = inst
            .header()
            .unwrap_or_else(|| panic!("{name}: header missing"));
        assert_eq!(
            header.string(HeaderString::AppName),
            Some("Inno Test (password)"),
            "{name}: AppName",
        );
        assert!(
            header.has_option(HeaderOption::Password),
            "{name}: Password"
        );
        assert!(!inst.is_encrypted(), "{name}: nothing is encrypted");
        assert!(inst.has_password(), "{name}: has a password");
        assert!(
            !header.has_option(HeaderOption::EncryptionUsed),
            "{name}: EncryptionUsed",
        );
        assert!(
            matches!(
                inst.encryption().map(|e| e.mode),
                None | Some(EncryptionMode::None)
            ),
            "{name}: encryption mode",
        );
        let payload = |inst: &InnoInstaller<'_>| {
            let bulk: Vec<_> = inst
                .extract_files()
                .collect::<Result<_, _>>()
                .unwrap_or_else(|e| panic!("{name}: extract_files: {e}"));
            assert_eq!(bulk.len(), 1, "{name}: one payload");
            bulk[0].1.clone()
        };
        assert_eq!(payload(&inst), b"Inno test payload v1\n", "{name}: payload");

        match InnoInstaller::from_bytes_with_passwords(&bytes, &[]) {
            Err(Error::PasswordRequired) => {}
            other => panic!(
                "{name}: empty: expected PasswordRequired, got {:?}",
                other.err()
            ),
        }
        match InnoInstaller::from_bytes_with_passwords(&bytes, &["nope"]) {
            Err(Error::WrongPassword) => {}
            other => panic!(
                "{name}: wrong: expected WrongPassword, got {:?}",
                other.err()
            ),
        }
        let unlocked = InnoInstaller::from_bytes_with_passwords(&bytes, &["nope", "test123"])
            .unwrap_or_else(|e| panic!("{name}: unlock with 'test123': {e}"));
        assert_eq!(
            unlocked.password_used(),
            Some("test123"),
            "{name}: password_used"
        );
        assert_eq!(
            payload(&unlocked),
            b"Inno test payload v1\n",
            "{name}: payload"
        );

        let v = inst.version();
        eras.insert(if v.at_least(6, 5, 0) {
            "6.5+"
        } else if v.at_least(6, 4, 0) {
            "6.4"
        } else {
            "legacy"
        });
    }
    assert_eq!(
        eras,
        BTreeSet::from(["6.4", "6.5+", "legacy"]),
        "tests/samples/password/ must cover every verifier location",
    );
}

/// Walks `tests/samples/full/`: whatever compiler built it, every `full.iss`
/// installer carries what the script states. Its license, an `AnsiString`
/// read after the header's whole `String` table, and its compiled `[Code]`
/// land where they belong only if every header field before them was read,
/// so a header field the walker misses or invents shows up here. A `-x64-`
/// build is a 64-bit (PE32+, x64) installer.
#[test]
fn full_samples_carry_what_full_iss_states() {
    let license = std::fs::read(format!(
        "{}/tests/samples/build/full/license.txt",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read build/full/license.txt");
    let mut tested = 0usize;
    for (name, path) in samples_in("full") {
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
        let inst =
            InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
        let header = inst
            .header()
            .unwrap_or_else(|| panic!("{name}: header missing"));
        for (field, value) in [
            (HeaderString::AppId, "InnoTestFull"),
            (HeaderString::AppName, "Inno Test (full)"),
            (HeaderString::AppVersion, "2.3.4.5"),
            (HeaderString::AppPublisher, "BinFlip"),
            (HeaderString::AppPublisherUrl, "https://example.invalid/"),
            (HeaderString::DefaultDirName, "{autopf}\\InnoTestFull"),
            (HeaderString::DefaultGroupName, "Inno Test Full"),
        ] {
            assert_eq!(header.string(field), Some(value), "{name}: {field:?}");
        }
        assert_eq!(
            inst.license_text(),
            Some(license.as_slice()),
            "{name}: license"
        );
        assert!(inst.info_before().is_none(), "{name}: no InfoBeforeFile");
        assert!(inst.info_after().is_none(), "{name}: no InfoAfterFile");
        let cc = inst
            .compiledcode()
            .unwrap_or_else(|| panic!("{name}: no compiled code"))
            .unwrap_or_else(|e| panic!("{name}: IFPS: {e}"));
        assert_eq!(
            cc.procs().len() as u32,
            cc.header().proc_count,
            "{name}: procs"
        );
        assert!(cc.header().proc_count > 0, "{name}: no procedures");
        // `CompiledCodeVersion` (marker 7.0.0.3+): the compiler's
        // SetupBinVersion, bit 31 set when the code targets a 64-bit Setup.
        // A 7.x fixture missing from this table fails here, by design.
        let bin_version = [("7_0_2", 0x0700_0200u32), ("7_1_1", 0x0701_0100)]
            .into_iter()
            .find(|(slug, _)| name.ends_with(&format!("-tool{slug}.exe")))
            .map(|(_, v)| {
                v | if name.contains("-x64-") {
                    0x8000_0000
                } else {
                    0
                }
            });
        assert_eq!(
            header.tail().compiled_code_version,
            bin_version,
            "{name}: CompiledCodeVersion",
        );
        assert_eq!(inst.languages().len(), 6, "{name}: languages");
        assert_eq!(inst.tasks().len(), 5, "{name}: tasks");
        // The wizard colours and styles each era stores, at the defaults
        // full.iss leaves them.
        let tail = header.tail();
        let v = inst.version();
        assert_eq!(
            tail.wizard_back_color.is_some(),
            v.at_least(6, 7, 0),
            "{name}: WizardBackColor"
        );
        assert_eq!(
            tail.wizard_image_back_color.is_some(),
            v.at_least(6, 5, 2) || !v.at_least(5, 5, 7),
            "{name}: WizardImageBackColor",
        );
        assert_eq!(
            tail.wizard_dark_style,
            v.at_least(6, 6, 0)
                .then_some(innospect::WizardDarkStyle::Light),
            "{name}: WizardDarkStyle",
        );
        assert_eq!(
            tail.wizard_light_control_styling,
            v.at_least(6, 7, 0)
                .then_some(innospect::WizardLightControlStyling::All),
            "{name}: WizardLightControlStyling",
        );
        // Every [Registry] value decodes to what the script writes; the
        // dword "Runs" = "0" is stored as text ("$0") from 4.1.4 on, the
        // qword "Big" = "$123456789" likewise, the binary "Blob" as one
        // character per byte. Key-only entries have no value.
        let values: BTreeSet<(String, String)> = inst
            .registry_entries()
            .iter()
            .map(|r| (r.value_name.clone(), r.value_text().into_owned()))
            .collect();
        let expected: BTreeSet<(String, String)> = [
            ("", "InnoTestFile"),
            ("", "Inno test file"),
            ("", r"{app}\app.exe,0"),
            ("", r#""{app}\app.exe" "%1""#),
            ("InstallDir", "{app}"),
            ("Runs", "0"),
            ("Version", "2.3.4.5"),
            ("Temp", r"%TEMP%\InnoTestFull"),
            ("Blob", "0102ff"),
            ("Lines", "one{break}two"),
            ("Big", "4886718345"),
            ("IfMissing", "first"),
            ("", ""),
            ("Stale", ""),
            ("Swap", "7"),
            ("Value", "new"),
            ("Bits", "64"),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .collect();
        assert_eq!(values, expected, "{name}: registry values");
        let runs = inst
            .registry_entries()
            .iter()
            .find(|r| r.value_name == "Runs")
            .unwrap_or_else(|| panic!("{name}: Runs"));
        assert_eq!(runs.data, RegistryData::Number(0), "{name}: Runs");
        let value = |value_name: &str| {
            inst.registry_entries()
                .iter()
                .find(|r| r.value_name == value_name)
                .unwrap_or_else(|| panic!("{name}: {value_name}"))
        };
        assert_eq!(
            value("Big").data,
            RegistryData::Number(0x1_2345_6789),
            "{name}: Big"
        );
        assert_eq!(
            value("Blob").data,
            RegistryData::Binary(vec![1, 2, 0xff]),
            "{name}: Blob"
        );
        assert_eq!(
            value("Lines").data,
            RegistryData::MultiString("one{break}two".into()),
            "{name}: Lines"
        );
        assert_eq!(value("Temp").hive, RegistryHive::Auto, "{name}: HKA");
        // `64bit` on "Bits", `32bit` on the launcher: from 7.0.0.3 a byte of
        // their own, before a flag each.
        let launcher = inst
            .run_entries()
            .iter()
            .find(|r| r.name.ends_with("app.exe"))
            .unwrap_or_else(|| panic!("{name}: launcher"));
        if v.at_least_4(7, 0, 0, 3) {
            assert_eq!(
                value("Bits").bitness,
                Some(innospect::Bitness::Bits64),
                "{name}: Bits"
            );
            assert_eq!(
                launcher.bitness,
                Some(innospect::Bitness::Bits32),
                "{name}: launcher"
            );
            assert_eq!(
                value("Runs").bitness,
                Some(innospect::Bitness::InstallDefault),
                "{name}: Runs"
            );
        } else {
            assert!(
                value("Bits")
                    .flags
                    .contains(&innospect::RegistryFlag::Bits64),
                "{name}: Bits"
            );
            assert!(
                launcher.flags.contains(&innospect::RunFlag::Bits32),
                "{name}: launcher"
            );
            assert_eq!(value("Bits").bitness, None, "{name}: Bits");
        }
        // What Setup does with each entry, by its subkey and value name:
        // the script has one of each kind.
        let kinds: std::collections::BTreeMap<(String, String), RegistryOpKind> = inst
            .registry_ops()
            .filter(|op| op.kind != RegistryOpKind::Write)
            .map(|op| {
                (
                    (op.source.subkey.clone(), op.source.value_name.clone()),
                    op.kind,
                )
            })
            .collect();
        let expected: std::collections::BTreeMap<(String, String), RegistryOpKind> = [
            (
                r"Software\InnoTestFull\Kinds",
                "IfMissing",
                RegistryOpKind::WriteIfMissing,
            ),
            (
                r"Software\InnoTestFull\Kinds\Empty",
                "",
                RegistryOpKind::CreateKey,
            ),
            (
                r"Software\InnoTestFull\Kinds",
                "Stale",
                RegistryOpKind::DeleteValue,
            ),
            (r"Software\InnoTestFull\Old", "", RegistryOpKind::DeleteKey),
            (
                r"Software\InnoTestFull\Kinds",
                "Swap",
                RegistryOpKind::ReplaceValue,
            ),
            (
                r"Software\InnoTestFull\Fresh",
                "Value",
                RegistryOpKind::ReplaceKey,
            ),
            (
                r"Software\InnoTestFull\Mark",
                "",
                RegistryOpKind::UninstallOnly,
            ),
        ]
        .into_iter()
        .map(|(k, n, kind)| ((k.to_owned(), n.to_owned()), kind))
        .collect();
        assert_eq!(kinds, expected, "{name}: registry ops");
        let arches = inst
            .architecture()
            .unwrap_or_else(|| panic!("{name}: no architectures"));
        assert_eq!(
            arches,
            [Architecture::Amd64].into_iter().collect(),
            "{name}: ArchitecturesAllowed",
        );

        let extracted: Vec<_> = inst
            .extract_files()
            .collect::<Result<_, _>>()
            .unwrap_or_else(|e| panic!("{name}: extract_files: {e}"));
        let total: usize = extracted.iter().map(|(_, b)| b.len()).sum();
        assert_eq!((extracted.len(), total), (9, 70730), "{name}: payload");
        // `nocompression`: its chunk is stored as is, and extracts.
        let (stored, stored_bytes) = extracted
            .iter()
            .find(|(f, _)| f.destination.ends_with("stored.txt"))
            .unwrap_or_else(|| panic!("{name}: stored.txt not installed"));
        let location = inst
            .file_location_for(stored)
            .unwrap_or_else(|| panic!("{name}: stored.txt location"));
        assert!(
            !location.flags.contains(&DataFlag::ChunkCompressed),
            "{name}: stored.txt compressed"
        );
        let readme = std::fs::read(format!(
            "{}/tests/samples/build/full/stored.txt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("read build/full/stored.txt");
        assert_eq!(stored_bytes, &readme, "{name}: stored.txt");
        let license_file = extracted
            .iter()
            .find(|(f, _)| f.destination.ends_with("license.txt"))
            .unwrap_or_else(|| panic!("{name}: license.txt not installed"));
        assert_eq!(license_file.1, license, "{name}: installed license.txt");

        // IMAGE_FILE_HEADER.Machine: 0x8664 for a 64-bit installer, 0x14c
        // for a 32-bit one.
        let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let machine = u16::from_le_bytes(bytes[pe + 4..pe + 6].try_into().unwrap());
        let expected = if name.contains("-x64-") {
            0x8664
        } else {
            0x14c
        };
        assert_eq!(machine, expected, "{name}: PE machine");
        tested += 1;
    }
    assert!(tested >= 2, "only {tested} full samples");
}

/// Walks `tests/samples/encrypted/` and exercises every
/// `enc-files-tool*.exe` (euFiles) and `enc-full-tool*.exe`
/// (euFull) sample end-to-end:
///   - no-password parse must surface `is_encrypted() == true`;
///     modern (6.5+) builds additionally surface the expected
///     `EncryptionMode`,
///   - empty-password trial must fail with `PasswordRequired`,
///   - wrong-password trial must fail with `WrongPassword`,
///   - `"test123"` must unlock and yield the canonical payload.
///
/// Fails unless both kinds are present.
#[test]
fn encrypted_samples_parse_and_unlock() {
    let samples = samples_in("encrypted");

    let mut tested_files = 0usize;
    let mut tested_full = 0usize;
    for (name, path) in samples {
        let expected = if name.starts_with("enc-files-") {
            EncryptionMode::Files
        } else if name.starts_with("enc-full-") {
            EncryptionMode::Full
        } else {
            continue; // ignore unrelated files (README, scripts/, etc.)
        };

        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: read: {e}"));
        let inst =
            InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
        assert!(inst.is_encrypted(), "{name}: should report encrypted");
        assert!(inst.has_password(), "{name}: should report a password");

        // Sample categories the existing matrix actually produces:
        //   - Modern (6.4+) password verifier present: `EncryptionInfo`
        //     surfaces with `mode == expected` when chunks are
        //     encrypted, or `mode == None` when the .iss only set
        //     `Password=`.
        //   - Legacy (pre-6.4): no `EncryptionInfo`. Verifier lives
        //     in `HeaderTail.legacy_password_*`.
        // In both cases `is_encrypted()` is true and the password
        // trial is exercised below.
        let actual_mode = if let Some(info) = inst.encryption() {
            assert!(info.kdf_iterations > 0, "{name}: zero kdf_iterations");
            if info.mode != EncryptionMode::None {
                assert_eq!(info.mode, expected, "{name}: encryption mode");
            }
            info.mode
        } else {
            // Pre-6.4 legacy path. Make sure the option flag is set
            // so callers can detect "this installer needs a password".
            assert!(
                inst.is_encrypted(),
                "{name}: legacy installer not flagged encrypted"
            );
            EncryptionMode::None
        };

        // Empty list -> PasswordRequired (the verifier exists either way).
        let r = InnoInstaller::from_bytes_with_passwords(&bytes, &[]);
        match r {
            Err(Error::PasswordRequired) => {}
            Err(e) => panic!("{name}: empty: expected PasswordRequired, got {e}"),
            Ok(_) => panic!("{name}: empty: expected PasswordRequired, got Ok"),
        }

        // Wrong password -> WrongPassword.
        let r = InnoInstaller::from_bytes_with_passwords(&bytes, &["nope"]);
        match r {
            Err(Error::WrongPassword) => {}
            Err(e) => panic!("{name}: wrong: expected WrongPassword, got {e}"),
            Ok(_) => panic!("{name}: wrong: expected WrongPassword, got Ok"),
        }

        // Right password unlocks.
        let unlocked = InnoInstaller::from_bytes_with_passwords(&bytes, &["test123"])
            .unwrap_or_else(|e| panic!("{name}: unlock with 'test123': {e}"));
        assert_eq!(
            unlocked.password_used(),
            Some("test123"),
            "{name}: password_used"
        );
        assert!(
            unlocked.is_encrypted(),
            "{name}: unlocked still flagged encrypted"
        );

        // For euFull, setup-0 must have decrypted to non-empty bytes.
        if actual_mode == EncryptionMode::Full {
            assert!(
                !unlocked.decompressed_setup0().is_empty(),
                "{name}: euFull setup-0 should decrypt to non-empty",
            );
            assert!(
                unlocked.header().is_some(),
                "{name}: euFull header should parse post-decrypt",
            );
        }

        let payload = unlocked
            .files()
            .iter()
            .find(|f| f.destination.ends_with("payload.txt"))
            .unwrap_or_else(|| panic!("{name}: payload.txt missing"));
        let mut reader = unlocked
            .extract(payload)
            .unwrap_or_else(|e| panic!("{name}: extract: {e}"));
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .unwrap_or_else(|e| panic!("{name}: read: {e}"));
        assert_eq!(buf, b"Inno test payload v1\n", "{name}: payload bytes");

        match expected {
            EncryptionMode::Files => tested_files = tested_files.saturating_add(1),
            EncryptionMode::Full => tested_full = tested_full.saturating_add(1),
            _ => {}
        }
    }
    assert!(
        tested_files > 0 && tested_full > 0,
        "tests/samples/encrypted/ needs both euFiles and euFull samples \
         (files={tested_files} full={tested_full})",
    );
    eprintln!("encrypted_samples_parse_and_unlock: files={tested_files} full={tested_full}");
}

/// **Every branch lands on an instruction of its own procedure.** IFPS
/// branches are deltas from the end of their instruction - the gotos, the
/// pop-and-gotos, `flaggoto` and the exception-handler sections alike - so
/// each resolves to an instruction boundary (or the end of the body) of the
/// procedure it sits in. Read as a procedure-local absolute, `flaggoto`
/// reached a boundary for 4 of the 14 in a real-world installer, and the
/// exception sections for none of the 4 in `code-tool6_4_3.exe`; the
/// population assertion keeps this from passing on an installer with no
/// branches.
#[test]
fn every_script_branch_lands_on_an_instruction() {
    let mut branches = 0usize;
    for name in [
        "code/code-tool6_4_3.exe",
        "full/full-tool6_4_0.exe",
        "full/full-tool6_1_0.exe",
    ] {
        let bytes = sample(name);
        let inst = InnoInstaller::from_bytes(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        let cc = inst
            .compiledcode()
            .expect("compiledcode() returns Some")
            .expect("IFPS Container parses");
        for proc_index in 0..(cc.procs().len() as u32) {
            let Some(disasm) = cc
                .disassemble(proc_index)
                .unwrap_or_else(|e| panic!("{name}: disassemble proc {proc_index}: {e}"))
            else {
                continue;
            };
            let starts: BTreeSet<u32> = disasm.instructions.iter().map(|i| i.offset).collect();
            let end = disasm.instructions.last().map_or(0, |i| i.next_offset);
            for instruction in &disasm.instructions {
                for target in instruction.branch_targets().into_iter().flatten() {
                    branches += 1;
                    assert!(
                        starts.contains(&target) || target == end,
                        "{name}: proc {proc_index} {:?} at {:#x} targets {target:#x}, \
                         no instruction of its procedure",
                        instruction.opcode,
                        instruction.offset,
                    );
                }
            }
        }
    }
    assert!(branches > 0, "the installers carry no branches");
}

/// **A compiled script's frames are what its declarations say.** Over every
/// procedure of `code-tool6_4_3.exe`: each declaration parses; each body's
/// stack height is consistent on every path, try blocks included; every call
/// to an internal procedure consumes exactly the slots its declaration names,
/// which is also how many the caller pops right after it (the two rules
/// `StackMap::call_slots` chooses between, checked against each other); and
/// every stack operand names a slot that exists where it is used - a result
/// or parameter below the frame base, a live local above it, made by one push
/// on every path to the use (`StackMap::slot_owner`).
#[test]
fn every_script_frame_matches_its_declaration() {
    let bytes = sample("code/code-tool6_4_3.exe");
    let inst = InnoInstaller::from_bytes(&bytes).expect("parses");
    let cc = inst.compiledcode().expect("code").expect("container");
    let (mut calls, mut operands, mut dll) = (0usize, 0usize, 0usize);
    for proc in cc.procs() {
        if let ProcKind::External(external) = &proc.kind {
            let decl = external
                .declaration()
                .expect("the compiler declares every import")
                .expect("parses");
            dll += usize::from(decl.dll.is_some());
        }
    }
    for index in 0..(cc.procs().len() as u32) {
        let Some(ProcKind::Internal(internal)) = cc.proc(index).map(|p| &p.kind) else {
            continue;
        };
        let signature = internal.signature().expect("declared").expect("parses");
        let disasm = cc.disassemble(index).unwrap().expect("internal");
        let map = disasm.stack_map().expect("consistent heights");
        for (at, instruction) in disasm.instructions.iter().enumerate() {
            let Some(height) = map.height_before(at) else {
                continue;
            };
            if let Opcode::Call { proc_no } = instruction.opcode
                && let Some(ProcKind::Internal(callee)) = cc.proc(proc_no).map(|p| &p.kind)
            {
                let declared = callee.signature().unwrap().unwrap().slot_count();
                let by_declaration = map.call_slots(&disasm, at, Some(declared));
                let by_pops = map.call_slots(&disasm, at, None);
                assert_eq!(by_declaration, by_pops, "call at {:#x}", instruction.offset);
                assert!(by_declaration.is_some());
                calls += 1;
            }
            let mut check = |var: VarRef| {
                let VarRef::Stack(offset) = var else {
                    return;
                };
                match signature.slot(offset) {
                    FrameSlot::Local(n) => {
                        assert!(
                            n <= height,
                            "s+{n} at {:#x} is above the stack ({height})",
                            instruction.offset
                        );
                        assert!(
                            map.slot_owner(at, n).is_some(),
                            "s+{n} at {:#x} has no one push that made it",
                            instruction.offset
                        );
                    }
                    FrameSlot::Result | FrameSlot::Param(_) => {}
                    other => panic!("{other:?} at {:#x}", instruction.offset),
                }
                operands += 1;
            };
            for var in instruction
                .opcode
                .operands()
                .into_iter()
                .flat_map(|operand| operand.var_refs())
            {
                check(var);
            }
        }
    }
    assert!(calls >= 6, "the script calls its procedures ({calls})");
    assert!(
        operands > 50,
        "the bodies address their frames ({operands})"
    );
    assert_eq!(dll, 1, "MessageBeep is a DLL import");
}

/// **The end of a `try` section continues where the runtime sends it.**
/// `code.iss`'s `Guarded` nests a `try..finally` in a `try..except`. Ending the
/// inner body runs its finally; ending the finally leaves the inner `try`;
/// ending the outer body leaves it, skipping the except section, which only an
/// exception reaches; ending the except section leaves too. Read as falling
/// through, the normal path ran the except code and returned -1.
#[test]
fn a_try_section_ends_where_the_runtime_sends_it() {
    let bytes = sample("code/code-tool6_4_3.exe");
    let inst = InnoInstaller::from_bytes(&bytes).expect("parses");
    let cc = inst.compiledcode().expect("code").expect("container");
    let guarded = (0..cc.procs().len() as u32)
        .find(|index| {
            matches!(cc.proc(*index).map(|p| &p.kind),
                Some(ProcKind::Internal(internal)) if internal.export_name == Some(b"GUARDED"))
        })
        .expect("GUARDED is compiled");
    let disasm = cc.disassemble(guarded).unwrap().expect("internal");
    let exits: Vec<(u32, Option<u32>)> = disasm
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction)| matches!(instruction.opcode, Opcode::PopExceptionHandler { .. }))
        .map(|(index, instruction)| (instruction.offset, disasm.handler_exit(index)))
        .collect();
    assert_eq!(
        exits,
        [
            (0x97c, Some(0x97e)),
            (0x98e, Some(0x990)),
            (0x990, Some(0x9a3)),
            (0x9a1, Some(0x9a3)),
        ],
        "inner body to its finally, finally out, outer body past the except"
    );
}
