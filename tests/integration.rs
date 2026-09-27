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
    Architecture, Compression, EncryptionMode, Error, HeaderAnsi, HeaderOption, HeaderString,
    InnoInstaller, SetupLdrFamily, Variant,
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
    // Eight payload files and the uninstaller; each payload file its own
    // location. Four icons, seven registry values, and two run entries: the
    // launcher, and the "view the README" entry `isreadme` adds.
    assert_eq!(counts.languages, 6);
    assert_eq!(counts.files, 9);
    assert_eq!(counts.file_locations, 8);
    assert_eq!(counts.icons, 4);
    assert_eq!(counts.registry, 7);
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
    assert_eq!(inst.files().len(), 9);
    assert_eq!(inst.icons().len(), 4);
    assert_eq!(inst.ini_entries().len(), 0);
    assert_eq!(inst.registry_entries().len(), 7);
    assert_eq!(inst.install_deletes().len(), 0);
    assert_eq!(inst.uninstall_deletes().len(), 0);
    assert_eq!(inst.run_entries().len(), 2);
    assert_eq!(inst.uninstall_runs().len(), 0);
    assert_eq!(inst.file_locations().len(), 8);

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
    assert_eq!(extracted, 8);
    // app.exe 65536 + license.txt 1852 + readme.txt 21 + doc1..5, each
    // 22 bytes repeated 10 * i times: 220 * (1 + 2 + 3 + 4 + 5) = 3300.
    assert_eq!(total, 70_709);
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
    assert_eq!(counts.files, 9);
    assert_eq!(counts.file_locations, 8);
    assert_eq!(counts.icons, 4);
    assert_eq!(counts.registry, 7);
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
    assert_eq!(inst.files().len(), 9);
    assert_eq!(inst.icons().len(), 4);
    assert_eq!(inst.registry_entries().len(), 7);
    assert_eq!(inst.run_entries().len(), 2);
    assert_eq!(inst.file_locations().len(), 8);

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
    // The script writes one value under LocalMachine.
    let hklm_count = inst
        .registry_entries()
        .iter()
        .filter(|r| matches!(r.hive, innospect::RegistryHive::LocalMachine))
        .count();
    assert_eq!(hklm_count, 1, "HKLM entries");

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
    assert_eq!(extracted, 8);
}

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
            for suffix in suffixes {
                expected.insert(match script {
                    "plain" => format!("plain/plain-tool{slug}{suffix}.exe"),
                    "encrypted" => format!("encrypted/enc-files-tool{slug}{suffix}.exe"),
                    "encrypted-full" => format!("encrypted/enc-full-tool{slug}{suffix}.exe"),
                    other => format!("{other}/{other}-tool{slug}{suffix}.exe"),
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

        let header = inst
            .header()
            .unwrap_or_else(|| panic!("{name}: header missing"));
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
/// or parameter below the frame base, a live local above it.
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
                    FrameSlot::Local(n) => assert!(
                        n <= height,
                        "s+{n} at {:#x} is above the stack ({height})",
                        instruction.offset
                    ),
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
