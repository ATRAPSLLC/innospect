//! Inno Setup installer dump tool.
//!
//! Usage:
//!   `cargo run --example dump -- <setup.exe>`

use std::{env, fs, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("usage: dump <setup.exe>");
        process::exit(1);
    };

    let data = fs::read(path).unwrap_or_else(|e| {
        eprintln!("error reading {path}: {e}");
        process::exit(1);
    });

    let parse = || {
        innospect::InnoInstaller::from_bytes(&data).unwrap_or_else(|e| {
            eprintln!("error parsing Inno Setup installer: {e}");
            process::exit(1);
        })
    };
    // A disk-spanning installer's files are in slice files beside it, under
    // the names Setup looks for.
    let probe = parse();
    let dir = std::path::Path::new(path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("setup.exe");
    let slice_names: Vec<String> = (0..probe.slice_count())
        .map(|i| probe.slice_file_name(i, file_name))
        .collect();
    let slice_data: Vec<Vec<u8>> = slice_names
        .iter()
        .map_while(|name| fs::read(dir.join(name)).ok())
        .collect();
    let slice_refs: Vec<&[u8]> = slice_data.iter().map(Vec::as_slice).collect();
    let installer = if slice_refs.is_empty() {
        parse()
    } else {
        parse().with_slices(&slice_refs).unwrap_or_else(|e| {
            eprintln!("error reading the slice files: {e}");
            process::exit(1);
        })
    };
    drop(probe);

    let v = installer.version();
    println!("== Identification ==");
    println!("  marker:        {:?}", v.marker_str());
    println!("  version:       {}.{}.{}.{}", v.a, v.b, v.c, v.d);
    println!("  flags:         {:?}", v.flags);
    println!("  variant:       {:?}", installer.variant());
    println!(
        "  setupldr:      {:?} (locator: {:?})",
        installer.setup_ldr_family(),
        installer.pe_locator_mode(),
    );

    let ot = installer.offset_table();
    println!();
    println!("== Offset table ==");
    println!("  generation:    {:?}", ot.source.generation);
    println!("  version_id:    {}", ot.version_id);
    println!("  start:         {:#x}", ot.source.start);
    println!("  Offset0:       {:#x}", ot.offset_setup0);
    println!("  Offset1:       {:#x}", ot.offset_setup1);
    println!("  OffsetEXE:     {:#x}", ot.offset_exe);
    println!("  TotalSize:     {} bytes", ot.total_size,);

    println!();
    println!("== Setup-0 ==");
    println!("  compression:   {:?}", installer.compression());
    println!(
        "  encryption:    {:?}",
        installer.encryption().map(|e| e.mode)
    );
    let setup0 = installer.decompressed_setup0();
    println!("  decompressed:  {} bytes", setup0.len());
    if !setup0.is_empty() {
        let preview_len = 128.min(setup0.len());
        let preview: Vec<u8> = setup0
            .iter()
            .take(preview_len)
            .map(|&b| if (32..127).contains(&b) { b } else { b'.' })
            .collect();
        println!("  preview:       {:?}", String::from_utf8_lossy(&preview),);
    }

    if let Some(header) = installer.header() {
        println!();
        println!("== Setup header ==");
        println!("  AppName:        {:?}", header.app_name().unwrap_or(""));
        println!("  AppId:          {:?}", header.app_id().unwrap_or(""));
        println!("  AppVersion:     {:?}", header.app_version().unwrap_or(""));
        println!(
            "  AppPublisher:   {:?}",
            header.app_publisher().unwrap_or(""),
        );
        println!(
            "  DefaultDirName: {:?}",
            header.default_dir_name().unwrap_or(""),
        );

        let counts = header.counts();
        println!();
        println!("== Entry counts ==");
        println!("  languages:        {}", counts.languages);
        println!("  custom_messages:  {}", counts.custom_messages);
        println!("  permissions:      {}", counts.permissions);
        println!("  types:            {}", counts.types);
        println!("  components:       {}", counts.components);
        println!("  tasks:            {}", counts.tasks);
        println!("  directories:      {}", counts.directories);
        if let Some(n) = counts.iss_sig_keys {
            println!("  iss_sig_keys:     {n}");
        }
        println!("  files:            {}", counts.files);
        println!("  file_locations:   {}", counts.file_locations);
        println!("  icons:            {}", counts.icons);
        println!("  ini_entries:      {}", counts.ini_entries);
        println!("  registry:         {}", counts.registry);
        println!("  install_deletes:  {}", counts.install_deletes);
        println!("  uninstall_deletes:{}", counts.uninstall_deletes,);
        println!("  run:              {}", counts.run);
        println!("  uninstall_run:    {}", counts.uninstall_run);

        let license_len = installer
            .header()
            .and_then(|h| h.ansi(innospect::HeaderAnsi::LicenseText))
            .map_or(0, <[u8]>::len);
        let info_before_len = installer
            .header()
            .and_then(|h| h.ansi(innospect::HeaderAnsi::InfoBeforeText))
            .map_or(0, <[u8]>::len);
        let info_after_len = installer
            .header()
            .and_then(|h| h.ansi(innospect::HeaderAnsi::InfoAfterText))
            .map_or(0, <[u8]>::len);
        let compiled_len = installer
            .header()
            .and_then(|h| h.ansi(innospect::HeaderAnsi::CompiledCodeText))
            .map_or(0, <[u8]>::len);
        println!();
        println!("== Embedded blobs ==");
        println!("  license_text:        {license_len} bytes");
        println!("  info_before:         {info_before_len} bytes");
        println!("  info_after:          {info_after_len} bytes");
        println!("  compiled_code_text:  {compiled_len} bytes");
        for kind in [
            innospect::WizardImageKind::Large,
            innospect::WizardImageKind::Small,
            innospect::WizardImageKind::Back,
        ] {
            let sizes: Vec<usize> = installer
                .wizard_images(kind)
                .iter()
                .map(|i| i.len())
                .collect();
            let dark = installer
                .wizard_images_dark(kind)
                .map(|d| format!(", dark {:?}", d.iter().map(|i| i.len()).collect::<Vec<_>>()))
                .unwrap_or_default();
            println!("  wizard images ({kind}): {sizes:?}{dark}");
        }
        for (label, dll) in [
            ("decompressor DLL", installer.decompressor_dll()),
            ("decryption DLL", installer.decryption_dll()),
            ("7-Zip DLL", installer.seven_zip_dll()),
        ] {
            if let Some(dll) = dll {
                println!("  {label}: {} bytes", dll.len());
            }
        }

        let tail = header.tail();
        let tail_size = header
            .records_offset()
            .saturating_sub(header.tail_start_offset());
        println!();
        println!("== Fixed numeric tail ({tail_size} bytes) ==");
        println!(
            "  MinVersion (Win):       {}.{} build {}",
            tail.windows_version_range.min.windows.major,
            tail.windows_version_range.min.windows.minor,
            tail.windows_version_range.min.windows.build,
        );
        println!(
            "  OnlyBelowVersion (Win): {}.{} build {}",
            tail.windows_version_range.only_below.windows.major,
            tail.windows_version_range.only_below.windows.minor,
            tail.windows_version_range.only_below.windows.build,
        );
        println!("  WizardStyle:            {:?}", tail.wizard_style);
        println!(
            "  WizardSizePercent:      ({}, {})",
            tail.wizard_size_percent_x, tail.wizard_size_percent_y,
        );
        println!("  PrivilegesRequired:     {:?}", tail.privileges_required);
        println!("  CompressMethod:         {:?}", tail.compress_method);
        println!(
            "  ExtraDiskSpaceRequired: {} bytes",
            tail.extra_disk_space_required,
        );
        println!(
            "  UninstallDisplaySize:   {} bytes",
            tail.uninstall_display_size,
        );
        println!("  Options ({} set):", tail.options.len());
        let mut sorted: Vec<_> = tail.options.iter().collect();
        sorted.sort_by_key(|o| format!("{o:?}"));
        for opt in sorted {
            println!("    - {opt:?}");
        }
    }

    println!();
    println!("== Data block (file-location records) ==");
    let data = installer.data_block();
    println!("  decompressed:  {} bytes", data.len());

    println!();
    println!(
        "== Records (3c lightweight) - languages={} messages={} permissions={} types={} components={} tasks={} ==",
        installer.languages().len(),
        installer.messages().len(),
        installer.permissions().len(),
        installer.types().len(),
        installer.components().len(),
        installer.tasks().len(),
    );
    for (i, l) in installer.languages().iter().enumerate().take(5) {
        let name = l.name_string().unwrap_or_default();
        let pretty = l.language_name_string().unwrap_or_default();
        println!(
            "  language[{i}]: id={:#06x} cp={:?} name={:?} ({:?})",
            l.language_id, l.codepage, name, pretty,
        );
    }
    if installer.languages().len() > 5 {
        println!(
            "    … {} more",
            installer.languages().len().saturating_sub(5)
        );
    }
    for (i, t) in installer.tasks().iter().enumerate().take(8) {
        println!(
            "  task[{i}]: name={:?} flags={:?} level={}",
            t.name, t.flags, t.level,
        );
    }

    println!();
    println!(
        "== Records (3d heavy) - dirs={} files={} icons={} ini={} reg={} ins_del={} unins_del={} run={} unins_run={} file_loc={} ==",
        installer.directories().len(),
        installer.files().len(),
        installer.icons().len(),
        installer.ini_entries().len(),
        installer.registry_entries().len(),
        installer.install_deletes().len(),
        installer.uninstall_deletes().len(),
        installer.run_entries().len(),
        installer.uninstall_runs().len(),
        installer.file_locations().len(),
    );
    for (i, f) in installer.files().iter().enumerate().take(4) {
        println!(
            "  file[{i}]: src={:?} dst={:?} loc={} ext_size={} flags={}",
            f.source,
            f.destination,
            f.location_index,
            f.external_size,
            f.flags.len(),
        );
    }
    if installer.files().len() > 4 {
        println!("    … {} more", installer.files().len().saturating_sub(4));
    }
    for (i, r) in installer.registry_entries().iter().enumerate() {
        println!(
            "  reg[{i}]: hive={:?} subkey={:?} name={:?} type={:?}",
            r.hive, r.subkey, r.value_name, r.value_type,
        );
    }
    for (i, ic) in installer.icons().iter().enumerate().take(4) {
        println!(
            "  icon[{i}]: name={:?} target={:?} args={:?}",
            ic.name, ic.filename, ic.parameters,
        );
    }
    for (i, r) in installer.run_entries().iter().enumerate().take(4) {
        println!(
            "  run[{i}]: cmd={:?} args={:?} wait={:?} flags={:?}",
            r.name, r.parameters, r.wait, r.flags,
        );
    }
    for (i, d) in installer.file_locations().iter().enumerate().take(2) {
        println!(
            "  file_loc[{i}]: orig_size={} compressed={} chunk_offset={} flags={:?}",
            d.original_size, d.chunk_compressed_size, d.chunk_sub_offset, d.flags,
        );
    }

    for (i, r) in installer.uninstall_runs().iter().enumerate().take(3) {
        println!(
            "  uninstall_run[{i}]: cmd={:?} args={:?}",
            r.name, r.parameters
        );
    }
    for (i, d) in installer.directories().iter().enumerate().take(3) {
        println!("  dir[{i}]: {:?} flags={:?}", d.name, d.flags);
    }
    for (i, e) in installer.ini_entries().iter().enumerate().take(3) {
        println!(
            "  ini[{i}]: {:?} [{}] {}={:?}",
            e.inifile, e.section, e.key, e.value
        );
    }
    for (i, d) in installer.install_deletes().iter().enumerate().take(3) {
        println!("  install_delete[{i}]: {:?} {:?}", d.name, d.target_type);
    }
    for (i, d) in installer.uninstall_deletes().iter().enumerate().take(3) {
        println!("  uninstall_delete[{i}]: {:?} {:?}", d.name, d.target_type);
    }
    for (i, t) in installer.types().iter().enumerate().take(3) {
        println!("  type[{i}]: {:?} {:?}", t.name, t.description);
    }
    for (i, c) in installer.components().iter().enumerate().take(3) {
        println!("  component[{i}]: {:?} types={:?}", c.name, c.types);
    }
    println!(
        "  messages: {}  permissions: {}  issig keys: {}",
        installer.messages().len(),
        installer.permissions().len(),
        installer.iss_sig_keys().len()
    );

    println!();
    println!("== Analysis ==");
    if let Some(arches) = installer.architecture() {
        let mut names: Vec<_> = arches.iter().map(|a| a.as_str()).collect();
        names.sort_unstable();
        println!("  architectures: {names:?}");
    }
    for cmd in installer.exec_commands().take(5) {
        println!(
            "  exec ({}): {:?} {:?}",
            cmd.phase,
            cmd.filename(),
            cmd.parameters()
        );
    }
    for op in installer.registry_ops().take(5) {
        println!(
            "  registry {}: {} {:?} {:?}",
            op.kind, op.source.hive, op.source.subkey, op.source.value_name
        );
    }
    for shortcut in installer.shortcuts().take(5) {
        println!(
            "  shortcut {:?} -> {:?}",
            shortcut.icon.name,
            shortcut.target.map(|f| f.destination.as_str())
        );
    }
    match installer.compiledcode() {
        Some(Ok(code)) => {
            let procs = code.procs();
            println!("  [Code]: {} procs", procs.len());
            for proc in procs.iter().take(12) {
                if let innospect::pascalscript::ProcKind::External(ext) = &proc.kind {
                    let name = String::from_utf8_lossy(ext.name);
                    let what = installer.inno_api_description(&name).unwrap_or("");
                    println!("    import {name}: {what}");
                }
            }
        }
        Some(Err(e)) => println!("  [Code]: {e}"),
        None => {}
    }

    if installer.uses_slice_files() {
        println!();
        println!("== Slice files ==");
        for (i, name) in slice_names.iter().enumerate() {
            let found = slice_data.get(i).map_or(0, Vec::len);
            println!("  slice[{i}]: {name} ({found} bytes)");
        }
    }

    println!();
    println!("== Extraction ==");
    let mut extracted = 0usize;
    let mut total_bytes: u64 = 0;
    let mut errors = 0usize;
    for f in installer.files() {
        if f.location_index == u32::MAX {
            continue;
        }
        match installer.extract_to_vec(f) {
            Ok(bytes) => {
                total_bytes = total_bytes.saturating_add(bytes.len() as u64);
                extracted = extracted.saturating_add(1);
            }
            Err(e) => {
                errors = errors.saturating_add(1);
                if errors <= 3 {
                    println!("  ! {:?}: {e}", f.destination);
                }
            }
        }
    }
    println!("  extracted: {extracted} files / {total_bytes} bytes / {errors} errors");
}
