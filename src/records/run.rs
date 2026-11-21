//! `TSetupRunEntry`: one `[Run]` or `[UninstallRun]` entry, a program Setup
//! runs after installing (`[Run]`) or the uninstaller runs before removing
//! files (`[UninstallRun]`). Both sections share the record; the installer
//! keeps them in separate lists ([`crate::InnoInstaller::run_entries`],
//! [`crate::InnoInstaller::uninstall_runs`]).
//!
//! On disk (`SECompressedBlockWrite`): the string fields in the order below,
//! each a u32 byte length and its data (UTF-16LE in Unicode builds), then
//! the conditions and Windows version range of [`ItemBase`], `ShowCmd`,
//! `Wait`, from SetupID 7.0.0.3 a `Bitness` byte, and the `Options` set.
//! Which fields exist depends on the version; each field says when it
//! appeared. Reader reference: innoextract `setup/run.cpp`; every layout is
//! checked against upstream's own declarations by the `crate::upstream`
//! tests.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::{
        item::{ItemBase, ItemConditions},
        windows::{Bitness, WindowsVersionRange},
    },
    util::{
        encoding::read_setup_string,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// `Wait`: whether Setup waits for the launched program before going on
/// (`TSetupRunEntry.Wait`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunWait {
    /// `rwWaitUntilTerminated`: wait until the process has exited. The
    /// default, or the `waituntilterminated` flag.
    UntilTerminated,
    /// `rwNoWait`: start the process and go on (`nowait` flag).
    NoWait,
    /// `rwWaitUntilIdle`: wait until the process is idle, waiting for user
    /// input, via `WaitForInputIdle` (`waituntilidle` flag).
    UntilIdle,
}

stable_name_enum!(RunWait, {
    Self::UntilTerminated => "until_terminated",
    Self::NoWait => "no_wait",
    Self::UntilIdle => "until_idle",
});

/// `TSetupRunEntry.Options`: the entry's `Flags:` that have a bit of their
/// own. `runhidden`, `runminimized` and `runmaximized` set
/// [`RunEntry::show_command`] instead, and `nowait`, `waituntilidle` and
/// `waituntilterminated` set [`RunEntry::wait`].
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunFlag {
    /// `roShellExec` (`shellexec`): open `Filename` with `ShellExecute`, so
    /// it may be a document, folder or URL rather than an executable.
    ShellExec,
    /// `roSkipIfDoesntExist` (`skipifdoesntexist`): no error when `Filename`
    /// does not exist (1.3.9+).
    SkipIfDoesntExist,
    /// `roPostInstall` (`postinstall`, `[Run]` only): show a checkbox on the
    /// Setup Completed page; the user chooses whether the entry runs
    /// (2.0.0+).
    PostInstall,
    /// `roUnchecked` (`unchecked`): the `postinstall` checkbox starts
    /// unchecked (2.0.0+).
    Unchecked,
    /// `roSkipIfSilent` (`skipifsilent`): skip the entry in a silent
    /// install (2.0.0+).
    SkipIfSilent,
    /// `roSkipIfNotSilent` (`skipifnotsilent`): run the entry only in a
    /// silent install (2.0.0+).
    SkipIfNotSilent,
    /// `roHideWizard` (`hidewizard`): hide the wizard while the program runs
    /// (2.0.8+).
    HideWizard,
    /// `roRun32Bit` (`32bit`): run the program 32-bit. From SetupID 7.0.0.3
    /// bitness is [`RunEntry::bitness`] instead (5.1.10 to 7.0.0.2).
    Bits32,
    /// `roRun64Bit` (`64bit`): run the program 64-bit (5.1.10 to 7.0.0.2;
    /// then [`RunEntry::bitness`]).
    Bits64,
    /// `roRunAsOriginalUser` (`runasoriginaluser`, `[Run]` only): run with
    /// the credentials of the user who started Setup, normally not elevated
    /// (5.2.0+).
    RunAsOriginalUser,
    /// `roDontLogParameters` (`dontlogparameters`): keep the command line
    /// out of the Setup log (6.1.0+).
    DontLogParameters,
    /// `roLogOutput` (`logoutput`): write the program's output to the Setup
    /// log, or pass each line to the `OnLog` procedure (6.3.0+).
    LogOutput,
}

stable_flag_enum!(RunFlag, {
    ShellExec => "shell_exec",
    SkipIfDoesntExist => "skip_if_doesnt_exist",
    PostInstall => "post_install",
    Unchecked => "unchecked",
    SkipIfSilent => "skip_if_silent",
    SkipIfNotSilent => "skip_if_not_silent",
    HideWizard => "hide_wizard",
    Bits32 => "bits32",
    Bits64 => "bits64",
    RunAsOriginalUser => "run_as_original_user",
    DontLogParameters => "dont_log_parameters",
    LogOutput => "log_output",
});

/// One `[Run]` / `[UninstallRun]` entry (`TSetupRunEntry`). A string field
/// the version does not have is empty.
#[derive(Clone, Debug)]
pub struct RunEntry {
    /// `Filename:` (Pascal `Name`): the program to run, or with
    /// [`RunFlag::ShellExec`] the document, folder or URL to open. May
    /// contain constants such as `{app}`, unexpanded.
    pub name: String,
    /// `Parameters:`: the command-line arguments, unexpanded.
    pub parameters: String,
    /// `WorkingDir:`: the initial current directory; empty means the
    /// directory of `Filename`.
    pub working_dir: String,
    /// `RunOnceId:` (`[UninstallRun]`): when the application was installed
    /// several times, an entry with this ID runs only once at uninstall
    /// (1.3.9+).
    pub run_once_id: String,
    /// `StatusMsg:`: the wizard's status text while the program runs; empty
    /// means "Finishing installation..." (2.0.2+).
    pub status_message: String,
    /// `Verb:`: the `ShellExecute` verb with [`RunFlag::ShellExec`], such as
    /// `open` or `print`; empty means the file type's default (5.1.13+).
    pub verb: String,
    /// `Description:` (`[Run]`): the label of the `postinstall` checkbox
    /// (2.0.0+, or any ISX build).
    pub description: String,
    /// `OnLog:` (`[Run]`): the `[Code]` procedure called with each line of
    /// the program's output, with [`RunFlag::LogOutput`] (SetupID 7.0.0.1+).
    pub on_log: String,
    /// `Components:`, `Tasks:`, `Languages:`, `Check:`, `BeforeInstall:`,
    /// `AfterInstall:` and `MinVersion:` / `OnlyBelowVersion:`.
    pub item: ItemBase,
    /// `ShowCmd`: the `ShowWindow` command the program starts with:
    /// `SW_SHOWNORMAL` (1) by default, `SW_SHOWMINNOACTIVE` (7) with
    /// `runminimized`, `SW_SHOWMAXIMIZED` (3) with `runmaximized`, `SW_HIDE`
    /// (0) with `runhidden` (1.3.24+; 0 before).
    pub show_command: i32,
    /// `Wait`, decoded; `None` for a value this crate does not know, which
    /// [`Self::wait_raw`] keeps.
    pub wait: Option<RunWait>,
    /// `Wait` as stored.
    pub wait_raw: u8,
    /// `Bitness`: whether the program runs 32- or 64-bit (SetupID 7.0.0.3+,
    /// replacing [`RunFlag::Bits32`] / [`RunFlag::Bits64`]). `None` before,
    /// or for a value this crate does not know.
    pub bitness: Option<Bitness>,
    /// `Bitness` as stored; 0 when the version has no such byte.
    pub bitness_raw: u8,
    /// `Options`, decoded.
    pub flags: HashSet<RunFlag>,
    /// `Options` as stored: the set's bytes, whose size grows with the
    /// number of flags the version defines.
    pub options_raw: Vec<u8>,
}

impl FromReader for RunEntry {
    /// Reads one `TSetupRunEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let name = read_setup_string(reader, version, "Run.Name")?;
        let parameters = read_setup_string(reader, version, "Run.Parameters")?;
        let working_dir = read_setup_string(reader, version, "Run.WorkingDir")?;
        let run_once_id = if version.at_least(1, 3, 9) {
            read_setup_string(reader, version, "Run.RunOnceID")?
        } else {
            String::new()
        };
        let status_message = if version.at_least(2, 0, 2) {
            read_setup_string(reader, version, "Run.StatusMsg")?
        } else {
            String::new()
        };
        let verb = if version.at_least(5, 1, 13) {
            read_setup_string(reader, version, "Run.Verb")?
        } else {
            String::new()
        };
        let description = if version.at_least(2, 0, 0) || version.is_isx() {
            read_setup_string(reader, version, "Run.Description")?
        } else {
            String::new()
        };

        // Format 7.0.0+ inlined `OnLog` between Description and the
        // condition strings (issrc commit `5a0ee1d4`, 2026-03-02 -
        // the same commit that bumped SetupID to `7.0.0.x`).
        // `OnLog` is the last string, after the condition strings and
        // before the version range, so `ItemBase` is read in its two parts.
        let conditions = ItemConditions::read(reader, version)?;
        let on_log = if version.at_least(7, 0, 0) {
            read_setup_string(reader, version, "Run.OnLog")?
        } else {
            String::new()
        };
        let item = ItemBase {
            conditions,
            winver: WindowsVersionRange::read(reader, version)?,
        };

        let show_command = if version.at_least(1, 3, 24) {
            reader.i32_le("Run.ShowCmd")?
        } else {
            0
        };

        let wait_raw = reader.u8("Run.Wait")?;
        let wait = RunWait::from_raw(wait_raw);

        // SetupBinVersion 7.0.0.3 (issrc commit `3553e3b7`) adds a
        // Bitness byte between `Wait` and `Options`. 7.0.0.0..7.0.0.2
        // still use the legacy `ro32Bit` / `ro64Bit` flag bits.
        let (bitness, bitness_raw) = if version.at_least_4(7, 0, 0, 3) {
            let raw = reader.u8("Run.Bitness")?;
            (Bitness::from_raw(raw), raw)
        } else {
            (None, 0)
        };

        let table = run_flag_table(version);
        let raw = reader.set_bytes(table.len(), version, "Run.Options")?;
        let flags = crate::util::flags::decode_packed_flags(&raw, &table);

        Ok(Self {
            name,
            parameters,
            working_dir,
            run_once_id,
            status_message,
            verb,
            description,
            on_log,
            item,
            show_command,
            wait,
            wait_raw,
            bitness,
            bitness_raw,
            flags,
            options_raw: raw,
        })
    }
}

impl RunWait {
    /// Resolves the persisted on-disk discriminant byte back to a [`RunWait`],
    /// or [`None`] for an unknown value. Used to re-derive the label from a
    /// stored `wait_raw`.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::UntilTerminated),
            1 => Some(Self::NoWait),
            2 => Some(Self::UntilIdle),
            _ => None,
        }
    }
}

fn run_flag_table(version: &Version) -> Vec<RunFlag> {
    let mut t = Vec::new();
    if version.at_least(1, 2, 3) {
        t.push(RunFlag::ShellExec);
    }
    if version.at_least(1, 3, 9) || (version.is_isx() && version.at_least(1, 3, 8)) {
        t.push(RunFlag::SkipIfDoesntExist);
    }
    if version.at_least(2, 0, 0) {
        t.push(RunFlag::PostInstall);
        t.push(RunFlag::Unchecked);
        t.push(RunFlag::SkipIfSilent);
        t.push(RunFlag::SkipIfNotSilent);
    }
    if version.at_least(2, 0, 8) {
        t.push(RunFlag::HideWizard);
    }
    // SetupBinVersion 7.0.0.3 (issrc commit `3553e3b7`) moves the
    // bitness from these flag bits into a separate `Bitness` byte.
    // 7.0.0.0..7.0.0.2 still keep the named flags.
    if version.at_least(5, 1, 10) && !version.at_least_4(7, 0, 0, 3) {
        t.push(RunFlag::Bits32);
        t.push(RunFlag::Bits64);
    }
    if version.at_least(5, 2, 0) {
        t.push(RunFlag::RunAsOriginalUser);
    }
    if version.at_least(6, 1, 0) {
        t.push(RunFlag::DontLogParameters);
    }
    if version.at_least(6, 3, 0) {
        t.push(RunFlag::LogOutput);
    }
    t
}
