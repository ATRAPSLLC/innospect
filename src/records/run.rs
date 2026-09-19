//! `TSetupRunEntry` - `[Run]` / `[UninstallRun]` directive entry.
//! The same struct serves both directives.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupRunEntry = packed record
//!     Name, Parameters, WorkingDir, RunOnceID,
//!         StatusMsg, Verb, Description: AnsiString;
//!     [ItemConditions]
//!     [WindowsVersionRange]
//!     ShowCmd: Integer;        // since 1.3.24
//!     Wait: TSetupRunWait;     // u8 enum
//!     Options: TSetupRunOptions;
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/run.cpp`.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::{item::ItemBase, windows::Bitness},
    util::{encoding::read_setup_string, read::Reader},
    version::Version,
};

/// `TSetupRunWait` - how to wait for the launched process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunWait {
    /// `wuWaitUntilTerminated`.
    UntilTerminated,
    /// `wuNoWait`.
    NoWait,
    /// `wuWaitUntilIdle`.
    UntilIdle,
}

stable_name_enum!(RunWait, {
    Self::UntilTerminated => "until_terminated",
    Self::NoWait => "no_wait",
    Self::UntilIdle => "until_idle",
});

/// `TSetupRunOptions` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum RunFlag {
    ShellExec,
    SkipIfDoesntExist,
    PostInstall,
    Unchecked,
    SkipIfSilent,
    SkipIfNotSilent,
    HideWizard,
    Bits32,
    Bits64,
    RunAsOriginalUser,
    DontLogParameters,
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

/// Parsed `TSetupRunEntry`.
#[derive(Clone, Debug)]
pub struct RunEntry {
    /// `Filename:` directive (Inno calls this `Name` internally).
    pub name: String,
    /// `Parameters:` directive.
    pub parameters: String,
    /// `WorkingDir:` directive.
    pub working_dir: String,
    /// `RunOnceID:` directive (1.3.9+).
    pub run_once_id: String,
    /// `StatusMsg:` directive (2.0.2+).
    pub status_message: String,
    /// `Verb:` directive - ShellExecute verb (5.1.13+).
    pub verb: String,
    /// `Description:` directive (2.0.0+ or any ISX).
    pub description: String,
    /// `OnLog:` directive (6.7.0+). Empty on older versions.
    pub on_log: String,
    /// Shared conditions + Windows version range.
    pub item: ItemBase,
    /// `ShowCmd:` directive (1.3.24+). 0 on older versions.
    pub show_command: i32,
    /// Decoded `Wait` enum.
    pub wait: Option<RunWait>,
    /// Raw `Wait` byte.
    pub wait_raw: u8,
    /// `Bitness` enum (6.7.0+; replaces `Bits32`/`Bits64` flag bits).
    pub bitness: Option<Bitness>,
    /// Raw bitness byte (or 0 when absent).
    pub bitness_raw: u8,
    /// Decoded options.
    pub flags: HashSet<RunFlag>,
    /// Raw `Options` bytes (variable byte width per version).
    pub options_raw: Vec<u8>,
}

impl RunEntry {
    /// Reads one `TSetupRunEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
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
        let on_log = if version.at_least(7, 0, 0) {
            read_setup_string(reader, version, "Run.OnLog")?
        } else {
            String::new()
        };

        let item = ItemBase::read(reader, version)?;

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
        let raw = reader.set_bytes(table.len(), true, "Run.Options")?;
        let flags = super::decode_packed_flags(&raw, &table);

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
