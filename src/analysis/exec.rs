//! Install + uninstall command execution unified.
//!
//! Inno Setup expresses post-install command execution through two
//! parallel record streams: `[Run]` for install-time commands and
//! `[UninstallRun]` for commands that fire at uninstall time. Both
//! produce the same `RunEntry` Rust shape.
//! [`InnoInstaller::exec_commands`](crate::InnoInstaller::exec_commands)
//! walks both, tagging each with a [`ExecPhase`] so callers can
//! filter on install vs. uninstall without joining two iterators
//! manually.

use crate::records::run::RunEntry;

/// Whether a command runs at install time or at uninstall time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecPhase {
    /// `[Run]` - fires after files are copied.
    Install,
    /// `[UninstallRun]` - fires before files are removed.
    Uninstall,
}

/// A single command-execution directive, sourced from either
/// `[Run]` or `[UninstallRun]`.
///
/// All fields borrow from the underlying [`RunEntry`]; the entry
/// carries every Inno-specific field (flags, conditions, working
/// directory, etc.) for callers that need full fidelity.
#[derive(Clone, Copy, Debug)]
pub struct ExecCommand<'a> {
    /// Install-time vs. uninstall-time placement.
    pub phase: ExecPhase,
    /// Underlying parsed record.
    pub source: &'a RunEntry,
}

impl<'a> ExecCommand<'a> {
    /// Returns the `Filename:` directive - the executable, batch
    /// file, or shell URL to invoke. Inno calls this field `Name`
    /// internally; the analyst-friendly view exposes it as
    /// `filename` to match the `[Run]` directive name.
    #[must_use]
    pub fn filename(&self) -> &'a str {
        &self.source.name
    }

    /// Returns the `Parameters:` directive (command-line arguments,
    /// possibly with `{constant}` substitutions still embedded).
    #[must_use]
    pub fn parameters(&self) -> &'a str {
        &self.source.parameters
    }

    /// Returns the `WorkingDir:` directive, or an empty string if
    /// the command inherits Setup's own working directory.
    #[must_use]
    pub fn working_dir(&self) -> &'a str {
        &self.source.working_dir
    }

    /// Returns the `Description:` directive (the user-visible
    /// label shown next to the post-install checkbox), or empty.
    #[must_use]
    pub fn description(&self) -> &'a str {
        &self.source.description
    }
}

/// Iterator yielded by
/// [`InnoInstaller::exec_commands`](crate::InnoInstaller::exec_commands).
///
/// Visits every install-time `[Run]` entry first (in declaration
/// order) followed by every uninstall-time `[UninstallRun]` entry
/// (also in declaration order).
#[derive(Clone)]
pub struct ExecIter<'a> {
    install: std::slice::Iter<'a, RunEntry>,
    uninstall: std::slice::Iter<'a, RunEntry>,
}

impl<'a> ExecIter<'a> {
    pub(crate) fn new(install: &'a [RunEntry], uninstall: &'a [RunEntry]) -> Self {
        Self {
            install: install.iter(),
            uninstall: uninstall.iter(),
        }
    }
}

impl<'a> Iterator for ExecIter<'a> {
    type Item = ExecCommand<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(source) = self.install.next() {
            return Some(ExecCommand {
                phase: ExecPhase::Install,
                source,
            });
        }
        self.uninstall.next().map(|source| ExecCommand {
            phase: ExecPhase::Uninstall,
            source,
        })
    }
}
