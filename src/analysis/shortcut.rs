//! `[Icons]` entries (Start Menu / desktop shortcuts) joined to
//! their `[Files]` targets.
//!
//! Inno's `[Icons]` directive declares shortcut metadata
//! (`Filename:`, `Parameters:`, `WorkingDir:`, `IconFile:`) but
//! doesn't itself materialize the binary the shortcut points at -
//! that comes from a separate `[Files]` entry. For analyst code
//! that wants to know "which executables in this installer get a
//! shortcut?", the natural shape is the join.
//!
//! [`InnoInstaller::shortcuts`](crate::InnoInstaller::shortcuts)
//! walks the icons stream and, for each entry whose `filename`
//! resolves to a `[Files]` `destination` path, includes the
//! matched [`FileEntry`]. Icons that target system paths (e.g.
//! `{sys}\notepad.exe`) or arbitrary URIs leave
//! [`Shortcut::target`] as `None`.

use crate::records::{file::FileEntry, icon::IconEntry};

/// A single shortcut (`[Icons]` entry) plus the install-time file
/// it targets, if any.
#[derive(Clone, Copy, Debug)]
pub struct Shortcut<'a> {
    /// The icon entry that defines the shortcut.
    pub icon: &'a IconEntry,
    /// The matched [`FileEntry`] whose `destination` equals
    /// `icon.filename`, or `None` if no `[Files]` entry matches -
    /// e.g. system-path shortcuts (`{sys}\notepad.exe`), URLs, or
    /// shortcuts to files installed by an `[Code]` script.
    pub target: Option<&'a FileEntry>,
}

/// Iterator yielded by
/// [`InnoInstaller::shortcuts`](crate::InnoInstaller::shortcuts).
#[derive(Clone)]
pub struct ShortcutIter<'a> {
    icons: std::slice::Iter<'a, IconEntry>,
    files: &'a [FileEntry],
}

impl<'a> ShortcutIter<'a> {
    pub(crate) fn new(icons: &'a [IconEntry], files: &'a [FileEntry]) -> Self {
        Self {
            icons: icons.iter(),
            files,
        }
    }

    fn match_target(&self, icon_filename: &str) -> Option<&'a FileEntry> {
        if icon_filename.is_empty() {
            return None;
        }
        self.files.iter().find(|f| f.destination == icon_filename)
    }
}

impl<'a> Iterator for ShortcutIter<'a> {
    type Item = Shortcut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let icon = self.icons.next()?;
        let target = self.match_target(&icon.filename);
        Some(Shortcut { icon, target })
    }
}
