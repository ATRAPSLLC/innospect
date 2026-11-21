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
    /// The first `[Files]` entry whose `destination` is `icon.filename`,
    /// compared as Windows compares paths (ignoring case), or `None` if
    /// none is: a system file (`{sys}\notepad.exe`), a URL, a file a
    /// `[Code]` script installs, or an external file whose destination
    /// holds only its directory. Several entries can install the same path
    /// under different conditions (an x86 and an x64 build, say); the
    /// others are in [`crate::InnoInstaller::files`] with the same
    /// `destination`.
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
    /// Walks `icons` (`[Icons]`), resolving each target against `files`
    /// (`[Files]`), as [`InnoInstaller::shortcuts`](crate::InnoInstaller::shortcuts)
    /// does over an installer's own entries.
    #[must_use]
    pub fn new(icons: &'a [IconEntry], files: &'a [FileEntry]) -> Self {
        Self {
            icons: icons.iter(),
            files,
        }
    }

    fn match_target(&self, icon_filename: &str) -> Option<&'a FileEntry> {
        if icon_filename.is_empty() {
            return None;
        }
        let same = |a: &str, b: &str| {
            a.chars()
                .flat_map(char::to_lowercase)
                .eq(b.chars().flat_map(char::to_lowercase))
        };
        self.files
            .iter()
            .find(|f| same(&f.destination, icon_filename))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        upstream::{MARKERS, encode_strings, version},
        util::read::{FromReader, Reader},
    };

    fn read<T: FromReader>(record: &str) -> T {
        let build = MARKERS
            .iter()
            .find(|m| m.id == "7.1.1")
            .map(|m| &m.variants[0].builds[0])
            .expect("7.1.1 layout");
        let record = build
            .records
            .iter()
            .find(|r| r.name == record)
            .expect("record");
        let mut buf = Vec::new();
        encode_strings(record, true, &version("7.1.1", true), &mut buf);
        buf.resize(buf.len() + record.tail + 64, 0);
        T::read(&mut Reader::new(&buf), &version("7.1.1", true)).expect("parses")
    }

    /// A shortcut finds its file whatever the case of the path, the first
    /// of several entries for one path, and nothing for a system file.
    #[test]
    fn target_is_matched_as_windows_compares_paths() {
        let file = |dest: &str| {
            let mut f: FileEntry = read("TSetupFileEntry");
            f.destination = dest.to_owned();
            f
        };
        let files = [
            file(r"{app}\Docs\Readme.TXT"),
            file(r"{app}\app.exe"),
            file(r"{app}\app.exe"),
        ];
        let icon = |name: &str| {
            let mut i: IconEntry = read("TSetupIconEntry");
            i.filename = name.to_owned();
            i
        };
        let icons = [
            icon(r"{app}\docs\readme.txt"),
            icon(r"{app}\app.exe"),
            icon(r"{sys}\notepad.exe"),
            icon(""),
        ];
        let targets: Vec<_> = ShortcutIter::new(&icons, &files)
            .map(|s| s.target.map(std::ptr::from_ref))
            .collect();
        assert_eq!(
            targets,
            [
                Some(std::ptr::from_ref(&files[0])),
                Some(std::ptr::from_ref(&files[1])),
                None,
                None
            ]
        );
    }
}
