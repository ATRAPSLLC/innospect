//! Registry entries classified by what Setup does with them at install
//! time.
//!
//! A `[Registry]` entry's effect follows from its `ValueType` and its
//! `deletekey`, `deletevalue`, `createvalueifdoesntexist` and
//! `dontcreatekey` flags together: a delete flag with a value type other
//! than `none` deletes and then writes, and `none` without one only creates
//! the key. [`InnoInstaller::registry_ops`](crate::InnoInstaller::registry_ops)
//! tags each entry with the [`RegistryOpKind`] Setup's
//! `ProcessRegistryEntries` (issrc `Projects/Src/Setup.Install.pas`) would
//! carry out, so callers need not re-derive it from the flags.
//!
//! For uninstall-time effects (`uninsdeletevalue`, `uninsdeletekey`,
//! `uninsclearvalue`, `uninsdeletekeyifempty`) inspect the underlying
//! entry's `flags` through [`RegistryOp::source`].

use crate::records::registry::{RegistryEntry, RegistryFlag, RegistryValueType};

/// What Setup does with a `[Registry]` entry at install time, as its
/// `ProcessRegistryEntries` branches on the entry's flags and `ValueType`.
/// With `dontcreatekey` the key must already exist for anything but a
/// delete to happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RegistryOpKind {
    /// Creates the key, or sets the value when [`RegistryEntry::value_type`]
    /// is not `none`, replacing one already there.
    Write,
    /// Sets the value only when it does not exist yet
    /// (`createvalueifdoesntexist`).
    WriteIfMissing,
    /// Creates the key and nothing else (`ValueType: none`, no flags).
    CreateKey,
    /// Deletes [`RegistryEntry::value_name`] (`deletevalue` with
    /// `ValueType: none`).
    DeleteValue,
    /// Deletes the key with its values and subkeys (`deletekey` with
    /// `ValueType: none`, or with `dontcreatekey`, which leaves nothing to
    /// write into).
    DeleteKey,
    /// Deletes the value, then writes it anew (`deletevalue` with a value
    /// type); `createvalueifdoesntexist` has no effect.
    ReplaceValue,
    /// Deletes the key, then creates it again with the value (`deletekey`
    /// with a value type).
    ReplaceKey,
    /// Nothing; the entry is only recorded for the uninstaller
    /// (`ValueType: none` with `dontcreatekey`, or `deletekey` on a subkey
    /// that is blank or only backslashes, which Setup refuses to delete).
    UninstallOnly,
}

stable_name_enum!(RegistryOpKind, {
    Self::Write => "write",
    Self::WriteIfMissing => "write_if_missing",
    Self::CreateKey => "create_key",
    Self::DeleteValue => "delete_value",
    Self::DeleteKey => "delete_key",
    Self::ReplaceValue => "replace_value",
    Self::ReplaceKey => "replace_key",
    Self::UninstallOnly => "uninstall_only",
});

/// A single classified `[Registry]` operation.
///
/// Borrows from the underlying [`RegistryEntry`]; that entry
/// carries every Inno-specific detail (hive, value type, raw
/// value bytes, conditions, uninstall-time flags) for callers
/// that need full fidelity.
#[derive(Clone, Copy, Debug)]
pub struct RegistryOp<'a> {
    /// What Setup does with the entry at install time.
    pub kind: RegistryOpKind,
    /// Underlying parsed record.
    pub source: &'a RegistryEntry,
}

impl RegistryOp<'_> {
    /// Setup's `ProcessRegistryEntries`, branch for branch. A value type
    /// this crate does not know counts as one that writes.
    fn classify(entry: &RegistryEntry) -> RegistryOpKind {
        let has = |flag| entry.flags.contains(&flag);
        let writes = entry.value_type != Some(RegistryValueType::None);
        // `IsDeletableSubkey`: Setup will not delete a blank or
        // backslash-only subkey (checked here before constants expand).
        let deletes_key = has(RegistryFlag::DeleteKey) && entry.subkey.chars().any(|c| c != '\\');
        if has(RegistryFlag::DeleteKey) && !writes {
            return if deletes_key {
                RegistryOpKind::DeleteKey
            } else {
                RegistryOpKind::UninstallOnly
            };
        }
        if has(RegistryFlag::DeleteValue) && !writes {
            return RegistryOpKind::DeleteValue;
        }
        if !writes {
            return if has(RegistryFlag::DontCreateKey) {
                RegistryOpKind::UninstallOnly
            } else {
                RegistryOpKind::CreateKey
            };
        }
        if deletes_key {
            return if has(RegistryFlag::DontCreateKey) {
                RegistryOpKind::DeleteKey
            } else {
                RegistryOpKind::ReplaceKey
            };
        }
        if has(RegistryFlag::DeleteValue) {
            RegistryOpKind::ReplaceValue
        } else if has(RegistryFlag::CreateValueIfDoesntExist) {
            RegistryOpKind::WriteIfMissing
        } else {
            RegistryOpKind::Write
        }
    }
}

/// Iterator yielded by
/// [`InnoInstaller::registry_ops`](crate::InnoInstaller::registry_ops).
#[derive(Clone)]
pub struct RegistryOpIter<'a> {
    inner: std::slice::Iter<'a, RegistryEntry>,
}

impl<'a> RegistryOpIter<'a> {
    /// Walks `entries` (`[Registry]`), as
    /// [`InnoInstaller::registry_ops`](crate::InnoInstaller::registry_ops)
    /// does over an installer's own entries.
    #[must_use]
    pub fn new(entries: &'a [RegistryEntry]) -> Self {
        Self {
            inner: entries.iter(),
        }
    }
}

impl<'a> Iterator for RegistryOpIter<'a> {
    type Item = RegistryOp<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let source = self.inner.next()?;
        Some(RegistryOp {
            kind: RegistryOp::classify(source),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        upstream::{MARKERS, encode_strings, version},
        util::read::{FromReader, Reader},
    };

    fn entry(subkey: &str, value_type: RegistryValueType, flags: &[RegistryFlag]) -> RegistryEntry {
        let build = MARKERS
            .iter()
            .find(|m| m.id == "7.1.1")
            .map(|m| &m.variants[0].builds[0])
            .expect("7.1.1 layout");
        let record = build
            .records
            .iter()
            .find(|r| r.name == "TSetupRegistryEntry")
            .expect("registry");
        let mut buf = Vec::new();
        encode_strings(record, true, &version("7.1.1", true), &mut buf);
        buf.resize(buf.len() + record.tail + 64, 0);
        let mut e =
            RegistryEntry::read(&mut Reader::new(&buf), &version("7.1.1", true)).expect("parses");
        e.subkey = subkey.to_owned();
        e.value_type = Some(value_type);
        e.flags = flags.iter().copied().collect();
        e
    }

    /// Every branch of Setup's `ProcessRegistryEntries`.
    #[test]
    fn classification_follows_setup() {
        use RegistryFlag::{
            CreateValueIfDoesntExist as IfMissing, DeleteKey, DeleteValue, DontCreateKey,
        };
        use RegistryOpKind as K;
        use RegistryValueType::{None as Nothing, String as Str};
        let cases: &[(&str, RegistryValueType, &[RegistryFlag], RegistryOpKind)] = &[
            ("Software\\A", Str, &[], K::Write),
            ("Software\\A", Str, &[DontCreateKey], K::Write),
            ("Software\\A", Str, &[IfMissing], K::WriteIfMissing),
            ("Software\\A", Nothing, &[], K::CreateKey),
            ("Software\\A", Nothing, &[IfMissing], K::CreateKey),
            ("Software\\A", Nothing, &[DontCreateKey], K::UninstallOnly),
            ("Software\\A", Nothing, &[DeleteValue], K::DeleteValue),
            ("Software\\A", Nothing, &[DeleteKey], K::DeleteKey),
            (
                "Software\\A",
                Nothing,
                &[DeleteKey, DeleteValue],
                K::DeleteKey,
            ),
            ("Software\\A", Str, &[DeleteValue], K::ReplaceValue),
            (
                "Software\\A",
                Str,
                &[DeleteValue, IfMissing],
                K::ReplaceValue,
            ),
            ("Software\\A", Str, &[DeleteKey], K::ReplaceKey),
            ("Software\\A", Str, &[DeleteKey, DeleteValue], K::ReplaceKey),
            (
                "Software\\A",
                Str,
                &[DeleteKey, DontCreateKey],
                K::DeleteKey,
            ),
            ("", Nothing, &[DeleteKey], K::UninstallOnly),
            ("\\\\", Nothing, &[DeleteKey], K::UninstallOnly),
            ("", Str, &[DeleteKey], K::Write),
            ("\\", Str, &[DeleteKey, DeleteValue], K::ReplaceValue),
        ];
        for (subkey, value_type, flags, want) in cases {
            let e = entry(subkey, *value_type, flags);
            assert_eq!(
                RegistryOp::classify(&e),
                *want,
                "{subkey:?} {value_type:?} {flags:?}"
            );
        }
    }

    /// A value type the crate does not know is treated as one that writes.
    #[test]
    fn unknown_value_type_writes() {
        let mut e = entry(
            "Software\\A",
            RegistryValueType::String,
            &[RegistryFlag::DeleteKey],
        );
        e.value_type = None;
        assert_eq!(RegistryOp::classify(&e), RegistryOpKind::ReplaceKey);
    }
}
