//! Parse and inspect Inno Setup installer binaries.
//!
//! This crate provides typed access to the internal structures of an
//! [Inno Setup](https://jrsoftware.org/isinfo.php) installer executable,
//! from the PE loader stub through the compressed setup header down to
//! individual records and embedded files.
//!
//! Every format detail is taken from upstream's own source (issrc and the
//! `issrc-*.zip` archives for older releases) and cross-checked with
//! innoextract. Record layouts are verified against upstream's
//! declarations for every SetupID marker whose source is available, from
//! 1.2.10 (its 32-bit and 16-bit builds) to 7.1.1, and whole installers
//! against ones built by the official compilers from 1.3.26 to 7.1.1, one
//! for every setup data marker from 1.3.25 to 4.2.6, and 1.2.16's own
//! 16-bit package (`tests/samples`). See [`version::Variant`] for what is
//! recognised but untested.
//!
//! # Stable Identifiers
//!
//! Public discriminator enums expose stable [`core::fmt::Display`]
//! strings, and most also expose `as_str()`. Consumers may persist
//! those strings in databases and compare them across crate releases.
//! New variants on `#[non_exhaustive]` enums are added in minor-version
//! releases; once a variant's display string is published, that string
//! is a compatibility surface and will not be renamed.
//!
//! # Architecture
//!
//! The crate is organized in layers that mirror the on-disk format:
//!
//! - **Offset table** ([`overlay`]): where the setup loader keeps setup-0,
//!   setup-1 and the Setup program inside the executable.
//! - **Version** ([`version`]): the SetupID marker that names setup-0's
//!   format, which every later layer reads by.
//! - **setup-0 blocks** ([`decompress`]): the CRC-framed, stored / zlib /
//!   LZMA1 blocks holding the header, the records and the data entries.
//! - **Header and records** ([`header`], [`records`]): `TSetupHeader` and
//!   every record type after it, from languages to uninstall runs, plus the
//!   data entries that locate each file's bytes.
//! - **Files** ([`extract`]): setup-1's chunks (stored, zlib, bzip2, LZMA1,
//!   LZMA2; encrypted with ARC4 or XChaCha20), the BCJ filter and checksum
//!   checks, as a streaming reader.
//! - **Analysis** ([`analysis`]): views joining records (commands, registry
//!   operations, shortcuts) and the compiled `[Code]` script.
//! - **High-level API** ([`InnoInstaller`]): ties everything together
//!   into a convenient exploration interface for analysis use cases.
//!
//! The public modules hold the types callers see. The machinery behind
//! them lives in private modules and never appears in the API: `loader`
//! (finding the offset table in the PE, decoding the SetupID marker),
//! `stream` (setup-0 blocks, setup-1 chunks and slices, the BCJ filter,
//! file checksums), `crypto` (ARC4, XChaCha20, the key derivations) and
//! `util` (the bounds-checked reader every record parser uses, string
//! decoding, packed sets). Every record type is read through the private
//! `util::read::FromReader` trait.

// The `missing_docs`, `unsafe_code`, `clippy::unwrap_used`,
// `clippy::expect_used`, `clippy::panic`,
// `clippy::arithmetic_side_effects`, and `clippy::indexing_slicing` lints
// are declared in `Cargo.toml` under `[lints]` so they enforce on every
// build regardless of the consuming workspace. innospect is used in
// malware-analysis pipelines where every input byte is adversarial and
// the parser must not panic.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

macro_rules! stable_name_enum {
    ($ty:ty, { $($pat:pat => $name:literal),+ $(,)? }) => {
        impl $ty {
            /// Returns this value's stable identifier.
            #[must_use]
            pub fn as_str(&self) -> &'static str {
                match self {
                    $($pat => $name,)+
                }
            }
        }

        impl core::fmt::Display for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

macro_rules! stable_flag_enum {
    ($ty:ty, { $($variant:ident => $name:literal),+ $(,)? }) => {
        stable_name_enum!($ty, { $(Self::$variant => $name,)+ });

        impl $ty {
            /// Canonical storage order for this flag enum: append-only, so a
            /// flag's [`Self::index`] and [`Self::bit`] never change across
            /// releases.
            pub const ORDER: &'static [Self] = &[$(Self::$variant,)+];

            /// Canonical stable-name order for this flag enum.
            pub const NAME_ORDER: &'static [&'static str] = &[$($name,)+];

            /// Returns this flag's position in [`Self::ORDER`].
            #[must_use]
            pub fn index(self) -> u32 {
                Self::ORDER
                    .iter()
                    .position(|flag| *flag == self)
                    .and_then(|idx| u32::try_from(idx).ok())
                    .unwrap_or(u32::MAX)
            }

            /// Returns this flag's canonical bit: `1 << index()`. A `u128`,
            /// since [`crate::HeaderOption`] has more than 64 flags.
            #[must_use]
            pub fn bit(self) -> u128 {
                1_u128.checked_shl(self.index()).unwrap_or(0)
            }

            /// Converts a set of flags into the canonical bitmask.
            #[must_use]
            pub fn set_to_bits(set: &std::collections::HashSet<Self>) -> u128 {
                set.iter().fold(0_u128, |acc, flag| acc | flag.bit())
            }
        }
    };
}

pub mod analysis;
pub mod decompress;
pub mod error;
pub mod extract;
pub mod header;
pub mod installer;
pub mod overlay;
pub mod records;
pub mod version;

/// Re-export of the `pascalscript` crate so existing
/// `innospect::pascalscript::*` paths resolve through `innospect`. The
/// parser itself is the standalone
/// [`pascalscript`](https://github.com/ATRAPSLLC/pascalscript-rs)
/// crate; this re-export is for caller convenience.
pub use ::pascalscript;

mod crypto;
mod loader;
mod stream;
#[cfg(test)]
mod upstream;
mod util;

pub use error::Error;
pub use extract::FileReader;
pub use header::{
    Architecture, AutoNoYes, CompressMethod, EntryCounts, HeaderAnsi, HeaderOption, HeaderString,
    HeaderTail, ImageAlphaFormat, InstallMode, LanguageDetectionMethod, PrivilegesRequired,
    PrivilegesRequiredOverride, SetupHeader, UninstallLogMode, UninstallStyle, WizardDarkStyle,
    WizardLightControlStyling, WizardStyle, YesNoAuto,
};
pub use installer::{Compression, EncryptionInfo, EncryptionMode, InnoInstaller, WizardImageKind};
pub use overlay::{
    OffsetTable, OffsetTableSource, SetupLdrFamily, pe::LocatorMode as PeLocatorMode,
};
pub use records::{
    component::{ComponentEntry, ComponentFlag},
    dataentry::{DataChecksum, DataEntry, DataFlag, SignMode},
    delete::{DeleteEntry, DeleteTargetType},
    directory::{DirectoryEntry, DirectoryFlag},
    file::{FileEntry, FileEntryType, FileFlag, FileVerification, FileVerificationKind},
    icon::{CloseOnExit, IconEntry, IconFlag},
    ini::{IniEntry, IniFlag},
    isssigkey::ISSigKeyEntry,
    language::{LanguageCodepage, LanguageEntry},
    message::MessageEntry,
    permission::PermissionEntry,
    registry::{RegistryData, RegistryEntry, RegistryFlag, RegistryHive, RegistryValueType},
    run::{RunEntry, RunFlag, RunWait},
    task::{TaskEntry, TaskFlag},
    type_::{SetupTypeKind, TypeEntry},
    windows::Bitness,
};
pub use version::{Variant, Version, VersionFlags};

// Thread-safety guarantee: InnoInstaller borrows from a `&[u8]` input
// buffer, holds no interior mutability, and contains no raw pointers
// or `Cell`/`RefCell`. It is therefore both `Send` and `Sync`. This
// static assertion makes the guarantee a compile-time invariant: a
// future change that adds a non-Send/non-Sync field will break the
// build here, not silently at a downstream `.await` point.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InnoInstaller<'static>>();
};

#[cfg(test)]
mod flag_tests {
    use std::collections::HashSet;

    macro_rules! check {
        ($($ty:ty),+ $(,)?) => {$({
            let order = <$ty>::ORDER;
            assert!(order.len() <= 128, "{}: {} flags", stringify!($ty), order.len());
            assert_eq!(order.len(), <$ty>::NAME_ORDER.len(), stringify!($ty));
            for (i, flag) in order.iter().enumerate() {
                assert_eq!(flag.index() as usize, i, "{}: {flag:?}", stringify!($ty));
                assert_eq!(flag.as_str(), <$ty>::NAME_ORDER[i], stringify!($ty));
            }
            let all: HashSet<$ty> = order.iter().copied().collect();
            assert_eq!(all.len(), order.len(), "{}: duplicate flags", stringify!($ty));
            let bits = <$ty>::set_to_bits(&all);
            assert_eq!(bits.count_ones() as usize, order.len(), "{}: bits", stringify!($ty));
        })+};
    }

    /// Every flag has its own bit, the one its place in `ORDER` gives,
    /// `HeaderOption`'s from 64 on included.
    #[test]
    fn every_flag_has_its_own_bit() {
        use crate::{
            ComponentFlag, DataFlag, DirectoryFlag, FileFlag, HeaderOption, IconFlag, IniFlag,
            RegistryFlag, RunFlag, TaskFlag,
        };
        check!(
            HeaderOption,
            FileFlag,
            DirectoryFlag,
            RegistryFlag,
            RunFlag,
            IconFlag,
            ComponentFlag,
            TaskFlag,
            IniFlag,
            DataFlag,
        );
        assert!(HeaderOption::ORDER.len() > 64, "the case u64 bits lost");
    }
}
