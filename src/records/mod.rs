//! Setup record parsing and iteration.
//!
//! Reads the typed record entries that follow `TSetupHeader` in the
//! decompressed `setup-0` stream. Each submodule maps to one Pascal
//! record type from `Shared.Struct.pas`. Each documents how its layout
//! changes with the version; the `crate::upstream` tests check every one
//! against upstream's declaration for each SetupID marker.
//!
//! [`windows`] holds the bit-packed-set helpers used by both the
//! fixed numeric tail of `TSetupHeader` and the per-record
//! `ItemBase`. [`item`] is the conditions section + version-range
//! bundle every record-with-conditions reads. The remaining modules
//! map one-to-one to Pascal record types - lightweight ones
//! ([`type_`], [`component`], [`task`], [`language`], [`message`],
//! [`permission`]) and heavier ones ([`directory`], [`mod@file`],
//! [`icon`], [`ini`], [`registry`], [`run`], [`delete`],
//! [`dataentry`], [`isssigkey`]).

pub mod component;
pub mod dataentry;
pub mod delete;
pub mod directory;
pub mod file;
pub mod icon;
pub mod ini;
pub mod isssigkey;
pub mod item;
pub mod language;
pub mod message;
pub mod permission;
pub mod registry;
pub mod run;
pub mod task;
pub mod type_;
pub mod windows;
