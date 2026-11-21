//! The setup loader's offset table: where in the installer executable
//! setup-0, setup-1 and the Setup program are.
//!
//! An installer is SetupLdr, a small Windows program, with the setup data
//! appended. Before 5.1.5 SetupLdr finds its `TSetupLdrOffsetTable` through
//! a pointer at file offset `0x30`; from 5.1.5 the table is the PE resource
//! `11111`. This crate follows the pointer when it is there and otherwise
//! scans for the table's 12-byte magic ([`pe::LocatorMode`]), then decodes
//! it into an [`OffsetTable`].
//!
//! Upstream: `TSetupLdrOffsetTable` (issrc `Projects/Src/Shared.Struct.pas`)
//! and the setup loader (`Projects/SetupLdr.dpr`); reader reference:
//! innoextract `loader/offsets.cpp`.

pub mod offsettable;
pub mod pe;

pub use offsettable::{OffsetTable, OffsetTableSource, SetupLdrFamily};
