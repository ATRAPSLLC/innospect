//! Inno-side wrapper for the embedded `[Code]` PascalScript blob.
//!
//! The structural parser lives in the standalone
//! [`pascalscript`] crate (sibling repo at `../pascalscript/`) -
//! fully host-agnostic, since RemObjects PascalScript III is
//! used by many Delphi applications beyond Inno Setup. This
//! module re-exports the parser's [`Container`] type for
//! analyst convenience and adds one Inno-specific helper:
//! [`inno_api_description`] - a table mapping
//! Inno's runtime-registered PascalScript externals (the names a
//! `[Code]` script can call) to short descriptions.

pub use pascalscript::Container;

mod innoapi;
pub use innoapi::{INNO_API, inno_api_description};
