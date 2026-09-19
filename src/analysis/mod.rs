//! Higher-level views over the typed-record streams.
//!
//! The record iterators on [`crate::InnoInstaller`]
//! ([`crate::InnoInstaller::run_entries`],
//! [`crate::InnoInstaller::registry_entries`], etc.) yield the raw
//! parsed records. The submodules here re-shape those records into
//! analyst-friendly views:
//!
//! - [`exec`] - install + uninstall command execution.
//! - [`registryop`] - registry mutations classified by operation
//!   kind.
//! - [`shortcut`] - `[Icons]` entries joined to their `[Files]`
//!   targets where possible.
//! - [`compiledcode`] - IFPS container fingerprint for the
//!   compiled `[Code]` blob (header-only at the moment).
//!
//! Every view here borrows from the underlying record or buffer;
//! nothing is cloned or re-decoded.
pub mod compiledcode;
pub mod exec;
pub mod registryop;
pub mod shortcut;

pub use compiledcode::{INNO_API, inno_api_description};
pub use exec::{ExecCommand, ExecPhase};
pub use registryop::{RegistryOp, RegistryOpKind};
pub use shortcut::Shortcut;
