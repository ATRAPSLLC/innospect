//! Finding and identifying the setup data inside an installer: the
//! `SetupLdrOffsetTable` in the PE container, and the SetupID marker that
//! names the setup-0 format.
//!
//! Internal: the public view is [`crate::overlay`] and [`crate::version`].

pub mod marker;
pub mod pe;
