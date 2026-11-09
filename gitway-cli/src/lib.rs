// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! Shared library surface for the Gitway binaries.
//!
//! The three binaries (`gitway`, `gitway-keygen`, `gitway-add`) are separate
//! compilation targets, so code that more than one of them needs lives here
//! rather than being `#[path]`-included into each (which would re-flag the
//! unused parts as dead code per binary).  Today that is:
//!
//! - [`biometric`] — the cross-platform biometric vault (`gitway`, `gitway-add`);
//! - [`agent_env`] — presence-based agent / CI detection;
//! - [`a11y`] — the Standard §18 accessible-mode toggle;
//! - [`term`] — OSC 52 clipboard and OSC 9;4 progress behind the
//!   `spacecraft-tui-protocols` gates.
//!
//! [`a11y`] and [`term`] cache their resolved state in process-wide
//! `OnceLock`s: both are, by contract, resolved once at startup and read
//! everywhere (§18.1, tui-protocols §2.2), and this crate is private to the
//! Gitway binaries rather than a reusable library.

pub mod a11y;
pub mod agent_env;
pub mod biometric;
pub mod term;
