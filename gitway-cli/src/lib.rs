// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! Shared library surface for the Gitway binaries.
//!
//! The three binaries (`gitway`, `gitway-keygen`, `gitway-add`) are separate
//! compilation targets, so code that more than one of them needs lives here
//! rather than being `#[path]`-included into each (which would re-flag the
//! unused parts as dead code per binary).  Today that is the cross-platform
//! [`biometric`] vault, used by both `gitway` and `gitway-add`.

pub mod biometric;
