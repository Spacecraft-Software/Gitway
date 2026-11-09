// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
//! Dispatcher for the `gitway list-algorithms` subcommand
//! (M17, PRD §5.8.6 FR-79).
//!
//! Prints every algorithm Gitway can negotiate, grouped by category,
//! tagged with `default` / `available` / `denylisted` flags.  Useful
//! for writing valid `--kex` / `--ciphers` / `--macs` /
//! `--host-key-algorithms` override lists without trial and error.
//!
//! Output respects NFR-11: stdout carries the human-format text or
//! the JSON envelope; status / tracing land on stderr.

use anvil_ssh::algorithms::{all_supported, AlgEntry};
use anvil_ssh::AnvilError;

use crate::{emit_json, metadata_block, OutputMode};

/// Runs `gitway list-algorithms` in the requested output mode.
///
/// # Errors
///
/// Currently infallible — `all_supported()` is a pure-data call.  The
/// `Result` return type keeps the dispatcher signature consistent
/// with the other Gitway subcommand verbs (`config show`, `hosts list`).
#[allow(
    clippy::unnecessary_wraps,
    reason = "Result return shape matches the other gitway subcommand verb \
              dispatchers (config::run, hosts::run, agent::run); a future \
              richer catalogue (e.g. queried from a remote algorithm registry) \
              will need fallibility."
)]
pub fn run(mode: OutputMode) -> Result<u32, AnvilError> {
    let cat = all_supported();
    tracing::debug!(
        target: anvil_ssh::log::CAT_CONFIG,
        kex_count = cat.kex.len(),
        cipher_count = cat.cipher.len(),
        mac_count = cat.mac.len(),
        host_key_count = cat.host_key.len(),
        "list_algorithms catalogue assembled",
    );

    if mode == OutputMode::Json {
        emit_json_catalogue(&cat);
    } else {
        emit_human_catalogue(&cat);
    }
    Ok(0)
}

fn emit_human_catalogue(cat: &anvil_ssh::algorithms::Catalogue) {
    let linear = gitway::a11y::current().enabled();
    let sections = [
        ("KEX", &cat.kex),
        ("Ciphers", &cat.cipher),
        ("MACs", &cat.mac),
        ("Host-key algorithms", &cat.host_key),
    ];
    for (i, (title, entries)) in sections.into_iter().enumerate() {
        if linear {
            // Standard §18.2 tabular fallback: one `field: value` per line,
            // a blank line between entries, no column alignment.
            println!("{title}:");
            println!();
            for entry in entries {
                println!("name: {}", entry.name);
                println!("status: {}", status_of(entry));
                println!();
            }
        } else {
            if i > 0 {
                println!();
            }
            println!("# {title}");
            for entry in entries {
                println!("{}", format_entry(entry));
            }
        }
    }
}

fn status_of(entry: &AlgEntry) -> &'static str {
    if entry.denylisted {
        "denylisted"
    } else if entry.is_default {
        "default"
    } else {
        "available"
    }
}

fn format_entry(entry: &AlgEntry) -> String {
    format!("{:<44} {}", entry.name, status_of(entry))
}

fn emit_json_catalogue(cat: &anvil_ssh::algorithms::Catalogue) {
    let envelope = serde_json::json!({
        "metadata": metadata_block("gitway list-algorithms"),
        "data": {
            "kex":      cat.kex.iter().map(entry_to_json).collect::<Vec<_>>(),
            "cipher":   cat.cipher.iter().map(entry_to_json).collect::<Vec<_>>(),
            "mac":      cat.mac.iter().map(entry_to_json).collect::<Vec<_>>(),
            "host_key": cat.host_key.iter().map(entry_to_json).collect::<Vec<_>>(),
        },
    });
    emit_json(&envelope);
}

fn entry_to_json(entry: &AlgEntry) -> serde_json::Value {
    serde_json::json!({
        "name":       entry.name,
        "is_default": entry.is_default,
        "denylisted": entry.denylisted,
    })
}
