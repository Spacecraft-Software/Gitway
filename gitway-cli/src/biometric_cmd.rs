// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! Handler for the `gitway biometric` subcommand group: enroll, forget, list,
//! status.
//!
//! This module lives only in the `gitway` binary (it needs the JSON-envelope
//! helpers from the crate root); the cross-binary vault implementation lives in
//! the shared library at `gitway::biometric`.

use std::path::{Path, PathBuf};

use ssh_key::PrivateKey;

use anvil_ssh::AnvilError;

use crate::cli::{BiometricEnrollArgs, BiometricForgetArgs, BiometricSubcommand};
use crate::{emit_json, metadata_block, prompt_passphrase_interactive, OutputMode};
use gitway::biometric::{
    self, key_id, key_id_from_fingerprint, BiometricError, BiometricVault, Tier,
};

// Exit codes (CLI Standard Rule 2 / docs/exit-codes.md).
const EXIT_OK: u32 = 0;
const EXIT_GENERAL: u32 = 1;
const EXIT_USAGE: u32 = 2;
const EXIT_NOT_FOUND: u32 = 3;
const EXIT_USER_DECLINED: u32 = 73;
const EXIT_NEEDS_INTERACTIVE: u32 = 78;

/// Dispatch a `gitway biometric` invocation.
pub(crate) fn run(command: BiometricSubcommand, mode: OutputMode) -> Result<u32, AnvilError> {
    match command {
        BiometricSubcommand::Enroll(args) => run_enroll(&args, mode),
        BiometricSubcommand::Forget(args) => run_forget(&args, mode),
        BiometricSubcommand::List => Ok(run_list(mode)),
        BiometricSubcommand::Status => Ok(run_status(mode)),
    }
}

// ── enroll ────────────────────────────────────────────────────────────────────

fn run_enroll(args: &BiometricEnrollArgs, mode: OutputMode) -> Result<u32, AnvilError> {
    let vault = biometric::vault();
    if !vault.is_available() {
        return Ok(emit_unavailable(
            vault.binding_tier(),
            mode,
            "gitway biometric enroll",
        ));
    }

    // One-time, prominent disclosure when the active backend is only advisory
    // (Linux): the fingerprint gates a login-keyring secret, it is not a
    // security boundary.  Shown before any passphrase is collected.
    if vault.binding_tier() == Tier::Advisory && mode == OutputMode::Human {
        eprintln!("gitway: NOTE: {}", Tier::Advisory.description());
    }

    let paths = resolve_paths(&args.files)?;
    let mut results = Vec::with_capacity(paths.len());
    let mut exit = EXIT_OK;

    for path in &paths {
        let outcome = enroll_one(vault.as_ref(), path)?;
        if !outcome.ok {
            exit = outcome.exit_code;
        }
        results.push(outcome);
    }

    emit_results(mode, "gitway biometric enroll", &results, "enrolled");
    Ok(exit)
}

/// Enroll a single key.  Genuine I/O / prompt failures propagate as
/// [`AnvilError`]; domain failures (not encrypted, wrong passphrase, keystore
/// error) are returned as a non-ok [`Outcome`] so a batch enrollment continues.
fn enroll_one(vault: &dyn BiometricVault, path: &Path) -> Result<Outcome, AnvilError> {
    let display = path.display().to_string();
    let key = match read_key(path) {
        Ok(key) => key,
        Err(message) => return Ok(Outcome::failed(display, message, EXIT_USAGE)),
    };
    if !key.is_encrypted() {
        return Ok(Outcome::failed(
            display,
            "key is not passphrase-protected; biometric unlock only applies to encrypted keys"
                .to_owned(),
            EXIT_USAGE,
        ));
    }

    let id = key_id(&key);
    let fingerprint = biometric::fingerprint_of(&id).to_owned();

    // Force a typed passphrase (never biometric) during enrollment.
    let passphrase = prompt_passphrase_interactive(path)?;

    // Verify the passphrase actually decrypts the key before storing it.
    if key.decrypt(passphrase.as_bytes()).is_err() {
        return Ok(Outcome::failed(
            display,
            "passphrase did not decrypt the key; nothing was stored".to_owned(),
            EXIT_USAGE,
        ));
    }

    match vault.store(&id, &passphrase) {
        Ok(()) => Ok(Outcome::ok(display, fingerprint)),
        Err(error) => Ok(Outcome::failed(
            display,
            error.to_string(),
            exit_for(&error),
        )),
    }
}

// ── forget ────────────────────────────────────────────────────────────────────

fn run_forget(args: &BiometricForgetArgs, mode: OutputMode) -> Result<u32, AnvilError> {
    let vault = biometric::vault();

    let mut results = Vec::new();
    let mut exit = EXIT_OK;

    if args.all {
        let enrolled = match vault.list() {
            Ok(list) => list,
            Err(error) => return Ok(emit_error(&error, mode, "gitway biometric forget")),
        };
        for key in enrolled {
            let id = key_id_from_fingerprint(&key.fingerprint);
            match vault.delete(&id) {
                Ok(()) => results.push(Outcome::ok(key.fingerprint.clone(), key.fingerprint)),
                Err(error) => {
                    exit = exit_for(&error);
                    results.push(Outcome::failed(key.fingerprint, error.to_string(), exit));
                }
            }
        }
    } else if args.files.is_empty() {
        return Err(AnvilError::invalid_config(
            "specify one or more key files to forget, or pass --all",
        ));
    } else {
        for path in &args.files {
            let display = path.display().to_string();
            let id = match read_key(path) {
                Ok(key) => key_id(&key),
                Err(message) => {
                    exit = EXIT_USAGE;
                    results.push(Outcome::failed(display, message, EXIT_USAGE));
                    continue;
                }
            };
            match vault.delete(&id) {
                Ok(()) => results.push(Outcome::ok(
                    display,
                    biometric::fingerprint_of(&id).to_owned(),
                )),
                Err(error) => {
                    exit = exit_for(&error);
                    results.push(Outcome::failed(display, error.to_string(), exit));
                }
            }
        }
    }

    emit_results(mode, "gitway biometric forget", &results, "forgot");
    Ok(exit)
}

// ── list ──────────────────────────────────────────────────────────────────────

fn run_list(mode: OutputMode) -> u32 {
    let vault = biometric::vault();
    let enrolled = match vault.list() {
        Ok(list) => list,
        Err(error) => return emit_error(&error, mode, "gitway biometric list"),
    };

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": metadata_block("gitway biometric list"),
                "data": {
                    "count": enrolled.len(),
                    "enrolled": enrolled.iter().map(|key| serde_json::json!({
                        "fingerprint": key.fingerprint,
                        "comment": key.comment,
                    })).collect::<Vec<_>>(),
                }
            }));
        }
        OutputMode::Human => {
            if enrolled.is_empty() {
                eprintln!("gitway: no keys are enrolled for biometric unlock");
            } else {
                for key in &enrolled {
                    match &key.comment {
                        Some(comment) => println!("{} ({comment})", key.fingerprint),
                        None => println!("{}", key.fingerprint),
                    }
                }
            }
        }
    }
    EXIT_OK
}

// ── status ────────────────────────────────────────────────────────────────────

fn run_status(mode: OutputMode) -> u32 {
    let vault = biometric::vault();
    let available = vault.is_available();
    let tier = vault.binding_tier();
    // Only enumerate when a backend is present, and never let a listing error
    // turn a status query into a failure.
    let enrolled = if available {
        vault.list().ok().map(|list| list.len())
    } else {
        None
    };

    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": metadata_block("gitway biometric status"),
                "data": {
                    "available": available,
                    "tier": tier.as_str(),
                    "description": tier.description(),
                    "enrolled_count": enrolled,
                }
            }));
        }
        OutputMode::Human => {
            println!("available: {}", if available { "yes" } else { "no" });
            println!("tier:      {}", tier.as_str());
            println!("guarantee: {}", tier.description());
            if let Some(count) = enrolled {
                println!("enrolled:  {count}");
            }
        }
    }
    EXIT_OK
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// The outcome of a single enroll/forget operation, for batch reporting.
struct Outcome {
    target: String,
    ok: bool,
    message: String,
    fingerprint: Option<String>,
    exit_code: u32,
}

impl Outcome {
    fn ok(target: String, fingerprint: String) -> Self {
        Self {
            target,
            ok: true,
            message: String::new(),
            fingerprint: Some(fingerprint),
            exit_code: EXIT_OK,
        }
    }

    fn failed(target: String, message: String, exit_code: u32) -> Self {
        Self {
            target,
            ok: false,
            message,
            fingerprint: None,
            exit_code,
        }
    }
}

/// Emit a batch of [`Outcome`]s.  `verb` is the success past-tense word
/// ("enrolled" / "forgot").
fn emit_results(mode: OutputMode, command: &str, results: &[Outcome], verb: &str) {
    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": metadata_block(command),
                "data": {
                    "results": results.iter().map(|outcome| serde_json::json!({
                        "target": outcome.target,
                        "ok": outcome.ok,
                        "fingerprint": outcome.fingerprint,
                        "message": if outcome.ok { verb } else { outcome.message.as_str() },
                    })).collect::<Vec<_>>(),
                }
            }));
        }
        OutputMode::Human => {
            for outcome in results {
                if outcome.ok {
                    eprintln!("gitway: {verb} {}", outcome.target);
                } else {
                    eprintln!("gitway: {}: {}", outcome.target, outcome.message);
                }
            }
        }
    }
}

/// Map a [`BiometricError`] to its exit code.
fn exit_for(error: &BiometricError) -> u32 {
    match error {
        BiometricError::NotEnrolled => EXIT_NOT_FOUND,
        BiometricError::Cancelled => EXIT_USER_DECLINED,
        BiometricError::Unavailable(_) => EXIT_NEEDS_INTERACTIVE,
        BiometricError::Backend(_) => EXIT_GENERAL,
    }
}

/// Print a single [`BiometricError`] in the active mode and return its exit
/// code.
fn emit_error(error: &BiometricError, mode: OutputMode, command: &str) -> u32 {
    let code = exit_for(error);
    match mode {
        OutputMode::Json => {
            emit_json(&serde_json::json!({
                "metadata": metadata_block(command),
                "error": { "exit_code": code, "message": error.to_string() }
            }));
        }
        OutputMode::Human => eprintln!("gitway: error: {error}"),
    }
    code
}

/// Emit the "no backend available" error for a requested operation.
fn emit_unavailable(tier: Tier, mode: OutputMode, command: &str) -> u32 {
    let error = BiometricError::Unavailable(tier.description().to_owned());
    emit_error(&error, mode, command)
}

/// Read and parse a private key, returning a human-readable message on failure.
fn read_key(path: &Path) -> std::result::Result<PrivateKey, String> {
    let pem = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    PrivateKey::from_openssh(&pem).map_err(|e| format!("cannot parse {}: {e}", path.display()))
}

/// Resolve the key paths to operate on, defaulting to the standard identities
/// when none are given (matches `ssh-add` / `gitway agent add`).
fn resolve_paths(files: &[PathBuf]) -> Result<Vec<PathBuf>, AnvilError> {
    if !files.is_empty() {
        return Ok(files.to_vec());
    }
    let home =
        dirs::home_dir().ok_or_else(|| AnvilError::invalid_config("cannot determine $HOME"))?;
    let found: Vec<_> = ["id_ed25519", "id_ecdsa", "id_rsa"]
        .iter()
        .map(|name| home.join(".ssh").join(name))
        .filter(|p| p.exists())
        .collect();
    if found.is_empty() {
        return Err(AnvilError::no_key_found());
    }
    Ok(found)
}
