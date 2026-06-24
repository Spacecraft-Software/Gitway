// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-03-30
// S3: enforce zero unsafe in all project-owned code at compile time.
#![forbid(unsafe_code)]
//! `gitway-add` — drop-in replacement for the subset of `ssh-add` that
//! shells out by name (IDE integrations, git-credential-manager,
//! systemd user units, etc.).
//!
//! ## Supported argv surface
//!
//! | Flag | Purpose |
//! |------|---------|
//! | `-l` | List loaded fingerprints (default when no files given) |
//! | `-L` | List full public keys |
//! | `-d <file>` | Remove a specific identity |
//! | `-D` | Remove all identities |
//! | `-x` | Lock the agent with a passphrase |
//! | `-X` | Unlock the agent |
//! | `-t <seconds>` | Lifetime for subsequently-added keys |
//! | `-E <sha256\|sha512>` | Fingerprint hash for `-l` |
//! | `-c` | Ask for confirmation on each sign |
//! | `<file>...` | Add these private keys (default: `~/.ssh/id_ed25519`) |
//!
//! Unsupported ssh-add flags are silently ignored for compatibility.
//!
//! ## Platform support
//!
//! Cross-platform as of v0.6.1. On Unix the agent client speaks over a
//! Unix domain socket at `$SSH_AUTH_SOCK`; on Windows the same env var
//! carries a named-pipe path (OpenSSH for Windows defaults to
//! `\\.\pipe\openssh-ssh-agent`).

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use ssh_key::{HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use anvil_ssh::agent::client::Agent;
use anvil_ssh::keygen::fingerprint;
use anvil_ssh::AnvilError;

// The cross-platform biometric vault lives in the shared library
// (`gitway-cli/src/lib.rs`); both `gitway` and `gitway-add` consume it from
// there so neither binary re-flags the parts it does not use as dead code.
use gitway::biometric::{self, AutoUnlock, UnlockMode};

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("gitway-add: error: {e}");
            // Actionable "what to do next" line — every `AnvilError`
            // kind provides a prescriptive hint.  Call sites that know
            // the context attach a more specific hint via `with_hint`.
            eprintln!("gitway-add: what to do: {}", e.hint());
            // Single-line diagnostic — IDE/credential-manager callers
            // routinely swallow stderr; emit one grep-able record so a
            // user chasing "agent add silently failed" in their IDE
            // log has a timestamped line to find.
            anvil_ssh::diagnostic::emit_for(&e);
            ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(1))
        }
    }
}

fn run(args: &[String]) -> Result<u32, AnvilError> {
    // `--help` is handled before argv parsing (so it never trips the
    // "unsupported flag" path) and before connecting to the agent.  Usage goes
    // to stdout with exit 0, matching `gitway --help`.
    if args
        .iter()
        .any(|a| matches!(a.as_str(), "-h" | "--help" | "-?"))
    {
        print_help();
        return Ok(0);
    }

    let parsed = Parsed::from_args(args)?;
    let mut agent = Agent::from_env()?;

    match parsed.mode {
        Mode::List { full } => list(&mut agent, full, parsed.hash),
        Mode::RemoveOne { path } => remove_one(&mut agent, &path),
        Mode::RemoveAll => remove_all(&mut agent),
        Mode::Lock => lock_unlock(&mut agent, /* lock = */ true),
        Mode::Unlock => lock_unlock(&mut agent, /* lock = */ false),
        Mode::Add { paths } => {
            let unlock = UnlockMode::from_flags(parsed.biometric, parsed.no_biometric);
            add(&mut agent, &paths, parsed.lifetime, parsed.confirm, unlock)
        }
    }
}

/// Print the `--help` usage text to stdout.  Mirrors the supported-argv table
/// in this file's header; kept in sync by hand (there is no clap here).
fn print_help() {
    println!(
        "gitway-add — load SSH keys into the gitway agent (an ssh-add-compatible shim)

Usage: gitway-add [OPTIONS] [FILE...]

With no FILE, adds the default keys (~/.ssh/id_ed25519, then id_ecdsa, id_rsa).
A key that is already loaded in the agent is skipped (no passphrase re-prompt).

Options:
  -l                  List loaded key fingerprints (default when no FILE given)
  -L                  List loaded public keys in full
  -d <file>           Remove the identity for <file>
  -D                  Remove all identities from the agent
  -x                  Lock the agent with a passphrase
  -X                  Unlock the agent
  -t <seconds>        Lifetime for keys added in this invocation (ssh-add -t)
  -E <sha256|sha512>  Fingerprint hash to display for -l
  -c                  Require confirmation on each signing request (ssh-add -c)
  --biometric         Enroll the key for biometric unlock while adding it
  --no-biometric      Force a typed passphrase even if the key is enrolled
  -h, --help          Show this help and exit

Keys load into the agent on $SSH_AUTH_SOCK.  Unsupported ssh-add flags are
accepted and ignored for compatibility."
    );
}

// ── Parser ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum Mode {
    List { full: bool },
    RemoveOne { path: PathBuf },
    RemoveAll,
    Lock,
    Unlock,
    Add { paths: Vec<PathBuf> },
}

#[derive(Debug)]
struct Parsed {
    mode: Mode,
    hash: HashAlg,
    lifetime: Option<Duration>,
    confirm: bool,
    biometric: bool,
    no_biometric: bool,
}

impl Parsed {
    fn from_args(args: &[String]) -> Result<Self, AnvilError> {
        let mut hash = HashAlg::Sha256;
        let mut lifetime: Option<Duration> = None;
        let mut confirm = false;
        let mut biometric = false;
        let mut no_biometric = false;

        let mut mode: Option<Mode> = None;
        let mut paths: Vec<PathBuf> = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            match a.as_str() {
                "-l" => {
                    set_mode(&mut mode, Mode::List { full: false }, "-l")?;
                    i += 1;
                }
                "-L" => {
                    set_mode(&mut mode, Mode::List { full: true }, "-L")?;
                    i += 1;
                }
                "-D" => {
                    set_mode(&mut mode, Mode::RemoveAll, "-D")?;
                    i += 1;
                }
                "-x" => {
                    set_mode(&mut mode, Mode::Lock, "-x")?;
                    i += 1;
                }
                "-X" => {
                    set_mode(&mut mode, Mode::Unlock, "-X")?;
                    i += 1;
                }
                "-c" => {
                    confirm = true;
                    i += 1;
                }
                "--biometric" => {
                    biometric = true;
                    i += 1;
                }
                "--no-biometric" => {
                    no_biometric = true;
                    i += 1;
                }
                "-d" => {
                    // `take` already advances `i` past both the flag and its value.
                    let path = take(args, &mut i, "-d")?;
                    set_mode(&mut mode, Mode::RemoveOne { path: path.into() }, "-d")?;
                }
                "-t" => {
                    let secs = take(args, &mut i, "-t")?;
                    lifetime = Some(parse_lifetime(&secs)?);
                }
                "-E" => {
                    let value = take(args, &mut i, "-E")?;
                    hash = parse_hash(&value)?;
                }
                // Silently-ignored ssh-add flags we do not implement yet.
                // (These are non-fatal for the CI/IDE integration use
                // case; behaviour diverges from real ssh-add when the
                // flag carries semantic meaning.)
                "-q" | "-v" | "-vv" | "-vvv" | "-H" | "-T" | "-s" | "-S" | "-e" | "-k" => {
                    i += 1;
                }
                "--" => {
                    i += 1;
                    // Everything after `--` is a positional path.
                    while i < args.len() {
                        paths.push(PathBuf::from(&args[i]));
                        i += 1;
                    }
                }
                other if other.starts_with('-') => {
                    return Err(AnvilError::invalid_config(format!(
                        "unsupported flag: {other}"
                    )));
                }
                _ => {
                    paths.push(PathBuf::from(a));
                    i += 1;
                }
            }
        }

        // Default when no mode-selecting flag was given.
        let mode = match mode {
            Some(m) => m,
            None if paths.is_empty() => Mode::Add {
                paths: default_key_paths()?,
            },
            None => Mode::Add { paths },
        };

        if biometric && no_biometric {
            return Err(AnvilError::invalid_config(
                "--biometric conflicts with --no-biometric",
            ));
        }

        Ok(Self {
            mode,
            hash,
            lifetime,
            confirm,
            biometric,
            no_biometric,
        })
    }
}

/// Parse the `-t` lifetime argument (an integer number of seconds).
fn parse_lifetime(secs: &str) -> Result<Duration, AnvilError> {
    let n: u64 = secs.parse().map_err(|_e: std::num::ParseIntError| {
        AnvilError::invalid_config(format!(
            "-t requires an integer number of seconds, got {secs:?}"
        ))
    })?;
    Ok(Duration::from_secs(n))
}

/// Parse the `-E` fingerprint-hash argument (`sha256` or `sha512`).
fn parse_hash(value: &str) -> Result<HashAlg, AnvilError> {
    match value.to_ascii_lowercase().as_str() {
        "sha256" => Ok(HashAlg::Sha256),
        "sha512" => Ok(HashAlg::Sha512),
        other => Err(AnvilError::invalid_config(format!(
            "-E requires sha256 or sha512, got {other:?}"
        ))),
    }
}

fn set_mode(slot: &mut Option<Mode>, new: Mode, flag: &str) -> Result<(), AnvilError> {
    if slot.is_some() {
        return Err(AnvilError::invalid_config(format!(
            "{flag} conflicts with a previous mode flag"
        )));
    }
    *slot = Some(new);
    Ok(())
}

fn take(args: &[String], i: &mut usize, flag: &str) -> Result<String, AnvilError> {
    *i += 1;
    let v = args
        .get(*i)
        .cloned()
        .ok_or_else(|| AnvilError::invalid_config(format!("{flag} requires a value")))?;
    *i += 1;
    Ok(v)
}

// ── Operations ────────────────────────────────────────────────────────────────

fn list(agent: &mut Agent, full: bool, hash: HashAlg) -> Result<u32, AnvilError> {
    let ids = agent.list()?;
    if ids.is_empty() {
        println!("The agent has no identities.");
        return Ok(1);
    }
    for id in &ids {
        if full {
            let line = id
                .public_key
                .to_openssh()
                .map_err(|e| AnvilError::signing(format!("serialize failed: {e}")))?;
            println!("{line}");
        } else {
            println!(
                "{} {} ({})",
                fingerprint(&id.public_key, hash),
                id.comment,
                id.public_key.algorithm().as_str().to_uppercase(),
            );
        }
    }
    Ok(0)
}

fn remove_one(agent: &mut Agent, path: &Path) -> Result<u32, AnvilError> {
    let raw = fs::read_to_string(path)?;
    let public_key = PublicKey::from_openssh(raw.trim())
        .or_else(|_| PrivateKey::from_openssh(&raw).map(|sk| sk.public_key().clone()))
        .map_err(|e| AnvilError::invalid_config(format!("cannot parse {}: {e}", path.display())))?;
    agent.remove(&public_key)?;
    println!(
        "Identity removed: {}",
        fingerprint(&public_key, HashAlg::Sha256)
    );
    Ok(0)
}

fn remove_all(agent: &mut Agent) -> Result<u32, AnvilError> {
    agent.remove_all()?;
    println!("All identities removed.");
    Ok(0)
}

fn lock_unlock(agent: &mut Agent, lock: bool) -> Result<u32, AnvilError> {
    let pp = if lock {
        let first = rpassword::prompt_password("Enter lock passphrase: ")
            .map(Zeroizing::new)
            .map_err(AnvilError::from)?;
        let confirm = rpassword::prompt_password("Confirm lock passphrase: ")
            .map(Zeroizing::new)
            .map_err(AnvilError::from)?;
        if *first != *confirm {
            return Err(AnvilError::invalid_config("passphrases did not match"));
        }
        first
    } else {
        rpassword::prompt_password("Enter unlock passphrase: ")
            .map(Zeroizing::new)
            .map_err(AnvilError::from)?
    };

    if lock {
        agent.lock(&pp)?;
        println!("Agent locked.");
    } else {
        agent.unlock(&pp)?;
        println!("Agent unlocked.");
    }
    Ok(0)
}

fn add(
    agent: &mut Agent,
    paths: &[PathBuf],
    lifetime: Option<Duration>,
    confirm: bool,
    unlock: UnlockMode,
) -> Result<u32, AnvilError> {
    // Identities the agent already holds — so re-adding a key that is still
    // loaded can skip the passphrase/biometric prompt entirely.  Best effort:
    // if the agent cannot be listed (e.g. it is locked), fall through to the
    // normal add path rather than failing.
    let loaded = agent.list().unwrap_or_default();
    for path in paths {
        let pem = fs::read_to_string(path)?;
        let key = PrivateKey::from_openssh(&pem).map_err(|e| {
            AnvilError::invalid_config(format!("cannot parse {}: {e}", path.display()))
        })?;
        // `--biometric` (Enroll) must always run so it can (re)store the
        // passphrase behind the keystore, even when the key is already loaded.
        if unlock != UnlockMode::Enroll {
            let want = fingerprint(key.public_key(), HashAlg::Sha256);
            if loaded
                .iter()
                .any(|id| fingerprint(&id.public_key, HashAlg::Sha256) == want)
            {
                println!("Identity already loaded: {}", path.display());
                continue;
            }
        }
        let decrypted = load_and_decrypt(path, key, unlock)?;
        agent.add(&decrypted, lifetime, confirm)?;
        println!("Identity added: {}", path.display());
    }
    Ok(0)
}

/// Decrypt an already-parsed key, honoring the biometric `unlock` mode (mirrors
/// `gitway agent add`, but with this shim's own passphrase prompt: stdin when
/// not a TTY, else `rpassword`).
fn load_and_decrypt(
    path: &Path,
    key: PrivateKey,
    unlock: UnlockMode,
) -> Result<PrivateKey, AnvilError> {
    if !key.is_encrypted() {
        return Ok(key);
    }

    let decrypt = |pp: &Zeroizing<String>| {
        key.decrypt(pp.as_bytes())
            .map_err(|e| AnvilError::signing(format!("decrypt failed: {e}")))
    };
    let id = biometric::key_id(&key);

    match unlock {
        UnlockMode::Disabled => decrypt(&prompt_passphrase(path)?),
        UnlockMode::Enroll => {
            let pp = prompt_passphrase(path)?;
            let decrypted = decrypt(&pp)?;
            match biometric::vault().store(&id, &pp) {
                Ok(()) => eprintln!(
                    "gitway-add: enrolled {} for biometric unlock",
                    path.display()
                ),
                Err(e) => eprintln!("gitway-add: warning: biometric enrollment failed: {e}"),
            }
            Ok(decrypted)
        }
        UnlockMode::Auto => match biometric::auto_unlock_passphrase(&key) {
            AutoUnlock::Passphrase(pp) => decrypt(&pp),
            AutoUnlock::Stale => {
                eprintln!(
                    "gitway-add: stored biometric passphrase no longer decrypts {} — \
                     removed stale enrollment",
                    path.display()
                );
                decrypt(&prompt_passphrase(path)?)
            }
            AutoUnlock::Fallback => decrypt(&prompt_passphrase(path)?),
        },
    }
}

/// Prompt for a typed passphrase: read from stdin when not a TTY (scripts /
/// credential managers), otherwise prompt on the terminal via `rpassword`.
fn prompt_passphrase(path: &Path) -> Result<Zeroizing<String>, AnvilError> {
    if let Some(from_stdin) = passphrase_from_stdin_if_not_tty() {
        return Ok(from_stdin);
    }
    rpassword::prompt_password(format!("Enter passphrase for {}: ", path.display()))
        .map(Zeroizing::new)
        .map_err(AnvilError::from)
}

/// When stdin is not a terminal (e.g. the shim is invoked from a script),
/// reading a passphrase from a TTY prompt can fail with ENXIO.  Fall back
/// to reading one line from stdin — matches `ssh-add`'s `-p` / piped-input
/// behaviour without actually implementing `-p`.
fn passphrase_from_stdin_if_not_tty() -> Option<Zeroizing<String>> {
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        return None;
    }
    let mut s = String::new();
    if std::io::stdin().read_to_string(&mut s).is_err() {
        return None;
    }
    // Trim a single trailing newline, like rpassword does.
    let trimmed = s.trim_end_matches('\n').to_owned();
    Some(Zeroizing::new(trimmed))
}

fn default_key_paths() -> Result<Vec<PathBuf>, AnvilError> {
    let home =
        dirs::home_dir().ok_or_else(|| AnvilError::invalid_config("cannot determine $HOME"))?;
    let candidates = ["id_ed25519", "id_ecdsa", "id_rsa"];
    let found: Vec<_> = candidates
        .iter()
        .map(|name| home.join(".ssh").join(name))
        .filter(|p| p.exists())
        .collect();
    if found.is_empty() {
        return Err(AnvilError::no_key_found());
    }
    Ok(found)
}
