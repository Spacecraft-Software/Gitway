// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! Biometric (local fingerprint) unlock for SSH key passphrases.
//!
//! A fingerprint cannot decrypt a key the way a passphrase can — biometrics
//! only *gate access to a stored secret*.  This module therefore stores a
//! key's passphrase in the operating system's secure keystore and releases it
//! after a local biometric check, so the next `gitway-add` /
//! `gitway agent add` can unlock the key with a fingerprint instead of typed
//! input.
//!
//! # Binding strength is not uniform across platforms
//!
//! The three backends differ in how strongly the released secret is bound to
//! the biometric — see [`Tier`].  On macOS the Secure Enclave releases the
//! secret only on a biometric/passcode match; on Windows the secret is
//! DPAPI-encrypted and a Hello consent prompt gates the read; on Linux the
//! `fprintd` check is *advisory* — the passphrase is protected by the login
//! keyring, not the fingerprint, so a local attacker with an unlocked session
//! can bypass the check.  Callers that surface this to the user must be honest
//! about the active tier.
//!
//! # Threading
//!
//! The [`BiometricVault`] trait is intentionally **blocking**.  The Linux
//! backend drives async D-Bus work on a dedicated thread with its own
//! current-thread runtime (see `linux.rs`) so it is safe to call from both
//! synchronous code (`gitway-add`) and from within the transport path's Tokio
//! runtime without the "runtime within a runtime" panic.

use std::fmt;

use ssh_key::{HashAlg, PrivateKey};
use zeroize::Zeroizing;

#[cfg(all(feature = "biometric", target_os = "linux"))]
mod linux;
#[cfg(all(feature = "biometric", target_os = "macos"))]
mod macos;
#[cfg(all(feature = "biometric", target_os = "windows"))]
mod windows;

// The fallback is compiled whenever no real backend applies (feature off, or a
// platform without an implementation).  Gating it to exactly that case keeps it
// from tripping the `unused` lints when a real backend *is* compiled.
#[cfg(not(all(
    feature = "biometric",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
)))]
mod unsupported;

/// Keystore service-name prefix.  Every stored item is keyed by
/// `gitway:ssh:<SHA256-fingerprint>` so entries are namespaced to Gitway and
/// can be enumerated / matched without a separate local index (the keystore is
/// the single source of truth).
const KEY_ID_PREFIX: &str = "gitway:ssh:";

/// How strongly the released passphrase is bound to the biometric on the
/// active platform.  Surfaced verbatim by `gitway biometric status` so users
/// are never misled into treating the Linux convenience gate as a security
/// boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// macOS — secret released by the Secure Enclave only on biometric/passcode
    /// match.
    HardwareBound,
    /// Windows — secret DPAPI-encrypted at rest; a Hello consent prompt gates
    /// the read but is not cryptographically bound to it.
    DpapiConsent,
    /// Linux — `fprintd` verifies the fingerprint, but the passphrase is
    /// protected by the login keyring, not the fingerprint.  Convenience, not a
    /// security boundary.
    Advisory,
    /// No biometric backend (feature disabled at build time, or an unsupported
    /// platform).
    Unsupported,
}

impl Tier {
    /// Stable machine token for JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HardwareBound => "hardware-bound",
            Self::DpapiConsent => "dpapi-consent",
            Self::Advisory => "advisory",
            Self::Unsupported => "unsupported",
        }
    }

    /// One-line human description of the security guarantee.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::HardwareBound => {
                "hardware-bound (Secure Enclave); the secret is released only on a \
                 biometric or passcode match"
            }
            Self::DpapiConsent => {
                "DPAPI-encrypted at rest; Windows Hello consent gates the read but is \
                 not cryptographically bound to it"
            }
            Self::Advisory => {
                "advisory gate — fprintd verifies your fingerprint, but the passphrase \
                 is protected by your login keyring, not by the fingerprint; a local \
                 attacker with an unlocked session can bypass the fingerprint check; \
                 treat this as convenience, not a security boundary"
            }
            Self::Unsupported => "no biometric backend is available on this build",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the key-load path should treat biometric unlock, derived from the
/// `--biometric` / `--no-biometric` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMode {
    /// Use biometric when the key is enrolled and a backend is available;
    /// otherwise prompt for a passphrase (the default).
    Auto,
    /// Prompt for the passphrase once, store it behind a biometric check, then
    /// load the key (`--biometric`).
    Enroll,
    /// Always prompt for a typed passphrase, even if enrolled (`--no-biometric`).
    Disabled,
}

impl UnlockMode {
    /// Resolve the mode from the two CLI flags (which are mutually exclusive).
    #[must_use]
    pub fn from_flags(enroll: bool, disabled: bool) -> Self {
        if disabled {
            Self::Disabled
        } else if enroll {
            Self::Enroll
        } else {
            Self::Auto
        }
    }
}

/// A key enrolled for biometric unlock.  Holds no secret material — only the
/// public fingerprint and (optional) comment, safe to print and serialize.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledKey {
    /// `SHA256:...` fingerprint of the enrolled key's public half.
    pub fingerprint: String,
    /// Key comment, when the backend records one.
    pub comment: Option<String>,
}

/// Failure modes of a biometric backend.  The CLI maps these onto exit codes
/// (see `biometric.rs`): [`Cancelled`](Self::Cancelled) → 73,
/// [`Unavailable`](Self::Unavailable) → 78 when explicitly requested,
/// [`NotEnrolled`](Self::NotEnrolled) → 3.
#[derive(Debug)]
pub enum BiometricError {
    /// No enrollment exists for the requested key.
    NotEnrolled,
    /// The user dismissed the biometric prompt, or the fingerprint did not
    /// match.
    Cancelled,
    /// No usable backend at runtime (no sensor / fprintd / Hello, no session
    /// bus or keyring, or the feature was compiled out).  Carries a
    /// human-readable reason.
    Unavailable(String),
    /// The keystore or biometric service returned an unexpected error.
    Backend(String),
}

impl fmt::Display for BiometricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnrolled => f.write_str("key is not enrolled for biometric unlock"),
            Self::Cancelled => f.write_str("biometric verification was cancelled or did not match"),
            Self::Unavailable(why) => write!(f, "biometric unlock is unavailable: {why}"),
            Self::Backend(why) => write!(f, "biometric backend error: {why}"),
        }
    }
}

impl std::error::Error for BiometricError {}

/// Convenience alias for backend results.
pub type Result<T> = std::result::Result<T, BiometricError>;

/// Cross-platform secure storage gated by a local biometric check.
///
/// All methods are blocking.  Implementations must never log or otherwise leak
/// the passphrase, and must move any secret obtained from a foreign keystore
/// buffer into a [`Zeroizing<String>`] immediately, rejecting non-UTF-8 output.
pub trait BiometricVault {
    /// Whether a usable sensor *and* keystore are reachable right now.  Must be
    /// cheap and side-effect-free (no biometric prompt) — it runs on the
    /// auto-unlock fast path and in headless/CI environments where it must
    /// return `false` reliably rather than hang.
    fn is_available(&self) -> bool;

    /// The security-binding tier of this backend (for honest status output).
    fn binding_tier(&self) -> Tier;

    /// Persist `passphrase` for `key_id` behind the platform's biometric ACL.
    ///
    /// # Errors
    /// Returns [`BiometricError::Unavailable`] when no backend is reachable, or
    /// [`BiometricError::Backend`] when the keystore rejects the write.
    fn store(&self, key_id: &str, passphrase: &Zeroizing<String>) -> Result<()>;

    /// Release the stored passphrase for `key_id`, raising the biometric
    /// prompt.  Returns [`BiometricError::NotEnrolled`] *without* prompting when
    /// no enrollment exists.
    ///
    /// # Errors
    /// Returns [`BiometricError::NotEnrolled`] when no enrollment exists,
    /// [`BiometricError::Cancelled`] when the user dismisses the prompt or the
    /// fingerprint does not match, [`BiometricError::Unavailable`] when no
    /// backend is reachable, or [`BiometricError::Backend`] on an unexpected
    /// keystore error.
    fn retrieve(&self, key_id: &str) -> Result<Zeroizing<String>>;

    /// Remove the enrollment for `key_id`.  Returns
    /// [`BiometricError::NotEnrolled`] when nothing was stored.
    ///
    /// # Errors
    /// Returns [`BiometricError::NotEnrolled`] when nothing was stored, or
    /// [`BiometricError::Backend`] when the keystore rejects the removal.
    fn delete(&self, key_id: &str) -> Result<()>;

    /// Enumerate all Gitway enrollments held by the keystore.
    ///
    /// # Errors
    /// Returns [`BiometricError::Unavailable`] when no keystore is reachable, or
    /// [`BiometricError::Backend`] on an unexpected keystore error.
    fn list(&self) -> Result<Vec<EnrolledKey>>;
}

/// The biometric backend for the current build configuration.
#[must_use]
pub fn vault() -> Box<dyn BiometricVault> {
    backend()
}

#[cfg(all(feature = "biometric", target_os = "linux"))]
fn backend() -> Box<dyn BiometricVault> {
    Box::new(linux::LinuxVault::new())
}

#[cfg(all(feature = "biometric", target_os = "macos"))]
fn backend() -> Box<dyn BiometricVault> {
    Box::new(macos::MacosVault::new())
}

#[cfg(all(feature = "biometric", target_os = "windows"))]
fn backend() -> Box<dyn BiometricVault> {
    Box::new(windows::WindowsVault::new())
}

#[cfg(not(all(
    feature = "biometric",
    any(target_os = "linux", target_os = "macos", target_os = "windows")
)))]
fn backend() -> Box<dyn BiometricVault> {
    Box::new(unsupported::UnsupportedVault)
}

/// Keystore identifier for `key`, derived from its public-key SHA-256
/// fingerprint.  The public half of an encrypted OpenSSH key is in the clear,
/// so this works before decryption.
#[must_use]
pub fn key_id(key: &PrivateKey) -> String {
    format!(
        "{KEY_ID_PREFIX}{}",
        key.public_key().fingerprint(HashAlg::Sha256)
    )
}

/// Strip the [`KEY_ID_PREFIX`] back off a stored item name to recover the bare
/// `SHA256:...` fingerprint for display.  Returns the input unchanged if it
/// carries no prefix (defensive — keeps `list` output readable even if an item
/// was written by a different tool under the same collection).
#[must_use]
pub fn fingerprint_of(key_id: &str) -> &str {
    key_id.strip_prefix(KEY_ID_PREFIX).unwrap_or(key_id)
}

/// Rebuild a keystore identifier from a bare `SHA256:...` fingerprint — the
/// inverse of [`fingerprint_of`].  Used by `biometric forget --all`, which
/// learns fingerprints from [`BiometricVault::list`] and needs `key_id`s to
/// delete them.
#[must_use]
pub fn key_id_from_fingerprint(fingerprint: &str) -> String {
    format!("{KEY_ID_PREFIX}{fingerprint}")
}

/// Best-effort biometric unlock for the auto path (no explicit `--biometric`).
///
/// Returns `Some(passphrase)` only when the key is enrolled, a backend is
/// available, and the user authenticated.  Every failure mode — not enrolled,
/// cancelled, unavailable, backend error — collapses to `None` so the caller
/// silently falls back to the normal passphrase prompt.  This is what makes
/// biometric purely additive on the transport path: it never blocks a push.
#[must_use]
pub fn auto_unlock(key_id: &str) -> Option<Zeroizing<String>> {
    match vault().retrieve(key_id) {
        Ok(passphrase) => Some(passphrase),
        Err(BiometricError::NotEnrolled | BiometricError::Cancelled) => None,
        Err(BiometricError::Unavailable(why)) => {
            log::debug!("biometric: unavailable, falling back to passphrase: {why}");
            None
        }
        Err(BiometricError::Backend(why)) => {
            log::debug!("biometric: backend error, falling back to passphrase: {why}");
            None
        }
    }
}

/// Outcome of [`auto_unlock_passphrase`] — a best-effort biometric unlock for an
/// already-parsed encrypted key.
pub enum AutoUnlock {
    /// A stored passphrase was released and verified to still decrypt the key.
    Passphrase(Zeroizing<String>),
    /// A stored passphrase existed but no longer decrypts the key (its passphrase
    /// was changed since enrollment); the stale enrollment has been forgotten.
    /// Callers should note this and fall back to a typed passphrase.
    Stale,
    /// Nothing usable: not enrolled, no backend available, the user cancelled, or
    /// a backend error.  Callers fall back silently to a typed passphrase.
    Fallback,
}

// Manual Debug so a released passphrase is never rendered into a log line or a
// panic message (the derived impl would print the secret via `Zeroizing`'s
// inner `String`).
impl fmt::Debug for AutoUnlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passphrase(_) => f.write_str("Passphrase(<redacted>)"),
            Self::Stale => f.write_str("Stale"),
            Self::Fallback => f.write_str("Fallback"),
        }
    }
}

/// Best-effort biometric unlock for an already-parsed encrypted key.
///
/// Computes the key's keystore id, asks the platform vault to release the stored
/// passphrase (raising the biometric prompt), and **verifies the released secret
/// still decrypts `key`**.  A secret that no longer decrypts (the key's
/// passphrase was changed since enrollment) is reported as [`AutoUnlock::Stale`]
/// and the enrollment is forgotten, so the next load does not prompt-then-fail in
/// a loop.  This is the single source of truth for the auto-unlock-and-self-heal
/// behavior shared by `gitway agent add`, `gitway-add`, and the transport
/// passphrase path.
#[must_use]
pub fn auto_unlock_passphrase(key: &PrivateKey) -> AutoUnlock {
    let id = key_id(key);
    let Some(passphrase) = auto_unlock(&id) else {
        return AutoUnlock::Fallback;
    };
    if key.decrypt(passphrase.as_bytes()).is_ok() {
        return AutoUnlock::Passphrase(passphrase);
    }
    // The stored secret no longer matches the on-disk key: forget it so we do
    // not prompt-then-fail on every future load.
    let _ = vault().delete(&id);
    AutoUnlock::Stale
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_round_trips_through_fingerprint_of() {
        let id = format!("{KEY_ID_PREFIX}SHA256:abc123");
        assert_eq!(fingerprint_of(&id), "SHA256:abc123");
    }

    #[test]
    fn fingerprint_of_tolerates_missing_prefix() {
        assert_eq!(fingerprint_of("SHA256:bare"), "SHA256:bare");
    }

    #[test]
    fn tier_tokens_are_stable() {
        assert_eq!(Tier::HardwareBound.as_str(), "hardware-bound");
        assert_eq!(Tier::DpapiConsent.as_str(), "dpapi-consent");
        assert_eq!(Tier::Advisory.as_str(), "advisory");
        assert_eq!(Tier::Unsupported.as_str(), "unsupported");
    }

    #[test]
    fn auto_unlock_debug_never_leaks_the_passphrase() {
        let rendered = format!(
            "{:?}",
            AutoUnlock::Passphrase(Zeroizing::new("hunter2".to_owned()))
        );
        assert_eq!(rendered, "Passphrase(<redacted>)");
        assert!(!rendered.contains("hunter2"));
    }
}
