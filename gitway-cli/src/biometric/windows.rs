// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! Windows biometric backend: Windows Hello consent + Credential Locker.
//!
//! The passphrase is stored in the per-user Credential Locker
//! (`PasswordVault`, DPAPI-encrypted at rest).  Because the locker itself is
//! not biometric-gated, a separate Windows Hello consent prompt
//! (`UserConsentVerifier`) gates each read.  The Hello result is *not*
//! cryptographically bound to the locker read, so this backend is
//! [`Tier::DpapiConsent`] — stronger than Linux, not as strong as the macOS
//! Secure Enclave.
//!
//! NOTE: this file targets `cfg(windows)` and is validated in the CI build
//! matrix (the Linux development host cannot compile it).  `UserConsentVerifier`
//! historically required a UI thread; the dedicated worker thread here is the
//! mitigation, but the behaviour must be confirmed on a real console session
//! (see `docs/biometric.md`).

use windows::core::HSTRING;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Security::Credentials::{PasswordCredential, PasswordVault};
use zeroize::Zeroizing;

use super::{fingerprint_of, BiometricError, BiometricVault, EnrolledKey, Result, Tier};

/// Credential Locker resource all Gitway SSH-passphrase entries share.  The
/// user-name field holds the key's `SHA256:...` fingerprint.
const RESOURCE: &str = "org.SpacecraftSoftware.gitway.ssh-passphrase";

/// HRESULT for "element not found" — what `PasswordVault::Retrieve` returns
/// when no credential matches.
const ERROR_NOT_FOUND: i32 = 0x8007_0490u32 as i32;

/// Windows Hello + Credential Locker backend.
#[derive(Debug)]
pub(crate) struct WindowsVault;

impl WindowsVault {
    /// Construct the backend.  Cheap — all I/O happens lazily per operation.
    pub(crate) const fn new() -> Self {
        Self
    }
}

/// The credential user-name for a key is its bare fingerprint.
fn account_of(key_id: &str) -> &str {
    fingerprint_of(key_id)
}

/// Run `op` on a dedicated thread.  WinRT consent prompts want their own
/// thread/apartment, and the blocking `IAsyncOperation::get()` must not stall a
/// Tokio worker when called from the transport path.  Cold path — the per-call
/// thread cost is irrelevant.
fn on_worker_thread<T, F>(op: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        scope.spawn(op).join().unwrap_or_else(|_panic| {
            Err(BiometricError::Backend(
                "biometric worker thread panicked".to_owned(),
            ))
        })
    })
}

/// Raise the Windows Hello consent prompt, mapping its outcome to a result.
fn verify_consent() -> Result<()> {
    let message = HSTRING::from("Unlock your SSH key");
    let operation = UserConsentVerifier::RequestVerificationAsync(&message)
        .map_err(|e| BiometricError::Backend(format!("hello request: {e}")))?;
    let result = operation
        .get()
        .map_err(|e| BiometricError::Backend(format!("hello result: {e}")))?;
    if result == UserConsentVerificationResult::Verified {
        Ok(())
    } else {
        Err(BiometricError::Cancelled)
    }
}

impl BiometricVault for WindowsVault {
    fn is_available(&self) -> bool {
        on_worker_thread(|| {
            let operation = UserConsentVerifier::CheckAvailabilityAsync()
                .map_err(|e| BiometricError::Unavailable(format!("hello availability: {e}")))?;
            let availability = operation
                .get()
                .map_err(|e| BiometricError::Unavailable(format!("hello availability: {e}")))?;
            if availability == UserConsentVerifierAvailability::Available {
                Ok(())
            } else {
                Err(BiometricError::Unavailable(
                    "Windows Hello is not available or not configured".to_owned(),
                ))
            }
        })
        .is_ok()
    }

    fn binding_tier(&self) -> Tier {
        Tier::DpapiConsent
    }

    fn store(&self, key_id: &str, passphrase: &Zeroizing<String>) -> Result<()> {
        let account = account_of(key_id).to_owned();
        let secret: Zeroizing<String> = passphrase.clone();
        on_worker_thread(move || {
            let vault = PasswordVault::new()
                .map_err(|e| BiometricError::Backend(format!("credential locker: {e}")))?;
            // Overwrite any prior enrollment (Add does not replace).
            if let Ok(existing) =
                vault.Retrieve(&HSTRING::from(RESOURCE), &HSTRING::from(account.as_str()))
            {
                let _ = vault.Remove(&existing);
            }
            let credential = PasswordCredential::CreatePasswordCredential(
                &HSTRING::from(RESOURCE),
                &HSTRING::from(account.as_str()),
                &HSTRING::from(secret.as_str()),
            )
            .map_err(|e| BiometricError::Backend(format!("create credential: {e}")))?;
            vault
                .Add(&credential)
                .map_err(|e| BiometricError::Backend(format!("locker write: {e}")))
        })
    }

    fn retrieve(&self, key_id: &str) -> Result<Zeroizing<String>> {
        let account = account_of(key_id).to_owned();
        on_worker_thread(move || {
            let vault = PasswordVault::new()
                .map_err(|e| BiometricError::Backend(format!("credential locker: {e}")))?;
            // Enrollment check FIRST — never prompt for a key that is not stored.
            let credential = vault
                .Retrieve(&HSTRING::from(RESOURCE), &HSTRING::from(account.as_str()))
                .map_err(|e| {
                    if e.code().0 == ERROR_NOT_FOUND {
                        BiometricError::NotEnrolled
                    } else {
                        BiometricError::Backend(format!("locker read: {e}"))
                    }
                })?;
            // Hello consent gate.
            verify_consent()?;
            let password = credential
                .Password()
                .map_err(|e| BiometricError::Backend(format!("locker password: {e}")))?;
            let text = password.to_string_lossy();
            if text.is_empty() {
                return Err(BiometricError::Backend(
                    "stored passphrase was empty".to_owned(),
                ));
            }
            Ok(Zeroizing::new(text))
        })
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        let account = account_of(key_id).to_owned();
        on_worker_thread(move || {
            let vault = PasswordVault::new()
                .map_err(|e| BiometricError::Backend(format!("credential locker: {e}")))?;
            let credential = vault
                .Retrieve(&HSTRING::from(RESOURCE), &HSTRING::from(account.as_str()))
                .map_err(|e| {
                    if e.code().0 == ERROR_NOT_FOUND {
                        BiometricError::NotEnrolled
                    } else {
                        BiometricError::Backend(format!("locker read: {e}"))
                    }
                })?;
            vault
                .Remove(&credential)
                .map_err(|e| BiometricError::Backend(format!("locker delete: {e}")))
        })
    }

    fn list(&self) -> Result<Vec<EnrolledKey>> {
        on_worker_thread(|| {
            let vault = PasswordVault::new()
                .map_err(|e| BiometricError::Backend(format!("credential locker: {e}")))?;
            let found = match vault.FindAllByResource(&HSTRING::from(RESOURCE)) {
                Ok(found) => found,
                // No entries for our resource reports "element not found".
                Err(e) if e.code().0 == ERROR_NOT_FOUND => return Ok(Vec::new()),
                Err(e) => return Err(BiometricError::Backend(format!("locker list: {e}"))),
            };
            let mut enrolled = Vec::new();
            for credential in &found {
                // Listing does not read the password, so no Hello prompt.
                let fingerprint = credential
                    .UserName()
                    .map(|name| name.to_string_lossy())
                    .unwrap_or_default();
                enrolled.push(EnrolledKey {
                    fingerprint,
                    comment: None,
                });
            }
            Ok(enrolled)
        })
    }
}
