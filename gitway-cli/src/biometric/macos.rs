// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! macOS biometric backend: Keychain Services + a Touch ID `SecAccessControl`.
//!
//! The passphrase is stored as a generic-password Keychain item carrying a
//! biometric access-control attribute (`AccessControlOptions::USER_PRESENCE` —
//! Touch ID with passcode fallback).  Reading the item via
//! `SecItemCopyMatching` then raises the system Touch ID prompt and the Secure
//! Enclave releases the secret only on a successful match, making this backend
//! [`Tier::HardwareBound`].
//!
//! NOTE: this file targets `cfg(target_os = "macos")` and is validated in the
//! CI build matrix (the Linux development host cannot compile it).  The
//! prompt-on-read behaviour in particular must be confirmed on real hardware
//! (see `docs/biometric.md`).

use security_framework::base::Error as KeychainError;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, SearchResult};
use security_framework::passwords::{
    delete_generic_password, generic_password, set_generic_password_options,
};
use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};
use zeroize::{Zeroize as _, Zeroizing};

use super::{fingerprint_of, BiometricError, BiometricVault, EnrolledKey, Result, Tier};

/// Keychain service all Gitway SSH-passphrase items share.  The account field
/// holds the key's `SHA256:...` fingerprint, so `list` is a service query.
const SERVICE: &str = "org.SpacecraftSoftware.gitway.ssh-passphrase";

// OSStatus values we special-case (from `<Security/SecBase.h>`).
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;

/// Keychain + Touch ID backend.
#[derive(Debug)]
pub(crate) struct MacosVault;

impl MacosVault {
    /// Construct the backend.  Cheap — all I/O happens lazily per operation.
    pub(crate) const fn new() -> Self {
        Self
    }
}

/// The account field for a key is its bare fingerprint.
fn account_of(key_id: &str) -> &str {
    fingerprint_of(key_id)
}

/// Map a Keychain `OSStatus` onto a [`BiometricError`].
fn map_error(error: &KeychainError) -> BiometricError {
    match error.code() {
        ERR_SEC_ITEM_NOT_FOUND => BiometricError::NotEnrolled,
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED => BiometricError::Cancelled,
        code => BiometricError::Backend(format!("keychain error {code}")),
    }
}

impl BiometricVault for MacosVault {
    fn is_available(&self) -> bool {
        // The Keychain is always present; whether Touch ID (vs. passcode
        // fallback) is offered is resolved by the system at prompt time.
        true
    }

    fn binding_tier(&self) -> Tier {
        Tier::HardwareBound
    }

    fn store(&self, key_id: &str, passphrase: &Zeroizing<String>) -> Result<()> {
        let account = account_of(key_id);
        // SecItemAdd fails with errSecDuplicateItem on overwrite; clear any
        // prior enrollment first (ignore "not found").
        let _ = delete_generic_password(SERVICE, account);

        let mut options = PasswordOptions::new_generic_password(SERVICE, account);
        // USER_PRESENCE = device-owner authentication: Touch ID with passcode
        // fallback.  The prompt is raised on retrieval, not on this add.
        options.set_access_control_options(AccessControlOptions::USER_PRESENCE);
        options.set_label(&format!("Gitway SSH passphrase ({account})"));
        set_generic_password_options(passphrase.as_bytes(), options).map_err(|e| map_error(&e))
    }

    fn retrieve(&self, key_id: &str) -> Result<Zeroizing<String>> {
        let options = PasswordOptions::new_generic_password(SERVICE, account_of(key_id));
        // Raises the Touch ID prompt because the item carries an access control.
        let mut bytes = generic_password(options).map_err(|e| map_error(&e))?;
        let secret = match std::str::from_utf8(&bytes) {
            Ok(text) => Zeroizing::new(text.to_owned()),
            Err(_e) => {
                bytes.zeroize();
                return Err(BiometricError::Backend(
                    "stored passphrase is not valid UTF-8".to_owned(),
                ));
            }
        };
        // The keychain buffer is a plain Vec<u8>; overwrite it now that the
        // secret has been copied into a Zeroizing wrapper.
        bytes.zeroize();
        Ok(secret)
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        delete_generic_password(SERVICE, account_of(key_id)).map_err(|e| map_error(&e))
    }

    fn list(&self) -> Result<Vec<EnrolledKey>> {
        let mut options = ItemSearchOptions::new();
        options
            .class(ItemClass::generic_password())
            .service(SERVICE)
            // Attributes only — NOT load_data — so listing never triggers a
            // biometric prompt.
            .load_attributes(true)
            .limit(Limit::All);

        let results = match options.search() {
            Ok(results) => results,
            // An empty keychain reports errSecItemNotFound; treat as no entries.
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
            Err(e) => return Err(map_error(&e)),
        };

        let mut enrolled = Vec::with_capacity(results.len());
        for result in results {
            if let SearchResult::Dict(_) = result {
                if let Some(attributes) = result.simplify_dict() {
                    // "acct" = kSecAttrAccount, "icmt" = kSecAttrComment.
                    let fingerprint = attributes.get("acct").cloned().unwrap_or_default();
                    let comment = attributes.get("icmt").cloned();
                    enrolled.push(EnrolledKey {
                        fingerprint,
                        comment,
                    });
                }
            }
        }
        Ok(enrolled)
    }
}
