// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! Fallback biometric backend for builds without support.
//!
//! Compiled when either the `biometric` feature is off or the target platform
//! has no implementation.  Every operation reports unavailability so the CLI
//! surface stays identical across builds — `gitway biometric status` answers
//! truthfully and the key-load path falls through to the passphrase prompt.

use zeroize::Zeroizing;

use super::{BiometricError, BiometricVault, EnrolledKey, Result, Tier};

/// The no-op backend.  Holds no state.
#[derive(Debug)]
pub(crate) struct UnsupportedVault;

impl UnsupportedVault {
    /// Reason returned by every operation.
    fn reason() -> BiometricError {
        // Distinguish the two ways this backend gets selected so the message is
        // actionable: a feature-disabled build vs. an unsupported platform.
        #[cfg(not(feature = "biometric"))]
        let why = "this build was compiled without the `biometric` feature";
        #[cfg(feature = "biometric")]
        let why = "no biometric backend is available for this platform";
        BiometricError::Unavailable(why.to_owned())
    }
}

impl BiometricVault for UnsupportedVault {
    fn is_available(&self) -> bool {
        false
    }

    fn binding_tier(&self) -> Tier {
        Tier::Unsupported
    }

    fn store(&self, _key_id: &str, _passphrase: &Zeroizing<String>) -> Result<()> {
        Err(Self::reason())
    }

    fn retrieve(&self, _key_id: &str) -> Result<Zeroizing<String>> {
        Err(Self::reason())
    }

    fn delete(&self, _key_id: &str) -> Result<()> {
        Err(Self::reason())
    }

    fn list(&self) -> Result<Vec<EnrolledKey>> {
        Err(Self::reason())
    }
}
