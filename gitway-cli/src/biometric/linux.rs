// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! Linux biometric backend: `fprintd` (verify gate) + Secret Service (store).
//!
//! `fprintd` only returns match / no-match — it stores nothing — so this
//! backend is inherently two-part: the fingerprint check runs over `fprintd`
//! on the **system** bus, and the passphrase lives in the Secret Service
//! keyring (`org.freedesktop.secrets`, gnome-keyring / `KWallet`) on the
//! **session** bus, accessed via [`oo7`].
//!
//! This makes the Linux backend [`Tier::Advisory`]: the passphrase is protected
//! by the login keyring, not the fingerprint.  See the module docs and
//! `docs/biometric.md` for the honest threat-model statement that the CLI
//! surfaces to users.

use std::future::Future;
use std::time::Duration;

use futures_lite::StreamExt as _;
use oo7::{Keyring, Secret};
use zeroize::Zeroizing;

use super::{fingerprint_of, BiometricError, BiometricVault, EnrolledKey, Result, Tier};

/// Attribute marking an item as ours, so `list` / `delete` never touch a
/// secret written by another application.
const APP_ATTR: (&str, &str) = ("application", "gitway");
/// Attribute distinguishing SSH passphrases from any future Gitway secret.
const TYPE_ATTR: (&str, &str) = ("type", "ssh-passphrase");

/// Upper bound on a single fingerprint verification.  `fprintd`'s
/// `VerifyStatus` signal can stall indefinitely (sensor unplugged mid-scan,
/// driver wedged); without a ceiling the load path would hang.  30 s is long
/// enough for several retry swipes yet short enough to fail fast.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// Ceiling on the non-interactive availability probe so `is_available()` can
/// never hang in a headless / container environment with a dead bus.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

// ── fprintd D-Bus proxies (system bus) ────────────────────────────────────────

#[zbus::proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
trait FprintManager {
    /// Object path of the default fingerprint device, or a D-Bus error when no
    /// device is present.
    fn get_default_device(&self) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint"
)]
trait FprintDevice {
    /// Claim the device for `username` (`""` = the calling user).
    fn claim(&self, username: &str) -> zbus::Result<()>;
    /// Release a previously claimed device.
    fn release(&self) -> zbus::Result<()>;
    /// Begin verification against `finger_name` (`"any"` = any enrolled finger).
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
    /// Stop an in-progress verification.
    fn verify_stop(&self) -> zbus::Result<()>;
    /// Enrolled finger names for `username` (`""` = the calling user).
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;
    /// Progress signal; `result` is e.g. `"verify-match"` / `"verify-no-match"`
    /// / `"verify-retry-scan"`, and `done` is `true` on the terminal event.
    #[zbus(signal)]
    fn verify_status(&self, result: String, done: bool) -> zbus::Result<()>;
}

// ── Vault ─────────────────────────────────────────────────────────────────────

/// fprintd + Secret Service backend.
#[derive(Debug)]
pub(crate) struct LinuxVault;

impl LinuxVault {
    /// Construct the backend.  Cheap — all I/O happens lazily per operation.
    pub(crate) const fn new() -> Self {
        Self
    }
}

impl BiometricVault for LinuxVault {
    fn is_available(&self) -> bool {
        run_blocking(|| async {
            // A device must exist *and* the keyring must be reachable; either
            // missing makes the feature non-functional.  Both are bounded by
            // PROBE_TIMEOUT so a dead bus fails fast instead of hanging.
            let conn = zbus::Connection::system()
                .await
                .map_err(|e| BiometricError::Unavailable(format!("system bus: {e}")))?;
            let mgr = FprintManagerProxy::new(&conn)
                .await
                .map_err(|e| BiometricError::Unavailable(format!("fprintd manager: {e}")))?;
            timeout(PROBE_TIMEOUT, mgr.get_default_device())
                .await?
                .map_err(|e| BiometricError::Unavailable(format!("no fingerprint device: {e}")))?;
            timeout(PROBE_TIMEOUT, Keyring::new())
                .await?
                .map_err(|e| BiometricError::Unavailable(format!("no keyring: {e}")))?;
            Ok(())
        })
        .is_ok()
    }

    fn binding_tier(&self) -> Tier {
        Tier::Advisory
    }

    fn store(&self, key_id: &str, passphrase: &Zeroizing<String>) -> Result<()> {
        let key_id = key_id.to_owned();
        // Clone into another Zeroizing so the worker thread owns it; the copy is
        // overwritten on drop just like the original.
        let secret: Zeroizing<String> = passphrase.clone();
        run_blocking(move || async move {
            let keyring = open_keyring().await?;
            let attrs = attributes(&key_id);
            let label = format!("Gitway SSH passphrase ({})", fingerprint_of(&key_id));
            keyring
                .create_item(&label, &attrs, Secret::text(secret.as_str()), true)
                .await
                .map_err(|e| BiometricError::Backend(format!("keyring write: {e}")))?;
            Ok(())
        })
    }

    fn retrieve(&self, key_id: &str) -> Result<Zeroizing<String>> {
        let key_id = key_id.to_owned();
        run_blocking(move || async move {
            // 1. Enrollment check FIRST — never raise a fingerprint prompt for a
            //    key that was never enrolled.
            let keyring = open_keyring().await?;
            let attrs = attributes(&key_id);
            let items = keyring
                .search_items(&attrs)
                .await
                .map_err(|e| BiometricError::Backend(format!("keyring search: {e}")))?;
            let Some(item) = items.into_iter().next() else {
                return Err(BiometricError::NotEnrolled);
            };

            // 2. Advisory biometric gate.
            verify_fingerprint().await?;

            // 3. Release the secret; reject non-UTF-8 (a passphrase is UTF-8).
            let secret = item
                .secret()
                .await
                .map_err(|e| BiometricError::Backend(format!("keyring read: {e}")))?;
            let text = std::str::from_utf8(secret.as_bytes()).map_err(|_e| {
                BiometricError::Backend("stored passphrase is not valid UTF-8".to_owned())
            })?;
            Ok(Zeroizing::new(text.to_owned()))
        })
    }

    fn delete(&self, key_id: &str) -> Result<()> {
        let key_id = key_id.to_owned();
        run_blocking(move || async move {
            let keyring = open_keyring().await?;
            let attrs = attributes(&key_id);
            let items = keyring
                .search_items(&attrs)
                .await
                .map_err(|e| BiometricError::Backend(format!("keyring search: {e}")))?;
            if items.is_empty() {
                return Err(BiometricError::NotEnrolled);
            }
            keyring
                .delete(&attrs)
                .await
                .map_err(|e| BiometricError::Backend(format!("keyring delete: {e}")))?;
            Ok(())
        })
    }

    fn list(&self) -> Result<Vec<EnrolledKey>> {
        run_blocking(|| async {
            let keyring = open_keyring().await?;
            let query = vec![APP_ATTR, TYPE_ATTR];
            let items = keyring
                .search_items(&query)
                .await
                .map_err(|e| BiometricError::Backend(format!("keyring search: {e}")))?;
            let mut enrolled = Vec::with_capacity(items.len());
            for item in items {
                let attrs = item
                    .attributes()
                    .await
                    .map_err(|e| BiometricError::Backend(format!("keyring attributes: {e}")))?;
                let fingerprint = attrs
                    .get("fingerprint")
                    .cloned()
                    .or_else(|| attrs.get("key-id").map(|k| fingerprint_of(k).to_owned()))
                    .unwrap_or_default();
                let comment = attrs.get("comment").cloned();
                enrolled.push(EnrolledKey {
                    fingerprint,
                    comment,
                });
            }
            Ok(enrolled)
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Attribute set identifying a single key's stored passphrase.  Secret Service
/// matches items whose attributes are a *superset* of the query, so the same
/// set is used for both `create_item` and `search_items`.
fn attributes(key_id: &str) -> Vec<(&str, &str)> {
    vec![
        APP_ATTR,
        TYPE_ATTR,
        ("key-id", key_id),
        ("fingerprint", fingerprint_of(key_id)),
    ]
}

/// Open the default Secret Service collection, attempting a best-effort unlock
/// (the session usually unlocked it at login; a failure here surfaces later as
/// a search/read error with a clearer message).
async fn open_keyring() -> Result<Keyring> {
    let keyring = Keyring::new()
        .await
        .map_err(|e| BiometricError::Unavailable(format!("keyring: {e}")))?;
    // Ignore unlock failures — many setups auto-unlock at login and `unlock`
    // is a no-op; a genuinely locked keyring fails the subsequent operation
    // with an actionable message.
    let _ = keyring.unlock().await;
    Ok(keyring)
}

/// Run the fprintd verify handshake.  Returns `Ok(())` only on `verify-match`;
/// a no-match, timeout, or stream end maps to [`BiometricError::Cancelled`].
async fn verify_fingerprint() -> Result<()> {
    let conn = zbus::Connection::system()
        .await
        .map_err(|e| BiometricError::Unavailable(format!("system bus: {e}")))?;
    let manager = FprintManagerProxy::new(&conn)
        .await
        .map_err(|e| BiometricError::Unavailable(format!("fprintd manager: {e}")))?;
    let device_path = manager
        .get_default_device()
        .await
        .map_err(|e| BiometricError::Unavailable(format!("no fingerprint device: {e}")))?;
    let device = FprintDeviceProxy::builder(&conn)
        .path(device_path)
        .map_err(|e| BiometricError::Backend(format!("device path: {e}")))?
        .build()
        .await
        .map_err(|e| BiometricError::Backend(format!("device proxy: {e}")))?;

    if device
        .list_enrolled_fingers("")
        .await
        .unwrap_or_default()
        .is_empty()
    {
        return Err(BiometricError::Unavailable(
            "no fingerprints are enrolled with fprintd (run `fprintd-enroll`)".to_owned(),
        ));
    }

    device
        .claim("")
        .await
        .map_err(|e| BiometricError::Backend(format!("claim device: {e}")))?;

    // Run the scan, then ALWAYS stop + release — even on error or timeout — so
    // the device is never left claimed (which would break system fingerprint
    // login until the next reboot).
    let verdict = scan(&device).await;
    let _ = device.verify_stop().await;
    let _ = device.release().await;

    match verdict {
        Ok(true) => Ok(()),
        Ok(false) => Err(BiometricError::Cancelled),
        Err(e) => Err(e),
    }
}

/// Drive a single verification: subscribe before `VerifyStart` (so no signal is
/// missed), then consume `VerifyStatus` until the terminal `done` event or the
/// [`VERIFY_TIMEOUT`].  `true` = matched.
async fn scan(device: &FprintDeviceProxy<'_>) -> Result<bool> {
    let mut status = device
        .receive_verify_status()
        .await
        .map_err(|e| BiometricError::Backend(format!("verify signal: {e}")))?;
    device
        .verify_start("any")
        .await
        .map_err(|e| BiometricError::Backend(format!("verify start: {e}")))?;

    let matched = timeout(VERIFY_TIMEOUT, async {
        while let Some(signal) = status.next().await {
            let args = signal
                .args()
                .map_err(|e| BiometricError::Backend(format!("verify args: {e}")))?;
            if *args.done() {
                // Terminal event: anything other than a match is a failure.
                return Ok(args.result().as_str() == "verify-match");
            }
            // Non-terminal retry hints (verify-retry-scan, …) — keep waiting.
        }
        // Stream ended without a terminal event.
        Ok::<bool, BiometricError>(false)
    })
    .await;

    // A timeout is treated as "not verified" rather than an error so the caller
    // maps it to Cancelled (exit 73 in the explicit path) consistently.
    matched.unwrap_or(Ok(false))
}

/// Apply a deadline to `future`, mapping expiry to a [`BiometricError`].
async fn timeout<F: Future>(limit: Duration, future: F) -> Result<F::Output> {
    tokio::time::timeout(limit, future)
        .await
        .map_err(|_elapsed| BiometricError::Unavailable("D-Bus call timed out".to_owned()))
}

/// Drive `f`'s future to completion on a dedicated thread with its own
/// current-thread Tokio runtime.
///
/// The vault trait is blocking but `oo7` / `zbus` are async.  Spawning a fresh
/// thread (rather than `Handle::block_on`) avoids the "cannot start a runtime
/// from within a runtime" panic when this is called from inside the transport
/// path's Tokio runtime, and works uniformly from synchronous callers
/// (`gitway-add`).  This is a cold path (one key load), so the per-call thread
/// + runtime spin-up cost is irrelevant.
fn run_blocking<T, F, Fut>(f: F) -> Result<T>
where
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<T>>,
    T: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| BiometricError::Backend(format!("tokio runtime init: {e}")))?;
                runtime.block_on(f())
            })
            .join()
            .unwrap_or_else(|_panic| {
                Err(BiometricError::Backend(
                    "biometric worker thread panicked".to_owned(),
                ))
            })
    })
}
