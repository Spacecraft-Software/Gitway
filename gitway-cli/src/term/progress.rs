// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! OSC 9;4 progress (Tier 2, `references/progress-pointer.md`).
//!
//! Gitway's long waits have no measurable percentage — a fingerprint scan,
//! an RSA key generation — so only the indeterminate state (`3`) is used.
//! The indicator is decorative: every caller also reports the wait in text.
//!
//! # Restore on every exit path (§2.3)
//!
//! A progress indicator left set keeps spinning in the terminal tab after
//! Gitway exits.  It is cleared by:
//!
//! - the [`Progress`] guard's `Drop` (normal return and `?` error paths);
//! - a panic hook, chained before the previous hook so the panic message
//!   prints on a cleared terminal;
//! - a signal watcher (SIGINT / SIGTERM / SIGHUP on Unix; Ctrl-C, Ctrl-Break
//!   and console close on Windows) that clears and then exits.
//!
//! The hooks install once, on the first [`indeterminate`] call, and stay for
//! the rest of the process.  Once installed, a terminating signal ends the
//! process through `exit(128 + N)` rather than by signal death — the same
//! outcome for every caller Gitway has (git checks the non-zero status).  If
//! the watcher cannot be set up, no progress is emitted at all: Gitway never
//! sets a state it cannot guarantee to clear.
//!
//! Only one indicator is active at a time; Gitway never nests these waits.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use super::{write_stderr, Protocol};

/// `OSC 9 ; 4 ; 3 ; 0 ST` — indeterminate.
const SET_INDETERMINATE: &[u8] = b"\x1b]9;4;3;0\x1b\\";

/// `OSC 9 ; 4 ; 0 ; 0 ST` — remove the indicator.
const CLEAR: &[u8] = b"\x1b]9;4;0;0\x1b\\";

/// Whether an indicator is currently set.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether the restore hooks are in place (resolved once).
static HOOKS: OnceLock<bool> = OnceLock::new();

/// Keeps an indeterminate progress indicator set until dropped.
#[derive(Debug)]
#[must_use = "the indicator clears when this guard drops"]
pub struct Progress {
    active: bool,
}

impl Progress {
    /// Whether this guard set an indicator (false when the protocol is off).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if self.active {
            clear();
        }
    }
}

/// Sets an indeterminate progress indicator, when the resolved protocol
/// state allows it and the restore hooks are in place.
pub fn indeterminate() -> Progress {
    let inactive = Progress { active: false };
    if !super::current().enabled(Protocol::Progress) || !hooks_installed() {
        return inactive;
    }
    if write_stderr(SET_INDETERMINATE).is_err() {
        return inactive;
    }
    ACTIVE.store(true, Ordering::SeqCst);
    Progress { active: true }
}

/// Removes the indicator if one is set.  Safe to call from any path, any
/// number of times.
pub fn clear() {
    if ACTIVE.swap(false, Ordering::SeqCst) {
        let _ = write_stderr(CLEAR);
    }
}

fn hooks_installed() -> bool {
    *HOOKS.get_or_init(|| {
        if !signals::spawn_watcher() {
            return false;
        }
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            clear();
            previous(info);
        }));
        true
    })
}

mod signals {
    use std::sync::mpsc;
    use std::time::Duration;

    /// How long to wait for the watcher thread to register its handlers.
    /// Registration is a few syscalls; this only bounds a pathological stall.
    const READY_TIMEOUT: Duration = Duration::from_millis(500);

    /// Starts a thread that clears the indicator and exits when a terminating
    /// signal arrives.  Returns `true` once at least one handler is
    /// registered.
    ///
    /// The thread runs its own current-thread Tokio runtime so it works the
    /// same from `gitway` (inside a runtime) and `gitway-add` (no runtime).
    pub(super) fn spawn_watcher() -> bool {
        let (ready_tx, ready_rx) = mpsc::channel::<bool>();
        let spawned = std::thread::Builder::new()
            .name("gitway-term-restore".to_owned())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    let _ = ready_tx.send(false);
                    return;
                };
                runtime.block_on(watch(ready_tx));
            });
        spawned.is_ok() && ready_rx.recv_timeout(READY_TIMEOUT).unwrap_or(false)
    }

    /// Resolves when `signal` is delivered, or never when it is not
    /// registered.
    #[cfg(unix)]
    async fn next(signal: &mut Option<tokio::signal::unix::Signal>) {
        match signal {
            Some(s) => {
                let _ = s.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
    }

    #[cfg(unix)]
    async fn watch(ready: mpsc::Sender<bool>) {
        use tokio::signal::unix::{signal, SignalKind};

        // Each registration replaces the default action for that signal for
        // the life of the process, so this thread must stay to honor it.
        let mut interrupt = signal(SignalKind::interrupt()).ok();
        let mut terminate = signal(SignalKind::terminate()).ok();
        let mut hangup = signal(SignalKind::hangup()).ok();
        let any = interrupt.is_some() || terminate.is_some() || hangup.is_some();
        let _ = ready.send(any);
        if !any {
            return;
        }
        // POSIX signal numbers: SIGHUP = 1, SIGINT = 2, SIGTERM = 15.
        let signo = tokio::select! {
            () = next(&mut interrupt) => 2,
            () = next(&mut terminate) => 15,
            () = next(&mut hangup) => 1,
        };
        super::clear();
        std::process::exit(128 + signo);
    }

    #[cfg(windows)]
    async fn watch(ready: mpsc::Sender<bool>) {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};

        // Ctrl-C first: if it cannot be registered nothing is, and the default
        // handling stays intact.  The other two are best effort.
        let Ok(mut interrupt) = ctrl_c() else {
            let _ = ready.send(false);
            return;
        };
        let mut brk = ctrl_break().ok();
        let mut close = ctrl_close().ok();
        let _ = ready.send(true);
        tokio::select! {
            _ = interrupt.recv() => {}
            () = async {
                match brk.as_mut() {
                    Some(s) => { let _ = s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
            () = async {
                match close.as_mut() {
                    Some(s) => { let _ = s.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => {}
        }
        super::clear();
        // STATUS_CONTROL_C_EXIT (0xC000013A), the status Windows reports for a
        // process ended by Ctrl-C; the wrapping cast is the documented
        // NTSTATUS-to-exit-code mapping.
        #[expect(clippy::cast_possible_wrap, reason = "NTSTATUS bit pattern")]
        std::process::exit(0xC000_013A_u32 as i32);
    }

    #[cfg(not(any(unix, windows)))]
    async fn watch(ready: mpsc::Sender<bool>) {
        let _ = ready.send(false);
    }
}
