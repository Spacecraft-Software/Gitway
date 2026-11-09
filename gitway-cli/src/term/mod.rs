// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! Modern terminal protocols, emitted only where they are safe
//! (`spacecraft-tui-protocols`).
//!
//! Gitway is a line-oriented CLI, not a full-screen TUI, so only two
//! protocols do real work here:
//!
//! | Protocol | Used for | Module |
//! |---|---|---|
//! | OSC 52 clipboard write | `gitway keygen … --copy` (public key) | [`clipboard`] |
//! | OSC 9;4 progress | the fingerprint wait, RSA key generation | [`progress`] |
//!
//! The kitty keyboard protocol, kitty graphics (and animation), the OSC 5522
//! rich clipboard, and OSC 22 pointer shapes are recognized by the override
//! grammar but always resolve to `not_used`: Gitway reads no keys outside
//! line-buffered passphrase prompts, shows no images, and has no mouse
//! regions.  Neither OSC 52 write nor OSC 9;4 has a terminal query, so Gitway
//! sends **no probes** and never touches raw mode; detection is the §2.1
//! gates plus, for progress, the identity allow-list.
//!
//! # Gates (§2.1)
//!
//! Nothing is emitted when stderr is not a terminal, in agent / CI mode, when
//! `TERM` is `dumb`, or when `TERM` is unset outside a recognized Windows
//! console host (Windows Terminal and `ConEmu` set no `TERM`).  A user override
//! can turn a protocol off or skip the identity check, but never bypasses
//! these gates — a sequence written to a pipe or an agent transcript is never
//! wanted.
//!
//! # User override (§2.5)
//!
//! `--term-protocols=<list>` (on `gitway`) and `SPACECRAFT_TERM_PROTOCOLS`
//! (every binary) take a comma-separated list: `+name` forces on, `-name`
//! forces off, a bare name means `+name`, and `all` addresses every protocol.
//! Later entries win, so `-all,+clipboard` keeps only the clipboard.  The flag
//! is layered on top of the variable, protocol by protocol.

pub mod clipboard;
pub mod progress;

use std::ffi::OsString;
use std::fmt;
use std::sync::OnceLock;

/// Environment variable carrying the §2.5 override list.
pub const ENV_VAR: &str = "SPACECRAFT_TERM_PROTOCOLS";

/// Every protocol name the override grammar accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Kitty keyboard protocol.
    Keyboard,
    /// Kitty graphics protocol and its fallback ladder.
    Graphics,
    /// Kitty graphics animation.
    Animation,
    /// OSC 52 clipboard write.
    Clipboard,
    /// OSC 5522 rich (MIME) clipboard.
    ClipboardRich,
    /// OSC 9;4 progress.
    Progress,
    /// OSC 22 pointer shape.
    Pointer,
}

impl Protocol {
    /// All protocols, in the order `describe` lists them.
    pub const ALL: [Self; 7] = [
        Self::Keyboard,
        Self::Graphics,
        Self::Animation,
        Self::Clipboard,
        Self::ClipboardRich,
        Self::Progress,
        Self::Pointer,
    ];

    /// The override-grammar name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard",
            Self::Graphics => "graphics",
            Self::Animation => "animation",
            Self::Clipboard => "clipboard",
            Self::ClipboardRich => "clipboard-rich",
            Self::Progress => "progress",
            Self::Pointer => "pointer",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// One protocol's user override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Override {
    /// No override; detection decides.
    #[default]
    Auto,
    /// `+name`: skip the identity check.
    On,
    /// `-name`: never emit.
    Off,
}

/// A parsed override list (`+clipboard,-progress`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Overrides([Override; 7]);

impl Overrides {
    /// The override for `protocol`.
    #[must_use]
    pub fn get(&self, protocol: Protocol) -> Override {
        self.0[protocol.index()]
    }

    /// Layers `top` over `self`: wherever `top` says something, it wins.
    #[must_use]
    pub fn layered(self, top: Self) -> Self {
        let mut out = self;
        for (slot, over) in out.0.iter_mut().zip(top.0) {
            if over != Override::Auto {
                *slot = over;
            }
        }
        out
    }
}

/// An override list named a protocol Gitway does not know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    token: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = Protocol::ALL.iter().map(|p| p.name()).collect();
        write!(
            f,
            "unknown terminal protocol `{}` (expected +/-{} or all)",
            self.token,
            names.join("|"),
        )
    }
}

impl std::error::Error for ParseError {}

/// Parses an override list.  Empty entries are skipped.
///
/// # Errors
///
/// Returns [`ParseError`] naming the first unknown protocol.
pub fn parse_overrides(list: &str) -> Result<Overrides, ParseError> {
    let mut out = Overrides::default();
    for raw in list.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let (setting, name) = if let Some(rest) = token.strip_prefix('+') {
            (Override::On, rest)
        } else if let Some(rest) = token.strip_prefix('-') {
            (Override::Off, rest)
        } else {
            (Override::On, token)
        };
        let name = name.trim().to_ascii_lowercase();
        if name == "all" {
            out.0 = [setting; 7];
        } else if let Some(p) = Protocol::from_name(&name) {
            out.0[p.index()] = setting;
        } else {
            return Err(ParseError {
                token: token.to_owned(),
            });
        }
    }
    Ok(out)
}

/// The multiplexer the process runs inside, if any (§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiplexer {
    /// `TMUX` is set.
    Tmux,
    /// `ZELLIJ` is set.
    Zellij,
    /// `STY` is set (GNU screen).
    Screen,
}

/// The environment facts the gates and the allow-list read, captured once.
#[derive(Debug, Clone, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent environment facts read from separate variables, \
              not states of one machine"
)]
pub struct TermEnv {
    /// Whether stderr — where every sequence goes — is a terminal.
    pub stderr_tty: bool,
    /// Agent / CI mode ([`crate::agent_env`]).
    pub agent: bool,
    /// `TERM`.
    pub term: Option<String>,
    /// `TERM_PROGRAM`.
    pub term_program: Option<String>,
    /// `TERM_PROGRAM_VERSION`.
    pub term_program_version: Option<String>,
    /// `WT_SESSION` is set (Windows Terminal).
    pub windows_terminal: bool,
    /// `ConEmuPID` set or `ConEmuANSI=ON`.
    pub conemu: bool,
    /// `TMUX` / `ZELLIJ` / `STY`.
    pub multiplexer: Option<Multiplexer>,
}

impl TermEnv {
    /// Captures the live process environment.
    #[must_use]
    pub fn capture() -> Self {
        use std::io::IsTerminal as _;
        Self::from_lookup(std::io::stderr().is_terminal(), |name| {
            std::env::var_os(name)
        })
    }

    /// Builds a [`TermEnv`] from an injectable lookup (for tests).
    pub fn from_lookup(stderr_tty: bool, lookup: impl Fn(&str) -> Option<OsString>) -> Self {
        let text = |name: &str| {
            lookup(name)
                .map(|v| v.to_string_lossy().into_owned())
                .filter(|v| !v.is_empty())
        };
        let multiplexer = if text("TMUX").is_some() {
            Some(Multiplexer::Tmux)
        } else if text("ZELLIJ").is_some() {
            Some(Multiplexer::Zellij)
        } else if text("STY").is_some() {
            Some(Multiplexer::Screen)
        } else {
            None
        };
        Self {
            stderr_tty,
            agent: crate::agent_env::is_agent_or_ci_with(&lookup),
            term: text("TERM"),
            term_program: text("TERM_PROGRAM"),
            term_program_version: text("TERM_PROGRAM_VERSION"),
            windows_terminal: text("WT_SESSION").is_some(),
            conemu: text("ConEmuPID").is_some()
                || text("ConEmuANSI").is_some_and(|v| v.eq_ignore_ascii_case("on")),
            multiplexer,
        }
    }

    /// The first §2.1 gate that blocks emission, if any.
    fn blocking_gate(&self) -> Option<&'static str> {
        if !self.stderr_tty {
            return Some("not_a_tty");
        }
        if self.agent {
            return Some("agent_mode");
        }
        match self.term.as_deref() {
            Some("dumb") => Some("dumb_terminal"),
            // Windows console hosts set no TERM; their own markers stand in.
            None if !(self.windows_terminal || self.conemu) => Some("dumb_terminal"),
            _ => None,
        }
    }

    /// The OSC 9;4 allow-list (`references/progress-pointer.md`).  Returns
    /// the matched terminal, or `None` when the terminal might treat OSC 9
    /// as a desktop notification.
    fn progress_terminal(&self) -> Option<&'static str> {
        if self.windows_terminal {
            return Some("windows-terminal");
        }
        if self.conemu {
            return Some("conemu");
        }
        if self.term.as_deref().is_some_and(|t| t.starts_with("foot")) {
            return Some("foot");
        }
        let program = self.term_program.as_deref()?.to_ascii_lowercase();
        let version = self.term_program_version.as_deref().unwrap_or("");
        if program.contains("ghostty") {
            Some("ghostty")
        } else if program.contains("vscode") {
            Some("vscode")
        } else if program.contains("rio") {
            Some("rio")
        } else if program.contains("contour") {
            Some("contour")
        } else if program.contains("iterm") && iterm_supports_progress(version) {
            Some("iterm2")
        } else if program == "wezterm" && wezterm_supports_progress(version) {
            Some("wezterm")
        } else {
            // kitty is left out on purpose: it needs an XTVERSION reply to
            // tell a progress-capable build from one that shows OSC 9 as a
            // notification, and Gitway sends no probes.  Users on a capable
            // kitty opt in with `+progress`.
            None
        }
    }
}

/// iTerm2 shows OSC 9;4 from 3.6 on; earlier builds pop a notification.
fn iterm_supports_progress(version: &str) -> bool {
    let mut parts = version.split('.').map(|p| p.parse::<u32>().ok());
    match (parts.next().flatten(), parts.next().flatten()) {
        (Some(major), Some(minor)) => (major, minor) >= (3, 6),
        _ => false,
    }
}

/// First `WezTerm` build that renders OSC 9;4 rather than notifying.  The
/// 20240203 stable release treats it as a notification; `TERM_PROGRAM_VERSION`
/// starts with the build date (`20250210-…`).
/// A `YYYYMMDD` date compared as a number.
const WEZTERM_PROGRESS_SINCE: u32 = 20_250_210;

fn wezterm_supports_progress(version: &str) -> bool {
    version
        .get(..8)
        .and_then(|d| d.parse::<u32>().ok())
        .is_some_and(|date| date >= WEZTERM_PROGRESS_SINCE)
}

/// One protocol's resolved state and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Whether Gitway will emit the protocol.
    pub enabled: bool,
    /// Machine-readable reason (`describe`, `--verbose`).
    pub reason: &'static str,
}

impl Decision {
    fn on(reason: &'static str) -> Self {
        Self {
            enabled: true,
            reason,
        }
    }

    fn off(reason: &'static str) -> Self {
        Self {
            enabled: false,
            reason,
        }
    }
}

/// The resolved state of every protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocols([Decision; 7]);

impl Protocols {
    /// Resolves every protocol against `env` and the user `overrides`.
    #[must_use]
    pub fn resolve(env: &TermEnv, overrides: Overrides) -> Self {
        let gate = env.blocking_gate();
        let decide = |p: Protocol| -> Decision {
            if !matches!(p, Protocol::Clipboard | Protocol::Progress) {
                return Decision::off("not_used");
            }
            if let Some(blocked) = gate {
                return Decision::off(blocked);
            }
            match (overrides.get(p), p) {
                (Override::Off, _) => Decision::off("disabled_by_user"),
                (Override::On, _) => Decision::on("forced_by_user"),
                // OSC 52 write has no query; the gates are the detection.
                (Override::Auto, Protocol::Clipboard) => Decision::on("gates_passed"),
                (Override::Auto, _) => match (env.multiplexer, env.progress_terminal()) {
                    (Some(_), _) => Decision::off("inside_multiplexer"),
                    (None, Some(terminal)) => Decision::on(terminal),
                    (None, None) => Decision::off("terminal_not_allow_listed"),
                },
            }
        };
        let mut out = [Decision::off("not_used"); 7];
        for p in Protocol::ALL {
            out[p.index()] = decide(p);
        }
        Self(out)
    }

    /// The decision for `protocol`.
    #[must_use]
    pub fn decision(&self, protocol: Protocol) -> Decision {
        self.0[protocol.index()]
    }

    /// Whether Gitway will emit `protocol`.
    #[must_use]
    pub fn enabled(&self, protocol: Protocol) -> bool {
        self.decision(protocol).enabled
    }

    /// `{ "<name>": { "enabled": bool, "reason": "…" }, … }`.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let map: serde_json::Map<String, serde_json::Value> = Protocol::ALL
            .iter()
            .map(|p| {
                let d = self.decision(*p);
                (
                    p.name().to_owned(),
                    serde_json::json!({ "enabled": d.enabled, "reason": d.reason }),
                )
            })
            .collect();
        serde_json::Value::Object(map)
    }
}

static RESOLVED: OnceLock<Protocols> = OnceLock::new();

/// Resolves the protocols once for the process: `flag` (from
/// `--term-protocols`) layered over [`ENV_VAR`], against the live
/// environment.  The first call wins.
///
/// An unparseable [`ENV_VAR`] is ignored with a warning (it is not a usage
/// error of this invocation); the flag is validated by clap before this runs.
pub fn init(flag: Overrides) -> Protocols {
    *RESOLVED.get_or_init(|| {
        let env_overrides = match std::env::var(ENV_VAR) {
            Ok(list) => parse_overrides(&list).unwrap_or_else(|e| {
                tracing::warn!(target: "gitway::term", error = %e, "ignoring {ENV_VAR}");
                Overrides::default()
            }),
            Err(_) => Overrides::default(),
        };
        Protocols::resolve(&TermEnv::capture(), env_overrides.layered(flag))
    })
}

/// The process-wide state; resolves from the environment alone when no
/// binary called [`init`] first (the shims).
#[must_use]
pub fn current() -> Protocols {
    init(Overrides::default())
}

/// Writes `bytes` to stderr in one call and flushes.  Every sequence goes to
/// stderr: stdout carries git pack data or JSON only.
fn write_stderr(bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut err = std::io::stderr().lock();
    err.write_all(bytes)?;
    err.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(tty: bool, pairs: &[(&str, &str)]) -> TermEnv {
        TermEnv::from_lookup(tty, |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        })
    }

    fn resolve(e: &TermEnv, list: &str) -> Protocols {
        Protocols::resolve(e, parse_overrides(list).expect("valid list"))
    }

    #[test]
    fn parses_signed_and_bare_names() {
        let o = parse_overrides("-all, +clipboard,progress").expect("valid");
        assert_eq!(o.get(Protocol::Clipboard), Override::On);
        assert_eq!(o.get(Protocol::Progress), Override::On);
        assert_eq!(o.get(Protocol::Pointer), Override::Off);
    }

    #[test]
    fn rejects_unknown_names() {
        let e = parse_overrides("+sparkles").expect_err("unknown");
        assert!(e.to_string().contains("`+sparkles`"));
    }

    #[test]
    fn flag_layers_over_env() {
        let env_list = parse_overrides("-clipboard,-progress").expect("valid");
        let flag = parse_overrides("+progress").expect("valid");
        let merged = env_list.layered(flag);
        assert_eq!(merged.get(Protocol::Clipboard), Override::Off);
        assert_eq!(merged.get(Protocol::Progress), Override::On);
    }

    #[test]
    fn nothing_is_emitted_without_a_tty() {
        let p = resolve(&env(false, &[("TERM", "foot")]), "+all");
        assert_eq!(p.decision(Protocol::Clipboard).reason, "not_a_tty");
        assert!(!p.enabled(Protocol::Progress));
    }

    #[test]
    fn nothing_is_emitted_in_agent_mode_even_when_forced() {
        let p = resolve(
            &env(
                true,
                &[("TERM", "foot"), ("AI_AGENT", "claude-code_2_agent")],
            ),
            "+all",
        );
        assert_eq!(p.decision(Protocol::Clipboard).reason, "agent_mode");
        assert!(!p.enabled(Protocol::Progress));
    }

    #[test]
    fn dumb_or_missing_term_blocks() {
        let p = resolve(&env(true, &[("TERM", "dumb")]), "");
        assert_eq!(p.decision(Protocol::Clipboard).reason, "dumb_terminal");
        let p = resolve(&env(true, &[]), "");
        assert_eq!(p.decision(Protocol::Clipboard).reason, "dumb_terminal");
    }

    #[test]
    fn windows_terminal_needs_no_term() {
        let p = resolve(&env(true, &[("WT_SESSION", "abc")]), "");
        assert_eq!(p.decision(Protocol::Progress).reason, "windows-terminal");
        assert!(p.enabled(Protocol::Clipboard));
    }

    #[test]
    fn progress_is_allow_list_only() {
        let p = resolve(&env(true, &[("TERM", "xterm-256color")]), "");
        assert_eq!(
            p.decision(Protocol::Progress).reason,
            "terminal_not_allow_listed"
        );
        let p = resolve(
            &env(
                true,
                &[("TERM", "xterm-ghostty"), ("TERM_PROGRAM", "ghostty")],
            ),
            "",
        );
        assert!(p.enabled(Protocol::Progress));
        let p = resolve(&env(true, &[("TERM", "foot-extra")]), "");
        assert!(p.enabled(Protocol::Progress));
    }

    #[test]
    fn wezterm_stable_is_excluded() {
        let stable = env(
            true,
            &[
                ("TERM", "xterm-256color"),
                ("TERM_PROGRAM", "WezTerm"),
                ("TERM_PROGRAM_VERSION", "20240203-110809-5046fc22"),
            ],
        );
        assert!(!resolve(&stable, "").enabled(Protocol::Progress));
        let nightly = env(
            true,
            &[
                ("TERM", "xterm-256color"),
                ("TERM_PROGRAM", "WezTerm"),
                ("TERM_PROGRAM_VERSION", "20250312-071211-2b75fef6"),
            ],
        );
        assert!(resolve(&nightly, "").enabled(Protocol::Progress));
    }

    #[test]
    fn iterm_needs_3_6() {
        let old = env(
            true,
            &[
                ("TERM", "xterm"),
                ("TERM_PROGRAM", "iTerm.app"),
                ("TERM_PROGRAM_VERSION", "3.5.11"),
            ],
        );
        assert!(!resolve(&old, "").enabled(Protocol::Progress));
        let new = env(
            true,
            &[
                ("TERM", "xterm"),
                ("TERM_PROGRAM", "iTerm.app"),
                ("TERM_PROGRAM_VERSION", "3.6.1"),
            ],
        );
        assert!(resolve(&new, "").enabled(Protocol::Progress));
    }

    #[test]
    fn multiplexer_skips_progress_unless_forced() {
        let e = env(
            true,
            &[("TERM", "foot"), ("TMUX", "/tmp/tmux-1000/default,1,0")],
        );
        assert_eq!(
            resolve(&e, "").decision(Protocol::Progress).reason,
            "inside_multiplexer"
        );
        assert!(resolve(&e, "+progress").enabled(Protocol::Progress));
        // OSC 52 goes through tmux unwrapped (`set-clipboard on`).
        assert!(resolve(&e, "").enabled(Protocol::Clipboard));
    }

    #[test]
    fn user_can_turn_everything_off() {
        let p = resolve(&env(true, &[("TERM", "foot")]), "-all");
        assert_eq!(p.decision(Protocol::Clipboard).reason, "disabled_by_user");
        assert_eq!(p.decision(Protocol::Progress).reason, "disabled_by_user");
    }

    #[test]
    fn unused_protocols_stay_off_when_forced() {
        let p = resolve(&env(true, &[("TERM", "xterm-kitty")]), "+all");
        for unused in [
            Protocol::Keyboard,
            Protocol::Graphics,
            Protocol::Animation,
            Protocol::ClipboardRich,
            Protocol::Pointer,
        ] {
            assert_eq!(p.decision(unused).reason, "not_used");
        }
    }
}
