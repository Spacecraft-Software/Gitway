// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! Standard §18 accessible mode — one toggle, resolved once per process.
//!
//! Precedence (§18.1), highest first:
//!
//! 1. `--accessible` / `--no-accessible` (only `gitway` has flags; the
//!    `gitway-keygen` / `gitway-add` shims keep their upstream-compatible argv
//!    and read the environment alone).
//! 2. `SPACECRAFT_A11Y=1` / `SPACECRAFT_A11Y=0`.
//! 3. Configuration — Gitway has no configuration file of its own (it reads
//!    `ssh_config(5)`, which has no place for this), so this level is empty.
//! 4. Unambiguous hints: `TERM=dumb`, a non-empty `NO_COLOR`, or
//!    `GTK_MODULES` naming both `gail` and `atk`.
//!
//! Unset everywhere means the default presentation, unchanged.  An explicit
//! "off" at any level beats every lower level, hints included.
//!
//! What accessible mode changes in Gitway (it emits no color and has no
//! full-screen TUI, so the list is short): tables render as one
//! `field: value` per line, decorative glyphs (`✓`) are dropped, confirmation
//! prompts spell out each choice and the default, and no terminal animation
//! is sent ([`crate::term`] keeps OSC 9;4 progress as a supplement to text).

use std::ffi::OsString;
use std::sync::OnceLock;

/// Environment variable carrying the §18.1 toggle.
pub const ENV_VAR: &str = "SPACECRAFT_A11Y";

/// Which §18.1 level decided the resolved state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `--accessible` / `--no-accessible`.
    Flag,
    /// `SPACECRAFT_A11Y`.
    Env,
    /// `TERM=dumb`, `NO_COLOR`, or the GTK AT-SPI bridge modules.
    Hint,
    /// Nothing set; the default presentation applies.
    Default,
}

impl Source {
    /// Stable machine-readable name, used in `describe` and `--verbose`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Env => "env",
            Self::Hint => "hint",
            Self::Default => "default",
        }
    }
}

/// The resolved accessible-mode state and the level that decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accessibility {
    enabled: bool,
    source: Source,
}

impl Accessibility {
    /// Whether accessible mode is on.
    #[must_use]
    pub fn enabled(self) -> bool {
        self.enabled
    }

    /// The §18.1 level that decided [`Self::enabled`].
    #[must_use]
    pub fn source(self) -> Source {
        self.source
    }

    /// `" ✓"` in the default presentation, nothing in accessible mode —
    /// screen readers pronounce the glyph, and the sentence it follows
    /// already states the outcome.
    #[must_use]
    pub fn check_mark(self) -> &'static str {
        if self.enabled {
            ""
        } else {
            " ✓"
        }
    }

    /// Machine-readable summary for `describe` and `--verbose`.
    #[must_use]
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "source": self.source.as_str(),
        })
    }
}

/// Applies the §18.1 precedence to already-read inputs.
#[must_use]
pub fn resolve(flag: Option<bool>, env: Option<bool>, hint: bool) -> Accessibility {
    let (enabled, source) = match (flag, env) {
        (Some(v), _) => (v, Source::Flag),
        (None, Some(v)) => (v, Source::Env),
        (None, None) if hint => (true, Source::Hint),
        (None, None) => (false, Source::Default),
    };
    Accessibility { enabled, source }
}

/// Reads the environment levels through `lookup` and resolves.
pub fn resolve_with(
    flag: Option<bool>,
    lookup: impl Fn(&str) -> Option<OsString>,
) -> Accessibility {
    let env = lookup(ENV_VAR).and_then(|v| parse_toggle(&v.to_string_lossy()));
    resolve(flag, env, hint_with(&lookup))
}

/// Parses a toggle value.  Anything unrecognized is ignored (`None`) rather
/// than guessed at — silence is never consent.
fn parse_toggle(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// The §18.1 level-4 hints.  Only unambiguous signals: never `$LANG`,
/// terminal size, or the absence of a TTY.
fn hint_with(lookup: &impl Fn(&str) -> Option<OsString>) -> bool {
    let no_color = lookup("NO_COLOR").is_some_and(|v| !v.is_empty());
    let dumb = lookup("TERM").is_some_and(|v| v == "dumb");
    // Both `gail` and `atk` must be present — either alone is not the AT-SPI
    // bridge signal.
    let at_spi = lookup("GTK_MODULES").is_some_and(|v| {
        let text = v.to_string_lossy();
        let parts: Vec<&str> = text.split(':').collect();
        parts.contains(&"gail") && parts.contains(&"atk")
    });
    no_color || dumb || at_spi
}

static RESOLVED: OnceLock<Accessibility> = OnceLock::new();

/// Resolves accessible mode from `flag` plus the process environment and
/// caches it for the rest of the process.  The first call wins; later calls
/// return the cached value (§18.1: never re-resolve mid-run).
pub fn init(flag: Option<bool>) -> Accessibility {
    *RESOLVED.get_or_init(|| resolve_with(flag, |name| std::env::var_os(name)))
}

/// The process-wide state; resolves from the environment alone when no
/// binary called [`init`] first (the shims).
#[must_use]
pub fn current() -> Accessibility {
    init(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn unset_everywhere_is_default_off() {
        let a = resolve_with(None, env(&[("TERM", "xterm-256color")]));
        assert!(!a.enabled());
        assert_eq!(a.source(), Source::Default);
        assert_eq!(a.check_mark(), " ✓");
    }

    #[test]
    fn flag_beats_env_and_hints() {
        let a = resolve_with(Some(false), env(&[(ENV_VAR, "1"), ("TERM", "dumb")]));
        assert!(!a.enabled());
        assert_eq!(a.source(), Source::Flag);
    }

    #[test]
    fn env_zero_beats_hints() {
        let a = resolve_with(None, env(&[(ENV_VAR, "0"), ("NO_COLOR", "1")]));
        assert!(!a.enabled());
        assert_eq!(a.source(), Source::Env);
    }

    #[test]
    fn env_one_enables() {
        let a = resolve_with(None, env(&[(ENV_VAR, "1")]));
        assert!(a.enabled());
        assert_eq!(a.check_mark(), "");
    }

    #[test]
    fn unrecognized_env_value_falls_through() {
        let a = resolve_with(None, env(&[(ENV_VAR, "maybe")]));
        assert_eq!(a.source(), Source::Default);
    }

    #[test]
    fn hints_require_unambiguous_signals() {
        assert!(resolve_with(None, env(&[("TERM", "dumb")])).enabled());
        assert!(resolve_with(None, env(&[("NO_COLOR", "1")])).enabled());
        assert!(!resolve_with(None, env(&[("NO_COLOR", "")])).enabled());
        assert!(resolve_with(None, env(&[("GTK_MODULES", "gail:atk-bridge:atk")])).enabled());
        assert!(!resolve_with(None, env(&[("GTK_MODULES", "gail")])).enabled());
    }
}
