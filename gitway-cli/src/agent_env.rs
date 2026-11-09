// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! Agent / CI environment detection (CLI Standard §5, agentic-CLI §4).
//!
//! Detection is **presence-based**: `AI_AGENT` and `AGENT` select agent mode
//! when set to *any* non-empty value, because real harnesses export
//! descriptive strings (`AI_AGENT=claude-code_2-1-218_agent`), not `1`.  `CI`
//! is the one value-carrying variable: it counts when set and not `false` /
//! `0`.
//!
//! `CLAUDECODE`, `CURSOR_AGENT`, and `GEMINI_CLI` are **informational only**
//! and never switch the output mode on their own; [`invoking_agent`] reports
//! them for describe-style telemetry.
//!
//! The shared library hosts this so all three binaries (and the terminal
//! protocol gate in [`crate::term`]) agree on what "agent mode" means.

use std::ffi::OsString;

/// Environment variables whose presence selects agent / CI mode.
pub const MODE_VARS: [&str; 3] = ["AI_AGENT", "AGENT", "CI"];

/// Environment variables that only identify the invoking harness.
pub const INFORMATIONAL_VARS: [&str; 3] = ["CLAUDECODE", "CURSOR_AGENT", "GEMINI_CLI"];

/// Returns `true` when the process runs under an agent or CI harness.
#[must_use]
pub fn is_agent_or_ci() -> bool {
    is_agent_or_ci_with(|name| std::env::var_os(name))
}

/// [`is_agent_or_ci`] over an injectable environment lookup (for tests).
pub fn is_agent_or_ci_with(lookup: impl Fn(&str) -> Option<OsString>) -> bool {
    let non_empty = |name: &str| lookup(name).is_some_and(|v| !v.is_empty());
    non_empty("AI_AGENT") || non_empty("AGENT") || lookup("CI").is_some_and(|v| ci_truthy(&v))
}

/// `CI` is truthy when set, non-empty, and not `false` / `0`
/// (case-insensitive).
fn ci_truthy(value: &OsString) -> bool {
    let text = value.to_string_lossy();
    let text = text.trim();
    !text.is_empty() && text != "0" && !text.eq_ignore_ascii_case("false")
}

/// Names the agent harness that launched the process, when one of the
/// informational variables is set.  Never a behavioral switch.
#[must_use]
pub fn invoking_agent() -> Option<&'static str> {
    let set = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    if set("CLAUDECODE") {
        Some("claude-code")
    } else if set("CURSOR_AGENT") {
        Some("cursor")
    } else if set("GEMINI_CLI") {
        Some("gemini-cli")
    } else {
        None
    }
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
    fn descriptive_ai_agent_value_is_detected() {
        assert!(is_agent_or_ci_with(env(&[(
            "AI_AGENT",
            "claude-code_2-1-218_agent"
        )])));
    }

    #[test]
    fn agent_set_to_any_value_is_detected() {
        assert!(is_agent_or_ci_with(env(&[("AGENT", "codex")])));
        assert!(is_agent_or_ci_with(env(&[("AGENT", "1")])));
    }

    #[test]
    fn empty_agent_value_is_not_detected() {
        assert!(!is_agent_or_ci_with(env(&[("AI_AGENT", "")])));
    }

    #[test]
    fn ci_is_value_carrying() {
        assert!(is_agent_or_ci_with(env(&[("CI", "true")])));
        assert!(is_agent_or_ci_with(env(&[("CI", "1")])));
        assert!(is_agent_or_ci_with(env(&[("CI", "woodpecker")])));
        assert!(!is_agent_or_ci_with(env(&[("CI", "false")])));
        assert!(!is_agent_or_ci_with(env(&[("CI", "FALSE")])));
        assert!(!is_agent_or_ci_with(env(&[("CI", "0")])));
        assert!(!is_agent_or_ci_with(env(&[("CI", "")])));
    }

    #[test]
    fn informational_vars_do_not_select_agent_mode() {
        assert!(!is_agent_or_ci_with(env(&[
            ("CLAUDECODE", "1"),
            ("CURSOR_AGENT", "1"),
            ("GEMINI_CLI", "1"),
        ])));
    }
}
