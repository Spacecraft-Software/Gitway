// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for agent-env-var auto-detection of JSON output mode
//! (M20.2, per the CLI Standard).
//!
//! Gitway's detection (`gitway::agent_env`) is presence-based per the CLI
//! Standard §5: JSON output mode is selected when
//!
//! - `AI_AGENT` is set to any non-empty value (real harnesses export
//!   descriptive strings such as `claude-code_2-1-218_agent`, not `1`);
//! - `AGENT` is set to any non-empty value;
//! - `CI` is truthy (set, and not `false` / `0`).
//!
//! `CLAUDECODE`, `CURSOR_AGENT`, and `GEMINI_CLI` are informational only and
//! must NOT select JSON on their own.
//!
//! Each test spawns `gitway --test --insecure-skip-host-check --port 1
//! 127.0.0.1` (which deterministically fails because port 1 refuses
//! connections), with one of the env vars set, and asserts that the
//! resulting stderr contains a JSON blob (`{"metadata":...,"error":...}`)
//! rather than the human-mode `gitway: error:` prefix.
//!
//! The tests do not require network access — they only need to confirm
//! the output mode selection happens before any I/O.

use std::path::PathBuf;
use std::process::Command;

fn gitway() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway"))
}

/// Runs `gitway --test` against an unreachable port with the given env var
/// set, returns the captured stderr.
fn run_with_env(name: &str, value: &str) -> String {
    let output = Command::new(gitway())
        .args([
            "--test",
            "--insecure-skip-host-check",
            "--no-config",
            "--port",
            "1",
            "--connect-timeout",
            "1",
            "--attempts",
            "1",
            "127.0.0.1",
        ])
        // Wipe inherited agent / CI env vars so detection is deterministic.
        .env_remove("AI_AGENT")
        .env_remove("AGENT")
        .env_remove("CI")
        .env_remove("CLAUDECODE")
        .env_remove("CURSOR_AGENT")
        .env_remove("GEMINI_CLI")
        .env(name, value)
        .output()
        .expect("failed to spawn gitway");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Returns `true` if the stderr contains the JSON error envelope shape.
fn contains_json_error_envelope(stderr: &str) -> bool {
    stderr.lines().any(|l| {
        let trimmed = l.trim_start();
        trimmed.starts_with('{')
            && trimmed.contains("\"metadata\"")
            && trimmed.contains("\"error\"")
            && trimmed.contains("\"schema_version\"")
    })
}

#[test]
fn ai_agent_env_selects_json_mode() {
    let stderr = run_with_env("AI_AGENT", "1");
    assert!(
        contains_json_error_envelope(&stderr),
        "AI_AGENT=1 did not select JSON mode; stderr=\n{stderr}",
    );
}

#[test]
fn agent_env_selects_json_mode() {
    let stderr = run_with_env("AGENT", "1");
    assert!(
        contains_json_error_envelope(&stderr),
        "AGENT=1 did not select JSON mode; stderr=\n{stderr}",
    );
}

#[test]
fn ci_env_selects_json_mode() {
    let stderr = run_with_env("CI", "true");
    assert!(
        contains_json_error_envelope(&stderr),
        "CI=true did not select JSON mode; stderr=\n{stderr}",
    );
}

#[test]
fn ci_env_uppercase_selects_json_mode() {
    // `CI=true` is case-insensitive per is_agent_or_ci_env.
    let stderr = run_with_env("CI", "TRUE");
    assert!(
        contains_json_error_envelope(&stderr),
        "CI=TRUE did not select JSON mode; stderr=\n{stderr}",
    );
}

#[test]
fn descriptive_ai_agent_value_selects_json_mode() {
    // The value a live Claude Code session exports — the `== "1"` detector
    // this replaces failed to recognise it.
    let stderr = run_with_env("AI_AGENT", "claude-code_2-1-218_agent");
    assert!(
        contains_json_error_envelope(&stderr),
        "descriptive AI_AGENT did not select JSON mode; stderr=\n{stderr}",
    );
}

#[test]
fn ci_false_keeps_human_mode() {
    let stderr = run_with_env("CI", "false");
    assert!(
        !contains_json_error_envelope(&stderr),
        "CI=false unexpectedly selected JSON mode; stderr=\n{stderr}",
    );
}

#[test]
fn informational_env_vars_do_not_select_json_mode() {
    for name in ["CLAUDECODE", "CURSOR_AGENT", "GEMINI_CLI"] {
        let stderr = run_with_env(name, "1");
        assert!(
            stderr.contains("gitway: error:") && !contains_json_error_envelope(&stderr),
            "{name}=1 changed the output mode; stderr=\n{stderr}",
        );
    }
}

#[test]
fn no_agent_env_uses_human_mode() {
    // Without any agent env var set, output should be human-mode (with the
    // `gitway: error:` prefix line on stderr).
    let output = Command::new(gitway())
        .args([
            "--test",
            "--insecure-skip-host-check",
            "--no-config",
            "--port",
            "1",
            "--connect-timeout",
            "1",
            "--attempts",
            "1",
            "127.0.0.1",
        ])
        .env_remove("AI_AGENT")
        .env_remove("AGENT")
        .env_remove("CI")
        .env_remove("CLAUDECODE")
        .env_remove("CURSOR_AGENT")
        .env_remove("GEMINI_CLI")
        .output()
        .expect("failed to spawn gitway");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("gitway: error:"),
        "human-mode prefix missing; stderr=\n{stderr}",
    );
    // Human mode must NOT emit the JSON envelope.
    assert!(
        !contains_json_error_envelope(&stderr),
        "human-mode unexpectedly emitted a JSON envelope; stderr=\n{stderr}",
    );
}
