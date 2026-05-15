// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for agent-env-var auto-detection of JSON output mode
//! (M20.2, Spacecraft Software SFRS).
//!
//! Gitway's `is_agent_or_ci_env` (in `gitway-cli/src/main.rs`) auto-selects
//! JSON output mode when any of these are set in the process environment:
//!
//! - `AI_AGENT=1`
//! - `AGENT=1`
//! - `CI=true` (case-insensitive)
//! - `CLAUDECODE=1`
//! - `CURSOR_AGENT=1`
//! - `GEMINI_CLI=1`
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
fn claudecode_env_selects_json_mode() {
    let stderr = run_with_env("CLAUDECODE", "1");
    assert!(
        contains_json_error_envelope(&stderr),
        "CLAUDECODE=1 did not select JSON mode; stderr=\n{stderr}",
    );
}

#[test]
fn cursor_agent_env_selects_json_mode() {
    let stderr = run_with_env("CURSOR_AGENT", "1");
    assert!(
        contains_json_error_envelope(&stderr),
        "CURSOR_AGENT=1 did not select JSON mode; stderr=\n{stderr}",
    );
}

#[test]
fn gemini_cli_env_selects_json_mode() {
    let stderr = run_with_env("GEMINI_CLI", "1");
    assert!(
        contains_json_error_envelope(&stderr),
        "GEMINI_CLI=1 did not select JSON mode; stderr=\n{stderr}",
    );
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
