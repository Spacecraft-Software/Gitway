// SPDX-License-Identifier: GPL-3.0-or-later
//! Integration tests for the terminal-protocol gates (`spacecraft-tui-protocols`
//! §2, §6) and the Standard §18 accessible-mode toggle.
//!
//! Every child runs with stdout and stderr captured, so neither is a
//! terminal: the §2.1 gate must keep every escape sequence out, even when the
//! user forces a protocol on.  Rendering on a real terminal is covered by the
//! unit tests in `src/term/` and by manual checks under `script(1)`.

use std::path::PathBuf;
use std::process::{Command, Output};

const ESC: u8 = 0x1b;

fn gitway() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gitway"))
}

/// A `gitway` command with the agent, accessibility, and protocol variables
/// cleared so each test sets exactly what it checks.
fn cmd() -> Command {
    let mut c = Command::new(gitway());
    for var in [
        "AI_AGENT",
        "AGENT",
        "CI",
        "CLAUDECODE",
        "CURSOR_AGENT",
        "GEMINI_CLI",
        "SPACECRAFT_A11Y",
        "SPACECRAFT_TERM_PROTOCOLS",
        "NO_COLOR",
        "GTK_MODULES",
    ] {
        c.env_remove(var);
    }
    c.env("TERM", "xterm-256color");
    c
}

fn run(c: &mut Command) -> Output {
    c.output().expect("failed to spawn gitway")
}

fn json_stdout(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); stdout=\n{}\nstderr=\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        )
    })
}

fn assert_no_escapes(out: &Output) {
    assert!(!out.stdout.contains(&ESC), "escape byte on stdout");
    assert!(!out.stderr.contains(&ESC), "escape byte on stderr");
}

#[test]
fn copy_is_never_sent_to_a_pipe_even_when_forced() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("id_ed25519");
    let out = run(cmd()
        .args(["--term-protocols=+all", "--json", "keygen", "generate"])
        .args(["--no-passphrase", "--copy", "-f"])
        .arg(&key));
    assert!(out.status.success(), "generate failed: {out:?}");
    assert_no_escapes(&out);
    let v = json_stdout(&out);
    assert_eq!(v["data"]["clipboard"]["sent"], false);
    assert_eq!(v["data"]["clipboard"]["reason"], "not_a_tty");
}

#[test]
fn extract_public_copy_reports_outcome() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("id_ed25519");
    let gen = run(cmd()
        .args(["--json", "keygen", "generate", "--no-passphrase", "-f"])
        .arg(&key));
    assert!(gen.status.success(), "generate failed: {gen:?}");
    let out = run(cmd()
        .env("AI_AGENT", "claude-code_2-1-218_agent")
        .args(["keygen", "extract-public", "--copy", "-f"])
        .arg(&key)
        .arg("-o")
        .arg(dir.path().join("out.pub")));
    assert!(out.status.success(), "extract-public failed: {out:?}");
    assert_no_escapes(&out);
    let v = json_stdout(&out);
    assert_eq!(v["data"]["clipboard"]["sent"], false);
}

#[test]
fn copy_key_is_absent_without_the_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = dir.path().join("id_ed25519");
    let out = run(cmd()
        .args(["--json", "keygen", "generate", "--no-passphrase", "-f"])
        .arg(&key));
    assert!(out.status.success());
    assert!(json_stdout(&out)["data"].get("clipboard").is_none());
}

#[test]
fn unknown_protocol_is_a_usage_error() {
    let out = run(cmd().args(["--term-protocols=+sparkles", "describe"]));
    assert_eq!(out.status.code(), Some(2), "expected exit 2: {out:?}");
}

#[test]
fn describe_reports_resolved_protocols() {
    let out = run(cmd().arg("describe"));
    assert!(out.status.success());
    let v = json_stdout(&out);
    let p = &v["terminal_protocols"]["resolved"];
    assert_eq!(p["clipboard"]["enabled"], false);
    assert_eq!(p["clipboard"]["reason"], "not_a_tty");
    assert_eq!(p["keyboard"]["reason"], "not_used");
    assert_eq!(
        v["terminal_protocols"]["env_var"],
        "SPACECRAFT_TERM_PROTOCOLS"
    );
}

#[test]
fn invalid_env_override_is_ignored_not_fatal() {
    let out = run(cmd()
        .env("SPACECRAFT_TERM_PROTOCOLS", "+sparkles")
        .arg("describe"));
    assert!(out.status.success(), "bad env var must not fail: {out:?}");
}

fn a11y_of(out: &Output) -> (bool, String) {
    let v = json_stdout(out);
    let r = &v["accessibility"]["resolved"];
    (
        r["enabled"].as_bool().expect("enabled is bool"),
        r["source"].as_str().expect("source is str").to_owned(),
    )
}

#[test]
fn accessible_mode_is_off_by_default() {
    let out = run(cmd().arg("describe"));
    assert_eq!(a11y_of(&out), (false, "default".to_owned()));
}

#[test]
fn accessible_flag_env_and_hint_precedence() {
    let out = run(cmd().args(["describe", "--accessible"]));
    assert_eq!(a11y_of(&out), (true, "flag".to_owned()));

    let out = run(cmd().env("SPACECRAFT_A11Y", "1").arg("describe"));
    assert_eq!(a11y_of(&out), (true, "env".to_owned()));

    let out = run(cmd()
        .env("SPACECRAFT_A11Y", "1")
        .args(["--no-accessible", "describe"]));
    assert_eq!(a11y_of(&out), (false, "flag".to_owned()));

    let out = run(cmd().env("TERM", "dumb").arg("describe"));
    assert_eq!(a11y_of(&out), (true, "hint".to_owned()));

    let out = run(cmd()
        .env("NO_COLOR", "1")
        .env("SPACECRAFT_A11Y", "0")
        .arg("describe"));
    assert_eq!(a11y_of(&out), (false, "env".to_owned()));
}
