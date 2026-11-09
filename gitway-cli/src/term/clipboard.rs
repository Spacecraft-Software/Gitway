// SPDX-License-Identifier: GPL-3.0-or-later
// Rust guideline compliant 2026-05-18
//! OSC 52 clipboard write (Tier 1, `references/clipboard.md`).
//!
//! `OSC 52 ; c ; <base64> ST` asks the terminal to set the system clipboard.
//! It works across SSH and through tmux (`set-clipboard on`), which is the
//! point of using it over a platform clipboard API.  There is no query for
//! write support, and a terminal without it ignores the sequence silently, so
//! every caller must also tell the user where the copied text lives.
//!
//! Only writing is implemented; reading the clipboard is never needed.

use super::{write_stderr, Protocol};

/// Largest payload, in bytes of text, Gitway will send.
///
/// Several terminals and tmux cap an OSC 52 sequence at about 100 KB of
/// base64; 74 000 bytes of text encode to 98 668 bytes, just under that.  A
/// public key is under 1 KB, so this only guards against misuse.
pub const MAX_PAYLOAD_BYTES: usize = 74_000;

/// What happened to a copy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyOutcome {
    /// The sequence was written to the terminal.  Whether the terminal acted
    /// on it is unknowable.
    Sent,
    /// The protocol is off; the string is the resolution reason
    /// (`not_a_tty`, `agent_mode`, `disabled_by_user`, …).
    Disabled(&'static str),
    /// The text exceeds [`MAX_PAYLOAD_BYTES`].
    TooLarge,
    /// Writing to stderr failed.
    WriteFailed,
}

impl CopyOutcome {
    /// Whether the sequence went out.
    #[must_use]
    pub fn sent(self) -> bool {
        self == Self::Sent
    }

    /// Machine-readable reason for `--json` output.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Disabled(reason) => reason,
            Self::TooLarge => "payload_too_large",
            Self::WriteFailed => "write_failed",
        }
    }

    /// `{ "sent": bool, "reason": "…" }`.
    #[must_use]
    pub fn to_json(self) -> serde_json::Value {
        serde_json::json!({ "sent": self.sent(), "reason": self.reason() })
    }
}

/// Copies `text` to the clipboard through the terminal, when the resolved
/// protocol state allows it.
#[must_use]
pub fn copy(text: &str) -> CopyOutcome {
    let decision = super::current().decision(Protocol::Clipboard);
    if !decision.enabled {
        return CopyOutcome::Disabled(decision.reason);
    }
    if text.len() > MAX_PAYLOAD_BYTES {
        return CopyOutcome::TooLarge;
    }
    match write_stderr(encode(text).as_bytes()) {
        Ok(()) => CopyOutcome::Sent,
        Err(_) => CopyOutcome::WriteFailed,
    }
}

/// Builds the full `OSC 52 ; c ; <base64> ST` sequence.
fn encode(text: &str) -> String {
    format!("\x1b]52;c;{}\x1b\\", base64(text.as_bytes()))
}

/// Standard (RFC 4648 §4) base64 with padding.
///
/// Hand-rolled to avoid a new direct dependency for twenty lines (Gitway's
/// dependency policy); covered by the RFC 4648 §10 test vectors below.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let sextet = |shift: u32| char::from(ALPHABET[((n >> shift) & 0x3f) as usize]);
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { '=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        let cases = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in cases {
            assert_eq!(base64(plain.as_bytes()), encoded, "input {plain:?}");
        }
    }

    #[test]
    fn sequence_uses_st_terminator() {
        assert_eq!(encode("hi"), "\x1b]52;c;aGk=\x1b\\");
    }

    #[test]
    fn max_payload_fits_under_100_kb_of_base64() {
        assert!(MAX_PAYLOAD_BYTES.div_ceil(3) * 4 < 100_000);
    }
}
