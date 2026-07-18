# Gitway exit codes

Gitway follows the Spacecraft Software Dual-Mode CLI Standard (Rule 2)
exit-code conventions.  Every binary in the workspace (`gitway`,
`gitway-keygen`, `gitway-add`) uses the same numbering.

**Frozen at:** v1.0.0.  New codes are additive only; existing codes
never change meaning.

## Standard codes

| Code | Meaning | When you see it |
|---|---|---|
| **0** | Success | Command completed; SSH session authenticated; signature verified. |
| **1** | General / unexpected error | Catch-all.  Filesystem error, internal logic error, an `AnvilError` variant that doesn't map to a more specific code, etc. |
| **2** | Usage error | Bad arguments, conflicting flags, missing required value, unparseable `~/.ssh/config` file, host has no embedded fingerprint and `--insecure-skip-host-check` not passed. |
| **3** | Not found | No identity key on disk, unknown host, key file missing, allowed-signers file missing. |
| **4** | Permission denied | Authentication failure (server rejected the offered identity), host-key mismatch (`@revoked` line matched, or fingerprint disagrees with the embedded pin), file permission too loose. |

## Specialized codes

| Code | Meaning | Where it fires |
|---|---|---|
| **73** | User declined a confirmation prompt | `gitway hosts add` when the user types `n` at the FR-85 fingerprint-confirm prompt; **biometric unlock** when the fingerprint prompt is cancelled or does not match. |
| **78** | Interactive input required but unavailable | `gitway hosts add` when stdin is not a TTY (piped, `--json`, agent env detected) and `--yes` was not passed; **biometric** enroll / `--biometric` load when no biometric backend is available (no sensor, fprintd, Hello, session bus, or keyring). |

Biometric subcommands also reuse the standard codes: **3** (not found) when
`gitway biometric forget` targets a key that is not enrolled, and **2** (usage)
when an enroll passphrase does not decrypt the key.  Auto-mode loads never fail
on biometric unavailability — they fall back to a passphrase prompt and exit per
the normal path.

## Machine-readable surface

The full table is reproduced inside the
`gitway schema` output under the top-level `exit_codes` key, so
agents that load the schema can look codes up programmatically:

```sh
gitway schema | jq '.exit_codes'
```

JSON-mode error envelopes include the exit code on `error.exit_code`:

```jsonc
{
  "metadata": { /* ... */ },
  "error": {
    "code": "auth_failed",
    "exit_code": 4,
    "message": "Permission denied (publickey)",
    "hint": "Verify your SSH key is added to your GitHub account."
  }
}
```

## Stability statement

- Codes 0–4 follow SSH/POSIX conventions and **will never change**.
- Specialized codes (73, 78) are stable for v1.0.x.
- Adding a new specialized code in a 1.x minor release is allowed.
- Removing or renumbering any code is a major-version (2.0)
  breaking change.
